/*
MIT License

Copyright (c) 2019 Cassiano Martin

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#ifndef _NO_DATABASE
#include <sqlite3.h>
#endif

#include "cache.h"
#include "md5.h"
#include "utils.h"
#include "config.h"

#ifndef _NO_DATABASE
sqlite3 *db;
sqlite3_stmt *insert;
sqlite3_stmt *sselect;
sqlite3_stmt *sstats;

static const char *ins = "replace into cache(hash,category,stamp) values(?,?,strftime('%s','now'))";
static const char *sel = "select category from cache where hash=? and (strftime('%s','now')-stamp)<604800";
static const char *stats = "select count(id) from cache";

static const char *sql = "PRAGMA journal_mode=WAL; " \
                         "CREATE TABLE IF NOT EXISTS cache ( " \
                         "       id        INTEGER PRIMARY KEY AUTOINCREMENT, " \
                         "       hash      BLOB NOT NULL, " \
                         "       category  TEXT NOT NULL, " \
                         "       stamp     INTEGER NOT NULL); " \
                         "CREATE UNIQUE INDEX IF NOT EXISTS idx_hash ON cache(hash);";
#endif

static pthread_mutex_t mtx;

static SLIST_HEAD(, cache_t) cache_entries;

/*
 * 
 */

void cache_init()
{
    SLIST_INIT(&cache_entries);

#ifndef _NO_DATABASE
    wlog(LOG_LVL4, "SQLite3 %s database init\n", sqlite3_libversion());

    CALL_SQLITE(open_v2(config.cachedb, &db, SQLITE_OPEN_NOMUTEX|SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL));
    CALL_SQLITE(exec(db, sql, NULL, NULL, NULL));

    // prepare queries
    CALL_SQLITE(prepare_v2(db, ins, strlen(ins), &insert, NULL));
    CALL_SQLITE(prepare_v2(db, sel, strlen(sel), &sselect, NULL));
    CALL_SQLITE(prepare_v2(db, stats, strlen(stats), &sstats, NULL));
#endif

    pthread_mutex_init(&mtx, NULL);
}

void cache_flush()
{
    struct cache_t *entry;

    // remove allocated entries
    SLIST_FOREACH(entry, &cache_entries, next)
        if(entry->category!=NULL) free(entry->category);

    // remove linked list array entries
    while(!SLIST_EMPTY(&cache_entries))
    {
        entry = SLIST_FIRST(&cache_entries);
        SLIST_REMOVE_HEAD(&cache_entries, next);
        free(entry);
    }

#ifndef _NO_DATABASE
    CALL_SQLITE(finalize(insert));
    CALL_SQLITE(finalize(sselect));
    CALL_SQLITE(finalize(sstats));
    CALL_SQLITE(close(db));
#endif

    // destroy thread mutex
    pthread_mutex_destroy(&mtx);
}

// lookup a cached value in memory
struct cache_t *cache_lookup(char *domain)
{
    struct cache_t *entry;
    unsigned char digest[MD5_DIGEST_LENGTH];
    const char *text;
    MD5_CTX ctx;

    // init md5 context
    MD5_Init(&ctx);
    MD5_Update(&ctx, (void *)domain, strlen(domain));
    MD5_Final(digest, &ctx);

    // protect code from thread race
    pthread_mutex_lock(&mtx);

    // scan memory for hash
    SLIST_FOREACH(entry, &cache_entries, next)
    {
        if(memcmp(digest, entry->hash, MD5_DIGEST_LENGTH)==0)
            goto found;
    }

    // alloc a new entry on cache slist
    if((entry = calloc(sizeof(*entry),1))==NULL)
        wquit("cache_t malloc() failed.\n");

    entry->category = NULL;
    memcpy(entry->hash, digest, MD5_DIGEST_LENGTH);

#ifndef _NO_DATABASE
    // scan database cache
    CALL_SQLITE(bind_blob(sselect, 1, entry->hash, MD5_DIGEST_LENGTH, SQLITE_TRANSIENT));

    // fetch database record and copy on cache entry
    if(sqlite3_step(sselect)==SQLITE_ROW)
    {
        text = (const char *)sqlite3_column_text(sselect, 0);
        entry->category = strdup(text);

        // insert record on liked list
        SLIST_INSERT_HEAD(&cache_entries, entry, next);

        wlog(LOG_LVL4, "Cached record %s hit: %s\n", dump_hexdigest(entry->hash), entry->category);
    }

    CALL_SQLITE(reset(sselect));
#endif


found:
    pthread_mutex_unlock(&mtx);

    return entry;
}

void cache_insert(struct cache_t *entry)
{
    // insert new value in memory and database cache
    pthread_mutex_lock(&mtx);

    SLIST_INSERT_HEAD(&cache_entries, entry, next);

#ifndef _NO_DATABASE
    // insert database cache value
    CALL_SQLITE(bind_blob(insert, 1, entry->hash, MD5_DIGEST_LENGTH, SQLITE_TRANSIENT));
    CALL_SQLITE(bind_text(insert, 2, entry->category, strlen(entry->category), SQLITE_TRANSIENT));
    CALL_SQLITE_EXPECT(step(insert), DONE);
    CALL_SQLITE(reset(insert));
#endif
    pthread_mutex_unlock(&mtx);

    wlog(LOG_LVL4, "Record %s added to cache: %s\n", dump_hexdigest(entry->hash), entry->category);
}

// number of cached items in memory
int cache_statistics()
{
    struct cache_t *entry;
    int count = 0;

    pthread_mutex_lock(&mtx);

#ifndef _NO_DATABASE
    if(sqlite3_step(sstats)==SQLITE_ROW)
        wlog(LOG_LVL4, "Database cached items stats: %d\n", sqlite3_column_int(sstats, 0));

    CALL_SQLITE(reset(sstats));
#endif

    SLIST_FOREACH(entry, &cache_entries, next)
        count++;

    if(count>10000)
    {
        wlog(LOG_LVL1, "Cache overflow, flushing old data...\n");

        // remove allocated entries
        SLIST_FOREACH(entry, &cache_entries, next)
            if(entry->category!=NULL) free(entry->category);

        // remove linked list array entries
        while(!SLIST_EMPTY(&cache_entries))
        {
            entry = SLIST_FIRST(&cache_entries);
            SLIST_REMOVE_HEAD(&cache_entries, next);
            free(entry);
        }
    }

    pthread_mutex_unlock(&mtx);

    wlog(LOG_LVL4, "Memory cached items stats: %d\n", count);

    return count;
}