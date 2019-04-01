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

#ifndef _NO_DATABASE

#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sqlite3.h>
#include <netinet/in.h>
#include <bits/pthreadtypes.h>

#include "utils.h"
#include "log.h"
#include "config.h"

#define MAX_QUEUE 100

typedef struct
{
    char domain[265];
    char result[64];
    uint32_t ipaddr;
    int hitcode;
} q_buf __attribute__((aligned));

enum stmt_order
{
    STMT_LOG_INSERT,
    STMT_LOG_UPDATE,
    STMT_GROUP_UPDATE,
    STMT_IPADDR_INSERT
};

static sqlite3 *db;
static sqlite3_stmt *stmt_log[4];

static pthread_t thread;
static pthread_mutex_t mtx;
static pthread_mutex_t cond_mtx;
static pthread_cond_t cond;

static q_buf queue[2][MAX_QUEUE];
int rnum = 0;
int qnum = 0;

static const char *sql = "PRAGMA journal_mode=WAL; " \
                         "CREATE TABLE IF NOT EXISTS log ( " \
                         "       id        INTEGER PRIMARY KEY AUTOINCREMENT, " \
                         "       ipaddr    UNSIGNED INTEGER NOT NULL, " \
                         "       hitcount  INTEGER DEFAULT 0, " \
                         "       hitcode   INTEGER DEFAULT 0, " \
                         "       group_id  INTEGER DEFAULT 0, " \
                         "       domain    TEXT NOT NULL, " \
                         "       category  TEXT NULL, " \
                         "       stamp     INTEGER NOT NULL); " \
                         "CREATE UNIQUE INDEX IF NOT EXISTS idx_log ON log(ipaddr,domain); " \
                         "CREATE INDEX IF NOT EXISTS idx_stamp ON log(stamp); " \

                         "CREATE TABLE IF NOT EXISTS log_ipaddr (" \
                         "       id        INTEGER PRIMARY KEY AUTOINCREMENT, " \
                         "       ipaddr    UNSIGNED INTEGER NOT NULL, " \
                         "       group_id  INTEGER DEFAULT 0, " \
                         "       stamp     INTEGER NOT NULL); " \
                         "CREATE UNIQUE INDEX IF NOT EXISTS idx_ipaddr ON log_ipaddr(ipaddr,stamp); " \

                         "CREATE TABLE IF NOT EXISTS log_group (" \
                         "       id        INTEGER PRIMARY KEY AUTOINCREMENT, " \
                         "       ipaddr    UNSIGNED INTEGER NOT NULL, " \
                         "       group_id  INTEGER NOT NULL); " \
                         "CREATE UNIQUE INDEX IF NOT EXISTS idx_group ON log_group(ipaddr); ";

static const char *queries[] = { 
    "insert or ignore into log(ipaddr,domain,category,hitcode,stamp) values(?,?,?,?,strftime('%s','now'))",
    "update log set hitcount=hitcount+1 where ipaddr=? and domain=?",
    "update log set group_id = (select case when count(l.group_id)>0 then l.group_id else 0 end from log_group l where l.ipaddr=?) where ipaddr=? and domain=?",
    "insert or ignore into log_ipaddr(ipaddr,group_id,stamp) values(?, (select case when count(l.group_id)>0 then l.group_id else 0 end from log_group l where l.ipaddr=?), strftime('%s',strftime('%Y-%m-%d'),'utc'))"
};

static void *dbworker(void *arg)
{
    q_buf *q;
    uint32_t addr;

    while(1)
    {
        pthread_mutex_lock(&cond_mtx);
        pthread_cond_wait(&cond, &cond_mtx);

        wlog(LOG_LVL3, "Database thread running on queue %d!\n", qnum^1);

        q = queue[qnum^1];
        
        CALL_SQLITE(exec(db, "begin transaction", 0, 0, NULL));
        for(int i=0; i<MAX_QUEUE; i++)
        {
            addr = ntohl(q->ipaddr);

            CALL_SQLITE(bind_int(stmt_log[STMT_LOG_INSERT], 1, addr));
            CALL_SQLITE(bind_text(stmt_log[STMT_LOG_INSERT], 2, q->domain, strlen(q->domain), SQLITE_STATIC));
            CALL_SQLITE(bind_text(stmt_log[STMT_LOG_INSERT], 3, q->result, strlen(q->result), SQLITE_STATIC));
            CALL_SQLITE(bind_int(stmt_log[STMT_LOG_INSERT], 4, q->hitcode));
            CALL_SQLITE_EXPECT(step(stmt_log[STMT_LOG_INSERT]), DONE);
            CALL_SQLITE(reset(stmt_log[STMT_LOG_INSERT]));
            
            CALL_SQLITE(bind_int(stmt_log[STMT_LOG_UPDATE], 1, addr));
            CALL_SQLITE(bind_text(stmt_log[STMT_LOG_UPDATE], 2, q->domain, strlen(q->domain), SQLITE_STATIC));
            CALL_SQLITE_EXPECT(step(stmt_log[STMT_LOG_UPDATE]), DONE);
            CALL_SQLITE(reset(stmt_log[STMT_LOG_UPDATE]));

            CALL_SQLITE(bind_int(stmt_log[STMT_GROUP_UPDATE], 1, addr));
            CALL_SQLITE(bind_int(stmt_log[STMT_GROUP_UPDATE], 2, addr));
            CALL_SQLITE(bind_text(stmt_log[STMT_GROUP_UPDATE], 3, q->domain, strlen(q->domain), SQLITE_STATIC));
            CALL_SQLITE_EXPECT(step(stmt_log[STMT_GROUP_UPDATE]), DONE);
            CALL_SQLITE(reset(stmt_log[STMT_GROUP_UPDATE]));

            CALL_SQLITE(bind_int(stmt_log[STMT_IPADDR_INSERT], 1, addr));
            CALL_SQLITE(bind_int(stmt_log[STMT_IPADDR_INSERT], 2, addr));
            CALL_SQLITE_EXPECT(step(stmt_log[STMT_IPADDR_INSERT]), DONE);
            CALL_SQLITE(reset(stmt_log[STMT_IPADDR_INSERT]));

            wlog(LOG_LVL3, "LOG insert: %s, %s\n", q->domain, q->result);
            q++;
        }
        CALL_SQLITE(exec(db, "commit transaction", 0, 0, NULL));

        pthread_mutex_unlock(&cond_mtx);
    }

    return 0;
}

void log_init()
{
    CALL_SQLITE(open_v2(config.reportdb, &db, SQLITE_OPEN_NOMUTEX|SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL));
    CALL_SQLITE(exec(db, sql, NULL, NULL, NULL));

    CALL_SQLITE(prepare_v2(db, queries[STMT_LOG_INSERT], strlen(queries[STMT_LOG_INSERT]), &stmt_log[STMT_LOG_INSERT], NULL));
    CALL_SQLITE(prepare_v2(db, queries[STMT_LOG_UPDATE], strlen(queries[STMT_LOG_UPDATE]), &stmt_log[STMT_LOG_UPDATE], NULL));
    CALL_SQLITE(prepare_v2(db, queries[STMT_GROUP_UPDATE], strlen(queries[STMT_GROUP_UPDATE]), &stmt_log[STMT_GROUP_UPDATE], NULL));
    CALL_SQLITE(prepare_v2(db, queries[STMT_IPADDR_INSERT], strlen(queries[STMT_IPADDR_INSERT]), &stmt_log[STMT_IPADDR_INSERT], NULL));

    memset(&queue, 0, sizeof(q_buf)*MAX_QUEUE*2);

    pthread_mutex_init(&mtx, NULL);
    pthread_mutex_init(&cond_mtx, NULL);
    pthread_cond_init(&cond, NULL);

    // create thread and pass its queue block
    if(pthread_create(&thread, NULL, dbworker, NULL))
        wquit("dbworker pthread_create() failed\n");

    wlog(LOG_LVL3, "Report thread init.\n");
}

//! called from threaded code!
void log_insert(uint32_t ipaddr, char *domain, char *cat, int hitcode)
{
    q_buf *q = queue[qnum]+rnum;

    pthread_mutex_lock(&cond_mtx);

    strncpy(q->domain, domain, sizeof(q->domain));
    strncpy(q->result, cat, sizeof(q->result));
    q->ipaddr = ipaddr;
    q->hitcode = hitcode;
    rnum++;

    // queue is full, dump contents to database
    if(rnum>=MAX_QUEUE)
    {
        // swap queues
        rnum=0;
        qnum^=1;

        // notify database thread
        pthread_cond_signal(&cond);

        wlog(LOG_LVL3, "Notify database thread!\n");
    }
    pthread_mutex_unlock(&cond_mtx);

    wlog(LOG_LVL4, "Record %s added to database queue\n", domain);
}

void log_close()
{
    void *res;

    // cancel active thread
    pthread_cancel(thread);
    pthread_join(thread, &res);

    if(res==PTHREAD_CANCELED)
        wlog(LOG_LVL3, "Database thread stopped successfully!\n");

    CALL_SQLITE(finalize(stmt_log[STMT_LOG_INSERT]));
    CALL_SQLITE(finalize(stmt_log[STMT_LOG_UPDATE]));
    CALL_SQLITE(finalize(stmt_log[STMT_GROUP_UPDATE]));
    CALL_SQLITE(finalize(stmt_log[STMT_IPADDR_INSERT]));
    CALL_SQLITE(close(db));
    
    // destroy thread mutex
    pthread_mutex_destroy(&mtx);
}

#endif