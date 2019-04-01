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

/* 
 * File:   cache.h
 * Author: cassiano
 *
 * Created on September 1, 2015, 5:15 PM
 */

#include <sys/queue.h>

#include "md5.h"

#ifndef CACHE_H
#define	CACHE_H

#ifdef	__cplusplus
extern "C" {
#endif

// shared cache among threads
struct cache_t
{
    unsigned char hash[MD5_DIGEST_LENGTH];
    char *category;
    SLIST_ENTRY(cache_t) next;
};


void cache_init();

struct cache_t *cache_lookup(char *domain);

void cache_insert(struct cache_t *entry);

void cache_flush();

int cache_statistics();

#ifdef	__cplusplus
}
#endif

#endif	/* CACHE_H */

