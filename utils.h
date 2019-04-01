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
 * File:   utils.h
 * Author: cassiano
 *
 * Created on September 15, 2015, 10:33 AM
 */

#include <stdlib.h>
#include <netdb.h>

#ifndef UTILS_H
#define	UTILS_H

#ifdef	__cplusplus
extern "C" {
#endif

#define b_random(a,b) ((a)+random()*((b)-(a)))

#ifndef _NO_DATABASE

#define CALL_SQLITE(f) \
    { \
        int i; \
        i = sqlite3_ ## f; \
        if (i != SQLITE_OK) \
            wlog(LOG_LVL2, "%s failed with status %d: %s\n", #f, i, sqlite3_errmsg (db)); \
    } \

#define CALL_SQLITE_EXPECT(f,x) \
    { \
        int i; \
        i = sqlite3_ ## f; \
        if (i != SQLITE_ ## x) \
            wlog(LOG_LVL2, "%s failed with status %d: %s\n", #f, i, sqlite3_errmsg (db)); \
    } \

#endif

enum loglevel
{
    LOG_LVL0,
    LOG_LVL1,
    LOG_LVL2,
    LOG_LVL3,
    LOG_LVL4,
    LOG_WARN,
    LOG_ERROR
};

void wlog(int level, char *txt, ...);

void wquit(char *txt, ...);

struct hostent *dnslookup(char *host);

size_t strlcpy(char *dst, const char *src, size_t dsize);

size_t strlcat(char *dst, const char *src, size_t dsize);

#ifdef	__cplusplus
}
#endif

#endif	/* UTILS_H */

