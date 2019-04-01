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
 * File:   config.h
 * Author: cassiano
 *
 * Created on September 9, 2015, 5:28 PM
 */

#include <stdbool.h>
#include <netinet/in.h>

#ifndef CONFIG_H
#define	CONFIG_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct
{
    // config file location
    char filename[128];
    char logfile[128];
    char license[41];

    bool validlicense;

    char reportdb[128];
    char cachedb[128];

    // DNS rewrite ip address
    char rwhost[64];
    struct in_addr rwaddr;
    int tries;

    int serveridx;
    char serverdns[64];
    struct in_addr serveraddr[32];  // up to 32 redundant hosts

    int threads;
    int loglevel;
    bool daemon;

    // user/group to drop privilege
    char user[32];
    char group[32];
} config_t;

extern config_t config; // in config.c

void init_config();

bool parse_config();

#ifdef	__cplusplus
}
#endif

#endif	/* CONFIG_H */

