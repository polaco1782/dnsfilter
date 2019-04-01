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
 * File:   acl.h
 * Author: cassiano
 *
 * Created on September 16, 2015, 4:21 PM
 */

#include <sys/queue.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <time.h>
#include "cache.h"
#include "queue.h"

#ifndef ACL_H
#define	ACL_H

#ifdef	__cplusplus
extern "C" {
#endif

enum acltypes_1
{
    ACL_ANYNETWORK,
    ACL_IPADDR,
    ACL_MARK,
    ACL_TIME
};

enum acltypes_2
{
    ACL_PATTERN,
    ACL_CATEGORIZED
};

enum aclrules
{
    T_ALLOW,
    T_DENY,
    T_REDIRECT,
    T_NOMATCH,
    T_IGNORE,
    T_INVALID
};

struct category_t
{
    char *category;
    SLIST_ENTRY(category_t) next;
};

struct acl_t
{
    int type1;
    int type2;
    int type3;
    int action;

    char *data1;
    void *data2;

    uint32_t mark;
    time_t time1;
    time_t time2;

    struct in_addr addr1;
    struct in_addr addr2;
    struct in_addr mask;

    SLIST_HEAD(category_head, category_t) category_list;
    STAILQ_ENTRY(acl_t) next;
};
    
void acl_init();

void parse_acl(char *acl);

struct acl_t *acl_check(struct iphdr *ip, uint32_t nfmark, queueinfo_t *qinfo, char *domain);

#ifdef	__cplusplus
}
#endif

#endif	/* ACL_H */

