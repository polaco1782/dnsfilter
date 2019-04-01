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
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <netdb.h>
#include <pthread.h>
#include <assert.h>

#include "acl.h"
#include "utils.h"
#include "config.h"
#include "cache.h"
#include "http.h"

#define GET_TOKEN(x,y,z,f) y=(x!=NULL?strsep(&x, z):NULL); if(y==NULL && f) wquit("ERROR: Missing ACL parameters on configuration file\n")

static pthread_mutex_t mtx;
static STAILQ_HEAD(, acl_t) acl_list;

in_addr_t netmask(int prefix)
{
    return htonl(0xffffffff << (32-prefix));
}

in_addr_t broadcast(in_addr_t addr, int prefix)
{
    return addr |~ netmask(prefix);
}

in_addr_t network(in_addr_t addr, int prefix)
{
    return addr & netmask(prefix);
}

bool match_pattern(const char *s, const char *pattern)
{
    for(;;)
    {
        if(!*pattern)
            return(!*s);

        if(*pattern=='*')
        {
            pattern++;

            if(!*pattern)
                return true;
            if(*pattern!='?' && *pattern!='*')
            {
                for(; *s; s++)
                {
                    if(*s== *pattern && match_pattern(s+1, pattern+1))
                        return true;
                }
                return false;
            }
            for(; *s; s++)
            {
                if(match_pattern(s, pattern))
                    return true;
            }
            return false;
        }
        if(!*s)
            return false;

        if(*pattern!='?' && *pattern!=*s)
            return false;

        s++;
        pattern++;
    }
}

void acl_init()
{
    STAILQ_INIT(&acl_list);
    pthread_mutex_init(&mtx, NULL);
}

int acl_action(char *acl)
{
    if(!strcmp(acl, "allow"))
    {
        wlog(LOG_LVL2, "acl_action type is ALLOW\n");
        return T_ALLOW;
    }
    else
    if(!strcmp(acl, "deny"))
    {
        wlog(LOG_LVL2, "acl_action type is DENY\n");
        return T_DENY;
    }
    else
    if(!strcmp(acl, "redirect"))
    {
        wlog(LOG_LVL2, "acl_action type is REDIRECT\n");
        return T_REDIRECT;
    }
    else
    if(!strcmp(acl, "ignore"))
    {
        wlog(LOG_LVL2, "acl_action type is IGNORE\n");
        return T_IGNORE;
    }

    wquit("acl_action() Invalid acl action [%s] in configuration file\n", acl);

    return T_INVALID;
}

int acl_type2(char *acl)
{
    if(!strcmp(acl, "category"))
    {
        wlog(LOG_LVL2, "acl_type2 type is CATEGORY\n");
        return ACL_CATEGORIZED;
    }
    if(!strcmp(acl, "pattern"))
    {
        wlog(LOG_LVL2, "acl_type2 type is PATTERN\n");
        return ACL_PATTERN;
    }

    wquit("acl_type2() Invalid acl type2 [%s] in configuration file\n", acl);

    return T_INVALID;
}

// invoked from config.c, not threaded
void parse_acl(char *line)
{
    struct acl_t *entry;
    char *token;
    char *acl;

    // copy acl line buffer
    acl = strdup(line);

    wlog(LOG_LVL2, "Parsing ACL [%s]\n", acl);

    // get first token from acl string
    GET_TOKEN(acl, token, " ", true);

    // alloc a new entry on acl slist
    if((entry = calloc(sizeof(*entry), 1))==NULL)
        wquit("acl_t malloc() failed.\n");

    SLIST_INIT(&entry->category_list);

    if(!strcmp(token, "ipaddr"))
    {
        int prefix = 0;
        char *addr;

        GET_TOKEN(acl, token, " ", true);
        wlog(LOG_LVL2, "acl type1 is ip address\n");

        // assume single host if no prefix given
        if(strstr(token,"/")==NULL)
        {
            prefix = 32;
            addr = token;
        }
        else
        {
            // extract IP address from prefix (TODO: needs a rewrite!)
            if(sscanf(token,"%*d.%*d.%*d.%*d/%d",&prefix)!=1)
                wquit("IP address prefix parse error: %s\n", token);

            GET_TOKEN(token, addr, "/", false);
        }

        entry->type1 = ACL_IPADDR;
        entry->addr1.s_addr = inet_addr(addr);
        entry->mask.s_addr = netmask(prefix);

        wlog(LOG_LVL2, "ADD entry data addr: %s, prefix: %d\n", token, prefix);
    }
    else
    if(!strcmp(token, "mark"))
    {
        GET_TOKEN(acl, token, " ", true);
        wlog(LOG_LVL2, "acl type1 is mark\n");

        entry->type1 = ACL_MARK;
        entry->mark = (int)strtol(token, NULL, 0);

        wlog(LOG_LVL2, "ADD entry mark data: %s, value: %d\n", token, entry->mark);
    }
    else
    if(!strcmp(token, "anynetwork"))
    {
        wlog(LOG_LVL2, "acl type1 is any network\n");

        entry->type1 = ACL_ANYNETWORK;
    }
    else
        wquit("Invalid ACL type [%s]\n", token);

    // acl action token
    GET_TOKEN(acl, token, " ", true);
    entry->action = acl_action(token);

    // acl second rule type token
    GET_TOKEN(acl, token, " ", true);
    entry->type2 = acl_type2(token);

    ///////////////////////////////////////////////////////////////////
    // categorized ACL rule
    if(entry->type2==ACL_CATEGORIZED)
    {
        char *cats;

        // acl category token
        GET_TOKEN(acl, token, " ", true);
        GET_TOKEN(token, cats, ",", true);

        while(cats!=NULL)
        {
            struct category_t *cat;

            wlog(LOG_LVL2, "Adding category [%s] to ACL\n", cats);

            // alloc a new entry nested category slist
            if((cat = calloc(sizeof(*cat), 1))==NULL)
                wquit("category_t malloc() failed.\n");

            cat->category = strdup(cats);

            // insert op stream in list
            SLIST_INSERT_HEAD(&entry->category_list, cat, next);

            // get next token from ACL
            cats = strsep(&token, ",");
        }
    }
    else
    ///////////////////////////////////////////////////////////////////
    if(entry->type2==ACL_PATTERN)
    {
        GET_TOKEN(acl, token, " ", true);

        entry->data1 = strdup(token);

        wlog(LOG_LVL2, "ADD entry data pattern: %s\n", token);
    }
    else
        wquit("Invalid ACL type2 [%s] in configuration file\n", token);

    // extract redirection data from string
    if(entry->action == T_REDIRECT)
    {
        GET_TOKEN(acl, token, " ", true);

        struct hostent *he;

        he = dnslookup(token);

        entry->data2 = (void *)calloc(sizeof(struct in_addr), 1);
        memcpy(entry->data2, he->h_addr, he->h_length);

        wlog(LOG_LVL2, "ADD entry for REDIRECT action: %s\n", token);
    }

    // acl time rule type
    GET_TOKEN(acl, token, " ", false);

    if(token!=NULL)
    {
        if(!strcmp(token, "time"))
        {
            struct tm t1,t2;

            memset(&t1, 0, sizeof(struct tm));
            memset(&t2, 0, sizeof(struct tm));

            t1.tm_year = 70;
            t2.tm_year = 70;
            t1.tm_mday = 1;
            t2.tm_mday = 1;

            GET_TOKEN(acl, token, " ", true);
            wlog(LOG_LVL2, "ADD entry for TIME1 check: %s\n", token);
            sscanf(token, "%02d:%02d", &t1.tm_hour, &t1.tm_min);

            GET_TOKEN(acl, token, " ", true);
            wlog(LOG_LVL2, "ADD entry for TIME2 check: %s\n", token);
            sscanf(token, "%02d:%02d", &t2.tm_hour, &t2.tm_min);

            entry->type3 = ACL_TIME;
            entry->time1 = mktime(&t1);
            entry->time2 = mktime(&t2);

            // validate entry order
            if(entry->time1>entry->time2)
                wquit("ERROR: ACL start time is greater than end time!\n");

            wlog(LOG_LVL4, "Time start: %02d:%02d (%d), Time end: %02d:%02d (%d), total %d seconds\n",
                    t1.tm_hour, t1.tm_min, entry->time1,
                    t2.tm_hour, t2.tm_min, entry->time2,
                    entry->time2-entry->time1);
        }
    }

    STAILQ_INSERT_TAIL(&acl_list, entry, next);
}

//! scan acl list and return matched entry, if any.
struct acl_t *acl_check(struct iphdr *ip, uint32_t nfmark, queueinfo_t *qinfo, char *domain)
{
    struct cache_t *cache_entry;
    struct acl_t *entry;
    struct in_addr *src;
    struct category_t *cats;

    src = (struct in_addr *)&ip->daddr;

    // loop acl linked list
    STAILQ_FOREACH(entry, &acl_list, next)
    {
        wlog(LOG_LVL3, "<--- ACL TEST BEGIN --->\n");

////////////////////////////// TYPE 1 TEST //////////////////////////////////
        if(entry->type1==ACL_IPADDR)
        {
            wlog(LOG_LVL4, "ACL_IPADDR: src  = %s\n", inet_ntoa(*src));
            wlog(LOG_LVL4, "ACL_IPADDR: addr = %s\n", inet_ntoa(entry->addr1));
            wlog(LOG_LVL4, "ACL_IPADDR: mask = %s\n", inet_ntoa(entry->mask));

            wlog(LOG_LVL4, "Current ACL type1 is ACL_IPADDR\n");

            if((src->s_addr & entry->mask.s_addr)==(entry->addr1.s_addr & entry->mask.s_addr))
                wlog(LOG_LVL3, "ACL_IPADDR: address [%s] match\n", inet_ntoa(*src));
            else
                continue;
        }
        else
        if(entry->type1==ACL_MARK)
        {
            wlog(LOG_LVL3, "Current ACL type1 is ACL_MARK\n");

            if(nfmark==entry->mark)
                wlog(LOG_LVL3, "ACL_MARK: value [0x%x] match\n", entry->mark);
            else
            {
                wlog(LOG_LVL3, "ACL_MARK: value [0x%x] does NOT match [0x%x]\n", entry->mark, nfmark);
                continue;
            }
        }
        else
        if(entry->type1==ACL_ANYNETWORK)
        {
            wlog(LOG_LVL3, "Current ACL type1 is ACL_ANYNETWORK\n");
            wlog(LOG_LVL3, "ACL_ANYNETWORK: match\n");
        }
        else
        {
            wlog(LOG_ERROR, "ACL type1 invalid??\n");
            continue;
        }
////////////////////////////// TYPE 1 TEST //////////////////////////////////



////////////////////////////// TYPE 2 TEST //////////////////////////////////
        if(entry->type2==ACL_PATTERN)
        {
            wlog(LOG_LVL3, "Current ACL type2 is ACL_PATTERN\n");
            if(match_pattern(domain, entry->data1))
                wlog(LOG_LVL2, "ACL_PATTERN: string [%s] matched pattern [%s]\n", domain, entry->data1);
            else
            {
                wlog(LOG_LVL2, "ACL_PATTERN: string [%s] NOT MATCH pattern [%s]\n", domain, entry->data1);
                continue;
            }
        }
        else
        if(entry->type2==ACL_CATEGORIZED)
        {
            if(!config.validlicense)
                continue;

            // try to locate a cached result, or allocate a new one
            cache_entry = cache_lookup(domain);

            if(cache_entry->category!=NULL && cache_entry->hash!=NULL)
            {
                wlog(LOG_LVL3, "In cache entry %s -> %s\n", domain, cache_entry->category);

                // entry is cached, but is a missed response from classification server
                if(cache_entry->category[0]=='Y' && cache_entry->category[1]=='Y')
                {
                    free(cache_entry->category);

                    if(perform_lookup(qinfo, cache_entry, domain))
                        wlog(LOG_LVL3, "CFS Reclassify Response: %s -> [%s]\n", domain, cache_entry->category);
                    else
                    {
                        cache_entry->category = strdup("YY");
                        wlog(LOG_LVL3, "CFS Reclassify Failed: %s -> [%s]\n", domain, cache_entry->category);

                        // locate a new server to connect
                        curl_init(qinfo, true);
                        return NULL;
                    }
                }
            }
            else
            {
                // lookup category on server
                if(perform_lookup(qinfo, cache_entry, domain))
                {
                    cache_insert(cache_entry);
                    wlog(LOG_LVL3, "CFS Response: %s -> [%s]\n", domain, cache_entry->category);
                }
                else
                {
                    // dont cache server missed records
                    free(cache_entry);

                    wlog(LOG_LVL2, "Failed to perform a server lookup\n");

                    // locate a new server to connect
                    curl_init(qinfo, true);

                    return NULL;
                }
            }

            bool found = false;
            assert(cache_entry->category != NULL);

            SLIST_FOREACH(cats, &entry->category_list, next)
            {
                // TODO: better rewrite this code
                if(strcasestr(cache_entry->category, cats->category)!=NULL)
                {
                    wlog(LOG_LVL2, "ACL_CATEGORIZED: string [%s] matched [%s]\n", domain, cache_entry->category);
                    found = true;

                    // stop inner slist loop
                    break;
                }
                else
                    wlog(LOG_LVL2, "ACL_CATEGORIZED: string [%s] NOT MATCH [%s]\n", domain, cats->category);
            }

            // jump back to main acl loop
            if(!found)
                continue;
        }
        else
        {
            wlog(LOG_ERROR, "ACL type2 invalid??\n");
            continue;
        }
////////////////////////////// TYPE 2 TEST //////////////////////////////////



////////////////////////////// TYPE 3 TEST //////////////////////////////////
        if(entry->type3 == ACL_TIME)
        {
            time_t rawtime;
            struct tm *timeinfo;

            time(&rawtime);
            timeinfo = localtime(&rawtime);

            timeinfo->tm_gmtoff = 0;
            timeinfo->tm_isdst = 0;
            timeinfo->tm_mday = 1;
            timeinfo->tm_mon = 0;
            timeinfo->tm_sec = 0;
            timeinfo->tm_wday = 0;
            timeinfo->tm_yday = 0;
            timeinfo->tm_year = 70;

            rawtime = mktime(timeinfo);

            if((unsigned)(rawtime-entry->time1)<=(entry->time2-entry->time1))
                wlog(LOG_LVL2, "ACL_TIME: [%d] matched [%d]\n", (rawtime-entry->time1), (entry->time2-entry->time1));
            else
            {
                wlog(LOG_LVL2, "ACL_TIME: [%d] does NOT match [%d]\n", (rawtime-entry->time1), (entry->time2-entry->time1));
                continue;
            }
        }
////////////////////////////// TYPE 3 TEST //////////////////////////////////

        // a NULL entry is not allowed to get in here. if so, there is a bug
        assert(entry != NULL);

        // ACL is valid and matched all tests, return it
        return entry;
    }

    // no ACL code matched
    wlog(LOG_LVL3, "--> acl_check: no matched results\n");

    return NULL;
}