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
 * File:   main.c
 * Author: cassiano
 *
 * Created on August 25, 2015, 2:43 PM
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <unistd.h>
#include <resolv.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <getopt.h>
#include <assert.h>
#include <time.h>

#include "privs.h"
#include "config.h"
#include "cache.h"
#include "checksums.h"
#include "queue.h"
#include "utils.h"
#include "dns.h"
#include "acl.h"
#include "log.h"
#include "http.h"

#define VERSION "1.0a"

#ifndef NUM_THREADS
    #define NUM_THREADS 10
#endif

static volatile bool quit = 0;

static queueinfo_t queue[NUM_THREADS];
static pthread_t thread[NUM_THREADS];

static pthread_mutex_t veredict_mtx;

// queue_callback is called each time a packet arrives on netfilter, *data is a
// pointer to the current queue info struct
static int queue_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    struct nfqnl_msg_packet_hdr *ph;
    uint8_t *packet;
    uint32_t nfmark;
    int payload_len;
    struct iphdr *ip;
    struct udphdr *udp;
    struct tcphdr *tcp;
    struct dnshdr *dns;
    struct dnsanswer *answer;
    struct dnstype *question;
    struct in_addr *addr;
    uint8_t *end, *start;
    char domain[256];
    size_t dnsize, asize = 0;

    // to measure response times
    clock_t callback_start = clock();
    clock_t callback_end;

    struct acl_t *acl = NULL;
    int result;

    // get packet header and nfmark from queue
    ph = nfq_get_msg_packet_hdr(nfa);
    nfmark = nfq_get_nfmark(nfa);

    uint32_t id = htonl(ph->packet_id);
    payload_len = nfq_get_payload(nfa, &packet);

    ip = (struct iphdr *)packet;
    
    if(ip->protocol == IPPROTO_UDP)
    {
        udp = (struct udphdr *)(packet+ip->ihl*4);
        dns = (struct dnshdr *)(udp+1);
    }
    else
    if(ip->protocol == IPPROTO_TCP)
    {
        tcp = (struct tcphdr *)(packet+ip->ihl*4);
        dns = (struct dnshdr *)(tcp+1);
    }
    else
    {
        wlog(LOG_WARN, "Unsupported packet type %d received\n", ip->protocol);

        return nfq_set_verdict(qh, id, NF_ACCEPT, payload_len, packet);
    }

    // raw access to DNS bytes
    start = (uint8_t *)(dns+1);
    end = (uint8_t *)(packet+payload_len);

    // return if no anwser provided
    if(ntohs(dns->answer_rrs)<1)
        goto bogus;

    // expand DNS query
    dnsize = dn_expand((uint8_t *)dns, end, start, domain, sizeof(domain));

    // bogus DNS name
    if(dnsize<0)
        goto bogus;

    // loop on each DNS query (actually only 1)
    question = (struct dnstype *)(start+dnsize);

    wlog(LOG_LVL4, "Domain: %s, Question type: %d\n",domain, ntohs(question->type));

    // check acl match
    acl = acl_check(ip, nfmark, (queueinfo_t *)data, domain);

    if(acl!=NULL)
    {
        if(acl->action != T_IGNORE)
        {
            // size to answer record
            asize = dnsize+sizeof(struct dnstype);

            // loop on each DNS answer
            for(int i = 0; i<ntohs(dns->answer_rrs); i++)
            {
                // pointer to answer section
                answer = (struct dnsanswer *)(start+asize);
                asize += sizeof(struct dnsanswer);

                if(asize>payload_len)
                    goto bogus;

                if(asize+ntohs(answer->len)>payload_len)
                    goto bogus;

                wlog(LOG_LVL4, "DNS: Answer type: %d, size: %d\n", ntohs(answer->qtype.type), ntohs(answer->len));

                // A record
                if(ntohs(answer->qtype.type)==T_A && ntohs(answer->len)==4)
                {
                    addr = (struct in_addr *)(start+asize);

                    if(acl->action==T_DENY)
                    {
                        // rewrite DNS record and set TTL
                        addr->s_addr = config.rwaddr.s_addr;
                        answer->ttl = 0;

                        wlog(LOG_LVL3, "acl->action is T_DENY\n");
                    }
                    else if(acl->action==T_REDIRECT)
                    {
                        wlog(LOG_LVL3, "acl->action is T_REDIRECT\n");

                        // rewrite DNS record and set TTL
                        addr->s_addr = ((struct in_addr *)acl->data2)->s_addr;
                        answer->ttl = 0;
                    }
                    else if(acl->action==T_ALLOW)
                    {
                        wlog(LOG_LVL3, "acl->action is T_ALLOW\n");
                        answer->ttl = 0;
                    }
                }

                // increment pointer to next answer
                asize += ntohs(answer->len);
            }

            // log acl actions
#ifndef _NO_DATABASE
            // TODO
            log_insert(ip->daddr, domain, config.validlicense?entry->category:"5A", acl->action);
#endif
        }
        else
        {
            wlog(LOG_LVL3, "acl->action is T_IGNORE\n");
            goto bogus;
        }
    }
#ifndef _NO_DATABASE
    else
        // TODO
        log_insert(ip->daddr, domain, config.validlicense?entry->category:"5A", T_NOMATCH);
#endif

    // recompute packet checksums
    if(ip->protocol == IPPROTO_UDP)
        compute_udp_checksum(ip, (uint16_t *)udp);
    else
        compute_tcp_checksum(ip, (uint16_t *)tcp);

    compute_ip_checksum(ip);

bogus:
    pthread_mutex_lock(&veredict_mtx);

    // replace packet and set veredict to accept
    result = nfq_set_verdict(qh, id, NF_ACCEPT, payload_len, packet);
    pthread_mutex_unlock(&veredict_mtx);

    callback_end = clock();
    wlog(LOG_LVL4, "callback time: %1.3f sec\n", (float)(callback_end - callback_start) / CLOCKS_PER_SEC);

    return result;
}

void *worker(void *arg)
{
    queueinfo_t *queue = (queueinfo_t *)arg;
    uint8_t buf[4096] __attribute__((aligned));
    int rv, fd;

    fd = nfq_fd(queue->nfq);
    
    wlog(LOG_LVL3, "Thread ID=%d started!\n", queue->tid);

    while((rv = recv(fd, buf, sizeof(buf), 0)) && rv>=0)
    {
        wlog(LOG_LVL4, "Thread %d received a packet\n", queue->tid);

        nfq_handle_packet(queue->nfq, buf, rv);
        queue->packets++;
    }

    wlog(LOG_LVL3, "Thread ID=%d shutting down...\n", queue->tid);

    return 0;
}

void signal_quit()
{
    wlog(LOG_LVL0, "Shutting down...\n");
    quit = true;
}

void dns_init()
{
    struct hostent *rwhost;
    struct hostent *server;

    if(!strlen(config.rwhost))
        wquit("ERROR: rewrite host server variable is empty!\n");
                
    if(!strlen(config.serverdns))
        wquit("ERROR: main classification server variable is empty!\n");

    // resolve dns and copy address
    rwhost = dnslookup(config.rwhost);
    memcpy(&config.rwaddr, rwhost->h_addr, rwhost->h_length);

    server = dnslookup(config.serverdns);
    memcpy(&config.serveraddr[0], server->h_addr, server->h_length);
}

void startup()
{
    dns_init();
    cache_init();

#ifndef _NO_DATABASE
    log_init();
#endif

    memset(&queue, 0, sizeof(*queue));

    // init veredict thread mutex
    pthread_mutex_init(&veredict_mtx, NULL);

    for(int i=0; i<NUM_THREADS; i++)
    {
        queue[i].tid = i;
        queue[i].nfq = nfq_open();

        if(!curl_init(&queue[i], false))
            wquit("Failed to initialize curl!\n");

        if(!queue[i].nfq)
            wquit("error during nfq_open()\n");

        if(nfq_unbind_pf(queue[i].nfq, AF_INET)<0)
            wquit("error during nfq_unbind_pf()\n");

        if(nfq_bind_pf(queue[i].nfq, AF_INET)<0)
            wquit("error during nfq_bind_pf()\n");

        // create a new queue
        queue[i].nfq_q = nfq_create_queue(queue[i].nfq, i, &queue_callback, (void *)&queue[i]);
        if(!queue[i].nfq_q)
            wquit("error during nfq_create_queue()\n");

        if(nfq_set_mode(queue[i].nfq_q, NFQNL_COPY_PACKET, 0xffff)<0)
            wquit("cannot set packet_copy mode\n");

        // create thread and pass its queue block
        if(pthread_create(&thread[i], NULL, worker, (void *)&queue[i]))
            wquit("pthread_create() failed\n");
    }

    // main code loop
    while(!quit)
    {
        static uint32_t cnt = 1;
        static uint32_t pkts, pps1 = 0;
        static float pps2;

        if(cnt++ %60==0)
        {
            wlog(LOG_LVL1, "Cache status:\n");
            wlog(LOG_LVL1, "<----------->\n");
            cache_statistics();

            wlog(LOG_LVL1, "Thread status:\n");
            wlog(LOG_LVL1, "<----------->\n");
            for(int i=0; i<NUM_THREADS; i++)
            {
                pkts=queue[i].packets;
                wlog(LOG_LVL1, "thread %d packets: %lu\n", i, pkts);
                pps1+=pkts;
            }

            pps2 = (pps1/cnt);

            wlog(LOG_LVL1, "Average thread packets: %0.2f\n", pps2);
        }

        sleep(1);
    }
    // end main code loop

    for(int i = 0; i<NUM_THREADS; i++)
    {
        void *res;

        // cancel active threads
        pthread_cancel(thread[i]);
        pthread_join(thread[i], &res);

        if(res==PTHREAD_CANCELED)
            wlog(LOG_LVL3, "Thread %d stopped successfully!\n", i);

        // close nfqueue handlers
        nfq_destroy_queue(queue[i].nfq_q);
        nfq_close(queue[i].nfq);

        wlog(LOG_LVL3, "Closed nfqueue socket %d\n", i);
    }

#ifndef _NO_DATABASE
    log_close();
#endif
    cache_flush();
}

int main(int argc, char** argv)
{
    pid_t pid, sid;
    int c;

    // initialize linked lists
    acl_init();
    init_config();

    while((c = getopt(argc, argv, "f:hv"))!=-1)
    {
        switch (c)
        {
            case 'f':
                strncpy(config.filename, optarg, sizeof(config.filename));
                break;
            case 'h':
                fprintf(stdout, "Usage: [-f config-file] [-h] [-v]\n");
                exit(EXIT_SUCCESS);
            case 'v':
                fprintf(stdout, "DNSfilter Version %s\n", VERSION);
                fprintf(stdout, "Copyright 2015 Cassiano Martin <cassiano@polaco.pro.br>");
                exit(EXIT_SUCCESS);
            default:
                abort();
        }
    }

    // read configuration file
    parse_config();

#ifndef _NO_PRIVDROP
    // drop all caps first
    drop_capabilities();
#endif

    wlog(LOG_LVL0, "DNSfilter starting up...\n");

    signal(SIGINT, signal_quit);
    signal(SIGTERM, signal_quit);
    //signal(SIGPIPE, SIG_IGN);

    if(config.daemon)
    {
        pid = fork();
        if(pid < 0)
            wquit("\n fork() failed\n");

        if(pid > 0)
            exit(EXIT_SUCCESS);

        umask(0);
                
        sid = setsid();
        if(sid < 0)
            wquit("\n setsid() failed\n");
        
        if((chdir("/")) < 0)
            wquit("\n chdir() failed\n");
        
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    startup();

    return(EXIT_SUCCESS);
}