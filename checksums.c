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
 * File:   checksums.c
 * Author: cassiano
 *
 * Created on August 25, 2015, 2:55 PM
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* Compute checksum for count bytes starting at addr, using one's complement of one's complement sum*/
static uint16_t compute_checksum(uint16_t *addr, unsigned int count)
{
    register unsigned long sum = 0;
    while(count>1)
    {
        sum += *addr++;
        count -= 2;
    }
    if(count>0)
    {
        sum += ((*addr)&htons(0xFF00));
    }
    while(sum>>16)
    {
        sum = (sum&0xffff) + (sum>>16);
    }

    sum = ~sum;
    return((uint16_t)sum);
}

/* set ip checksum of a given ip header*/
void compute_ip_checksum(struct iphdr* iphdrp)
{
    iphdrp->check = 0;
    iphdrp->check = compute_checksum((uint16_t*)iphdrp, iphdrp->ihl<<2);
}

void compute_tcp_checksum(struct iphdr *pIph, uint16_t *ipPayload)
{
    register unsigned long sum = 0;
    uint16_t tcpLen = ntohs(pIph->tot_len) - (pIph->ihl<<2);
    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);

    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(tcpLen);

    tcphdrp->check = 0;
    while(tcpLen>1)
    {
        sum += *ipPayload++;
        tcpLen -= 2;
    }
    if(tcpLen>0)
        sum += ((*ipPayload)&htons(0xFF00));

    while(sum>>16)
    {
        sum = (sum&0xffff) + (sum>>16);
    }

    sum = ~sum;
    tcphdrp->check = (uint16_t)sum;
}

/* set tcp checksum: given IP header and UDP datagram */
void compute_udp_checksum(struct iphdr *pIph, uint16_t *ipPayload)
{
    register unsigned long sum = 0;
    struct udphdr *udphdrp = (struct udphdr*)(ipPayload);
    uint16_t udpLen = htons(udphdrp->len);

    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    sum += htons(IPPROTO_UDP);
    sum += udphdrp->len;

    udphdrp->check = 0;
    while(udpLen>1)
    {
        sum += *ipPayload++;
        udpLen -= 2;
    }

    if(udpLen>0)
        sum += ((*ipPayload)&htons(0xFF00));

    while(sum>>16)
    {
        sum = (sum&0xffff) + (sum>>16);
    }

    sum = ~sum;
    udphdrp->check = ((uint16_t)sum==0x0000)?0xFFFF:(uint16_t)sum;
}
