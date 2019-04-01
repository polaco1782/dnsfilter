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
 * File:   dns.h
 * Author: cassiano
 *
 * Created on August 27, 2015, 11:01 AM
 */

#include <stdint.h>

#ifndef DNS_H
#define	DNS_H

#ifdef	__cplusplus
extern "C" {
#endif

// structs for the DNS protocol
struct dnsflags
{
    uint16_t rd : 1;
    uint16_t tc : 1;
    uint16_t aa : 1;
    uint16_t opcode : 4;
    uint16_t qr : 1;

    uint16_t rcode : 4;
    uint16_t z : 3;
    uint16_t ra : 1;
};

struct dnshdr
{
    uint16_t txid;
    struct dnsflags dns_flags;
    uint16_t questions;
    uint16_t answer_rrs;
    uint16_t authority_rrs;
    uint16_t additional_rrs;
};

struct dnstype
{
    uint16_t type;
    uint16_t cls;
};

struct dnsanswer
{
    uint16_t name;
    struct dnstype qtype;
    uint16_t pad;
    uint16_t ttl;
    uint16_t len;
};


#ifdef	__cplusplus
}
#endif

#endif	/* DNS_H */

