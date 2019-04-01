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
 * File:   http.c
 * Author: cassiano
 *
 * Created on January 3, 2017, 2:24 PM
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <curl/curl.h>

#include "config.h"
#include "http.h"
#include "utils.h"

/*
 * 
 */

bool perform_lookup(queueinfo_t *qinfo, struct cache_t *entry, char *domain)
{
    CURLcode res;
    char *lookup;

    asprintf(&lookup, "%s/%s", config.license, domain);

    curl_easy_setopt(qinfo->handle, CURLOPT_POSTFIELDS, lookup);
    res = curl_easy_perform(qinfo->handle);

    free(lookup);

    if(res==CURLE_OK)
    {
        // copy response data
        entry->category = strdup(qinfo->data);
        return true;
    }
    else
    {
        // response from server has failed
        entry->category = (NULL);
        return false;
    }
}

size_t writefunc(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    queueinfo_t *mem = (queueinfo_t *)userp;

    if(realsize>=mem->size)
    {
        // grow buffer if necessary
        mem->data = realloc(mem->data, realsize+1);
        mem->size = realsize;
    }

    memcpy(mem->data, contents, realsize);
    mem->data[realsize] = 0;

    return realsize;
}

// create a new curl instance for each thread
bool curl_init(queueinfo_t *qinfo, bool reinit)
{
    char *buf;

    if(!reinit)
    {
        qinfo->handle = curl_easy_init();
        qinfo->data = (char *)malloc(1);
        qinfo->headers = NULL;
        qinfo->size = 0;

        if(qinfo->handle)
        {
            // each thread connect to a different server
            if(config.serveraddr[config.serveridx].s_addr == 0)
                config.serveridx = 0;

            asprintf(&buf, "http://%s:4080", inet_ntoa(config.serveraddr[config.serveridx++]));

            wlog(LOG_LVL3, "Server lookup URL: %s\n", buf);

            curl_easy_setopt(qinfo->handle, CURLOPT_VERBOSE, 0);
            curl_easy_setopt(qinfo->handle, CURLOPT_HEADER, 0);

            curl_easy_setopt(qinfo->handle, CURLOPT_NOSIGNAL, 1);

            curl_easy_setopt(qinfo->handle, CURLOPT_TCP_KEEPALIVE, 1);
            curl_easy_setopt(qinfo->handle, CURLOPT_TCP_KEEPIDLE, 120);
            curl_easy_setopt(qinfo->handle, CURLOPT_TCP_KEEPINTVL, 60);

            curl_easy_setopt(qinfo->handle, CURLOPT_SSL_VERIFYPEER, 0);
            curl_easy_setopt(qinfo->handle, CURLOPT_SSL_VERIFYHOST, 0);

            curl_easy_setopt(qinfo->handle, CURLOPT_FOLLOWLOCATION, 0);
            curl_easy_setopt(qinfo->handle, CURLOPT_URL, buf);
            curl_easy_setopt(qinfo->handle, CURLOPT_POST, 1);

            // timeout values
            curl_easy_setopt(qinfo->handle, CURLOPT_CONNECTTIMEOUT, 10);
            curl_easy_setopt(qinfo->handle, CURLOPT_TIMEOUT, 5);
            curl_easy_setopt(qinfo->handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
            curl_easy_setopt(qinfo->handle, CURLOPT_USERAGENT, "iDB WiFi");
            curl_easy_setopt(qinfo->handle, CURLOPT_WRITEFUNCTION, writefunc);
            curl_easy_setopt(qinfo->handle, CURLOPT_WRITEDATA, (void *)qinfo);

            qinfo->headers = curl_slist_append(qinfo->headers, "Content-Type: text/plain");
            curl_easy_setopt(qinfo->handle, CURLOPT_HTTPHEADER, qinfo->headers);

            free(buf);
            return true;
        }
    }
    else
    {
        if(config.serveraddr[config.serveridx].s_addr == 0)
            config.serveridx = 0;

        asprintf(&buf, "http://%s:4080", inet_ntoa(config.serveraddr[config.serveridx++]));

        wlog(LOG_LVL3, "Server lookup URL: %s\n", buf);

        curl_easy_setopt(qinfo->handle, CURLOPT_URL, buf);
        
        free(buf);
        return true;
    }

    return false;
}
