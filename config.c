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
#include <string.h>
#include <stdlib.h>
#include <netdb.h>

#include "config.h"
#include "utils.h"
#include "acl.h"

config_t config;

#define read_bool(x) (!strncmp(x,"true",4)?1:0)
#define IFIS(x,str) if(!memcmp(x,str,sizeof(str)-1))

void init_config()
{
    // reset and set default config file path
    memset(&config, 0, sizeof(config_t));
    strlcpy(config.filename, "/etc/dnsfilter.conf", sizeof(config.filename));
}

bool parse_config()
{
    char line[512];
    char *p;
    char *param;
    int i;
    FILE *f;

    fprintf(stdout, "Parsing configuration file: %s\n", config.filename);

    f = fopen(config.filename, "r");
    if(f!=NULL)
    {
        while(!feof(f))
        {
            *line = 0;
            fgets(line, 512, f);

            i = strlen(line);
            if(line[i-1]=='\n') line[i-1] = 0;

            p = line;
            while(*p)
            {
                if(p[0]=='#')
                {
                    p[0] = 0;
                    break;
                }
                p++;
            }

            p = line;
            while(*p<=' '&& *p) p++;
            if(!*p) continue;
            param = line;

            while(*param && *param!=' ') param++;
            if(*param) param++;

            IFIS(line, "user") strlcpy(config.user, param, sizeof(config.user));
            IFIS(line, "group") strlcpy(config.group, param, sizeof(config.group));
            IFIS(line, "license") strlcpy(config.license, param, sizeof(config.license));
            IFIS(line, "logfile") strlcpy(config.logfile, param, sizeof(config.logfile));
            IFIS(line, "report_database") strlcpy(config.reportdb, param, sizeof(config.reportdb));
            IFIS(line, "cache_database") strlcpy(config.cachedb, param, sizeof(config.cachedb));
            IFIS(line, "loglevel") config.loglevel = atoi(param);
            IFIS(line, "daemon") config.daemon = read_bool(param);
            IFIS(line, "threads") config.threads = atoi(param);
            IFIS(line, "acl") parse_acl(param);
            IFIS(line, "resolv_retry") config.tries = atoi(param);
            IFIS(line, "rewrite_host") strlcpy(config.rwhost, param, sizeof(config.rwhost));
            IFIS(line, "cfs_server") strlcpy(config.serverdns, param, sizeof(config.serverdns));
        }

        if(strlen(config.license)!=40)
        {
            config.validlicense = false;
            fprintf(stdout, "License code is not valid %s!\n", config.license);
        }
        else
            config.validlicense = true;
    }
    else
        wquit("FATAL: Could not read configuration file %s!\n", config.filename);

    return 0;
}
