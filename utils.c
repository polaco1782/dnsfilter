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
#include <stdarg.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "config.h"
#include "utils.h"

void wlog(int level, char *txt, ...)
{
    static FILE *logfile;
    static char buf[512];
    va_list argp;

    if(config.loglevel>=level || level==LOG_ERROR)
    {
        if(!logfile && config.daemon)
        {
            logfile=fopen(config.logfile, "wt");
            if(!logfile)
            {
                fprintf(stderr, "Could not open log file [%s] for writing!\n",config.logfile);
                exit(EXIT_FAILURE);
            }
        }

        va_start(argp, txt);
        vsprintf(buf, txt, argp);

        if(config.daemon)
        {
            //fputs(buf, logfile);
            fprintf(logfile, "L%d: %s", level, buf);
            fflush(logfile);
        }
        else
        {
            if(level==LOG_ERROR)
            {
                fprintf(stderr, "L%d: %s", level, buf);
                fflush(stderr);
            }
            else
            {
                fprintf(stdout, "L%d: %s", level, buf);
                fflush(stdout);
            }
        }
    }
}

void wquit(char *txt, ...)
{
    static char buf[512];
    va_list argp;

    va_start(argp, txt);
    vsprintf(buf, txt, argp);

    wlog(LOG_ERROR, buf);

    exit(EXIT_FAILURE);
}

struct hostent *dnslookup(char *host)
{
    struct hostent *he;
    struct in_addr **addr_list;

    for(int i=0; ;i++)
    {
        // code needs some rewrite, as gethostbyname uses a static buffer
        he = gethostbyname(host);

        if(he == NULL)
        {
            if(i > config.tries && config.tries != 0)
                wquit("Could not resolve hostname [%s]!\n", host);
            else
                wlog(LOG_LVL1, "Failed to resolve [%s] IP address, retrying...\n", host);
        }
        else
            break;

        sleep(5);
    }

    addr_list = (struct in_addr **)he->h_addr_list;
    for(int i = 0; addr_list[i] != NULL; i++)
        wlog(LOG_LVL1, "Host address found: %s\n", inet_ntoa(*addr_list[i]));

    wlog(LOG_LVL1, "Resolved hostname [%s] to ip address %s\n", host, inet_ntoa(*(struct in_addr *)he->h_addr));

    // return all available hosts
    return he;
}

/*
 * Copy string src to buffer dst of size dsize.  At most dsize-1
 * chars will be copied.  Always NUL terminates (unless dsize == 0).
 * Returns strlen(src); if retval >= dsize, truncation occurred.
 */
size_t strlcpy(char *dst, const char *src, size_t dsize)
{
    const char *osrc = src;
    size_t nleft = dsize;

    /* Copy as many bytes as will fit. */
    if(nleft != 0)
    {
        while(--nleft != 0)
        {
            if((*dst++ = *src++) == '\0')
                break;
        }
    }

    /* Not enough room in dst, add NUL and traverse rest of src. */
    if(nleft == 0)
    {
        if(dsize != 0)
            *dst = '\0'; /* NUL-terminate dst */
        while(*src++)
            ;
    }

    return (src - osrc - 1); /* count does not include NUL */
}

/*
 * Appends src to string dst of size dsize (unlike strncat, dsize is the
 * full size of dst, not space left).  At most dsize-1 characters
 * will be copied.  Always NUL terminates (unless dsize <= strlen(dst)).
 * Returns strlen(src) + MIN(dsize, strlen(initial dst)).
 * If retval >= dsize, truncation occurred.
 */
size_t strlcat(char *dst, const char *src, size_t dsize)
{
    const char *odst = dst;
    const char *osrc = src;
    size_t n = dsize;
    size_t dlen;

    /* Find the end of dst and adjust bytes left but don't go past end. */
    while(n-- != 0 && *dst != '\0')
        dst++;
    dlen = dst - odst;
    n = dsize - dlen;

    if(n-- == 0)
        return (dlen + strlen(src));
    while(*src != '\0')
    {
        if(n != 0)
        {
            *dst++ = *src;
            n--;
        }
        src++;
    }
    *dst = '\0';

    return (dlen + (src - osrc)); /* count does not include NUL */
}
