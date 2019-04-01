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

#ifndef _NO_PRIVDROP

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <grp.h>
#include <pwd.h>
#include <cap-ng.h>

#include "privs.h"
#include "config.h"
#include "utils.h"

static int cap_get_guid(char *user_name, char *group_name, unsigned int *uid, unsigned int *gid)
{
    unsigned int userid = 0;
    unsigned int groupid = 0;

    struct passwd *pw;

    /* Get the user ID */
    if(isdigit((unsigned char)user_name[0])!=0)
    {
        userid = atoi(user_name);
        pw = getpwuid(userid);
        if(pw==NULL)
            wquit("unable to get the user %s, check if user exist!!\n", user_name);
    }
    else
    {
        pw = getpwnam(user_name);
        if(pw==NULL)
            wquit("unable to get the user %s, check if user exist!!\n", user_name);

        userid = pw->pw_uid;
    }

    /* Get the group ID */
    if(group_name!=NULL)
    {
        struct group *gp;

        if(isdigit((unsigned char)group_name[0])!=0)
        {
            groupid = atoi(group_name);
        }
        else
        {
            gp = getgrnam(group_name);
            if(gp==NULL)
                wquit("unable to get the group ID, check if group exist!!\n");

            groupid = gp->gr_gid;
        }
    }
    else
    {
        groupid = pw->pw_gid;
    }

    endgrent();
    endpwent();

    *uid = userid;
    *gid = groupid;

    return 0;
}

static int cap_get_gid(char *group_name, unsigned int *gid)
{
    unsigned int grpid = 0;
    struct group *gp;

    if(isdigit((unsigned char)group_name[0])!=0)
    {
        grpid = atoi(group_name);
    }
    else
    {
        gp = getgrnam(group_name);
        if(gp==NULL)
            wquit("unable to get the group ID, check if group exist!!\n");

        grpid = gp->gr_gid;
    }

    endgrent();

    *gid = grpid;

    return 0;
}

void drop_capabilities()
{
    unsigned int userid = 0;
    unsigned int groupid = 0;

    capng_clear(CAPNG_SELECT_BOTH);
    capng_updatev(CAPNG_ADD, CAPNG_EFFECTIVE|CAPNG_PERMITTED, CAP_NET_ADMIN, -1);

    cap_get_guid(config.user, config.group, &userid, &groupid);

    if(capng_change_id(userid, groupid, CAPNG_DROP_SUPP_GRP|CAPNG_CLEAR_BOUNDING)<0)
        wquit("Failed to change user/group id!\n");

    capng_apply(CAPNG_SELECT_BOTH);

    wlog(LOG_LVL2, "Dropped root capabilities. Running as user %s, group %s\n", config.user, config.group);
}

#endif