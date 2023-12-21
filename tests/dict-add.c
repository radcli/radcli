/*
 * Copyright (c) 2020 Igor Mineev <igron99@mail.ru>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <stdlib.h>
#include <sys/types.h>
#include <syslog.h>
#include <radcli/radcli.h>
#include <string.h>

#define AUTH_PORT_PASSWORD ":1812:testing123"
#define SERVER_ADDR "localhost"

int
main (int argc, char **argv)
{
    rc_handle 	*rh = NULL;

    char		auth_server_ip[255] = {0};
    char		*server_ip = NULL;

    if(argc > 2)
    {
        printf("ERROR: Invalid number of arguments.\n");
        exit(1);
    }

    if (argc == 2)
        server_ip = argv[1];
    else
        server_ip = NULL;

    /* Initialize the 'rh' structure */

    rh = rc_new();
    if (rh == NULL)
    {
        printf("ERROR: Failed to allocate initial structure\n");
        exit(1);
    }

    /* Initialize the config structure */

    rh = rc_config_init(rh);
    if (rh == NULL)
    {
        printf("ERROR: Failed to initialize configuration\n");
        exit(1);
    }

    /*
     * Set the required options for configuration
     */

    if (rc_add_config(rh, "radius_retries", "3", "config", 0) != 0)
    {
        printf("ERROR: Unable to set radius_retries.\n");
        rc_destroy(rh);
        exit(1);
    }

    if (rc_add_config(rh, "radius_timeout", "5", "config", 0) != 0)
    {
        printf("ERROR: Unable to set radius_timeout.\n");
        rc_destroy(rh);
        exit(1);
    }

    /* auth/acct servers are added in the form: host[:port[:secret]]
     * If you don't set the secret via the add_config option, you must set a 'servers'
     * entry to specify the location of the 'servers' file which stores the secrets to
     * be used.
     */
    /* If the IP Address is provided via Command-line, take it for processing. Else,
     * use localhost as default.
     */
    if(server_ip == NULL)
        server_ip = SERVER_ADDR;

    snprintf(auth_server_ip, sizeof(auth_server_ip), "%s%s", server_ip,
             AUTH_PORT_PASSWORD);

    if (rc_add_config(rh, "authserver", auth_server_ip, "config", 0) != 0)
    {
        printf("ERROR: Unable to set authserver.\n");
        rc_destroy(rh);
        exit(1);
    }

    /* Done setting configuration items */

    /* Make dictionary */

    struct Entry {
        const char * name;
        int val;
        int type;
    } entries[] = {
            {"User-Name", 1, PW_TYPE_STRING},
            {"Password", 2, PW_TYPE_STRING},
            {"NAS-IP-Address", 4, PW_TYPE_IPADDR},
            {"NAS-Port-Id", 5, PW_TYPE_INTEGER},
            {"Service-Type", 6, PW_TYPE_INTEGER},
            {"Reply-Message", 18, PW_TYPE_STRING},
            {"State", 24, PW_TYPE_STRING},
    };

    for (int i = 0; i < sizeof(entries)/sizeof(entries[0]); ++i)
    {
        if (rc_dict_addattr(rh, entries[i].name, entries[i].val, entries[i].type, 0) == NULL)
        {
            printf("ERROR: Can not add attribute %s.\n", entries[i].name);
            rc_destroy(rh);
            exit(1);
        }
    }

    DICT_ATTR *attr;
    /* Check dict */
    for (int i = 0; i < sizeof(entries)/sizeof(entries[0]); ++i)
    {
        if ((attr = rc_dict_getattr(rh, entries[i].val)) != 0)
        {
            if (attr->value != entries[i].val || attr->type != entries[i].type)
            {
                printf("ERROR: Wrong attribute %s.\n", entries[i].name);
                rc_destroy(rh);
                exit(1);
            }
        }
    }

    rc_destroy(rh);

    exit(0);
}
