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

    /* Check dict: rc_dict_getattr() (numeric lookup) and rc_dict_findattr()
     * (name lookup) must both resolve every rc_dict_addattr()'d entry, and
     * must agree with each other -- the pointer returned by each call is a
     * lazily-materialized, cached shim shadow (lib/dict.c), so calling
     * either twice for the same entry must also return the identical
     * pointer, not a fresh allocation each time. */
    for (int i = 0; i < sizeof(entries)/sizeof(entries[0]); ++i)
    {
        DICT_ATTR *by_id, *by_name;

        if ((by_id = rc_dict_getattr(rh, entries[i].val)) == NULL)
        {
            printf("ERROR: rc_dict_getattr() could not find attribute %s.\n", entries[i].name);
            rc_destroy(rh);
            exit(1);
        }
        if (by_id->value != (uint64_t)entries[i].val || by_id->type != entries[i].type)
        {
            printf("ERROR: Wrong attribute %s.\n", entries[i].name);
            rc_destroy(rh);
            exit(1);
        }

        if ((by_name = rc_dict_findattr(rh, entries[i].name)) == NULL)
        {
            printf("ERROR: rc_dict_findattr() could not find attribute %s.\n", entries[i].name);
            rc_destroy(rh);
            exit(1);
        }
        if (by_name != by_id)
        {
            printf("ERROR: rc_dict_getattr()/rc_dict_findattr() returned different "
                   "pointers for the same attribute %s (shim cache not stable).\n",
                   entries[i].name);
            rc_destroy(rh);
            exit(1);
        }

        if (rc_dict_getattr(rh, entries[i].val) != by_id)
        {
            printf("ERROR: rc_dict_getattr() returned a different pointer on a "
                   "second call for %s (shim cache not stable).\n", entries[i].name);
            rc_destroy(rh);
            exit(1);
        }
    }

    /* rc_dict_addattr() with a non-zero vendorspec, and rc_dict_addvend():
     * neither is exercised anywhere else, so a vendor-scoped attribute
     * lookup regression in the shim would otherwise go unnoticed. */
    {
        DICT_VENDOR *vend;
        DICT_ATTR *vattr;

        if (rc_dict_addvend(rh, "Test-Vendor", 99999) == NULL)
        {
            printf("ERROR: Can not add vendor Test-Vendor.\n");
            rc_destroy(rh);
            exit(1);
        }
        if (rc_dict_addattr(rh, "Test-Vendor-Attr", 1, PW_TYPE_STRING, 99999) == NULL)
        {
            printf("ERROR: Can not add vendor-scoped attribute Test-Vendor-Attr.\n");
            rc_destroy(rh);
            exit(1);
        }

        if ((vend = rc_dict_findvend(rh, "test-vendor")) == NULL || vend->vendorpec != 99999)
        {
            printf("ERROR: rc_dict_findvend() (case-insensitive) did not resolve Test-Vendor.\n");
            rc_destroy(rh);
            exit(1);
        }
        if (rc_dict_getvend(rh, 99999) != vend)
        {
            printf("ERROR: rc_dict_getvend() did not agree with rc_dict_findvend() for Test-Vendor.\n");
            rc_destroy(rh);
            exit(1);
        }
        if (rc_dict_findvend(rh, "No-Such-Vendor") != NULL)
        {
            printf("ERROR: rc_dict_findvend() matched a vendor that was never added.\n");
            rc_destroy(rh);
            exit(1);
        }

        if ((vattr = rc_dict_getattr(rh, RADCLI_VENDOR_ATTR_SET(1, 99999))) == NULL ||
            VENDOR(vattr->value) != 99999 || ATTRID(vattr->value) != 1)
        {
            printf("ERROR: rc_dict_getattr() did not resolve the vendor-scoped attribute "
                   "by its RADCLI_VENDOR_ATTR_SET()-combined id.\n");
            rc_destroy(rh);
            exit(1);
        }
        if (rc_dict_findattr(rh, "Test-Vendor-Attr") != vattr)
        {
            printf("ERROR: rc_dict_findattr() did not agree with rc_dict_getattr() for "
                   "the vendor-scoped attribute.\n");
            rc_destroy(rh);
            exit(1);
        }
    }

    /* rc_dict_addval()/rc_dict_findval()/rc_dict_getval(): the third leg of
     * the programmatic API, otherwise untested anywhere in the suite. */
    {
        DICT_VALUE *val;

        if (rc_dict_addval(rh, "Service-Type", "Login-User", 1) == NULL)
        {
            printf("ERROR: Can not add value Login-User.\n");
            rc_destroy(rh);
            exit(1);
        }
        if (rc_dict_addval(rh, "Service-Type", "Framed-User", 2) == NULL)
        {
            printf("ERROR: Can not add value Framed-User.\n");
            rc_destroy(rh);
            exit(1);
        }

        if ((val = rc_dict_findval(rh, "login-user")) == NULL || val->value != 1 ||
            strcmp(val->attrname, "Service-Type") != 0)
        {
            printf("ERROR: rc_dict_findval() (case-insensitive) did not resolve Login-User.\n");
            rc_destroy(rh);
            exit(1);
        }

        /* rc_dict_getval() takes (value, attrname) -- the reverse order of
         * rc_dict_findval()'s single name argument -- and must resolve by
         * the (attribute, value) pair, not just the value, since two
         * different attributes can legitimately share a numeric value. */
        if (rc_dict_getval(rh, 1, "Service-Type") != val)
        {
            printf("ERROR: rc_dict_getval() did not agree with rc_dict_findval() for "
                   "Login-User (or shim cache not stable).\n");
            rc_destroy(rh);
            exit(1);
        }
        if (rc_dict_getval(rh, 1, "No-Such-Attribute") != NULL)
        {
            printf("ERROR: rc_dict_getval() matched a value under the wrong attribute name.\n");
            rc_destroy(rh);
            exit(1);
        }
        if (rc_dict_getval(rh, 2, "Service-Type") == NULL)
        {
            printf("ERROR: rc_dict_getval() could not find Framed-User (value 2).\n");
            rc_destroy(rh);
            exit(1);
        }
    }

    /* rc_dict_free(): every rc_dict_addattr()/addval()/addvend()'d entry
     * above must become unreachable, and the handle must still accept a
     * fresh rc_dict_addattr() afterwards (rh->dict is recreated lazily). */
    rc_dict_free(rh);

    if (rc_dict_findattr(rh, "User-Name") != NULL)
    {
        printf("ERROR: rc_dict_findattr() still resolved User-Name after rc_dict_free().\n");
        rc_destroy(rh);
        exit(1);
    }
    if (rc_dict_findvend(rh, "Test-Vendor") != NULL)
    {
        printf("ERROR: rc_dict_findvend() still resolved Test-Vendor after rc_dict_free().\n");
        rc_destroy(rh);
        exit(1);
    }
    if (rc_dict_findval(rh, "Login-User") != NULL)
    {
        printf("ERROR: rc_dict_findval() still resolved Login-User after rc_dict_free().\n");
        rc_destroy(rh);
        exit(1);
    }

    if (rc_dict_addattr(rh, "Post-Free-Attr", 1, PW_TYPE_STRING, 0) == NULL)
    {
        printf("ERROR: rc_dict_addattr() failed after rc_dict_free() (rh->dict not "
               "recreated lazily).\n");
        rc_destroy(rh);
        exit(1);
    }
    if (rc_dict_findattr(rh, "Post-Free-Attr") == NULL)
    {
        printf("ERROR: rc_dict_findattr() could not find an attribute added after "
               "rc_dict_free().\n");
        rc_destroy(rh);
        exit(1);
    }

    rc_destroy(rh);

    exit(0);
}
