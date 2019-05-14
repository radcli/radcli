/*
 * radchallenge.c - a sample c program showing how to embed the configuration of a radius and to challenge
 * client, using the FreeRADIUS Client Library without an external configuration and dictionary file .
 */

#include <stdlib.h>
#include <sys/types.h>
#include <syslog.h>
#include <radcli/radcli.h>
#include <string.h>

#define AUTH_PORT_PASSWORD ":1812:testing123"
#define ACCT_PORT_PASSWORD ":1813:testing123"
#define SERVER_ADDR "localhost"

int
main (int argc, char **argv)
{
    int		retval = 0;
    rc_handle 	*rh = NULL;
    uint32_t 	client_port = 0;
    uint32_t	status_type = PW_STATUS_STOP;
    VALUE_PAIR      *send = NULL;
    VALUE_PAIR      *received = NULL;

/*
	VALUE_PAIR 	*vp = NULL;
	DICT_VALUE 	*dval = NULL;
*/
    char		username[255] = "bob@somedomain.here";
    char		password[255] = "MegaSecretPassword777";
    char		state[255]    = "StateFromPreviousResponse";
    char		callfrom[255] = "8475551212";
    char		callto[255] = "8479630116";
    char		myuuid[255] = "981743-asdf-90834klj234";
    char		auth_server_ip[255] = {0};
    char		acct_server_ip[255] = {0};
    char		*server_ip = NULL;

    int use_state = 0;

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
        printf("ERROR: Failed to initialze configuration\n");
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

    if (rc_dict_addattr(rh, "User-Name", 1, PW_TYPE_STRING, 0) == NULL)
    {
        printf("ERROR: Can not add attribute User-Name.\n");
        rc_destroy(rh);
        exit(1);
    }
    if (rc_dict_addattr(rh, "Password", 2, PW_TYPE_STRING, 0) == NULL)
    {
        printf("ERROR: Can not add attribute Password.\n");
        rc_destroy(rh);
        exit(1);
    }
    if (rc_dict_addattr(rh, "NAS-IP-Address", 4, PW_TYPE_IPADDR, 0) == NULL)
    {
        printf("ERROR: Can not add attribute NAS-IP-Address.\n");
        rc_destroy(rh);
        exit(1);
    }
    if (rc_dict_addattr(rh, "NAS-Port-Id", 5, PW_TYPE_INTEGER, 0) == NULL)
    {
        printf("ERROR: Can not add attribute NAS-Port-Id.\n");
        rc_destroy(rh);
        exit(1);
    }
    if (rc_dict_addattr(rh, "Service-Type", 6, PW_TYPE_INTEGER, 0) == NULL)
    {
        printf("ERROR: Can not add attribute Service-Type.\n");
        rc_destroy(rh);
        exit(1);
    }
    if (rc_dict_addattr(rh, "Reply-Message", 18, PW_TYPE_STRING, 0) == NULL)
    {
        printf("ERROR: Can not add attribute Password.\n");
        rc_destroy(rh);
        exit(1);
    }
    if (rc_dict_addattr(rh, "State", 24, PW_TYPE_STRING, 0) == NULL)
    {
        printf("ERROR: Can not add attribute Password.\n");
        rc_destroy(rh);
        exit(1);
    }

    /* Initialize socket related info in RADIUS Handle */
    if (rc_apply_config(rh) == -1)
    {
        printf("ERROR: Failed to update Radius handle socket info");
        exit(1);
    }

    if (rc_avpair_add(rh, &send, PW_USER_NAME, username, -1, 0) == NULL)
    {
        printf("ERROR: Failed adding User-Name: to %s\n", username);
        exit(1);
    }
    if (rc_avpair_add(rh, &send, PW_USER_PASSWORD, password, -1, 0) == NULL)
    {
        printf("ERROR: Failed adding Password: to %s\n", password);
        exit(1);
    }
    if (use_state)
    {
        if (rc_avpair_add(rh, &send, PW_STATE, state, -1, 0) == NULL) {
            printf("ERROR: Failed adding State: to %s\n", state);
            exit(1);
        }
    }
    uint32_t service = PW_AUTHENTICATE_ONLY;
    if (rc_avpair_add(rh, &send, PW_SERVICE_TYPE, &service, sizeof(service), 0) == NULL)
    {
        printf("ERROR: Failed adding Service-Type: to %u\n", service);
        exit(1);
    }

    int result = rc_auth(rh, 0, send, &received, nullptr);

    if(result == OK_RC)
    {
        printf("INFO: Auth OK: %s\n", username);
        retval = 0;
    }
    else if (result == CHALLENGE_RC)
    {
        printf("INFO: Auth challenge: %s\n", username);
        retval = 0;
    }
    else
    {
        printf("INFO: Auth Failed: %s\n", username);
        retval = -1;
    }
    rc_destroy(rh);
    rc_avpair_free(send);
    rc_avpair_free(received);

    exit(retval);
}
