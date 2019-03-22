/*
 * radembedded_dict.c - a sample c program showing how to embed the 
 * configuration of a radius client, using the RADIUS Client Library 
 * without an external configuration file and external dictionary file.
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
	rc_handle	*rh = NULL;
	uint32_t	client_port = 0;
	uint32_t	status_type = PW_STATUS_STOP;
	VALUE_PAIR	*send = NULL;
	char		username[255] = "bob@somedomain.here";
	char		callfrom[255] = "8475551212";
	char		callto[255] = "8479630116";
	char		myuuid[255] = "981743-asdf-90834klj234";
	char		auth_server_ip[255] = {0};
	char		acct_server_ip[255] = {0};
	char		*server_ip = NULL;                                                               
	char		dict_buffer[] = 
		"ATTRIBUTE	User-Name		1	string\n"
		"ATTRIBUTE	Password		2	string\n"
		"ATTRIBUTE	CHAP-Password		3	string\n"
		"ATTRIBUTE	NAS-IP-Address		4	ipv4addr\n"
		"ATTRIBUTE	NAS-Port-Id		5	integer\n"
		"ATTRIBUTE	Service-Type		6	integer\n"
		"ATTRIBUTE	Framed-Protocol		7	integer\n"
		"ATTRIBUTE	Framed-IP-Address	8	ipv4addr\n"
		"ATTRIBUTE	Framed-IP-Netmask	9	ipv4addr\n"
		"ATTRIBUTE	Framed-Routing		10	integer\n"
		"ATTRIBUTE	Filter-Id		11	string\n"
		"ATTRIBUTE	Framed-MTU		12	integer\n"
		"ATTRIBUTE	Framed-Compression	13	integer\n"
		"ATTRIBUTE	Login-IP-Host		14	ipv4addr\n"
		"ATTRIBUTE	Login-Service		15	integer\n"
		"ATTRIBUTE	Login-TCP-Port		16	integer\n"
		"ATTRIBUTE	Reply-Message		18	string\n"
		"ATTRIBUTE	Callback-Number		19	string\n"
		"ATTRIBUTE	Callback-Id		20	string\n"
		"ATTRIBUTE	Framed-Route		22	string\n"
		"ATTRIBUTE	Framed-IPX-Network	23	ipv4addr\n"
		"ATTRIBUTE	State			24	string\n"
		"ATTRIBUTE	Class			25	string\n"
		"ATTRIBUTE	Vendor-Specific		26	string\n"
		"ATTRIBUTE	Session-Timeout		27	integer\n"
		"ATTRIBUTE	Idle-Timeout		28	integer\n"
		"ATTRIBUTE	Termination-Action	29	integer\n"
		"ATTRIBUTE	Called-Station-Id	30	string\n"
		"ATTRIBUTE	Calling-Station-Id	31	string\n"
		"ATTRIBUTE	NAS-Identifier		32	string\n"
		"ATTRIBUTE	Proxy-State		33	string\n"
		"ATTRIBUTE	Login-LAT-Service	34	string\n"
		"ATTRIBUTE	Login-LAT-Node		35	string\n"
		"ATTRIBUTE	Login-LAT-Group		36	string\n"
		"ATTRIBUTE	Framed-AppleTalk-Link	37	integer\n"
		"ATTRIBUTE	Framed-AppleTalk-Network	38	integer\n"
		"ATTRIBUTE	Framed-AppleTalk-Zone	39	string\n"
		"ATTRIBUTE	Acct-Status-Type	40	integer\n"
		"ATTRIBUTE	Acct-Delay-Time		41	integer\n"
		"ATTRIBUTE	Acct-Input-Octets	42	integer\n"
		"ATTRIBUTE	Acct-Output-Octets	43	integer\n"
		"ATTRIBUTE	Acct-Session-Id		44	string\n"
		"ATTRIBUTE	Acct-Authentic		45	integer\n"
		"ATTRIBUTE	Acct-Session-Time	46	integer\n"
		"ATTRIBUTE	Acct-Input-Packets	47	integer\n"
		"ATTRIBUTE	Acct-Output-Packets	48	integer\n"
		"ATTRIBUTE	Acct-Terminate-Cause	49	integer\n"
		"ATTRIBUTE	Acct-Multi-Session-Id	50	string\n"
		"ATTRIBUTE	Acct-Link-Count		51	integer\n"
		"ATTRIBUTE	Acct-Input-Gigawords	52	integer\n"
		"ATTRIBUTE	Acct-Output-Gigawords	53	integer\n"
		"ATTRIBUTE	Event-Timestamp		55	integer\n"
		"ATTRIBUTE	Egress-VLANID		56	string\n"
		"ATTRIBUTE	Ingress-Filters		57	integer\n"
		"ATTRIBUTE	Egress-VLAN-Name	58	string\n"
		"ATTRIBUTE	User-Priority-Table	59	string\n"
		"ATTRIBUTE	CHAP-Challenge		60	string\n"
		"ATTRIBUTE	NAS-Port-Type		61	integer\n"
		"ATTRIBUTE	Port-Limit		62	integer\n"
		"ATTRIBUTE	Login-LAT-Port		63	integer\n"
		"ATTRIBUTE	Tunnel-Type		64	string\n"
		"ATTRIBUTE	Tunnel-Medium-Type	65	string\n"
		"ATTRIBUTE	Tunnel-Client-Endpoint	66	string\n"
		"ATTRIBUTE	Tunnel-Server-Endpoint	67	string\n"
		"ATTRIBUTE	Acct-Tunnel-Connection	68	string\n"
		"ATTRIBUTE	Tunnel-Password		69	string\n"
		"ATTRIBUTE	ARAP-Password		70	string\n"
		"ATTRIBUTE	ARAP-Features		71	string\n"
		"ATTRIBUTE	ARAP-Zone-Access	72	integer\n"
		"ATTRIBUTE	ARAP-Security		73	integer\n"
		"ATTRIBUTE	ARAP-Security-Data	74	string\n"
		"ATTRIBUTE	Password-Retry		75	integer\n"
		"ATTRIBUTE	Prompt			76	integer\n"
		"ATTRIBUTE	Connect-Info		77	string\n"
		"ATTRIBUTE	Configuration-Token	78	string\n"
		"ATTRIBUTE	EAP-Message		79	string\n"
		"ATTRIBUTE	Message-Authenticator	80	string\n"
		"ATTRIBUTE	Tunnel-Private-Group-ID	81	string\n"
		"ATTRIBUTE	Tunnel-Assignment-ID	82	string\n"
		"ATTRIBUTE	Tunnel-Preference	83	string\n"
		"ATTRIBUTE	ARAP-Challenge-Response	84	string\n"
		"ATTRIBUTE	Acct-Interim-Interval	85	integer\n"
		"ATTRIBUTE	Acct-Tunnel-Packets-Lost	86	integer\n"
		"ATTRIBUTE	NAS-Port-Id-String	87	string\n"
		"ATTRIBUTE	Framed-Pool		88	string\n"
		"ATTRIBUTE	Chargeable-User-Identity	89	string\n"
		"ATTRIBUTE	Tunnel-Client-Auth-ID	90	string\n"
		"ATTRIBUTE	Tunnel-Server-Auth-ID	91	string\n"
		"ATTRIBUTE	NAS-Filter-Rule		92	string\n"
		"ATTRIBUTE	Originating-Line-Info	94	string\n"
		"ATTRIBUTE	NAS-IPv6-Address	95	ipv6addr\n"
		"ATTRIBUTE	Framed-Interface-Id	96	string\n"
		"ATTRIBUTE	Framed-IPv6-Prefix	97	ipv6prefix\n"
		"ATTRIBUTE	Login-IPv6-Host		98	ipv6addr\n"
		"ATTRIBUTE	Framed-IPv6-Route	99	string\n"
		"ATTRIBUTE	Framed-IPv6-Pool	100	string\n"
		"ATTRIBUTE	Error-Cause		101	integer\n"
		"ATTRIBUTE	EAP-Key-Name		102	string\n";

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
	snprintf(acct_server_ip, sizeof(acct_server_ip), "%s%s", server_ip,
		 ACCT_PORT_PASSWORD);

	if (rc_add_config(rh, "authserver", auth_server_ip, "config", 0) != 0)                          
	{                                                                                               
		printf("ERROR: Unable to set authserver.\n");                                               
		rc_destroy(rh);                                                                             
		exit(1);                                                                                    
	}                                                                                               

	if (rc_add_config(rh, "acctserver", acct_server_ip, "config", 0) != 0)       
	{
	    printf("ERROR: Unable to set acctserver.\n");
	    rc_destroy(rh);
	    exit(1);
	}

	/* Done setting configuration items */

	/* Initialize the dictionary contents in radius handle from the buffer */

	if (rc_read_dictionary_from_buffer(rh, dict_buffer, sizeof(dict_buffer)) != 0)
	{
	    printf("ERROR: Failed to initialize radius dictionary\n");
	    exit(1);
	}
	if (rc_avpair_add(rh, &send, PW_ACCT_STATUS_TYPE, &status_type, -1, 0) == NULL)
	{
	    printf("ERROR: Failed adding Acct-Status-Type: to %d\n", status_type);
	    exit(1);
	}
	if (rc_avpair_add(rh, &send, PW_ACCT_SESSION_ID, myuuid, -1, 0) == NULL)
	{
	    printf("ERROR: Failed adding Acct-Session-ID: to %s\n", myuuid);
	    exit(1);
	}
	if (rc_avpair_add(rh, &send, PW_USER_NAME, username, -1, 0) == NULL)
	{
	    printf("ERROR: Failed adding User-Name: to %s\n", username);
	    exit(1);
	}
	if (rc_avpair_add(rh, &send, PW_CALLED_STATION_ID, callto, -1, 0) == NULL)
	{
	    printf("ERROR: Failed adding Called-Station-ID: to %s\n", callto);
	    exit(1);
	}
	if (rc_avpair_add(rh, &send, PW_CALLING_STATION_ID, callfrom, -1, 0) == NULL)
	{
	    printf("ERROR: Failed adding Calling-Station-ID: to %s\n", callfrom);
	    exit(1);
	}

	/* Initialize socket related info in RADIUS Handle */
	if (rc_apply_config(rh) == -1)
	{
	    printf("ERROR: Failed to update Radius handle socket info");
	    exit(1);
	}

	if(rc_acct(rh, client_port, send) == OK_RC)
	{
	    printf("INFO: Accounting OK: %s\n", username);
	    retval = 0;
	}
	else
	{
	    printf("INFO: Accounting Failed: %s\n", username);
	    retval = -1;
	}
	rc_destroy(rh);
	rc_avpair_free(send);

	exit(retval);
}
