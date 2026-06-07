/*
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
 * Copyright (C) 2015 Nikos Mavrogiannopoulos
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 *
 */

#include	<config.h>
#include	<stdio.h>
#include	<syslog.h>
#include	<radcli/radcli.h>

int
main (int argc, char **argv)
{
	int             result;
	char		username[128];
	char            passwd[AUTH_PASS_LEN + 1];
	VALUE_PAIR 	*send = NULL, *received = NULL;
	uint32_t	service;
	rc_handle	*rh;

	/* openlog() sets the syslog identity used by radcli's internal messages */
	openlog("my-prog-name", LOG_PID, LOG_DAEMON);

	if ((rh = rc_read_config(RC_CONFIG_FILE)) == NULL)
		return ERROR_RC;

	snprintf(username, sizeof(username), "my-username");
	snprintf(passwd,   sizeof(passwd),   "my-password");

	/*
	 * Fill in User-Name
	 */
	if (rc_avpair_add(rh, &send, PW_USER_NAME, username, -1, 0) == NULL) {
		rc_destroy(rh);
		return ERROR_RC;
	}

	/*
	 * Fill in User-Password
	 */
	if (rc_avpair_add(rh, &send, PW_USER_PASSWORD, passwd, -1, 0) == NULL) {
		rc_avpair_free(send);
		rc_destroy(rh);
		return ERROR_RC;
	}

	/*
	 * Fill in Service-Type
	 */
	service = PW_AUTHENTICATE_ONLY;
	if (rc_avpair_add(rh, &send, PW_SERVICE_TYPE, &service, -1, 0) == NULL) {
		rc_avpair_free(send);
		rc_destroy(rh);
		return ERROR_RC;
	}

	result = rc_auth(rh, 0, send, &received, NULL);

	if (result == OK_RC) {
		VALUE_PAIR *vp = received;
		char name[128];
		char value[128];

		fprintf(stderr, "\"%s\" RADIUS Authentication OK\n", username);

		/* print the known attributes in the reply */
		while(vp != NULL) {
			if (rc_avpair_tostr(rh, vp, name, sizeof(name), value, sizeof(value)) == 0) {
				fprintf(stderr, "%s:\t%s\n", name, value);
			}
			vp = rc_avpair_next(vp);
		}
	} else {
		fprintf(stderr, "\"%s\" RADIUS Authentication failure (RC=%i)\n", username, result);
	}

	rc_avpair_free(send);
	rc_avpair_free(received);
	rc_destroy(rh);

	return result;
}
