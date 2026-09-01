/*
 * Copyright (C) 1995,1996,1997,1998 Lars Fenneberg
 *
 * Copyright 1992 Livingston Enterprises, Inc.
 *
 * Copyright 1992,1993, 1994,1995 The Regents of the University of Michigan
 * and Merit Network, Inc. All Rights Reserved
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 *
 * Copyright (C) 2026 Nikos Mavrogiannopoulos
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/** @file radcli-defs.h
 * @brief Single source of truth for definitions shared between radcli.h and radcli2.h.
 *
 * Both radcli.h and radcli2.h include this file so the numeric `PW_*`
 * attribute IDs, the numeric `PW_*` VALUEs of well-known attributes
 * (Service-Type, Framed-Protocol, NAS-Port-Type, Acct-Status-Type,
 * Acct-Terminate-Cause, etc.), and the RC_OPTION_TABLE config-option list
 * have a single source of truth instead of being hand-duplicated (or
 * allowed to drift) under two different naming schemes. It declares
 * nothing but these plain enums/macros -- no dependency on rc_attr_type,
 * DICT_ATTR, DICT_VALUE, OPTION, rc_handle, or any other radcli.h/radcli2.h
 * type -- so including it does not pull radcli2.h into radcli.h's
 * structures or vice versa. Guarded against double inclusion, since both
 * headers may be included together in the same translation unit.
 *
 * The VALUE enums are split out from radcli.h: a radcli2.h-only caller has
 * no dictionary-lookup workaround for these, the way
 * radcli_dict_lookup()/_lookup_num() cover attribute names/IDs -- these are
 * enumerated *values* of an attribute, not attributes themselves, so the
 * fixed RFC set belongs in a compiled-in, shared enum like this one. A
 * vendor-specific or supplemental-dictionary VALUE outside this fixed set
 * has no such compiled-in name and needs a runtime dictionary VALUE lookup
 * instead -- not addressed here.
 *
 * RC_OPTION_TABLE is the single X()-macro list both lib/options.h's
 * internal rc_option_id enum (driving rc_add_config()/rc_read_config()'s
 * string-based grammar) and radcli2.h's public radcli_opt_id enum (driving
 * radcli_ctx_set_opt_str()/_set_opt_int()) are generated from, so the
 * legacy and new APIs can never recognise a different set of option names
 * by accident.
 */

#ifndef RADCLI_DEFS_H
#define RADCLI_DEFS_H

/* *INDENT-OFF* */
#ifdef __cplusplus
extern "C" {
#endif
/* *INDENT-ON* */

/** \enum rc_attr_id Standard RADIUS attribute-value pair identifiers
 */
typedef enum rc_attr_id {
	PW_USER_NAME=1,		//!< Its type is string.
	PW_USER_PASSWORD=2,	//!< Its type is string.
	PW_CHAP_PASSWORD=3,	//!< Its type is string.
	PW_NAS_IP_ADDRESS=4,	//!< Its type is ipaddr.
	PW_NAS_PORT=5,		//!< Its type is integer.
	PW_SERVICE_TYPE=6,	//!< Its type is integer.
	PW_FRAMED_PROTOCOL=7,	//!< Its type is integer.
	PW_FRAMED_IP_ADDRESS=8,	//!< Its type is ipaddr.
	PW_FRAMED_IP_NETMASK=9,	//!< Its type is ipaddr.
	PW_FRAMED_ROUTING=10,	//!< Its type is integer.
	PW_FILTER_ID=11,	//!< Its type is string.
	PW_FRAMED_MTU=12,	//!< Its type is integer.
	PW_FRAMED_COMPRESSION=13,	//!< Its type is integer.
	PW_LOGIN_IP_HOST=14,	//!< Its type is ipaddr.
	PW_LOGIN_SERVICE=15,	//!< Its type is integer.
	PW_LOGIN_PORT=16,	//!< Its type is integer.
	PW_OLD_PASSWORD=17,	//!< Its type is string - deprecated.
	PW_REPLY_MESSAGE=18,	//!< Its type is string.
	PW_LOGIN_CALLBACK_NUMBER=19,	//!< Its type is string.
	PW_FRAMED_CALLBACK_ID=20,	//!< Its type is string.
	PW_EXPIRATION=21,		//!< Its type is date - deprecated.
	PW_FRAMED_ROUTE=22,		//!< Its type is string.
	PW_FRAMED_IPX_NETWORK=23,	//!< Its type is integer.
	PW_STATE=24,		//!< Its type is string.
	PW_CLASS=25,		//!< Its type is string.
	PW_VENDOR_SPECIFIC=26,	//!< Its type is string.
	PW_SESSION_TIMEOUT=27,	//!< Its type is integer.
	PW_IDLE_TIMEOUT=28,	//!< Its type is integer.
	PW_TERMINATION_ACTION=29,	//!< Its type is integer.
	PW_CALLED_STATION_ID=30,	//!< Its type is string.
	PW_CALLING_STATION_ID=31,	//!< Its type is string.
	PW_NAS_IDENTIFIER=32,	//!< Its type is string.
	PW_PROXY_STATE=33,	//!< Its type is string.
	PW_LOGIN_LAT_SERVICE=34,//!< Its type is string.
	PW_LOGIN_LAT_NODE=35,	//!< Its type is string.
	PW_LOGIN_LAT_GROUP=36,	//!< Its type is string.
	PW_FRAMED_APPLETALK_LINK=37,	//!< Its type is integer.
	PW_FRAMED_APPLETALK_NETWORK=38,	//!< Its type is integer.
	PW_FRAMED_APPLETALK_ZONE=39,	//!< Its type is string.
	PW_ACCT_STATUS_TYPE=40,		//!< Its type is integer.
	PW_ACCT_DELAY_TIME=41,		//!< Its type is integer.
	PW_ACCT_INPUT_OCTETS=42,	//!< Its type is integer.
	PW_ACCT_OUTPUT_OCTETS=43,	//!< Its type is integer.
	PW_ACCT_SESSION_ID=44,		//!< Its type is string.
	PW_ACCT_AUTHENTIC=45,		//!< Its type is integer.
	PW_ACCT_SESSION_TIME=46,	//!< Its type is integer.
	PW_ACCT_INPUT_PACKETS=47,	//!< Its type is integer.
	PW_ACCT_OUTPUT_PACKETS=48,	//!< Its type is integer.
	PW_ACCT_TERMINATE_CAUSE=49,	//!< Its type is integer.
	PW_ACCT_MULTI_SESSION_ID=50,	//!< Its type is string.
	PW_ACCT_LINK_COUNT=51,		//!< Its type is integer.
	PW_ACCT_INPUT_GIGAWORDS=52,	//!< Its type is integer.
	PW_ACCT_OUTPUT_GIGAWORDS=53,	//!< Its type is integer.
	PW_EVENT_TIMESTAMP=55,		//!< Its type is integer.
	PW_EGRESS_VLANID=56,		//!< Its type is string.
	PW_INGRESS_FILTERS=57,		//!< Its type is integer.
	PW_EGRESS_VLAN_NAME=58,		//!< Its type is string.
	PW_USER_PRIORITY_TABLE=59,	//!< Its type is string.
	PW_CHAP_CHALLENGE=60,		//!< Its type is string.
	PW_NAS_PORT_TYPE=61,		//!< Its type is integer.
	PW_PORT_LIMIT=62,		//!< Its type is integer.
	PW_LOGIN_LAT_PORT=63,		//!< Its type is string.
	PW_TUNNEL_TYPE=64,		//!< Its type is string.
	PW_TUNNEL_MEDIUM_TYPE=65,	//!< Its type is integer.
	PW_TUNNEL_CLIENT_ENDPOINT=66,	//!< Its type is string.
	PW_TUNNEL_SERVER_ENDPOINT=67,	//!< Its type is string.
	PW_ACCT_TUNNEL_CONNECTION=68,	//!< Its type is string.
	PW_TUNNEL_PASSWORD=69,		//!< Its type is string.
	PW_ARAP_PASSWORD=70,		//!< Its type is string.
	PW_ARAP_FEATURES=71,		//!< Its type is string.
	PW_ARAP_ZONE_ACCESS=72,		//!< Its type is integer.
	PW_ARAP_SECURITY=73,		//!< Its type is integer.
	PW_ARAP_SECURITY_DATA=74,	//!< Its type is string.
	PW_PASSWORD_RETRY=75,		//!< Its type is integer.
	PW_PROMPT=76,			//!< Its type is integer.
	PW_CONNECT_INFO=77,		//!< Its type is string.
	PW_CONFIGURATION_TOKEN=78,	//!< Its type is string.
	PW_EAP_MESSAGE=79,		//!< Its type is string.
	PW_MESSAGE_AUTHENTICATOR=80,	//!< Its type is string.
	PW_TUNNEL_PRIVATE_GROUP_ID=81,	//!< Its type is string.
	PW_TUNNEL_ASSIGNMENT_ID=82,	//!< Its type is string.
	PW_TUNNEL_PREFERENCE=83,	//!< Its type is string.
	PW_ARAP_CHALLENGE_RESPONSE=84,	//!< Its type is string.
	PW_ACCT_INTERIM_INTERVAL=85,	//!< Its type is integer.
	PW_ACCT_TUNNEL_PACKETS_LOST=86,	//!< Its type is integer.
	PW_NAS_PORT_ID_STRING=87,	//!< Its type is string.
	PW_FRAMED_POOL=88,		//!< Its type is string.
	PW_CHARGEABLE_USER_IDENTITY=89,	//!< Its type is string.
	PW_CUI=89,			//!< Its type is string.
	PW_TUNNEL_CLIENT_AUTH_ID=90,	//!< Its type is string.
	PW_TUNNEL_SERVER_AUTH_ID=91,	//!< Its type is string.
	PW_NAS_FILTER_RULE=92,		//!< Its type is string.
	PW_ORIGINATING_LINE_INFO=94,	//!< Its type is string.
	PW_NAS_IPV6_ADDRESS=95,		//!< Its type is string.
	PW_FRAMED_INTERFACE_ID=96,	//!< Its type is string.
	PW_FRAMED_IPV6_PREFIX=97,	//!< Its type is string.
	PW_LOGIN_IPV6_HOST=98,		//!< Its type is string.
	PW_FRAMED_IPV6_ROUTE=99,	//!< Its type is string.
	PW_FRAMED_IPV6_POOL=100,	//!< Its type is string.
	PW_ERROR_CAUSE=101,		//!< Its type is integer.
	PW_EAP_KEY_NAME=102,		//!< Its type is string.

	//!< RFC 5090: RADIUS Extension for Digest Authentication (obsoletes RFC 4590)
	PW_DIGEST_RESPONSE=103,		//!< Its type is string.
	PW_DIGEST_REALM=104,		//!< Its type is string.
	PW_DIGEST_NONCE=105,		//!< Its type is string.
	PW_DIGEST_RESPONSE_AUTH=106,	//!< Its type is string.
	PW_DIGEST_NEXTNONCE=107,	//!< Its type is string.
	PW_DIGEST_METHOD=108,		//!< Its type is string.
	PW_DIGEST_URI=109,		//!< Its type is string.
	PW_DIGEST_QOP=110,		//!< Its type is string.
	PW_DIGEST_ALGORITHM=111,	//!< Its type is string.
	PW_DIGEST_ENTITY_BODY_HASH=112,	//!< Its type is string.
	PW_DIGEST_CNONCE=113,		//!< Its type is string.
	PW_DIGEST_NONCE_COUNT=114,	//!< Its type is string.
	PW_DIGEST_USERNAME=115,		//!< Its type is string.
	PW_DIGEST_OPAQUE=116,		//!< Its type is string.
	PW_DIGEST_AUTH_PARAM=117,	//!< Its type is string.
	PW_DIGEST_AKA_AUTS=118,		//!< Its type is string.
	PW_DIGEST_DOMAIN=119,		//!< Its type is string.
	PW_DIGEST_STALE=120,		//!< Its type is string.
	PW_DIGEST_HA1=121,		//!< Its type is string.
	PW_SIP_AOR=122,			//!< Its type is string.

	PW_DELEGATED_IPV6_PREFIX=123,	//!< Its type is ipv6prefix.

	/*!< Its type is integer64. Only radcli2.h's rc_attr_type-equivalent,
	 * RADCLI_TYPE_INTEGER64, can express this attribute's width -- the
	 * legacy radcli.h rc_attr_type enum has no 64-bit type, so
	 * rc_avpair_add()/legacy callers cannot type-check it. */
	PW_MIP6_FEATURE_VECTOR=124,

	//!< DSL Forum WT-101 (RFC 4679) line-characteristics attributes.
	PW_ACTUAL_DATA_RATE_UPSTREAM=129,	//!< Its type is integer.
	PW_ACTUAL_DATA_RATE_DOWNSTREAM=130,	//!< Its type is integer.
	PW_MINIMUM_DATA_RATE_UPSTREAM=131,	//!< Its type is integer.
	PW_MINIMUM_DATA_RATE_DOWNSTREAM=132,	//!< Its type is integer.
	PW_ATTAINABLE_DATA_RATE_UPSTREAM=133,	//!< Its type is integer.
	PW_ATTAINABLE_DATA_RATE_DOWNSTREAM=134,	//!< Its type is integer.
	PW_MAXIMUM_DATA_RATE_UPSTREAM=135,	//!< Its type is integer.
	PW_MAXIMUM_DATA_RATE_DOWNSTREAM=136,	//!< Its type is integer.
	PW_MINIMUM_DATA_RATE_UPSTREAM_LOW_POWER=137,	//!< Its type is integer.
	PW_MINIMUM_DATA_RATE_DOWNSTREAM_LOW_POWER=138,	//!< Its type is integer.
	PW_MAXIMUM_INTERLEAVING_DELAY_UPSTREAM=139,	//!< Its type is integer.
	PW_ACTUAL_INTERLEAVING_DELAY_UPSTREAM=140,	//!< Its type is integer.
	PW_MAXIMUM_INTERLEAVING_DELAY_DOWNSTREAM=141,	//!< Its type is integer.
	PW_ACTUAL_INTERLEAVING_DELAY_DOWNSTREAM=142,	//!< Its type is integer.

	PW_ACCESS_LOOP_ENCAPSULATION=144,	//!< Its type is string.

	PW_FRAMED_IPV6_ADDRESS=168,	//!< Its type is ipaddr6.
	PW_DNS_SERVER_IPV6_ADDRESS=169,	//!< Its type is ipaddr6.
	PW_ROUTE_IPV6_INFORMATION=170,	//!< Its type is ipv6prefix.
	PW_DELEGATED_IPV6_PREFIX_POOL=171,	//!< Its type is string.
	PW_STATEFUL_IPV6_ADDRESS_POOL=172,	//!< Its type is string.

	//!< Merit Experimental Extensions
	PW_USER_ID=222,			//!< Its type is string.
	PW_USER_REALM=223,		//!< Its type is string.

	PW_IWF_SESSION=254		//!< Its type is string.
} rc_attr_id;

/* Compatibility names for the two RFC 5090 attributes whose canonical name
 * differs from the old draft-sterman-aaa-sip-00 spelling, in case any
 * out-of-tree caller already uses the old macro name. These are the *new*
 * numeric values (112/115) -- a caller recompiling against this header gets
 * correct RFC 5090 wire behavior under the old name for free. */
#define PW_DIGEST_BODY_DIGEST PW_DIGEST_ENTITY_BODY_HASH
#define PW_DIGEST_USER_NAME   PW_DIGEST_USERNAME

/** \enum rc_service_type RFC2865 Service-Type values
 */
typedef enum rc_service_type {
	PW_LOGIN=1,
	PW_FRAMED=2,
	PW_CALLBACK_LOGIN=3,
	PW_CALLBACK_FRAMED=4,
	PW_OUTBOUND=5,
	PW_ADMINISTRATIVE=6,
	PW_NAS_PROMPT=7,
	PW_AUTHENTICATE_ONLY=8,
	PW_CALLBACK_NAS_PROMPT=9
} rc_service_type;

/** \enum rc_framed_protocol RFC2865 Framed-Protocol values
 */
typedef enum rc_framed_protocol {
	PW_PPP=1,
	PW_SLIP=2,
	PW_ARA=	3,
	PW_GANDALF=4,
	PW_XYLOGICS=5
} rc_framed_protocol;

/** \enum rc_framed_routing_type RFC2865 Framed-Routing values
 */
typedef enum rc_framed_routing_type {
	PW_NONE=0,
	PW_BROADCAST=1,
	PW_LISTEN=2,
	PW_BROADCAST_LISTEN=3
} rc_framed_routing_type;

/** \enum rc_framed_comp RFC2865 Framed-Compression values
 */
typedef enum rc_framed_comp {
	PW_COMP_NONE=0,
	PW_VAN_JACOBSON_TCP_IP=1,
	PW_IPX_HEADER_COMPRESSION=2,
	PW_COMP_LZS=3
} rc_framed_comp;

/** \enum rc_login_service_type RFC2865 Login-Service values
 */
typedef enum rc_login_service_type {
	PW_TELNET=0,
	PW_RLOGIN=1,
	PW_TCP_CLEAR=2,
	PW_PORTMASTER=3,
	PW_LAT=4,
	PW_X25_PAD=5,
	PW_X25_T3POS=6
} rc_login_service_type;

/** \enum rc_termination_action RFC2865 Termination-Action values
 */
typedef enum rc_termination_action {
	PW_DEFAULT=0,
	PW_RADIUS_REQUEST=1
} rc_termination_action;

/** \enum rc_acct_status_type RFC2866 Acct-Status-Type values
 */
typedef enum rc_acct_status_type {
	PW_STATUS_START=1,
	PW_STATUS_STOP=2,
	PW_STATUS_ALIVE=3,
	PW_STATUS_MODEM_START=4,
	PW_STATUS_MODEM_STOP=5,
	PW_STATUS_CANCEL=6,
	PW_ACCOUNTING_ON=7,
	PW_ACCOUNTING_OFF=8
} rc_acct_status_type;

/** \enum rc_acct_terminate_cause RFC2866 Acct-Terminate-Cause values
 */
typedef enum rc_acct_terminate_cause {
	PW_USER_REQUEST=1,
	PW_LOST_CARRIER=2,
	PW_LOST_SERVICE=3,
	PW_ACCT_IDLE_TIMEOUT=4,
	PW_ACCT_SESSION_TIMEOUT=5,
	PW_ADMIN_RESET=6,
	PW_ADMIN_REBOOT=7,
	PW_PORT_ERROR=8,
	PW_NAS_ERROR=9,
	PW_NAS_REQUEST=10,
	PW_NAS_REBOOT=11,
	PW_PORT_UNNEEDED=12,
	PW_PORT_PREEMPTED=13,
	PW_PORT_SUSPENDED=14,
	PW_SERVICE_UNAVAILABLE=15,
	PW_CALLBACK=16,
	PW_USER_ERROR=17,
	PW_HOST_REQUEST=18
} rc_acct_terminate_cause;

/** \enum rc_nas_port_type RFC2866 NAS-Port-Type values
 */
typedef enum rc_nas_port_type {
	PW_ASYNC=0,
	PW_SYNC=1,
	PW_ISDN_SYNC=2,
	PW_ISDN_SYNC_V120=3,
	PW_ISDN_SYNC_V110=4,
	PW_VIRTUAL=5
} rc_nas_port_type;

/** \enum rc_acct_auth_type RFC2866 Acct-Authentic values
 */
typedef enum rc_acct_auth_type {
	PW_RADIUS=1,
	PW_LOCAL=2,
	PW_REMOTE=3
} rc_acct_auth_type;

/** \enum rc_vendor_pec --- http://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
 */
typedef enum rc_vendor_pec {
  VENDOR_NONE=0,
  VENDOR_MICROSOFT	     = 311,
  VENDOR_ROARING_PENGUIN     = 10055
} rc_vendor_type;

/* Option value types -- shared between lib/options.h's internal OPTION.type
 * and, indirectly, radcli_ctx_set_opt_str()/_set_opt_int()'s validation
 * that the right setter is used for a given radcli_opt_id. */
#define RADCLI_OPT_TYPE_STR	(1<<0)			//!< string.
#define RADCLI_OPT_TYPE_INT	(1<<1)			//!< integer.
#define RADCLI_OPT_TYPE_SRV	(1<<2)			//!< server list.

#define RC_OPTION_TABLE \
/* internally used options */ \
RADCLI_OPT_ENTRY(OPT_CONFIG_FILE,	"config_file",		RADCLI_OPT_TYPE_STR) \
/* RADIUS specific options */ \
RADCLI_OPT_ENTRY(OPT_SERV_TYPE,	"serv-type",		RADCLI_OPT_TYPE_STR) \
RADCLI_OPT_ENTRY(OPT_SERV_AUTH_TYPE,	"serv-auth-type",	RADCLI_OPT_TYPE_STR) /* alias for serv-type */ \
RADCLI_OPT_ENTRY(OPT_NAMESPACE,	"namespace",		RADCLI_OPT_TYPE_STR) \
RADCLI_OPT_ENTRY(OPT_USE_PUBLIC_ADDR,	"use-public-addr",	RADCLI_OPT_TYPE_STR) \
RADCLI_OPT_ENTRY(OPT_TLS_VERIFY_HOSTNAME, "tls-verify-hostname", RADCLI_OPT_TYPE_STR) \
RADCLI_OPT_ENTRY(OPT_REQUIRE_MESSAGE_AUTHENTICATOR, "require-message-authenticator", RADCLI_OPT_TYPE_STR) /* default: required; set "no" for legacy servers */ \
RADCLI_OPT_ENTRY(OPT_TLS_CA_FILE,	"tls-ca-file",		RADCLI_OPT_TYPE_STR) \
RADCLI_OPT_ENTRY(OPT_TLS_CERT_FILE,	"tls-cert-file",	RADCLI_OPT_TYPE_STR) \
RADCLI_OPT_ENTRY(OPT_TLS_KEY_FILE,	"tls-key-file",		RADCLI_OPT_TYPE_STR) \
/* Config-file equivalent of radcli2.h's radcli_ctx_set_tls_psk(): identity
 * as plain text, key as hex text (like the legacy authserver
 * "psk@username@hexkey" form, but as two independent options instead of a
 * delimited string). Only meaningful when serv-type is tls/dtls; both must
 * be set together. See rc_init_tls() (lib/tls.c). */ \
RADCLI_OPT_ENTRY(OPT_TLS_PSK_IDENTITY,	"tls-psk-identity",	RADCLI_OPT_TYPE_STR) \
RADCLI_OPT_ENTRY(OPT_TLS_PSK_KEY,	"tls-psk-key",		RADCLI_OPT_TYPE_STR) \
/* Seconds between RFC 5997 Status-Server watchdogs on an established
 * RadSec (TLS/DTLS) session: radcli_ctx_get_poll() advises the timing,
 * radcli_ctx_dispatch() sends them automatically once due -- radcli owns
 * no timer itself (REQ-GEN-SEC-003). Any RadSec radcli_ctx, DAE or not
 * (REQ-WATCHDOG-NET-001/002). No effect on UDP. Default 15
 * (draft-ietf-radext-reverse-coa's recommended Tw); 0 disables it.
 * Otherwise MUST be at least 6 (REQ-WATCHDOG-CFG-001) -- a smaller value is
 * rejected outright, since the watchdog send reconnects once 2.5x this has
 * elapsed with nothing received (REQ-WATCHDOG-NET-003). */ \
RADCLI_OPT_ENTRY(OPT_WATCHDOG_INTERVAL, "watchdog-interval", RADCLI_OPT_TYPE_INT) \
RADCLI_OPT_ENTRY(OPT_NAS_IDENTIFIER,	"nas-identifier",	RADCLI_OPT_TYPE_STR) \
RADCLI_OPT_ENTRY(OPT_NAS_IP,		"nas-ip",		RADCLI_OPT_TYPE_STR) \
RADCLI_OPT_ENTRY(OPT_AUTHSERVER,	"authserver",		RADCLI_OPT_TYPE_SRV) \
RADCLI_OPT_ENTRY(OPT_ACCTSERVER,	"acctserver",		RADCLI_OPT_TYPE_SRV) \
RADCLI_OPT_ENTRY(OPT_SERVERS,		"servers",		RADCLI_OPT_TYPE_STR) \
/* Fallback shared secret for authserver/acctserver, applied only when a
 * server's SERVER->secret[0] is not already set inline (host:port:secret)
 * -- the config-file equivalent of radcli2.h's radcli_ctx_set_secret().
 * See radcli2_priv_apply_config() (lib/config.c). */ \
RADCLI_OPT_ENTRY(OPT_SECRET,		"secret",		RADCLI_OPT_TYPE_STR) \
RADCLI_OPT_ENTRY(OPT_DICTIONARY,	"dictionary",		RADCLI_OPT_TYPE_STR) \
RADCLI_OPT_ENTRY(OPT_DEFAULT_REALM,	"default_realm",	RADCLI_OPT_TYPE_STR) \
RADCLI_OPT_ENTRY(OPT_RADIUS_TIMEOUT,	"radius_timeout",	RADCLI_OPT_TYPE_INT) \
RADCLI_OPT_ENTRY(OPT_RADIUS_RETRIES,	"radius_retries",	RADCLI_OPT_TYPE_INT) \
RADCLI_OPT_ENTRY(OPT_BINDADDR,		"bindaddr",		RADCLI_OPT_TYPE_STR) \
RADCLI_OPT_ENTRY(OPT_CLIENTDEBUG,	"clientdebug",		RADCLI_OPT_TYPE_INT) \
/* RFC 5176 dynamic authorization (CoA/Disconnect) -- see lib/dae.c.
 * dae-server is a comma-separated list of "address_or_hostname[:secret]"
 * entries (no port: it identifies an authorized sender, not something
 * radcli connects to); parsing, prefix rejection, and hostname
 * resolution are lib/dae.c's job, not the generic config layer's. */ \
RADCLI_OPT_ENTRY(OPT_DAE_ACCEPT,	"dae-accept",		RADCLI_OPT_TYPE_STR) \
RADCLI_OPT_ENTRY(OPT_DAE_LISTEN,	"dae-listen",		RADCLI_OPT_TYPE_STR) \
RADCLI_OPT_ENTRY(OPT_DAE_SECRET,	"dae-secret",		RADCLI_OPT_TYPE_STR) \
RADCLI_OPT_ENTRY(OPT_DAE_SERVER,	"dae-server",		RADCLI_OPT_TYPE_STR) \
RADCLI_OPT_ENTRY(OPT_DAE_MAX_CLOCK_SKEW, "dae-max-clock-skew", RADCLI_OPT_TYPE_INT) \
RADCLI_OPT_ENTRY(OPT_DAE_REQUIRE_MESSAGE_AUTHENTICATOR, "dae-require-message-authenticator", RADCLI_OPT_TYPE_STR)

/* *INDENT-OFF* */
#ifdef __cplusplus
}
#endif
/* *INDENT-ON* */

#endif /* RADCLI_DEFS_H */
