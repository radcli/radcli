/* SPDX-License-Identifier: BSD-2-Clause
 * Private loopback DTLS/PSK peer; replies include both RADIUS authenticators. */
#define _POSIX_C_SOURCE 200809L
#include <config.h>
#include <radcli/radcli.h>
#include "util.h"
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include <gnutls/crypto.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Supply exactly the public test identity/key; reject all other identities. */
static int key_for(gnutls_session_t session, const char *name, gnutls_datum_t *key)
{
    const unsigned char bytes[16] = {1, 2, 3, 4};
    (void)session;
    if (strcmp(name, "probe"))
        return -1;
    key->data = gnutls_malloc(sizeof(bytes));
    if (!key->data)
        return -1;
    memcpy(key->data, bytes, sizeof(bytes));
    key->size = sizeof(bytes);
    return 0;
}

/* A single bounded connection suffices to verify a real handshake and the
 * lifetime of radcli's transport state after next is promoted to conn. */
int main(int argc, char **argv)
{
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    struct sockaddr_in remote;
    socklen_t len = sizeof(addr), remote_len = sizeof(remote);
    gnutls_session_t session;
    gnutls_psk_server_credentials_t creds;
    unsigned char packet[4096], reply[38], digest_input[49];
    unsigned char *authenticator, *message_authenticator;
    pkt_buf response, digest;
    const char secret[] = "radius/dtls";
    int fd, ret;
    if (argc != 2)
        return 2;
    setbuf(stdout, NULL);
    alarm(8);
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0 || bind(fd, (struct sockaddr *)&addr, sizeof(addr)) ||
        getsockname(fd, (struct sockaddr *)&addr, &len))
        return 2;
    printf("PORT %u\n", ntohs(addr.sin_port));
    /* Peek keeps ClientHello available for GnuTLS, and connect isolates the
     * selected peer. No production ports, certificates or services are used. */
    if (recvfrom(fd, packet, sizeof(packet), MSG_PEEK, (struct sockaddr *)&remote, &remote_len) < 0 ||
        connect(fd, (struct sockaddr *)&remote, remote_len))
        return 2;
    if (gnutls_global_init() < 0 || gnutls_psk_allocate_server_credentials(&creds) < 0)
        return 2;
    gnutls_psk_set_server_credentials_function(creds, key_for);
    if (gnutls_init(&session, GNUTLS_SERVER | GNUTLS_DATAGRAM) < 0 ||
        gnutls_priority_set_direct(session, "NORMAL:-KX-ALL:+PSK:-VERS-ALL:+VERS-DTLS1.2", NULL) < 0 ||
        gnutls_credentials_set(session, GNUTLS_CRD_PSK, creds) < 0)
        return 2;
    gnutls_transport_set_int(session, fd);
    gnutls_dtls_set_timeouts(session, 500, 4000);
    do {
        ret = gnutls_handshake(session);
    } while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
    printf("HANDSHAKE %d\n", ret);
    if (ret)
        return 1;
    /* Direct-library tests finish here; radcli tests must also accept a
     * cryptographically valid Access-Accept on the established connection. */
    if (!strcmp(argv[1], "radius")) {
        ret = gnutls_record_recv(session, packet, sizeof(packet));
        if (ret < 20 || packet[0] != 1)
            return 1;
        /* RFC 2869 section 5.14: compute Message-Authenticator with the
         * request authenticator and a zeroed attribute value first. Reserve
         * patch locations through pkt_buf so all writes stay bounded. */
        pb_init(&response, reply, sizeof(reply));
        if (pb_put_byte(&response, 2) || pb_put_byte(&response, packet[1]) ||
            pb_put_byte(&response, 0) || pb_put_byte(&response, sizeof(reply)))
            return 2;
        authenticator = pb_put_reserve(&response, 16);
        if (!authenticator)
            return 2;
        memcpy(authenticator, packet + 4, 16);
        if (pb_put_byte(&response, 80) || pb_put_byte(&response, 18))
            return 2;
        message_authenticator = pb_put_reserve(&response, 16);
        if (!message_authenticator)
            return 2;
        memset(message_authenticator, 0, 16);
        if (gnutls_hmac_fast(GNUTLS_MAC_MD5, secret, sizeof(secret)-1,
                            reply, sizeof(reply), message_authenticator))
            return 2;
        /* RFC 2865 section 3: Response Authenticator covers the completed
         * response attributes followed by the shared secret. */
        pb_init(&digest, digest_input, sizeof(digest_input));
        if (pb_put_bytes(&digest, reply, sizeof(reply)) ||
            pb_put_bytes(&digest, secret, sizeof(secret)-1) ||
            gnutls_hash_fast(GNUTLS_DIG_MD5, digest_input, sizeof(digest_input), authenticator))
            return 2;
        if (gnutls_record_send(session, reply, sizeof(reply)) != sizeof(reply))
            return 1;
        printf("ACCESS_ACCEPT id=%u\n", reply[1]);
    }
    gnutls_deinit(session);
    gnutls_psk_free_server_credentials(creds);
    gnutls_global_deinit();
    close(fd);
    return 0;
}
