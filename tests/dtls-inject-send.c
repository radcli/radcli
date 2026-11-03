/* SPDX-License-Identifier: BSD-2-Clause
 * Test-only fault injection into the first UDP send of each client process. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

/* Preserve real send semantics except for one explicitly requested transient
 * failure. This fixture is never linked into the production library. */
ssize_t send(int fd, const void *buf, size_t len, int flags)
{
    static int injected;
    const char *mode = getenv("DTLS_TEST_INJECT");
    ssize_t (*real_send)(int, const void *, size_t, int) = dlsym(RTLD_NEXT, "send");
    int type;
    socklen_t size = sizeof(type);
    if (!real_send) {
        errno = EIO;
        return -1;
    }
    /* Identify UDP without assuming descriptor numbers or touching the peer. */
    if (!injected && mode && getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size) == 0 && type == SOCK_DGRAM) {
        injected = 1;
        fprintf(stderr, "INJECTED_UDP_SEND_%s\n", mode);
        errno = !strcmp(mode, "EINTR") ? EINTR : EAGAIN;
        return -1;
    }
    return real_send(fd, buf, len, flags);
}
