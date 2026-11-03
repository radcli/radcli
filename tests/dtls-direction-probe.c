/* SPDX-License-Identifier: BSD-2-Clause */
#define _POSIX_C_SOURCE 200809L
#include <radcli/radcli2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <syslog.h>

/* Measure library calls separately from the event loop's deliberate waits. */
static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1000000000.0;
}

/* Exercise the public asynchronous API against a disposable DTLS peer;
 * report completion and readiness so the harness can reject a busy loop. */
int main(int argc, char **argv)
{
    radcli_ctx *ctx;
    radcli_avp_list *attrs;
    radcli_request *request;
    char endpoint[100];
    double start;
    int ret, result = RADCLI_AGAIN;
    unsigned rounds = 0;

    if (argc != 3 && argc != 4)
        return 2;
    setbuf(stdout, NULL);
    /* Mirror library diagnostics to stderr without requiring a syslog daemon. */
    openlog("radcli-transport-probe", LOG_PERROR, LOG_USER);
    ctx = radcli_ctx_new(0);
    snprintf(endpoint, sizeof(endpoint), "127.0.0.1:%s:testing123", argv[2]);
    if (!ctx ||
        radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SERV_TYPE, argv[1]) ||
        radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, endpoint) ||
        radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 2) ||
        radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 1) ||
        radcli_ctx_set_opt_int(ctx, RADCLI_OPT_WATCHDOG_INTERVAL, 0)) {
        fprintf(stderr, "FAIL: could not configure context\n");
        return 2;
    }

    /* The positive peer accepts this public test-only PSK, while the
     * silent peer exercises handshake timeouts without certificates. */
    if (!strcmp(argv[1], "tls") || !strcmp(argv[1], "dtls")) {
        const unsigned char key[16] = {1, 2, 3, 4};
        if (radcli_ctx_set_tls_psk(ctx, "probe", 5, key, sizeof(key)))
            return 2;
    }
    start = now();
    ret = radcli_ctx_apply(ctx);
    printf("apply result=%d seconds=%.6f\n", ret, now() - start);
    if (ret)
        return 2;

    /* The request owns a copy of these AVPs. Keep it alive until completion
     * or cancellation so its registry entry remains valid during dispatch. */
    attrs = radcli_avp_list_new();
    if (!attrs || radcli_avp_add_str_by_num(attrs, ctx, PW_USER_NAME, 0, "probe"))
        return 2;
    request = radcli_request_new(ctx, RADCLI_CODE_ACCESS_REQUEST, attrs);
    radcli_avp_list_free(attrs);
    if (!request)
        return 2;
    start = now();
    errno = 0;
    /* Submission must leave the handshake to dispatch without waiting. */
    ret = radcli_request_perform(request, RADCLI_REQUEST_SENDONLY | RADCLI_REQUEST_NONBLOCK);
    printf("perform result=%d seconds=%.6f errno=%d\n", ret, now() - start, errno);

    /* Start the pending handshake before cancellation, so teardown exercises
     * backend-owned transport state rather than only an unstarted request. */
    if (argc == 4) {
        radcli_ctx_dispatch(ctx);
        radcli_request_free(request);
        radcli_ctx_free(ctx);
        puts("CANCELLED");
        return 0;
    }

    /* Polling is allowed to wait; dispatch itself must return promptly.
     * The harness has an independent process timeout for stalled calls. */
    /* Bound elapsed time rather than iteration count: a readiness spin must
     * remain observable through the real RADIUS timeout, not end the probe. */
    double loop_start = now(), deadline = loop_start + 10, max_dispatch = 0;
    clock_t cpu_start = clock();
    unsigned zero_timeout = 0, write_ready = 0, read_ready = 0;
    while (ret == RADCLI_OK && result == RADCLI_AGAIN && now() < deadline) {
        struct pollfd fds[RADCLI_CTX_MAX_POLLFDS];
        size_t nfds;
        int timeout;
        if (radcli_ctx_get_poll(ctx, fds, RADCLI_CTX_MAX_POLLFDS, &nfds, &timeout))
            return 2;
        rounds++;
        zero_timeout += timeout == 0;
        /* Capture the library's initial watcher instructions so an always
         * writable socket can be distinguished from an expired timer. */
        if (rounds <= 5)
            printf("POLL nfds=%zu events=%d timeout_ms=%d\n", nfds,
                   nfds ? fds[0].events : 0, timeout);
        poll(fds, nfds, timeout < 0 || timeout > 2500 ? 2500 : timeout);
        /* Summarize readiness without flooding logs or altering the requested
         * poll timeout; this keeps a busy loop visible in CPU and call counts. */
        for (size_t i = 0; i < nfds; i++) {
            write_ready += (fds[i].revents & POLLOUT) != 0;
            read_ready += (fds[i].revents & POLLIN) != 0;
        }
        start = now();
        radcli_ctx_dispatch(ctx);
        double elapsed = now() - start;
        if (elapsed > max_dispatch)
            max_dispatch = elapsed;
        if (rounds <= 5 || elapsed > 0.01)
            printf("dispatch seconds=%.6f\n", elapsed);
        result = radcli_request_done(request);
    }
    /* Include the maximum of every call, including the suppressed fast ones. */
    printf("dispatch seconds=%.6f\n", max_dispatch);
    printf("LOOP wall=%.6f cpu=%.6f zero_timeout=%u write_ready=%u read_ready=%u\n",
           now() - loop_start, (double)(clock() - cpu_start) / CLOCKS_PER_SEC,
           zero_timeout, write_ready, read_ready);
    printf("done result=%d rounds=%u\n", result, rounds);
    radcli_request_free(request);
    radcli_ctx_free(ctx);
    return 0;
}
