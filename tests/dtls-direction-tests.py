# SPDX-License-Identifier: BSD-2-Clause
"""REQ-NET-NET-023: DTLS waits without spinning and recovers from send stalls."""
import json
import os
import re
import socket
import subprocess
import sys
from dtls_silent import measure
from dtls_positive import case


# The Meson-built client uses its build-tree library. Keep dependency selection
# inherited so this same regression can test installed or patched GnuTLS.
probe, peer = sys.argv[1:]
env = os.environ.copy()
results = []
silent = measure(probe, 'dtls', env)
silent['passed'] = (silent['nonblocking_timeout_observed'] and
                    silent['loop']['cpu_seconds'] < 0.2 and
                    silent['loop']['write_ready'] < 1000)
results.append(silent)

# Successful authentication must survive both packet loss and transient send
# failures; CPU and iteration limits reject the original fast-return spin.
for fault in ('none', 'loss', 'EAGAIN', 'EINTR'):
    fault_env = env.copy()
    if fault in ('EAGAIN', 'EINTR'):
        # Only the client executable contains the send fault fixture.
        fault_env['DTLS_TEST_INJECT'] = fault
    result = case(probe, peer, 'radius', fault, 'native', fault == 'loss', fault_env)
    loop = re.search(r'LOOP wall=([0-9.]+) cpu=([0-9.]+).*write_ready=(\d+)', result['stdout'])
    result['passed'] &= bool(loop and float(loop[2]) < 0.2 and int(loop[3]) < 1000)
    if fault in ('EAGAIN', 'EINTR'):
        result['passed'] &= 'INJECTED_UDP_SEND_'+fault in result['stderr']
        # The injected failed send must result in another write-ready wakeup
        # after the initial UDP-connect notification.
        result['passed'] &= bool(loop and int(loop[3]) >= 2)
    results.append(result)

# Cancel after dispatch creates handshake transport state. Sanitized runs
# check its release on teardown without requiring a completed handshake.
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink:
    sink.bind(('127.0.0.1', 0))
    run = subprocess.run([probe, 'dtls', str(sink.getsockname()[1]), 'cancel'],
                         env=env, capture_output=True, text=True, timeout=4)
    results.append(dict(fault='cancel', exit=run.returncode, stdout=run.stdout,
                        stderr=run.stderr, passed=run.returncode == 0 and 'CANCELLED' in run.stdout))
print(json.dumps(results, indent=2), flush=True)
if not all(r['passed'] for r in results):
    raise SystemExit(1)
