# SPDX-License-Identifier: BSD-2-Clause
"""Measure a pending handshake against a silent, isolated loopback peer."""
import re
import socket
import subprocess
import threading


# Keep each peer on numeric loopback and an OS-allocated port. The outer
# process deadline catches a library hang independently of its own timers.
def measure(binary, transport, env):
    stream = transport in ('tcp', 'tls')
    peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM if stream else socket.SOCK_DGRAM)
    peer.bind(('127.0.0.1', 0))
    peer.settimeout(0.2)
    if stream:
        peer.listen(1)
    port = peer.getsockname()[1]
    stop = threading.Event()
    evidence = {'accepted': False, 'bytes': 0}

    # Keep the accepted socket open without answering RADIUS or handshake
    # traffic, so a timeout cannot be confused with immediate peer closure.
    def consume():
        conn = None
        try:
            while not stop.is_set():
                try:
                    if stream and conn is None:
                        conn, _ = peer.accept()
                        conn.settimeout(0.2)
                        evidence['accepted'] = True
                    elif stream:
                        data = conn.recv(65536)
                        if not data:
                            break
                        evidence['bytes'] += len(data)
                    else:
                        evidence['bytes'] += len(peer.recvfrom(65536)[0])
                except socket.timeout:
                    continue
        except OSError as exc:
            evidence['error'] = str(exc)
        finally:
            if conn is not None:
                conn.close()

    thread = threading.Thread(target=consume, daemon=True)
    thread.start()
    try:
        run = subprocess.run([str(binary), transport, str(port)], env=env,
                             text=True, capture_output=True, timeout=15)
        result = {'transport': transport, 'exit': run.returncode,
                  'stdout': run.stdout, 'stderr': run.stderr}
    except subprocess.TimeoutExpired:
        result = {'transport': transport, 'external_timeout': True}
    finally:
        stop.set()
        thread.join(2)
        peer.close()
    result['peer'] = evidence

    # A successful process exit is insufficient: verify the asynchronous
    # submission, final timeout, peer traffic, and every recorded call duration.
    output = result.get('stdout', '')
    durations = [float(x) for x in re.findall(r'(?:perform result=-?\d+|dispatch) seconds=([0-9.]+)', output)]
    result['max_call_seconds'] = max(durations, default=None)
    # Short individual dispatch calls can still burn a core when poll never
    # sleeps. Record this separately from network blocking and terminal status.
    loop = re.search(r'LOOP wall=([0-9.]+) cpu=([0-9.]+) zero_timeout=(\d+) write_ready=(\d+) read_ready=(\d+)', output)
    if loop:
        result['loop'] = dict(zip(('wall_seconds', 'cpu_seconds', 'zero_timeout', 'write_ready', 'read_ready'),
                                  [float(loop[1]), float(loop[2]), int(loop[3]), int(loop[4]), int(loop[5])]))
        result['event_loop_spin_observed'] = float(loop[2]) > 0.8 * float(loop[1]) and int(loop[4]) + int(loop[3]) > 100000
    result['nonblocking_timeout_observed'] = bool(
        result.get('exit') == 0 and 'perform result=0 ' in output and
        'done result=-2 ' in output and durations and max(durations) < 0.2 and
        evidence['bytes'] > 0 and 'error' not in evidence)
    return result


