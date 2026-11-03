# SPDX-License-Identifier: BSD-2-Clause
"""Exercise actual DTLS handshakes, packet loss, and RADIUS acceptance."""
import select
import socket
import subprocess
import threading


# A datagram proxy drops exactly one client flight when requested. It forwards
# all later datagrams unchanged, so success depends on real retransmission.
def case(binary, peer_binary, kind, mode, policy, loss, env):
    peer = subprocess.Popen([peer_binary, kind], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    proxy = None
    thread = None
    stop = threading.Event()
    evidence = {'dropped': 0, 'forwarded': 0}
    try:
        if not select.select([peer.stdout], [], [], 3)[0]:
            raise RuntimeError('peer did not become ready')
        line = peer.stdout.readline()
        port = int(line.split()[1])
        if loss:
            proxy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            proxy.bind(('127.0.0.1', 0))
            proxy.settimeout(0.05)
            server = ('127.0.0.1', port)
            port = proxy.getsockname()[1]

            def forward():
                client = None
                while not stop.is_set():
                    try:
                        packet, source = proxy.recvfrom(65536)
                    except socket.timeout:
                        continue
                    if source == server:
                        if client:
                            proxy.sendto(packet, client)
                    else:
                        client = source
                        if not evidence['dropped']:
                            evidence['dropped'] += 1
                            continue
                        proxy.sendto(packet, server)
                    evidence['forwarded'] += 1

            thread = threading.Thread(target=forward)
            thread.start()
        args = [binary, 'dtls', str(port)] if kind == 'radius' else [binary, str(port), mode, policy]
        run = subprocess.run(args, env=env, capture_output=True, text=True, timeout=10)
        stdout, stderr = peer.communicate(timeout=3)
        ok = (run.returncode == 0 and peer.returncode == 0 and
              ('done result=0 ' in run.stdout if kind == 'radius' else 'RESULT ret=0 ' in run.stdout))
        return dict(kind=kind, mode=mode, policy=policy, loss=loss,
                    exit=run.returncode, stdout=run.stdout, stderr=run.stderr,
                    peer_stdout=line+stdout, peer_stderr=stderr,
                    peer_exit=peer.returncode, proxy=evidence, passed=ok)
    finally:
        stop.set()
        if thread:
            thread.join()
        if proxy:
            proxy.close()
        if peer.poll() is None:
            peer.terminate()
            peer.communicate(timeout=2)


