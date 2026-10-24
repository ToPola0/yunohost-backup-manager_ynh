"""SMB transport selection inside the YunoHost Backup Manager application.

When a Tailscale 100.64.0.0/10 address is not reachable by ordinary TCP,
connect through the already-running ``tailscale nc`` interface. No listeners,
services or network rules are installed outside this application's process.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import ipaddress
import os
import shutil
import socket
import socketserver
import subprocess
import threading

TAILSCALE_RANGE = ipaddress.ip_network('100.64.0.0/10')


@dataclass(frozen=True)
class SMBEndpoint:
    host: str
    port: int
    via_tailscale: bool


def _direct_reachable(host):
    try:
        with socket.create_connection((host, 445), timeout=2.0):
            return True
    except (OSError, TimeoutError):
        return False


def _tailscale_ip(host):
    try:
        return ipaddress.ip_address(host) in TAILSCALE_RANGE
    except ValueError:
        return False


class _LocalRelay(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, target, cli):
        self.target = target
        self.cli = cli
        self.children = set()
        self.children_lock = threading.Lock()
        super().__init__(('127.0.0.1', 0), _BridgeHandler)

    def register(self, proc):
        with self.children_lock:
            self.children.add(proc)

    def unregister(self, proc):
        with self.children_lock:
            self.children.discard(proc)

    def stop_children(self):
        with self.children_lock:
            children = tuple(self.children)
        for proc in children:
            if proc.poll() is None:
                proc.terminate()
        for proc in children:
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)


class _BridgeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        proc = subprocess.Popen(
            [self.server.cli, 'nc', self.server.target, '445'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0, close_fds=True,
        )
        self.server.register(proc)
        sock = self.request

        def toward_tailscale():
            try:
                while True:
                    data = sock.recv(256 * 1024)
                    if not data:
                        break
                    view = memoryview(data)
                    while view:
                        written = os.write(proc.stdin.fileno(), view)
                        view = view[written:]
            except (OSError, BrokenPipeError):
                pass
            finally:
                try:
                    proc.stdin.close()
                except OSError:
                    pass

        pump = threading.Thread(target=toward_tailscale, daemon=True)
        pump.start()
        try:
            while True:
                data = os.read(proc.stdout.fileno(), 256 * 1024)
                if not data:
                    break
                sock.sendall(data)
        except OSError:
            pass
        finally:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            if proc.poll() is None:
                proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
            try:
                proc.stdout.close()
            except OSError:
                pass
            pump.join(timeout=1)
            self.server.unregister(proc)


@contextmanager
def smb_endpoint(host):
    """Supply an address/port used by both SMB implementations.

    On standard routed networks use direct TCP. Only for unreachable
    Tailnet IPv4 addresses, use an ephemeral in-process loopback relay.
    """
    if not _tailscale_ip(host) or _direct_reachable(host):
        yield SMBEndpoint(host, 445, False)
        return

    cli = shutil.which('tailscale')
    if not cli:
        raise ConnectionError(
            'Port SMB 445 jest niedostępny, a polecenie tailscale nie jest dostępne dla aplikacji.'
        )

    with _LocalRelay(host, cli) as server:
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={'poll_interval': 0.05}, daemon=True)
        thread.start()
        try:
            yield SMBEndpoint('127.0.0.1', server.server_address[1], True)
        finally:
            server.shutdown()
            server.stop_children()
            thread.join(timeout=2)
