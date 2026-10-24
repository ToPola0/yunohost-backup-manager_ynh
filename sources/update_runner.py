"""Run YunoHost's native app upgrade outside the app's own systemd cgroup.

Invoked via a transient systemd-run unit. No persistent OS services or
network configuration are added. Updating the app restarts its web server;
this runner must outlive that restart to record the final result.
"""
import argparse
import os
import subprocess
import time
from pathlib import Path
from updater import APP_ID, REPOSITORY, LOG_FILE, write_state


def run(expected_version):
    write_state(status='running', target=expected_version,
                started_at=int(time.time()),
                message='YunoHost aktualizuje aplikację. Panel może być chwilowo niedostępny.')
    command = ['/usr/bin/yunohost', 'app', 'upgrade', APP_ID, '--url', REPOSITORY]
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(LOG_FILE, flags, 0o600)
        with os.fdopen(fd, 'wb') as log:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=7200, check=False)
        if result.returncode == 0:
            write_state(status='success', target=expected_version,
                        finished_at=int(time.time()), message='Aktualizacja zakończona pomyślnie.')
        else:
            with open(LOG_FILE, 'rb') as log:
                log.seek(max(0, log.seek(0, os.SEEK_END) - 4096))
                tail = log.read().decode('utf-8', errors='replace')
            write_state(status='error', target=expected_version,
                        finished_at=int(time.time()),
                        message='Aktualizacja YunoHost nie powiodła się (kod %s).\n%s' %
                                (result.returncode, tail[-2500:]))
    except Exception as exc:
        write_state(status='error', target=expected_version,
                    finished_at=int(time.time()),
                    message='Błąd aktualizacji: %s: %s' % (type(exc).__name__, exc))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-version', required=True)
    args = parser.parse_args()
    run(args.expected_version)
