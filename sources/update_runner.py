"""Upgrade *this YunoHost app* and verify that its new code is serving requests.

Runs within the application's transient updater job, not a persistent system service.
Only the application itself may be restarted by this module.
"""
import argparse
import ast
import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path
from updater import APP_ID, REPOSITORY, LOG_FILE, write_state

UPDATER_SOURCE = Path(__file__).with_name('updater.py')
APPLICATION_URL = 'http://127.0.0.1:5051/api/updates/status'


def source_version():
    """Read the installed application's version without executing the source file."""
    tree = ast.parse(UPDATER_SOURCE.read_text(encoding='utf-8'))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == 'APP_VERSION'
            for target in node.targets
        ):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return node.value.value
    raise RuntimeError('Zainstalowany plik updater.py nie zawiera numeru wersji.')


def runtime_version():
    """The version returned by the *running* Gunicorn worker, not a file/cache."""
    with urllib.request.urlopen(APPLICATION_URL, timeout=3) as result:
        if result.status != 200:
            raise RuntimeError('Panel zwraca HTTP ' + str(result.status))
        data = json.load(result)
        if not data.get('success'):
            raise RuntimeError('Panel nie zgłosił prawidłowego stanu.')
        return data.get('installed')


def await_runtime(expected_version, attempts=16, pause=0.7):
    last_error = 'Brak odpowiedzi panelu.'
    for attempt in range(attempts):
        try:
            version = runtime_version()
            if version == expected_version:
                return True, version
            last_error = 'Panel nadal uruchamia wersję %s (oczekiwano %s).' % (version, expected_version)
        except Exception as exc:
            last_error = '%s: %s' % (type(exc).__name__, exc)
        if attempt + 1 != attempts:
            time.sleep(pause)
    return False, last_error


def log_line(message):
    with LOG_FILE.open('a', encoding='utf-8') as log:
        log.write('YBM CHECK ' + message + '\n')


def run(expected_version):
    started = int(time.time())
    write_state(status='running', target=expected_version,
                started_at=started,
                message='YunoHost aktualizuje aplikację. Panel może być chwilowo niedostępny.')
    command = ['/usr/bin/yunohost', 'app', 'upgrade', APP_ID, '--url', REPOSITORY]
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(LOG_FILE, flags, 0o600)
        with os.fdopen(fd, 'wb') as log:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=7200, check=False)
        if result.returncode:
            raise RuntimeError('YunoHost zakończył aktualizację kodem %s.' % result.returncode)
        log_line('YunoHost zgłosił sukces. Sprawdzanie plików i uruchomionego panelu...')
        disk_version = source_version()
        if disk_version != expected_version:
            raise RuntimeError('YunoHost zakończył operację, lecz kod wtyczki pozostał w wersji %s '
                               '(oczekiwano %s). Sprawdź zawartość repozytorium.'
                               % (disk_version, expected_version))
        ok, detail = await_runtime(expected_version)
        if not ok:
            log_line('Panel nie uruchomił nowej wersji: ' + str(detail))
            log_line('Ponowny rozruch wyłącznie usługi ' + APP_ID + '...')
            # Restart ONLY this application's service, never Tailscale or other services.
            restart = subprocess.run(['/usr/bin/systemctl', 'restart', APP_ID],
                                     capture_output=True, text=True, timeout=45, check=False)
            if restart.returncode:
                raise RuntimeError('Restart usługi wtyczki nie powiódł się: '
                                   + (restart.stderr or restart.stdout or str(restart.returncode))[-1200:])
            ok, detail = await_runtime(expected_version, attempts=22)
            if not ok:
                raise RuntimeError('Nowa wersja jest na dysku, lecz panel jej nie uruchomił: ' + str(detail))
        log_line('Weryfikacja zakończona: panel działa w wersji ' + expected_version)
        write_state(status='success', target=expected_version,
                    started_at=started, finished_at=int(time.time()),
                    message='Aktualizacja zweryfikowana: panel działa w wersji ' + expected_version + '.')
    except Exception as exc:
        error = '%s: %s' % (type(exc).__name__, exc)
        try:
            log_line('BŁĄD: ' + error)
        except OSError:
            pass
        write_state(status='error', target=expected_version,
                    started_at=started, finished_at=int(time.time()),
                    message='Aktualizacja nie została potwierdzona: ' + error[-1800:])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-version', required=True)
    args = parser.parse_args()
    run(args.expected_version)
