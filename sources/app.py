from flask import Flask, jsonify, render_template_string, request, session
from cryptography.fernet import Fernet
from smb.SMBConnection import SMBConnection
from smb import smb_structs
from smb_transport import smb_endpoint
import smbclient
import sqlite3
import threading
import pathlib
import os
import re
import io
import uuid
import subprocess
import shutil
import hashlib
import time
import hmac
import secrets
from updater import APP_VERSION, check_remote, read_state, write_state

app = Flask(__name__)
app.json.ensure_ascii = False
ROOT = pathlib.Path(__file__).resolve().parent
DATA = ROOT / 'data'
DATA.mkdir(exist_ok=True)
DB = DATA / 'magazyny.sqlite3'
KEY_FILE = DATA / 'secret.key'
SMB_LOCK = threading.RLock()

if not KEY_FILE.exists():
    with open(KEY_FILE, 'xb') as f:
        f.write(Fernet.generate_key())
try:
    os.chmod(KEY_FILE, 0o600)
except OSError:
    pass
CIPHER = Fernet(KEY_FILE.read_bytes())
# A separate signing derivation for the updater's CSRF-protected admin action.
app.config.update(SECRET_KEY=hashlib.sha256(KEY_FILE.read_bytes() + b'/session-signing').digest(),
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
                  SESSION_COOKIE_SECURE=True)
UPDATE_LAUNCH_LOCK = threading.Lock()


def db_connect():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


with db_connect() as db:
    db.execute('''CREATE TABLE IF NOT EXISTS aplikacje (id TEXT PRIMARY KEY, name TEXT NOT NULL, domain_path TEXT NOT NULL DEFAULT '')''')
    db.execute('''CREATE TABLE IF NOT EXISTS magazyny (
        id TEXT PRIMARY KEY, server TEXT NOT NULL, username TEXT NOT NULL,
        password BLOB NOT NULL, domain TEXT NOT NULL, share TEXT NOT NULL,
        protocol TEXT NOT NULL, subdirectory TEXT NOT NULL DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    columns = {row[1] for row in db.execute('PRAGMA table_info(magazyny)')}
    if 'subdirectory' not in columns:
        db.execute("ALTER TABLE magazyny ADD COLUMN subdirectory TEXT NOT NULL DEFAULT ''")


def clean(data, require_share=True, require_id=False):
    server = str(data.get('server', '')).strip()
    username = str(data.get('username', '')).strip()
    password = str(data.get('password', ''))
    domain = str(data.get('domain', '')).strip()
    share = str(data.get('share', '')).strip()
    subdirectory = str(data.get('subdirectory', '')).strip().replace('\\', '/')
    protocol = str(data.get('protocol', 'auto')).strip()
    storage_id = str(data.get('id', '')).strip()
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,253}', server):
        raise ValueError('Nieprawidłowy adres serwera.')
    if not username or not password:
        raise ValueError('Podaj użytkownika i hasło.')
    if len(username) > 255 or len(domain) > 255:
        raise ValueError('Za długa nazwa użytkownika lub domeny.')
    if protocol not in ('auto', 'smb1', 'smb2'):
        raise ValueError('Nieprawidłowy protokół.')
    if require_share and (not share or not re.fullmatch(r'[^\\/:*?"<>|\x00-\x1f]{1,255}', share)):
        raise ValueError('Nieprawidłowa nazwa udziału.')
    if subdirectory:
        segments = subdirectory.strip('/').split('/')
        if (subdirectory.startswith('/') or any(part in ('', '.', '..') for part in segments)
                or any(not re.fullmatch(r'[^\\/:*?"<>|\x00-\x1f]{1,255}', part) for part in segments)
                or len(subdirectory) > 1024):
            raise ValueError('Nieprawidłowy podkatalog. Podaj ścieżkę względną, np. kopie/yunohost.')
    if require_id and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,49}', storage_id):
        raise ValueError('ID: 1–50 znaków, litery, cyfry, _ i -.')
    return dict(id=storage_id, server=server, username=username, password=password,
                domain=domain, share=share, protocol=protocol, subdirectory=subdirectory)


def connect_legacy(cfg, smb1, address, port):
    # PySMB przechowuje przełącznik dialektu globalnie; wywołania są serializowane.
    smb_structs.SUPPORT_SMB2 = not smb1
    conn = SMBConnection(cfg['username'], cfg['password'], 'YHBACKUP',
                         cfg['server'], domain=cfg['domain'], use_ntlm_v2=True,
                         is_direct_tcp=True)
    try:
        if not conn.connect(address, port, timeout=15):
            raise ConnectionError('Serwer odrzucił połączenie SMB.')
        return conn
    except Exception:
        conn.close()
        raise


def legacy_discover(cfg, smb1):
    with SMB_LOCK:
        with smb_endpoint(cfg['server']) as endpoint:
            conn = connect_legacy(cfg, smb1, endpoint.host, endpoint.port)
            try:
                return [s.name for s in conn.listShares(timeout=15)
                        if not s.isSpecial and not s.isTemporary]
            finally:
                conn.close()


def ensure_legacy_dirs(conn, cfg):
    """Create missing subdirectories, from the share root downwards."""
    current = ''
    for part in cfg['subdirectory'].split('/') if cfg['subdirectory'] else []:
        current += '/' + part
        try:
            conn.listPath(cfg['share'], current + '/', timeout=10)
        except Exception:
            # Only create if it is truly missing; don't mask permissions/network errors.
            parent = current.rsplit('/', 1)[0] or '/'
            entries = conn.listPath(cfg['share'], parent, timeout=10)
            if any(entry.filename.casefold() == part.casefold() for entry in entries):
                raise
            conn.createDirectory(cfg['share'], current, timeout=10)
            conn.listPath(cfg['share'], current + '/', timeout=10)


def ensure_modern_dirs(cfg, cache, server):
    root = '\\\\' + server + '\\' + cfg['share']
    for part in cfg['subdirectory'].split('/') if cfg['subdirectory'] else []:
        root += '\\' + part
        try:
            smbclient.mkdir(root, connection_cache=cache)
        except FileExistsError:
            pass
        # Confirm that the path exists and is accessible.
        smbclient.listdir(root, connection_cache=cache)


def legacy_test(cfg):
    with SMB_LOCK:
        with smb_endpoint(cfg['server']) as endpoint:
            conn = connect_legacy(cfg, True, endpoint.host, endpoint.port)
            name = 'yhbackup_test_' + uuid.uuid4().hex + '.tmp'
            folder = '/' + cfg['subdirectory'].strip('/') if cfg['subdirectory'] else ''
            test_path = folder + '/' + name
            try:
                ensure_legacy_dirs(conn, cfg)
                conn.listPath(cfg['share'], folder + '/' if folder else '/', timeout=15)
                conn.storeFile(cfg['share'], test_path,
                               io.BytesIO(b'YunoHost Backup Manager test'), timeout=15)
                try:
                    conn.deleteFiles(cfg['share'], test_path, timeout=15)
                except Exception as e:
                    raise RuntimeError(f'Plik zapisany, ale nieusunięty: {name}. {e}')
                return 'SMB1' + (' przez Tailscale' if endpoint.via_tailscale else '')
            finally:
                conn.close()


def modern_test(cfg):
    cache = {}
    user = (cfg['domain'] + '\\' if cfg['domain'] else '') + cfg['username']
    with smb_endpoint(cfg['server']) as endpoint:
        server = endpoint.host
        root = '\\\\' + server + '\\' + cfg['share']
        if cfg['subdirectory']:
            root += '\\' + cfg['subdirectory'].replace('/', '\\')
        name = 'yhbackup_test_' + uuid.uuid4().hex + '.tmp'
        path = root + '\\' + name
        try:
            smbclient.register_session(server, username=user,
                                       password=cfg['password'], port=endpoint.port,
                                       connection_timeout=15, connection_cache=cache)
            ensure_modern_dirs(cfg, cache, server)
            smbclient.listdir(root, connection_cache=cache)
            with smbclient.open_file(path, mode='wb', connection_cache=cache) as f:
                f.write(b'YunoHost Backup Manager test')
            try:
                smbclient.remove(path, connection_cache=cache)
            except Exception as e:
                raise RuntimeError(f'Plik zapisany, ale nieusunięty: {name}. {e}')
            return 'SMB2/3' + (' przez Tailscale' if endpoint.via_tailscale else '')
        finally:
            try:
                smbclient.delete_session(server, connection_cache=cache)
            except Exception:
                pass


def try_protocol(cfg, smb1, modern):
    if cfg['protocol'] == 'smb1':
        return smb1()
    if cfg['protocol'] == 'smb2':
        return modern()
    errors = []
    for name, fn in [('SMB2/3', modern), ('SMB1', smb1)]:
        try:
            return fn()
        except Exception as e:
            errors.append(f'{name}: {type(e).__name__}: {e}')
    raise ConnectionError('Nie udało się połączyć:\n' + '\n'.join(errors))


def public(row):
    return {k: row[k] for k in ('id', 'server', 'username', 'domain', 'share', 'protocol', 'subdirectory', 'created_at')}


@app.get('/')
def home():
    return render_template_string(HTML)


@app.get('/api/magazyny')
def list_storages():
    with db_connect() as db:
        rows = db.execute('SELECT * FROM magazyny ORDER BY created_at, id').fetchall()
    return jsonify(success=True, magazyny=[public(r) for r in rows])


@app.post('/api/discover-shares')
def discover():
    try:
        cfg = clean(request.get_json(silent=True) or {}, require_share=False)
        shares = try_protocol(cfg, lambda: legacy_discover(cfg, True),
                              lambda: legacy_discover(cfg, False))
        return jsonify(success=True, shares=shares,
                       message=f'Znaleziono udziałów: {len(shares)}.')
    except Exception as e:
        return jsonify(success=False, shares=[], message=f'{type(e).__name__}: {e}'), 400


@app.post('/api/test-smb')
def test():
    try:
        cfg = clean(request.get_json(silent=True) or {})
        dialect = try_protocol(cfg, lambda: legacy_test(cfg), lambda: modern_test(cfg))
        return jsonify(success=True, message=f'Odczyt i zapis działają poprawnie ({dialect}).')
    except Exception as e:
        return jsonify(success=False, message=f'{type(e).__name__}: {e}'), 400


@app.post('/api/magazyny')
def save_storage():
    try:
        cfg = clean(request.get_json(silent=True) or {}, require_id=True)
        # Wymagamy udanego testu przed zapisem konfiguracji.
        dialect = try_protocol(cfg, lambda: legacy_test(cfg), lambda: modern_test(cfg))
        with db_connect() as db:
            db.execute('''INSERT INTO magazyny
                (id, server, username, password, domain, share, protocol, subdirectory)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (cfg['id'], cfg['server'], cfg['username'],
                 CIPHER.encrypt(cfg['password'].encode('utf-8')),
                 cfg['domain'], cfg['share'], cfg['protocol'], cfg['subdirectory']))
        return jsonify(success=True, message=f'Magazyn zapisany. Test: {dialect}.')
    except sqlite3.IntegrityError:
        return jsonify(success=False, message='Magazyn o takim ID już istnieje.'), 409
    except Exception as e:
        return jsonify(success=False, message=f'{type(e).__name__}: {e}'), 400


@app.put('/api/magazyny/<storage_id>')
def update_storage(storage_id):
    try:
        with db_connect() as db:
            old = db.execute('SELECT * FROM magazyny WHERE id=?', (storage_id,)).fetchone()
            if old is None:
                return jsonify(success=False, message='Nie znaleziono magazynu.'), 404
            data = request.get_json(silent=True) or {}
            if not data.get('password'):
                data['password'] = CIPHER.decrypt(old['password']).decode('utf-8')
            data['id'] = storage_id
            cfg = clean(data, require_id=True)
            dialect = try_protocol(cfg, lambda: legacy_test(cfg), lambda: modern_test(cfg))
            db.execute('''UPDATE magazyny SET server=?, username=?, password=?,
                          domain=?, share=?, protocol=?, subdirectory=? WHERE id=?''',
                       (cfg['server'], cfg['username'],
                        CIPHER.encrypt(cfg['password'].encode('utf-8')),
                        cfg['domain'], cfg['share'], cfg['protocol'], cfg['subdirectory'], storage_id))
        return jsonify(success=True, message=f'Magazyn zaktualizowany. Test: {dialect}.')
    except Exception as e:
        return jsonify(success=False, message=f'{type(e).__name__}: {e}'), 400


@app.delete('/api/magazyny/<storage_id>')
def delete_storage(storage_id):
    with db_connect() as db:
        result = db.execute('DELETE FROM magazyny WHERE id=?', (storage_id,))
    if not result.rowcount:
        return jsonify(success=False, message='Nie znaleziono magazynu.'), 404
    return jsonify(success=True, message='Magazyn usunięty.')





# Wykonywanie kopii jest dostępne tylko bezpośrednio na serwerze YunoHost.
BACKUP_DIR = pathlib.Path('/home/yunohost.backup/archives')
BACKUP_LOCK = threading.Lock()
BACKUP_STATE = {'status': 'idle', 'message': 'Brak uruchomionej kopii.', 'details': []}


def on_yunohost():
    return shutil.which('yunohost') is not None and BACKUP_DIR.is_dir() and os.geteuid() == 0


def yn_command(*args, timeout=7200):
    result = subprocess.run(['yunohost', *args], capture_output=True, text=True,
                            timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or 'Błąd YunoHost').strip()[-2000:])
    return result.stdout


def actual_apps():
    import json
    result = json.loads(yn_command('app', 'list', '--output-as', 'json', timeout=30))
    apps = result.get('apps', [])
    return [{'id': a['id'], 'name': a.get('name', a['id']),
             'domain_path': a.get('domain_path', '')} for a in apps]


def cfg_from_storage(storage_id):
    with db_connect() as db:
        row = db.execute('SELECT * FROM magazyny WHERE id=?', (storage_id,)).fetchone()
        if row is None:
            raise ValueError('Magazyn nie istnieje.')
        cfg = dict(row)
    cfg['password'] = CIPHER.decrypt(cfg['password']).decode('utf-8')
    return cfg


class HashWriter:
    def __init__(self):
        self.digest = hashlib.sha256()
        self.count = 0

    def write(self, chunk):
        self.digest.update(chunk)
        self.count += len(chunk)
        return len(chunk)


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def transfer_legacy(cfg, files):
    with SMB_LOCK:
        with smb_endpoint(cfg['server']) as endpoint:
            conn = connect_legacy(cfg, True, endpoint.host, endpoint.port)
            folder = '/' + cfg['subdirectory'] if cfg['subdirectory'] else ''
            try:
                ensure_legacy_dirs(conn, cfg)
                for path in files:
                    target = folder + '/' + path.name
                    with path.open('rb') as f:
                        conn.storeFile(cfg['share'], target, f, timeout=7200)
                    verifier = HashWriter()
                    conn.retrieveFile(cfg['share'], target, verifier, timeout=7200)
                    if verifier.count != path.stat().st_size or verifier.digest.hexdigest() != file_hash(path):
                        raise RuntimeError('Błąd weryfikacji SMB: ' + path.name)
            finally:
                conn.close()


def transfer_modern(cfg, files):
    cache = {}
    user = (cfg['domain'] + '\\' if cfg['domain'] else '') + cfg['username']
    with smb_endpoint(cfg['server']) as endpoint:
        server = endpoint.host
        root = '\\\\' + server + '\\' + cfg['share']
        if cfg['subdirectory']:
            root += '\\' + cfg['subdirectory'].replace('/', '\\')
        try:
            smbclient.register_session(server, username=user,
                                       password=cfg['password'], port=endpoint.port,
                                       connection_timeout=15, connection_cache=cache)
            ensure_modern_dirs(cfg, cache, server)
            for path in files:
                target = root + '\\' + path.name
                with path.open('rb') as source, smbclient.open_file(target, 'wb', connection_cache=cache) as dest:
                    shutil.copyfileobj(source, dest, 1024 * 1024)
                verifier = HashWriter()
                with smbclient.open_file(target, 'rb', connection_cache=cache) as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b''):
                        verifier.write(chunk)
                if verifier.count != path.stat().st_size or verifier.digest.hexdigest() != file_hash(path):
                    raise RuntimeError('Błąd weryfikacji SMB: ' + path.name)
        finally:
            try:
                smbclient.delete_session(server, connection_cache=cache)
            except Exception:
                pass


def backup_worker(app_ids, storage_id):
    try:
        BACKUP_STATE.update(status='running', message='Sprawdzanie miejsca...', details=[])
        # Zapobiegamy przepełnieniu dysku: zapas 1 GiB ponad szacowaną wielkość.
        estimated = 0
        for app_id in app_ids:
            output = yn_command('backup', 'create', '--apps', app_id, '--dry-run', timeout=300)
            match = re.search(r'(?m)^size:\s*(\d+)\s*$', output)
            if not match:
                raise RuntimeError('Nie udało się ustalić rozmiaru kopii dla ' + app_id)
            estimated += int(match.group(1))
        free = shutil.disk_usage(BACKUP_DIR).free
        if free < estimated + 1024 ** 3:
            raise RuntimeError('Za mało wolnego miejsca na kopię lokalną.')
        cfg = cfg_from_storage(storage_id)
        name = 'ybm_' + time.strftime('%Y%m%d_%H%M%S') + '_' + uuid.uuid4().hex[:8]
        BACKUP_STATE['message'] = 'Tworzenie lokalnej kopii YunoHost...'
        # Używamy jednej kopii z wybranymi aplikacjami.
        yn_command('backup', 'create', '--apps', *app_ids, '--name', name)
        files = [BACKUP_DIR / (name + '.tar'), BACKUP_DIR / (name + '.info.json')]
        if not all(f.is_file() and f.stat().st_size > 0 for f in files):
            raise RuntimeError('Niekompletna kopia lokalna; pliki pozostają na dysku.')
        BACKUP_STATE['message'] = 'Przesyłanie i weryfikacja obu plików na SMB...'
        if cfg['protocol'] == 'smb1':
            transfer_legacy(cfg, files)
        elif cfg['protocol'] == 'smb2':
            transfer_modern(cfg, files)
        else:
            # Ustal protokół PRZED transferem; nie ponawiaj po błędzie weryfikacji.
            try:
                modern_test(cfg)
            except Exception:
                legacy_test(cfg)
                transfer_legacy(cfg, files)
            else:
                transfer_modern(cfg, files)
        BACKUP_STATE['message'] = 'Weryfikacja zakończona. Usuwanie lokalnej kopii...'
        yn_command('backup', 'delete', name, timeout=120)
        BACKUP_STATE.update(status='success', message='Kopia ' + name + ' przesłana i zweryfikowana. Lokalna usunięta.',
                            details=[f.name for f in files])
    except Exception as exc:
        BACKUP_STATE.update(status='error',
                            message=str(exc) + ' Kopia lokalna, jeśli powstała, nie została celowo usunięta.')
    finally:
        BACKUP_LOCK.release()


@app.get('/api/backup/status')
def backup_status():
    return jsonify(success=True, available=on_yunohost(), **BACKUP_STATE)


@app.post('/api/backup/start')
def backup_start():
    if not on_yunohost():
        return jsonify(success=False, message='Uruchom Backup Manager bezpośrednio na YunoHost jako root.'), 400
    payload = request.get_json(silent=True) or {}
    app_ids = payload.get('apps', [])
    storage_id = payload.get('storage', '')
    if not isinstance(app_ids, list) or not app_ids or len(app_ids) > 100:
        return jsonify(success=False, message='Wybierz aplikacje.'), 400
    valid = {app['id'] for app in actual_apps()}
    if any(not isinstance(a, str) or a not in valid for a in app_ids):
        return jsonify(success=False, message='Nieprawidłowa lista aplikacji.'), 400
    if not isinstance(storage_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,49}', storage_id):
        return jsonify(success=False, message='Wybierz magazyn.'), 400
    if read_state().get('status') in ('launching', 'running'):
        return jsonify(success=False, message='Trwa aktualizacja aplikacji. Poczekaj na zakończenie.'), 409
    if not BACKUP_LOCK.acquire(blocking=False):
        return jsonify(success=False, message='Kopia już trwa.'), 409
    BACKUP_STATE.update(status='running', message='Rozpoczynanie...', details=[])
    threading.Thread(target=backup_worker, args=(app_ids, storage_id), daemon=True).start()
    return jsonify(success=True, message='Rozpoczęto wykonywanie kopii.')


@app.get('/api/aplikacje')
def list_apps():
    if on_yunohost():
        return jsonify(success=True, apps=actual_apps(), source='yunohost')
    # Lokalny tryb rozwoju: lista importowana z wyniku CLI YunoHost.
    with db_connect() as db:
        rows = db.execute('SELECT id, name, domain_path FROM aplikacje ORDER BY name').fetchall()
    return jsonify(success=True, apps=[dict(row) for row in rows], source='import')


@app.post('/api/aplikacje/import')
def import_apps():
    try:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or not isinstance(payload.get('apps'), list):
            raise ValueError('Wklej poprawny wynik polecenia yunohost app list --output-as json.')
        apps = payload['apps']
        if len(apps) > 200:
            raise ValueError('Za dużo aplikacji.')
        cleaned = []
        for item in apps:
            if not isinstance(item, dict):
                raise ValueError('Nieprawidłowy wpis aplikacji.')
            app_id = item.get('id')
            name = item.get('name')
            domain_path = item.get('domain_path', '')
            if (not isinstance(app_id, str) or not re.fullmatch(r'[a-zA-Z0-9_]{1,100}', app_id)
                    or not isinstance(name, str) or not 1 <= len(name) <= 200
                    or not isinstance(domain_path, str) or len(domain_path) > 500):
                raise ValueError('Nieprawidłowe dane aplikacji.')
            cleaned.append((app_id, name, domain_path))
        with db_connect() as db:
            db.execute('DELETE FROM aplikacje')
            db.executemany('INSERT INTO aplikacje (id, name, domain_path) VALUES (?, ?, ?)', cleaned)
        return jsonify(success=True, message=f'Zaimportowano aplikacji: {len(cleaned)}.')
    except (ValueError, TypeError) as exc:
        return jsonify(success=False, message=str(exc)), 400



@app.get('/api/updates/check')
def updates_check():
    # Same-origin clients receive a short-lived signed-session CSRF token.
    token = secrets.token_urlsafe(32)
    session['update_csrf'] = token
    response = {'installed': APP_VERSION, 'csrf': token, 'state': read_state()}
    try:
        response.update(check_remote())
        response['success'] = True
    except Exception as exc:
        response.update(success=False, available=False, latest=None,
                        message='Nie udało się sprawdzić GitHuba: %s' % exc)
    return jsonify(response)


@app.get('/api/updates/status')
def updates_status():
    return jsonify(success=True, installed=APP_VERSION, state=read_state())


@app.post('/api/updates/start')
def updates_start():
    if not on_yunohost():
        return jsonify(success=False, message='Aktualizacja jest dostępna wyłącznie na YunoHost.'), 400
    csrf = request.headers.get('X-Update-CSRF', '')
    expected_csrf = session.get('update_csrf', '')
    if not csrf or not expected_csrf or not hmac.compare_digest(csrf, expected_csrf):
        return jsonify(success=False, message='Nieprawidłowe potwierdzenie żądania. Odśwież panel.'), 403
    if BACKUP_LOCK.locked():
        return jsonify(success=False, message='Trwa tworzenie kopii. Poczekaj na zakończenie.'), 409
    if not UPDATE_LAUNCH_LOCK.acquire(blocking=False):
        return jsonify(success=False, message='Uruchamianie aktualizacji już trwa.'), 409
    try:
        current = read_state()
        if current['status'] in ('launching', 'running'):
            return jsonify(success=False, message='Aktualizacja już trwa.'), 409
        version = check_remote()  # Repeat validation immediately before launching.
        if not version['available']:
            return jsonify(success=False, message='Masz już najnowszą wersję.'), 409
        expected_version = (request.get_json(silent=True) or {}).get('version')
        if not isinstance(expected_version, str) or expected_version != version['latest']:
            return jsonify(success=False, message='Wersja na GitHubie zmieniła się. Sprawdź ponownie.'), 409
        runner = str(ROOT / 'update_runner.py')
        systemd_run = shutil.which('systemd-run')
        if not systemd_run or not pathlib.Path(runner).is_file():
            return jsonify(success=False, message='Brak uruchamiacza aktualizacji w pakiecie.'), 500
        if BACKUP_LOCK.locked():
            return jsonify(success=False, message='W międzyczasie rozpoczęła się kopia zapasowa.'), 409
        write_state(status='launching', target=expected_version,
                    started_at=int(time.time()), message='Uruchamianie aktualizacji YunoHost...')
        unit = 'yunohost-backup-manager-upd-' + uuid.uuid4().hex[:12]
        try:
            result = subprocess.run(
                [systemd_run, '--quiet', '--collect', '--unit=' + unit,
                 '--property=Type=exec', '--', '/usr/bin/python3', runner,
                 '--expected-version', expected_version],
                capture_output=True, text=True, timeout=20, check=False)
            if result.returncode:
                raise RuntimeError((result.stderr or result.stdout or 'systemd-run nie uruchomił aktualizacji.')[-1200:])
        except Exception as exc:
            write_state(status='error', target=expected_version,
                        finished_at=int(time.time()), message='Nie uruchomiono aktualizacji: %s' % exc)
            return jsonify(success=False, message=str(exc)), 500
        return jsonify(success=True, message='Aktualizacja uruchomiona.', target=expected_version)
    except Exception as exc:
        return jsonify(success=False, message='Nie można rozpocząć aktualizacji: %s' % exc), 500
    finally:
        UPDATE_LAUNCH_LOCK.release()

HTML = r'''<!doctype html>
<html lang="pl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>YunoHost Backup Manager</title><style>
*{box-sizing:border-box}body{margin:0;background:#f1f3f7;color:#26354b;font:15px Arial,sans-serif}
header{background:#263b58;color:white;padding:22px 32px;font-size:22px;font-weight:bold}
main{max-width:960px;margin:32px auto;padding:0 18px}.panel{background:white;border-radius:10px;padding:26px;margin-bottom:20px;box-shadow:0 3px 16px #0001}
h2{margin:0 0 20px}label{display:block;font-weight:bold;margin:14px 0 6px}input,select{width:100%;padding:11px;border:1px solid #c7d0de;border-radius:5px;font:inherit;background:white}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:0 18px}@media(max-width:650px){.grid{grid-template-columns:1fr}}
button{background:#315b92;color:white;border:0;border-radius:5px;padding:11px 17px;cursor:pointer;font:inherit}button.secondary{background:#53677e}button.danger{background:#a83232}button:disabled{opacity:.5;cursor:wait}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:22px}.message{white-space:pre-wrap;margin-top:18px;padding:13px;border-radius:5px;display:none}.ok{background:#dff2e5;color:#176331}.error{background:#fbe5e5;color:#8a2525}
textarea{width:100%;min-height:95px;padding:11px;border:1px solid #c7d0de;border-radius:5px;font:13px monospace} .appitem{display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid #e4e8ef}.appitem input{width:auto}.appitem small{display:block;margin-top:3px}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:12px 8px;border-bottom:1px solid #e4e8ef}td button{padding:7px 10px;margin:2px}small{color:#657286}.tablewrap{overflow-x:auto}
</style></head><body><header>YunoHost Backup Manager <small style="color:#cad5e5">0.5~ynh7</small></header><main>
<section class="panel" id="updatePanel"><h2>Aktualizacje aplikacji</h2>
<p>Wersja zainstalowana: <strong id="versionInstalled">0.5~ynh7</strong> &nbsp;|&nbsp; GitHub: <strong id="versionRemote">Sprawdzanie...</strong></p>
<div id="updateMessage" class="message" style="display:none"></div>
<div class="actions"><button type="button" id="checkUpdate" class="secondary">Sprawdź aktualizacje</button><button type="button" id="startUpdate" disabled>Aktualizuj aplikację</button></div>
<p><small>Aktualizacja korzysta z mechanizmu YunoHost. Podczas jej wykonywania panel może być chwilowo niedostępny. Zapisane magazyny i hasła pozostają w katalogu danych aplikacji.</small></p>
</section>
<section class="panel"><h2>Magazyny SMB/CIFS</h2><div class="tablewrap"><table><thead><tr><th>ID</th><th>Serwer</th><th>Udział</th><th>Protokół</th><th>Akcje</th></tr></thead><tbody id="rows"><tr><td colspan="5">Wczytywanie...</td></tr></tbody></table></div></section>
<section class="panel"><h2 id="formTitle">Dodaj magazyn SMB/CIFS</h2><form id="form">
<div class="grid"><div><label for="id">ID magazynu</label><input id="id" name="id" placeholder="np. nas-backup" required></div>
<div><label for="server">Serwer</label><input id="server" name="server" placeholder="192.168.2.122" required></div>
<div><label for="username">Użytkownik</label><input id="username" name="username" required></div>
<div><label for="password">Hasło</label><input id="password" name="password" type="password" autocomplete="new-password" required></div>
<div><label for="domain">Domena / grupa robocza (opcjonalnie)</label><input id="domain" name="domain" placeholder="WORKGROUP"></div>
<div><label for="protocol">Protokół</label><select id="protocol" name="protocol"><option value="auto">Automatycznie (SMB1 / SMB2 / SMB3)</option><option value="smb1">SMB1</option><option value="smb2">SMB2 / SMB3</option></select></div>
</div><label for="share">Udział SMB (Share)</label><select id="share" name="share" required><option value="">Najpierw pobierz udziały</option></select>
<label for="subdirectory">Subdirectory (opcjonalnie)</label><input id="subdirectory" name="subdirectory" placeholder="np. kopie/yunohost"><p><small>Jeśli podkatalog nie istnieje, zostanie automatycznie utworzony podczas testu lub zapisu magazynu. Pozostaw puste, aby użyć katalogu głównego udziału.</small></p>
<div class="actions"><button type="button" id="discover">Pobierz udziały</button><button type="button" id="test" class="secondary">Sprawdź odczyt i zapis</button><button type="submit" id="save">Zapisz magazyn</button><button type="button" id="cancel" class="secondary" hidden>Anuluj edycję</button></div></form>
<div id="message" class="message"></div><p><small>Hasła są szyfrowane lokalnie. Podczas edycji puste hasło oznacza zachowanie poprzedniego. Aplikacja testowa działa wyłącznie lokalnie.</small></p></section>
<section class="panel"><h2>Kopie zapasowe – wybór aplikacji</h2>
<p><small>Na YunoHost aplikacje wykrywane są automatycznie. Na Windows pozostaje tryb lokalnego podglądu.</small></p>
<div id="apps"><small>Wczytywanie aplikacji...</small></div>
<label for="backupStorage">Magazyn docelowy</label><select id="backupStorage"><option value="">Wybierz magazyn</option></select>
<div class="actions"><button type="button" id="runBackup" disabled>Wykonaj kopię</button></div>
<details style="margin-top:22px"><summary>Importuj listę aplikacji z YunoHost (tryb lokalny)</summary>
<p><small>Wklej wynik polecenia <code>yunohost app list --output-as json</code>. Nie podawaj haseł.</small></p>
<textarea id="appsJson" placeholder='{"apps":[{"id":"wordpress","name":"Bałchan","domain_path":"strona.rpkj.ovh/organypiszczalkowe"}]}'></textarea>
<div class="actions"><button type="button" id="importApps">Importuj aplikacje</button></div></details>
<div id="appsMessage" class="message"></div><div id="backupMessage" class="message"></div></section>
</main><script>
const $=id=>document.getElementById(id);let editing=null;let records=[];
function msg(ok,s){$('message').style.display='block';$('message').className='message '+(ok?'ok':'error');$('message').textContent=s}
function data(){return Object.fromEntries(new FormData($('form')))}
async function api(url,method='GET',payload){const base=window.location.pathname.replace(/\/$/,'');const r=await fetch(base+url,{method,headers:{'Content-Type':'application/json'},body:payload?JSON.stringify(payload):undefined});return await r.json()}
function busy(v){for(const x of ['discover','test','save'])$(x).disabled=v}
function reset(){editing=null;$('form').reset();$('id').disabled=false;$('password').required=true;$('formTitle').textContent='Dodaj magazyn SMB/CIFS';$('cancel').hidden=true;$('share').innerHTML='<option value="">Najpierw pobierz udziały</option>'}
async function refresh(){const x=await api('/api/magazyny');records=x.magazyny||[];const storage=$('backupStorage');const selected=storage.value;storage.replaceChildren(new Option('Wybierz magazyn',''));for(const m of records)storage.add(new Option(m.id+' ('+m.server+'/'+m.share+')',m.id));storage.value=selected;const tbody=$('rows');tbody.replaceChildren();if(!records.length){const tr=tbody.insertRow();const td=tr.insertCell();td.colSpan=5;td.textContent='Brak zapisanych magazynów.';return}for(const m of records){const tr=tbody.insertRow();for(const v of [m.id,m.server,m.share,m.protocol==='auto'?'Auto':m.protocol.toUpperCase()])tr.insertCell().textContent=v;const td=tr.insertCell();for(const [title,fn,danger] of [['Edytuj',()=>edit(m.id),false],['Usuń',()=>remove(m.id),true]]){const b=document.createElement('button');b.textContent=title;b.className=danger?'danger':'secondary';b.onclick=fn;td.appendChild(b)}}}
function edit(id){const m=records.find(x=>x.id===id);if(!m)return;editing=id;for(const k of ['id','server','username','domain','protocol','subdirectory'])$(k).value=m[k]||'';$('id').disabled=true;$('password').value='';$('password').required=false;$('share').replaceChildren(new Option(m.share,m.share));$('formTitle').textContent='Edytuj magazyn: '+id;$('cancel').hidden=false;msg(true,'Edytujesz magazyn. Puste hasło zachowa poprzednie.');$('form').scrollIntoView({behavior:'smooth'})}
async function remove(id){if(!confirm('Usunąć magazyn '+id+'?'))return;const x=await api('/api/magazyny/'+encodeURIComponent(id),'DELETE');msg(x.success,x.message);if(x.success){if(editing===id)reset();await refresh()}}
$('cancel').onclick=()=>{reset();msg(true,'Anulowano edycję.')};
for(const k of ['server','username','password','domain','protocol'])$(k).addEventListener('change',()=>{if(k==='password'&&editing)return;$('share').innerHTML='<option value="">Najpierw pobierz udziały</option>'});
async function withBusy(fn){busy(true);try{await fn()}catch(e){msg(false,'Błąd komunikacji: '+e.message)}finally{busy(false)}}
$('discover').onclick=()=>withBusy(async()=>{if(editing&&!$('password').value){msg(false,'Do ponownego pobrania udziałów podaj hasło.');return}msg(true,'Pobieranie udziałów...');const x=await api('/api/discover-shares','POST',data());$('share').replaceChildren();if(x.success&&x.shares.length){for(const s of x.shares)$('share').add(new Option(s,s));const m=records.find(r=>r.id===editing);if(m&&x.shares.includes(m.share))$('share').value=m.share}else $('share').add(new Option('Brak udziałów',''));msg(x.success,x.message)});
$('test').onclick=()=>withBusy(async()=>{if(!editing&&!$('form').reportValidity())return;if(editing&&!$('password').value){msg(false,'Do ręcznego testu podaj hasło.');return}msg(true,'Sprawdzanie odczytu i zapisu...');const x=await api('/api/test-smb','POST',data());msg(x.success,x.message)});
$('form').onsubmit=e=>{e.preventDefault();withBusy(async()=>{const payload=data();if(editing)payload.id=editing;msg(true,'Testowanie połączenia i zapisywanie...');const x=await api(editing?'/api/magazyny/'+encodeURIComponent(editing):'/api/magazyny',editing?'PUT':'POST',payload);msg(x.success,x.message);if(x.success){reset();await refresh()}})};
async function refreshApps(){
 const data=await api('/api/aplikacje');const host=$('apps');host.replaceChildren();
 if(!data.apps.length){host.textContent='Brak zaimportowanych aplikacji. Wklej wynik z YunoHost poniżej.';return}
 for(const a of data.apps){const line=document.createElement('label');line.className='appitem';
 const cb=document.createElement('input');cb.type='checkbox';cb.value=a.id;cb.checked=true;
 const desc=document.createElement('span');const title=document.createElement('strong');title.textContent=a.name+' ('+a.id+')';
 const path=document.createElement('small');path.textContent=a.domain_path;desc.append(title,path);line.append(cb,desc);host.appendChild(line)}
}
$('importApps').onclick=async()=>{const output=$('appsMessage');output.style.display='block';
 try{const input=JSON.parse($('appsJson').value);const result=await api('/api/aplikacje/import','POST',input);
 output.className='message '+(result.success?'ok':'error');output.textContent=result.message;if(result.success)await refreshApps()}
 catch(e){output.className='message error';output.textContent='Nieprawidłowy JSON: '+e.message}};
async function backupPoll(){
 const s=await api('/api/backup/status');const btn=$('runBackup');btn.disabled=!s.available||s.status==='running';
 const box=$('backupMessage');box.style.display='block';box.className='message '+(s.status==='error'?'error':'ok');
 box.textContent=s.available?s.message:'Tryb Windows: kopie będą dostępne po uruchomieniu aplikacji na YunoHost.';
}
$('runBackup').onclick=async()=>{
 const apps=[...$('apps').querySelectorAll('input[type=checkbox]:checked')].map(x=>x.value);
 const storage=$('backupStorage').value;
 if(!apps.length||!storage){alert('Wybierz aplikacje i magazyn.');return}
 if(!confirm('Wykonać kopię '+apps.join(', ')+' na magazyn '+storage+'?'))return;
 const r=await api('/api/backup/start','POST',{apps,storage});
 if(!r.success)alert(r.message);await backupPoll();
};
let updateToken='';let availableUpdate='';let updating=false;
function updateInfo(ok, text){const b=$('updateMessage');b.style.display='block';b.className='message '+(ok?'ok':'error');b.textContent=text}
async function checkUpdates(){
 $('checkUpdate').disabled=true; $('startUpdate').disabled=true;
 updateInfo(true,'Sprawdzanie aktualizacji na GitHubie...');
 try{
  const u=await api('/api/updates/check'); updateToken=u.csrf||'';availableUpdate='';
  $('versionInstalled').textContent=u.installed||'?';
  $('versionRemote').textContent=u.latest||'Brak danych';
  if(!u.success){updateInfo(false,u.message);return}
  if(u.available){availableUpdate=u.latest; updateInfo(true,'Dostępna nowa wersja: '+u.latest);$('startUpdate').disabled=updating}
  else updateInfo(true,'Aplikacja jest aktualna.');
  if(u.state&&['launching','running'].includes(u.state.status)){updating=true;$('startUpdate').disabled=true;updateInfo(true,u.state.message)}
 }catch(e){updateInfo(false,'Nie udało się sprawdzić aktualizacji: '+e.message)}
 finally{$('checkUpdate').disabled=false}
}
$('checkUpdate').onclick=checkUpdates;
$('startUpdate').onclick=async()=>{
 if(!availableUpdate||!updateToken)return;
 if(!confirm('Zaktualizować YunoHost Backup Manager do '+availableUpdate+'? Panel uruchomi ponownie własną usługę.'))return;
 $('startUpdate').disabled=true; updating=true;
 updateInfo(true,'Uruchamianie aktualizacji...');
 try{
  const url=window.location.pathname.replace(/\/$/,'')+'/api/updates/start';
  const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json','X-Update-CSRF':updateToken},body:JSON.stringify({version:availableUpdate})});
  const x=await r.json();
  if(!x.success){updating=false;updateInfo(false,x.message);$('startUpdate').disabled=false}
  else updateInfo(true,x.message+' Trwa aktualizacja w YunoHost...');
 }catch(e){updateInfo(false,'Błąd uruchamiania: '+e.message);updating=false}
};
async function pollUpdates(){
 try{
  const s=await api('/api/updates/status');if(!s.success)return;
  if(['launching','running'].includes(s.state.status)){
   updating=true; $('startUpdate').disabled=true;updateInfo(true,s.state.message);
  }else if(['success','error'].includes(s.state.status)){
   if(updating || s.state.status==='error')updateInfo(s.state.status==='success',s.state.message+(s.state.status==='success'?' Odśwież stronę, by zobaczyć nową wersję.':''));
   updating=false;
  }
 }catch(e){if(updating)updateInfo(true,'Trwa aktualizacja — oczekiwanie na ponowne uruchomienie panelu...')}
}
checkUpdates();setInterval(pollUpdates,3500);
backupPoll().catch(e=>msg(false,e.message));
setInterval(()=>backupPoll().catch(()=>{}),3000);
refreshApps().catch(e=>msg(false,e.message));
refresh().catch(e=>msg(false,e.message));
</script></body></html>'''

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5050, debug=False)
