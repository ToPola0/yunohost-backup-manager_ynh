from flask import Flask, jsonify, render_template_string, request, session, send_file
from cryptography.fernet import Fernet
from smb.SMBConnection import SMBConnection
from smb import smb_structs
from smb_transport import smb_endpoint
import smbclient
import sqlite3
import errno
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
import unicodedata
import tempfile
import json
import datetime
import fcntl
from updater import APP_VERSION, check_remote, read_state, write_state, read_log_chunk, LOG_FILE
from cron_schedule import CronSpec, next_occurrence

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
    db.execute('''CREATE TABLE IF NOT EXISTS harmonogramy (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, cron TEXT NOT NULL,
        storage_id TEXT NOT NULL, apps_json TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
        last_slot TEXT, last_run TEXT, last_result TEXT DEFAULT 'Nie uruchomiono'
    )''')


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


def ensure_modern_dirs(cfg, cache, server, port):
    root = '\\\\' + server + '\\' + cfg['share']
    for part in cfg['subdirectory'].split('/') if cfg['subdirectory'] else []:
        root += '\\' + part
        try:
            smbclient.mkdir(root, port=port, connection_cache=cache)
        except OSError as exc:
            # smbprotocol raises SMBOSError(errno=EEXIST), not FileExistsError,
            # for STATUS_OBJECT_NAME_COLLISION on an existing directory.
            if exc.errno != errno.EEXIST:
                raise
        # Also reject collisions with ordinary files and inaccessible directories.
        smbclient.listdir(root, port=port, connection_cache=cache)


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
            ensure_modern_dirs(cfg, cache, server, endpoint.port)
            smbclient.listdir(root, port=endpoint.port, connection_cache=cache)
            with smbclient.open_file(path, mode='wb', port=endpoint.port, connection_cache=cache) as f:
                f.write(b'YunoHost Backup Manager test')
            try:
                smbclient.remove(path, port=endpoint.port, connection_cache=cache)
            except Exception as e:
                raise RuntimeError(f'Plik zapisany, ale nieusunięty: {name}. {e}')
            return 'SMB2/3' + (' przez Tailscale' if endpoint.via_tailscale else '')
        finally:
            try:
                smbclient.delete_session(server, port=endpoint.port, connection_cache=cache)
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
BACKUP_STATE_GUARD = threading.RLock()
BACKUP_STATE = {'status': 'idle', 'phase': 'idle', 'percent': None,
                'message': 'Brak uruchomionej kopii.', 'details': [],
                'done_bytes': 0, 'total_bytes': 0, 'log': []}


def backup_event(message, phase=None, status=None, percent=None, reset=False):
    """Report verified stages; never invent a percentage for YunoHost CLI work."""
    with BACKUP_STATE_GUARD:
        if reset:
            BACKUP_STATE.update(log=[], done_bytes=0, total_bytes=0, details=[])
        BACKUP_STATE['message'] = message
        BACKUP_STATE['percent'] = percent
        if phase is not None:
            BACKUP_STATE['phase'] = phase
        if status is not None:
            BACKUP_STATE['status'] = status
        BACKUP_STATE['log'] = (BACKUP_STATE['log'] +
                               [time.strftime('%H:%M:%S') + '  ' + message])[-140:]


class BackupMeter:
    """Counts bytes sent and received from SMB for the selected archives."""
    def __init__(self, files):
        self.total = 2 * sum(path.stat().st_size for path in files)
        self.done = 0
        with BACKUP_STATE_GUARD:
            BACKUP_STATE['total_bytes'] = self.total
            BACKUP_STATE['done_bytes'] = 0
            BACKUP_STATE['percent'] = 0

    def advance(self, count):
        if count <= 0:
            return
        with BACKUP_STATE_GUARD:
            self.done += count
            BACKUP_STATE['done_bytes'] = self.done
            BACKUP_STATE['percent'] = min(100, int(self.done * 100 / max(self.total, 1)))


class MeteredReader:
    """Hash original bytes while tracking actual SMB uploads."""
    def __init__(self, stream, meter):
        self.stream = stream
        self.meter = meter
        self.digest = hashlib.sha256()
        self.count = 0

    def read(self, size=-1):
        chunk = self.stream.read(size)
        if chunk:
            self.digest.update(chunk)
            self.count += len(chunk)
            self.meter.advance(len(chunk))
        return chunk

    def __getattr__(self, key):
        return getattr(self.stream, key)



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
    def __init__(self, meter=None):
        self.digest = hashlib.sha256()
        self.count = 0
        self.meter = meter

    def write(self, chunk):
        self.digest.update(chunk)
        self.count += len(chunk)
        if self.meter is not None:
            self.meter.advance(len(chunk))
        return len(chunk)


def backup_archive_name(app_ids, app_names=None):
    """Use recognizable YunoHost app labels, IDs and time in archive filenames."""
    labels = app_names if app_names and len(app_names) == len(app_ids) else app_ids
    safe_labels = []
    for label, app_id in zip(labels, app_ids):
        text = unicodedata.normalize('NFKD', label.replace('ł', 'l').replace('Ł', 'L'))
        text = text.encode('ascii', 'ignore').decode('ascii')
        text = re.sub(r'[^A-Za-z0-9_-]+', '-', text).strip('-_')
        if not text:
            text = re.sub(r'[^A-Za-z0-9_-]+', '-', app_id).strip('-_') or 'app'
        safe_labels.append(text)
    description = '-'.join(safe_labels)
    if len(description) > 70:
        checksum = hashlib.sha256('\x00'.join(app_ids).encode('utf-8')).hexdigest()[:10]
        first = safe_labels[0][:40].rstrip('-_') or 'app'
        description = f'{first}-plus{len(app_ids)-1}-{checksum}'
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    return f'ybm_{description}_{timestamp}_{uuid.uuid4().hex[:6]}'


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def transfer_legacy(cfg, files, meter):
    with SMB_LOCK:
        with smb_endpoint(cfg['server']) as endpoint:
            conn = connect_legacy(cfg, True, endpoint.host, endpoint.port)
            folder = '/' + cfg['subdirectory'] if cfg['subdirectory'] else ''
            try:
                ensure_legacy_dirs(conn, cfg)
                for path in files:
                    target = folder + '/' + path.name
                    backup_event('SMB1: wysyłanie ' + path.name, phase='transfer',
                                 percent=BACKUP_STATE['percent'])
                    with path.open('rb') as stream:
                        source = MeteredReader(stream, meter)
                        conn.storeFile(cfg['share'], target, source, timeout=7200)
                    backup_event('SMB1: weryfikacja SHA256 ' + path.name, phase='transfer',
                                 percent=BACKUP_STATE['percent'])
                    verifier = HashWriter(meter)
                    conn.retrieveFile(cfg['share'], target, verifier, timeout=7200)
                    if (verifier.count != source.count or
                            verifier.count != path.stat().st_size or
                            verifier.digest.digest() != source.digest.digest()):
                        raise RuntimeError('Błąd weryfikacji SMB: ' + path.name)
                    backup_event('SMB1: SHA256 zgodne dla ' + path.name,
                                 phase='transfer', percent=BACKUP_STATE['percent'])
            finally:
                conn.close()


def transfer_modern(cfg, files, meter):
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
            ensure_modern_dirs(cfg, cache, server, endpoint.port)
            for path in files:
                target = root + '\\' + path.name
                backup_event('SMB2/3: wysyłanie ' + path.name, phase='transfer',
                             percent=BACKUP_STATE['percent'])
                with path.open('rb') as stream, smbclient.open_file(target, 'wb', port=endpoint.port, connection_cache=cache) as dest:
                    source = MeteredReader(stream, meter)
                    shutil.copyfileobj(source, dest, 1024 * 1024)
                backup_event('SMB2/3: weryfikacja SHA256 ' + path.name, phase='transfer',
                             percent=BACKUP_STATE['percent'])
                verifier = HashWriter(meter)
                with smbclient.open_file(target, 'rb', port=endpoint.port, connection_cache=cache) as remote:
                    for chunk in iter(lambda: remote.read(1024 * 1024), b''):
                        verifier.write(chunk)
                if (verifier.count != source.count or
                        verifier.count != path.stat().st_size or
                        verifier.digest.digest() != source.digest.digest()):
                    raise RuntimeError('Błąd weryfikacji SMB: ' + path.name)
                backup_event('SMB2/3: SHA256 zgodne dla ' + path.name,
                             phase='transfer', percent=BACKUP_STATE['percent'])
        finally:
            try:
                smbclient.delete_session(server, port=endpoint.port, connection_cache=cache)
            except Exception:
                pass


def backup_worker(app_ids, storage_id, app_names):
    try:
        backup_event('Sprawdzanie wolnego miejsca i rozmiaru kopii…',
                     phase='prepare', status='running')
        estimated = 0
        for app_id in app_ids:
            backup_event('Szacowanie miejsca: ' + app_id, phase='prepare')
            output = yn_command('backup', 'create', '--apps', app_id, '--dry-run', timeout=300)
            match = re.search(r'(?m)^size:\s*(\d+)\s*$', output)
            if not match:
                raise RuntimeError('Nie udało się ustalić rozmiaru kopii dla ' + app_id)
            estimated += int(match.group(1))
        free = shutil.disk_usage(BACKUP_DIR).free
        if free < estimated + 1024 ** 3:
            raise RuntimeError('Za mało wolnego miejsca na kopię lokalną.')
        cfg = cfg_from_storage(storage_id)
        name = backup_archive_name(app_ids, app_names)
        backup_event('YunoHost tworzy archiwum ' + name + ' (' + ', '.join(app_names) + ')',
                     phase='create')
        yn_command('backup', 'create', '--apps', *app_ids, '--name', name)
        files = [BACKUP_DIR / (name + '.tar'), BACKUP_DIR / (name + '.info.json')]
        if not all(f.is_file() and f.stat().st_size > 0 for f in files):
            raise RuntimeError('Niekompletna kopia lokalna; pliki pozostają na dysku.')
        meter = BackupMeter(files)
        total_mib = sum(path.stat().st_size for path in files) / 1024**2
        backup_event(f'Archiwum gotowe ({total_mib:.1f} MiB). Rozpoczynam wysyłanie i kontrolę SHA256.',
                     phase='transfer', percent=0)
        if cfg['protocol'] == 'smb1':
            transfer_legacy(cfg, files, meter)
        elif cfg['protocol'] == 'smb2':
            transfer_modern(cfg, files, meter)
        else:
            try:
                modern_test(cfg)
            except Exception as exc:
                backup_event('SMB2/3 niedostępny, sprawdzanie SMB1: ' + str(exc)[:200],
                             phase='transfer', percent=0)
                legacy_test(cfg)
                transfer_legacy(cfg, files, meter)
            else:
                transfer_modern(cfg, files, meter)
        backup_event('Weryfikacja ukończona. YunoHost usuwa lokalną kopię archiwum…',
                     phase='cleanup', percent=None)
        yn_command('backup', 'delete', name, timeout=120)
        with BACKUP_STATE_GUARD:
            BACKUP_STATE['details'] = (['Aplikacje: ' + ', '.join(f'{n} ({i})' for n,i in zip(app_names,app_ids))] +
                                       [f.name for f in files])
        backup_event('Kopia ' + name + ' przesłana, zweryfikowana (SHA256) i usunięta lokalnie.',
                     phase='complete', status='success', percent=100)
    except Exception as exc:
        backup_event(str(exc) + ' Kopia lokalna, jeśli powstała, nie została celowo usunięta.',
                     phase='error', status='error')
    finally:
        BACKUP_LOCK.release()


@app.get('/api/backup/status')
def backup_status():
    with BACKUP_STATE_GUARD:
        snapshot = {**BACKUP_STATE, 'log': list(BACKUP_STATE['log']),
                    'details': list(BACKUP_STATE['details'])}
    return jsonify(success=True, available=on_yunohost(), **snapshot)


@app.post('/api/backup/start')
def backup_start():
    if not on_yunohost():
        return jsonify(success=False, message='Uruchom Backup Manager bezpośrednio na YunoHost jako root.'), 400
    payload = request.get_json(silent=True) or {}
    app_ids = payload.get('apps', [])
    storage_id = payload.get('storage', '')
    if not isinstance(app_ids, list) or not app_ids or len(app_ids) > 100:
        return jsonify(success=False, message='Wybierz aplikacje.'), 400
    app_labels = {app['id']: app['name'] for app in actual_apps()}
    valid = set(app_labels)
    if any(not isinstance(a, str) or a not in valid for a in app_ids):
        return jsonify(success=False, message='Nieprawidłowa lista aplikacji.'), 400
    if not isinstance(storage_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,49}', storage_id):
        return jsonify(success=False, message='Wybierz magazyn.'), 400
    if read_state().get('status') in ('launching', 'running'):
        return jsonify(success=False, message='Trwa aktualizacja aplikacji. Poczekaj na zakończenie.'), 409
    if not BACKUP_LOCK.acquire(blocking=False):
        return jsonify(success=False, message='Trwa już tworzenie lub przywracanie kopii.'), 409
    backup_event('Rozpoczynanie kopii…', phase='prepare', status='running', reset=True)
    threading.Thread(target=backup_worker, args=(app_ids, storage_id, [app_labels[a] for a in app_ids]), daemon=True).start()
    return jsonify(success=True, message='Rozpoczęto wykonywanie kopii.')


# Harmonogram CRON w obrębie wtyczki. Nie modyfikuje systemowego crontaba.
def schedule_csrf_valid():
    supplied = request.headers.get('X-Schedule-CSRF', '')
    expected = session.get('schedule_csrf', '')
    return bool(supplied and expected and hmac.compare_digest(supplied, expected))


def schedules_public():
    with db_connect() as db:
        rows = db.execute('SELECT * FROM harmonogramy ORDER BY name COLLATE NOCASE').fetchall()
    result = []
    for row in rows:
        schedule = dict(row)
        schedule['enabled'] = bool(schedule['enabled'])
        schedule['apps'] = json.loads(schedule.pop('apps_json'))
        try:
            schedule['next_run'] = next_occurrence(schedule['cron']).strftime('%d.%m.%Y %H:%M') if schedule['enabled'] else None
        except (ValueError, OverflowError):
            schedule['next_run'] = 'Nie można wyznaczyć'
        result.append(schedule)
    return result


@app.get('/api/schedules')
def list_schedules():
    token = secrets.token_urlsafe(32)
    session['schedule_csrf'] = token
    return jsonify(success=True, csrf=token, schedules=schedules_public())


def validate_schedule(data):
    name = str(data.get('name', '')).strip()
    expression = str(data.get('cron', '')).strip()
    storage = data.get('storage', '')
    apps = data.get('apps', [])
    enabled = data.get('enabled', True)
    if not 1 <= len(name) <= 100:
        raise ValueError('Nazwa harmonogramu musi mieć od 1 do 100 znaków.')
    CronSpec(expression)  # parse once before persisting; rejects malformed ranges and steps
    if not isinstance(storage, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,49}', storage):
        raise ValueError('Nieprawidłowy identyfikator magazynu.')
    with db_connect() as db:
        if not db.execute('SELECT 1 FROM magazyny WHERE id=?', (storage,)).fetchone():
            raise ValueError('Wybierz istniejący magazyn.')
    if not isinstance(apps, list) or not apps or len(apps) > 100 or len(set(map(str, apps))) != len(apps):
        raise ValueError('Wybierz co najmniej jedną aplikację, bez powtórzeń.')
    known = {app['id'] for app in actual_apps()}
    if any(not isinstance(item, str) or item not in known for item in apps):
        raise ValueError('Wybrane aplikacje nie są aktualnie zainstalowane w YunoHost.')
    if not isinstance(enabled, bool):
        raise ValueError('Nieprawidłowy stan harmonogramu.')
    return name, expression, storage, json.dumps(apps), int(enabled)


@app.post('/api/schedules')
def add_schedule():
    if not schedule_csrf_valid():
        return jsonify(success=False, message='Odśwież zakładkę Harmonogram — wygasło potwierdzenie.'), 403
    if not on_yunohost():
        return jsonify(success=False, message='Harmonogram jest dostępny tylko na YunoHost.'), 400
    try:
        name, expr, storage, apps, enabled = validate_schedule(request.get_json(silent=True) or {})
        with db_connect() as db:
            db.execute('INSERT INTO harmonogramy (id,name,cron,storage_id,apps_json,enabled) VALUES (?,?,?,?,?,?)',
                       (uuid.uuid4().hex, name, expr, storage, apps, enabled))
        return jsonify(success=True, message='Harmonogram został zapisany.')
    except (ValueError, TypeError) as exc:
        return jsonify(success=False, message=str(exc)), 400


@app.put('/api/schedules/<schedule_id>')
def modify_schedule(schedule_id):
    if not schedule_csrf_valid():
        return jsonify(success=False, message='Odśwież zakładkę Harmonogram — wygasło potwierdzenie.'), 403
    try:
        name, expr, storage, apps, enabled = validate_schedule(request.get_json(silent=True) or {})
        with db_connect() as db:
            result = db.execute('UPDATE harmonogramy SET name=?,cron=?,storage_id=?,apps_json=?,enabled=?,last_slot=NULL WHERE id=?',
                                (name,expr,storage,apps,enabled,schedule_id))
        if not result.rowcount:
            return jsonify(success=False, message='Nie znaleziono harmonogramu.'), 404
        return jsonify(success=True, message='Harmonogram zaktualizowany.')
    except (ValueError, TypeError) as exc:
        return jsonify(success=False, message=str(exc)), 400


@app.delete('/api/schedules/<schedule_id>')
def remove_schedule(schedule_id):
    if not schedule_csrf_valid():
        return jsonify(success=False, message='Odśwież zakładkę Harmonogram — wygasło potwierdzenie.'), 403
    with db_connect() as db:
        result = db.execute('DELETE FROM harmonogramy WHERE id=?', (schedule_id,))
    if not result.rowcount:
        return jsonify(success=False, message='Nie znaleziono harmonogramu.'), 404
    return jsonify(success=True, message='Harmonogram usunięty. Archiwa kopii pozostały bez zmian.')


def schedule_result(schedule_id, outcome):
    try:
        with db_connect() as db:
            db.execute('UPDATE harmonogramy SET last_result=? WHERE id=?', (outcome[:400], schedule_id))
    except sqlite3.Error:
        app.logger.exception('Nie zapisano wyniku harmonogramu')


def scheduled_backup_runner(app_ids, storage, names, schedule_id):
    try:
        backup_worker(app_ids, storage, names)
        with BACKUP_STATE_GUARD:
            result = BACKUP_STATE['status']
            message = BACKUP_STATE['message']
        schedule_result(schedule_id, ('Zakończono: ' if result == 'success' else 'Błąd: ') + message[:240])
    except BaseException as exc:
        schedule_result(schedule_id, 'Błąd zadania: ' + str(exc)[:240])
        raise


def scheduler_tick(now=None):
    if not on_yunohost():
        return
    now = now or datetime.datetime.now().astimezone()
    slot = now.strftime('%Y-%m-%d %H:%M %z')
    with db_connect() as db:
        schedules = db.execute('SELECT * FROM harmonogramy WHERE enabled=1').fetchall()
    for item in schedules:
        try:
            if not CronSpec(item['cron']).matches(now):
                continue
            with db_connect() as db:
                claimed = db.execute('UPDATE harmonogramy SET last_slot=?,last_run=?,last_result=? '
                                     'WHERE id=? AND enabled=1 AND (last_slot IS NULL OR last_slot<>?)',
                                     (slot, now.strftime('%d.%m.%Y %H:%M'), 'Przygotowanie…', item['id'], slot))
            if not claimed.rowcount:
                continue
            if read_state().get('status') in ('launching','running') or not BACKUP_LOCK.acquire(blocking=False):
                schedule_result(item['id'], 'Pominięto termin: trwa inna kopia, przywracanie lub aktualizacja.')
                continue
            try:
                ids = json.loads(item['apps_json'])
                names = {a['id']: a['name'] for a in actual_apps()}
                if not ids or any(a not in names for a in ids):
                    raise ValueError('Co najmniej jedna aplikacja nie jest już zainstalowana.')
                cfg_from_storage(item['storage_id'])  # deleted storage / missing credentials
                backup_event('Harmonogram: ' + item['name'] + '. Rozpoczynanie kopii…', phase='prepare', status='running', reset=True)
                thread = threading.Thread(target=scheduled_backup_runner,
                                          args=(ids, item['storage_id'], [names[a] for a in ids], item['id']), daemon=True)
                thread.start()
                schedule_result(item['id'], 'Uruchomiono kopię — szczegóły w zakładce Kopie zapasowe.')
            except Exception:
                BACKUP_LOCK.release()
                raise
        except Exception as exc:
            schedule_result(item['id'], 'Błąd harmonogramu: ' + str(exc)[:240])
            app.logger.exception('Błąd zadania cron %s', item['id'])


def scheduler_loop():
    # Prevent duplicate runs even if Gunicorn were configured with more workers.
    lock_file = DATA / '.cron-scheduler.lock'
    with lock_file.open('a+b') as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        while True:
            try:
                scheduler_tick()
            except Exception:
                app.logger.exception('Błąd pętli harmonogramu')
            time.sleep(12)


threading.Thread(target=scheduler_loop, name='ybm-cron', daemon=True).start()


# Archiwum -> wybór kopii -> przywracanie: w tym samym panelu co tworzenie.
# Wykorzystuje wyłącznie istniejące połączenia SMB wtyczki i interfejs CLI YunoHost.
RESTORE_STATE_GUARD = threading.RLock()
RESTORE_STATE = {'status': 'idle', 'phase': 'idle', 'percent': None,
                 'message': 'Nie uruchomiono przywracania.', 'done_bytes': 0,
                 'total_bytes': 0, 'log': []}
ARCHIVE_NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,179}\Z')
RESTORE_METADATA_MAX = 2 * 1024 * 1024


def restore_event(message, phase=None, status=None, percent=None, reset=False):
    with RESTORE_STATE_GUARD:
        if reset:
            RESTORE_STATE.update(log=[], done_bytes=0, total_bytes=0)
        RESTORE_STATE['message'] = str(message)
        RESTORE_STATE['percent'] = percent
        if phase is not None:
            RESTORE_STATE['phase'] = phase
        if status is not None:
            RESTORE_STATE['status'] = status
        RESTORE_STATE['log'] = (RESTORE_STATE['log'] +
            [time.strftime('%H:%M:%S') + '  ' + str(message)])[-160:]


def remote_folder(cfg):
    return '/' + cfg['subdirectory'].strip('/') if cfg['subdirectory'] else ''


def remote_unc(cfg, server):
    root = '\\\\' + server + '\\' + cfg['share']
    if cfg['subdirectory']:
        root += '\\' + cfg['subdirectory'].replace('/', '\\')
    return root


def archive_name_ok(name):
    return isinstance(name, str) and bool(ARCHIVE_NAME_RE.fullmatch(name)) and '..' not in name


def parse_archive_metadata(data):
    import json
    if len(data) > RESTORE_METADATA_MAX:
        raise ValueError('Metadane archiwum są za duże.')
    meta = json.loads(data.decode('utf-8'))
    apps = meta.get('apps', {})
    if not isinstance(apps, dict):
        raise ValueError('Archiwum nie zawiera poprawnej listy aplikacji.')
    app_ids = [app_id for app_id in apps if isinstance(app_id, str)
               and re.fullmatch(r'[A-Za-z0-9_]{1,100}', app_id)]
    if len(app_ids) != len(apps):
        raise ValueError('Archiwum zawiera nieprawidłowe identyfikatory aplikacji.')
    app_names = {app_id: str(apps[app_id].get('name') or app_id)[:130] if isinstance(apps[app_id], dict) else app_id
                 for app_id in app_ids}
    return {'apps': app_ids, 'app_names': app_names, 'created_at': meta.get('created_at') if isinstance(meta.get('created_at'), (int, float)) else None,
            'description': str(meta.get('description') or '')[:200]}


def remote_archive_catalog(cfg, only=None):
    """List tar+info.json pairs without downloading the tar archive."""
    if only is not None and not archive_name_ok(only):
        raise ValueError('Nieprawidłowa nazwa archiwum.')

    def legacy():
        result = []
        with SMB_LOCK:
            with smb_endpoint(cfg['server']) as endpoint:
                conn = connect_legacy(cfg, True, endpoint.host, endpoint.port)
                try:
                    folder = remote_folder(cfg)
                    entries = {entry.filename: entry for entry in
                               conn.listPath(cfg['share'], folder + '/' if folder else '/', timeout=45)
                               if not entry.isDirectory}
                    names = sorted({n[:-4] for n in entries if n.endswith('.tar') and
                                    archive_name_ok(n[:-4]) and (only is None or n[:-4] == only)}, reverse=True)
                    for name in names[:300]:
                        tar_item = entries[name + '.tar']
                        info_item = entries.get(name + '.info.json')
                        record = {'name': name, 'size': int(tar_item.file_size), 'info_size': int(info_item.file_size) if info_item else 0,
                                  'complete': bool(info_item), 'apps': [], 'app_names': {}, 'created_at': None,
                                  'message': ''}
                        if info_item:
                            if info_item.file_size > RESTORE_METADATA_MAX:
                                record['message'] = 'Metadane przekraczają limit 2 MiB.'
                            else:
                                try:
                                    sink = io.BytesIO()
                                    conn.retrieveFile(cfg['share'], folder + '/' + name + '.info.json',
                                                      sink, timeout=45)
                                    record.update(parse_archive_metadata(sink.getvalue()))
                                except Exception as exc:
                                    record['message'] = 'Nie można odczytać metadanych: ' + str(exc)[:160]
                        else:
                            record['message'] = 'Brakuje pliku .info.json'
                        result.append(record)
                    return result
                finally:
                    conn.close()

    def modern():
        result = []
        cache = {}
        with smb_endpoint(cfg['server']) as endpoint:
            server = endpoint.host
            root = remote_unc(cfg, server)
            user = (cfg['domain'] + '\\' if cfg['domain'] else '') + cfg['username']
            try:
                smbclient.register_session(server, username=user, password=cfg['password'],
                                           port=endpoint.port, connection_timeout=15,
                                           connection_cache=cache)
                names_in_folder = set(smbclient.listdir(root, port=endpoint.port, connection_cache=cache))
                names = sorted({n[:-4] for n in names_in_folder if n.endswith('.tar') and
                                archive_name_ok(n[:-4]) and (only is None or n[:-4] == only)}, reverse=True)
                for name in names[:300]:
                    path = root + '\\' + name + '.tar'
                    try:
                        size = int(smbclient.stat(path, port=endpoint.port, connection_cache=cache).st_size)
                    except OSError:
                        continue
                    complete = name + '.info.json' in names_in_folder
                    record = {'name': name, 'size': size, 'complete': complete, 'info_size': 0,
                              'apps': [], 'app_names': {}, 'created_at': None, 'message': ''}
                    if complete:
                        info_path = root + '\\' + name + '.info.json'
                        try:
                            info_size = smbclient.stat(info_path, port=endpoint.port,
                                                       connection_cache=cache).st_size
                            record['info_size'] = int(info_size)
                            if info_size > RESTORE_METADATA_MAX:
                                raise ValueError('Metadane przekraczają limit 2 MiB.')
                            with smbclient.open_file(info_path, 'rb', port=endpoint.port,
                                                     connection_cache=cache) as f:
                                record.update(parse_archive_metadata(f.read(RESTORE_METADATA_MAX + 1)))
                        except Exception as exc:
                            record['message'] = 'Nie można odczytać metadanych: ' + str(exc)[:160]
                    else:
                        record['message'] = 'Brakuje pliku .info.json'
                    result.append(record)
                return result
            finally:
                try:
                    smbclient.delete_session(server, port=endpoint.port, connection_cache=cache)
                except Exception:
                    pass

    return try_protocol(cfg, legacy, modern)


class RestoreWriter:
    def __init__(self, stream, expected, total):
        self.stream, self.expected, self.total = stream, expected, total
        self.done = 0

    def write(self, chunk):
        self.done += len(chunk)
        if self.done > self.expected:
            raise RuntimeError('Rozmiar pobieranego archiwum przekroczył deklarowany rozmiar.')
        result = self.stream.write(chunk)
        with RESTORE_STATE_GUARD:
            RESTORE_STATE['done_bytes'] += len(chunk)
            RESTORE_STATE['percent'] = int(min(100, RESTORE_STATE['done_bytes'] * 100 / max(self.total, 1)))
        return result

    def flush(self):
        self.stream.flush()


def remote_restore_download(cfg, name, tar_bytes, info_bytes, destination):
    """Download both original backup files through the app's SMB transport."""
    files = [(name + '.tar', tar_bytes), (name + '.info.json', info_bytes)]
    total = tar_bytes + info_bytes

    def legacy():
        with SMB_LOCK:
            with smb_endpoint(cfg['server']) as endpoint:
                conn = connect_legacy(cfg, True, endpoint.host, endpoint.port)
                try:
                    folder = remote_folder(cfg)
                    for filename, expected in files:
                        restore_event('Pobieranie ' + filename, phase='download', percent=RESTORE_STATE['percent'])
                        entry = [e for e in conn.listPath(cfg['share'], folder + '/' if folder else '/', timeout=45)
                                 if e.filename == filename and not e.isDirectory]
                        if not entry:
                            raise RuntimeError('Plik zniknął z magazynu: ' + filename)
                        size = int(entry[0].file_size)
                        if expected is not None and size != expected:
                            raise RuntimeError('Archiwum zmieniło rozmiar na magazynie.')
                        if filename.endswith('.info.json') and size > RESTORE_METADATA_MAX:
                            raise RuntimeError('Metadane archiwum są zbyt duże.')
                        with (destination / (filename + '.part')).open('xb') as out:
                            writer = RestoreWriter(out, size, total)
                            conn.retrieveFile(cfg['share'], folder + '/' + filename, writer, timeout=7200)
                            if writer.done != size:
                                raise RuntimeError('Niekompletny plik: ' + filename)
                finally:
                    conn.close()

    def modern():
        cache = {}
        with smb_endpoint(cfg['server']) as endpoint:
            server = endpoint.host
            root = remote_unc(cfg, server)
            user = (cfg['domain'] + '\\' if cfg['domain'] else '') + cfg['username']
            try:
                smbclient.register_session(server, username=user, password=cfg['password'],
                                           port=endpoint.port, connection_timeout=15,
                                           connection_cache=cache)
                for filename, expected in files:
                    restore_event('Pobieranie ' + filename, phase='download', percent=RESTORE_STATE['percent'])
                    remote = root + '\\' + filename
                    size = int(smbclient.stat(remote, port=endpoint.port, connection_cache=cache).st_size)
                    if expected is not None and size != expected:
                        raise RuntimeError('Archiwum zmieniło rozmiar na magazynie.')
                    if filename.endswith('.info.json') and size > RESTORE_METADATA_MAX:
                        raise RuntimeError('Metadane archiwum są zbyt duże.')
                    with smbclient.open_file(remote, 'rb', port=endpoint.port,
                                             connection_cache=cache) as source, \
                         (destination / (filename + '.part')).open('xb') as out:
                        writer = RestoreWriter(out, size, total)
                        for chunk in iter(lambda: source.read(1024 * 1024), b''):
                            writer.write(chunk)
                        if writer.done != size:
                            raise RuntimeError('Niekompletny plik: ' + filename)
            finally:
                try:
                    smbclient.delete_session(server, port=endpoint.port, connection_cache=cache)
                except Exception:
                    pass

    def clean_partial():
        for filename, _ in files:
            try:
                (destination / (filename + '.part')).unlink(missing_ok=True)
            except OSError:
                pass
        with RESTORE_STATE_GUARD:
            RESTORE_STATE['done_bytes'] = 0
            RESTORE_STATE['percent'] = 0

    def modern_attempt():
        clean_partial()
        return modern()

    def legacy_attempt():
        clean_partial()
        return legacy()

    try_protocol(cfg, legacy_attempt, modern_attempt)


def run_restore_yunohost(name, apps):
    """Stream actual CLI output; never report success before a zero exit status."""
    import queue
    command = ['yunohost', 'backup', 'restore', name, '--apps', *apps]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, errors='replace', bufsize=1)
    lines = queue.Queue()

    def reader():
        try:
            for line in proc.stdout:
                lines.put(line.rstrip())
        finally:
            lines.put(None)

    reader_thread = threading.Thread(target=reader, daemon=True)
    reader_thread.start()
    deadline = time.monotonic() + 7200
    finished = False
    while not finished:
        if time.monotonic() > deadline:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            raise RuntimeError('Przywracanie YunoHost przekroczyło limit 2 godzin.')
        try:
            item = lines.get(timeout=1)
        except queue.Empty:
            continue
        if item is None:
            finished = True
        elif item:
            restore_event(item[:1400], phase='restore', status='running')
    rc = proc.wait(timeout=30)
    if rc != 0:
        raise RuntimeError('YunoHost zakończył przywracanie błędem (kod %s). Zobacz log.' % rc)


def restore_worker(storage_id, name, apps, size, info_size):
    created = []
    staging = None
    success = False
    try:
        cfg = cfg_from_storage(storage_id)
        restore_event('Przygotowanie do pobrania archiwum: ' + name, phase='prepare', status='running')
        if any((BACKUP_DIR / (name + ext)).exists() for ext in ('.tar', '.info.json')):
            raise RuntimeError('Lokalne archiwum o tej nazwie już istnieje. Niczego nie nadpisano.')
        free = shutil.disk_usage(BACKUP_DIR).free
        if free < size + max(256 * 1024 * 1024, size // 4):
            raise RuntimeError('Za mało miejsca lokalnego na pobranie i przygotowanie przywracania.')
        with RESTORE_STATE_GUARD:
            RESTORE_STATE['total_bytes'] = size + info_size
        restore_event('Pobieranie archiwum SMB; nie zmieniamy pliku na magazynie.',
                      phase='download', percent=0)
        staging = pathlib.Path(tempfile.mkdtemp(prefix='.ybm-restore-', dir=BACKUP_DIR))
        remote_restore_download(cfg, name, size, info_size, staging)
        for ext in ('.tar', '.info.json'):
            part = staging / (name + ext + '.part')
            target = BACKUP_DIR / (name + ext)
            if target.exists():
                raise RuntimeError('W międzyczasie utworzono lokalne archiwum o tej nazwie.')
            part.rename(target)
            created.append(target)
        local_meta = parse_archive_metadata((BACKUP_DIR / (name + '.info.json')).read_bytes())
        if not set(apps).issubset(set(local_meta['apps'])):
            raise RuntimeError('Lista aplikacji w archiwum zmieniła się podczas pobierania.')
        installed = {a['id'] for a in actual_apps()}
        collision = sorted(installed.intersection(apps))
        if collision:
            raise RuntimeError('Przywracanie zatrzymane: już zainstalowane aplikacje: ' + ', '.join(collision) + '. Niczego nie odinstalowano.')
        restore_event('Uruchamianie przywracania YunoHost: ' + ', '.join(apps),
                      phase='restore', status='running', percent=None)
        run_restore_yunohost(name, apps)
        success = True
        restore_event('Przywrócono aplikacje: ' + ', '.join(apps),
                      phase='complete', status='success', percent=100)
    except Exception as exc:
        restore_event(str(exc), phase='error', status='error', percent=None)
    finally:
        if success:
            for path in created:
                try:
                    path.unlink()
                except OSError:
                    restore_event('Nie udało się usunąć lokalnego pliku tymczasowego: ' + path.name)
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
        BACKUP_LOCK.release()


@app.get('/api/restore/archives')
def restore_archives():
    storage_id = request.args.get('storage', '')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,49}', storage_id):
        return jsonify(success=False, message='Wybierz magazyn.'), 400
    try:
        cfg = cfg_from_storage(storage_id)
        entries = remote_archive_catalog(cfg)
        installed = {a['id'] for a in actual_apps()} if on_yunohost() else set()
        for record in entries:
            record['conflicts'] = [a for a in record['apps'] if a in installed]
        token = secrets.token_urlsafe(32)
        session['restore_csrf'] = token
        return jsonify(success=True, archives=entries, csrf=token)
    except Exception as exc:
        return jsonify(success=False, message=type(exc).__name__ + ': ' + str(exc)[:600]), 400


@app.get('/api/restore/status')
def restore_status():
    with RESTORE_STATE_GUARD:
        snapshot = {**RESTORE_STATE, 'log': list(RESTORE_STATE['log'])}
    return jsonify(success=True, **snapshot)


@app.post('/api/restore/start')
def restore_start():
    if not on_yunohost():
        return jsonify(success=False, message='Przywracanie jest dostępne wyłącznie na YunoHost.'), 400
    csrf = request.headers.get('X-Restore-CSRF', '')
    expected = session.get('restore_csrf', '')
    if not csrf or not expected or not hmac.compare_digest(csrf, expected):
        return jsonify(success=False, message='Odśwież listę archiwów przed przywracaniem.'), 403
    payload = request.get_json(silent=True) or {}
    storage_id, name, apps = payload.get('storage'), payload.get('name'), payload.get('apps')
    if not isinstance(storage_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,49}', storage_id):
        return jsonify(success=False, message='Nieprawidłowy magazyn.'), 400
    if not archive_name_ok(name) or not isinstance(apps, list) or not apps or len(apps) > 100 or any(
            not isinstance(a, str) or not re.fullmatch(r'[A-Za-z0-9_]{1,100}', a) for a in apps) or len(apps) != len(set(apps)):
        return jsonify(success=False, message='Nieprawidłowa lista aplikacji lub archiwum.'), 400
    if read_state().get('status') in ('launching', 'running'):
        return jsonify(success=False, message='Trwa aktualizacja aplikacji.'), 409
    if not BACKUP_LOCK.acquire(blocking=False):
        return jsonify(success=False, message='Trwa inna operacja kopii lub przywracania.'), 409
    try:
        cfg = cfg_from_storage(storage_id)
        records = remote_archive_catalog(cfg, name)
        if len(records) != 1 or not records[0]['complete'] or records[0]['message']:
            raise ValueError('Niekompletne archiwum lub błędne metadane.')
        archive = records[0]
        if not set(apps).issubset(set(archive['apps'])):
            raise ValueError('Nie wybrano aplikacji należących do archiwum.')
        collision = sorted({a['id'] for a in actual_apps()}.intersection(apps))
        if collision:
            raise ValueError('Aplikacje już zainstalowane: ' + ', '.join(collision) + '. Nie zostaną nadpisane ani odinstalowane.')
        if (BACKUP_DIR / (name + '.tar')).exists() or (BACKUP_DIR / (name + '.info.json')).exists():
            raise ValueError('Lokalne archiwum o tej nazwie już istnieje. Nie zostanie nadpisane.')
        session.pop('restore_csrf', None)
        restore_event('Rozpoczynam przywracanie: ' + name, phase='prepare', status='running', reset=True)
        threading.Thread(target=restore_worker,
                         args=(storage_id, name, apps, archive['size'], archive['info_size']), daemon=True).start()
        return jsonify(success=True, message='Rozpoczęto pobieranie i przywracanie kopii.')
    except Exception as exc:
        BACKUP_LOCK.release()
        return jsonify(success=False, message=str(exc)[:700]), 400


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


@app.get('/api/updates/log')
def updates_log():
    raw_offset = request.args.get('offset', '0')
    if not re.fullmatch(r'[0-9]{1,15}', raw_offset):
        return jsonify(success=False, message='Nieprawidłowa pozycja logu.'), 400
    return jsonify(success=True, **read_log_chunk(int(raw_offset)))


@app.get('/logo.png')
def app_icon():
    return send_file(ROOT / 'logo.png', mimetype='image/png', max_age=86400)


@app.post('/api/updates/start')
def updates_start():
    if not on_yunohost():
        return jsonify(success=False, message='Aktualizacja jest dostępna wyłącznie na YunoHost.'), 400
    csrf = request.headers.get('X-Update-CSRF', '')
    expected_csrf = session.get('update_csrf', '')
    if not csrf or not expected_csrf or not hmac.compare_digest(csrf, expected_csrf):
        return jsonify(success=False, message='Nieprawidłowe potwierdzenie żądania. Odśwież panel.'), 403
    if BACKUP_LOCK.locked():
        return jsonify(success=False, message='Trwa tworzenie lub przywracanie kopii. Poczekaj na zakończenie.'), 409
    if not UPDATE_LAUNCH_LOCK.acquire(blocking=False):
        return jsonify(success=False, message='Uruchamianie aktualizacji już trwa.'), 409
    try:
        current = read_state()
        if current['status'] in ('launching', 'running'):
            return jsonify(success=False, message='Aktualizacja już trwa.'), 409
        version = check_remote()  # Repeat validation immediately before launching.
        payload = request.get_json(silent=True) or {}
        repair = payload.get('repair') is True
        same_version = version['latest'] == APP_VERSION
        if not version['available'] and not (repair and same_version):
            return jsonify(success=False, message='Brak nowej wersji. Ponowna instalacja jest możliwa po wybraniu trybu naprawy.'), 409
        expected_version = payload.get('version')
        if not isinstance(expected_version, str) or expected_version != version['latest']:
            return jsonify(success=False, message='Wersja na GitHubie zmieniła się. Sprawdź ponownie.'), 409
        runner = str(ROOT / 'update_runner.py')
        systemd_run = shutil.which('systemd-run')
        if not systemd_run or not pathlib.Path(runner).is_file():
            return jsonify(success=False, message='Brak uruchamiacza aktualizacji w pakiecie.'), 500
        if BACKUP_LOCK.locked():
            return jsonify(success=False, message='W międzyczasie rozpoczęła się kopia zapasowa.'), 409
        # Only the app's own last-update log is cleared for a fresh run.
        with open(LOG_FILE, 'wb'):
            pass
        write_state(status='launching', target=expected_version,
                    started_at=int(time.time()), message='Uruchamianie aktualizacji YunoHost...')
        unit = 'yunohost-backup-manager-upd-' + uuid.uuid4().hex[:12]
        try:
            result = subprocess.run(
                [systemd_run, '--quiet', '--collect', '--unit=' + unit,
                 '--property=Type=exec', '--', '/usr/bin/python3', runner,
                 '--expected-version', expected_version] + (['--force'] if repair else []),
                capture_output=True, text=True, timeout=20, check=False)
            if result.returncode:
                raise RuntimeError((result.stderr or result.stdout or 'systemd-run nie uruchomił aktualizacji.')[-1200:])
        except Exception as exc:
            write_state(status='error', target=expected_version,
                        finished_at=int(time.time()), message='Nie uruchomiono aktualizacji: %s' % exc)
            return jsonify(success=False, message=str(exc)), 500
        return jsonify(success=True, message='Ponowna instalacja uruchomiona.' if repair else 'Aktualizacja uruchomiona.', target=expected_version)
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

/* Aktualizacja: animacja pracy bez fałszywych procentów. */
#updateProgress{margin-top:18px}
.update-progress-caption{display:flex;justify-content:space-between;gap:12px;align-items:center;font-size:13px;color:#415773;margin:0 0 8px}
.update-track{height:10px;border-radius:999px;background:#e3eaf2;position:relative;overflow:hidden}
.update-progress-fill{position:absolute;top:0;bottom:0;width:35%;left:-35%;border-radius:999px;background:linear-gradient(90deg,#38a8dc,#305a9c);animation:ynh-work 1.65s ease-in-out infinite}
@keyframes ynh-work{to{left:100%}}
.update-track.complete .update-progress-fill{animation:none;left:0;width:100%;background:#2f9b60}
.update-track.failed .update-progress-fill{animation:none;left:0;width:100%;background:#c24343}
#updateLogPanel{margin-top:14px;border:1px solid #d8e0eb;border-radius:7px;overflow:hidden}
#updateLogPanel summary{cursor:pointer;user-select:none;padding:12px 14px;font-weight:600;background:#f1f5fa;color:#334d71}
#updateLogPanel pre{font:12px/1.55 Consolas,'Liberation Mono',monospace;white-space:pre-wrap;overflow-wrap:anywhere;overflow-y:auto;max-height:320px;min-height:90px;margin:0;padding:14px;color:#d8e7ff;background:#142136}
#updateLogPanel .actions{margin:0;padding:8px 10px;background:#f1f5fa}
#updateLogPanel .actions button{padding:7px 12px;font-size:12px}
#updateLogPanel[hidden],#updateProgress[hidden]{display:none}
#backupProgress{margin-top:18px}
#backupLogPanel{margin-top:14px;border:1px solid #d8e0eb;border-radius:7px;overflow:hidden}
#backupLogPanel summary{cursor:pointer;user-select:none;padding:12px 14px;font-weight:600;background:#f1f5fa;color:#334d71}
#backupLogPanel pre{font:12px/1.55 Consolas,'Liberation Mono',monospace;white-space:pre-wrap;overflow-wrap:anywhere;overflow-y:auto;max-height:300px;min-height:80px;margin:0;padding:14px;color:#d8e7ff;background:#142136}
#backupProgress[hidden],#backupLogPanel[hidden]{display:none}
.update-track.measured .update-progress-fill{animation:none;left:0;width:0%;transition:width .25s ease}
#importProgress{margin-top:18px}
#importLogPanel{margin-top:14px;border:1px solid #d8e0eb;border-radius:7px;overflow:hidden}
#importLogPanel summary{cursor:pointer;user-select:none;padding:12px 14px;font-weight:600;background:#f1f5fa;color:#334d71}
#importLogPanel pre{font:12px/1.55 Consolas,'Liberation Mono',monospace;white-space:pre-wrap;overflow-wrap:anywhere;overflow-y:auto;max-height:240px;min-height:65px;margin:0;padding:14px;color:#d8e7ff;background:#142136}
#importLogPanel[hidden],#importProgress[hidden]{display:none}

/* Panel 0.5~ynh16 — nawigacja kategoriami. */
:root{--navy:#14263e;--navy-soft:#1c3552;--primary:#2d639c;--line:#e2e8f0;--text:#20334b;--muted:#637389}
html{min-height:100%;scroll-behavior:smooth}
body{background:#f2f5f9;color:var(--text)}
.app-shell{display:grid;grid-template-columns:254px minmax(0,1fr);min-height:100vh}
.app-sidebar{background:linear-gradient(175deg,#182c46 0%,#11223a 100%);color:#e9f1fc;display:flex;flex-direction:column;padding:26px 15px 20px;min-width:0;position:sticky;top:0;height:100vh;box-shadow:3px 0 20px #16294012}
.sidebar-brand{display:flex;align-items:center;gap:12px;padding:5px 9px 27px;border-bottom:1px solid #ffffff19;margin-bottom:25px;min-width:0}
.sidebar-brand img{width:48px;height:48px;flex:none;object-fit:contain;border-radius:10px;background:#0f2945}
.brand-copy{min-width:0}.brand-copy strong{display:block;font-size:15px;line-height:1.35;letter-spacing:.1px}.brand-copy small{display:block;margin-top:6px;font-size:11px;color:#aebfd4;font-weight:normal}
.sidebar-group-label{font-size:10px;letter-spacing:1.4px;font-weight:700;color:#899fb9;padding:0 13px;margin-bottom:12px}
.sidebar-nav{display:flex;flex-direction:column;gap:6px}
.nav-item{display:flex;align-items:center;gap:13px;padding:13px 14px;border-radius:9px;color:#ccd8e9;text-decoration:none;font-size:14px;font-weight:600;line-height:1.3;border:1px solid transparent;transition:background .15s ease,color .15s ease,border .15s ease}
.nav-item svg{height:21px;width:21px;flex:none;opacity:.9}
.nav-item:hover{background:#ffffff12;color:white}
.nav-item:focus-visible{outline:2px solid #94cbf1;outline-offset:2px}
.nav-item.active{background:#2b527d;color:#fff;border-color:#ffffff26;box-shadow:inset 3px 0 0 #67c2fa}
.sidebar-bottom{margin-top:auto;padding:18px 12px 1px;font-size:11px;color:#a9b9ce;border-top:1px solid #ffffff15;display:flex;gap:8px;align-items:center}
.sidebar-mark{background:#51b8a7;width:7px;height:7px;border-radius:50%;flex:none}
.app-workspace{min-width:0}
.workspace-topbar{min-height:68px;background:#fff;border-bottom:1px solid var(--line);padding:17px clamp(22px,4vw,56px);display:flex;align-items:center;justify-content:space-between;gap:12px;color:#637389;font-size:13px}
.crumb-divider{display:inline-block;padding:0 9px;color:#a0aabb}
.version-pill{color:#3d5877;background:#f1f5fa;border:1px solid #e1e8f1;border-radius:99px;padding:7px 12px;white-space:nowrap;font-size:12px;font-weight:600}
.workspace-content{max-width:1160px;margin:0 auto;padding:34px clamp(22px,4vw,52px) 54px;min-width:0}
.page-heading{margin-bottom:25px}.page-eyebrow{font-size:10px;letter-spacing:1.5px;font-weight:750;color:#71859c}.page-heading h1{font-size:30px;line-height:1.24;margin:8px 0 9px;color:#172b46}.page-heading p{font-size:14px;line-height:1.55;color:#6a798c;margin:0}
.category-view[hidden]{display:none!important}
.panel{border:1px solid #e5eaf0;box-shadow:0 5px 20px #2437500b;border-radius:12px;margin-bottom:20px;padding:26px}
.panel h2{font-size:19px;line-height:1.35;color:#1e3653;margin-bottom:19px}
input,select,textarea{border-color:#cbd6e3}
input:focus,select:focus,textarea:focus{outline:2px solid #80b7ee;outline-offset:1px}
button{background:#315f98}button:hover:not(:disabled){filter:brightness(1.07)}
button:focus-visible{outline:2px solid #7ab9f3;outline-offset:2px}
@media(max-width:900px){.app-shell{grid-template-columns:210px minmax(0,1fr)}.app-sidebar{padding:21px 10px}.sidebar-brand{gap:9px;padding:5px 8px 21px}.sidebar-brand img{width:40px;height:40px}.brand-copy strong{font-size:13px}.nav-item{padding:12px 10px;gap:10px}}
@media(max-width:720px){
 .app-shell{display:block}.app-sidebar{position:static;height:auto;padding:13px 14px 12px;box-shadow:none}
 .sidebar-brand{margin:0 0 13px;padding:0 4px 10px;border-bottom:1px solid #ffffff1b}
 .sidebar-brand img{width:36px;height:36px}.brand-copy strong{font-size:13px;line-height:1.2}.brand-copy small{margin-top:3px}
 .sidebar-group-label,.sidebar-bottom{display:none}
 .sidebar-nav{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px}
 .nav-item{justify-content:center;gap:7px;padding:11px 6px;text-align:center;font-size:12px}
 .nav-item svg{width:17px;height:17px}.nav-item.active{box-shadow:inset 0 -3px 0 #67c2fa}
 .workspace-topbar{min-height:48px;padding:10px 18px;font-size:12px}
 .workspace-content{padding:25px 16px 42px}.page-heading{margin-bottom:20px}.page-heading h1{font-size:25px}
 .panel{padding:19px 16px;border-radius:10px}.panel h2{font-size:18px}
}
@media(max-width:390px){.nav-item{font-size:11px;gap:5px}.nav-item svg{height:16px;width:16px}.version-pill{font-size:11px}}
@media(prefers-reduced-motion:reduce){.nav-item{transition:none}html{scroll-behavior:auto}}

/* Jednolity widok kopii i przywracania, wzorowany na sposobie pracy Proxmox. */
.backup-toolbar{display:flex;align-items:flex-end;gap:12px;flex-wrap:wrap;margin:5px 0 14px}
.backup-toolbar .backup-storage-field{flex:1;min-width:220px}
.backup-toolbar label{margin:0 0 7px}
.backup-toolbar .actions{margin:0 0 2px}
.archive-table input[type=radio]{width:auto;cursor:pointer}
.archive-table tbody tr{cursor:pointer}
.archive-table tbody tr:hover{background:#f5f8fc}
.archive-table tbody tr.selected{background:#e8f2ff}
.archive-table td{font-size:13px;vertical-align:middle}
.archive-table .archive-name{font-weight:700;word-break:break-word}
.archive-table .archive-apps{max-width:260px;color:#52657e}
.archive-table .archive-status{font-size:12px;color:#39785e}
.archive-table .archive-status.bad{color:#a33939}
.archive-help{font-size:12px;color:#657286;margin-top:12px;line-height:1.5}
.archive-actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:15px}
.archive-actions .archive-selection{margin-right:auto;font-size:13px;color:#657286}
.backup-create-panel[hidden],#restoreProgress[hidden],#restoreLogPanel[hidden]{display:none}
.backup-create-panel{border-top:1px solid #e5eaf0;padding-top:19px;margin-top:18px}
#restoreProgress{margin-top:18px}
#restoreLogPanel{margin-top:14px;border:1px solid #d8e0eb;border-radius:7px;overflow:hidden}
#restoreLogPanel summary{cursor:pointer;user-select:none;padding:12px 14px;font-weight:600;background:#f1f5fa;color:#334d71}
#restoreLogPanel pre{font:12px/1.55 Consolas,'Liberation Mono',monospace;white-space:pre-wrap;overflow-wrap:anywhere;overflow-y:auto;max-height:310px;min-height:70px;margin:0;padding:14px;color:#d8e7ff;background:#142136}
.restore-dialog{border:1px solid #d7dfeb;border-radius:12px;padding:25px;width:min(560px,calc(100% - 30px));max-height:90vh;box-shadow:0 20px 70px #162b4780;background:white;color:#253954}
.restore-dialog::backdrop{background:#172739ae}
.restore-dialog h2{font-size:21px;margin:0 0 15px}
.restore-dialog p{font-size:14px;line-height:1.5}
.restore-app{display:block;font-weight:normal;border-bottom:1px solid #e5eaf0;padding:9px 2px;margin:0}
.restore-app input{width:auto;vertical-align:middle;margin-right:8px}
.restore-alert{background:#fff2de;color:#86520c;border-radius:7px;padding:12px;margin:12px 0;font-size:13px}
.restore-alert.bad{background:#fbe5e5;color:#842a2a}
.restore-dialog .actions{justify-content:flex-end}


/* Harmonogram kopii: wszystkie ustawienia przechowywane w danych wtyczki. */
.schedule-form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 16px}
.schedule-hint{font-size:12px;line-height:1.6;color:#5b6f86;margin-top:9px}
.schedule-apps{max-height:230px;overflow-y:auto;padding:8px 12px;border:1px solid #dce4ee;border-radius:8px}
.schedule-apps .appitem{margin:0;font-weight:normal}
.schedule-table td{vertical-align:middle;font-size:13px}
.schedule-tag{display:inline-block;border-radius:14px;background:#e0f1e7;color:#23744a;padding:5px 9px;font-size:12px}
.schedule-tag.off{background:#eceff4;color:#57677b}
.schedule-grid-actions{display:flex;gap:6px;flex-wrap:wrap}
@media(max-width:720px){.schedule-form-grid{grid-template-columns:1fr}}
</style></head><body>
<div class="app-shell">
<aside class="app-sidebar" aria-label="Menu aplikacji">
  <div class="sidebar-brand">
    <img id="appLogo" alt="" width="48" height="48">
    <div class="brand-copy"><strong>YunoHost<br>Backup Manager</strong><small>0.5~ynh16</small></div>
  </div>
  <div class="sidebar-group-label">ZARZĄDZANIE</div>
  <nav class="sidebar-nav" aria-label="Kategorie">
<a class="nav-item active" href="#magazyn" data-view="magazyn" aria-current="page"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3.5" width="18" height="7" rx="2"/><rect x="3" y="13.5" width="18" height="7" rx="2"/><path d="M7.5 7h.01M7.5 17h.01M11 7h7M11 17h7"/></svg><span>Magazyn</span></a>
<a class="nav-item" href="#kopie" data-view="kopie"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M5 7.5V5a2 2 0 0 1 2-2h8l4 4v12a2 2 0 0 1-2 2h-2"/><path d="M15 3v5h5M3 16a6 6 0 1 0 2-4.5"/><path d="M3 11v5h5"/></svg><span>Kopie zapasowe</span></a>
<a class="nav-item" href="#harmonogram" data-view="harmonogram"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2M7 2v3M17 2v3"/></svg><span>Harmonogram (cron)</span></a>
<a class="nav-item" href="#aktualizacja" data-view="aktualizacja"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 16V3m0 0L7.5 7.5M12 3l4.5 4.5M4 16v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"/></svg><span>Aktualizacja</span></a>
  </nav>
  <div class="sidebar-bottom"><span class="sidebar-mark"></span> Panel kopii zapasowych</div>
</aside>
<div class="app-workspace">
  <header class="workspace-topbar"><span>YunoHost <span class="crumb-divider">/</span> Backup Manager</span><span class="version-pill">v0.5~ynh16</span></header>
  <main class="workspace-content" id="mainContent">
    <div class="page-heading"><span class="page-eyebrow">PANEL ZARZĄDZANIA</span><h1 id="viewTitle">Magazyn</h1><p id="viewDescription">Zarządzaj magazynami SMB/CIFS i połączeniami sieciowymi.</p></div>
    <div class="category-view" id="view-magazyn" data-category="magazyn">
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
    </div>
    <div class="category-view" id="view-kopie" data-category="kopie" hidden>
<section class="panel" id="backupLibrary"><h2>Archiwa kopii zapasowych</h2>
<div class="backup-toolbar"><div class="backup-storage-field"><label for="backupStorage">Magazyn kopii</label>
<select id="backupStorage"><option value="">Wybierz magazyn</option></select></div>
<div class="actions"><button type="button" class="secondary" id="reloadArchives">Odśwież listę</button><button type="button" id="showBackupForm">+ Nowa kopia</button></div></div>
<div class="tablewrap"><table class="archive-table"><thead><tr><th></th><th>Archiwum</th><th>Data</th><th>Rozmiar</th><th>Aplikacje w kopii</th><th>Stan</th></tr></thead>
<tbody id="archiveRows"><tr><td colspan="6">Wybierz magazyn, aby wyświetlić archiwa.</td></tr></tbody></table></div>
<div class="archive-actions"><span class="archive-selection" id="archiveSelection">Nie wybrano archiwum.</span>
<button type="button" id="restoreSelected" disabled>Przywróć wybraną kopię</button></div>
<p class="archive-help">Wykaz pochodzi bezpośrednio z magazynu SMB. Przywracanie pobiera wybrane archiwum, a następnie uruchamia mechanizm YunoHost. Aplikacja nie usuwa ani nie nadpisuje istniejących instalacji.</p>
<div id="archiveMessage" class="message"></div>
<div class="backup-create-panel" id="backupCreatePanel" hidden>
<h2>Nowa kopia zapasowa</h2>
<p><small>Wybierz aplikacje. Archiwum zostanie zapisane na wskazanym wyżej magazynie SMB.</small></p>
<div id="apps"><small>Wczytywanie aplikacji...</small></div>
<div class="actions"><button type="button" id="runBackup" disabled>Utwórz kopię</button><button type="button" class="secondary" id="hideBackupForm">Anuluj</button></div>
<details style="margin-top:22px"><summary>Importuj listę aplikacji z YunoHost (tryb lokalny)</summary>
<p><small>Wklej wynik polecenia <code>yunohost app list --output-as json</code>. Nie podawaj haseł.</small></p>
<textarea id="appsJson" placeholder='{"apps":[{"id":"wordpress","name":"Bałchan","domain_path":"strona.rpkj.ovh/organypiszczalkowe"}]}'></textarea>
<div class="actions"><button type="button" id="importApps">Importuj aplikacje</button></div>
<div id="importProgress" hidden><div class="update-progress-caption"><strong id="importStage">Importowanie aplikacji</strong><span id="importPhase">Przygotowanie danych…</span></div>
<div id="importTrack" class="update-track" role="progressbar" aria-label="Stan importu" aria-valuetext="Trwa import"><span class="update-progress-fill"></span></div></div>
<details id="importLogPanel" hidden open><summary>Podgląd przebiegu importu</summary><pre id="importLogText" role="log" aria-label="Log importu"></pre></details></details>
<div id="appsMessage" class="message"></div></div></section>
<section class="panel" id="operationsPanel"><h2>Postęp operacji i dziennik</h2>
<div id="backupProgress" hidden>
  <div class="update-progress-caption"><strong id="backupStage">Przygotowywanie kopii</strong><span id="backupPhase">Trwa praca…</span></div>
  <div id="backupTrack" class="update-track" role="progressbar" aria-label="Postęp wykonywania kopii" aria-valuetext="Trwa praca"><span id="backupFill" class="update-progress-fill"></span></div>
</div><details id="backupLogPanel" hidden open><summary>Podgląd tworzenia kopii (log)</summary><pre id="backupLogText" role="log" aria-label="Log tworzenia kopii">Oczekiwanie na uruchomienie…</pre></details>
<div id="backupMessage" class="message"></div>
<div id="restoreProgress" hidden>
  <div class="update-progress-caption"><strong id="restoreStage">Przywracanie kopii</strong><span id="restorePhase">Trwa praca…</span></div>
  <div id="restoreTrack" class="update-track" role="progressbar" aria-label="Postęp przywracania" aria-valuetext="Trwa przywracanie"><span id="restoreFill" class="update-progress-fill"></span></div>
</div><details id="restoreLogPanel" hidden open><summary>Podgląd przywracania (log YunoHost)</summary><pre id="restoreLogText" role="log" aria-label="Log przywracania"></pre></details>
<div id="restoreMessage" class="message"></div></section>
<dialog class="restore-dialog" id="restoreDialog" aria-labelledby="restoreDialogHeading"><h2 id="restoreDialogHeading">Przywracanie archiwum</h2>
<p id="restoreDialogName"></p><p>Wybierz aplikacje z archiwum:</p><div id="restoreApps"></div>
<div class="restore-alert" id="restoreWarning">YunoHost nie pozwala przywrócić aplikacji na już zainstalowaną instancję. Istniejące aplikacje nie zostaną usunięte.</div>
<label for="restorePhrase">Aby potwierdzić, wpisz <strong>PRZYWRÓĆ</strong></label>
<input id="restorePhrase" type="text" autocomplete="off" placeholder="PRZYWRÓĆ" />
<div class="actions"><button type="button" class="secondary" id="cancelRestore">Anuluj</button><button type="button" id="confirmRestore" class="danger" disabled>Rozpocznij przywracanie</button></div></dialog>
    </div>
    <div class="category-view" id="view-harmonogram" data-category="harmonogram" hidden>
      <section class="panel"><h2>Harmonogram kopii zapasowych</h2>
        <p class="schedule-hint">Zadania wykonują się automatycznie według pięciopolowego zapisu cron w lokalnej strefie czasowej serwera. Używają tych samych magazynów, kontroli SHA256 i logu co kopia ręczna. Jeśli trwa inna operacja, dany termin zostanie pominięty. Wtyczka nie modyfikuje systemowego crontaba.</p>
        <div class="tablewrap"><table class="schedule-table"><thead><tr><th>Nazwa</th><th>Magazyn</th><th>Cron</th><th>Następne uruchomienie</th><th>Stan</th><th>Ostatni wynik</th><th>Akcje</th></tr></thead><tbody id="scheduleRows"><tr><td colspan="7">Ładowanie harmonogramów…</td></tr></tbody></table></div>
      </section>
      <section class="panel"><h2 id="scheduleFormTitle">Dodaj harmonogram</h2>
        <form id="scheduleForm"><div class="schedule-form-grid">
          <div><label for="scheduleName">Nazwa zadania</label><input id="scheduleName" maxlength="100" placeholder="np. Kopia nocna" required></div>
          <div><label for="scheduleStorage">Magazyn docelowy</label><select id="scheduleStorage" required><option value="">Wybierz magazyn</option></select></div>
          <div><label for="schedulePreset">Częstotliwość</label><select id="schedulePreset"><option value="0 2 * * *">Codziennie o 02:00</option><option value="0 2 * * 0">Co niedzielę o 02:00</option><option value="0 2 * * 1">Co poniedziałek o 02:00</option><option value="0 2 1 * *">Pierwszego dnia miesiąca o 02:00</option><option value="custom">Własny zapis cron</option></select></div>
          <div><label for="scheduleCron">Wyrażenie cron (min godz dzień miesiąc dzień tyg.)</label><input id="scheduleCron" value="0 2 * * *" maxlength="120" spellcheck="false" required><p class="schedule-hint">Przykład: <code>30 3 * * 1-5</code> — od poniedziałku do piątku o 03:30.</p></div>
        </div><label>Aplikacje objęte kopią</label><div class="schedule-apps" id="scheduleApps">Ładowanie aplikacji…</div>
        <label class="appitem"><input type="checkbox" id="scheduleEnabled" checked><span>Harmonogram włączony</span></label>
        <div class="actions"><button type="submit" id="scheduleSave">Zapisz harmonogram</button><button type="button" class="secondary" id="scheduleCancel" hidden>Anuluj edycję</button><button type="button" class="secondary" id="scheduleRefresh">Odśwież</button></div></form>
        <div id="scheduleMessage" class="message"></div>
      </section>
    </div>
    <div class="category-view" id="view-aktualizacja" data-category="aktualizacja" hidden>
<section class="panel" id="updatePanel"><h2>Aktualizacje aplikacji</h2>
<p>Wersja zainstalowana: <strong id="versionInstalled">0.5~ynh16</strong> &nbsp;|&nbsp; GitHub: <strong id="versionRemote">Sprawdzanie...</strong></p>
<div id="updateMessage" class="message" style="display:none"></div>
<div class="actions"><button type="button" id="checkUpdate" class="secondary">Sprawdź aktualizacje</button><button type="button" id="startUpdate" disabled>Aktualizuj aplikację</button></div>
<div id="updateProgress" hidden>
  <div class="update-progress-caption"><strong id="updateStage">Aktualizacja w toku</strong><span id="updatePhase">YunoHost wykonuje aktualizację…</span></div>
  <div id="updateTrack" class="update-track" role="progressbar" aria-label="Stan aktualizacji" aria-valuetext="Trwa aktualizacja"><span class="update-progress-fill"></span></div>
</div>
<details id="updateLogPanel" hidden><summary>Podgląd przebiegu aktualizacji (log YunoHost)</summary>
<pre id="updateLogText" role="log" aria-label="Log aktualizacji">Oczekiwanie na komunikaty YunoHost…</pre>
<div class="actions"><button type="button" id="copyUpdateLog" class="secondary">Kopiuj log</button></div></details>
<p><small>Aktualizacja korzysta z mechanizmu YunoHost. Podczas jej wykonywania panel może być chwilowo niedostępny. Zapisane magazyny i hasła pozostają w katalogu danych aplikacji.</small></p>
</section>
    </div>
  </main>
</div>
</div><script>
const $=id=>document.getElementById(id);let editing=null;let records=[];
const categoryDetails={
 magazyn:{title:'Magazyn',description:'Zarządzaj magazynami SMB/CIFS i połączeniami sieciowymi.'},
 kopie:{title:'Kopie zapasowe',description:'Przeglądaj archiwa z magazynu, twórz nowe kopie i przywracaj wybrane aplikacje.'},
 harmonogram:{title:'Harmonogram (cron)',description:'Automatyczne kopie zapasowe według ustalonego terminarza.'},
 aktualizacja:{title:'Aktualizacja',description:'Sprawdź nową wersję aplikacji i zobacz przebieg aktualizacji.'}
};
function navigateCategory(name){
 const section=categoryDetails[name]?name:'magazyn';
 document.querySelectorAll('.category-view').forEach(el=>{el.hidden=el.dataset.category!==section});
 document.querySelectorAll('.nav-item[data-view]').forEach(el=>{
  const active=el.dataset.view===section;
  el.classList.toggle('active',active);
  if(active)el.setAttribute('aria-current','page');else el.removeAttribute('aria-current');
 });
 $('viewTitle').textContent=categoryDetails[section].title;
 $('viewDescription').textContent=categoryDetails[section].description;
 document.title=categoryDetails[section].title+' — YunoHost Backup Manager';
}
function routeCategory(){navigateCategory(decodeURIComponent(location.hash.slice(1)))}
document.querySelectorAll('.nav-item[data-view]').forEach(link=>link.addEventListener('click',event=>{
 event.preventDefault();const view=link.dataset.view;
 if(location.hash.slice(1)!==view)location.hash=view;else navigateCategory(view);
 window.scrollTo({top:0,behavior:'instant'});
}));
window.addEventListener('hashchange',routeCategory);
routeCategory();
$('appLogo').src=window.location.pathname.replace(/\/$/,'')+'/logo.png';
function msg(ok,s){$('message').style.display='block';$('message').className='message '+(ok?'ok':'error');$('message').textContent=s}
function data(){return Object.fromEntries(new FormData($('form')))}
async function api(url,method='GET',payload){const base=window.location.pathname.replace(/\/$/,'');const r=await fetch(base+url,{method,headers:{'Content-Type':'application/json'},body:payload?JSON.stringify(payload):undefined});return await r.json()}
function busy(v){for(const x of ['discover','test','save'])$(x).disabled=v}
function storageLocation(m){return m.share+(m.subdirectory?'/'+m.subdirectory.replace(/^\/+|\/+$/g,''):'')}
function reset(){editing=null;$('form').reset();$('id').disabled=false;$('password').required=true;$('formTitle').textContent='Dodaj magazyn SMB/CIFS';$('cancel').hidden=true;$('share').innerHTML='<option value="">Najpierw pobierz udziały</option>'}
async function refresh(){const x=await api('/api/magazyny');records=x.magazyny||[];syncScheduleStorages();const storage=$('backupStorage');const selected=storage.value;storage.replaceChildren(new Option('Wybierz magazyn',''));for(const m of records)storage.add(new Option(m.id+' ('+m.server+'/'+storageLocation(m)+')',m.id));storage.value=selected|| (records.length===1?records[0].id:'');if(storage.value!==selected)refreshArchives().catch(e=>archiveNotice(false,e.message));const tbody=$('rows');tbody.replaceChildren();if(!records.length){const tr=tbody.insertRow();const td=tr.insertCell();td.colSpan=5;td.textContent='Brak zapisanych magazynów.';return}for(const m of records){const tr=tbody.insertRow();for(const v of [m.id,m.server,storageLocation(m),m.protocol==='auto'?'Auto':m.protocol.toUpperCase()])tr.insertCell().textContent=v;const td=tr.insertCell();for(const [title,fn,danger] of [['Edytuj',()=>edit(m.id),false],['Usuń',()=>remove(m.id),true]]){const b=document.createElement('button');b.textContent=title;b.className=danger?'danger':'secondary';b.onclick=fn;td.appendChild(b)}}}
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
$('importApps').onclick=async()=>{
 const output=$('appsMessage'), button=$('importApps'), progress=$('importProgress'), track=$('importTrack');
 const log=$('importLogText'), phase=$('importPhase'), stage=$('importStage');
 if(button.disabled)return;
 button.disabled=true;progress.hidden=false;$('importLogPanel').hidden=false;$('importLogPanel').open=true;
 track.className='update-track';track.setAttribute('aria-valuetext','Trwa import');
 stage.textContent='Importowanie aplikacji';phase.textContent='Sprawdzanie danych…';
 log.textContent='';output.style.display='block';output.className='message ok';output.textContent='Importowanie listy aplikacji…';
 const addLog=(text)=>{log.textContent+=text+'\n';log.scrollTop=log.scrollHeight};
 try{
  addLog('Odczyt danych JSON z formularza.');
  const input=JSON.parse($('appsJson').value);
  if(!input||!Array.isArray(input.apps))throw new Error('Wklej obiekt JSON z listą apps.');
  addLog('Odczytano '+input.apps.length+' wpisów.');
  phase.textContent='Przesyłanie '+input.apps.length+' wpisów do aplikacji…';
  addLog('Wysyłanie i walidacja danych na serwerze…');
  const result=await api('/api/aplikacje/import','POST',input);
  if(!result.success)throw new Error(result.message||'Serwer odrzucił import.');
  addLog(result.message);phase.textContent='Odświeżanie listy aplikacji…';
  await refreshApps();addLog('Lista aplikacji została odświeżona.');
  track.classList.add('complete');track.setAttribute('aria-valuetext','Import zakończony');
  stage.textContent='Import zakończony';phase.textContent='Gotowe';
  output.className='message ok';output.textContent=result.message;
 }catch(e){
  addLog('BŁĄD: '+e.message);track.classList.add('failed');track.setAttribute('aria-valuetext','Import nieudany');
  stage.textContent='Błąd importu';phase.textContent='Sprawdź log';
  output.className='message error';output.textContent='Import nieudany: '+e.message;
 }finally{button.disabled=false}
};

// Biblioteka archiwów i przywracanie w tym samym widoku (jak magazyn kopii w Proxmox).
let archiveRecords=[], selectedArchive='', restoreToken='', restoreRunning=false, backupWasRunning=false;
let activeRestore=null, lastRestoreFinished='';
function archiveNotice(ok,text){const box=$('archiveMessage');box.style.display='block';box.className='message '+(ok?'ok':'error');box.textContent=text}
function readableSize(bytes){if(!Number.isFinite(bytes))return '—';return bytes>=1073741824?(bytes/1073741824).toFixed(2)+' GiB':(bytes/1048576).toFixed(1)+' MiB'}
function archiveTime(a){if(typeof a.created_at==='number')return new Date(a.created_at*1000).toLocaleString('pl-PL');
 const m=a.name.match(/_(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})_/);
 return m?`${m[3]}.${m[2]}.${m[1]} ${m[4]}:${m[5]}`:'—'}
function showArchiveRows(){const target=$('archiveRows');target.replaceChildren();
 if(!archiveRecords.length){const row=target.insertRow();const td=row.insertCell();td.colSpan=6;td.textContent='Nie znaleziono archiwów w wybranym magazynie.';}
 for(const item of archiveRecords){
  const row=target.insertRow();row.classList.toggle('selected',item.name===selectedArchive);
  const radio=document.createElement('input');radio.type='radio';radio.name='archive-choice';radio.value=item.name;
  radio.checked=item.name===selectedArchive;radio.setAttribute('aria-label','Wybierz '+item.name);
  row.insertCell().append(radio);
  const name=row.insertCell();name.className='archive-name';name.textContent=item.name;
  row.insertCell().textContent=archiveTime(item);
  row.insertCell().textContent=readableSize(item.size);
  const apps=row.insertCell();apps.className='archive-apps';apps.textContent=item.apps?.length?item.apps.map(id=>(item.app_names&&item.app_names[id])||id).join(', '):'Brak informacji';
  const status=row.insertCell();status.className='archive-status'+((!item.complete||item.message)?' bad':'');
  status.textContent=item.message||(item.conflicts?.length?'Aplikacja już zainstalowana':'Gotowe');
  const choose=()=>{selectedArchive=item.name;showArchiveRows()};
  row.addEventListener('click',choose);radio.addEventListener('change',choose);
 }
 const selected=archiveRecords.find(a=>a.name===selectedArchive);
 const okay=Boolean(selected&&selected.complete&&!selected.message&&selected.apps?.length&&!restoreRunning);
 $('restoreSelected').disabled=!okay;
 $('archiveSelection').textContent=selected?'Wybrano: '+selected.name:'Nie wybrano archiwum.';
}
async function refreshArchives(){
 const storage=$('backupStorage').value;
 selectedArchive='';archiveRecords=[];restoreToken='';
 const target=$('archiveRows');target.replaceChildren();
 if(!storage){const r=target.insertRow();const td=r.insertCell();td.colSpan=6;td.textContent='Wybierz magazyn.';
  $('restoreSelected').disabled=true;$('archiveSelection').textContent='Nie wybrano archiwum.';return}
 const row=target.insertRow();const td=row.insertCell();td.colSpan=6;td.textContent='Odczytywanie archiwów z magazynu SMB…';
 $('reloadArchives').disabled=true;$('restoreSelected').disabled=true;
 try{
  const result=await api('/api/restore/archives?storage='+encodeURIComponent(storage));
  if(!result.success)throw new Error(result.message||'Nie udało się pobrać listy.');
  archiveRecords=result.archives||[];restoreToken=result.csrf||'';
  showArchiveRows();
  $('archiveMessage').style.display='none';
 }catch(e){archiveRecords=[];target.replaceChildren();const r=target.insertRow();const td=r.insertCell();td.colSpan=6;td.textContent='Nie udało się pobrać listy archiwów.';archiveNotice(false,e.message);}
 finally{$('reloadArchives').disabled=false}
}
$('backupStorage').addEventListener('change',()=>refreshArchives());
$('reloadArchives').onclick=()=>refreshArchives();
$('showBackupForm').onclick=()=>{$('backupCreatePanel').hidden=false;$('showBackupForm').disabled=true;};
$('hideBackupForm').onclick=()=>{if(backupWasRunning)return;$('backupCreatePanel').hidden=true;$('showBackupForm').disabled=false;};
function syncRestoreDialog(){
 const selected=[...$('restoreApps').querySelectorAll('input:checked')];
 const forbidden=selected.some(el=>el.dataset.conflict==='1');
 const valid=$('restorePhrase').value.trim()==='PRZYWRÓĆ' && selected.length>0 && !forbidden && !restoreRunning;
 $('confirmRestore').disabled=!valid;
 const note=$('restoreWarning');
 note.classList.toggle('bad',forbidden);
 note.textContent=forbidden?'Wybrane aplikacje już istnieją na serwerze. Przywracanie ich bez wcześniejszego usunięcia nie jest dostępne w YunoHost. Wtyczka niczego nie odinstaluje.':
  'Przywracanie zmienia instalację YunoHost. Upewnij się, że wybrano właściwe archiwum i aplikacje. Pliki na magazynie SMB pozostaną bez zmian.';
}
$('restoreSelected').onclick=()=>{
 activeRestore=archiveRecords.find(x=>x.name===selectedArchive);
 if(!activeRestore||!activeRestore.apps?.length||activeRestore.message)return;
 $('restoreDialogName').textContent='Archiwum: '+activeRestore.name+'  |  '+readableSize(activeRestore.size);
 const host=$('restoreApps');host.replaceChildren();
 for(const name of activeRestore.apps){const label=document.createElement('label');label.className='restore-app';
  const input=document.createElement('input');input.type='checkbox';input.value=name;
  input.dataset.conflict=(activeRestore.conflicts||[]).includes(name)?'1':'0';
  input.checked=input.dataset.conflict!=='1';
  const span=document.createElement('span');span.textContent=((activeRestore.app_names&&activeRestore.app_names[name])||name)+' ('+name+')'+(input.dataset.conflict==='1'?' — już zainstalowana':'');
  label.append(input,span);host.append(label);input.addEventListener('change',syncRestoreDialog);}
 $('restorePhrase').value='';syncRestoreDialog();$('restoreDialog').showModal();
};
$('restorePhrase').addEventListener('input',syncRestoreDialog);
$('cancelRestore').onclick=()=>$('restoreDialog').close();
$('confirmRestore').onclick=async()=>{
 const apps=[...$('restoreApps').querySelectorAll('input:checked')].map(i=>i.value);
 if(!apps.length||!activeRestore||!restoreToken||$('restorePhrase').value.trim()!=='PRZYWRÓĆ')return;
 $('confirmRestore').disabled=true;
 try{
  const base=window.location.pathname.replace(/\/$/,'');
  const reply=await fetch(base+'/api/restore/start',{method:'POST',headers:{'Content-Type':'application/json','X-Restore-CSRF':restoreToken},
   body:JSON.stringify({storage:$('backupStorage').value,name:activeRestore.name,apps})});
  const result=await reply.json();
  if(!result.success)throw new Error(result.message||'Nie udało się rozpocząć przywracania.');
  $('restoreDialog').close();restoreRunning=true;restoreToken='';
  const box=$('restoreMessage');box.style.display='block';box.className='message ok';box.textContent=result.message;
  $('restoreLogPanel').open=true;await restorePoll();
 }catch(e){archiveNotice(false,e.message);$('restoreDialog').close()}
};
async function restorePoll(){
 const s=await api('/api/restore/status');
 const previousRestore=restoreRunning;restoreRunning=s.status==='running';
 const p=$('restoreProgress'),l=$('restoreLogPanel'),track=$('restoreTrack'),fill=$('restoreFill');
 if(s.status==='idle'){p.hidden=true;l.hidden=true;return;}
 p.hidden=false;l.hidden=false;track.className='update-track';fill.style.width='';
 $('restoreStage').textContent=({prepare:'Przygotowanie',download:'Pobieranie kopii z SMB',restore:'Przywracanie przez YunoHost',complete:'Przywracanie zakończone',error:'Błąd przywracania'})[s.phase]||'Przywracanie kopii';
 if(s.status==='success'){track.classList.add('complete');$('restorePhase').textContent='Gotowe';}
 else if(s.status==='error'){track.classList.add('failed');$('restorePhase').textContent='Sprawdź log';}
 else if(s.phase==='download'&&typeof s.percent==='number'){
  track.classList.add('measured');fill.style.width=Math.min(100,Math.max(0,s.percent))+'%';
  $('restorePhase').textContent=s.percent+'% pobierania ('+readableSize(s.done_bytes)+' / '+readableSize(s.total_bytes)+')';
 }else $('restorePhase').textContent='Śledź rzeczywisty log poniżej';
 const out=$('restoreLogText'),t=(s.log||[]).join('\n');
 if(out.textContent!==t){const follow=out.scrollHeight-out.scrollTop-out.clientHeight<45;
  out.textContent=t||'Oczekiwanie na komunikaty…';if(follow)out.scrollTop=out.scrollHeight;}
 const msg=$('restoreMessage');msg.style.display='block';msg.className='message '+(s.status==='error'?'error':'ok');msg.textContent=s.message;
 if(s.status==='success'||s.status==='error'){
  const final=(s.log||[]).slice(-1)[0]||s.message;
  if(lastRestoreFinished!==final){lastRestoreFinished=final;refreshArchives().catch(()=>{});}
 }
 if(previousRestore!==restoreRunning)showArchiveRows();
}

async function backupPoll(){
 const s=await api('/api/backup/status');const btn=$('runBackup');btn.disabled=!s.available||s.status==='running'||restoreRunning;
 const box=$('backupMessage');box.style.display=s.status==='idle'?'none':'block';box.className='message '+(s.status==='error'?'error':'ok');
 box.textContent=s.available?s.message:'Tryb Windows: kopie będą dostępne po uruchomieniu aplikacji na YunoHost.';
 const progress=$('backupProgress'),logPanel=$('backupLogPanel'),track=$('backupTrack'),fill=$('backupFill');
 if(s.status==='idle'){progress.hidden=true;logPanel.hidden=true;return}
 if(s.status==='running')backupWasRunning=true;else if(backupWasRunning && s.status==='success'){backupWasRunning=false;refreshArchives().catch(()=>{})}else if(s.status==='error')backupWasRunning=false;
 progress.hidden=false;logPanel.hidden=false;track.className='update-track';fill.style.width='';
 const names={prepare:'Sprawdzanie miejsca',create:'Tworzenie archiwum YunoHost',
              transfer:'Transfer i weryfikacja SMB',cleanup:'Usuwanie kopii lokalnej',
              complete:'Kopia zakończona',error:'Błąd tworzenia kopii'};
 $('backupStage').textContent=names[s.phase]||'Tworzenie kopii';
 if(s.status==='success'){
  track.classList.add('complete');$('backupPhase').textContent='Gotowe';
  track.setAttribute('aria-valuetext','Kopia zweryfikowana i zakończona');
 }else if(s.status==='error'){
  track.classList.add('failed');$('backupPhase').textContent='Zobacz log';
  track.setAttribute('aria-valuetext','Nie udało się wykonać kopii');
 }else if(s.phase==='transfer' && typeof s.percent==='number'){
  track.classList.add('measured');fill.style.width=Math.min(100,Math.max(0,s.percent))+'%';
  const done=(s.done_bytes/1048576).toFixed(1),total=(s.total_bytes/1048576).toFixed(1);
  $('backupPhase').textContent=s.percent+'% transmisji i weryfikacji ('+done+' / '+total+' MiB)';
  track.setAttribute('aria-valuenow',String(s.percent));
  track.setAttribute('aria-valuetext','Transfer i weryfikacja '+s.percent+'%');
 }else{
  track.removeAttribute('aria-valuenow');$('backupPhase').textContent='Postęp w logu poniżej';
  track.setAttribute('aria-valuetext','Trwa '+(names[s.phase]||'tworzenie kopii'));
 }
 const log=$('backupLogText'),lines=(s.log||[]).join('\n');
 if(log.textContent!==lines){const follow=log.scrollHeight-log.scrollTop-log.clientHeight<45;
  log.textContent=lines||'Oczekiwanie na komunikaty…';if(follow)log.scrollTop=log.scrollHeight;}
}
$('runBackup').onclick=async()=>{
 const apps=[...$('apps').querySelectorAll('input[type=checkbox]:checked')].map(x=>x.value);
 const storage=$('backupStorage').value;
 if(!apps.length||!storage){alert('Wybierz aplikacje i magazyn.');return}
 if(!confirm('Wykonać kopię '+apps.join(', ')+' na magazyn '+storage+'?'))return;
 const r=await api('/api/backup/start','POST',{apps,storage});
 if(!r.success)alert(r.message);else{document.getElementById('backupCreatePanel').hidden=false;backupWasRunning=true}await backupPoll();
};
// Zakładka harmonogramu — cron zapisany tylko w bazie danych wtyczki.
let scheduleToken='',scheduleEditing='',scheduleRows=[];
function scheduleNotice(ok,text){const el=$('scheduleMessage');el.style.display='block';el.className='message '+(ok?'ok':'error');el.textContent=text;}
function syncScheduleStorages(){const node=$('scheduleStorage'),old=node.value;node.replaceChildren(new Option('Wybierz magazyn',''));
 for(const m of records)node.add(new Option(m.id+' ('+storageLocation(m)+')',m.id));node.value=old;}
function scheduleAppChoices(selected){const host=$('scheduleApps');host.replaceChildren();const opts=[...$('apps').querySelectorAll('input[type=checkbox]')];
 if(!opts.length){host.textContent='Brak aplikacji. Najpierw odśwież listę w zakładce Kopie zapasowe.';return;}
 for(const opt of opts){const wrapper=document.createElement('label');wrapper.className='appitem';const cb=document.createElement('input');cb.type='checkbox';cb.value=opt.value;cb.checked=Boolean(selected&&selected.includes(opt.value));
 const cap=document.createElement('span');cap.textContent=opt.closest('label')?.querySelector('strong')?.textContent||opt.value;wrapper.append(cb,cap);host.append(wrapper);}}
function scheduleReset(){scheduleEditing='';$('scheduleForm').reset();$('scheduleCron').value='0 2 * * *';$('schedulePreset').value='0 2 * * *';$('scheduleEnabled').checked=true;
 $('scheduleFormTitle').textContent='Dodaj harmonogram';$('scheduleCancel').hidden=true;scheduleAppChoices([]);}
function scheduleEdit(id){const r=scheduleRows.find(s=>s.id===id);if(!r)return;scheduleEditing=id;$('scheduleName').value=r.name;$('scheduleStorage').value=r.storage_id;
 $('scheduleCron').value=r.cron;$('schedulePreset').value=[...$('schedulePreset').options].some(o=>o.value===r.cron)?r.cron:'custom';$('scheduleEnabled').checked=r.enabled;
 scheduleAppChoices(r.apps);$('scheduleFormTitle').textContent='Edytuj harmonogram: '+r.name;$('scheduleCancel').hidden=false;$('scheduleForm').scrollIntoView({behavior:'smooth'});}
async function loadSchedules(){try{const r=await api('/api/schedules');if(!r.success)throw new Error(r.message);scheduleToken=r.csrf;scheduleRows=r.schedules;
 const body=$('scheduleRows');body.replaceChildren();if(!scheduleRows.length){const tr=body.insertRow();const td=tr.insertCell();td.colSpan=7;td.textContent='Brak harmonogramów.';}
 for(const item of scheduleRows){const tr=body.insertRow();for(const value of [item.name,item.storage_id,item.cron,item.next_run||'—'])tr.insertCell().textContent=value;
 const status=tr.insertCell(),badge=document.createElement('span');badge.className='schedule-tag'+(item.enabled?'':' off');badge.textContent=item.enabled?'Włączony':'Wyłączony';status.append(badge);
 tr.insertCell().textContent=(item.last_run?item.last_run+' — ':'')+(item.last_result||'Nie uruchomiono');const action=tr.insertCell();action.className='schedule-grid-actions';
 for(const [name,cb,bad] of [['Edytuj',()=>scheduleEdit(item.id),false],[item.enabled?'Wyłącz':'Włącz',()=>scheduleToggle(item),false],['Usuń',()=>scheduleRemove(item),true]]){
 const button=document.createElement('button');button.type='button';button.textContent=name;button.className=bad?'danger':'secondary';button.onclick=cb;action.append(button)}}
 }catch(e){scheduleNotice(false,'Nie udało się pobrać harmonogramów: '+e.message)}}
async function scheduleWrite(url,method,body){const root=window.location.pathname.replace(/\/$/,'');const resp=await fetch(root+url,{method,headers:{'Content-Type':'application/json','X-Schedule-CSRF':scheduleToken},body:JSON.stringify(body)});return await resp.json();}
async function scheduleToggle(item){try{const r=await scheduleWrite('/api/schedules/'+encodeURIComponent(item.id),'PUT',{name:item.name,cron:item.cron,storage:item.storage_id,apps:item.apps,enabled:!item.enabled});
 scheduleNotice(Boolean(r.success),r.message);if(r.success)await loadSchedules();}catch(e){scheduleNotice(false,e.message)}}
async function scheduleRemove(item){if(!confirm('Usunąć harmonogram "'+item.name+'"? Archiwa pozostaną na magazynie.'))return;
 try{const r=await scheduleWrite('/api/schedules/'+encodeURIComponent(item.id),'DELETE',{});scheduleNotice(Boolean(r.success),r.message);if(r.success){if(scheduleEditing===item.id)scheduleReset();await loadSchedules();}}catch(e){scheduleNotice(false,e.message)}}
$('schedulePreset').addEventListener('change',()=>{const v=$('schedulePreset').value;if(v!=='custom')$('scheduleCron').value=v});
$('scheduleCron').addEventListener('input',()=>{const v=$('scheduleCron').value;$('schedulePreset').value=[...$('schedulePreset').options].some(o=>o.value===v)?v:'custom'});
$('scheduleCancel').onclick=()=>scheduleReset();$('scheduleRefresh').onclick=loadSchedules;
$('scheduleForm').addEventListener('submit',async event=>{event.preventDefault();const apps=[...$('scheduleApps').querySelectorAll('input:checked')].map(x=>x.value);
 if(!apps.length){scheduleNotice(false,'Wybierz co najmniej jedną aplikację.');return}
 const btn=$('scheduleSave');btn.disabled=true;
 try{const payload={name:$('scheduleName').value,cron:$('scheduleCron').value,storage:$('scheduleStorage').value,apps,enabled:$('scheduleEnabled').checked};
 const url=scheduleEditing?'/api/schedules/'+encodeURIComponent(scheduleEditing):'/api/schedules';const r=await scheduleWrite(url,scheduleEditing?'PUT':'POST',payload);
 scheduleNotice(Boolean(r.success),r.message);if(r.success){scheduleReset();await loadSchedules();}
 }catch(e){scheduleNotice(false,e.message)}finally{btn.disabled=false}});

let updateToken='';let availableUpdate='';let repairMode=false;let updating=false;
let updateLogOffset=0, updateLogLoading=false, updatePollLoading=false, updateLastRun='';
function updateInfo(ok,text){const b=$('updateMessage');b.style.display='block';b.className='message '+(ok?'ok':'error');b.textContent=text}
function showUpdateProgress(status){
 const progress=$('updateProgress');const track=$('updateTrack');
 progress.hidden=false;track.className='update-track';
 if(status==='success')track.classList.add('complete');
 else if(status==='error')track.classList.add('failed');
 track.setAttribute('aria-valuetext',status==='success'?'Zakończono':status==='error'?'Wystąpił błąd':'Trwa aktualizacja');
 $('updateStage').textContent=status==='success'?'Aktualizacja zakończona':status==='error'?'Aktualizacja nie powiodła się':'Aktualizacja w toku';
 $('updatePhase').textContent=status==='success'?'Gotowe':status==='error'?'Sprawdź log poniżej':'Postęp rzeczywisty w logu poniżej';
 $('updateLogPanel').hidden=false;
}
function clearUpdateLog(){
 updateLogOffset=0;$('updateLogText').textContent='Oczekiwanie na komunikaty YunoHost…';
 $('updateLogPanel').hidden=false;$('updateLogPanel').open=true;
}
async function fetchUpdateLog(){
 if(updateLogLoading)return;
 updateLogLoading=true;
 try{
  const result=await api('/api/updates/log?offset='+updateLogOffset);
  if(!result.success)return;
  const box=$('updateLogText');
  if(result.reset || result.skipped || (updateLogOffset===0 && result.text)){
   box.textContent=result.skipped?'[Pominięto początek bardzo długiego logu]\n':'';
  }
  if(result.text){
   const follow=box.scrollHeight-box.scrollTop-box.clientHeight<45;
   if(box.textContent==='Oczekiwanie na komunikaty YunoHost…')box.textContent='';
   box.textContent+=result.text;
   // Keep browser memory bounded; the full log remains on disk inside the app.
   if(box.textContent.length>280000)box.textContent='[Starsze komunikaty pominięte]\n'+box.textContent.slice(-240000);
   if(follow)box.scrollTop=box.scrollHeight;
  }
  updateLogOffset=result.next_offset;
 }catch(e){/* The app server can restart while it updates itself. */}
 finally{updateLogLoading=false}
}
async function checkUpdates(){
 $('checkUpdate').disabled=true;$('startUpdate').disabled=true;
 updateInfo(true,'Sprawdzanie aktualizacji na GitHubie...');
 try{
  const u=await api('/api/updates/check');updateToken=u.csrf||'';availableUpdate='';
  $('versionInstalled').textContent=u.installed||'?';
  $('versionRemote').textContent=u.latest||'Brak danych';
  if(!u.success){updateInfo(false,u.message);return}
  repairMode=!u.available && u.latest===u.installed;
  availableUpdate=(u.available||repairMode)?u.latest:'';
  $('startUpdate').textContent=repairMode?'Zainstaluj ponownie':'Aktualizuj aplikację';
  $('startUpdate').disabled=updating||!availableUpdate;
  if(u.available) updateInfo(true,'Dostępna nowa wersja: '+u.latest);
  else if(repairMode) updateInfo(true,'Aplikacja jest aktualna. W razie problemów możesz ponownie zainstalować tę samą wersję bez usuwania danych.');
  else updateInfo(false,'Na GitHubie jest starsza wersja. Instalacja starszej wersji jest zablokowana.');
  if(u.state&&['launching','running'].includes(u.state.status)){
   updating=true;$('startUpdate').disabled=true;updateInfo(true,u.state.message);
   showUpdateProgress(u.state.status);
  }
 }catch(e){updateInfo(false,'Nie udało się sprawdzić aktualizacji: '+e.message)}
 finally{$('checkUpdate').disabled=false}
}
$('checkUpdate').onclick=checkUpdates;
$('copyUpdateLog').onclick=async()=>{
 try{await navigator.clipboard.writeText($('updateLogText').textContent);$('copyUpdateLog').textContent='Skopiowano';
 }catch(e){$('copyUpdateLog').textContent='Nie udało się skopiować'}
};
$('startUpdate').onclick=async()=>{
 if(!availableUpdate||!updateToken)return;
 if(!confirm((repairMode?'Ponownie zainstalować wersję ':'Zaktualizować YunoHost Backup Manager do ')+availableUpdate+'? YunoHost wykona kopię bezpieczeństwa i uruchomi ponownie usługę wtyczki.'))return;
 $('startUpdate').disabled=true;updating=true;
 showUpdateProgress('launching');clearUpdateLog();
 updateInfo(true,'Uruchamianie aktualizacji...');
 try{
  const url=window.location.pathname.replace(/\/$/,'')+'/api/updates/start';
  const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json','X-Update-CSRF':updateToken},body:JSON.stringify({version:availableUpdate,repair:repairMode})});
  const x=await r.json();
  if(!x.success){updating=false;updateInfo(false,x.message);$('startUpdate').disabled=false;showUpdateProgress('error')}
  else{updateInfo(true,'Aktualizacja uruchomiona. Komunikaty YunoHost pojawią się poniżej.');await fetchUpdateLog()}
 }catch(e){updateInfo(false,'Błąd uruchamiania: '+e.message);updating=false;showUpdateProgress('error')}
};
async function pollUpdates(){
 if(updatePollLoading)return;
 updatePollLoading=true;
 try{
  const s=await api('/api/updates/status');if(!s.success)return;
  // Version in the running process, not the old page's built-in label.
  if(s.installed && $('versionInstalled').textContent!==s.installed){
   $('versionInstalled').textContent=s.installed;
   if(!updating)checkUpdates().catch(()=>{});
  }
  const state=s.state, status=state.status;
  const run=String(state.started_at||'')+':'+String(state.target||'');
  if(run!==':'&&updateLastRun&&run!==updateLastRun){clearUpdateLog()}
  if(run!==':')updateLastRun=run;
  if(['launching','running'].includes(status)){
   updating=true;$('startUpdate').disabled=true;updateInfo(true,state.message);
   showUpdateProgress(status);await fetchUpdateLog();
  }else if(['success','error'].includes(status)){
   if(updating||status==='error')updateInfo(status==='success',state.message+(status==='success'?' Panel działa już w nowej wersji.':''));
   updating=false;showUpdateProgress(status);await fetchUpdateLog();
   if(status==='success' && s.installed===state.target && availableUpdate===state.target){
    availableUpdate=repairMode?s.installed:'';$('versionInstalled').textContent=s.installed;
    $('versionRemote').textContent=s.installed;
    $('startUpdate').disabled=!repairMode;
    updateInfo(true,repairMode?'Ponowna instalacja zakończona: '+s.installed:'Aplikacja jest aktualna: '+s.installed);
   }
  }
 }catch(e){if(updating)updateInfo(true,'Trwa aktualizacja — oczekiwanie na ponowne uruchomienie panelu...')}
 finally{updatePollLoading=false}
}
checkUpdates();pollUpdates();setInterval(pollUpdates,1700);
backupPoll().catch(e=>msg(false,e.message));
setInterval(()=>backupPoll().catch(()=>{}),3000);
restorePoll().catch(()=>{});setInterval(()=>restorePoll().catch(()=>{}),3000);
refreshApps().then(()=>scheduleAppChoices([])).catch(e=>msg(false,e.message));
loadSchedules().catch(()=>{});
setInterval(()=>{if(location.hash==='#harmonogram')loadSchedules().catch(()=>{});},30000);
refresh().catch(e=>msg(false,e.message));
</script></body></html>'''

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5050, debug=False)
