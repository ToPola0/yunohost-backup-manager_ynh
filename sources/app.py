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
from updater import APP_VERSION, check_remote, read_state, write_state, read_log_chunk, LOG_FILE

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
        return jsonify(success=False, message='Kopia już trwa.'), 409
    backup_event('Rozpoczynanie kopii…', phase='prepare', status='running', reset=True)
    threading.Thread(target=backup_worker, args=(app_ids, storage_id, [app_labels[a] for a in app_ids]), daemon=True).start()
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
</style></head><body><header style="display:flex;align-items:center;gap:12px"><img id="appLogo" alt="" width="48" height="48" style="border-radius:9px;object-fit:contain"><span>YunoHost Backup Manager <small style="color:#cad5e5">0.5~ynh13</small></span></header><main>
<section class="panel" id="updatePanel"><h2>Aktualizacje aplikacji</h2>
<p>Wersja zainstalowana: <strong id="versionInstalled">0.5~ynh13</strong> &nbsp;|&nbsp; GitHub: <strong id="versionRemote">Sprawdzanie...</strong></p>
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
<div id="backupProgress" hidden>
  <div class="update-progress-caption"><strong id="backupStage">Przygotowywanie kopii</strong><span id="backupPhase">Trwa praca…</span></div>
  <div id="backupTrack" class="update-track" role="progressbar" aria-label="Postęp wykonywania kopii" aria-valuetext="Trwa praca"><span id="backupFill" class="update-progress-fill"></span></div>
</div>
<details id="backupLogPanel" hidden open><summary>Podgląd tworzenia kopii (log)</summary>
<pre id="backupLogText" role="log" aria-label="Log tworzenia kopii">Oczekiwanie na uruchomienie…</pre></details>
<details style="margin-top:22px"><summary>Importuj listę aplikacji z YunoHost (tryb lokalny)</summary>
<p><small>Wklej wynik polecenia <code>yunohost app list --output-as json</code>. Nie podawaj haseł.</small></p>
<textarea id="appsJson" placeholder='{"apps":[{"id":"wordpress","name":"Bałchan","domain_path":"strona.rpkj.ovh/organypiszczalkowe"}]}'></textarea>
<div class="actions"><button type="button" id="importApps">Importuj aplikacje</button></div>
<div id="importProgress" hidden>
  <div class="update-progress-caption"><strong id="importStage">Importowanie aplikacji</strong><span id="importPhase">Przygotowanie danych…</span></div>
  <div id="importTrack" class="update-track" role="progressbar" aria-label="Stan importu" aria-valuetext="Trwa import"><span class="update-progress-fill"></span></div>
</div>
<details id="importLogPanel" hidden open><summary>Podgląd przebiegu importu</summary><pre id="importLogText" role="log" aria-label="Log importu"></pre></details></details>
<div id="appsMessage" class="message"></div><div id="backupMessage" class="message"></div></section>
</main><script>
const $=id=>document.getElementById(id);let editing=null;let records=[];
$('appLogo').src=window.location.pathname.replace(/\/$/,'')+'/logo.png';
function msg(ok,s){$('message').style.display='block';$('message').className='message '+(ok?'ok':'error');$('message').textContent=s}
function data(){return Object.fromEntries(new FormData($('form')))}
async function api(url,method='GET',payload){const base=window.location.pathname.replace(/\/$/,'');const r=await fetch(base+url,{method,headers:{'Content-Type':'application/json'},body:payload?JSON.stringify(payload):undefined});return await r.json()}
function busy(v){for(const x of ['discover','test','save'])$(x).disabled=v}
function storageLocation(m){return m.share+(m.subdirectory?'/'+m.subdirectory.replace(/^\/+|\/+$/g,''):'')}
function reset(){editing=null;$('form').reset();$('id').disabled=false;$('password').required=true;$('formTitle').textContent='Dodaj magazyn SMB/CIFS';$('cancel').hidden=true;$('share').innerHTML='<option value="">Najpierw pobierz udziały</option>'}
async function refresh(){const x=await api('/api/magazyny');records=x.magazyny||[];const storage=$('backupStorage');const selected=storage.value;storage.replaceChildren(new Option('Wybierz magazyn',''));for(const m of records)storage.add(new Option(m.id+' ('+m.server+'/'+storageLocation(m)+')',m.id));storage.value=selected;const tbody=$('rows');tbody.replaceChildren();if(!records.length){const tr=tbody.insertRow();const td=tr.insertCell();td.colSpan=5;td.textContent='Brak zapisanych magazynów.';return}for(const m of records){const tr=tbody.insertRow();for(const v of [m.id,m.server,storageLocation(m),m.protocol==='auto'?'Auto':m.protocol.toUpperCase()])tr.insertCell().textContent=v;const td=tr.insertCell();for(const [title,fn,danger] of [['Edytuj',()=>edit(m.id),false],['Usuń',()=>remove(m.id),true]]){const b=document.createElement('button');b.textContent=title;b.className=danger?'danger':'secondary';b.onclick=fn;td.appendChild(b)}}}
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
async function backupPoll(){
 const s=await api('/api/backup/status');const btn=$('runBackup');btn.disabled=!s.available||s.status==='running';
 const box=$('backupMessage');box.style.display='block';box.className='message '+(s.status==='error'?'error':'ok');
 box.textContent=s.available?s.message:'Tryb Windows: kopie będą dostępne po uruchomieniu aplikacji na YunoHost.';
 const progress=$('backupProgress'),logPanel=$('backupLogPanel'),track=$('backupTrack'),fill=$('backupFill');
 if(s.status==='idle'){progress.hidden=true;logPanel.hidden=true;return}
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
 if(!r.success)alert(r.message);await backupPoll();
};
let updateToken='';let availableUpdate='';let updating=false;
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
  if(u.available){availableUpdate=u.latest;updateInfo(true,'Dostępna nowa wersja: '+u.latest);$('startUpdate').disabled=updating}
  else updateInfo(true,'Aplikacja jest aktualna.');
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
 if(!confirm('Zaktualizować YunoHost Backup Manager do '+availableUpdate+'? Panel uruchomi ponownie własną usługę.'))return;
 $('startUpdate').disabled=true;updating=true;
 showUpdateProgress('launching');clearUpdateLog();
 updateInfo(true,'Uruchamianie aktualizacji...');
 try{
  const url=window.location.pathname.replace(/\/$/,'')+'/api/updates/start';
  const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json','X-Update-CSRF':updateToken},body:JSON.stringify({version:availableUpdate})});
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
    availableUpdate='';$('versionInstalled').textContent=s.installed;
    $('versionRemote').textContent=s.installed;
    $('startUpdate').disabled=true;updateInfo(true,'Aplikacja jest aktualna: '+s.installed);
   }
  }
 }catch(e){if(updating)updateInfo(true,'Trwa aktualizacja — oczekiwanie na ponowne uruchomienie panelu...')}
 finally{updatePollLoading=false}
}
checkUpdates();pollUpdates();setInterval(pollUpdates,1700);
backupPoll().catch(e=>msg(false,e.message));
setInterval(()=>backupPoll().catch(()=>{}),3000);
refreshApps().catch(e=>msg(false,e.message));
refresh().catch(e=>msg(false,e.message));
</script></body></html>'''

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5050, debug=False)
