"""Built-in, YunoHost-native app updater; all configuration lives in the app."""
from pathlib import Path
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.request

APP_ID = 'yunohost-backup-manager'
APP_VERSION = '0.5~ynh8'
REPOSITORY = 'https://github.com/ToPola0/yunohost-backup-manager_ynh'
MANIFEST_URL = 'https://raw.githubusercontent.com/ToPola0/yunohost-backup-manager_ynh/main/manifest.toml'
DATA_DIR = Path(__file__).resolve().parent / 'data'
STATE_FILE = DATA_DIR / '.update-status.json'
LOG_FILE = DATA_DIR / '.update-last.log'


def check_remote():
    """Read a *fixed*, TLS-verified upstream manifest (no user-controlled URLs)."""
    import tomllib
    req = urllib.request.Request(MANIFEST_URL, headers={'User-Agent': 'YunoHost-Backup-Manager-Updater/1.0',
                                                         'Accept': 'text/plain'})
    with urllib.request.urlopen(req, timeout=12) as response:
        content = response.read(65537)
    if len(content) > 65536:
        raise ValueError('Manifest na GitHubie jest zbyt duży.')
    manifest = tomllib.loads(content.decode('utf-8'))
    if manifest.get('id') != APP_ID:
        raise ValueError('Nieprawidłowy identyfikator aplikacji w repozytorium.')
    version = manifest.get('version')
    if not isinstance(version, str) or not re.fullmatch(r'[0-9][0-9a-zA-Z.+:~_-]{0,70}', version):
        raise ValueError('Nieprawidłowy numer wersji na GitHubie.')
    newer = subprocess.run(['dpkg', '--compare-versions', version, 'gt', APP_VERSION],
                           check=False, timeout=5).returncode == 0
    return {'installed': APP_VERSION, 'latest': version, 'available': newer}


def read_state():
    try:
        with STATE_FILE.open('r', encoding='utf-8') as file:
            result = json.load(file)
        if isinstance(result, dict) and result.get('status') in ('launching','running','success','error'):
            if result['status'] in ('launching', 'running'):
                started = result.get('started_at')
                if isinstance(started, (int, float)) and time.time() - started > 10800:
                    return {'status': 'error', 'message': 'Poprzednia aktualizacja nie zakończyła się w ciągu 3 godzin. Sprawdź logi YunoHost i spróbuj ponownie.'}
            return result
    except (OSError, ValueError):
        pass
    return {'status': 'idle', 'message': 'Nie uruchomiono aktualizacji.'}


def write_state(**state):
    """Durable, atomic update state, shared across service restarts."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.update-', suffix='.tmp', dir=DATA_DIR)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as file:
            json.dump(state, file, ensure_ascii=False)
            file.flush()
            os.fsync(file.fileno())
        os.chmod(name, 0o600)
        os.replace(name, STATE_FILE)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass
