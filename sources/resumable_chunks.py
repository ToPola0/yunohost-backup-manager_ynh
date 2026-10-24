"""Resumable, per-chunk verified SMB archives; confined to the application's own code.

Only a validated complete.json is a backup. Partial directories are staging and
are deliberately hidden from the library. No external daemon, mount, or cron.
"""
from contextlib import contextmanager
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
import datetime
import errno
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import threading

import smbclient

CHUNK_SIZE = 256 * 1024 * 1024
BLOCK_SIZE = 1024 * 1024
FORMAT = 'ybm-smb-chunks-v1'
MAX_MANIFEST = 4 * 1024 * 1024
MAX_REPORT = 1024 * 1024
_SAFE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,179}\Z')


def validate_name(name):
    if not isinstance(name, str) or not _SAFE.fullmatch(name) or '..' in name:
        raise ValueError('Nieprawidłowa nazwa archiwum.')
    return name


def join_rel(*parts):
    for part in parts:
        if not isinstance(part, str) or not part or part in ('.', '..') or '/' in part or '\\' in part:
            raise ValueError('Nieprawidłowa ścieżka archiwum.')
    return '/'.join(parts)


@dataclass
class Entry:
    size: int
    directory: bool = False


class LimitedReader:
    def __init__(self, path, offset, expected, callback=None):
        self.source = open(path, 'rb')
        self.source.seek(offset)
        self.offset = offset
        self.expected = expected
        self.pos = 0
        self.sha256 = hashlib.sha256()
        self.callback = callback

    def read(self, n=-1):
        remaining = self.expected - self.pos
        if remaining <= 0:
            return b''
        result = self.source.read(min(remaining, BLOCK_SIZE if n < 0 else n))
        if result:
            self.pos += len(result)
            self.sha256.update(result)
            if self.callback:
                self.callback(len(result))
        return result

    def tell(self):
        return self.pos

    def seek(self, offset, whence=os.SEEK_SET):
        if whence == os.SEEK_END:
            target = self.expected + offset
        elif whence == os.SEEK_CUR:
            target = self.pos + offset
        elif whence == os.SEEK_SET:
            target = offset
        else:
            raise ValueError('Nieprawidłowy tryb seek().')
        if target < 0 or target > self.expected:
            raise ValueError('Próba odczytu poza fragmentem.')
        if target != self.pos and not (self.pos in (0, self.expected) and target in (0, self.expected)):
            raise IOError('Nieobsługiwane przewijanie strumienia SMB.')
        self.source.seek(self.offset + target)
        self.pos = target
        if target == 0:
            self.sha256 = hashlib.sha256()
        return self.pos

    def __getattr__(self, name):
        return getattr(self.source, name)

    def close(self):
        self.source.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class BoundedWriter:
    def __init__(self, stream, max_size, on_data=None):
        self.stream = stream
        self.max_size = max_size
        self.received = 0
        self.sha256 = hashlib.sha256()
        self.on_data = on_data

    def write(self, value):
        if self.received + len(value) > self.max_size:
            raise ValueError('Przekroczono dozwolony rozmiar fragmentu.')
        self.stream.write(value)
        self.sha256.update(value)
        self.received += len(value)
        if self.on_data:
            self.on_data(len(value))
        return len(value)


class SMBStore:
    """One authenticated SMB connection (SMB1 or SMB2/3) and relative paths."""
    def __init__(self, cfg, dialect, endpoint_factory, legacy_factory, legacy_dirs, modern_dirs):
        self.cfg, self.dialect = cfg, dialect
        self.endpoint_factory = endpoint_factory
        self.legacy_factory, self.legacy_dirs, self.modern_dirs = legacy_factory, legacy_dirs, modern_dirs
        self.context = None
        self.conn = None
        self.cache = {}
        self.server = None
        self.port = None
        self.root = None

    def __enter__(self):
        self.context = self.endpoint_factory(self.cfg['server'])
        endpoint = self.context.__enter__()
        self.server, self.port = endpoint.host, endpoint.port
        try:
            if self.dialect == 'smb1':
                self.conn = self.legacy_factory(self.cfg, True, endpoint.host, endpoint.port)
                self.legacy_dirs(self.conn, self.cfg)
                self.root = '/' + self.cfg['subdirectory'].strip('/') if self.cfg['subdirectory'] else ''
            else:
                user = (self.cfg['domain'] + '\\' if self.cfg['domain'] else '') + self.cfg['username']
                smbclient.register_session(self.server, username=user, password=self.cfg['password'],
                                           port=self.port, connection_timeout=15, connection_cache=self.cache)
                self.modern_dirs(self.cfg, self.cache, self.server, self.port)
                self.root = '\\\\' + self.server + '\\' + self.cfg['share']
                if self.cfg['subdirectory']:
                    self.root += '\\' + self.cfg['subdirectory'].replace('/', '\\')
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        try:
            if self.conn:
                self.conn.close()
            elif self.server:
                try:
                    smbclient.delete_session(self.server, port=self.port, connection_cache=self.cache)
                except Exception:
                    pass
        finally:
            if self.context:
                self.context.__exit__(None, None, None)

    def path(self, rel=''):
        if rel:
            for p in rel.split('/'):
                join_rel(p)
        if self.dialect == 'smb1':
            return (self.root + '/' + rel).replace('//', '/') if rel else (self.root or '/')
        return self.root + ('\\' + rel.replace('/', '\\') if rel else '')

    def listing(self, rel=''):
        if self.dialect == 'smb1':
            items = self.conn.listPath(self.cfg['share'], self.path(rel) + ('/' if rel else ''), timeout=60)
            return {e.filename: Entry(int(e.file_size), bool(e.isDirectory)) for e in items
                    if e.filename not in ('.', '..')}
        out = {}
        for name in smbclient.listdir(self.path(rel), port=self.port, connection_cache=self.cache):
            p = join_rel(rel, name) if rel else join_rel(name)
            entry_stat = smbclient.stat(self.path(p), port=self.port, connection_cache=self.cache)
            out[name] = Entry(int(entry_stat.st_size), stat.S_ISDIR(entry_stat.st_mode))
        return out

    def ensure_directory(self, rel):
        components = rel.split('/')
        for i in range(1, len(components)+1):
            current = '/'.join(components[:i])
            parent = '/'.join(components[:i-1])
            entries = self.listing(parent)
            if components[i-1] in entries:
                if not entries[components[i-1]].directory:
                    raise ValueError('Ścieżka magazynu zajęta przez plik.')
                continue
            if self.dialect == 'smb1':
                self.conn.createDirectory(self.cfg['share'], self.path(current), timeout=60)
            else:
                try:
                    smbclient.mkdir(self.path(current), port=self.port, connection_cache=self.cache)
                except OSError as exc:
                    if exc.errno != errno.EEXIST:
                        raise

    def exists(self, rel):
        parent, _, base = rel.rpartition('/')
        return self.listing(parent).get(base)

    def stream_write(self, rel, source, expected, callback=None):
        if self.dialect == 'smb1':
            self.conn.storeFile(self.cfg['share'], self.path(rel), source, timeout=3600)
            if source.pos != expected:
                raise IOError('Nie udało się wysłać wszystkich bajtów części.')
        else:
            with smbclient.open_file(self.path(rel), 'wb', port=self.port, connection_cache=self.cache) as dest:
                while True:
                    chunk = source.read(BLOCK_SIZE)
                    if not chunk:
                        break
                    dest.write(chunk)
            if source.pos != expected:
                raise IOError('Nie udało się wysłać wszystkich bajtów części.')

    def read_to(self, rel, writer, maximum):
        if self.dialect == 'smb1':
            self.conn.retrieveFile(self.cfg['share'], self.path(rel), writer, timeout=3600)
        else:
            with smbclient.open_file(self.path(rel), 'rb', port=self.port, connection_cache=self.cache) as src:
                while True:
                    chunk = src.read(BLOCK_SIZE)
                    if not chunk:
                        break
                    writer.write(chunk)
        if writer.received > maximum:
            raise IOError('Zdalny fragment przekroczył zadeklarowany rozmiar.')

    def read_small(self, rel, max_size):
        entry = self.exists(rel)
        if not entry or entry.directory or entry.size > max_size:
            raise FileNotFoundError('Brak pliku lub nieprawidłowy rozmiar: ' + rel)
        sink = io.BytesIO()
        writer = BoundedWriter(sink, max_size)
        self.read_to(rel, writer, max_size)
        if writer.received != entry.size:
            raise IOError('Niepełny odczyt: ' + rel)
        return sink.getvalue()

    def write_small(self, rel, raw):
        if len(raw) > MAX_MANIFEST:
            raise ValueError('Plik manifestu jest za duży.')
        stream = io.BytesIO(raw)
        if self.dialect == 'smb1':
            self.conn.storeFile(self.cfg['share'], self.path(rel), stream, timeout=120)
        else:
            with smbclient.open_file(self.path(rel), 'wb', port=self.port, connection_cache=self.cache) as dest:
                dest.write(raw)
        if self.read_small(rel, MAX_MANIFEST) != raw:
            raise IOError('Weryfikacja zdalnego pliku metadanych nie powiodła się.')

    def remove(self, rel):
        if self.dialect == 'smb1':
            self.conn.deleteFiles(self.cfg['share'], self.path(rel), timeout=120)
        else:
            smbclient.remove(self.path(rel), port=self.port, connection_cache=self.cache)

    def remove_dir(self, rel):
        if self.dialect == 'smb1':
            self.conn.deleteDirectory(self.cfg['share'], self.path(rel), timeout=120)
        else:
            smbclient.rmdir(self.path(rel), port=self.port, connection_cache=self.cache)


def make_manifest(name, files, apps, names, storage, started_at):
    manifest = {'format': FORMAT, 'archive': validate_name(name), 'storage': storage,
                'started_at': started_at, 'completed_at': None, 'report_sha256': None, 'files': {},
                'apps': [{'id': a, 'name': n} for a, n in zip(apps, names)]}
    for role, path in files.items():
        if role not in ('tar', 'info') or not path.is_file():
            raise RuntimeError('Brak pliku lokalnej kopii: ' + str(path))
        size = path.stat().st_size
        if size <= 0:
            raise RuntimeError('Archiwum lokalne ma nieprawidłowy rozmiar.')
        manifest['files'][role] = {'name': path.name, 'bytes': size, 'sha256': None, 'chunks': []}
        count = (size + CHUNK_SIZE - 1) // CHUNK_SIZE
        if count > 100000:
            raise RuntimeError('Zbyt wiele części kopii.')
        for n in range(count):
            manifest['files'][role]['chunks'].append({'name': f'{role}.{n:06d}.part',
                'bytes': min(CHUNK_SIZE, size-n*CHUNK_SIZE), 'sha256': None})
    return manifest


def manifest_validate(payload, name=None, require_complete=True):
    if not isinstance(payload, dict) or payload.get('format') != FORMAT:
        raise ValueError('Nieprawidłowy format wieloczęściowej kopii.')
    archive = validate_name(payload.get('archive'))
    if name is not None and archive != name:
        raise ValueError('Niezgodna nazwa archiwum.')
    if require_complete and not isinstance(payload.get('completed_at'), str):
        raise ValueError('Brak potwierdzenia ukończenia kopii.')
    if require_complete and (not isinstance(payload.get('report_sha256'), str) or
                             not re.fullmatch(r'[a-f0-9]{64}', payload['report_sha256'])):
        raise ValueError('Brak SHA256 raportu końcowego.')
    files = payload.get('files')
    if not isinstance(files, dict) or set(files) != {'tar', 'info'}:
        raise ValueError('Nieprawidłowy zestaw plików kopii.')
    for role, value in files.items():
        size, chunks = value.get('bytes'), value.get('chunks')
        if require_complete and (not isinstance(value.get('sha256'), str) or
                                 not re.fullmatch(r'[a-f0-9]{64}', value['sha256'])):
            raise ValueError('Brakuje pełnej sumy SHA256 archiwum.')
        if not isinstance(size, int) or size <= 0 or not isinstance(chunks, list) or len(chunks) != (size+CHUNK_SIZE-1)//CHUNK_SIZE or len(chunks) > 100000:
            raise ValueError('Nieprawidłowe rozmiary części.')
        for n, chunk in enumerate(chunks):
            wanted = min(CHUNK_SIZE, size - n*CHUNK_SIZE)
            if not isinstance(chunk, dict) or chunk.get('name') != f'{role}.{n:06d}.part' or chunk.get('bytes') != wanted:
                raise ValueError('Nieprawidłowa numeracja części.')
            sha = chunk.get('sha256')
            if require_complete and (not isinstance(sha, str) or not re.fullmatch(r'[a-f0-9]{64}', sha)):
                raise ValueError('Brak sumy SHA256 części.')
    return payload


def read_manifest(store, name):
    try:
        data = store.read_small(join_rel(name, 'complete.json'), MAX_MANIFEST)
    except (FileNotFoundError, OSError):
        return None
    return manifest_validate(json.loads(data.decode('utf-8')), name)


def chunks_match(store, rel, expected, sha, progress=None, cancelled=None):
    entry = store.exists(rel)
    if not entry or entry.directory or entry.size != expected:
        return False
    def tick(amount):
        if cancelled and cancelled():
            raise InterruptedError('Transfer anulowany przez operatora.')
        if progress:
            progress(amount)
    sink = BoundedWriter(_NullWriter(), expected, on_data=tick)
    store.read_to(rel, sink, expected)
    return sink.received == expected and sink.sha256.hexdigest() == sha


class _NullWriter:
    def write(self, data):
        return len(data)


def local_chunk_hash(path, offset, length):
    sha = hashlib.sha256()
    with open(path, 'rb') as src:
        src.seek(offset)
        remaining = length
        while remaining:
            data = src.read(min(remaining, BLOCK_SIZE))
            if not data:
                raise IOError('Źródłowy plik lokalny został skrócony.')
            sha.update(data)
            remaining -= len(data)
    return sha.hexdigest()


def upload_one(store, local_path, name, chunk, offset, sha, progress=None, cancelled=None):
    rel = join_rel(name, chunk['name'])
    if chunks_match(store, rel, chunk['bytes'], sha,
                    progress=(lambda n: progress('check', n)) if progress else None,
                    cancelled=cancelled):
        return 'verified_existing'
    if progress:
        progress('reset', 0)
    with LimitedReader(local_path, offset, chunk['bytes'],
                       callback=(lambda n: progress('upload', n)) if progress else None) as src:
        store.stream_write(rel, src, chunk['bytes'])
        if src.pos != chunk['bytes'] or src.sha256.hexdigest() != sha:
            raise IOError('Źródłowy fragment zmienił się podczas wysyłki.')
    if not chunks_match(store, rel, chunk['bytes'], sha,
                        progress=(lambda n: progress('verify', n)) if progress else None,
                        cancelled=cancelled):
        raise IOError('Odczyt kontrolny SHA256 części nie zgadza się.')
    return 'sent'


def manifest_bytes(value):
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    if len(raw) > MAX_MANIFEST:
        raise ValueError('Manifest kopii przekroczył limit.')
    return raw


def get_partial_metadata(store, name):
    try:
        return json.loads(store.read_small(join_rel(name, 'pending.json'), MAX_MANIFEST).decode('utf-8'))
    except FileNotFoundError:
        return None


def save_manifest(store, name, value, finished=False):
    store.write_small(join_rel(name, 'complete.json' if finished else 'pending.json'), manifest_bytes(value))


def upload_report(store, name, report):
    data = (json.dumps(report, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    if len(data) > MAX_REPORT:
        raise ValueError('Raport jest większy niż 1 MiB.')
    store.write_small(join_rel(name, 'report.json'), data)
    return hashlib.sha256(data).hexdigest()


def download_file(store, name, role, info, destination, progress=None, cancelled=None):
    """Assemble verified pieces locally. Keep already-good parts after disconnect."""
    expected = info['bytes']
    destination.parent.mkdir(parents=True, exist_ok=True)
    mode = 'r+b' if destination.exists() else 'w+b'
    with open(destination, mode) as out:
        for i, part in enumerate(info['chunks']):
            if cancelled and cancelled():
                raise InterruptedError('Przerwano pobieranie na żądanie operatora.')
            offset = i * CHUNK_SIZE
            # Trust no cached partial content without a fresh SHA256 comparison.
            out.seek(0, os.SEEK_END)
            if out.tell() >= offset + part['bytes']:
                out.seek(offset)
                digest = hashlib.sha256()
                left = part['bytes']
                while left:
                    data = out.read(min(BLOCK_SIZE, left))
                    if not data:
                        break
                    digest.update(data)
                    left -= len(data)
                if left == 0 and digest.hexdigest() == part['sha256']:
                    if progress:
                        progress(part['bytes'])
                    continue
            out.seek(offset)
            writer = BoundedWriter(out, part['bytes'])
            store.read_to(join_rel(name, part['name']), writer, part['bytes'])
            if writer.received != part['bytes'] or writer.sha256.hexdigest() != part['sha256']:
                raise IOError('Uszkodzona część podczas przywracania: ' + part['name'])
            out.flush()
            if progress:
                progress(part['bytes'])
        out.truncate(expected)
        out.flush()
        os.fsync(out.fileno())
    if destination.stat().st_size != expected:
        raise IOError('Niekompletne złożone archiwum.')
    full_sha = info.get('sha256')
    if not isinstance(full_sha, str) or not re.fullmatch('[a-f0-9]{64}', full_sha):
        raise ValueError('Manifest nie zawiera pełnej sumy SHA256.')
    sha = hashlib.sha256()
    with destination.open('rb') as source:
        for part in iter(lambda: source.read(BLOCK_SIZE), b''):
            sha.update(part)
    if sha.hexdigest() != full_sha:
        raise IOError('Pełne archiwum po złożeniu ma błędne SHA256.')


def synchronize_chunks(store, name, local_files, manifest, on_verified=None, cancelled=None,
                       on_progress=None, workers=1, store_factory=None):
    """Recheck *every* chunk; transfer only absent/invalid chunks.

    No completeness marker is written by this function. Caller publishes it
    only after report and whole-file hashes have also been verified.
    """
    validate_name(name)
    manifest_validate(manifest, name, require_complete=False)
    store.ensure_directory(name)
    result = {'sent': 0, 'reused': 0}
    jobs = []
    for role in ('tar', 'info'):
        local = pathlib.Path(local_files[role])
        descriptor = manifest['files'][role]
        if not local.is_file() or local.stat().st_size != descriptor['bytes']:
            raise RuntimeError('Źródłowa kopia lokalna zniknęła lub zmieniła rozmiar: ' + str(local))
        for n, chunk in enumerate(descriptor['chunks']):
            if cancelled and cancelled():
                raise InterruptedError('Operator zatrzymał przesyłanie kopii.')
            offset = n * CHUNK_SIZE
            digest = local_chunk_hash(local, offset, chunk['bytes'])
            if chunk['sha256'] is not None and chunk['sha256'] != digest:
                raise RuntimeError('Zmieniono lokalny fragment w trakcie przesyłania.')
            chunk['sha256'] = digest
            jobs.append((role, n, len(descriptor['chunks']), local, chunk, offset, digest))

    def process_one(worker_store, job, stop=None):
        role, n, count, local, chunk, offset, digest = job
        def interrupted():
            return (stop is not None and stop.is_set()) or (cancelled and cancelled())
        if interrupted():
            raise InterruptedError('Operator zatrzymał przesyłanie kopii.')
        def progress(stage, amount):
            if interrupted():
                raise InterruptedError('Operator zatrzymał przesyłanie kopii.')
            if on_progress:
                on_progress(role, n, stage, amount)
        return upload_one(worker_store, local, name, chunk, offset, digest,
                          progress=progress, cancelled=interrupted)

    def finished(job, outcome):
        role, n, count, _local, chunk, _offset, _digest = job
        result['reused' if outcome == 'verified_existing' else 'sent'] += 1
        if on_verified:
            on_verified(role, n, count, chunk['bytes'], outcome)

    # SMB1 uses a process-wide dialect flag in PySMB. Keep it strictly serial.
    # For SMB2/3 each worker gets its own SMB session, cache and endpoint. The
    # parent session is reserved for final manifests and the commit marker.
    if workers <= 1 or not store_factory or len(jobs) <= 1:
        for job in jobs:
            finished(job, process_one(store, job))
    else:
        workers = min(int(workers), 3, len(jobs))
        stop = threading.Event()
        first_error = None
        work = iter(jobs)

        def run_worker(job):
            if stop.is_set():
                raise InterruptedError('Zatrzymano inne przesyłania po błędzie.')
            with store_factory() as worker_store:
                return process_one(worker_store, job, stop)

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix='ybm-part') as pool:
            active = {}
            def submit_next():
                if stop.is_set():
                    return
                job = next(work, None)
                if job is not None:
                    active[pool.submit(run_worker, job)] = job

            for _ in range(workers):
                submit_next()
            while active:
                ready, _ = wait(tuple(active), return_when=FIRST_COMPLETED)
                for future in ready:
                    job = active.pop(future)
                    try:
                        outcome = future.result()
                        finished(job, outcome)
                    except Exception as exc:
                        # Preserve the original network error rather than a
                        # secondary cancellation from another worker.
                        if first_error is None or (isinstance(first_error, InterruptedError)
                                                   and not isinstance(exc, InterruptedError)):
                            first_error = exc
                        stop.set()
                    if not stop.is_set():
                        submit_next()
        if first_error is not None:
            raise first_error
    manifest_validate(manifest, name, require_complete=False)
    return result


def small_info_from_chunks(store, name, manifest):
    descriptor = manifest['files']['info']
    if descriptor['bytes'] > 2 * 1024 * 1024:
        raise ValueError('Metadane YunoHost przekraczają 2 MiB.')
    out = io.BytesIO()
    for chunk in descriptor['chunks']:
        writer = BoundedWriter(out, chunk['bytes'])
        store.read_to(join_rel(name, chunk['name']), writer, chunk['bytes'])
        if writer.received != chunk['bytes'] or writer.sha256.hexdigest() != chunk['sha256']:
            raise IOError('Nieprawidłowy fragment metadanych kopii.')
    data = out.getvalue()
    if len(data) != descriptor['bytes']:
        raise IOError('Niezgodny rozmiar metadanych.')
    return data


def verified_report(store, name, manifest):
    raw = store.read_small(join_rel(name, 'report.json'), MAX_REPORT)
    if hashlib.sha256(raw).hexdigest() != manifest['report_sha256']:
        raise IOError('SHA256 raportu nie zgadza się z manifestem.')
    report = json.loads(raw.decode('utf-8'))
    if not isinstance(report, dict) or report.get('archive') != name or report.get('status') != 'verified':
        raise ValueError('Raport nie potwierdza ukończenia kopii.')
    return raw


def catalog_chunked(store, parse_metadata, only=None):
    entries = store.listing()
    dirs = sorted((name for name, meta in entries.items() if meta.directory and _SAFE.fullmatch(name)
                   and (only is None or name == only)), reverse=True)
    records = []
    for name in dirs[:300]:
        # In-progress files never become a restorable row.
        if not store.exists(join_rel(name, 'complete.json')):
            continue
        try:
            manifest = read_manifest(store, name)
            if manifest is None:
                continue
            verified_report(store, name, manifest)
            info = parse_metadata(small_info_from_chunks(store, name, manifest))
            records.append({'name': name, 'format': 'chunked', 'complete': True,
                            'size': manifest['files']['tar']['bytes'],
                            'info_size': manifest['files']['info']['bytes'],
                            'report_available': bool(store.exists(join_rel(name, 'report.json'))),
                            'message': '', **info})
        except Exception:
            # Invalid completed entries are *not* considered safe to restore.
            continue
    return records


def safe_remove_complete(store, name):
    """Delete only contents specified by a trusted, validated final manifest."""
    manifest = read_manifest(store, name)
    if manifest is None:
        raise FileNotFoundError('Nie znaleziono kompletnej kopii.')
    entries = store.listing(name)
    expected = {'complete.json', 'report.json', 'pending.json'}
    for value in manifest['files'].values():
        expected.update(chunk['name'] for chunk in value['chunks'])
    unexpected = set(entries) - expected
    if unexpected:
        raise RuntimeError('W katalogu znajdują się nierozpoznane pliki; wtyczka ich nie usunie.')
    # Publish removal by deleting completion marker first; no partial appears in UI.
    store.remove(join_rel(name, 'complete.json'))
    for filename in sorted(expected - {'complete.json'}):
        if filename in entries:
            store.remove(join_rel(name, filename))
    store.remove_dir(name)
    return sorted(expected.intersection(set(entries) | {'complete.json'}))
