"""Safely identify and remove *only* unfinished YBM artifacts.

No system changes: all operations are invoked by the app on an explicitly
selected backup. The SMB directory must have no completion marker or unknown
files. Nothing outside a single named archive directory can be removed.
"""
import json
import re

from resumable_chunks import join_rel, manifest_validate, MAX_MANIFEST

OWN_BACKUP = re.compile(r'ybm_[A-Za-z0-9_.-]{1,80}_[0-9]{8}_[0-9]{6}_[a-f0-9]{6}\Z')
PART_FILENAME = re.compile(r'(?:tar|info)\.[0-9]{6}\.part\Z')
STAGING_NAMES = {'pending.json', 'report.json'}


def validate_own_backup(name):
    if not isinstance(name, str) or not OWN_BACKUP.fullmatch(name) or '..' in name:
        raise ValueError('Nazwa nie należy do kopii utworzonej przez Backup Manager.')
    return name


def scan_partial(store):
    """List only unfinished YBM directories containing recognizable work files."""
    result = []
    for name, meta in store.listing().items():
        if not meta.directory or not OWN_BACKUP.fullmatch(name):
            continue
        if store.exists(join_rel(name, 'complete.json')):
            continue
        entries = store.listing(name)
        if entries and all(not ent.directory and (PART_FILENAME.fullmatch(k) or k in STAGING_NAMES)
                           for k, ent in entries.items()):
            result.append(name)
    return sorted(result)


def delete_partial(store, name, storage_id=None):
    """Refuse complete or unknown directories. Idempotent for retried deletion."""
    validate_own_backup(name)
    root_entry = store.exists(name)
    if root_entry is None:
        return []
    if not root_entry.directory:
        raise ValueError('Ścieżka nie jest katalogiem niedokończonej kopii.')
    if store.exists(join_rel(name, 'complete.json')):
        raise ValueError('Kopia została ukończona; usuwanie pozostałości zablokowane.')
    entries = store.listing(name)
    unknown = [filename for filename, entry in entries.items()
               if entry.directory or not (PART_FILENAME.fullmatch(filename) or filename in STAGING_NAMES)]
    if unknown:
        raise ValueError('Katalog zawiera nieznane pliki; niczego nie usunięto: ' + ', '.join(unknown[:4]))
    if 'pending.json' in entries:
        # A network interruption can itself corrupt pending.json. Such a
        # staging file must not make abandoned chunks impossible to clean.
        # We already require a strict app-created directory name, exclusively
        # known part filenames and the absence of complete.json.
        raw = store.read_small(join_rel(name, 'pending.json'), MAX_MANIFEST)
        try:
            pending = json.loads(raw.decode('utf-8'))
        except (ValueError, UnicodeError):
            pending = None  # torn/incomplete write; directory whitelist still applies
        if pending is not None:
            manifest_validate(pending, name, require_complete=False)
        if pending is not None and storage_id is not None and pending.get('storage') != storage_id:
            raise ValueError('Kopia należy do innego magazynu. Nie usuwam katalogu.')
    removed = []
    # Stop at first error and allow another explicit retry; never guess success.
    for filename in sorted(entries):
        store.remove(join_rel(name, filename))
        removed.append(filename)
    store.remove_dir(name)
    return removed
