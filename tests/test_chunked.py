"""Offline tests for reconnect, corrupted fragments, commit and restore."""
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest

# Tests don't require contacting OMV or installing SMB libraries.
sys.modules.setdefault('smbclient', types.ModuleType('smbclient'))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sources'))
import resumable_chunks as c


class FakeStore:
    def __init__(self):
        self.files = {}
        self.directories = set()
        self.upload_count = {}
        self.fail_upload = None

    def ensure_directory(self, name):
        self.directories.add(name)

    def listing(self, rel=''):
        result = {}
        for name in self.directories:
            if (not rel and '/' not in name) or (rel and name.startswith(rel + '/') and '/' not in name[len(rel)+1:]):
                short = name[len(rel)+1:] if rel else name
                result[short] = c.Entry(0, True)
        for name, data in self.files.items():
            if not rel and '/' not in name:
                result[name] = c.Entry(len(data), False)
            elif rel and name.startswith(rel+'/') and '/' not in name[len(rel)+1:]:
                result[name[len(rel)+1:]] = c.Entry(len(data), False)
        return result

    def exists(self, rel):
        d = self.files.get(rel)
        return c.Entry(len(d), False) if d is not None else None

    def stream_write(self, rel, reader, expected, callback=None):
        if rel == self.fail_upload:
            self.fail_upload = None
            self.files[rel] = reader.read(max(1, expected // 2))
            raise ConnectionError('simulated unplug / reconnect')
        buffer = bytearray()
        while data := reader.read(256):
            buffer.extend(data)
        self.files[rel] = bytes(buffer)
        self.upload_count[rel] = self.upload_count.get(rel, 0) + 1

    def read_to(self, rel, writer, maximum):
        for n in range(0, len(self.files[rel]), 333):
            writer.write(self.files[rel][n:n+333])

    def read_small(self, rel, max_size):
        if rel not in self.files:
            raise FileNotFoundError(rel)
        data = self.files[rel]
        assert len(data) <= max_size
        return data

    def write_small(self, rel, data):
        self.files[rel] = data
        assert self.read_small(rel, 10_000_000) == data

    def remove(self, rel):
        self.files.pop(rel)

    def remove_dir(self, rel):
        assert all(not key.startswith(rel + '/') for key in self.files)
        self.directories.remove(rel)


class ChunkTests(unittest.TestCase):
    def setUp(self):
        self.old_size = c.CHUNK_SIZE
        c.CHUNK_SIZE = 1024
        self.work = tempfile.TemporaryDirectory()
        self.local = Path(self.work.name)
        self.name = 'ybm_Test_20261024_110000_test01'
        self.tar = self.local / (self.name + '.tar')
        self.info = self.local / (self.name + '.info.json')
        self.tar.write_bytes(os.urandom(4100))
        self.info.write_text(json.dumps({'apps': {'wordpress': {'name': 'Bałchan'}}}), encoding='utf-8')
        self.files = {'tar': self.tar, 'info': self.info}
        self.manifest = c.make_manifest(self.name, self.files, ['wordpress'], ['Bałchan'], 'OMV2', '2026')
        self.store = FakeStore()

    def tearDown(self):
        self.work.cleanup()
        c.CHUNK_SIZE = self.old_size

    def transfer(self, **kwargs):
        return c.synchronize_chunks(self.store, self.name, self.files, self.manifest, **kwargs)

    def commit(self):
        for role, path in self.files.items():
            self.manifest['files'][role]['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        report = json.dumps({'archive': self.name, 'status': 'verified'}).encode()
        self.store.write_small(self.name + '/report.json', report)
        self.manifest['report_sha256'] = hashlib.sha256(report).hexdigest()
        self.manifest['completed_at'] = '2026-10-24T11:00:00Z'
        c.save_manifest(self.store, self.name, self.manifest, finished=True)

    def test_every_part_is_in_one_named_folder(self):
        self.transfer()
        listing = self.store.listing(self.name)
        parts = [key for key in listing if key.endswith('.part')]
        self.assertEqual(len(parts), 6)
        self.assertTrue(all('/' not in filename for filename in parts))
        self.assertEqual(self.store.directories, {self.name})
        self.assertTrue(all(key.startswith(self.name + '/') for key in self.store.files))

    def test_resume_after_partial_upload_and_manifest_gate(self):
        self.store.fail_upload = self.name + '/tar.000001.part'
        with self.assertRaises(ConnectionError):
            self.transfer()
        self.assertIsNone(c.read_manifest(self.store, self.name))
        self.assertFalse(c.catalog_chunked(self.store, lambda b: {'apps': []}))
        first = self.store.upload_count[self.name + '/tar.000000.part']
        result = self.transfer()
        self.assertEqual(result['reused'], 1)
        self.assertEqual(self.store.upload_count[self.name + '/tar.000000.part'], first)
        self.assertEqual(result['sent'], 5)  # 5 tar pieces + 1 info, first reused
        self.commit()
        self.assertEqual(c.read_manifest(self.store, self.name)['archive'], self.name)
        rows = c.catalog_chunked(self.store, lambda b: {'apps': ['wordpress']})
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]['complete'])

    def test_remote_corruption_only_repairs_corrupted_part(self):
        self.transfer()
        original_counts = dict(self.store.upload_count)
        key = self.name + '/tar.000002.part'
        self.store.files[key] = b'X' * 1024
        outcome = self.transfer()
        self.assertEqual(outcome['sent'], 1)
        for rel, count in original_counts.items():
            self.assertEqual(self.store.upload_count[rel], count + (1 if rel == key else 0))

    def test_restore_checks_each_chunk_and_full_archive_hash(self):
        self.transfer()
        self.commit()
        manifest = c.read_manifest(self.store, self.name)
        for role in ('tar', 'info'):
            path = self.local / ('rebuilt_' + role + '.part')
            c.download_file(self.store, self.name, role, manifest['files'][role], path)
            self.assertEqual(path.read_bytes(), self.files[role].read_bytes())
            # Existing downloaded chunks may be reused after an interrupted restore.
            c.download_file(self.store, self.name, role, manifest['files'][role], path)
        self.store.files[self.name + '/tar.000000.part'] = b'M' * 1024
        with self.assertRaises(IOError):
            c.download_file(self.store, self.name, 'tar', manifest['files']['tar'],
                            self.local / 'broken.part')

    def test_delete_does_not_touch_any_other_archive(self):
        self.transfer()
        self.commit()
        self.store.files['other-file.txt'] = b'dont touch'
        deleted = c.safe_remove_complete(self.store, self.name)
        self.assertIn('complete.json', deleted)
        self.assertEqual(self.store.files, {'other-file.txt': b'dont touch'})

    def test_prevents_destruction_when_unknown_file_inside_folder(self):
        self.transfer()
        self.commit()
        self.store.files[self.name + '/userfile.txt'] = b'private'
        with self.assertRaises(RuntimeError):
            c.safe_remove_complete(self.store, self.name)
        self.assertIn(self.name + '/complete.json', self.store.files)

    def test_live_byte_progress_and_resume(self):
        values = []
        self.transfer(on_progress=lambda role, number, stage, size: values.append((stage, size)))
        self.assertTrue(any(stage == 'upload' for stage, n in values))
        self.assertTrue(any(stage == 'verify' for stage, n in values))
        values.clear()
        self.transfer(on_progress=lambda role, number, stage, size: values.append((stage, size)))
        self.assertTrue(any(stage == 'check' for stage, n in values))
        self.assertFalse(any(stage == 'upload' for stage, n in values))

    def test_corrupt_report_never_makes_complete_copy_visible(self):
        self.transfer()
        self.commit()
        self.store.files[self.name + '/report.json'] = b'broken'
        self.assertEqual(c.catalog_chunked(self.store, lambda b: {'apps':['wordpress']}), [])

    def test_cancel_keeps_backup_not_committed(self):
        calls = [0]
        def cancel():
            calls[0] += 1
            return calls[0] > 2
        with self.assertRaises(InterruptedError):
            self.transfer(cancelled=cancel)
        self.assertIsNone(c.read_manifest(self.store, self.name))


if __name__ == '__main__':
    unittest.main()
