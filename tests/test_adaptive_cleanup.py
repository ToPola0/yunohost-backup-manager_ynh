"""Unit tests: adaptive selection, partial-only cleanup, and safe retry."""
from contextlib import contextmanager
from pathlib import Path
import sys
import tempfile
import types
import unittest

sys.modules.setdefault('smbclient', types.ModuleType('smbclient'))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sources'))
from resumable_chunks import AdaptiveUploadWidth, synchronize_chunks, make_manifest, Entry
from orphan_cleanup import scan_partial, delete_partial
from test_chunked import FakeStore
import resumable_chunks as rc


class AdaptiveTests(unittest.TestCase):
    def test_choose_best_one_when_parallel_uploads_get_slower(self):
        planner = AdaptiveUploadWidth(3)
        self.assertEqual(planner.choose(12), 1)
        planner.record(1, 100_000_000, 10)
        self.assertEqual(planner.choose(11), 2)
        planner.record(2, 100_000_000, 12)
        self.assertEqual(planner.choose(9), 3)
        planner.record(3, 100_000_000, 15)
        self.assertEqual(planner.choose(6), 1)

    def test_choose_two_when_three_not_better(self):
        planner = AdaptiveUploadWidth(3)
        planner.record(1, 100_000_000, 20)
        planner.record(2, 100_000_000, 9)
        planner.record(3, 100_000_000, 9)
        self.assertEqual(planner.choose(9), 2)

    def test_choose_three_if_measurements_show_gain(self):
        planner = AdaptiveUploadWidth(3)
        planner.record(1, 100_000_000, 30)
        planner.record(2, 100_000_000, 20)
        planner.record(3, 100_000_000, 9)
        self.assertEqual(planner.choose(9), 3)

    def test_adaptive_actual_transfer_checks_all_fragments(self):
        previous = rc.CHUNK_SIZE
        try:
            rc.CHUNK_SIZE = 1024
            with tempfile.TemporaryDirectory() as folder:
                f = Path(folder) / 'archive.tar'
                meta = Path(folder) / 'archive.info.json'
                f.write_bytes(b'content-' * 1200)
                meta.write_bytes(b'{"ok":true}')
                name = 'ybm_KGW_20261024_123456_abcdef'
                manifest = make_manifest(name, {'tar': f, 'info': meta}, ['wordpress__2'], ['KGW'], 'OMV2', 'now')
                store = FakeStore()
                @contextmanager
                def session():
                    yield store
                readings = []
                outcome = synchronize_chunks(store, name, {'tar': f, 'info': meta}, manifest,
                     workers=3, adaptive=True, store_factory=session,
                     on_adapt=lambda width, rate, _: readings.append((width, rate)))
                self.assertEqual(outcome['sent'], len(manifest['files']['tar']['chunks']) + 1)
                self.assertEqual(outcome['reused'], 0)
                self.assertIn(1, [width for width, _ in readings])
                self.assertIn(2, [width for width, _ in readings])
                self.assertIn(3, [width for width, _ in readings])
                again = synchronize_chunks(store, name, {'tar': f, 'info': meta}, manifest,
                     workers=3, adaptive=True, store_factory=session)
                self.assertEqual(again['sent'], 0)
                self.assertEqual(again['reused'], outcome['sent'])
        finally:
            rc.CHUNK_SIZE = previous


class LeftoverTests(unittest.TestCase):
    def setUp(self):
        class DirectoryAwareStore(FakeStore):
            def exists(self, rel):
                if rel in self.directories:
                    return Entry(0, True)
                return super().exists(rel)
        self.store = DirectoryAwareStore()
        self.name = 'ybm_KGW_20261024_161656_907097'
        self.store.directories.add(self.name)
        self.store.files[self.name+'/tar.000000.part'] = b'1234'
        self.store.files[self.name+'/info.000000.part'] = b'{}'

    def test_cancelled_parts_can_be_removed_and_no_other_directory_touched(self):
        another = 'ybm_Balchan_20261024_105243_d672c5'
        self.store.directories.add(another)
        self.store.files[another+'/complete.json'] = b'complete'
        self.assertEqual(scan_partial(self.store), [self.name])
        files = delete_partial(self.store, self.name)
        self.assertEqual(len(files), 2)
        self.assertNotIn(self.name, self.store.directories)
        self.assertIn(another+'/complete.json', self.store.files)

    def test_finished_backup_cannot_be_cleaned(self):
        self.store.files[self.name+'/complete.json'] = b'complete'
        with self.assertRaises(ValueError):
            delete_partial(self.store, self.name)
        self.assertIn(self.name+'/tar.000000.part', self.store.files)

    def test_unknown_file_prevents_any_deletion(self):
        self.store.files[self.name+'/notes.txt'] = b'keep'
        with self.assertRaises(ValueError):
            delete_partial(self.store, self.name)
        self.assertEqual(len(self.store.files), 3)

    def test_torn_pending_manifest_can_be_cleaned(self):
        self.store.files[self.name+'/pending.json'] = b'{"format":"bad","files":'
        deleted = delete_partial(self.store, self.name)
        self.assertIn('pending.json', deleted)
        self.assertNotIn(self.name, self.store.directories)

    def test_wrong_storage_in_valid_manifest_never_deleted(self):
        previous = rc.CHUNK_SIZE
        try:
            rc.CHUNK_SIZE = 1024
            with tempfile.TemporaryDirectory() as directory:
                tar = Path(directory) / 'test.tar'
                info = Path(directory) / 'test.info.json'
                tar.write_bytes(b'valid tar')
                info.write_bytes(b'{}')
                manifest = make_manifest(self.name, {'tar': tar, 'info': info},
                                         ['wordpress__2'], ['KGW'], 'OMV-other', 'now')
                import json
                self.store.files[self.name+'/pending.json'] = json.dumps(manifest).encode()
                with self.assertRaises(ValueError):
                    delete_partial(self.store, self.name, 'OMV2')
                self.assertIn(self.name+'/tar.000000.part', self.store.files)
        finally:
            rc.CHUNK_SIZE = previous

    def test_invalid_name_and_nested_subfolder_refused(self):
        with self.assertRaises(ValueError):
            delete_partial(self.store, '../other')
        self.store.directories.add(self.name + '/otherdir')
        with self.assertRaises(ValueError):
            delete_partial(self.store, self.name)


if __name__ == '__main__':
    unittest.main()
