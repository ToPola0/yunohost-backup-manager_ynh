"""Offline integration tests: rotation NEVER deletes unrelated or unfinished copies."""
import ast
import hashlib
import json
import sqlite3
import tempfile
from contextlib import contextmanager
from pathlib import Path
import threading
import unittest

from test_chunked import FakeStore
import resumable_chunks as rc

SOURCE = (Path(__file__).resolve().parents[1] / 'sources' / 'app.py').read_text()
FUNCTIONS = {node.name: node for node in ast.parse(SOURCE).body if isinstance(node, ast.FunctionDef)}


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.store = FakeStore()
        self.old_size = rc.CHUNK_SIZE
        rc.CHUNK_SIZE = 1024
        self.s1, self.s2 = 'a'*32, 'b'*32
        self.work = tempfile.TemporaryDirectory()
        self.dir = Path(self.work.name)
        self.names = []

        @contextmanager
        def open_store(*args):
            yield self.store

        g = {
            'json': json, 're': __import__('re'), 'SMB_LOCK': threading.RLock(),
            'read_manifest': rc.read_manifest,
            'verified_report': rc.verified_report,
            'safe_remove_complete': rc.safe_remove_complete,
            'validate_name': rc.validate_name,
            'chunk_dialect': lambda cfg: cfg.get('protocol','smb2'),
            'open_chunk_store': open_store,
        }
        fragment = ast.Module(body=[FUNCTIONS['choose_retention_victims'], FUNCTIONS['prune_scheduled_backups']], type_ignores=[])
        exec(compile(ast.fix_missing_locations(fragment), '<retention_functions>', 'exec'), g)
        self.choose = g['choose_retention_victims']
        self.prune = g['prune_scheduled_backups']

    def tearDown(self):
        rc.CHUNK_SIZE = self.old_size
        self.work.cleanup()

    def backup(self, id_suffix, owner, complete=True, corrupt=False):
        name = f'ybm_Test_20261024_{id_suffix}_abcdef'
        tar, info = self.dir/(name+'.tar'), self.dir/(name+'.info.json')
        tar.write_bytes(b'hello!'*250)
        info.write_bytes(b'{"ok":true}')
        files = {'tar':tar,'info':info}
        manifest = rc.make_manifest(name, files, ['wordpress'], ['Test'], 'OMV2', '2026-10-24')
        if owner:
            manifest['schedule_id'] = owner
        rc.synchronize_chunks(self.store,name,files,manifest)
        for role, path in files.items():
            manifest['files'][role]['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        report = {'archive':name,'status':'verified'}
        if owner:
            report['schedule_id'] = owner
        report_data = json.dumps(report).encode()
        self.store.write_small(name+'/report.json', report_data)
        manifest['report_sha256'] = hashlib.sha256(report_data).hexdigest()
        manifest['completed_at'] = '2026-10-24T'+id_suffix[:2]+':00:00+00:00'
        rc.save_manifest(self.store,name,manifest,finished=True)
        if corrupt:
            self.store.files[name+'/report.json'] = b'bad report'
        if not complete:
            self.store.remove(name+'/complete.json')
        self.names.append(name)
        return name

    def test_keep_two_only_same_schedule(self):
        a=self.backup('100000', self.s1)
        b=self.backup('110000', self.s1)
        c=self.backup('120000', self.s1)
        d=self.backup('130000', self.s1)
        other=self.backup('140000', self.s2)
        manual=self.backup('150000', None)
        partial=self.backup('160000', self.s1, complete=False)
        corrupted=self.backup('170000', self.s1, corrupt=True)
        self.assertEqual(self.prune({'protocol':'smb2'},self.s1,2,d),2)
        for deleted in (a,b):
            self.assertNotIn(deleted,self.store.directories)
        for protected in (c,d,other,manual,partial,corrupted):
            self.assertIn(protected,self.store.directories)
        self.assertEqual(self.prune({'protocol':'smb2'},self.s1,2,d),0)

    def test_keeps_new_backup_even_if_clock_older(self):
        latest=self.backup('090000',self.s1)
        old=self.backup('180000',self.s1)
        self.assertEqual(self.prune({'protocol':'smb2'},self.s1,1,latest),1)
        self.assertIn(latest,self.store.directories)
        self.assertNotIn(old,self.store.directories)

    def test_bails_if_new_backup_not_verified(self):
        old=self.backup('100000',self.s1)
        bad=self.backup('200000',self.s1,complete=False)
        with self.assertRaises(RuntimeError):
            self.prune({'protocol':'smb2'},self.s1,1,bad)
        self.assertIn(old,self.store.directories)

    def test_unknown_files_prevent_deletion(self):
        old=self.backup('100000',self.s1)
        current=self.backup('110000',self.s1)
        self.store.files[old+'/keep-me.txt'] = b'DO NOT DELETE'
        with self.assertRaises(RuntimeError):
            self.prune({'protocol':'smb2'},self.s1,1,current)
        self.assertIn(old,self.store.directories)
        self.assertIn(old+'/complete.json',self.store.files)

    def test_smb1_retention_without_system_changes(self):
        old=self.backup('100000',self.s1)
        current=self.backup('110000',self.s1)
        self.assertEqual(self.prune({'protocol':'smb1'},self.s1,1,current),1)
        self.assertNotIn(old,self.store.directories)

    def test_sqlite_migration_preserves_prior_schedules(self):
        con=sqlite3.connect(':memory:')
        con.execute('CREATE TABLE harmonogramy (id TEXT PRIMARY KEY, name TEXT NOT NULL, cron TEXT NOT NULL, storage_id TEXT NOT NULL, apps_json TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, last_slot TEXT, last_run TEXT, last_result TEXT DEFAULT "Nie uruchomiono")')
        con.execute('INSERT INTO harmonogramy (id,name,cron,storage_id,apps_json) VALUES (?,?,?,?,?)',('one','test','0 2 * * *','OMV2','["wordpress"]'))
        con.execute('ALTER TABLE harmonogramy ADD COLUMN keep_count INTEGER NOT NULL DEFAULT 0')
        self.assertEqual(con.execute('SELECT name,keep_count FROM harmonogramy WHERE id="one"').fetchone(),('test',0))
        con.close()


if __name__=='__main__':
    unittest.main()

class RetentionScheduleValidationTests(unittest.TestCase):
    def test_keep_count_validation_bounds(self):
        import re
        ns = {'re': re,'json':json,
              'CronSpec':lambda expression: expression or (_ for _ in ()).throw(ValueError('empty cron')),
              'db_connect':lambda: self.fake_db(),
              'actual_apps':lambda:[{'id':'wordpress'}]}
        fragment = ast.Module(body=[FUNCTIONS['validate_schedule']],type_ignores=[])
        exec(compile(ast.fix_missing_locations(fragment),'<validation>','exec'),ns)
        validate = ns['validate_schedule']
        for keep in (0,1,3,365):
            data={'name':'Nocny backup','cron':'0 2 * * *','storage':'OMV2',
                  'apps':['wordpress'],'enabled':True,'keep_count':keep}
            self.assertEqual(validate(data)[-1],keep)
        for keep in (-1,366,'3',3.5,None,True):
            with self.assertRaises(ValueError):
                validate({'name':'Nocny backup','cron':'0 2 * * *','storage':'OMV2',
                          'apps':['wordpress'],'enabled':True,'keep_count':keep})

    @staticmethod
    def fake_db():
        class FakeDB:
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def execute(self,*args):return self
            def fetchone(self):return (1,)
        return FakeDB()
