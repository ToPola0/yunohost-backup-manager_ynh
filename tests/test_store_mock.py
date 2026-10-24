"""Check adapter operations without external SMB or network connections."""
import contextlib
import io
import pathlib
import stat
import sys
import tempfile
import types
import unittest

sys.modules.setdefault('smbclient', types.ModuleType('smbclient'))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]/'sources'))
import resumable_chunks as rc

class FakeSMB:
    def __init__(self):
        self.files = {}
        self.dirs = set()
        self.sessions = []
        self.main = None
        self.install_fake()

    @staticmethod
    def normalize(p):
        return str(p).replace('\\', '/').replace('//', '/')

    def install_fake(self):
        self.main = sys.modules['smbclient']
        for method in ('register_session','delete_session','listdir','stat','mkdir','open_file','remove','rmdir'):
            setattr(self.main, method, getattr(self, method))

    def register_session(self, server, username, password, port, connection_timeout, connection_cache):
        self.sessions.append((server, port, username))

    def delete_session(self, *a, **kw):
        pass

    def listdir(self, root, **kw):
        root = self.normalize(root).rstrip('/')
        if root not in self.dirs:
            raise FileNotFoundError(root)
        names = set()
        for entry in self.dirs | set(self.files):
            if entry.startswith(root+'/'):
                following = entry[len(root)+1:]
                if '/' not in following:
                    names.add(following)
        return sorted(names)

    def stat(self, path, **kw):
        p = self.normalize(path)
        if p in self.dirs:
            return types.SimpleNamespace(st_size=0, st_mode=stat.S_IFDIR)
        return types.SimpleNamespace(st_size=len(self.files[p]), st_mode=stat.S_IFREG)

    def mkdir(self, path, **kw):
        self.dirs.add(self.normalize(path))

    class FakeFile(io.BytesIO):
        def __init__(self, store, key, mode):
            self.store, self.key, self.mode = store, key, mode
            super().__init__(store.get(key, b'') if 'r' in mode else b'')
        def close(self):
            if 'w' in self.mode:
                self.store[self.key] = self.getvalue()
            super().close()

    def open_file(self, path, mode, **kw):
        return self.FakeFile(self.files, self.normalize(path), mode)

    def remove(self, path, **kw):
        del self.files[self.normalize(path)]

    def rmdir(self, path, **kw):
        self.dirs.remove(self.normalize(path))


class ModernStoreTest(unittest.TestCase):
    def test_modern_read_write_and_directory(self):
        stub = FakeSMB()
        stub.dirs.update(['/127.0.0.1/Archiwum','/127.0.0.1/Archiwum/yunohost'])
        cfg = {'server':'100.85.178.100', 'username':'test','password':'secret',
               'share':'Archiwum','subdirectory':'yunohost','domain':''}
        @contextlib.contextmanager
        def endpoint(_):
            yield types.SimpleNamespace(host='127.0.0.1',port=44529)
        with rc.SMBStore(cfg,'smb2',endpoint,None,None,lambda *a: None) as store:
            self.assertEqual(store.listing(), {})
            store.ensure_directory('ybm_TEST')
            self.assertIn('ybm_TEST',store.listing())
            with tempfile.TemporaryDirectory() as d:
                local=pathlib.Path(d)/'file.bin'
                local.write_bytes(b'abc'*2000)
                with rc.LimitedReader(local,0,local.stat().st_size) as reader:
                    store.stream_write('ybm_TEST/tar.000000.part',reader,local.stat().st_size)
                self.assertTrue(rc.chunks_match(store,'ybm_TEST/tar.000000.part',local.stat().st_size,
                                                rc.local_chunk_hash(local,0,local.stat().st_size)))
            store.write_small('ybm_TEST/report.json',b'{"verified":true}')
            self.assertEqual(store.read_small('ybm_TEST/report.json',1024),b'{"verified":true}')
            store.remove('ybm_TEST/report.json')
            store.remove('ybm_TEST/tar.000000.part')
            store.remove_dir('ybm_TEST')
        self.assertEqual(stub.sessions[0][1],44529)

class FakeLegacyConn:
    def __init__(self):
        self.files={}
        self.directories={'/','/yunohost'}

    def listPath(self, share, path, timeout=60):
        parent=path.rstrip('/') or '/'
        if parent not in self.directories:
            raise FileNotFoundError(parent)
        names=set()
        for entry in self.directories | set(self.files):
            if entry.startswith(parent.rstrip('/')+'/'):
                rest=entry[len(parent.rstrip('/'))+1:]
                if rest and '/' not in rest:names.add(rest)
        return [types.SimpleNamespace(filename=n,file_size=len(self.files.get(parent.rstrip('/')+'/'+n,b'')),
                                      isDirectory=(parent.rstrip('/')+'/'+n) in self.directories) for n in sorted(names)]

    def createDirectory(self,share,path,timeout):
        self.directories.add(path)

    def storeFile(self,share,path,reader,timeout):
        data=b''
        while block:=reader.read(301):data+=block
        self.files[path]=data

    def retrieveFile(self,share,path,writer,timeout):
        data=self.files[path]
        for off in range(0,len(data),201):writer.write(data[off:off+201])

    def deleteFiles(self,share,path,timeout):
        del self.files[path]

    def deleteDirectory(self,share,path,timeout):
        self.directories.remove(path)

    def close(self):pass


class LegacyStoreTest(unittest.TestCase):
    def test_smb1_roundtrip(self):
        conn=FakeLegacyConn()
        cfg={'server':'100.85.178.100','username':'test','password':'secret',
             'share':'Archiwum','subdirectory':'yunohost','domain':''}
        @contextlib.contextmanager
        def endpoint(_):yield types.SimpleNamespace(host='127.0.0.1',port=45011)
        with rc.SMBStore(cfg,'smb1',endpoint,lambda *a:conn,lambda *a:None,None) as s:
            s.ensure_directory('ybm_test')
            self.assertTrue(s.listing()['ybm_test'].directory)
            with tempfile.TemporaryDirectory() as d:
                file=pathlib.Path(d)/'part.bin';file.write_bytes(b'hello'*1000)
                with rc.LimitedReader(file,0,file.stat().st_size) as f:
                    s.stream_write('ybm_test/tar.000000.part',f,file.stat().st_size)
                self.assertTrue(rc.chunks_match(s,'ybm_test/tar.000000.part',file.stat().st_size,
                                                rc.local_chunk_hash(file,0,file.stat().st_size)))
            s.write_small('ybm_test/report.json',b'confirmed')
            self.assertEqual(s.read_small('ybm_test/report.json',100),b'confirmed')
            s.remove('ybm_test/report.json')
            s.remove('ybm_test/tar.000000.part')
            s.remove_dir('ybm_test')


if __name__ == "__main__":
    unittest.main()
