"""Opt-in owner-private cache. Integrity hashes are not signed authenticity."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
from .decision_types import canonical_json


class DecisionCache:
    def __init__(self, root: Path):
        self.root = Path(root).absolute()
        for p in (self.root,*self.root.parents):
            if p.is_symlink():
                raise ValueError('cache_symlink')
            if (p/'.git').exists():
                raise ValueError('cache_inside_repository')
        self.root.mkdir(mode=0o700,parents=True,exist_ok=True)
        fd=self._open_root()
        os.close(fd)

    def _open_root(self):
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        st=os.fstat(fd)
        if st.st_uid != os.getuid() or st.st_mode & 0o077:
            os.close(fd)
            raise ValueError('cache_not_private')
        return fd

    @staticmethod
    def _name(key):
        if not isinstance(key,str) or not re.fullmatch('[0-9a-f]{64}',key):
            raise ValueError('cache_key')
        return key+'.json'

    def get(self,key: str) -> dict | None:
        name=self._name(key)
        root=self._open_root()
        try:
            try:fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=root)
            except FileNotFoundError:return None
            with os.fdopen(fd,'rb') as f:
                st=os.fstat(f.fileno())
                if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
                    raise ValueError('cache_file_not_private')
                raw=f.read(262145)
            if len(raw)>262144:
                raise ValueError('cache_size')
            try:
                data=json.loads(raw)
                if data.get('schema') != 'jev-cache-v1' or data.get('key') != key:
                    raise ValueError('cache_identity')
                value=data['value']
                if data.get('digest') != hashlib.sha256(canonical_json(value)).hexdigest():
                    raise ValueError('cache_digest')
                if type(value) is not dict:
                    raise ValueError('cache_value')
                return value
            except (KeyError,TypeError,AttributeError,json.JSONDecodeError):
                raise ValueError('cache_invalid') from None
        finally:
            os.close(root)

    def put(self,key: str,receipt: dict) -> None:
        name=self._name(key)
        raw=canonical_json({'schema':'jev-cache-v1','key':key,'value':receipt,
                            'digest':hashlib.sha256(canonical_json(receipt)).hexdigest()})
        if len(raw)>262144:raise ValueError('cache_size')
        root=self._open_root();temp='.'+uuid.uuid4().hex
        try:
            try:
                st=os.stat(name,dir_fd=root,follow_symlinks=False)
            except FileNotFoundError:pass
            else:
                if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
                    raise ValueError('cache_file_not_private')
            fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=root)
            with os.fdopen(fd,'wb') as f:
                f.write(raw);f.flush();os.fsync(f.fileno())
            os.replace(temp,name,src_dir_fd=root,dst_dir_fd=root)
            os.fsync(root)
        finally:
            try:os.unlink(temp,dir_fd=root)
            except FileNotFoundError:pass
            os.close(root)
