"""Read-only recursive FTP/SFTP -> flattened R2 image sync.

Source files must be named <model><color>.<image-extension>, with 8-18 digits
before the extension. Duplicate identifiers are skipped, not overwritten.
"""
import datetime as dt
import ftplib
import hashlib
import io
import logging
import os
import posixpath
import re
import stat
import sys
from contextlib import contextmanager
from typing import Iterator

import boto3
import paramiko

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
LOG = logging.getLogger('sync')
FILE = re.compile(r'^(\d{8,18})\.(jpg|jpeg|png|webp|gif)$', re.I)
MIME = {'jpg':'image/jpeg','jpeg':'image/jpeg','png':'image/png','webp':'image/webp','gif':'image/gif'}
MAX_BYTES = int(os.getenv('MAX_IMAGE_BYTES', str(15*1024*1024)))


def env(name, default=None):
    val = os.getenv(name, default)
    if val is None or val == '':
        raise ValueError(f'Missing environment variable: {name}')
    return val


@contextmanager
def source():
    scheme = env('SOURCE_PROTOCOL').lower()
    host, user, password = env('SOURCE_HOST'), env('SOURCE_USER'), os.getenv('SOURCE_PASSWORD')
    port = int(os.getenv('SOURCE_PORT', '22' if scheme == 'sftp' else '21'))
    if scheme == 'ftp':
        if not password:
            raise ValueError('SOURCE_PASSWORD is required for FTP')
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=30)
        ftp.login(user, password)
        ftp.set_pasv(True)
        try: yield FTPSource(ftp)
        finally:
            try: ftp.quit()
            except Exception: ftp.close()
    elif scheme == 'sftp':
        transport = paramiko.Transport((host, port))
        transport.start_client(timeout=30)
        # Validate server identity BEFORE sending any authentication credentials.
        import base64
        fingerprint = env('SOURCE_SSH_SHA256')
        actual = base64.b64encode(hashlib.sha256(transport.get_remote_server_key().asbytes()).digest()).decode().rstrip('=')
        if actual != fingerprint.removeprefix('SHA256:').rstrip('='):
            transport.close()
            raise ValueError('SFTP host key fingerprint mismatch')
        if os.getenv('SOURCE_SSH_KEY_B64'):
            import base64
            key_text = base64.b64decode(env('SOURCE_SSH_KEY_B64')).decode()
            key_obj = None
            for cls in [paramiko.Ed25519Key,paramiko.RSAKey,paramiko.ECDSAKey]:
                try: key_obj=cls.from_private_key(io.StringIO(key_text)); break
                except (paramiko.SSHException, ValueError): continue
            if not key_obj: raise ValueError('Unsupported SSH private key')
            transport.auth_publickey(user,key_obj)
        else:
            if not password: raise ValueError('SOURCE_PASSWORD or SOURCE_SSH_KEY_B64 required')
            transport.auth_password(user,password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        try: yield SFTPSource(sftp)
        finally: sftp.close(); transport.close()
    else: raise ValueError('SOURCE_PROTOCOL must be ftp or sftp')


class FTPSource:
    def __init__(self,client):self.client=client
    def files(self,root):
        stack=[root]
        while stack:
            folder=stack.pop()
            for name, facts in self.client.mlsd(folder):
                if name in ('.','..'):continue
                path=posixpath.join(folder,name)
                if facts.get('type')=='dir':stack.append(path)
                elif facts.get('type')=='file':
                    yield path,int(facts.get('size',-1)),facts.get('modify','')
    def read(self,path):
        chunks=[];size=0
        def receive(chunk):
            nonlocal size
            size+=len(chunk)
            if size>MAX_BYTES:raise ValueError('File too large')
            chunks.append(chunk)
        self.client.retrbinary('RETR '+path,receive)
        return b''.join(chunks)


class SFTPSource:
    def __init__(self,client):self.client=client
    def files(self,root):
        stack=[root]
        while stack:
            folder=stack.pop()
            for entry in self.client.listdir_attr(folder):
                path=posixpath.join(folder,entry.filename)
                if stat.S_ISDIR(entry.st_mode):stack.append(path)
                elif stat.S_ISREG(entry.st_mode):yield path,entry.st_size,str(entry.st_mtime)
    def read(self,path):
        with self.client.open(path,'rb') as f:
            data=f.read(MAX_BYTES+1)
            if len(data)>MAX_BYTES:raise ValueError('File too large')
            return data


def verify_signature(data,extension):
    if extension in ('jpg','jpeg'): return data.startswith(b'\xff\xd8\xff')
    if extension=='png':return data.startswith(b'\x89PNG\r\n\x1a\n')
    if extension=='gif':return data[:3]==b'GIF'
    if extension=='webp':return data[:4]==b'RIFF' and data[8:12]==b'WEBP'
    return False


def main():
    r2=boto3.client('s3',endpoint_url=f"https://{env('R2_ACCOUNT_ID')}.r2.cloudflarestorage.com",aws_access_key_id=env('R2_ACCESS_KEY_ID'),aws_secret_access_key=env('R2_SECRET_ACCESS_KEY'),region_name='auto')
    bucket=os.getenv('R2_BUCKET','shoham-images')
    root=env('SOURCE_PATH','/')
    dry_run=os.getenv('DRY_RUN','true').lower()=='true'
    seen={};uploaded=unchanged=skipped=duplicate=failed=0
    with source() as src:
        for path,size,modified in src.files(root):
            m=FILE.fullmatch(posixpath.basename(path))
            if not m or size>MAX_BYTES or size==0: skipped+=1;continue
            key,ext=m.group(1),m.group(2).lower()
            if key in seen:
                duplicate+=1
                LOG.warning('DUPLICATE id=%s sources=%s and %s - requires resolution',key,seen[key],path)
                # If a duplicate is detected later, previous copy may already have been uploaded.
                # Preflight entire inventory below is preferred: sync runner gathers all entries first.
                continue
            seen[key]=path
        LOG.info('Inventory valid=%d duplicate_entries=%d skipped=%d',len(seen),duplicate,skipped)
        # Re-scan to collect ALL duplicate IDs and ensure neither copy is uploaded.
        duplicates=set();checked=set()
        for path,size,modified in src.files(root):
            m=FILE.fullmatch(posixpath.basename(path))
            if not m or size>MAX_BYTES or size==0:continue
            key=m.group(1)
            if key in checked:duplicates.add(key)
            checked.add(key)
        for path,size,modified in src.files(root):
            m=FILE.fullmatch(posixpath.basename(path))
            if not m or size<=0 or size>MAX_BYTES:continue
            key,extension=m.group(1),m.group(2).lower()
            if key in duplicates:continue
            meta={'source-path-sha256':hashlib.sha256(path.encode()).hexdigest(),'source-size':str(size),'source-mtime':modified or 'unknown'}
            try:
                try:
                    existing=r2.head_object(Bucket=bucket,Key=key)
                    old=existing.get('Metadata',{})
                    if all(old.get(k)==v for k,v in meta.items()):unchanged+=1;continue
                except r2.exceptions.ClientError as exc:
                    if exc.response['ResponseMetadata']['HTTPStatusCode']!=404:raise
                if dry_run:
                    LOG.info('DRY RUN would upload %s -> %s',path,key)
                    continue
                data=src.read(path)
                if not verify_signature(data,extension):raise ValueError('Image signature mismatch')
                r2.put_object(Bucket=bucket,Key=key,Body=data,ContentType=MIME[extension],Metadata=meta,CacheControl='public,max-age=300')
                uploaded+=1
                LOG.info('Uploaded id=%s from=%s',key,path)
            except Exception as exc:
                failed+=1;LOG.error('Failed id=%s: %s',key,exc)
    LOG.info('DONE uploaded=%d unchanged=%d skipped=%d duplicates=%d failed=%d dry_run=%s',uploaded,unchanged,skipped,duplicate,failed,dry_run)
    if failed:sys.exit(1)

if __name__=='__main__':main()
