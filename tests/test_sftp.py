# This file is part of ssh-python.
# Copyright (C) 2018 Panos Kittenis
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation, version 2.1.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-130

import unittest
import os
import platform
import stat
from sys import version_info
import shutil
import socket
from select import select
import time

from ssh.session import Session
from ssh import options
from ssh.sftp import SFTP
from ssh.sftp_handles import SFTPDir, SFTPFile
from ssh.sftp_attributes import SFTPAttributes
from ssh.exceptions import InvalidAPIUse, SFTPHandleError, SFTPError
from ssh.error_codes import SSH_AGAIN
from ssh.helper import wait_socket


from .base_test import SSHTestCase


class SFTPTest(SSHTestCase):

    def test_sftp_init(self):
        self._auth()
        sftp = self.session.sftp_new()
        self.assertIsInstance(sftp, SFTP)
        self.assertEqual(sftp.init(), 0)
        del sftp
        sftp = self.session.sftp_init()
        self.assertIsInstance(sftp, SFTP)

    def test_sftp_fail(self):
        self.assertRaises(InvalidAPIUse, self.session.sftp_new)
        self._auth()
        sftp = self.session.sftp_new()
        self.assertRaises(SFTPHandleError, sftp.opendir, '.')

    def test_sftp_dir(self):
        self._auth()
        sftp = self.session.sftp_new()
        sftp.init()
        _dir = sftp.opendir('.')
        self.assertIsInstance(_dir, SFTPDir)
        self.assertFalse(_dir.eof())
        self.assertEqual(_dir.closedir(), 0)
        # dir handle from context manager
        with sftp.opendir('.') as _dir:
            for attr in _dir:
                self.assertIsInstance(attr, SFTPAttributes)
                self.assertIsNotNone(attr.name)
        self.assertTrue(_dir.eof())

    def test_sftp_readdir(self):
        self._auth()
        sftp = self.session.sftp_new()
        sftp.init()
        with sftp.opendir('.') as _dir:
            attrs = _dir.readdir()
            self.assertIsInstance(attrs, SFTPAttributes)
            self.assertIsNotNone(attrs.uid)
            self.assertIsNotNone(attrs.gid)
            self.assertIsNotNone(attrs.owner)
            self.assertIsNotNone(attrs.group)
            self.assertTrue(attrs.size > 0)
            self.assertTrue(isinstance(attrs.name, bytes))
            self.assertTrue(len(attrs.longname) > 1)
            self.assertFalse(_dir.closed)
            self.assertEqual(_dir.closedir(), 0)
            self.assertTrue(_dir.closed)
        del _dir
        with sftp.opendir('.') as _dir:
            pass
        self.assertTrue(_dir.closed)
        del _dir

    def test_sftp_file_read(self):
        self._auth()
        sftp = self.session.sftp_new()
        sftp.init()
        if int(platform.python_version_tuple()[0]) >= 3:
            test_file_data = b'test' + bytes(os.linesep, 'utf-8')
        else:
            test_file_data = b'test' + os.linesep
        remote_filename = os.sep.join([os.path.dirname(__file__),
                                       'remote_test_file'])
        with open(remote_filename, 'wb') as test_fh:
            test_fh.write(test_file_data)
        try:
            with sftp.open(remote_filename, os.O_RDONLY, 0) as remote_fh:
                self.assertIsInstance(remote_fh, SFTPFile)
                remote_data = b""
                for rc, data in remote_fh:
                    remote_data += data
                self.assertFalse(remote_fh.closed)
                self.assertEqual(remote_fh.close(), 0)
                self.assertTrue(remote_fh.closed)
                self.assertEqual(remote_data, test_file_data)
            self.assertTrue(remote_fh.closed)
            del remote_fh
            with sftp.open(remote_filename, os.O_RDONLY, 0) as remote_fh:
                pass
            self.assertTrue(remote_fh.closed)
        finally:
            os.unlink(remote_filename)

    def test_sftp_write(self):
        self._auth()
        sftp = self.session.sftp_new()
        sftp.init()
        data = b"test file data"
        remote_filename = os.sep.join([os.path.dirname(__file__),
                                       "remote_test_file"])
        mode = int("0666") if version_info <= (2,) else 0o666
        with sftp.open(remote_filename,
                       os.O_CREAT | os.O_WRONLY,
                       mode) as remote_fh:
            remote_fh.write(data)
        with open(remote_filename, 'rb') as fh:
            written_data = fh.read()
        _stat = os.stat(remote_filename)
        try:
            self.assertEqual(stat.S_IMODE(_stat.st_mode), 420)
            self.assertTrue(fh.closed)
            self.assertEqual(data, written_data)
        except Exception:
            raise
        finally:
            os.unlink(remote_filename)

    def test_sftp_attrs_cls(self):
        attrs = SFTPAttributes.new_attrs(None)
        self.assertIsInstance(attrs, SFTPAttributes)
        self.assertEqual(attrs.uid, 0)
        self.assertEqual(attrs.gid, 0)
        attrs.flags = 1
        attrs.type = 2
        attrs.size = 3
        attrs.uid = 4
        attrs.gid = 5
        attrs.permissions = 6
        attrs.atime64 = 7
        attrs.atime = 8
        attrs.atime_nseconds = 9
        attrs.createtime = 10
        attrs.createtime_nseconds = 11
        attrs.mtime64 = 12
        attrs.mtime = 13
        attrs.mtime_nseconds = 14
        attrs.extended_count = 15
        self.assertEqual(attrs.flags, 1)
        self.assertEqual(attrs.type, 2)
        self.assertEqual(attrs.size, 3)
        self.assertEqual(attrs.uid, 4)
        self.assertEqual(attrs.gid, 5)
        self.assertEqual(attrs.permissions, 6)
        self.assertEqual(attrs.atime64, 7)
        self.assertEqual(attrs.atime, 8)
        self.assertEqual(attrs.atime_nseconds, 9)
        self.assertEqual(attrs.createtime, 10)
        self.assertEqual(attrs.createtime_nseconds, 11)
        self.assertEqual(attrs.mtime64, 12)
        self.assertEqual(attrs.mtime, 13)
        self.assertEqual(attrs.mtime_nseconds, 14)
        self.assertEqual(attrs.extended_count, 15)
        del attrs

    def test_sftp_stat(self):
        self._auth()
        sftp = self.session.sftp_init()
        self.assertIsInstance(sftp, SFTP)
        test_data = b"data"
        remote_filename = os.sep.join([os.path.dirname(__file__),
                                       "remote_test_file"])
        with open(remote_filename, 'wb') as fh:
            fh.write(test_data)
        _mask = int('0644') if version_info <= (2,) else 0o644
        os.chmod(remote_filename, _mask)
        _size = os.stat(remote_filename).st_size
        try:
            attrs = sftp.stat(remote_filename)
            self.assertTrue(isinstance(attrs, SFTPAttributes))
            self.assertEqual(attrs.uid, os.getuid())
            self.assertEqual(attrs.gid, os.getgid())
            self.assertEqual(stat.S_IMODE(attrs.permissions), 420)
            self.assertTrue(attrs.atime > 0)
            self.assertTrue(attrs.mtime > 0)
            self.assertTrue(attrs.flags > 0)
            self.assertEqual(attrs.size, _size)
        except Exception:
            raise
        finally:
            os.unlink(remote_filename)
        self.assertRaises(SFTPError, sftp.stat, remote_filename)
        self.assertNotEqual(sftp.get_error(), 0)

    def test_sftp_fstat(self):
        self._auth()
        sftp = self.session.sftp_init()
        self.assertTrue(sftp is not None)
        test_data = b"data"
        remote_filename = os.sep.join([os.path.dirname(__file__),
                                       "remote_test_file"])
        with open(remote_filename, 'wb') as fh:
            fh.write(test_data)
        try:
            with sftp.open(remote_filename, 0, 0) as fh:
                attrs = fh.fstat()
                self.assertTrue(isinstance(attrs, SFTPAttributes))
                self.assertEqual(attrs.uid, os.getuid())
                self.assertEqual(attrs.gid, os.getgid())
                self.assertTrue(attrs.flags > 0)
        except Exception:
            raise
        finally:
            os.unlink(remote_filename)

    def test_sftp_setstat(self):
        self._auth()
        sftp = self.session.sftp_init()
        self.assertTrue(sftp is not None)
        test_data = b"data"
        remote_filename = os.sep.join([os.path.dirname(__file__),
                                       "remote_test_file"])
        with open(remote_filename, 'wb') as fh:
            fh.write(test_data)
        _mask = int('0644') if version_info <= (2,) else 0o644
        os.chmod(remote_filename, _mask)
        attrs = sftp.stat(remote_filename)
        attrs.permissions = int("0400") if version_info <= (2,) else 0o400
        try:
            self.assertEqual(sftp.setstat(remote_filename, attrs), 0)
            attrs = sftp.stat(remote_filename)
            self.assertEqual(attrs.permissions, 33024)
        except Exception:
            raise
        finally:
            os.unlink(remote_filename)

    def test_canonicalize_path(self):
        self._auth()
        sftp = self.session.sftp_init()
        self.assertTrue(sftp is not None)
        self.assertIsNotNone(sftp.canonicalize_path('.'))

    def test_sftp_symlink_realpath_lstat(self):
        self._auth()
        sftp = self.session.sftp_init()
        self.assertTrue(sftp is not None)
        test_data = b"data"
        remote_filename = os.sep.join([os.path.dirname(__file__),
                                       "remote_test_file"])
        with open(remote_filename, 'wb') as fh:
            fh.write(test_data)
        symlink_target = os.sep.join([os.path.dirname(__file__),
                                      'remote_symlink'])
        try:
            self.assertEqual(sftp.symlink(remote_filename, symlink_target), 0)
            lstat = sftp.lstat(symlink_target)
            self.assertTrue(lstat is not None)
            self.assertEqual(lstat.size, os.lstat(symlink_target).st_size)
            realpath = sftp.canonicalize_path(symlink_target)
            self.assertTrue(realpath is not None)
            self.assertEqual(realpath, remote_filename)
        except Exception:
            raise
        finally:
            os.unlink(symlink_target)
            os.unlink(remote_filename)

    def test_readdir(self):
        self._auth()
        sftp = self.session.sftp_init()
        dir_data = [_dir for _dir in sftp.opendir('.')]
        self.assertTrue(len(dir_data) > 0)
        self.assertTrue(b'.' in (_ls.name for _ls in dir_data))
        self.assertTrue(b'..' in (_ls.name for _ls in dir_data))

    def test_readdir_failure(self):
        self._auth()
        sftp = self.session.sftp_init()
        self.assertRaises(SFTPError, sftp.opendir, 'fakeyfakey')

    def test_fsync(self):
        self._auth()
        sftp = self.session.sftp_init()
        test_data = b"data"
        remote_filename = os.sep.join([os.path.dirname(__file__),
                                       "remote_test_file"])
        with open(remote_filename, 'wb') as fh:
            fh.write(test_data)
        try:
            with sftp.open(remote_filename, 0, 0) as fh:
                self.assertEqual(fh.fsync(), 0)
        except Exception:
            raise
        finally:
            os.unlink(remote_filename)

    def test_statvfs(self):
        self._auth()
        sftp = self.session.sftp_init()
        vfs = sftp.statvfs('.')
        self.assertTrue(vfs is not None)
        self.assertTrue(vfs.f_files > 0)
        self.assertTrue(vfs.f_bsize > 0)
        self.assertTrue(vfs.f_namemax > 0)

    def test_fstatvfs(self):
        self._auth()
        sftp = self.session.sftp_init()
        test_data = b"data"
        remote_filename = os.sep.join([os.path.dirname(__file__),
                                       "remote_test_file"])
        with open(remote_filename, 'wb') as fh:
            fh.write(test_data)
        try:
            with sftp.open(remote_filename, 0, 0) as fh:
                vfs = fh.fstatvfs()
                self.assertTrue(vfs is not None)
                self.assertTrue(vfs.f_files > 0)
                self.assertTrue(vfs.f_bsize > 0)
                self.assertTrue(vfs.f_namemax > 0)
        except Exception:
            raise
        finally:
            os.unlink(remote_filename)

    def test_mkdir(self):
        mode = int("0644") if version_info <= (2,) else 0o644
        _path = 'tmp'
        abspath = os.path.join(os.path.expanduser('~'), _path)
        self._auth()
        sftp = self.session.sftp_init()
        try:
            shutil.rmtree(abspath)
        except OSError:
            pass
        sftp.mkdir(_path, mode)
        try:
            self.assertTrue(os.path.isdir(abspath))
        finally:
            shutil.rmtree(abspath)

    def test_handle_open_nonblocking(self):
        self._auth()
        sftp = self.session.sftp_init()
        self.session.set_blocking(False)
        fh = sftp.open('.', 0, 0)
        self.assertIsInstance(fh, SFTPFile)
        fh.set_nonblocking()
        fh.close()

    # def test_async_read(self):
    #     sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     sock.connect((self.host, self.port))
    #     self.session = Session()
    #     self.session.options_set(options.USER, self.user)
    #     self.session.options_set(options.HOST, self.host)
    #     self.session.options_set_port(self.port)
    #     self.assertEqual(self.session.set_socket(sock), 0)
    #     self.assertEqual(self.session.connect(), 0)
    #     self.assertEqual(self.session.userauth_publickey(self.pkey), 0)
    #     sftp = self.session.sftp_new()
    #     sftp.init()
    #     if int(platform.python_version_tuple()[0]) >= 3:
    #         test_file_data = b'test' + bytes(os.linesep, 'utf-8')
    #     else:
    #         test_file_data = b'test' + os.linesep
    #     remote_filename = os.sep.join([os.path.dirname(__file__),
    #                                    'remote_test_file'])
    #     with open(remote_filename, 'wb') as test_fh:
    #         test_fh.write(test_file_data)
    #     # self.session.set_blocking(False)
    #     try:
    #         with sftp.open(remote_filename, os.O_RDONLY, 0) as remote_fh:
    #             self.assertIsInstance(remote_fh, SFTPFile)
    #             remote_fh.set_nonblocking()
    #             remote_data = b""
    #             async_id = remote_fh.async_read_begin()
    #             self.assertNotEqual(async_id, 0)
    #             import ipdb; ipdb.set_trace()
    #             size, data = remote_fh.async_read(async_id)
    #             while size > 0 or size == SSH_AGAIN:
    #                 if size == SSH_AGAIN:
    #                     print("Would try again")
    #                     wait_socket(sock, self.session, timeout=1)
    #                     size, data = remote_fh.async_read(async_id)
    #                     continue
    #                 remote_data += data
    #                 size, data = remote_fh.async_read(async_id)
    #             self.assertFalse(remote_fh.closed)
    #             self.assertEqual(remote_fh.close(), 0)
    #             self.assertTrue(remote_fh.closed)
    #             self.assertEqual(remote_data, test_file_data)
    #         self.assertTrue(remote_fh.closed)
    #     finally:
    #         os.unlink(remote_filename)
