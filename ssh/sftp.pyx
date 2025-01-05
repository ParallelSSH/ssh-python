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

from libc.stdlib cimport malloc, free

from .session cimport Session
from .sftp_handles cimport SFTPFile, SFTPDir
from .sftp_attributes cimport SFTPAttributes
from .sftp_statvfs cimport SFTPStatVFS
from .utils cimport handle_error_codes, to_bytes, to_str
from .exceptions import SFTPError, SFTPHandleError

from .c_ssh cimport ssh_get_error, ssh_get_error_code, timeval
from . cimport c_sftp


cdef class SFTP:

    @staticmethod
    cdef SFTP from_ptr(c_sftp.sftp_session sftp, Session session):
        cdef SFTP _sftp = SFTP.__new__(SFTP)
        _sftp._sftp = sftp
        _sftp.session = session
        return _sftp

    def __dealloc__(self):
        if self._sftp is not NULL:
            c_sftp.sftp_free(self._sftp)
            self._sftp = NULL

    def init(self):
        cdef int rc
        with nogil:
            rc = c_sftp.sftp_init(self._sftp)
        return handle_error_codes(rc, self.session._session)

    def get_error(self):
        cdef int rc
        with nogil:
            rc = c_sftp.sftp_get_error(self._sftp)
        return rc

    def extensions_get_count(self):
        cdef unsigned int rc
        with nogil:
            rc = c_sftp.sftp_extensions_get_count(self._sftp)
        return rc

    def extensions_get_name(self, unsigned int indexn):
        cdef const char *_name
        cdef bytes name = None
        with nogil:
            _name = c_sftp.sftp_extensions_get_name(self._sftp, indexn)
        if _name is not NULL:
            name = _name
        return name

    def extensions_get_data(self, unsigned int indexn):
        cdef const char *_name
        cdef bytes name = None
        with nogil:
            _name = c_sftp.sftp_extensions_get_data(self._sftp, indexn)
        if _name is not NULL:
            name = _name
        return name

    def extension_supported(self, name not None, data not None):
        cdef bint rc
        cdef bytes b_name = to_bytes(name)
        cdef const char *c_name = b_name
        cdef bytes b_data = to_bytes(data)
        cdef const char *c_data = b_data
        with nogil:
            rc = c_sftp.sftp_extension_supported(
                self._sftp, c_name, c_data)
        return bool(rc)

    def opendir(self, path not None):
        cdef SFTPDir _dir
        cdef c_sftp.sftp_dir c_dir
        cdef bytes b_path = to_bytes(path)
        cdef const char *c_path = b_path
        with nogil:
            c_dir = c_sftp.sftp_opendir(self._sftp, c_path)
        if c_dir is NULL:
            raise SFTPHandleError(ssh_get_error(self.session._session))
        _dir = SFTPDir.from_ptr(c_dir, self)
        return _dir

    def stat(self, path not None):
        cdef SFTPAttributes _attrs
        cdef c_sftp.sftp_attributes c_attrs
        cdef bytes b_path = to_bytes(path)
        cdef const char *c_path = b_path
        with nogil:
            c_attrs = c_sftp.sftp_stat(self._sftp, c_path)
        if c_attrs is NULL:
            raise SFTPError(ssh_get_error(self.session._session))
        _attrs = SFTPAttributes.from_ptr(c_attrs, self)
        return _attrs

    def lstat(self, path not None):
        cdef SFTPAttributes _attrs
        cdef c_sftp.sftp_attributes c_attrs
        cdef bytes b_path = to_bytes(path)
        cdef const char *c_path = b_path
        with nogil:
            c_attrs = c_sftp.sftp_lstat(self._sftp, c_path)
        if c_attrs is NULL:
            raise SFTPError(ssh_get_error(self.session._session))
        _attrs = SFTPAttributes.from_ptr(c_attrs, self)
        return _attrs

    def open(self, path not None, int accesstype, c_sftp.mode_t mode):
        cdef bytes b_path = to_bytes(path)
        cdef const char *c_path = b_path
        cdef SFTPFile _file
        cdef c_sftp.sftp_file c_file
        with nogil:
            c_file = c_sftp.sftp_open(self._sftp, c_path, accesstype, mode)
        if c_file is NULL:
            raise SFTPHandleError(ssh_get_error(self.session._session))
        _file = SFTPFile.from_ptr(c_file, self)
        return _file

    def unlink(self, path not None):
        cdef bytes b_path = to_bytes(path)
        cdef const char *c_path = b_path
        cdef int rc
        with nogil:
            rc = c_sftp.sftp_unlink(self._sftp, c_path)
        if rc < 0:
            raise SFTPError(ssh_get_error(self.session._session))
        return rc

    def rmdir(self, path not None):
        cdef bytes b_path = to_bytes(path)
        cdef const char *c_path = b_path
        cdef int rc
        with nogil:
            rc = c_sftp.sftp_rmdir(self._sftp, c_path)
        if rc < 0:
            raise SFTPError(ssh_get_error(self.session._session))
        return rc

    def mkdir(self, path not None, c_sftp.mode_t mode):
        cdef bytes b_path = to_bytes(path)
        cdef const char *c_path = b_path
        cdef int rc
        with nogil:
            rc = c_sftp.sftp_mkdir(self._sftp, c_path, mode)
        return handle_error_codes(rc, self.session._session)

    def rename(self, original not None, newname not None):
        cdef bytes b_orig = to_bytes(original)
        cdef const char *c_orig = b_orig
        cdef bytes b_newname = to_bytes(newname)
        cdef const char *c_newname = b_newname
        cdef int rc
        with nogil:
            rc = c_sftp.sftp_rename(self._sftp, c_orig, c_newname)
        if rc < 0:
            raise SFTPError(ssh_get_error(self.session._session))
        return rc

    def setstat(self, path not None, SFTPAttributes attr):
        cdef bytes b_path = to_bytes(path)
        cdef const char *c_path = b_path
        cdef int rc
        with nogil:
            rc = c_sftp.sftp_setstat(self._sftp, c_path, attr._attrs)
        return handle_error_codes(rc, self.session._session)

    def chown(self, path not None,
              c_sftp.uid_t owner, c_sftp.gid_t group):
        cdef bytes b_path = to_bytes(path)
        cdef const char *c_path = b_path
        cdef int rc
        with nogil:
            rc = c_sftp.sftp_chown(self._sftp, c_path, owner, group)
        if rc < 0:
            raise SFTPError(ssh_get_error(self.session._session))
        return rc

    def chmod(self, path not None, c_sftp.mode_t mode):
        cdef bytes b_path = to_bytes(path)
        cdef const char *c_path = b_path
        cdef int rc
        with nogil:
            rc = c_sftp.sftp_chmod(self._sftp, c_path, mode)
        if rc < 0:
            raise SFTPError(ssh_get_error(self.session._session))
        return rc

    def utimes(self, path not None, long seconds, long microseconds):
        cdef bytes b_path = to_bytes(path)
        cdef const char *c_path = b_path
        cdef int rc
        cdef timeval *_val
        with nogil:
            _val = <timeval *>malloc(sizeof(timeval))
            if _val is NULL:
                with gil:
                    raise MemoryError
            _val.tv_sec = seconds
            _val.tv_usec = microseconds
            rc = c_sftp.sftp_utimes(self._sftp, c_path, _val)
            free(_val)
        if rc < 0:
            raise SFTPError(ssh_get_error(self.session._session))
        return rc

    def symlink(self, source not None, dest not None):
        cdef bytes b_source = to_bytes(source)
        cdef const char *c_source = b_source
        cdef bytes b_dest = to_bytes(dest)
        cdef const char *c_dest = b_dest
        cdef int rc
        with nogil:
            rc = c_sftp.sftp_symlink(self._sftp, c_source, c_dest)
        if rc < 0:
            raise SFTPError(ssh_get_error(self.session._session))
        return rc

    def readlink(self, path not None):
        cdef bytes b_path = to_bytes(path)
        cdef const char *c_path = b_path
        cdef char *_link
        cdef bytes b_link
        with nogil:
            _link = c_sftp.sftp_readlink(self._sftp, c_path)
        if _link is NULL:
            raise SFTPError(ssh_get_error(self.session._session))
        b_link = _link
        return to_str(b_link)

    def statvfs(self, path not None):
        cdef bytes b_path = to_bytes(path)
        cdef const char *c_path = b_path
        cdef SFTPStatVFS vfs
        cdef c_sftp.sftp_statvfs_t c_vfs
        with nogil:
            c_vfs = c_sftp.sftp_statvfs(self._sftp, c_path)
        if c_vfs is NULL:
            raise SFTPError(ssh_get_error(self.session._session))
        vfs = SFTPStatVFS.from_ptr(c_vfs, self)
        return vfs

    def canonicalize_path(self, path not None):
        cdef bytes b_path = to_bytes(path)
        cdef const char *c_path = b_path
        cdef char *_rpath
        cdef bytes b_rpath
        with nogil:
            _rpath = c_sftp.sftp_canonicalize_path(self._sftp, c_path)
        if _rpath is NULL:
            raise SFTPError(ssh_get_error(self.session._session))
        b_rpath = _rpath
        return to_str(b_rpath)

    def server_version(self):
        cdef int rc
        with nogil:
            rc = c_sftp.sftp_server_version(self._sftp)
        return handle_error_codes(rc, self.session._session)
