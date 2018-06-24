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

from session cimport Session
from sftp_handles cimport SFTPFile, SFTPDir
from utils cimport handle_ssh_error_codes

cimport c_sftp


cdef class SFTPStatVFS:

    def __dealloc__(self):
        if self._stats is not NULL:
            c_sftp.sftp_statvfs_free(self._stats)
            self._stats = NULL


cdef class SFTPAttributes:

    def __dealloc__(self):
        if self._attrs is not NULL:
            c_sftp.sftp_attributes_free(self._attrs)
            self._attrs = NULL


cdef class SFTP:

    @staticmethod
    cdef SFTP from_ptr(c_sftp.sftp_session sftp, Session session):
        cdef SFTP _sftp = SFTP.__new__(SFTP, session)
        _sftp._sftp = sftp
        return _sftp

    def __cinit__(self, Session session):
        self.session = session
        cdef int rc
        with nogil:
            rc = c_sftp.sftp_init(self._sftp)
        handle_ssh_error_codes(rc, self.session._session)

    def __dealloc__(self):
        if self._sftp is not NULL:
            c_sftp.sftp_free(self._sftp)
            self._sftp = NULL

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
        pass

    def extensions_get_data(self, unsigned int indexn):
        pass

    def extension_supported(self, name not None, data not None):
        pass

    def opendir(self, path not None):
        pass

    def stat(self, path not None):
        pass

    def lstat(self, path not None):
        pass

    def open(self, path not None, int accesstype, c_sftp.mode_t mode):
        pass

    def unlink(self, path not None):
        pass

    def rmdir(self, path not None):
        pass

    def mkdir(self, path not None, c_sftp.mode_t mode):
        pass

    def rename(self, original not None, newname not None):
        pass

    def setstat(self, path not None, SFTPAttributes attr):
        pass

    def chown(self, path not None,
              c_sftp.uid_t owner, c_sftp.gid_t group):
        pass

    def chmod(self, path not None, c_sftp.mode_t mode):
        pass

    def utimes(self, path not None, times):
        pass

    def symlink(self, source not None, dest not None):
        pass

    def readlink(self, path not None):
        pass

    def statvfs(self, path not None):
        pass

    def canonicalize_path(self, path not None):
        pass

    def server_version(self):
        pass
