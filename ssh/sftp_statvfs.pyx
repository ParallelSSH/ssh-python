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

from .sftp cimport SFTP

from . cimport c_sftp


cdef class SFTPStatVFS:

    def __dealloc__(self):
        if self._stats is not NULL:
            c_sftp.sftp_statvfs_free(self._stats)
            self._stats = NULL

    @staticmethod
    cdef SFTPStatVFS from_ptr(c_sftp.sftp_statvfs_t stats, SFTP sftp):
        cdef SFTPStatVFS _vfs = SFTPStatVFS.__new__(SFTPStatVFS)
        _vfs._stats = stats
        _vfs.sftp = sftp
        return _vfs

    @property
    def f_bsize(self):
        return self._stats.f_bsize if self._stats is not NULL else None

    @property
    def f_frsize(self):
        return self._stats.f_frsize if self._stats is not NULL else None

    @property
    def f_blocks(self):
        return self._stats.f_blocks if self._stats is not NULL else None

    @property
    def f_bfree(self):
        return self._stats.f_bfree if self._stats is not NULL else None

    @property
    def f_bavail(self):
        return self._stats.f_bavail if self._stats is not NULL else None

    @property
    def f_files(self):
        return self._stats.f_files if self._stats is not NULL else None

    @property
    def f_ffree(self):
        return self._stats.f_ffree if self._stats is not NULL else None

    @property
    def f_favail(self):
        return self._stats.f_favail if self._stats is not NULL else None

    @property
    def f_fsid(self):
        return self._stats.f_fsid if self._stats is not NULL else None

    @property
    def f_flag(self):
        return self._stats.f_flag if self._stats is not NULL else None

    @property
    def f_namemax(self):
        return self._stats.f_namemax if self._stats is not NULL else None
