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

from sftp cimport SFTP

cimport c_sftp


cdef class SFTPStatVFS:

    def __cinit__(self, SFTP sftp):
        self.sftp = sftp

    def __dealloc__(self):
        if self._stats is not NULL:
            c_sftp.sftp_statvfs_free(self._stats)
            self._stats = NULL

    @staticmethod
    cdef SFTPStatVFS from_ptr(c_sftp.sftp_statvfs_t stats, SFTP sftp):
        cdef SFTPStatVFS _vfs = SFTPStatVFS.__new__(SFTPStatVFS, sftp)
        _vfs._stats = stats
        return _vfs
