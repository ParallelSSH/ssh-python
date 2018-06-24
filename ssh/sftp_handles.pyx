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

from c_ssh cimport uint32_t, uint64_t
cimport c_sftp


cdef class SFTPFile:

    def __cinit__(self, SFTP sftp):
        self.sftp = sftp

    @staticmethod
    cdef SFTPFile from_ptr(c_sftp.sftp_file _file, SFTP sftp):
        cdef SFTPFile _fh = SFTPFile.__new__(SFTPFile, sftp)
        _fh._file = _file
        return _fh

    @property
    def sftp_session(self):
        return self.sftp

    def fstat(self):
        pass

    def close(self):
        pass

    def set_nonblocking(self):
        pass

    def set_blocking(self):
        pass

    def read(self, size_t count=1024000):
        pass

    def async_read_begin(self, uint32_t length=1024000):
        pass

    def async_read(self, uint32_t length, uint32_t, _id):
        pass

    def write(self, size_t count=1024000):
        pass

    def seek(self, uint32_t offset):
        pass

    def seek64(self, uint64_t offset):
        pass

    def tell(self):
        pass

    def tell64(self):
        pass

    def rewind(self):
        pass

    def fstatvfs(self):
        pass

    def fsync(self):
        pass


cdef class SFTPDir:

    def __cinit__(self, SFTP sftp):
        self.sftp = sftp

    @staticmethod
    cdef SFTPDir from_ptr(c_sftp.sftp_dir _dir, SFTP sftp):
        cdef SFTPDir _fh = SFTPDir(SFTPDir, sftp)
        _fh._dir = _dir
        return _fh

    @property
    def sftp_session(self):
        return self.sftp

    def eof(self):
        pass

    def closedir(self):
        pass

    def readdir(self):
        pass
