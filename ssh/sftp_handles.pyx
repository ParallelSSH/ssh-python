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

from sftp_attributes cimport SFTPAttributes

from .exceptions import SFTPHandleError

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

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __iter__(self):
        return self

    def __next__(self):
        size, data = self.read()
        while size > 0:
            return size
        raise StopIteration

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
        cdef SFTPDir _fh = SFTPDir.__new__(SFTPDir, sftp)
        _fh._dir = _dir
        return _fh

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closedir()

    def __iter__(self):
        return self

    def __next__(self):
        cdef SFTPAttributes _attrs
        _attrs = self.readdir()
        while _attrs is not None:
            return _attrs
        raise StopIteration

    @property
    def sftp_session(self):
        return self.sftp

    def eof(self):
        cdef bint rc
        with nogil:
            rc = c_sftp.sftp_dir_eof(self._dir)
        return bool(rc)

    def closedir(self):
        cdef int rc
        with nogil:
            rc = c_sftp.sftp_closedir(self._dir)
        return rc

    cpdef SFTPAttributes readdir(self):
        cdef SFTPAttributes _attrs
        cdef c_sftp.sftp_attributes c_attrs
        with nogil:
            c_attrs = c_sftp.sftp_readdir(self.sftp._sftp, self._dir)
        if c_sftp.sftp_dir_eof(self._dir) == 1:
            return
        elif c_attrs is NULL:
            raise SFTPHandleError
        _attrs = SFTPAttributes.from_ptr(c_attrs, self.sftp)
        return _attrs
