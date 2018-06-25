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

from sftp cimport SFTP

cimport c_sftp


cdef class SFTPAttributes:

    def __cinit__(self, SFTP sftp):
        self.sftp = sftp

    def __dealloc__(self):
        if self._attrs is not NULL:
            c_sftp.sftp_attributes_free(self._attrs)
            self._attrs = NULL

    @staticmethod
    cdef SFTPAttributes from_ptr(c_sftp.sftp_attributes attrs, SFTP sftp):
        cdef SFTPAttributes _attrs = SFTPAttributes.__new__(
            SFTPAttributes, sftp)
        _attrs._attrs = attrs
        return _attrs

    @staticmethod
    def new_attrs(SFTP sftp):
        cdef c_sftp.sftp_attributes _attrs
        with nogil:
            _attrs = <c_sftp.sftp_attributes>malloc(
                sizeof(c_sftp.sftp_attributes_struct))
        if _attrs is NULL:
            raise MemoryError
        return SFTPAttributes.from_ptr(_attrs, sftp)
