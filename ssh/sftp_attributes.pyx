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

    @property
    def name(self):
        if self._attrs is NULL:
            return
        cdef bytes b_name = self._attrs.name
        return b_name

    @property
    def longname(self):
        if self._attrs is NULL:
            return
        cdef bytes b_longname = self._attrs.longname
        return b_longname
        
    @property
    def flags(self):
        return self._attrs.flags if self._attrs is not NULL else None

    @property
    def type(self):
        return self._attrs.type if self._attrs is not NULL else None

    @property
    def size(self):
        return self._attrs.size if self._attrs is not NULL else None

    @property
    def uid(self):
        return self._attrs.uid if self._attrs is not NULL else None

    @property
    def gid(self):
        return self._attrs.gid if self._attrs is not NULL else None

    @property
    def owner(self):
        if self._attrs is NULL:
            return
        cdef bytes b_owner = self._attrs.owner \
            if self._attrs.owner is not NULL else None
        return b_owner

    @property
    def group(self):
        if self._attrs is NULL:
            return
        cdef bytes b_group = self._attrs.group \
            if self._attrs.group is not NULL else None
        return b_group

    @property
    def permissions(self):
        return self._attrs.permissions if self._attrs is not NULL else None

    @property
    def atime64(self):
        return self._attrs.atime64 if self._attrs is not NULL else None

    @property
    def atime(self):
        return self._attrs.atime if self._attrs is not NULL else None

    @property
    def atime_nseconds(self):
        return self._attrs.atime_nseconds if self._attrs is not NULL else None

    @property
    def createtime(self):
        return self._attrs.createtime if self._attrs is not NULL else None

    @property
    def createtime_nseconds(self):
        return self._attrs.createtime_nseconds if self._attrs is not NULL else None

    @property
    def mtime64(self):
        return self._attrs.mtime64 if self._attrs is not NULL else None

    @property
    def mtime(self):
        return self._attrs.mtime if self._attrs is not NULL else None

    @property
    def mtime_nseconds(self):
        return self._attrs.mtime_nseconds if self._attrs is not NULL else None

    # @property
    # def acl(self):
    #     return self._attrs.acl if self._attrs is not NULL else None

    @property
    def extended_count(self):
        return self._attrs.extended_count if self._attrs is not NULL else None

    # @property
    # def extended_type(self):
    #     return self._attrs.extended_type if self._attrs is not NULL else None

    # @property
    # def extended_data(self):
    #     return self._attrs.extended_data if self._attrs is not NULL else None
