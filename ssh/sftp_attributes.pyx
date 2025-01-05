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

from .sftp cimport SFTP
from .utils cimport ssh_string_to_bytes

from .c_ssh cimport ssh_string, uint8_t, uint32_t, uint64_t
from . cimport c_sftp


cdef class SFTPAttributes:

    def __cinit__(self):
        self.self_made = False

    def __dealloc__(self):
        if self._attrs is not NULL and not self.self_made:
            c_sftp.sftp_attributes_free(self._attrs)
            self._attrs = NULL
        elif self._attrs is not NULL and self.self_made:
            free(self._attrs)
            self._attrs = NULL

    @staticmethod
    cdef SFTPAttributes from_ptr(c_sftp.sftp_attributes attrs, SFTP sftp):
        cdef SFTPAttributes _attrs = SFTPAttributes.__new__(SFTPAttributes)
        _attrs._attrs = attrs
        _attrs.sftp = sftp
        return _attrs

    @staticmethod
    def new_attrs(SFTP sftp):
        cdef SFTPAttributes attrs
        cdef c_sftp.sftp_attributes _attrs
        with nogil:
            _attrs = <c_sftp.sftp_attributes>malloc(
                sizeof(c_sftp.sftp_attributes_struct))
        if _attrs is NULL:
            raise MemoryError
        _attrs.name = b''
        _attrs.longname = b''
        _attrs.flags = 0
        _attrs.type = 0
        _attrs.size = 0
        _attrs.uid = 0
        _attrs.gid = 0
        _attrs.owner = b''
        _attrs.group = b''
        _attrs.permissions = 0
        _attrs.atime64 = 0
        _attrs.atime = 0
        _attrs.atime_nseconds = 0
        _attrs.createtime = 0
        _attrs.createtime_nseconds = 0
        _attrs.mtime64 = 0
        _attrs.mtime = 0
        _attrs.mtime_nseconds = 0
        _attrs.acl = NULL
        _attrs.extended_count = 0
        _attrs.extended_type = NULL
        _attrs.extended_data = NULL
        attrs = SFTPAttributes.from_ptr(_attrs, sftp)
        attrs.self_made = True
        return attrs

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

    @flags.setter
    def flags(self, uint32_t flags):
        self._attrs.flags = flags

    @property
    def type(self):
        return self._attrs.type if self._attrs is not NULL else None

    @type.setter
    def type(self, uint8_t _type):
        self._attrs.type = _type

    @property
    def size(self):
        return self._attrs.size if self._attrs is not NULL else None

    @size.setter
    def size(self, uint64_t size):
        self._attrs.size = size

    @property
    def uid(self):
        return self._attrs.uid if self._attrs is not NULL else None

    @uid.setter
    def uid(self, uint32_t uid):
        self._attrs.uid = uid

    @property
    def gid(self):
        return self._attrs.gid if self._attrs is not NULL else None

    @gid.setter
    def gid(self, uint32_t gid):
        self._attrs.gid = gid

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

    @permissions.setter
    def permissions(self, uint32_t permissions):
        self._attrs.permissions = permissions

    @property
    def atime64(self):
        return self._attrs.atime64 if self._attrs is not NULL else None

    @atime64.setter
    def atime64(self, uint64_t atime):
        self._attrs.atime64 = atime

    @property
    def atime(self):
        return self._attrs.atime if self._attrs is not NULL else None

    @atime.setter
    def atime(self, uint32_t atime):
        self._attrs.atime = atime

    @property
    def atime_nseconds(self):
        return self._attrs.atime_nseconds if self._attrs is not NULL else None

    @atime_nseconds.setter
    def atime_nseconds(self, uint32_t nseconds):
        self._attrs.atime_nseconds = nseconds

    @property
    def createtime(self):
        return self._attrs.createtime if self._attrs is not NULL else None

    @createtime.setter
    def createtime(self, uint64_t createtime):
        self._attrs.createtime = createtime

    @property
    def createtime_nseconds(self):
        return self._attrs.createtime_nseconds \
            if self._attrs is not NULL else None

    @createtime_nseconds.setter
    def createtime_nseconds(self, uint32_t nseconds):
        self._attrs.createtime_nseconds = nseconds

    @property
    def mtime64(self):
        return self._attrs.mtime64 if self._attrs is not NULL else None

    @mtime64.setter
    def mtime64(self, uint64_t mtime):
        self._attrs.mtime64 = mtime

    @property
    def mtime(self):
        return self._attrs.mtime if self._attrs is not NULL else None

    @mtime.setter
    def mtime(self, uint32_t mtime):
        self._attrs.mtime = mtime

    @property
    def mtime_nseconds(self):
        return self._attrs.mtime_nseconds if self._attrs is not NULL else None

    @mtime_nseconds.setter
    def mtime_nseconds(self, uint32_t nseconds):
        self._attrs.mtime_nseconds = nseconds

    @property
    def acl(self):
        if self._attrs is NULL:
            return
        return ssh_string_to_bytes(self._attrs.acl)

    @property
    def extended_count(self):
        return self._attrs.extended_count if self._attrs is not NULL else None

    @extended_count.setter
    def extended_count(self, uint32_t count):
        self._attrs.extended_count = count

    @property
    def extended_type(self):
        if self._attrs is NULL:
            return
        return ssh_string_to_bytes(self._attrs.extended_type)

    @property
    def extended_data(self):
        if self._attrs is NULL:
            return
        return ssh_string_to_bytes(self._attrs.extended_data)
