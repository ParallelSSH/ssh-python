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

from cpython cimport PyObject_AsFileDescriptor

from .channel cimport Channel
from .session cimport Session

from .utils cimport handle_error_codes
from . cimport c_ssh


cdef class Flag:

    @staticmethod
    cdef Flag from_flag(c_ssh.ssh_connector_flags_e flag):
        cdef Flag _flag = Flag.__new__(Flag)
        _flag._flag = flag
        return _flag

    def __eq__(self, Flag other not None):
        return self._flag == other._flag

    def __str__(self):
        return str(self._flag)

    def __repr__(self):
        return self.__str__()


CONNECTOR_STDOUT = Flag.from_flag(
    c_ssh.ssh_connector_flags_e.SSH_CONNECTOR_STDOUT)
CONNECTOR_STDERR = Flag.from_flag(
    c_ssh.ssh_connector_flags_e.SSH_CONNECTOR_STDERR)
CONNECTOR_BOTH = Flag.from_flag(
    c_ssh.ssh_connector_flags_e.SSH_CONNECTOR_BOTH)


cdef class Connector:

    def __cinit__(self, Session session):
        self.session = session

    def __dealloc__(self):
        if self._connector is not NULL:
            c_ssh.ssh_connector_free(self._connector)
            self._connector = NULL

    @staticmethod
    cdef Connector from_ptr(c_ssh.ssh_connector _connector, Session session):
        cdef Connector connector = Connector.__new__(Connector, session)
        connector._connector = _connector
        return connector

    def set_in_channel(self, Channel channel, Flag flag):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_connector_set_in_channel(
                self._connector, channel._channel, flag._flag)
        return handle_error_codes(rc, self.session._session)

    def set_out_channel(self, Channel channel, Flag flag):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_connector_set_out_channel(
                self._connector, channel._channel, flag._flag)
        return handle_error_codes(rc, self.session._session)

    def set_in_fd(self, socket):
        cdef c_ssh.socket_t _sock = PyObject_AsFileDescriptor(socket)
        with nogil:
            c_ssh.ssh_connector_set_in_fd(self._connector, _sock)

    def set_out_fd(self, socket):
        cdef c_ssh.socket_t _sock = PyObject_AsFileDescriptor(socket)
        with nogil:
            c_ssh.ssh_connector_set_out_fd(self._connector, _sock)
