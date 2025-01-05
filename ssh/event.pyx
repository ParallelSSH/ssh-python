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

from .utils cimport handle_error_codes

from .connector cimport Connector
from .session cimport Session

from . cimport c_ssh


cdef class Event:

    def __cinit__(self):
        self._event = c_ssh.ssh_event_new()
        if self._event is NULL:
            raise MemoryError

    def __dealloc__(self):
        if self._event is not NULL:
            c_ssh.ssh_event_free(self._event)
            self._event = NULL

    @property
    def socket(self):
        return self._sock

    @staticmethod
    cdef Event from_ptr(c_ssh.ssh_event _event):
        cdef Event event = Event.__new__(Event)
        event._event = _event
        return event

    @staticmethod
    cdef int event_callback(c_ssh.socket_t fd, int revent, void *userdata):
        try:
            func = <object>userdata
            return func()
        except Exception:
            # TODO - pass back exception
            return -1

    def add_fd(self, sock, short events, callback=None):
        cdef c_ssh.socket_t _sock = PyObject_AsFileDescriptor(sock)
        cdef c_ssh.ssh_event_callback cb = \
            <c_ssh.ssh_event_callback>&Event.event_callback
        cdef int rc
        cdef void *_cb = NULL if callback is None else <void *>callback
        rc = c_ssh.ssh_event_add_fd(
            self._event, _sock, events, cb, _cb)
        if rc == 0:
            self._sock = sock
        return rc

    def remove_fd(self, socket):
        cdef c_ssh.socket_t _sock = PyObject_AsFileDescriptor(socket)
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_event_remove_fd(self._event, _sock)
        if rc == 0:
            self._sock = None
        return rc

    def add_session(self, Session session):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_event_add_session(self._event, session._session)
        handle_error_codes(rc, session._session)
        self.session = session
        return rc

    def add_connector(self, Connector connector):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_event_add_connector(
                self._event, connector._connector)
        if rc == 0:
            self.connector = connector
        return handle_error_codes(rc, connector.session._session)

    def dopoll(self, int timeout):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_event_dopoll(self._event, timeout)
        return rc

    def remove_session(self, Session session):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_event_remove_session(self._event, session._session)
        handle_error_codes(rc, session._session)
        self.session = None
        return rc

    def remove_connector(self, Connector connector):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_event_remove_connector(
                self._event, connector._connector)
        if rc == 0:
            self.connector = None
        return handle_error_codes(rc, connector.session._session)
