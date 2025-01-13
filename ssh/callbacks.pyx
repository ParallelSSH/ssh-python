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
from libc.string cimport memset

from .session cimport Session
from .utils cimport handle_error_codes

from .c_ssh cimport ssh_auth_callback
from . cimport c_callbacks


cdef int auth_callback(const char *prompt, char *buf, size_t len,
                       int echo, int verify, void *userdata):
    try:
        func = <object>userdata
        return func()
    except Exception:
        # TODO - pass back exception
        return -1
    # ssh_getpass(prompt, buf, len, echo, verify);


cdef class Callbacks:

    def __cinit__(self):
        self._cb = <c_callbacks.ssh_callbacks>malloc(
            sizeof(c_callbacks.ssh_callbacks_struct))
        if self._cb is NULL:
            raise MemoryError
        memset(self._cb, 0, sizeof(c_callbacks.ssh_callbacks_struct))
        c_callbacks.ssh_callbacks_init(self._cb)
        # self._cb.userdata = NULL
        self._cb.auth_function = <c_callbacks.ssh_auth_callback>&auth_callback
        # self._cb.log_function = NULL
        # self._cb.connect_status_function = NULL
        # self._cb.global_request_function = NULL
        # self._cb.channel_open_request_x11_function = NULL
        # self._cb.channel_open_request_auth_agent_function = NULL

    def __dealloc__(self):
        if self._cb is not NULL:
            free(self._cb)
            self._cb = NULL

    def set_userdata(self, func not None):
        self._cb.userdata = <void *>func

    def set_callbacks(self, Session session not None):
        cdef int rc
        with nogil:
            rc = c_callbacks.ssh_set_callbacks(
                session._session, self._cb)
        return handle_error_codes(rc, session._session)
