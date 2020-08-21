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
from libc.string cimport const_char

from session cimport Session
from utils cimport to_bytes, to_str, handle_error_codes


cimport c_ssh


cdef class Channel:

    def __cinit__(self, Session session):
        self.closed = False
        self._session = session

    def __dealloc__(self):
        if self._channel is not NULL and self._session is not None:
            c_ssh.ssh_channel_free(self._channel)
            self._channel = NULL

    @property
    def session(self):
        """Originating session."""
        return self._session

    @staticmethod
    cdef Channel from_ptr(c_ssh.ssh_channel _chan, Session session):
        cdef Channel chan = Channel.__new__(Channel, session)
        chan._channel = _chan
        return chan

    def close(self):
        cdef int rc
        if self.closed:
            return 0
        with nogil:
            rc = c_ssh.ssh_channel_close(self._channel)
        if rc == 0:
            self.closed = True
        return handle_error_codes(rc, self._session._session)

    def get_exit_status(self):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_get_exit_status(self._channel)
        return rc

    def get_session(self):
        return self.session

    def is_closed(self):
        cdef bint rc
        with nogil:
            rc = c_ssh.ssh_channel_is_closed(self._channel)
        return rc != 0

    def is_eof(self):
        cdef bint rc
        with nogil:
            rc = c_ssh.ssh_channel_is_eof(self._channel)
        return bool(rc)

    def is_open(self):
        cdef bint rc
        with nogil:
            rc = c_ssh.ssh_channel_is_open(self._channel)
        return bool(rc)

    def send_eof(self):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_send_eof(self._channel)
        return handle_error_codes(rc, self._session._session)

    def request_auth_agent(self):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_request_auth_agent(self._channel)
        return handle_error_codes(rc, self._session._session)

    def open_auth_agent(self):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_open_auth_agent(self._channel)
        return handle_error_codes(rc, self._session._session)

    def open_forward(self, remotehost, int remoteport,
                     sourcehost, int sourceport):
        cdef bytes b_remotehost = to_bytes(remotehost)
        cdef const_char *c_remotehost = b_remotehost
        cdef bytes b_sourcehost = to_bytes(sourcehost)
        cdef const_char *c_sourcehost = b_sourcehost
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_open_forward(
                self._channel, c_remotehost, remoteport,
                c_sourcehost, sourceport)
        return handle_error_codes(rc, self._session._session)

    def open_session(self):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_open_session(self._channel)
        return handle_error_codes(rc, self._session._session)

    def open_x11(self, sourcehost, int sourceport):
        cdef bytes b_sourcehost = to_bytes(sourcehost)
        cdef const_char *c_sourcehost = b_sourcehost
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_open_x11(
                self._channel, c_sourcehost, sourceport)
        return handle_error_codes(rc, self._session._session)

    def accept_x11(self, int timeout_ms):
        cdef Channel chan
        cdef c_ssh.ssh_channel _chan = NULL
        with nogil:
            _chan = c_ssh.ssh_channel_accept_x11(self._channel, timeout_ms)
        if _chan is NULL:
            raise MemoryError
        chan = Channel.from_ptr(_chan, self._session)
        return chan

    def poll(self, bint is_stderr=False):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_poll(self._channel, is_stderr)
        return handle_error_codes(rc, self._session._session)

    def poll_timeout(self, int timeout, bint is_stderr=False):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_poll_timeout(
                self._channel, timeout, is_stderr)
        return handle_error_codes(rc, self._session._session)

    def read(self, c_ssh.uint32_t size=1024*1024, bint is_stderr=False):
        cdef int rc
        cdef bytes buf = b''
        cdef char* cbuf
        with nogil:
            cbuf = <char *>malloc(sizeof(char)*size)
            if cbuf is NULL:
                with gil:
                    raise MemoryError
            rc = c_ssh.ssh_channel_read(self._channel, cbuf, size, is_stderr)
        try:
            if rc > 0:
                buf = cbuf[:rc]
        finally:
            free(cbuf)
        return handle_error_codes(rc, self._session._session), buf

    def read_nonblocking(self, c_ssh.uint32_t size=1024*1024,
                         bint is_stderr=False):
        cdef int rc
        cdef bytes buf = b''
        cdef char* cbuf
        with nogil:
            cbuf = <char *>malloc(sizeof(char)*size)
            if cbuf is NULL:
                with gil:
                    raise MemoryError
            rc = c_ssh.ssh_channel_read_nonblocking(
                self._channel, cbuf, size, is_stderr)
        try:
            if rc > 0:
                buf = cbuf[:rc]
        finally:
            free(cbuf)
        return handle_error_codes(rc, self._session._session), buf

    def read_timeout(self, int timeout,
                     c_ssh.uint32_t size=1024*1024, bint is_stderr=False):
        cdef int rc
        cdef bytes buf = b''
        cdef char* cbuf
        with nogil:
            cbuf = <char *>malloc(sizeof(char)*size)
            if cbuf is NULL:
                with gil:
                    raise MemoryError
            rc = c_ssh.ssh_channel_read_timeout(
                self._channel, cbuf, size, is_stderr, timeout)
        try:
            if rc > 0:
                buf = cbuf[:rc]
        finally:
            free(cbuf)
        return handle_error_codes(rc, self._session._session), buf

    def request_env(self, name, value):
        cdef bytes b_name = to_bytes(name)
        cdef const_char *c_name = b_name
        cdef bytes b_value = to_bytes(value)
        cdef const_char *c_value = b_value
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_request_env(self._channel, c_name, c_value)
        return handle_error_codes(rc, self._session._session)

    def request_exec(self, cmd):
        cdef bytes b_cmd = to_bytes(cmd)
        cdef const_char *c_cmd = b_cmd
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_request_exec(self._channel, c_cmd)
        return handle_error_codes(rc, self._session._session)

    def request_pty(self):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_request_pty(self._channel)
        return handle_error_codes(rc, self._session._session)

    def change_pty_size(self, int cols, int rows):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_change_pty_size(self._channel, cols, rows)
        return handle_error_codes(rc, self._session._session)

    def request_pty_size(self, terminal, int col, int row):
        cdef bytes b_terminal = to_bytes(terminal)
        cdef const_char *c_terminal = b_terminal
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_request_pty_size(
                self._channel, c_terminal, col, row)
        return handle_error_codes(rc, self._session._session)

    def request_send_signal(self, sig):
        cdef bytes b_sig = to_bytes(sig)
        cdef const_char *c_sig = b_sig
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_request_send_signal(
                self._channel, c_sig)
        return handle_error_codes(rc, self._session._session)

    def request_send_break(self, c_ssh.uint32_t length):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_request_send_break(
                self._channel, length)
        return handle_error_codes(rc, self._session._session)

    def request_shell(self):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_request_shell(self._channel)
        return handle_error_codes(rc, self._session._session)

    def request_sftp(self):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_request_sftp(self._channel)
        return handle_error_codes(rc, self._session._session)

    def request_subsystem(self, subsystem):
        cdef bytes b_sys = to_bytes(subsystem)
        cdef const_char *c_sys = b_sys
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_request_subsystem(
                self._channel, c_sys)
        return handle_error_codes(rc, self._session._session)

    def request_x11(self, int screen_number, bint single_connection=True):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_request_x11(
                self._channel, single_connection, NULL, NULL, screen_number)
        return handle_error_codes(rc, self._session._session)

    def set_blocking(self, bint blocking):
        with nogil:
            c_ssh.ssh_channel_set_blocking(self._channel, blocking)

    def set_counter(self, counter):
        raise NotImplementedError

    def write(self, bytes data):
        cdef c_ssh.uint32_t size = len(data)
        cdef const_char *c_data = data
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_write(self._channel, c_data, size)
        return handle_error_codes(rc, self._session._session)

    def write_stderr(self, bytes data):
        cdef c_ssh.uint32_t size = len(data)
        cdef const_char *c_data = data
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_write_stderr(self._channel, c_data, size)
        return handle_error_codes(rc, self._session._session)

    def window_size(self):
        cdef c_ssh.uint32_t size
        with nogil:
            size = c_ssh.ssh_channel_window_size(self._channel)
        return size

    def select(self, channels not None, outchannels not None, maxfd,
               readfds, timeout=None):
        raise NotImplementedError
