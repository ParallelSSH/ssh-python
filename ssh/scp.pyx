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

from .utils cimport to_bytes, to_str, handle_error_codes

from . cimport c_ssh


SSH_SCP_REQUEST_NEWDIR = c_ssh.ssh_scp_request_types.SSH_SCP_REQUEST_NEWDIR
SSH_SCP_REQUEST_NEWFILE = c_ssh.ssh_scp_request_types.SSH_SCP_REQUEST_NEWFILE
SSH_SCP_REQUEST_EOF = c_ssh.ssh_scp_request_types.SSH_SCP_REQUEST_EOF
SSH_SCP_REQUEST_ENDDIR = c_ssh.ssh_scp_request_types.SSH_SCP_REQUEST_ENDDIR
SSH_SCP_REQUEST_WARNING = c_ssh.ssh_scp_request_types.SSH_SCP_REQUEST_WARNING


SSH_SCP_WRITE = c_ssh.SSH_SCP_WRITE
SSH_SCP_READ = c_ssh.SSH_SCP_READ
SSH_SCP_RECURSIVE = c_ssh.SSH_SCP_RECURSIVE


cdef class SCP:

    def __cinit__(self):
        self.closed = False

    def __dealloc__(self):
        if self._scp is not NULL:
            if not self.closed:
                self.close()
            c_ssh.ssh_scp_free(self._scp)
            self._scp = NULL

    @staticmethod
    cdef SCP from_ptr(c_ssh.ssh_scp _scp, Session session):
        cdef SCP scp = SCP.__new__(SCP)
        scp._scp = _scp
        scp.session = session
        return scp

    def accept_request(self):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_scp_accept_request(self._scp)
        return handle_error_codes(rc, self.session._session)

    def deny_request(self, reason=None):
        cdef int rc
        cdef bytes b_reason
        cdef const char *_reason = NULL
        if reason is not None:
            b_reason = to_bytes(reason)
            _reason = b_reason
        with nogil:
            rc = c_ssh.ssh_scp_deny_request(self._scp, _reason)
        return handle_error_codes(rc, self.session._session)

    cpdef close(self):
        cdef int rc
        if self.closed:
            return 0
        with nogil:
            rc = c_ssh.ssh_scp_close(self._scp)
            if rc == 0:
                self.closed = True
        return handle_error_codes(rc, self.session._session)

    def init(self):
        """Handled by session.scp_new"""
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_scp_init(self._scp)
        return handle_error_codes(rc, self.session._session)

    def leave_directory(self):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_scp_leave_directory(self._scp)
        return handle_error_codes(rc, self.session._session)

    def pull_request(self):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_scp_pull_request(self._scp)
        return handle_error_codes(rc, self.session._session)

    def push_directory(self, dirname not None, int mode):
        cdef int rc
        cdef bytes b_dirname = to_bytes(dirname)
        cdef const char *_dirname = b_dirname
        with nogil:
            rc = c_ssh.ssh_scp_push_directory(self._scp, _dirname, mode)
        return handle_error_codes(rc, self.session._session)

    def push_file(self, filename not None, size_t size, int perms):
        cdef int rc
        cdef bytes b_filename = to_bytes(filename)
        cdef const char *_filename = b_filename
        with nogil:
            rc = c_ssh.ssh_scp_push_file(self._scp, _filename, size, perms)
        return handle_error_codes(rc, self.session._session)

    def push_file64(self, filename not None, c_ssh.uint64_t size, int perms):
        cdef int rc
        cdef bytes b_filename = to_bytes(filename)
        cdef const char *_filename = b_filename
        with nogil:
            rc = c_ssh.ssh_scp_push_file64(self._scp, _filename, size, perms)
        return handle_error_codes(rc, self.session._session)

    def read(self, c_ssh.uint32_t size=1024*1024):
        cdef int rc
        cdef bytes buf = b''
        cdef char* cbuf
        with nogil:
            cbuf = <char *>malloc(sizeof(char)*size)
            if cbuf is NULL:
                with gil:
                    raise MemoryError
            rc = c_ssh.ssh_scp_read(self._scp, cbuf, size)
        try:
            if rc > 0:
                buf = cbuf[:rc]
        finally:
            free(cbuf)
        return handle_error_codes(rc, self.session._session), buf

    def request_get_filename(self):
        cdef const char *_filename
        cdef bytes filename = b''
        with nogil:
            _filename = c_ssh.ssh_scp_request_get_filename(self._scp)
        if _filename is NULL:
            return filename
        filename = _filename
        return filename

    def request_get_permissions(self):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_scp_request_get_permissions(self._scp)
        return rc

    def request_get_size(self):
        cdef size_t rc
        with nogil:
            rc = c_ssh.ssh_scp_request_get_size(self._scp)
        return rc

    def request_get_size64(self):
        cdef c_ssh.uint64_t rc
        with nogil:
            rc = c_ssh.ssh_scp_request_get_size64(self._scp)
        return rc

    def request_get_warning(self):
        cdef const char *_warning
        cdef bytes warning = b''
        with nogil:
            _warning = c_ssh.ssh_scp_request_get_warning(self._scp)
        if _warning is NULL:
            return warning
        warning = _warning
        return warning

    def write(self, bytes data):
        cdef size_t size = len(data)
        cdef const_char *c_data = data
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_scp_write(self._scp, c_data, size)
        return handle_error_codes(rc, self.session._session)
