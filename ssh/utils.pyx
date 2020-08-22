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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

from select import select

from cpython.version cimport PY_MAJOR_VERSION

from c_ssh cimport ssh_error_types_e, ssh_get_error, ssh_auth_e, \
    SSH_OK, SSH_ERROR, SSH_AGAIN, SSH_EOF, ssh_session, ssh_string, \
    ssh_string_get_char, ssh_string_free, ssh_string_len, SSH_READ_PENDING, \
    SSH_WRITE_PENDING

from exceptions import OtherError, \
    AuthenticationPartial, AuthenticationDenied, AuthenticationError, \
    SSHError, EOF


ENCODING='utf-8'


cdef bytes to_bytes(_str):
    if isinstance(_str, bytes):
        return _str
    elif isinstance(_str, unicode):
        return _str.encode(ENCODING)
    return _str


cdef object to_str(char *c_str):
    _len = len(c_str)
    if PY_MAJOR_VERSION < 3:
        return c_str[:_len]
    return c_str[:_len].decode(ENCODING)


cdef object to_str_len(char *c_str, int length):
    if PY_MAJOR_VERSION < 3:
        return c_str[:length]
    return c_str[:length].decode(ENCODING)


cdef bytes ssh_string_to_bytes(ssh_string _str):
    if _str is NULL:
        return
    cdef const char *c_str
    cdef size_t str_len
    cdef bytes b_str = None
    with nogil:
        str_len = ssh_string_len(_str)
        c_str = ssh_string_get_char(_str)
    if c_str is NULL:
        raise MemoryError
    try:
        b_str = c_str[:str_len]
        return b_str
    finally:
        ssh_string_free(_str)


def wait_socket(session not None, sock not None, timeout=None):
    """Helper function for testing non-blocking mode.

    This function blocks the calling thread for <timeout> seconds -
    to be used only for testing purposes.
    """
    cdef int directions = session.get_poll_flags()
    if directions == 0:
        return 0
    readfds = (sock,) \
        if (directions & SSH_READ_PENDING) else ()
    writefds = (sock,) \
        if (directions & SSH_WRITE_PENDING) else ()
    select(readfds, writefds, (), timeout)


cdef int handle_error_codes(
        int errcode, ssh_session session) except -1:
    if errcode == SSH_OK:
        return SSH_OK
    elif errcode == SSH_ERROR:
        raise SSHError(errcode, ssh_get_error(session))
    elif errcode == SSH_EOF:
        raise EOF(ssh_get_error(session))
    elif errcode == SSH_AGAIN:
        return SSH_AGAIN
    else:
        if errcode < 0:
            raise OtherError(ssh_get_error(session))
        return errcode


cdef int handle_auth_error_codes(int errcode, ssh_session session) except -1:
    if errcode == ssh_auth_e.SSH_AUTH_SUCCESS:
        return ssh_auth_e.SSH_AUTH_SUCCESS
    elif errcode == ssh_auth_e.SSH_AUTH_DENIED:
        raise AuthenticationDenied(ssh_get_error(session))
    elif errcode == ssh_auth_e.SSH_AUTH_ERROR:
        raise AuthenticationError(ssh_get_error(session))
    elif errcode == ssh_auth_e.SSH_AUTH_PARTIAL:
        raise AuthenticationPartial(ssh_get_error(session))
    elif errcode == ssh_auth_e.SSH_AUTH_AGAIN:
        return ssh_auth_e.SSH_AUTH_AGAIN
    else:
        return handle_error_codes(errcode, session)
