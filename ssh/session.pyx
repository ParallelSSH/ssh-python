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
from libc.stdlib cimport malloc, free
from libc.string cimport const_char

from channel cimport Channel
from connector cimport Connector
from utils cimport to_bytes, to_str, handle_error_codes, handle_auth_error_codes
from options cimport Option
from key cimport SSHKey
from sftp cimport SFTP
from scp cimport SCP

from exceptions import OptionError, InvalidAPIUse, ChannelOpenFailure

from c_sftp cimport sftp_session, sftp_new, sftp_init
cimport c_ssh


# SSH status flags
SSH_CLOSED = c_ssh.SSH_CLOSED
SSH_READ_PENDING = c_ssh.SSH_READ_PENDING
SSH_CLOSED_ERROR = c_ssh.SSH_CLOSED_ERROR
SSH_WRITE_PENDING = c_ssh.SSH_WRITE_PENDING


# Authentication codes
SSH_AUTH_SUCCESS = c_ssh.ssh_auth_e.SSH_AUTH_SUCCESS
SSH_AUTH_DENIED = c_ssh.ssh_auth_e.SSH_AUTH_DENIED
SSH_AUTH_PARTIAL = c_ssh.ssh_auth_e.SSH_AUTH_PARTIAL
SSH_AUTH_INFO = c_ssh.ssh_auth_e.SSH_AUTH_INFO
SSH_AUTH_AGAIN = c_ssh.ssh_auth_e.SSH_AUTH_AGAIN
SSH_AUTH_ERROR = c_ssh.ssh_auth_e.SSH_AUTH_ERROR


cdef bint _check_connected(c_ssh.ssh_session session) nogil except -1:
    if not c_ssh.ssh_is_connected(session):
        with gil:
            raise InvalidAPIUse("Session is not connected")
    return 0


cdef class Session:
    """Libssh session class providing session related functions."""

    def __cinit__(self):
        self._session = c_ssh.ssh_new()
        if self._session is NULL:
            raise MemoryError

    def __dealloc__(self):
        if self._session is not NULL:
            c_ssh.ssh_free(self._session)
            self._session = NULL

    def set_socket(self, socket not None):
        """Set socket to use for session.

        Not part of libssh API but needs to be done in C to be able to
        translate python sockets to file descriptors to be used by libssh.
        """
        cdef c_ssh.socket_t _sock = PyObject_AsFileDescriptor(socket)
        cdef c_ssh.ssh_options_e fd = c_ssh.ssh_options_e.SSH_OPTIONS_FD
        cdef int rc
        self.sock = socket
        self._sock = _sock
        with nogil:
            rc = c_ssh.ssh_options_set(self._session, fd, &_sock)
        handle_error_codes(rc, self._session)
        return rc

    def blocking_flush(self, int timeout):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_blocking_flush(self._session, timeout)
        return handle_error_codes(rc, self._session)

    def channel_new(self):
        cdef c_ssh.ssh_channel _channel
        cdef Channel channel
        with nogil:
            _check_connected(self._session)
            _channel = c_ssh.ssh_channel_new(self._session)
        if _channel is NULL:
            raise ChannelOpenFailure
        channel = Channel.from_ptr(_channel, self)
        return channel

    def sftp_new(self):
        cdef sftp_session _sftp
        cdef SFTP sftp
        with nogil:
            _check_connected(self._session)
            _sftp = sftp_new(self._session)
        if _sftp is NULL:
            return handle_error_codes(
                c_ssh.ssh_get_error_code(self._session), self._session)
        sftp = SFTP.from_ptr(_sftp, self)
        return sftp

    def sftp_init(self):
        """Convenience function for creating and initialising new SFTP
        session.

        Not part of libssh API."""
        cdef sftp_session _sftp
        cdef SFTP sftp
        cdef int rc
        with nogil:
            _check_connected(self._session)
            _sftp = sftp_new(self._session)
            if _sftp is NULL:
                with gil:
                    return handle_error_codes(
                        c_ssh.ssh_get_error_code(self._session), self._session)
            rc = sftp_init(_sftp)
        sftp = SFTP.from_ptr(_sftp, self)
        handle_error_codes(rc, self._session)
        return sftp

    def connect(self):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_connect(self._session)
        return handle_error_codes(rc, self._session)

    def disconnect(self):
        """No-op. Handled by object de-allocation."""
        # Due to bug in libssh that segfaults if session
        # is disconnected before freeing channels spawned
        # by that session - even if channels are closed.
        pass
        # if not c_ssh.ssh_is_connected(self._session):
        #     return
        # with nogil:
        #     c_ssh.ssh_disconnect(self._session)

    def connector_new(self):
        cdef c_ssh.ssh_connector _connector
        with nogil:
            _connector = c_ssh.ssh_connector_new(self._session)
        if _connector is NULL:
            return
        return Connector.from_ptr(_connector, self)

    def accept_forward(self, int timeout, int dest_port):
        cdef c_ssh.ssh_channel _channel
        with nogil:
            _check_connected(self._session)
            _channel = c_ssh.ssh_channel_accept_forward(
                self._session, timeout, &dest_port)
        if _channel is NULL:
            return
        return Channel.from_ptr(_channel, self)

    def cancel_forward(self, address not None, int port):
        cdef bytes b_address = to_bytes(address)
        cdef char *c_address = b_address
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_cancel_forward(
                self._session, c_address, port)
        return handle_error_codes(rc, self._session)

    def listen_forward(self, address not None, int port, int bound_port):
        cdef bytes b_address = to_bytes(address)
        cdef char *c_address = b_address
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_channel_listen_forward(
                self._session, c_address, port, &bound_port)
        return handle_error_codes(rc, self._session)

    def get_disconnect_message(self):
        cdef const char *message
        cdef bytes b_message
        with nogil:
            _check_connected(self._session)
            message = c_ssh.ssh_get_disconnect_message(self._session)
        b_message = message
        return b_message

    def get_fd(self):
        cdef c_ssh.socket_t _sock
        with nogil:
            _sock = c_ssh.ssh_get_fd(self._session)
        return _sock

    def get_issue_banner(self):
        cdef char *_banner
        cdef bytes banner
        with nogil:
            _check_connected(self._session)
            _banner = c_ssh.ssh_get_issue_banner(self._session)
        if _banner is NULL:
            return
        banner = _banner
        return banner

    def get_openssh_version(self):
        cdef int rc
        with nogil:
            _check_connected(self._session)
            rc = c_ssh.ssh_get_openssh_version(self._session)
        return rc

    def get_server_publickey(self):
        cdef int rc
        cdef c_ssh.ssh_key _key
        with nogil:
            _check_connected(self._session)
            _key = c_ssh.ssh_key_new()
            if _key is NULL:
                with gil:
                    raise MemoryError
            rc = c_ssh.ssh_get_server_publickey(self._session, &_key)
            if rc != c_ssh.SSH_OK:
                c_ssh.ssh_key_free(_key)
                with gil:
                    return handle_error_codes(rc, self._session)
        return SSHKey.from_ptr(_key)

    def get_version(self):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_get_version(self._session)
        return rc

    def get_status(self):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_get_status(self._session)
        return rc

    def get_poll_flags(self):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_get_poll_flags(self._session)
        return rc

    def is_blocking(self):
        cdef bint rc
        with nogil:
            rc = c_ssh.ssh_is_blocking(self._session)
        return bool(rc)

    def is_connected(self):
        cdef bint rc
        with nogil:
            rc = c_ssh.ssh_is_connected(self._session)
        return bool(rc)

    def is_server_known(self):
        cdef bint rc
        with nogil:
            rc = c_ssh.ssh_is_server_known(self._session)
        return bool(rc)

    def copy_options(self, Session destination):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_options_copy(self._session, &destination._session)
        return handle_error_codes(rc, self._session)

    def options_getopt(self):
        raise NotImplementedError

    def options_parse_config(self, filepath):
        cdef bytes b_filepath = to_bytes(filepath)
        cdef char *c_filepath = b_filepath
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_options_parse_config(self._session, c_filepath)
        return handle_error_codes(rc, self._session)

    def options_set_port(self, int port):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_options_set(
                self._session, c_ssh.ssh_options_e.SSH_OPTIONS_PORT, &port)
        return handle_error_codes(rc, self._session)

    def options_set_gssapi_delegate_credentials(self, bint delegate):
        """
        Set delegating credentials to server on/off.

        :param delegate: Delegation on/off
        :type delegate: bool
        """
        with nogil:
            rc = c_ssh.ssh_options_set(
                self._session,
                c_ssh.ssh_options_e.SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS,
                &delegate)
        return handle_error_codes(rc, self._session)

    def options_set(self, Option option, value):
        """Set an option for session. This function can only be used for
        string options like host. For numeric options, port etc, use the
        individual functions.

        :param option: An SSH option object from one of
          :py:mod:`ssh.options`.
        :type option: :py:class:`ssh.options.Option`
        """
        cdef bytes b_value = to_bytes(value)
        cdef char *c_value
        cdef int rc
        c_value = b_value
        with nogil:
            rc = c_ssh.ssh_options_set(self._session, option._option, c_value)
        return handle_error_codes(rc, self._session)

    def options_get(self, Option option):
        """Get option value. This function can only be used for string options.
        For numeric or other options use the individual functions.
        """
        cdef char *_value
        cdef char **value = NULL
        cdef int rc
        cdef bytes b_value
        with nogil:
            rc = c_ssh.ssh_options_get(
                self._session, option._option, value)
        if rc < 0:
            raise OptionError
        _value = value[0]
        b_value = _value
        c_ssh.ssh_string_free_char(_value)
        return to_str(b_value)

    def options_get_port(self, unsigned int port_target):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_options_get_port(self._session, &port_target)
        return handle_error_codes(rc, self._session)

    def send_ignore(self, bytes data):
        cdef char *c_data = data
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_send_ignore(self._session, c_data)
        return handle_error_codes(rc, self._session)

    def send_debug(self, bytes message, int always_display):
        cdef char *c_message = message
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_send_debug(
                self._session, c_message, always_display)
        return handle_error_codes(rc, self._session)

    def gssapi_set_creds(self, creds not None):
        raise NotImplementedError

    def service_request(self, bytes service):
        cdef int rc
        cdef char *c_service = service
        with nogil:
            rc = c_ssh.ssh_service_request(self._session, c_service)
        return handle_error_codes(rc, self._session)

    # These are also excluded from Windows builds.
    IF not ON_WINDOWS:
        def set_agent_channel(self, Channel channel):
            cdef int rc
            with nogil:
                rc = c_ssh.ssh_set_agent_channel(
                    self._session, channel._channel)
            return handle_error_codes(rc, self._session)

        def set_agent_socket(self, socket not None):
            cdef int rc
            cdef c_ssh.socket_t _sock = PyObject_AsFileDescriptor(socket)
            with nogil:
                rc = c_ssh.ssh_set_agent_socket(self._session, _sock)
            return handle_error_codes(rc, self._session)

    def set_blocking(self, int blocking):
        with nogil:
            c_ssh.ssh_set_blocking(self._session, blocking)

    def set_counters(self, scounter, rcounter):
        raise NotImplementedError

    def set_fd_except(self):
        with nogil:
            c_ssh.ssh_set_fd_except(self._session)

    def set_fd_toread(self):
        with nogil:
            c_ssh.ssh_set_fd_toread(self._session)

    def set_fd_towrite(self):
        with nogil:
            c_ssh.ssh_set_fd_towrite(self._session)

    def silent_disconnect(self):
        with nogil:
            c_ssh.ssh_silent_disconnect(self._session)

    def userauth_none(self):
        cdef int rc
        with nogil:
            _check_connected(self._session)
            rc = c_ssh.ssh_userauth_none(self._session, NULL)
        return handle_auth_error_codes(rc, self._session)

    def userauth_list(self):
        cdef int rc
        with nogil:
            _check_connected(self._session)
            rc = c_ssh.ssh_userauth_list(self._session, NULL)
        return handle_error_codes(rc, self._session)

    def userauth_try_publickey(self, SSHKey pubkey not None):
        cdef int rc
        with nogil:
            _check_connected(self._session)
            rc = c_ssh.ssh_userauth_try_publickey(
                self._session, NULL, pubkey._key)
        return handle_auth_error_codes(rc, self._session)

    def userauth_publickey(self, SSHKey privkey not None):
        cdef int rc
        with nogil:
            _check_connected(self._session)
            rc = c_ssh.ssh_userauth_publickey(
                self._session, NULL, privkey._key)
        return handle_auth_error_codes(rc, self._session)

    # ssh_userauth_agent is excluded from libssh.h on Windows.
    IF not ON_WINDOWS:
        def userauth_agent(self, username not None):
            cdef bytes b_username = to_bytes(username)
            cdef char *c_username = b_username
            cdef int rc
            with nogil:
                _check_connected(self._session)
                rc = c_ssh.ssh_userauth_agent(self._session, c_username)
            return handle_auth_error_codes(rc, self._session)

    def userauth_publickey_auto(self, passphrase not None):
        cdef bytes b_passphrase = to_bytes(passphrase)
        cdef char *c_passphrase = b_passphrase
        cdef int rc
        with nogil:
            _check_connected(self._session)
            rc = c_ssh.ssh_userauth_publickey_auto(
                self._session, NULL, c_passphrase)
        return handle_auth_error_codes(rc, self._session)

    def userauth_password(self, username not None, password not None):
        cdef bytes b_username = to_bytes(username)
        cdef bytes b_password = to_bytes(password)
        cdef char *c_username = b_username
        cdef char *c_password = b_password
        cdef int rc
        with nogil:
            _check_connected(self._session)
            rc = c_ssh.ssh_userauth_password(
                self._session, c_username, c_password)
        return handle_auth_error_codes(rc, self._session)

    def userauth_kbdint(self, username not None, submethods not None):
        cdef bytes b_username = to_bytes(username)
        cdef bytes b_submethods = to_bytes(submethods)
        cdef char *c_username = b_username
        cdef char *c_submethods = b_submethods
        cdef int rc
        with nogil:
            _check_connected(self._session)
            rc = c_ssh.ssh_userauth_kbdint(
                self._session, c_username, c_submethods)
        return handle_auth_error_codes(rc, self._session)

    def userauth_kbdint_getinstruction(self):
        cdef bytes b_instruction
        cdef const_char *_instruction
        with nogil:
            _check_connected(self._session)
            _instruction = c_ssh.ssh_userauth_kbdint_getinstruction(
                self._session)
        b_instruction = to_str(<char *>_instruction)
        return b_instruction

    def userauth_kbdint_getname(self):
        cdef bytes b_name
        cdef const_char *_name
        with nogil:
            _check_connected(self._session)
            _name = c_ssh.ssh_userauth_kbdint_getname(self._session)
        b_name = to_str(<char *>_name)
        return b_name

    def userauth_kbdint_getnprompts(self):
        cdef int rc
        with nogil:
            _check_connected(self._session)
            rc = c_ssh.ssh_userauth_kbdint_getnprompts(self._session)
        return rc

    def userauth_kbdint_getprompt(self, unsigned int i, bytes echo not None):
        cdef const_char *_prompt
        cdef bytes b_prompt
        cdef char *c_echo = echo
        with nogil:
            _check_connected(self._session)
            _prompt = c_ssh.ssh_userauth_kbdint_getprompt(
                self._session, i, c_echo)
        b_prompt = _prompt
        return b_prompt

    def userauth_kbdint_getnanswers(self):
        cdef int rc
        with nogil:
            _check_connected(self._session)
            rc = c_ssh.ssh_userauth_kbdint_getnanswers(self._session)
        return rc

    def userauth_kbdint_getanswer(self, unsigned int i):
        cdef const_char *_answer
        cdef bytes b_answer
        with nogil:
            _check_connected(self._session)
            _answer = c_ssh.ssh_userauth_kbdint_getanswer(
                self._session, i)
        b_answer = _answer
        return b_answer

    def userauth_kbdint_setanswer(self, unsigned int i, bytes answer not None):
        cdef char *c_answer = answer
        cdef int rc
        with nogil:
            _check_connected(self._session)
            rc = c_ssh.ssh_userauth_kbdint_setanswer(
                self._session, i, <const_char *>(c_answer))
        return handle_auth_error_codes(rc, self._session)

    def userauth_gssapi(self):
        cdef int rc
        with nogil:
            _check_connected(self._session)
            rc = c_ssh.ssh_userauth_gssapi(self._session)
        return handle_auth_error_codes(rc, self._session)

    def write_knownhost(self):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_write_knownhost(self._session)
        return handle_error_codes(rc, self._session)

    def dump_knownhost(self):
        cdef const_char *_known_host
        cdef bytes b_known_host
        with nogil:
            _known_host = c_ssh.ssh_dump_knownhost(self._session)
        if _known_host is NULL:
            return
        b_known_host = _known_host
        return b_known_host

    def get_clientbanner(self):
        cdef const_char *_banner
        cdef bytes banner
        with nogil:
            _banner = c_ssh.ssh_get_clientbanner(self._session)
        if _banner is NULL:
            return
        banner = _banner
        return banner

    def get_serverbanner(self):
        cdef const_char *_banner
        cdef bytes banner
        with nogil:
            _banner = c_ssh.ssh_get_serverbanner(self._session)
        if _banner is NULL:
            return
        banner = _banner
        return banner

    def get_kex_algo(self):
        cdef const_char *_algo
        cdef bytes algo
        with nogil:
            _algo = c_ssh.ssh_get_kex_algo(self._session)
        if _algo is NULL:
            return
        algo = _algo
        return algo

    def get_cipher_in(self):
        cdef const_char *_cipher
        cdef bytes cipher
        with nogil:
            _cipher = c_ssh.ssh_get_cipher_in(self._session)
        if _cipher is NULL:
            return
        cipher = _cipher
        return cipher

    def get_cipher_out(self):
        cdef const_char *_cipher
        cdef bytes cipher
        with nogil:
            _cipher = c_ssh.ssh_get_cipher_out(self._session)
        if _cipher is NULL:
            return
        cipher = _cipher
        return cipher

    def get_hmac_in(self):
        cdef const_char *_hmac
        cdef bytes hmac
        with nogil:
            _hmac = c_ssh.ssh_get_hmac_in(self._session)
        if _hmac is NULL:
            return
        hmac = _hmac
        return hmac

    def get_hmac_out(self):
        cdef const_char *_hmac
        cdef bytes hmac
        with nogil:
            _hmac = c_ssh.ssh_get_hmac_out(self._session)
        if _hmac is NULL:
            return
        hmac = _hmac
        return hmac

    def get_error(self):
        cdef const_char *error
        cdef bytes b_error
        with nogil:
            error = c_ssh.ssh_get_error(self._session)
        if error is NULL:
            return
        b_error = error
        return to_str(b_error)

    def get_error_code(self):
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_get_error_code(self._session)
        return rc

    def scp_new(self, int mode, location not None):
        """Create and initialise SCP channel"""
        cdef c_ssh.ssh_scp _scp
        cdef bytes b_location = to_bytes(location)
        cdef char *c_location = b_location
        with nogil:
            _scp = c_ssh.ssh_scp_new(self._session, mode, c_location)
            if _scp is NULL:
                with gil:
                    return handle_error_codes(
                        c_ssh.ssh_get_error_code(self._session), self._session)
            if c_ssh.ssh_scp_init(_scp) != c_ssh.SSH_OK:
                c_ssh.ssh_scp_free(_scp)
                with gil:
                    return handle_error_codes(
                        c_ssh.ssh_get_error_code(self._session), self._session)
        return SCP.from_ptr(_scp, self)
