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

from c_ssh cimport ssh_options_e


cdef class Option:
    """Class for representing an SSH option."""

    @staticmethod
    cdef Option from_option(ssh_options_e option):
        cdef Option _option = Option.__new__(Option)
        _option._option = option
        return _option

    def __eq__(self, Option other):
        return self._option == other._option

    @property
    def value(self):
        return self._option

    def __str__(self):
        return str(self._option)

    def __repr__(self):
        return self.__str__()


# grep SSH_OPTIONS libssh/include/libssh/libssh.h | tr -d , | sed -E 's/SSH_OPTIONS_([A-Z0-9_]+)/\1 = Option.from_option(ssh_options_e.\0)/'
HOST = Option.from_option(ssh_options_e.SSH_OPTIONS_HOST)
PORT = Option.from_option(ssh_options_e.SSH_OPTIONS_PORT)
PORT_STR = Option.from_option(ssh_options_e.SSH_OPTIONS_PORT_STR)
FD = Option.from_option(ssh_options_e.SSH_OPTIONS_FD)
USER = Option.from_option(ssh_options_e.SSH_OPTIONS_USER)
SSH_DIR = Option.from_option(ssh_options_e.SSH_OPTIONS_SSH_DIR)
IDENTITY = Option.from_option(ssh_options_e.SSH_OPTIONS_IDENTITY)
ADD_IDENTITY = Option.from_option(ssh_options_e.SSH_OPTIONS_ADD_IDENTITY)
KNOWNHOSTS = Option.from_option(ssh_options_e.SSH_OPTIONS_KNOWNHOSTS)
TIMEOUT = Option.from_option(ssh_options_e.SSH_OPTIONS_TIMEOUT)
TIMEOUT_USEC = Option.from_option(ssh_options_e.SSH_OPTIONS_TIMEOUT_USEC)
SSH1 = Option.from_option(ssh_options_e.SSH_OPTIONS_SSH1)
SSH2 = Option.from_option(ssh_options_e.SSH_OPTIONS_SSH2)
LOG_VERBOSITY = Option.from_option(ssh_options_e.SSH_OPTIONS_LOG_VERBOSITY)
LOG_VERBOSITY_STR = Option.from_option(ssh_options_e.SSH_OPTIONS_LOG_VERBOSITY_STR)
CIPHERS_C_S = Option.from_option(ssh_options_e.SSH_OPTIONS_CIPHERS_C_S)
CIPHERS_S_C = Option.from_option(ssh_options_e.SSH_OPTIONS_CIPHERS_S_C)
COMPRESSION_C_S = Option.from_option(ssh_options_e.SSH_OPTIONS_COMPRESSION_C_S)
COMPRESSION_S_C = Option.from_option(ssh_options_e.SSH_OPTIONS_COMPRESSION_S_C)
PROXYCOMMAND = Option.from_option(ssh_options_e.SSH_OPTIONS_PROXYCOMMAND)
BINDADDR = Option.from_option(ssh_options_e.SSH_OPTIONS_BINDADDR)
STRICTHOSTKEYCHECK = Option.from_option(ssh_options_e.SSH_OPTIONS_STRICTHOSTKEYCHECK)
COMPRESSION = Option.from_option(ssh_options_e.SSH_OPTIONS_COMPRESSION)
COMPRESSION_LEVEL = Option.from_option(ssh_options_e.SSH_OPTIONS_COMPRESSION_LEVEL)
KEY_EXCHANGE = Option.from_option(ssh_options_e.SSH_OPTIONS_KEY_EXCHANGE)
HOSTKEYS = Option.from_option(ssh_options_e.SSH_OPTIONS_HOSTKEYS)
GSSAPI_SERVER_IDENTITY = Option.from_option(ssh_options_e.SSH_OPTIONS_GSSAPI_SERVER_IDENTITY)
GSSAPI_CLIENT_IDENTITY = Option.from_option(ssh_options_e.SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY)
GSSAPI_DELEGATE_CREDENTIALS = Option.from_option(ssh_options_e.SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS)
HMAC_C_S = Option.from_option(ssh_options_e.SSH_OPTIONS_HMAC_C_S)
HMAC_S_C = Option.from_option(ssh_options_e.SSH_OPTIONS_HMAC_S_C)
PASSWORD_AUTH = Option.from_option(ssh_options_e.SSH_OPTIONS_PASSWORD_AUTH)
PUBKEY_AUTH = Option.from_option(ssh_options_e.SSH_OPTIONS_PUBKEY_AUTH)
KBDINT_AUTH = Option.from_option(ssh_options_e.SSH_OPTIONS_KBDINT_AUTH)
GSSAPI_AUTH = Option.from_option(ssh_options_e.SSH_OPTIONS_GSSAPI_AUTH)
GLOBAL_KNOWNHOSTS = Option.from_option(ssh_options_e.SSH_OPTIONS_GLOBAL_KNOWNHOSTS)
NODELAY = Option.from_option(ssh_options_e.SSH_OPTIONS_NODELAY)
PUBLICKEY_ACCEPTED_TYPES = Option.from_option(ssh_options_e.SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES)
PROCESS_CONFIG = Option.from_option(ssh_options_e.SSH_OPTIONS_PROCESS_CONFIG)
REKEY_DATA = Option.from_option(ssh_options_e.SSH_OPTIONS_REKEY_DATA)
REKEY_TIME = Option.from_option(ssh_options_e.SSH_OPTIONS_REKEY_TIME)
