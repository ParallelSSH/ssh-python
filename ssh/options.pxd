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
    cdef ssh_options_e _option

    @staticmethod
    cdef object from_option(ssh_options_e option)


# cdef ssh_options_e HOST
# cdef ssh_options_e USER
# cdef ssh_options_e PORT
# cdef ssh_options_e PORT_STR
# cdef ssh_options_e FD
# cdef ssh_options_e USER
# cdef ssh_options_e SSH_DIR
# cdef ssh_options_e IDENTITY
# cdef ssh_options_e ADD_IDENTITY
# cdef ssh_options_e KNOWNHOSTS
# cdef ssh_options_e TIMEOUT
# cdef ssh_options_e TIMEOUT_USEC
# cdef ssh_options_e SSH1
# cdef ssh_options_e SSH2
# cdef ssh_options_e LOG_VERBOSITY
# cdef ssh_options_e LOG_VERBOSITY_STR
# cdef ssh_options_e CIPHERS_C_S
# cdef ssh_options_e CIPHERS_S_C
# cdef ssh_options_e COMPRESSION_C_S
# cdef ssh_options_e COMPRESSION_S_C
# cdef ssh_options_e PROXYCOMMAND
# cdef ssh_options_e BINDADDR
# cdef ssh_options_e STRICTHOSTKEYCHECK
# cdef ssh_options_e COMPRESSION
# cdef ssh_options_e COMPRESSION_LEVEL
# cdef ssh_options_e KEY_EXCHANGE
# cdef ssh_options_e HOSTKEYS
# cdef ssh_options_e GSSAPI_SERVER_IDENTITY
# cdef ssh_options_e GSSAPI_CLIENT_IDENTITY
# cdef ssh_options_e GSSAPI_DELEGATE_CREDENTIALS
# cdef ssh_options_e HMAC_C_S
# cdef ssh_options_e HMAC_S_C
# cdef ssh_options_e PASSWORD_AUTH
# cdef ssh_options_e PUBKEY_AUTH
# cdef ssh_options_e KBDINT_AUTH
# cdef ssh_options_e GSSAPI_AUTH
# cdef ssh_options_e GLOBAL_KNOWNHOSTS
# cdef ssh_options_e NODELAY
