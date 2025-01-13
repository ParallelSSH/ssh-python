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

from .c_ssh cimport ssh_session, ssh_string, ssh_message, uint32_t, \
    ssh_keytypes_e
from .c_keys cimport ssh_private_key_struct, ssh_public_key_struct

cdef extern from "libssh/legacy.h" nogil:
    ctypedef ssh_private_key_struct* ssh_private_key
    ctypedef ssh_public_key_struct* ssh_public_key
    int ssh_auth_list(ssh_session session)
    int ssh_userauth_offer_pubkey(ssh_session session, const char *username,
                                  int type, ssh_string publickey)
    int ssh_userauth_pubkey(ssh_session session, const char *username,
                            ssh_string publickey, ssh_private_key privatekey)
    # IF not _WIN32:
    int ssh_userauth_agent_pubkey(ssh_session session, const char *username,
                                  ssh_public_key publickey)
    int ssh_userauth_autopubkey(ssh_session session, const char *passphrase)
    int ssh_userauth_privatekey_file(
        ssh_session session, const char *username,
        const char *filename, const char *passphrase)
    void privatekey_free(ssh_private_key prv)
    ssh_private_key privatekey_from_file(
        ssh_session session, const char *filename,
        int type, const char *passphrase)
    void publickey_free(ssh_public_key key)
    int ssh_publickey_to_file(ssh_session session, const char *file,
                              ssh_string pubkey, int type)
    ssh_string publickey_from_file(ssh_session session, const char *filename,
                                   int *type)
    ssh_public_key publickey_from_privatekey(ssh_private_key prv)
    ssh_string publickey_to_string(ssh_public_key key)
    int ssh_try_publickey_from_file(ssh_session session, const char *keyfile,
                                    ssh_string *publickey, int *type)
    ssh_keytypes_e ssh_privatekey_type(ssh_private_key privatekey)
    ssh_string ssh_get_pubkey(ssh_session session)
    ssh_message ssh_message_retrieve(ssh_session session, uint32_t packettype)
    ssh_public_key ssh_message_auth_publickey(ssh_message msg)
