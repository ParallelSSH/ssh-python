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

from c_ssh cimport ssh_session, ssh_buffer, uint32_t, uint8_t, ssh_keytypes_e, \
    ssh_string, ssh_buffer_struct
from c_wrapper cimport ssh_hmac_e
from c_callbacks cimport ssh_packet_callbacks
from c_ed25519 cimport ed25519_pubkey, ed25519_privkey
from c_priv cimport ssh_key
from c_legacy cimport ssh_private_key, ssh_public_key

cdef extern from "libssh/pki.h" nogil:
    enum:
        MAX_PUBKEY_SIZE
        MAX_PRIVKEY_SIZE
        SSH_KEY_FLAG_EMPTY
        SSH_KEY_FLAG_PUBLIC
        SSH_KEY_FLAG_PRIVATE
    struct ssh_key_struct:
        ssh_keytypes_e type
        int flags
        const char *type_c
        int ecdsa_nid
        ed25519_pubkey *ed25519_pubkey
        ed25519_privkey *ed25519_privkey
        void *cert
        ssh_keytypes_e cert_type
    struct ssh_signature_struct:
        ssh_keytypes_e _type "type"
        const char *type_c
    ctypedef ssh_signature_struct *ssh_signature
    ssh_key ssh_key_dup(const ssh_key key)
    void ssh_key_clean (ssh_key key)

    ssh_signature ssh_signature_new()
    void ssh_signature_free(ssh_signature sign)

    int ssh_pki_export_signature_blob(const ssh_signature sign,
                                      ssh_string *sign_blob)
    int ssh_pki_import_signature_blob(const ssh_string sig_blob,
                                      const ssh_key pubkey,
                                      ssh_signature *psig)
    int ssh_pki_signature_verify_blob(ssh_session session,
                                      ssh_string sig_blob,
                                      const ssh_key key,
                                      unsigned char *digest,
                                      size_t dlen)
    int ssh_pki_export_pubkey_blob(const ssh_key key,
                                   ssh_string *pblob)
    int ssh_pki_import_pubkey_blob(const ssh_string key_blob,
                                   ssh_key *pkey)
    int ssh_pki_export_pubkey_rsa1(const ssh_key key,
                                   const char *host,
                                   char *rsa1,
                                   size_t rsa1_len)

    int ssh_pki_import_cert_blob(const ssh_string cert_blob,
                                 ssh_key *pkey)

    ssh_string ssh_pki_do_sign(ssh_session session, ssh_buffer sigbuf,
                               const ssh_key privatekey)
    ssh_string ssh_pki_do_sign_agent(ssh_session session,
                                     ssh_buffer_struct *buf,
                                     const ssh_key pubkey)
    ssh_string ssh_srv_pki_do_sign_sessionid(ssh_session session,
                                             const ssh_key privkey)
    ssh_public_key ssh_pki_convert_key_to_publickey(const ssh_key key)
    ssh_private_key ssh_pki_convert_key_to_privatekey(const ssh_key key)
