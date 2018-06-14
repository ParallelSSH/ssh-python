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

from c_ssh cimport uint8_t, ssh_keytypes_e, ssh_string, ssh_auth_callback, \
    ssh_buffer, ssh_keycmp_e, ssh_session
from c_pki cimport ssh_key_struct, ssh_signature

cdef extern from "libssh/include/pki_priv.h" nogil:
    ctypedef ssh_key_struct *ssh_key
    int bcrypt_pbkdf(const char *,
                     size_t passlen,
                     const uint8_t *salt,
                     size_t saltlen,
                     uint8_t *key,
                     size_t keylen,
                     unsigned int rounds)

    int pki_key_ecdsa_nid_from_name(const char *name)
    const char *pki_key_ecdsa_nid_to_name(int nid)
    ssh_key pki_key_dup(const ssh_key key, int demote);
    int pki_key_generate_rsa(ssh_key key, int parameter);
    int pki_key_generate_dss(ssh_key key, int parameter);
    int pki_key_generate_ecdsa(ssh_key key, int parameter);
    int pki_key_generate_ed25519(ssh_key key);

    int pki_key_compare(const ssh_key k1,
                        const ssh_key k2,
                        ssh_keycmp_e what)

    ssh_keytypes_e pki_privatekey_type_from_string(const char *privkey);
    ssh_key pki_private_key_from_base64(const char *b64_key,
                                        const char *passphrase,
                                        ssh_auth_callback auth_fn,
                                        void *auth_data)
    ssh_string pki_private_key_to_pem(const ssh_key key,
                                      const char *passphrase,
                                      ssh_auth_callback auth_fn,
                                      void *auth_data)

    int pki_pubkey_build_dss(ssh_key key,
                             ssh_string p,
                             ssh_string q,
                             ssh_string g,
                             ssh_string pubkey)
    int pki_pubkey_build_rsa(ssh_key key,
                             ssh_string e,
                             ssh_string n)
    int pki_pubkey_build_ecdsa(ssh_key key, int nid, ssh_string e)
    ssh_string pki_publickey_to_blob(const ssh_key key)
    int pki_export_pubkey_rsa1(const ssh_key key,
                               const char *host,
                               char *rsa1,
                               size_t rsa1_len)
    
    ssh_string pki_signature_to_blob(const ssh_signature sign);
    ssh_signature pki_signature_from_blob(const ssh_key pubkey,
                                          const ssh_string sig_blob,
                                          ssh_keytypes_e);
    int pki_signature_verify(ssh_session session,
                             const ssh_signature sig,
                             const ssh_key key,
                             const unsigned char *hash,
                             size_t hlen)

    ssh_signature pki_do_sign(const ssh_key privkey,
                              const unsigned char *hash,
                              size_t hlen)
    ssh_signature pki_do_sign_sessionid(const ssh_key key,
                                        const unsigned char *hash,
                                        size_t hlen)
    int pki_ed25519_sign(const ssh_key privkey, ssh_signature sig,
                         const unsigned char *hash, size_t hlen)
    int pki_ed25519_verify(const ssh_key pubkey, ssh_signature sig,
                           const unsigned char *hash, size_t hlen)
    int pki_ed25519_key_cmp(const ssh_key k1,
                            const ssh_key k2,
                            ssh_keycmp_e what)
    int pki_ed25519_key_dup(ssh_key, const ssh_key key)
    int pki_ed25519_public_key_to_blob(ssh_buffer buffer, ssh_key key)
    ssh_string pki_ed25519_sig_to_blob(ssh_signature sig)
    int pki_ed25519_sig_from_blob(ssh_signature sig, ssh_string sig_blob)
    ssh_key ssh_pki_openssh_privkey_import(
        const char *text_key,
        const char *passphrase, ssh_auth_callback auth_fn, void *auth_data)
    ssh_string ssh_pki_openssh_privkey_export(
        const ssh_key privkey,
        const char *passphrase, ssh_auth_callback auth_fn, void *auth_data)
