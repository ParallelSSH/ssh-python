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

from c_ssh cimport ssh_string
from c_wrapper cimport ssh_mac_e, ssh_hmac_e, ssh_des_e, ssh_hmac_struct

cdef extern from "libssh/include/crypto.h" nogil:
    enum:
        DIGEST_MAX_LEN
    enum ssh_key_exchange_e:
        SSH_KEX_DH_GROUP1_SHA1,
        SSH_KEX_DH_GROUP14_SHA1,
        SSH_KEX_ECDH_SHA2_NISTP256,
        SSH_KEX_ECDH_SHA2_NISTP384,
        SSH_KEX_ECDH_SHA2_NISTP521,
        SSH_KEX_CURVE25519_SHA256_LIBSSH_ORG

    enum ssh_cipher_e:
        SSH_NO_CIPHER,
        SSH_BLOWFISH_CBC,
        SSH_3DES_CBC,
        SSH_3DES_CBC_SSH1,
        SSH_DES_CBC_SSH1,
        SSH_AES128_CBC,
        SSH_AES192_CBC,
        SSH_AES256_CBC,
        SSH_AES128_CTR,
        SSH_AES192_CTR,
        SSH_AES256_CTR

    struct ssh_crypto_struct:
        pass

    ssh_string dh_server_signature
    size_t digest_len
    unsigned char *session_id
    unsigned char *secret_hash
    unsigned char *encryptIV
    unsigned char *decryptIV
    unsigned char *decryptkey
    unsigned char *encryptkey
    unsigned char *encryptMAC
    unsigned char *decryptMAC
    unsigned char hmacbuf[DIGEST_MAX_LEN]
    ssh_hmac_e in_hmac, out_hmac
    struct ssh_cipher_struct:
        const char *name
        unsigned int blocksize
        ssh_cipher_e ciphertype
    ssh_cipher_struct *in_cipher
    ssh_cipher_struct *out_cipher
