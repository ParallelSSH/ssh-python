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

from c_ssh cimport uint8_t

cdef extern from "libssh/ed25519.h" nogil:
    enum:
        ED25519_PK_LEN
        ED25519_SK_LEN
        ED25519_SIG_LEN
    ctypedef uint8_t ed25519_pubkey[ED25519_PK_LEN]
    ctypedef uint8_t ed25519_privkey[ED25519_SK_LEN]
    ctypedef uint8_t ed25519_signature[ED25519_SIG_LEN]
    int crypto_sign_ed25519_keypair(ed25519_pubkey pk, ed25519_privkey sk)
    int crypto_sign_ed25519(
        unsigned char *sm,unsigned long long *smlen,
        const unsigned char *m,unsigned long long mlen,
        const ed25519_privkey sk)
    int crypto_sign_ed25519_open(
        unsigned char *m,unsigned long long *mlen,
        const unsigned char *sm,unsigned long long smlen,
        const ed25519_pubkey pk)
