# This file is part of ssh-python.
# Copyright (C) 2018-2020 Panos Kittenis
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

from libc.string cimport const_char

from utils cimport to_str, to_bytes

from c_ssh cimport ssh_keytypes_e, ssh_key_type_to_char, ssh_key_type_from_name


cdef class KeyType:
    def __cinit__(self):
        self._type = ssh_keytypes_e.SSH_KEYTYPE_UNKNOWN

    @property
    def value(self):
        return self._type

    def __str__(self):
        cdef const_char *c_type
        c_type = ssh_key_type_to_char(self._type)
        if c_type is not NULL:
            return to_str(c_type)
        return "unknown"

    def __repr__(self):
        return self.__str__()


cdef class UnknownKey(KeyType):
    def __cinit__(self):
        self._type = ssh_keytypes_e.SSH_KEYTYPE_UNKNOWN


cdef class DSSKey(KeyType):
    def __cinit__(self):
        self._type = ssh_keytypes_e.SSH_KEYTYPE_DSS


cdef class RSAKey(KeyType):
    def __cinit__(self):
        self._type = ssh_keytypes_e.SSH_KEYTYPE_RSA


cdef class RSA1Key(KeyType):
    def __cinit__(self):
        self._type = ssh_keytypes_e.SSH_KEYTYPE_RSA1


cdef class ECDSAKey(KeyType):
    def __cinit__(self):
        self._type = ssh_keytypes_e.SSH_KEYTYPE_ECDSA


cdef class DSSCert01Key(KeyType):
    def __cinit__(self):
        self._type = ssh_keytypes_e.SSH_KEYTYPE_DSS_CERT01


cdef class RSACert01Key(KeyType):
    def __cinit__(self):
        self._type = ssh_keytypes_e.SSH_KEYTYPE_RSA_CERT01


cdef class ECDSA_P256(KeyType):
    def __cinit__(self):
        self._type = ssh_keytypes_e.SSH_KEYTYPE_ECDSA_P256


cdef class ECDSA_P384(KeyType):
    def __cinit__(self):
        self._type = ssh_keytypes_e.SSH_KEYTYPE_ECDSA_P384


cdef class ECDSA_P521(KeyType):
    def __cinit__(self):
        self._type = ssh_keytypes_e.SSH_KEYTYPE_ECDSA_P521


cdef class ECDSA_P256_CERT01(KeyType):
    def __cinit__(self):
        self._type = ssh_keytypes_e.SSH_KEYTYPE_ECDSA_P256_CERT01


cdef class ECDSA_P384_CERT01(KeyType):
    def __cinit__(self):
        self._type = ssh_keytypes_e.SSH_KEYTYPE_ECDSA_P384_CERT01


cdef class ECDSA_P521_CERT01(KeyType):
    def __cinit__(self):
        self._type = ssh_keytypes_e.SSH_KEYTYPE_ECDSA_P521_CERT01


cdef class ED25519Key(KeyType):
    def __cinit__(self):
        self._type = ssh_keytypes_e.SSH_KEYTYPE_ED25519


cdef class ED25519_CERT01(KeyType):
    def __cinit__(self):
        self._type = ssh_keytypes_e.SSH_KEYTYPE_ED25519_CERT01


cdef KeyType from_keytype(ssh_keytypes_e _type):
    if _type == ssh_keytypes_e.SSH_KEYTYPE_UNKNOWN:
        return UnknownKey()
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_DSS:
        return DSSKey()
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_RSA:
        return RSAKey()
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_RSA1:
        return RSA1Key()
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_ECDSA:
        return ECDSAKey()
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_DSS_CERT01:
        return DSSCert01Key()
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_RSA_CERT01:
        return RSACert01Key()
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_ECDSA_P256:
        return ECDSA_P256()
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_ECDSA_P384:
        return ECDSA_P384()
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_ECDSA_P521:
        return ECDSA_P521()
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_ECDSA_P256_CERT01:
        return ECDSA_P256_CERT01()
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_ECDSA_P384_CERT01:
        return ECDSA_P384_CERT01()
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_ECDSA_P521_CERT01:
        return ECDSA_P521_CERT01()
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_ED25519:
        return ED25519Key()
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_ED25519_CERT01:
        return ED25519_CERT01()
    else:
        raise ValueError("Unknown keytype %s", _type)


def key_type_from_name(key_name):
    cdef ssh_keytypes_e _type
    cdef bytes b_key_name = to_bytes(key_name)
    cdef const char *_key_name = b_key_name
    with nogil:
        _type = ssh_key_type_from_name(_key_name)
    return from_keytype(_type)
