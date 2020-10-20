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
        cdef bytes _type
        cdef const_char *c_type
        with nogil:
            c_type = ssh_key_type_to_char(self._type)
        _type = c_type
        return to_str(_type)

    def __repr__(self):
        return self.__str__()


cdef class UnknownKey(KeyType):
    pass


cdef class DSSKey(KeyType):
    pass


cdef class RSAKey(KeyType):
    pass


cdef class RSA1Key(KeyType):
    pass


cdef class ECDSAKey(KeyType):
    pass


cdef class DSSCert01Key(KeyType):
    pass


cdef class RSACert01Key(KeyType):

    def __cinit__(self):
        self._type = ssh_keytypes_e.SSH_KEYTYPE_RSA_CERT01


cdef class ECDSA_P256(KeyType):
    pass


cdef class ECDSA_P384(KeyType):
    pass


cdef class ECDSA_P521(KeyType):
    pass


cdef class ECDSA_P256_CERT01(KeyType):
    pass


cdef class ECDSA_P384_CERT01(KeyType):
    pass


cdef class ECDSA_P521_CERT01(KeyType):
    pass


cdef class ED25519_CERT01(KeyType):
    pass


cdef KeyType from_keytype(ssh_keytypes_e _type):
    cdef KeyType key_type
    if _type == ssh_keytypes_e.SSH_KEYTYPE_UNKNOWN:
        key_type = UnknownKey.__new__(UnknownKey)
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_DSS:
        key_type = DSSKey.__new__(DSSKey)
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_RSA:
        key_type = RSAKey.__new__(RSAKey)
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_RSA1:
        key_type = RSA1Key.__new__(RSA1Key)
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_ECDSA:
        key_type = ECDSAKey.__new__(ECDSAKey)
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_DSS_CERT01:
        key_type = DSSCert01Key.__new__(DSSCert01Key)
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_RSA_CERT01:
        key_type = RSACert01Key.__new__(RSACert01Key)
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_ECDSA_P256:
        key_type = ECDSA_P256.__new__(ECDSA_P256)
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_ECDSA_P384:
        key_type = ECDSA_P384.__new__(ECDSA_P384)
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_ECDSA_P521:
        key_type = ECDSA_P521.__new__(ECDSA_P521)
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_ECDSA_P256_CERT01:
        key_type = ECDSA_P256_CERT01.__new__(ECDSA_P256_CERT01)
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_ECDSA_P384_CERT01:
        key_type = ECDSA_P384_CERT01.__new__(ECDSA_P384_CERT01)
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_ECDSA_P521_CERT01:
        key_type = ECDSA_P521_CERT01.__new__(ECDSA_P521_CERT01)
    elif _type == ssh_keytypes_e.SSH_KEYTYPE_ED25519_CERT01:
        key_type = ED25519_CERT01.__new__(ED25519_CERT01)
    else:
        raise Exception("Unknown keytype %s", _type)
    key_type._type = _type
    return key_type


def key_type_from_name(key_name):
    cdef ssh_keytypes_e _type
    cdef bytes b_key_name = to_bytes(key_name)
    cdef char _key_name = b_key_name
    with nogil:
        _type = ssh_key_type_from_name(&_key_name)
    return from_keytype(_type)
