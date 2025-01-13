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

from .c_ssh cimport ssh_keytypes_e


cdef class KeyType:
    cdef ssh_keytypes_e _type


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
    pass


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


cdef KeyType from_keytype(ssh_keytypes_e _type)
