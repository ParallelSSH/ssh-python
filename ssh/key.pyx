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

from libc.string cimport const_char

from .keytypes cimport from_keytype, KeyType
from .utils cimport to_str, to_bytes

from .exceptions import KeyExportError, KeyImportError, KeyGenerationError

from . cimport c_ssh


cdef class SSHKey:

    @staticmethod
    cdef SSHKey from_ptr(c_ssh.ssh_key key):
        cdef SSHKey _key = SSHKey.__new__(SSHKey)
        _key._key = key
        return _key

    def __cinit__(self):
        self._key = c_ssh.ssh_key_new()
        if self._key is NULL:
            raise MemoryError

    def __dealloc__(self):
        if self._key is not NULL:
            c_ssh.ssh_key_free(self._key)
            self._key = NULL

    def is_private(self):
        cdef bint rc
        with nogil:
            rc = c_ssh.ssh_key_is_private(self._key)
        return bool(rc)

    def is_public(self):
        cdef bint rc
        with nogil:
            rc = c_ssh.ssh_key_is_public(self._key)
        return bool(rc)

    def __eq__(self, SSHKey other):
        cdef bint is_private
        cdef bint equal
        with nogil:
            is_private = c_ssh.ssh_key_is_private(self._key)
            equal = c_ssh.ssh_key_cmp(
                self._key, other._key, c_ssh.ssh_keycmp_e.SSH_KEY_CMP_PRIVATE) \
                if is_private else \
                c_ssh.ssh_key_cmp(
                    self._key, other._key,
                    c_ssh.ssh_keycmp_e.SSH_KEY_CMP_PUBLIC)
        return bool(not equal)

    def key_type(self):
        cdef c_ssh.ssh_keytypes_e _type
        if self._key is NULL:
            return
        _type = c_ssh.ssh_key_type(self._key)
        return from_keytype(_type)

    def ecdsa_name(self):
        cdef const_char *c_name
        cdef bytes b_name
        with nogil:
            c_name = c_ssh.ssh_pki_key_ecdsa_name(self._key)
        b_name = c_name
        return to_str(b_name)

    def export_privkey_file(self, filepath, passphrase=None):
        cdef bytes b_passphrase
        cdef bytes b_filepath = to_bytes(filepath)
        cdef const_char *c_passphrase = NULL
        cdef const_char *c_filepath = b_filepath
        cdef int rc
        if passphrase is not None:
            b_passphrase = to_bytes(passphrase)
            c_passphrase = b_passphrase
        with nogil:
            rc = c_ssh.ssh_pki_export_privkey_file(
                self._key, c_passphrase, NULL, NULL, c_filepath)
        if rc != c_ssh.SSH_OK:
            raise KeyExportError

    def export_privkey_to_pubkey(self):
        cdef SSHKey pub_key
        cdef c_ssh.ssh_key _pub_key
        cdef int rc
        with nogil:
            rc = c_ssh.ssh_pki_export_privkey_to_pubkey(self._key, &_pub_key)
        if rc != c_ssh.SSH_OK:
            raise KeyExportError
        pub_key = SSHKey.from_ptr(_pub_key)
        return pub_key

    def export_pubkey_base64(self):
        cdef char *_key
        cdef int rc
        cdef bytes b_key
        cdef size_t key_len
        with nogil:
            rc = c_ssh.ssh_pki_export_pubkey_base64(self._key, &_key)
            if rc != c_ssh.SSH_OK:
                with gil:
                    raise KeyExportError
        b_key = _key
        c_ssh.ssh_string_free_char(_key)
        return b_key


def generate(KeyType key_type, int bits):
    cdef SSHKey key
    cdef c_ssh.ssh_key _key
    cdef int rc
    with nogil:
        rc = c_ssh.ssh_pki_generate(key_type._type, bits, &_key)
    if rc != c_ssh.SSH_OK:
        raise KeyGenerationError
    key = SSHKey.from_ptr(_key)
    return key


def import_privkey_base64(bytes b64_key, passphrase=b''):
    cdef const_char *c_key = b64_key
    cdef bytes b_passphrase
    cdef const_char *c_passphrase = NULL
    cdef int rc
    cdef SSHKey key
    cdef c_ssh.ssh_key _key
    if passphrase is not None:
        b_passphrase = to_bytes(passphrase)
        c_passphrase = b_passphrase
    with nogil:
        rc = c_ssh.ssh_pki_import_privkey_base64(
            c_key, c_passphrase, NULL, NULL, &_key)
    if rc != c_ssh.SSH_OK:
        raise KeyImportError
    key = SSHKey.from_ptr(_key)
    return key


def import_privkey_file(filepath, passphrase=b''):
    cdef bytes b_passphrase
    cdef bytes b_filepath = to_bytes(filepath)
    cdef const_char *c_passphrase = NULL
    cdef const_char *c_filepath = b_filepath
    cdef int rc
    cdef SSHKey key
    cdef c_ssh.ssh_key _key
    if passphrase is not None:
        b_passphrase = to_bytes(passphrase)
        c_passphrase = b_passphrase
    with nogil:
        rc = c_ssh.ssh_pki_import_privkey_file(
            c_filepath, c_passphrase, NULL, NULL, &_key)
    if rc != c_ssh.SSH_OK:
        raise KeyImportError
    key = SSHKey.from_ptr(_key)
    return key


def import_pubkey_base64(bytes b64_key, KeyType key_type):
    cdef const_char *c_key = b64_key
    cdef int rc
    cdef SSHKey key
    cdef c_ssh.ssh_key _key
    with nogil:
        rc = c_ssh.ssh_pki_import_pubkey_base64(
            c_key, key_type._type, &_key)
    if rc != c_ssh.SSH_OK:
        raise KeyImportError
    key = SSHKey.from_ptr(_key)
    return key


def import_pubkey_file(filepath):
    cdef bytes b_filepath = to_bytes(filepath)
    cdef const_char *c_filepath = b_filepath
    cdef int rc
    cdef SSHKey key
    cdef c_ssh.ssh_key _key
    with nogil:
        rc = c_ssh.ssh_pki_import_pubkey_file(
            c_filepath, &_key)
    if rc != c_ssh.SSH_OK:
        raise KeyImportError
    key = SSHKey.from_ptr(_key)
    return key


def import_cert_base64(bytes b64_cert, KeyType key_type):
    cdef const_char *c_key = b64_cert
    cdef int rc
    cdef SSHKey key
    cdef c_ssh.ssh_key _key
    with nogil:
        rc = c_ssh.ssh_pki_import_cert_base64(
            c_key, key_type._type, &_key)
    if rc != c_ssh.SSH_OK:
        raise KeyImportError
    key = SSHKey.from_ptr(_key)
    return key


def import_cert_file(filepath):
    cdef bytes b_filepath = to_bytes(filepath)
    cdef const_char *c_filepath = b_filepath
    cdef int rc
    cdef SSHKey key
    cdef c_ssh.ssh_key _key
    with nogil:
        rc = c_ssh.ssh_pki_import_cert_file(
            c_filepath, &_key)
    if rc != c_ssh.SSH_OK:
        raise KeyImportError
    key = SSHKey.from_ptr(_key)
    return key


def copy_cert_to_privkey(SSHKey cert_key, SSHKey priv_key):
    if priv_key.is_private() is False:
        raise KeyImportError
    cdef c_ssh.ssh_key _priv_key = priv_key._key
    cdef c_ssh.ssh_key _cert_key = cert_key._key
    with nogil:
        rc = c_ssh.ssh_pki_copy_cert_to_privkey(
            _cert_key, _priv_key)
    if rc != c_ssh.SSH_OK:
        raise KeyImportError
