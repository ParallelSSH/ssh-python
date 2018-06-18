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

import unittest

from .base_test import SSHTestCase

from ssh.session import Session
from ssh.key import SSHKey, import_pubkey_file, import_privkey_file
from ssh import options
from ssh.exceptions import RequestDenied, KeyImportError


class SessionTest(SSHTestCase):

    def test_connect(self):
        self.assertEqual(self.session.connect(), 0)
        self.assertRaises(RequestDenied, self.session.userauth_none)
        self.assertRaises(
            RequestDenied, self.session.userauth_publickey_auto, '')

    def test_key_auth(self):
        self.assertEqual(self.session.connect(), 0)
        self.assertRaises(KeyImportError, import_pubkey_file, self.user_key)
        key = import_pubkey_file(self.user_pub_key)
        self.assertIsInstance(key, SSHKey)
        self.assertEqual(
            self.session.userauth_try_publickey(key), 0)
        # Private key as public key import error
        self.assertRaises(KeyImportError, import_privkey_file, self.user_pub_key)
        pkey = import_privkey_file(self.user_key)
        self.assertEqual(
            self.session.userauth_publickey(pkey), 0)
