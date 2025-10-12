#  This file is part of ssh-python.
#  Copyright (C) 2018-2025 Panos Kittenis.
#  Copyright (C) 2018-2025 ssh-python Contributors.
#
#  This library is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation, version 2.1.
#
#  This library is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public
#  License along with this library; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-130

import unittest

from ssh.key import generate
from ssh.keytypes import key_type_from_name, RSAKey, ED25519Key, UnknownKey


class KeyTypesTest(unittest.TestCase):

    def test_keygen(self):
        key_type = RSAKey()
        key = generate(key_type, 1024)
        self.assertIsInstance(key.key_type(), RSAKey)
    
    def test_key_type_from_name(self):
        keytype = key_type_from_name('ssh-rsa')
        self.assertIsInstance(keytype, RSAKey)
        self.assertEqual(str(keytype), 'ssh-rsa')
        keytype = key_type_from_name('ssh-ed25519')
        self.assertIsInstance(keytype, ED25519Key)
        self.assertEqual(str(keytype), 'ssh-ed25519')

    def test_unknown_to_string(self):
        self.assertEqual(str(UnknownKey()), 'unknown')
