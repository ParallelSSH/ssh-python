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
