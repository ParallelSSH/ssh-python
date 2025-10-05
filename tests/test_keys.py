import os

from ssh.key import (SSHKey, SSH_FILE_FORMAT_OPENSSH, SSH_FILE_FORMAT_PEM, import_pubkey_file,
                     import_privkey_file, generate)
from ssh.keytypes import RSAKey

from .base_case import SSHTestCase, PUB_FILE


class KeyTest(SSHTestCase):

    def test_imports(self):
        pub_file = import_pubkey_file(PUB_FILE)
        self.assertIsInstance(pub_file, SSHKey)

    def test_export_file_format(self):
        key_type = RSAKey()
        key = generate(key_type, 1024)
        for keyformat in (SSH_FILE_FORMAT_PEM, SSH_FILE_FORMAT_OPENSSH):
            export_file_path = 'test_file_export'
            try:
                key.export_privkey_file_format(export_file_path, keyformat)
                self.assertTrue(os.path.exists(export_file_path))
                imported_key = import_privkey_file(export_file_path)
                assert imported_key == key
            finally:
                os.unlink(export_file_path)

    def test_export_bad_file_format(self):
        key_type = RSAKey()
        key = generate(key_type, 1024)
        self.assertRaises(ValueError, key.export_privkey_file_format, "fake", 999)
