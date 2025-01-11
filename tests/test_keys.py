from ssh.key import SSHKey, import_pubkey_file

from .base_case import SSHTestCase, PUB_FILE


class KeyTest(SSHTestCase):

    def test_imports(self):
        pub_file = import_pubkey_file(PUB_FILE)
        self.assertIsInstance(pub_file, SSHKey)
