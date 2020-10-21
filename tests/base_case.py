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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

import unittest
import pwd
import os
import socket
import subprocess
from sys import version_info

from .embedded_server.openssh import OpenSSHServer
from ssh.session import Session
from ssh.key import import_privkey_file
from ssh import options


PKEY_FILENAME = os.path.sep.join([os.path.dirname(__file__), 'unit_test_key'])
PUB_FILE = "%s.pub" % (PKEY_FILENAME,)
USER_CERT_PRIV_KEY = os.path.sep.join([os.path.dirname(__file__), 'unit_test_cert_key'])
USER_CERT_PUB_KEY = os.path.sep.join([os.path.dirname(__file__), 'unit_test_cert_key.pub'])
USER_CERT_FILE = os.path.sep.join([os.path.dirname(__file__), 'unit_test_cert_key-cert.pub'])
CA_USER_KEY = os.path.sep.join([os.path.dirname(__file__), 'embedded_server', 'ca_user_key'])
USER = pwd.getpwuid(os.geteuid()).pw_name


class SSHTestCase(unittest.TestCase):

    @classmethod
    def sign_cert(cls):
        cmd = [
            'ssh-keygen', '-s', CA_USER_KEY, '-n', USER, '-I', 'tests', USER_CERT_PUB_KEY,
        ]
        subprocess.check_call(cmd)

    @classmethod
    def setUpClass(cls):
        _mask = int('0600') if version_info <= (2,) else 0o600
        for _file in [PKEY_FILENAME, USER_CERT_PRIV_KEY, CA_USER_KEY]:
            os.chmod(_file, _mask)
        cls.sign_cert()
        cls.server = OpenSSHServer()
        cls.server.start_server()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        del cls.server

    def setUp(self):
        self.host = '127.0.0.1'
        self.port = 2222
        self.cmd = 'echo me'
        self.resp = u'me'
        self.user_key = PKEY_FILENAME
        self.user_pub_key = PUB_FILE
        self.user_ca_key = USER_CERT_PRIV_KEY
        self.user_cert_file = USER_CERT_FILE
        self.user = USER
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))
        self.sock = sock
        self.session = Session()
        self.session.options_set(options.HOST, self.host)
        self.session.options_set_port(self.port)
        self.session.options_set(options.USER, self.user)
        self.session.set_socket(sock)
        self.pkey = import_privkey_file(self.user_key)
        # self.session.options_set(options.LOG_VERBOSITY, '1')

    def tearDown(self):
        del self.session

    def _auth(self):
        self.assertEqual(self.session.connect(), 0)
        self.assertEqual(
            self.session.userauth_publickey(self.pkey), 0)
