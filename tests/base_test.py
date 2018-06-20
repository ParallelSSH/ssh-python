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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

import unittest
import pwd
import os
# import socket
from sys import version_info

from .embedded_server.openssh import OpenSSHServer
from ssh.session import Session
from ssh.key import import_privkey_file
from ssh import options


PKEY_FILENAME = os.path.sep.join([os.path.dirname(__file__), 'unit_test_key'])
PUB_FILE = "%s.pub" % (PKEY_FILENAME,)


class SSHTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        _mask = int('0600') if version_info <= (2,) else 0o600
        os.chmod(PKEY_FILENAME, _mask)
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
        self.user = pwd.getpwuid(os.geteuid()).pw_name
        # sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # sock.connect((self.host, self.port))
        # self.sock = sock
        self.session = Session()
        self.session.options_set(options.HOST, self.host)
        self.session.options_set_port(self.port)
        self.session.options_set(options.USER, self.user)
        self.pkey = import_privkey_file(self.user_key)
        # self.session.options_set(options.LOG_VERBOSITY, '1')

    def tearDown(self):
        del self.session

    def _auth(self):
        self.assertEqual(self.session.connect(), 0)
        self.assertEqual(
            self.session.userauth_publickey(self.pkey), 0)
