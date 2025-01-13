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
import socket
import os
import base64
from select import select

from ssh.session import Session, SSH_AUTH_AGAIN, SSH_READ_PENDING, SSH_WRITE_PENDING
from ssh.channel import Channel
from ssh.key import SSHKey, import_pubkey_file, import_privkey_file, import_cert_file, \
    import_cert_base64, copy_cert_to_privkey
from ssh.keytypes import RSACert01Key
from ssh import options
from ssh.exceptions import KeyImportError, InvalidAPIUse, \
    AuthenticationDenied
from ssh.scp import SCP, SSH_SCP_READ, SSH_SCP_WRITE, SSH_SCP_RECURSIVE
from ssh.error_codes import SSH_AGAIN
from ssh.utils import wait_socket

from .base_case import SSHTestCase, PUB_FILE


class SessionTest(SSHTestCase):

    def test_should_not_segfault(self):
        session = Session()
        self.assertEqual(session.get_error(), '')
        self.assertRaises(InvalidAPIUse, session.userauth_none)
        self.assertRaises(InvalidAPIUse, session.userauth_publickey, import_pubkey_file(PUB_FILE))
        key = import_pubkey_file(PUB_FILE)
        self.assertRaises(InvalidAPIUse, session.userauth_try_publickey, key)
        self.assertRaises(InvalidAPIUse, session.userauth_publickey_auto, '')
        self.assertRaises(InvalidAPIUse, session.channel_new)
        self.assertRaises(InvalidAPIUse, session.get_disconnect_message)
        self.assertRaises(InvalidAPIUse, session.get_issue_banner)
        self.assertRaises(InvalidAPIUse, session.get_openssh_version)
        self.assertIsNone(session.dump_knownhost())
        self.assertIsNone(session.get_clientbanner())
        self.assertIsNone(session.get_serverbanner())
        self.assertIsNone(session.get_kex_algo())
        self.assertIsNone(session.get_cipher_in())
        self.assertIsNone(session.get_cipher_out())
        self.assertIsNone(session.get_hmac_in())
        self.assertIsNone(session.get_hmac_out())
        self.assertIsNotNone(session.get_error_code())
        session.connector_new()

    def test_set_timeout(self):
        session = Session()
        self.assertEqual(session.options_set(options.TIMEOUT, "1000"), 0)
        self.assertEqual(session.options_set(options.TIMEOUT_USEC, "1000"), 0)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        session = Session()
        session.options_set(options.USER, 'a user')
        session.options_set(options.HOST, self.host)
        session.options_set_port(self.port)
        self.assertEqual(session.set_socket(sock), 0)
        self.assertEqual(session.options_set(options.TIMEOUT, "1000"), 0)
        self.assertEqual(session.options_set(options.TIMEOUT_USEC, "1000"), 0)
