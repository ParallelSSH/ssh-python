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

from .base_test import SSHTestCase

from ssh.session import Session
from ssh.channel import Channel
from ssh.key import SSHKey, import_pubkey_file, import_privkey_file
from ssh import options
from ssh.exceptions import RequestDenied, KeyImportError, InvalidAPIUse


class SessionTest(SSHTestCase):

    def test_should_not_segfault(self):
        session = Session()
        self.assertEqual(session.get_error(), '')
        self.assertRaises(InvalidAPIUse, session.userauth_none)
        self.assertRaises(InvalidAPIUse, session.userauth_publickey, self.pkey)
        key = import_pubkey_file(self.user_pub_key)
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

    def test_socket_connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))
        session = Session()
        session.options_set(options.USER, self.user)
        session.options_set(options.HOST, self.host)
        session.options_set_port(self.port)
        self.assertEqual(session.set_socket(sock), 0)
        self.assertEqual(session.connect(), 0)
        self.assertRaises(RequestDenied, session.userauth_none)
        self.assertEqual(
            session.userauth_publickey(self.pkey), 0)

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

    def test_open_channel(self):
        self._auth()
        chan = self.session.channel_new()
        self.assertIsInstance(chan, Channel)
