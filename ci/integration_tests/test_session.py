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

from .base_case import SSHTestCase


class SessionTest(SSHTestCase):

    def test_non_blocking_connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))
        session = Session()
        session.options_set(options.USER, self.user)
        session.options_set(options.HOST, self.host)
        session.options_set_port(self.port)
        self.assertEqual(session.set_socket(sock), 0)
        session.set_blocking(0)
        rc = session.connect()
        while rc == SSH_AGAIN:
            wait_socket(session, sock)
            rc = session.connect()
        self.assertEqual(rc, 0)
        rc = session.userauth_publickey(self.pkey)
        while rc == SSH_AUTH_AGAIN:
            wait_socket(session, sock)
            rc = session.userauth_publickey(self.pkey)
        self.assertEqual(rc, 0)

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
        session.connector_new()

    def test_disconnect(self):
        self._auth()
        chan = self.session.channel_new()
        self.assertEqual(chan.open_session(), 0)
        chan.close()
        self.session.disconnect()
        del chan

    def test_socket_connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))
        session = Session()
        session.options_set(options.USER, self.user)
        session.options_set(options.HOST, self.host)
        session.options_set_port(self.port)
        self.assertEqual(session.set_socket(sock), 0)
        self.assertEqual(session.connect(), 0)
        self.assertRaises(AuthenticationDenied, session.userauth_none)
        self.assertEqual(
            session.userauth_publickey(self.pkey), 0)

    def test_connect(self):
        self.assertEqual(self.session.connect(), 0)
        self.assertRaises(AuthenticationDenied, self.session.userauth_none)
        self.assertRaises(
            AuthenticationDenied, self.session.userauth_publickey_auto, '')

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

    def test_cert_auth(self):
        self.assertEqual(self.session.connect(), 0)
        cert_key = import_cert_file(self.user_cert_file)
        self.assertIsInstance(cert_key, SSHKey)
        key_type = cert_key.key_type()
        self.assertIsInstance(key_type, RSACert01Key)
        cert_priv_key = import_privkey_file(self.user_ca_key)
        copy_cert_to_privkey(cert_key, cert_priv_key)
        self.assertEqual(self.session.userauth_try_publickey(cert_key), 0)
        self.assertEqual(self.session.userauth_publickey(cert_priv_key), 0)
        chan = self.session.channel_new()
        self.assertIsInstance(chan, Channel)

    def test_cert_imports(self):
        self.assertRaises(KeyImportError, import_cert_file, self.user_key)
        priv_key = SSHKey()
        cert_key = import_cert_file(self.user_cert_file)
        self.assertRaises(KeyImportError, copy_cert_to_privkey, cert_key, priv_key)
        with open(self.user_cert_file, 'rb') as fh:
            cert_key_data = base64.b64encode(fh.read())
            # cert_key_data = fh.read()
        rsa_cert = RSACert01Key()
        self.assertIsNotNone(rsa_cert.value)
        # Failing
        # cert_key_b64 = import_cert_base64(cert_key_data, rsa_cert)
        # self.assertIsInstance(cert_key_b64.key_type(), RSACert01Key)

    def test_open_channel(self):
        self._auth()
        chan = self.session.channel_new()
        self.assertIsInstance(chan, Channel)

    def test_scp_push(self):
        self._auth()
        scp = self.session.scp_new(SSH_SCP_WRITE, 'test_file')
        self.assertIsInstance(scp, SCP)
        test_data = b"data\n"
        remote_filename = os.sep.join([os.path.dirname(__file__),
                                       "remote_test_file"])
        to_copy = os.sep.join([os.path.dirname(__file__),
                               "copied"])
        with open(remote_filename, 'wb') as fh:
            fh.write(test_data)
        try:
            fileinfo = os.stat(remote_filename)
            scp.push_file64(to_copy, fileinfo.st_size, fileinfo.st_mode & 0o777)
            scp.write(test_data)
            del scp
        finally:
            os.unlink(remote_filename)

    def test_gssapi_creds(self):
        self.session.connect()
        rc = self.session.options_set(options.GSSAPI_SERVER_IDENTITY, 'identity')
        self.assertEqual(rc, 0)
        rc = self.session.options_set(options.GSSAPI_CLIENT_IDENTITY, 'my_id')
        self.assertEqual(rc, 0)
        rc = self.session.options_set_gssapi_delegate_credentials(True)
        self.assertEqual(rc, 0)
        self.assertRaises(AuthenticationDenied, self.session.userauth_gssapi)
        rc = self.session.options_set_gssapi_delegate_credentials(False)
        self.assertEqual(rc, 0)
        self.assertRaises(AuthenticationDenied, self.session.userauth_gssapi)

    def test_agent_auth(self):
        self.session.connect()
        self.assertRaises(
            AuthenticationDenied, self.session.userauth_agent, self.user)

    def test_set_timeout(self):
        session = Session()
        self.assertEqual(session.options_set(options.TIMEOUT, "1000"), 0)
        self.assertEqual(session.options_set(options.TIMEOUT_USEC, "1000"), 0)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))
        session = Session()
        session.options_set(options.USER, self.user)
        session.options_set(options.HOST, self.host)
        session.options_set_port(self.port)
        self.assertEqual(session.set_socket(sock), 0)
        self.assertEqual(session.options_set(options.TIMEOUT, "1000"), 0)
        self.assertEqual(session.options_set(options.TIMEOUT_USEC, "1000"), 0)

    def test_get_server_publickey(self):
        self.session.connect()
        self.assertIsInstance(self.session.get_server_publickey(), SSHKey)
