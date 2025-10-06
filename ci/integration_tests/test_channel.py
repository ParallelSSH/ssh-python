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
from pytest import mark
from time import sleep

from ssh.key import SSHKey, import_pubkey_file, import_privkey_file
from ssh import options
from ssh.exceptions import KeyImportError
from ssh.utils import wait_socket
from ssh.error_codes import SSH_AGAIN
from ssh.exceptions import EOF, SSHError

from .base_case import SSHTestCase


class ChannelTest(SSHTestCase):

    def test_close(self):
        self._auth()
        chan = self.session.channel_new()
        self.assertEqual(chan.open_session(), 0)
        self.assertFalse(chan.closed)
        chan.request_exec('echo me')
        chan.read()
        self.assertFalse(chan.closed)
        chan.close()
        self.assertTrue(chan.closed)
        chan.close()
        self.session.disconnect()
        chan.close()

    def test_channel_exec(self):
        self._auth()
        chan = self.session.channel_new()
        self.assertEqual(chan.open_session(), 0)
        self.assertTrue(chan.is_open())
        self.assertFalse(chan.is_closed())
        self.assertEqual(chan.request_exec(self.cmd), 0)
        self.assertFalse(chan.is_eof())
        self.assertFalse(chan.is_closed())
        all_data = b""
        size, data = chan.read()
        while size > 0:
            all_data += data
            try:
                size, data = chan.read()
            except SSHError:
                break
        lines = [s.decode('utf-8') for s in all_data.splitlines()]
        self.assertEqual(lines[0], self.resp)
        sleep(1)
        self.assertTrue(chan.is_eof())
        self.assertEqual(chan.close(), 0)
        self.assertFalse(chan.is_open())
        self.assertTrue(chan.is_closed())

    def test_channel_non_blocking_exec(self):
        self._auth()
        self.session.set_blocking(0)
        chan = self.session.channel_new()
        while chan == SSH_AGAIN:
            wait_socket(self.session, self.sock)
            chan = self.session.channel_new()
        chan.set_blocking(0)
        rc = chan.open_session()
        while rc == SSH_AGAIN:
            wait_socket(self.session, self.sock)
            rc = chan.open_session()
        self.assertEqual(rc, 0)
        self.assertTrue(chan.is_open())
        self.assertFalse(chan.is_closed())
        rc = chan.request_exec(self.cmd)
        while rc == SSH_AGAIN:
            wait_socket(self.session, self.sock)
            rc = chan.request_exec(self.cmd)
        self.assertEqual(rc, 0)
        self.assertFalse(chan.is_eof())
        self.assertFalse(chan.is_closed())
        all_data = b""
        while True:
            try:
                if chan.poll():
                    wait_socket(self.session, self.sock)
                size, data = chan.read_nonblocking()
                if size > 0:
                    all_data += data
            except EOF:
                break
        lines = [s.decode('utf-8') for s in all_data.splitlines()]
        self.assertEqual(lines[0], self.resp)
        self.assertRaises(EOF, chan.poll)
        self.assertTrue(chan.is_eof())
        rc = chan.close()
        while rc == SSH_AGAIN:
            wait_socket(self.session, self.sock)
            rc = chan.close()
        self.assertEqual(rc, 0)
        self.assertFalse(chan.is_open())
        self.assertTrue(chan.is_closed())

    def test_exit_code(self):
        self._auth()
        chan = self.session.channel_new()
        self.assertEqual(chan.open_session(), 0)
        self.assertEqual(chan.request_exec('exit 2'), 0)
        self.assertEqual(chan.send_eof(), 0)
        self.assertEqual(chan.close(), 0)
        status = chan.get_exit_status()
        self.assertEqual(status, 2)

    def test_exit_state(self):
        self._auth()
        chan = self.session.channel_new()
        self.assertEqual(chan.open_session(), 0)
        self.assertEqual(chan.request_exec('exit 2'), 0)
        self.assertEqual(chan.send_eof(), 0)
        self.assertEqual(chan.close(), 0)
        exit_code, signal, pcore_dumped = chan.get_exit_state()
        self.assertEqual(exit_code, 2)

    def test_exit_state_w_signal(self):
        self._auth()
        chan = self.session.channel_new()
        my_sig = 'TERM'
        chan.open_session()
        chan.request_exec('sleep 5 && exit 0')
        chan.send_eof()
        chan.request_send_signal(my_sig)
        chan.close()
        exit_code, signal, pcore_dumped = chan.get_exit_state()
        self.assertNotEqual(exit_code, 0)
        self.assertEqual(signal, bytes(my_sig, 'utf-8'))

    def test_exit_state_w_signal_non_blocking(self):
        self._auth()
        chan = self.session.channel_new()
        my_sig = 'TERM'
        chan.open_session()
        chan.request_exec('sleep 5 && exit 0')
        chan.send_eof()
        chan.request_send_signal(my_sig)
        chan.close()
        self.session.set_blocking(0)
        exit_code, signal, pcore_dumped = chan.get_exit_state()
        while exit_code == SSH_AGAIN:
            self.assertEqual(signal, b"")
            self.assertFalse(pcore_dumped)
            wait_socket(self.session, self.sock)
            exit_code, signal, pcore_dumped = chan.get_exit_state()
        self.assertNotEqual(exit_code, 0)
        self.assertEqual(signal, bytes(my_sig, 'utf-8'))

    def test_long_running_execute(self):
        self._auth()
        chan = self.session.channel_new()
        self.assertEqual(chan.open_session(), 0)
        self.assertEqual(chan.request_exec('sleep 1; exit 3'), 0)
        chan.send_eof()
        self.assertEqual(chan.close(), 0)
        self.assertEqual(chan.get_exit_status(), 3)

    def test_read_stderr(self):
        self._auth()
        chan = self.session.channel_new()
        self.assertEqual(chan.open_session(), 0)
        expected = ['stderr output']
        chan.request_exec('echo "stderr output" >&2')
        size, data = chan.read(is_stderr=True)
        self.assertTrue(size > 0)
        lines = [s.decode('utf-8') for s in data.splitlines()]
        self.assertListEqual(expected, lines)

    def test_pty(self):
        self._auth()
        chan = self.session.channel_new()
        chan.open_session()
        self.assertTrue(chan.request_pty() == 0)
        _out = u'stderr output'
        expected = [_out]
        chan.request_exec(u'echo "%s" >&2' % (_out,))
        # stderr output gets redirected to stdout with a PTY
        size, data = chan.read()
        self.assertTrue(size > 0)
        lines = [s.decode('utf-8') for s in data.splitlines()]
        self.assertListEqual(expected, lines)

    def test_write_stdin(self):
        self._auth()
        _in = u'writing to stdin'
        chan = self.session.channel_new()
        chan.open_session()
        chan.request_exec('cat')
        chan.write(_in + '\n')
        self.assertEqual(chan.send_eof(), 0)
        size, data = chan.read()
        self.assertTrue(size > 0)
        lines = [line.decode('utf-8') for line in data.splitlines()]
        self.assertListEqual([_in], lines)
        chan.close()
        chan.read()
        self.assertTrue(chan.is_eof())

    def test_write_stderr(self):
        self._auth()
        chan = self.session.channel_new()
        chan.open_session()
        chan.request_exec('echo something')
        _in = u'stderr'
        rc, bytes_written = chan.write_stderr(_in + '\n')
        self.assertEqual(rc, 7)
        self.assertEqual(bytes_written, 7)
        self.assertEqual(chan.close(), 0)
