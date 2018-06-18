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

from .base_test import SSHTestCase

from ssh.channel import Channel
from ssh.key import SSHKey, import_pubkey_file, import_privkey_file
from ssh import options
from ssh.exceptions import RequestDenied, KeyImportError


class ChannelTest(SSHTestCase):

    def test_channel_exec(self):
        self._auth()
        chan = self.session.channel_new()
        self.assertEqual(chan.open_session(), 0)
        self.assertTrue(chan.is_open())
        self.assertFalse(chan.is_closed())
        self.assertEqual(chan.request_exec(self.cmd), 0)
        self.assertFalse(chan.is_eof())
        self.assertFalse(chan.is_closed())
        all_data = ""
        size, data = chan.read()
        while size > 0:
            all_data += data
            size, data = chan.read()
        lines = [s.decode('utf-8') for s in all_data.splitlines()]
        self.assertEqual(lines[0], self.resp)
        self.assertTrue(chan.is_eof())
        self.assertFalse(chan.is_open())
        self.assertTrue(chan.is_closed())
        self.assertEqual(chan.close(), 0)
        
    def test_exit_code(self):
        self._auth()
        chan = self.session.channel_new()
        self.assertEqual(chan.open_session(), 0)
        self.assertEqual(chan.request_exec('exit 2'), 0)
        self.assertEqual(chan.send_eof(), 0)
        self.assertEqual(chan.close(), 0)
        status = chan.get_exit_status()
        self.assertEqual(status, 2)
    
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
