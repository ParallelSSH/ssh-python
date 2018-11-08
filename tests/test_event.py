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
from ssh import options
from ssh.event import Event
from ssh.callbacks import Callbacks
from ssh.connector import CONNECTOR_STDOUT, CONNECTOR_STDERR, \
    CONNECTOR_BOTH
from ssh.exceptions import SSHError


class CallbacksTest(SSHTestCase):

    def test_callbacks(self):
        cb = Callbacks()
        self.assertEqual(cb.set_callbacks(self.session), 0)


class EventTest(SSHTestCase):

    def test_event_session(self):
        self._auth()
        event = Event()
        self.assertIsInstance(event, Event)
        self.assertEqual(event.add_session(self.session), 0)
        self.assertEqual(self.session, event.session)
        self.assertEqual(event.remove_session(self.session), 0)
        self.assertIsNone(event.session)

    def test_event_connector(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        event = Event()
        self.assertEqual(event.add_fd(sock, 1), 0)
        self.assertEqual(sock, event.socket)
        self.assertEqual(event.remove_fd(sock), 0)
        self.assertIsNone(event.socket)
        self.assertEqual(event.add_fd(sock, 1, callback=lambda: 1), 0)
        connector = self.session.connector_new()
        self.assertIsNone(event.connector)
        self.assertRaises(SSHError, event.add_connector, connector)
        self.assertIsNone(event.connector)
        self.assertEqual(event.remove_connector(connector), 0)
        self.assertIsNone(event.connector)
