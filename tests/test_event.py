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

import socket

from ssh.session import Session
from ssh.event import Event
from ssh.callbacks import Callbacks
from ssh.exceptions import SSHError

from .base_case import SSHTestCase


class CallbacksTest(SSHTestCase):

    def test_callbacks(self):
        session = Session()
        cb = Callbacks()
        self.assertEqual(cb.set_callbacks(session), 0)


class EventTest(SSHTestCase):

    def test_event_session(self):
        event = Event()
        self.assertIsInstance(event, Event)

    def test_event_connector(self):
        session = Session()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        event = Event()
        self.assertEqual(event.add_fd(sock, 1), 0)
        self.assertEqual(sock, event.socket)
        self.assertEqual(event.remove_fd(sock), 0)
        self.assertIsNone(event.socket)
        self.assertEqual(event.add_fd(sock, 1, callback=lambda: 1), 0)
        connector = session.connector_new()
        self.assertIsNone(event.connector)
        self.assertRaises(SSHError, event.add_connector, connector)
        self.assertIsNone(event.connector)
        self.assertEqual(event.remove_connector(connector), 0)
        self.assertIsNone(event.connector)
