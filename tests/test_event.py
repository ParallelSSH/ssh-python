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
from ssh.connector import CONNECTOR_STDOUT, CONNECTOR_STDERR, \
    CONNECTOR_BOTH


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
        sock.connect((self.host, self.port))
        session = Session()
        session.options_set(options.USER, self.user)
        session.options_set(options.HOST, self.host)
        session.options_set_port(self.port)
        self.assertEqual(session.set_socket(sock), 0)
        self.assertEqual(session.connect(), 0)
        self.assertEqual(
            session.userauth_publickey(self.pkey), 0)
        
        event = Event()
        connector = session.connector_new()
        chan = session.channel_new()
        connector.set_in_channel(chan, CONNECTOR_STDOUT)
        connector.set_out_fd(sock)
        self.assertEqual(event.add_connector(connector), 0)
        # self.assertEqual(connector, event.connector)
        # self.assertEqual(event.remove_connector(connector), 0)
        # self.assertIsNone(event.connector)
