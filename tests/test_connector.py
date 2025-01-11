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

from ssh.connector import Connector
from ssh.session import Session

from .base_case import SSHTestCase


class ConnectorTest(SSHTestCase):

    def test_connector(self):
        session = Session()
        connector = session.connector_new()
        self.assertIsInstance(connector, Connector)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.assertIsNone(connector.set_in_fd(sock))
        self.assertIsNone(connector.set_out_fd(sock))
