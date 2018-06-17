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

from ssh.session import Session
from ssh import options
from ssh.exceptions import RequestDenied


class SessionTest(SSHTestCase):

    def test_connect(self):
        self.assertEqual(self.session.connect(), 0)
        self.assertRaises(RequestDenied, self.session.userauth_none)
        self.assertRaises(
            RequestDenied, self.session.userauth_publickey_auto, self.user, '')
