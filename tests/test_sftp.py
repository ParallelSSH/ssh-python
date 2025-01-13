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

from ssh.sftp import SFTP

from .base_case import SSHTestCase


class SFTPTest(SSHTestCase):

    def test_sftp_init(self):
        sftp = SFTP()
        self.assertIsInstance(sftp, SFTP)
        del sftp
        sftp = SFTP()
        self.assertEqual(sftp.init(), 0)
