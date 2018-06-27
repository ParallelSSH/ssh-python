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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

from select import select

from session cimport Session

from c_ssh cimport SSH_READ_PENDING, SSH_WRITE_PENDING, ssh_get_poll_flags


def wait_socket(_socket not None, Session session, timeout=1):
    """Helper function for testing non-blocking mode.

    This function blocks the calling thread for <timeout> seconds -
    to be used only for testing purposes.
    """
    cdef int directions = ssh_get_poll_flags(session._session)
    if directions == 0:
        return 0
    readfds = (_socket,) \
        if (directions & SSH_READ_PENDING) else ()
    writefds = (_socket,) \
        if (directions & SSH_WRITE_PENDING) else ()
    return select(readfds, writefds, (), timeout)
