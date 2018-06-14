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

from c_ssh cimport ssh_session, ssh_buffer, ssh_string, uint8_t

cdef extern from "libssh/include/callbacks.h" nogil:
    ctypedef ssh_string (*void) (ssh_session, const char*,
                                 int, ssh_string *, void *)
    ctypedef int (*ssh_packet_callback) (ssh_session session, uint8_t type, ssh_buffer packet, void *user)
    struct ssh_packet_callbacks_struct:
        uint8_t start
        uint8_t n_callbacks
        void *user
    ctypedef ssh_packet_callbacks_struct *ssh_packet_callbacks
