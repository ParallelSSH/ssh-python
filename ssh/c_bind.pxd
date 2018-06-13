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

cimport c_priv
cimport c_session


cdef extern from "libssh/include/bind.h" nogil:
    struct ssh_bind_struct:
        ssh_common_struct common
        ssh_bind_callbacks_struct *bind_callbacks
        void *bind_callbacks_userdata
        ssh_poll_handle_struct *poll
        char *wanted_methods[10]
        char *banner
        char *ecdsakey
        char *dsakey
        char *rsakey
        char *ed25519key
        ssh_key ecdsa
        ssh_key dsa
        ssh_key rsa
        ssh_key ed25519
        char *bindaddr
        socket_t bindfd
        unsigned int bindport
        int blocking
        int toaccept
    ssh_poll_handle_struct *ssh_bind_get_poll(ssh_bind_struct *sshbind)
