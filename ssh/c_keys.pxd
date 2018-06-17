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

from c_ssh cimport ssh_session, ssh_string

cdef extern from "libssh/keys.h" nogil:
    struct ssh_public_key_struct:
        int type
        const char *type_c
    struct ssh_private_key_struct:
        int type
    ctypedef ssh_public_key_struct* ssh_public_key
    const char *ssh_type_to_char(int type)
    int ssh_type_from_name(const char *name)
    ssh_public_key publickey_from_string(ssh_session session, ssh_string pubkey_s)
