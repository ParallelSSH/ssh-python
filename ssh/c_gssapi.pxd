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

from c_ssh cimport ssh_session, ssh_buffer, uint32_t, uint8_t, ssh_keytypes_e
from c_wrapper cimport ssh_hmac_e
from c_callbacks cimport ssh_packet_callbacks
from c_ed25519 cimport ed25519_pubkey, ed25519_privkey

cdef extern from "libssh/gssapi.h" nogil:
    enum:
        SSH_OID_TAG
    struct ssh_gssapi_struct:
        pass
    ctypedef ssh_gssapi_struct *ssh_gssapi;
