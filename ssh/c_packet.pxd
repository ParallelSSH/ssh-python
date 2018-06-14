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

from c_ssh cimport ssh_session, ssh_buffer, uint32_t, uint8_t
from c_wrapper cimport ssh_hmac_e
from c_callbacks cimport ssh_packet_callbacks

cdef extern from "libssh/include/packet.h" nogil:
    struct ssh_socket_struct:
        pass
    struct packet_struct:
        int valid
        uint32_t len
        uint8_t type
    ctypedef packet_struct PACKET
    enum ssh_packet_state_e:
        PACKET_STATE_INIT,
        PACKET_STATE_SIZEREAD,
        PACKET_STATE_PROCESSING
    int ssh_packet_send(ssh_session session)
    int ssh_packet_send_unimplemented(ssh_session session, uint32_t seqnum)
    int ssh_packet_parse_type(ssh_session session)

    int ssh_packet_socket_callback(const void *data, size_t len, void *user)
    void ssh_packet_register_socket_callback(ssh_session session,
                                             ssh_socket_struct *s)
    void ssh_packet_set_callbacks(ssh_session session,
                                  ssh_packet_callbacks callbacks)
    void ssh_packet_set_default_callbacks(ssh_session session)
    void ssh_packet_process(ssh_session session, uint8_t type)
    uint32_t ssh_packet_decrypt_len(ssh_session session, char *crypted)
    int ssh_packet_decrypt(ssh_session session, void *packet, unsigned int len)
    unsigned char *ssh_packet_encrypt(ssh_session session,
                                      void *packet,
                                      unsigned int len)
    int ssh_packet_hmac_verify(ssh_session session, ssh_buffer buffer,
                               unsigned char *mac, ssh_hmac_e type)
