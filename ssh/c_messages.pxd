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

from c_ssh cimport ssh_session, ssh_string, ssh_message, ssh_channel, uint32_t, uint16_t, \
    uint8_t, ssh_key_struct, ssh_buffer

cdef extern from "libssh/messages.h" nogil:
    struct ssh_auth_request:
        char *username
        int method
        char *password
        ssh_key_struct *pubkey
        char signature_state
        char kbdint_response

    struct ssh_channel_request_open:
        int type
        uint32_t sender
        uint32_t window
        uint32_t packet_size
        char *originator
        uint16_t originator_port
        char *destination
        uint16_t destination_port

    struct ssh_service_request:
        char *service

    struct ssh_global_request:
        int type
        uint8_t want_reply
        char *bind_address
        uint16_t bind_port

    struct ssh_channel_request:
        int type
        ssh_channel channel
        uint8_t want_reply
        char *TERM
        uint32_t width
        uint32_t height
        uint32_t pxwidth
        uint32_t pxheight
        ssh_string modes
        char *var_name
        char *var_value
        char *command
        char *subsystem
        uint8_t x11_single_connection
        char *x11_auth_protocol
        char *x11_auth_cookie
        uint32_t x11_screen_number

    struct ssh_message_struct:
        ssh_session session
        int type
        ssh_auth_request auth_request
        ssh_channel_request_open channel_request_open
        ssh_channel_request channel_request
        ssh_service_request service_request
        ssh_global_request global_request

    int ssh_message_handle_channel_request(ssh_session session, ssh_channel channel, ssh_buffer packet,
                                           const char *request, uint8_t want_reply)
    void ssh_message_queue(ssh_session session, ssh_message message)
    ssh_message ssh_message_pop_head(ssh_session session)
    int ssh_message_channel_request_open_reply_accept_channel(ssh_message msg, ssh_channel chan)
