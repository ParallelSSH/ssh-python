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

cimport c_ssh
from c_ssh cimport uint32_t, ssh_channel, ssh_session, ssh_buffer, ssh_counter
from c_misc cimport ssh_list
# cimport c_priv

cdef extern from "libssh/include/channels.h" nogil:
    enum ssh_channel_request_state_e:
        SSH_CHANNEL_REQ_STATE_NONE,
        SSH_CHANNEL_REQ_STATE_PENDING,
        SSH_CHANNEL_REQ_STATE_ACCEPTED,
        SSH_CHANNEL_REQ_STATE_DENIED,
        SSH_CHANNEL_REQ_STATE_ERROR

    enum ssh_channel_state_e:
        SSH_CHANNEL_STATE_NOT_OPEN,
        SSH_CHANNEL_STATE_OPENING,
        SSH_CHANNEL_STATE_OPEN_DENIED,
        SSH_CHANNEL_STATE_OPEN,
        SSH_CHANNEL_STATE_CLOSED

    enum:
        SSH_CHANNEL_FLAG_CLOSED_REMOTE
        SSH_CHANNEL_FLAG_FREED_LOCAL
        SSH_CHANNEL_FLAG_NOT_BOUND

    struct ssh_channel_struct:
        ssh_session session
        uint32_t local_channel
        uint32_t local_window
        int local_eof
        uint32_t local_maxpacket
        uint32_t remote_channel
        uint32_t remote_window
        int remote_eof
        uint32_t remote_maxpacket
        ssh_channel_state_e state
        int delayed_close
        int flags
        ssh_buffer stdout_buffer
        ssh_buffer stderr_buffer
        void *userarg
        int version
        int exit_status
        ssh_channel_request_state_e request_state
        ssh_list *callbacks
        ssh_counter counter

    c_ssh.ssh_channel ssh_channel_new(c_ssh.ssh_session session)
    int channel_default_bufferize(c_ssh.ssh_channel channel, void *data, int len,
                                  int is_stderr)
    int ssh_channel_flush(c_ssh.ssh_channel channel)
    uint32_t ssh_channel_new_id(c_ssh.ssh_session session)
    c_ssh.ssh_channel ssh_channel_from_local(c_ssh.ssh_session session, c_ssh.uint32_t id)
    void ssh_channel_do_free(c_ssh.ssh_channel channel)
