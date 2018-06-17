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

from c_ssh cimport ssh_scp, ssh_scp_request_types, ssh_channel, uint64_t, \
    ssh_session

cdef extern from "libssh/scp.h" nogil:
    enum ssh_scp_states:
        SSH_SCP_NEW,
        SSH_SCP_WRITE_INITED,
        SSH_SCP_WRITE_WRITING,
        SSH_SCP_READ_INITED,
        SSH_SCP_READ_REQUESTED,
        SSH_SCP_READ_READING,
        SSH_SCP_ERROR,
        SSH_SCP_TERMINATED

    struct ssh_scp_struct:
        ssh_session session
        int mode
        int recursive
        ssh_channel channel
        char *location
        ssh_scp_states state
        uint64_t filelen
        uint64_t processed
        ssh_scp_request_types request_type
        char *request_name
        char *warning
        int request_mode
    int ssh_scp_read_string(ssh_scp scp, char *buffer, size_t len)
    int ssh_scp_integer_mode(const char *mode)
    char *ssh_scp_string_mode(int mode)
    int ssh_scp_response(ssh_scp scp, char **response)
