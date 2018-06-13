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

# cimport c_callbacks

from c_ssh cimport uint32_t

cdef extern from "libssh/include/auth.h" nogil:
    struct ssh_kbdint_struct:
        uint32_t nprompts
        uint32_t nanswers
        char *name
        char *instruction
        char **prompts
        unsigned char *echo
        char **answers
    ctypedef ssh_kbdint_struct *ssh_kbdint
    ssh_kbdint ssh_kbdint_new();
    void ssh_kbdint_clean(ssh_kbdint kbd)
    void ssh_kbdint_free(ssh_kbdint kbd)
    enum ssh_auth_state_e:
        SSH_AUTH_STATE_NONE
        SSH_AUTH_STATE_PARTIAL
        SSH_AUTH_STATE_SUCCESS
        SSH_AUTH_STATE_FAILED
        SSH_AUTH_STATE_ERROR
        SSH_AUTH_STATE_INFO
        SSH_AUTH_STATE_PK_OK
        SSH_AUTH_STATE_KBDINT_SENT
        SSH_AUTH_STATE_GSSAPI_REQUEST_SENT
        SSH_AUTH_STATE_GSSAPI_TOKEN
        SSH_AUTH_STATE_GSSAPI_MIC_SENT
    enum ssh_auth_service_state_e:
        SSH_AUTH_SERVICE_NONE
        SSH_AUTH_SERVICE_SENT
        SSH_AUTH_SERVICE_ACCEPTED
        SSH_AUTH_SERVICE_DENIED
        SSH_AUTH_SERVICE_USER_SENT
