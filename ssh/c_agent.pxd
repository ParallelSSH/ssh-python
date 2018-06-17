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

cdef extern from "libssh/agent.h" nogil:
    # Messages for the authentication agent connection.
    enum:
        SSH_AGENTC_REQUEST_RSA_IDENTITIES
        SSH_AGENT_RSA_IDENTITIES_ANSWER
        SSH_AGENTC_RSA_CHALLENGE
        SSH_AGENT_RSA_RESPONSE
        SSH_AGENT_FAILURE
        SSH_AGENT_SUCCESS
        SSH_AGENTC_ADD_RSA_IDENTITY
        SSH_AGENTC_REMOVE_RSA_IDENTITY
        SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES

    # private OpenSSH extensions for SSH2
    enum:
        SSH2_AGENTC_REQUEST_IDENTITIES
        SSH2_AGENT_IDENTITIES_ANSWER
        SSH2_AGENTC_SIGN_REQUEST
        SSH2_AGENT_SIGN_RESPONSE
        SSH2_AGENTC_ADD_IDENTITY
        SSH2_AGENTC_REMOVE_IDENTITY
        SSH2_AGENTC_REMOVE_ALL_IDENTITIES

    enum:
        SSH_AGENTC_ADD_SMARTCARD_KEY
        SSH_AGENTC_REMOVE_SMARTCARD_KEY
        SSH_AGENTC_LOCK
        SSH_AGENTC_UNLOCK
        SSH_AGENTC_ADD_RSA_ID_CONSTRAINED
        SSH2_AGENTC_ADD_ID_CONSTRAINED
        SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED
        SSH_AGENT_CONSTRAIN_LIFETIME
        SSH_AGENT_CONSTRAIN_CONFIRM
        SSH2_AGENT_FAILURE
        SSH_COM_AGENT2_FAILURE
        SSH_AGENT_OLD_SIGNATURE

    struct ssh_socket_struct:
        pass

    struct ssh_agent_struct:
        ssh_socket_struct *sock
        c_ssh.ssh_buffer ident
        unsigned int count
        c_ssh.ssh_channel channel

    ssh_agent_struct *ssh_agent_new(c_ssh.ssh_session_struct *session)
    void ssh_agent_close(c_ssh.ssh_agent_struct *agent)
    void ssh_agent_free(c_ssh.ssh_agent_struct *agent)
    int ssh_agent_is_running(c_ssh.ssh_session_struct *session)
    int ssh_agent_get_ident_count(c_ssh.ssh_session_struct *session)
    c_ssh.ssh_key ssh_agent_get_next_ident(c_ssh.ssh_session_struct *session,
                                           char **comment)
    c_ssh.ssh_key ssh_agent_get_first_ident(c_ssh.ssh_session_struct *session,
                                            char **comment)
    c_ssh.ssh_string ssh_agent_sign_data(c_ssh.ssh_session session,
                                         const c_ssh.ssh_key pubkey,
                                         c_ssh.ssh_buffer_struct *data)
