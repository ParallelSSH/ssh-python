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

from c_ssh cimport ssh_session, ssh_buffer, ssh_string, uint32_t, uint8_t, \
    ssh_keytypes_e, ssh_counter, ssh_message, ssh_agent, socket_t, ssh_key
from c_poll cimport ssh_poll_ctx
from c_callbacks cimport ssh_packet_callbacks, ssh_packet_callbacks_struct, \
    ssh_socket_callbacks_struct, ssh_server_callbacks, ssh_callbacks
from c_misc cimport ssh_list
from c_gssapi cimport ssh_gssapi_struct
from c_auth cimport ssh_kbdint_struct
from c_crypto cimport ssh_crypto_struct
from c_channels cimport ssh_channel_request_state_e
from c_auth cimport ssh_auth_state_e, ssh_auth_service_state_e
from c_packet cimport PACKET
from c_socket cimport ssh_socket_struct
from c_priv cimport error_struct

cdef extern from "libssh/session.h" nogil:
    enum ssh_session_state_e:
        SSH_SESSION_STATE_NONE,
        SSH_SESSION_STATE_CONNECTING,
        SSH_SESSION_STATE_SOCKET_CONNECTED,
        SSH_SESSION_STATE_BANNER_RECEIVED,
        SSH_SESSION_STATE_INITIAL_KEX,
        SSH_SESSION_STATE_KEXINIT_RECEIVED,
        SSH_SESSION_STATE_DH,
        SSH_SESSION_STATE_AUTHENTICATING,
        SSH_SESSION_STATE_AUTHENTICATED,
        SSH_SESSION_STATE_ERROR,
        SSH_SESSION_STATE_DISCONNECTED

    enum ssh_dh_state_e:
        DH_STATE_INIT,
        DH_STATE_INIT_SENT,
        DH_STATE_NEWKEYS_SENT,
        DH_STATE_FINISHED

    enum ssh_pending_call_e:
        SSH_PENDING_CALL_NONE,
        SSH_PENDING_CALL_CONNECT,
        SSH_PENDING_CALL_AUTH_NONE,
        SSH_PENDING_CALL_AUTH_PASSWORD,
        SSH_PENDING_CALL_AUTH_OFFER_PUBKEY,
        SSH_PENDING_CALL_AUTH_PUBKEY,
        SSH_PENDING_CALL_AUTH_AGENT,
        SSH_PENDING_CALL_AUTH_KBDINT_INIT,
        SSH_PENDING_CALL_AUTH_KBDINT_SEND,
        SSH_PENDING_CALL_AUTH_GSSAPI_MIC

    enum:
        SSH_SESSION_FLAG_BLOCKING
        SH_SESSION_FLAG_AUTHENTICATED
        SSH_TIMEOUT_INFINITE
        SSH_TIMEOUT_USER
        SSH_TIMEOUT_DEFAULT
        SSH_TIMEOUT_NONBLOCKING
        SSH_OPT_FLAG_PASSWORD_AUTH
        SSH_OPT_FLAG_PUBKEY_AUTH
        SSH_OPT_FLAG_KBDINT_AUTH
        SSH_OPT_FLAG_GSSAPI_AUTH

    struct ssh_common_struct:
        error_struct error
        ssh_callbacks callbacks
        int log_verbosity

    struct srv:
        ssh_key rsa_key
        ssh_key dsa_key
        ssh_key ecdsa_key
        ssh_key ed25519_key
        ssh_keytypes_e hostkey

    struct opts:
        ssh_list *identity
        char *username
        char *host
        char *bindaddr
        char *sshdir
        char *knownhosts
        char *global_knownhosts
        char *wanted_methods[10]
        char *ProxyCommand
        char *custombanner
        unsigned long timeout
        unsigned long timeout_usec
        unsigned int port
        socket_t fd
        int StrictHostKeyChecking
        int ssh2
        int ssh1
        char compressionlevel
        char *gss_server_identity
        char *gss_client_identity
        int gss_delegate_creds
        int flags
        int nodelay

    struct ssh_auth_auto_state_struct:
        pass

    struct ssh_agent_state_struct:
        pass

    struct ssh_session_struct:
        ssh_common_struct common
        ssh_socket_struct *socket
        char *serverbanner
        char *clientbanner
        int protoversion
        int server
        int client
        int openssh
        uint32_t send_seq
        uint32_t recv_seq
        int connected
        int alive
        int flags
        ssh_string banner
        char *discon_msg
        ssh_buffer in_buffer;
        PACKET in_packet;
        ssh_buffer out_buffer;
        ssh_pending_call_e pending_call_state
        ssh_session_state_e session_state
        int packet_state
        ssh_dh_state_e dh_handshake_state
        ssh_auth_service_state_e auth_service_state
        ssh_auth_state_e auth_state
        ssh_channel_request_state_e global_req_state
        ssh_agent_state_struct *agent_state
        ssh_auth_auto_state_struct *auth_auto_state
        int first_kex_follows_guess_wrong
        ssh_buffer in_hashbuf
        ssh_buffer out_hashbuf
        ssh_crypto_struct *current_crypto
        ssh_crypto_struct *next_crypto
        ssh_list *channels
        int maxchannel
        int exec_channel_opened
        ssh_agent agent
        ssh_kbdint_struct *kbdint
        ssh_gssapi_struct *gssapi
        int version
        srv srv
        int auth_methods
        ssh_list *ssh_message_list
        int (*ssh_message_callback)( ssh_session_struct *session, ssh_message msg, void *userdata)
        void *ssh_message_callback_data
        ssh_server_callbacks server_callbacks
        void (*ssh_connection_callback)( ssh_session_struct *session)
        ssh_packet_callbacks_struct default_packet_callbacks
        ssh_list *packet_callbacks
        ssh_socket_callbacks_struct socket_callbacks
        ssh_poll_ctx default_poll_ctx
        opts opts
        ssh_counter socket_counter
        ssh_counter raw_counter

    ctypedef int (*ssh_termination_function)(void *user);
    int ssh_handle_packets(ssh_session session, int timeout);
    int ssh_handle_packets_termination(ssh_session session, int timeout,
                                       ssh_termination_function fct, void *user);
    void ssh_socket_exception_callback(int code, int errno_code, void *user);
