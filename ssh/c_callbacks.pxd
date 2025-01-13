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

from .c_ssh cimport ssh_session, ssh_channel, ssh_buffer, ssh_string, \
    uint32_t, uint8_t, ssh_key_struct, ssh_auth_callback, ssh_message

cdef extern from "libssh/callbacks.h" nogil:
    ctypedef void(*ssh_callback_int)(int code, void *user)
    ctypedef int(*ssh_callback_data)(const void *data, size_t len, void *user)
    ctypedef void(*ssh_callback_int_int)(
        int code, int errno_code, void *user)
    ctypedef int(*ssh_message_callback)(
        ssh_session, ssh_message message, void *user)
    ctypedef int(*ssh_channel_callback_int)(
        ssh_channel channel, int code, void *user)
    ctypedef int(*ssh_channel_callback_data)(
        ssh_channel channel, int code, void *data, size_t len, void *user)

    ctypedef void(*ssh_log_callback)(ssh_session session, int priority,
                                     const char *message, void *userdata)
    ctypedef void(*ssh_logging_callback)(
        int priority, const char *function, const char *buffer, void *userdata)
    ctypedef void(*ssh_status_callback)(
        ssh_session session, float status, void *userdata)
    ctypedef void(*ssh_global_request_callback)(
        ssh_session session, ssh_message message, void *userdata)
    ctypedef ssh_channel(*ssh_channel_open_request_x11_callback)(
        ssh_session session, const char * originator_address,
        int originator_port, void *userdata)
    ctypedef ssh_channel(*ssh_channel_open_request_auth_agent_callback)(
        ssh_session session, void *userdata)
    struct ssh_callbacks_struct:
        size_t size
        void *userdata
        ssh_auth_callback auth_function
        ssh_log_callback log_function
        void(*connect_status_function)(void *userdata, float status)
        ssh_global_request_callback global_request_function
        ssh_channel_open_request_x11_callback channel_open_request_x11_function
        ssh_channel_open_request_auth_agent_callback \
            channel_open_request_auth_agent_function
    ctypedef ssh_callbacks_struct *ssh_callbacks

    ctypedef int(*ssh_auth_password_callback)(
        ssh_session session, const char *user, const char *password,
        void *userdata)
    ctypedef int(*ssh_auth_none_callback)(
        ssh_session session, const char *user, void *userdata)
    ctypedef int(*ssh_auth_gssapi_mic_callback)(
        ssh_session session, const char *user, const char *principal,
        void *userdata)
    ctypedef int(*ssh_auth_pubkey_callback)(
        ssh_session session, const char *user, ssh_key_struct *pubkey,
        char signature_state, void *userdata)
    ctypedef int(*ssh_service_request_callback)(
        ssh_session session, const char *service, void *userdata)
    ctypedef ssh_channel(*ssh_channel_open_request_session_callback)(
        ssh_session session, void *userdata)

    ctypedef ssh_string(*void)(
        ssh_session, const char*, int, ssh_string *, void *)
    ctypedef int(*ssh_gssapi_accept_sec_ctx_callback)(
        ssh_session session, ssh_string input_token,
        ssh_string *output_token, void *userdata)
    ctypedef int(*ssh_gssapi_verify_mic_callback)(
        ssh_session session, ssh_string mic, void *mic_buffer,
        size_t mic_buffer_size, void *userdata)

    ctypedef ssh_string(*ssh_gssapi_select_oid_callback)(
        ssh_session session, const char *user,
        int n_oid, ssh_string *oids, void *userdata)

    struct ssh_server_callbacks_struct:
        size_t size
        void *userdata
        ssh_auth_password_callback auth_password_function
        ssh_auth_none_callback auth_none_function
        ssh_auth_gssapi_mic_callback auth_gssapi_mic_function
        ssh_auth_pubkey_callback auth_pubkey_function
        ssh_service_request_callback service_request_function
        ssh_channel_open_request_session_callback \
            channel_open_request_session_function
        ssh_gssapi_select_oid_callback gssapi_select_oid_function
        ssh_gssapi_accept_sec_ctx_callback gssapi_accept_sec_ctx_function
        ssh_gssapi_verify_mic_callback gssapi_verify_mic_function
    ctypedef ssh_server_callbacks_struct *ssh_server_callbacks
    int ssh_set_server_callbacks(ssh_session session, ssh_server_callbacks cb)
    void ssh_callbacks_init(void *cb)
    struct ssh_socket_callbacks_struct:
        void *userdata
        ssh_callback_data data
        ssh_callback_int controlflow
        ssh_callback_int_int exception
        ssh_callback_int_int connected
    ctypedef ssh_socket_callbacks_struct *ssh_socket_callbacks

    enum:
        SSH_SOCKET_FLOW_WRITEWILLBLOCK
        SSH_SOCKET_FLOW_WRITEWONTBLOCK
        SSH_SOCKET_EXCEPTION_EOF
        SSH_SOCKET_EXCEPTION_ERROR
        SSH_SOCKET_CONNECTED_OK
        SSH_SOCKET_CONNECTED_ERROR
        SSH_SOCKET_CONNECTED_TIMEOUT
    ctypedef int(*ssh_packet_callback)(
        ssh_session session, uint8_t type, ssh_buffer packet, void *user)
    enum:
        SSH_PACKET_USED
        SSH_PACKET_NOT_USED

    struct ssh_packet_callbacks_struct:
        uint8_t start
        uint8_t n_callbacks
        ssh_packet_callback *callbacks
        void *user
    ctypedef ssh_packet_callbacks_struct *ssh_packet_callbacks
    int ssh_set_callbacks(ssh_session session, ssh_callbacks cb)
    ctypedef int(*ssh_channel_data_callback)(
        ssh_session session, ssh_channel channel, void *data, uint32_t len,
        int is_stderr, void *userdata)

    ctypedef void(*ssh_channel_eof_callback)(
        ssh_session session, ssh_channel channel, void *userdata)
    ctypedef void(*ssh_channel_close_callback)(
        ssh_session session, ssh_channel channel, void *userdata)
    ctypedef void(*ssh_channel_signal_callback)(
        ssh_session session, ssh_channel channel,
        const char *signal, void *userdata)
    ctypedef void(*ssh_channel_exit_status_callback)(
        ssh_session session, ssh_channel channel,
        int exit_status, void *userdata)
    ctypedef void(*ssh_channel_exit_signal_callback)(
        ssh_session session, ssh_channel channel, const char *signal, int core,
        const char *errmsg, const char *lang, void *userdata)
    ctypedef int(*ssh_channel_pty_request_callback)(
        ssh_session session, ssh_channel channel, const char *term,
        int width, int height, int pxwidth, int pwheight, void *userdata)
    ctypedef int(*ssh_channel_shell_request_callback)(
        ssh_session session, ssh_channel channel, void *userdata)
    ctypedef void(*ssh_channel_auth_agent_req_callback)(
        ssh_session session, ssh_channel channel, void *userdata)
    ctypedef void(*ssh_channel_x11_req_callback)(
        ssh_session session, ssh_channel channel,
        int single_connection, const char *auth_protocol,
        const char *auth_cookie, uint32_t screen_number, void *userdata)
    ctypedef int(*ssh_channel_pty_window_change_callback)(
        ssh_session session, ssh_channel channel, int width, int height,
        int pxwidth, int pwheight, void *userdata)
    ctypedef int(*ssh_channel_exec_request_callback)(
        ssh_session session, ssh_channel channel, const char *command,
        void *userdata)
    ctypedef int(*ssh_channel_env_request_callback)(
        ssh_session session, ssh_channel channel, const char *env_name,
        const char *env_value, void *userdata)
    ctypedef int(*ssh_channel_subsystem_request_callback)(
        ssh_session session, ssh_channel channel, const char *subsystem,
        void *userdata)
    ctypedef int(*ssh_channel_write_wontblock_callback)(
        ssh_session session, ssh_channel channel,
        size_t bytes, void *userdata)
    struct ssh_channel_callbacks_struct:
        size_t size
        void *userdata
        ssh_channel_data_callback channel_data_function
        ssh_channel_eof_callback channel_eof_function
        ssh_channel_close_callback channel_close_function
        ssh_channel_signal_callback channel_signal_function
        ssh_channel_exit_status_callback channel_exit_status_function
        ssh_channel_exit_signal_callback channel_exit_signal_function
        ssh_channel_pty_request_callback channel_pty_request_function
        ssh_channel_shell_request_callback channel_shell_request_function
        ssh_channel_auth_agent_req_callback channel_auth_agent_req_function
        ssh_channel_x11_req_callback channel_x11_req_function
        ssh_channel_pty_window_change_callback \
            channel_pty_window_change_function
        ssh_channel_exec_request_callback channel_exec_request_function
        ssh_channel_env_request_callback channel_env_request_function
        ssh_channel_subsystem_request_callback \
            channel_subsystem_request_function
        ssh_channel_write_wontblock_callback channel_write_wontblock_function

    ctypedef ssh_channel_callbacks_struct *ssh_channel_callbacks
    int ssh_set_channel_callbacks(ssh_channel channel,
                                  ssh_channel_callbacks cb)
    int ssh_add_channel_callbacks(ssh_channel channel,
                                  ssh_channel_callbacks cb)
    int ssh_remove_channel_callbacks(ssh_channel channel,
                                     ssh_channel_callbacks cb)
    ctypedef int(*ssh_thread_callback)(void **lock)
    ctypedef unsigned long(*ssh_thread_id_callback)()
    struct ssh_threads_callbacks_struct:
        const char *type
        ssh_thread_callback mutex_init
        ssh_thread_callback mutex_destroy
        ssh_thread_callback mutex_lock
        ssh_thread_callback mutex_unlock
        ssh_thread_id_callback thread_id
    int ssh_threads_set_callbacks(ssh_threads_callbacks_struct *cb)
    ssh_threads_callbacks_struct *ssh_threads_get_pthread()
    ssh_threads_callbacks_struct *ssh_threads_get_noop()
    int ssh_set_log_callback(ssh_logging_callback cb)
    ssh_logging_callback ssh_get_log_callback()
