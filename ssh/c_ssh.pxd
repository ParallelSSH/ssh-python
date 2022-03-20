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

from libc.time cimport time_t
from posix.types cimport mode_t, suseconds_t


cdef extern from "libssh/libssh.h" nogil:
    ctypedef struct fd_set:
        pass
    cdef struct timeval:
        time_t       tv_sec
        suseconds_t  tv_usec
    ctypedef unsigned char uint8_t
    ctypedef unsigned short uint16_t
    ctypedef unsigned int uint32_t
    ctypedef unsigned long long uint64_t
    ctypedef int socket_t
    int SSH_VERSION_INT(int, int, int)
    int SSH_VERSION_DOT(int, int, int)
    int SSH_VERSION(int, int, int)
    enum:
        LIBSSH_VERSION_MAJOR
        LIBSSH_VERSION_MINOR
        LIBSSH_VERSION_MICRO
    LIBSSH_VERSION_INT(int, int, int)
    LIBSSH_VERSION(int, int, int)
    struct ssh_counter_struct:
        uint64_t in_bytes
        uint64_t out_bytes
        uint64_t in_packets
        uint64_t out_packets
    # Forward declarations for structures
    # defined in other header files
    struct ssh_agent_struct:
        pass
    struct ssh_buffer_struct:
        pass
    struct ssh_channel_struct:
        pass
    struct ssh_message_struct:
        pass
    struct ssh_pcap_file_struct:
        pass
    struct ssh_key_struct:
        pass
    struct ssh_scp_struct:
        pass
    struct ssh_session_struct:
        pass
    struct ssh_string_struct:
        pass
    struct ssh_event_struct:
        pass
    struct ssh_connector_struct:
        pass
    ctypedef ssh_counter_struct *ssh_counter
    ctypedef ssh_agent_struct* ssh_agent
    ctypedef ssh_buffer_struct* ssh_buffer
    ctypedef ssh_channel_struct* ssh_channel
    ctypedef ssh_message_struct* ssh_message
    ctypedef ssh_pcap_file_struct* ssh_pcap_file
    ctypedef ssh_key_struct* ssh_key
    ctypedef ssh_scp_struct* ssh_scp
    ctypedef ssh_session_struct* ssh_session
    ctypedef ssh_string_struct* ssh_string
    ctypedef ssh_event_struct* ssh_event
    ctypedef ssh_connector_struct * ssh_connector
    ctypedef void* ssh_gssapi_creds
    enum:
        SSH_INVALID_SOCKET
    enum ssh_kex_types_e:
        SSH_KEX
        SSH_HOSTKEYS
        SSH_CRYPT_C_S
        SSH_CRYPT_S_C
        SSH_MAC_C_S
        SSH_MAC_S_C
        SSH_COMP_C_S
        SSH_COMP_S_C
        SSH_LANG_C_S
        SSH_LANG_S_C
    enum:
        SSH_CRYPT
        SSH_MAC
        SSH_COMP
        SSH_LANG
    enum ssh_auth_e:
        SSH_AUTH_SUCCESS,
        SSH_AUTH_DENIED,
        SSH_AUTH_PARTIAL,
        SSH_AUTH_INFO,
        SSH_AUTH_AGAIN,
        SSH_AUTH_ERROR
    # Auth flags
    enum:
        SSH_AUTH_METHOD_UNKNOWN
        SSH_AUTH_METHOD_NONE
        SSH_AUTH_METHOD_PASSWORD
        SSH_AUTH_METHOD_PUBLICKEY
        SSH_AUTH_METHOD_HOSTBASED
        SSH_AUTH_METHOD_INTERACTIVE
        SSH_AUTH_METHOD_GSSAPI_MIC
    # Messages
    enum ssh_requests_e:
        SSH_REQUEST_AUTH,
        SSH_REQUEST_CHANNEL_OPEN,
        SSH_REQUEST_CHANNEL,
        SSH_REQUEST_SERVICE,
        SSH_REQUEST_GLOBAL
    enum ssh_channel_type_e:
        SSH_CHANNEL_UNKNOWN,
        SSH_CHANNEL_SESSION,
        SSH_CHANNEL_DIRECT_TCPIP,
        SSH_CHANNEL_FORWARDED_TCPIP,
        SSH_CHANNEL_X11,
        SSH_CHANNEL_AUTH_AGENT
    enum ssh_channel_requests_e:
        SSH_CHANNEL_REQUEST_UNKNOWN,
        SSH_CHANNEL_REQUEST_PTY,
        SSH_CHANNEL_REQUEST_EXEC,
        SSH_CHANNEL_REQUEST_SHELL,
        SSH_CHANNEL_REQUEST_ENV,
        SSH_CHANNEL_REQUEST_SUBSYSTEM,
        SSH_CHANNEL_REQUEST_WINDOW_CHANGE,
        SSH_CHANNEL_REQUEST_X11
    enum ssh_global_requests_e:
        SSH_GLOBAL_REQUEST_UNKNOWN,
        SSH_GLOBAL_REQUEST_TCPIP_FORWARD,
        SSH_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD,
        SSH_GLOBAL_REQUEST_KEEPALIVE
    enum ssh_publickey_state_e:
        SSH_PUBLICKEY_STATE_ERROR,
        SSH_PUBLICKEY_STATE_NONE,
        SSH_PUBLICKEY_STATE_VALID,
        SSH_PUBLICKEY_STATE_WRONG
    enum:
        SSH_CLOSED
        SSH_READ_PENDING
        SSH_CLOSED_ERROR
        SSH_WRITE_PENDING
    enum ssh_server_known_e:
        SSH_SERVER_ERROR,
        SSH_SERVER_NOT_KNOWN,
        SSH_SERVER_KNOWN_OK,
        SSH_SERVER_KNOWN_CHANGED,
        SSH_SERVER_FOUND_OTHER,
        SSH_SERVER_FILE_NOT_FOUND
    enum:
        MD5_DIGEST_LEN
    # Errors
    enum ssh_error_types_e:
        SSH_NO_ERROR,
        SSH_REQUEST_DENIED,
        SSH_FATAL,
        SSH_EINTR
    enum ssh_keytypes_e:
        SSH_KEYTYPE_UNKNOWN,
        SSH_KEYTYPE_DSS,
        SSH_KEYTYPE_RSA,
        SSH_KEYTYPE_RSA1,
        SSH_KEYTYPE_ECDSA,  # Deprecated
        SSH_KEYTYPE_ED25519,
        SSH_KEYTYPE_DSS_CERT01,
        SSH_KEYTYPE_RSA_CERT01,
        SSH_KEYTYPE_ECDSA_P256,
        SSH_KEYTYPE_ECDSA_P384,
        SSH_KEYTYPE_ECDSA_P521,
        SSH_KEYTYPE_ECDSA_P256_CERT01,
        SSH_KEYTYPE_ECDSA_P384_CERT01,
        SSH_KEYTYPE_ECDSA_P521_CERT01,
        SSH_KEYTYPE_ED25519_CERT01
    enum ssh_keycmp_e:
        SSH_KEY_CMP_PUBLIC,
        SSH_KEY_CMP_PRIVATE
    enum:
        SSH_OK
        SSH_ERROR
        SSH_AGAIN
        SSH_EOF
    enum:
        SSH_LOG_NOLOG
        SSH_LOG_PROTOCOL
        SSH_LOG_PACKET
        SSH_LOG_FUNCTIONS
        SSH_LOG_RARE
    enum:
        SSH_LOG_NONE
        SSH_LOG_WARN
        SSH_LOG_INFO
        SSH_LOG_DEBUG
        SSH_LOG_TRACE
    enum ssh_options_e:
        SSH_OPTIONS_HOST,
        SSH_OPTIONS_PORT,
        SSH_OPTIONS_PORT_STR,
        SSH_OPTIONS_FD,
        SSH_OPTIONS_USER,
        SSH_OPTIONS_SSH_DIR,
        SSH_OPTIONS_IDENTITY,
        SSH_OPTIONS_ADD_IDENTITY,
        SSH_OPTIONS_KNOWNHOSTS,
        SSH_OPTIONS_TIMEOUT,
        SSH_OPTIONS_TIMEOUT_USEC,
        SSH_OPTIONS_SSH1,
        SSH_OPTIONS_SSH2,
        SSH_OPTIONS_LOG_VERBOSITY,
        SSH_OPTIONS_LOG_VERBOSITY_STR,
        SSH_OPTIONS_CIPHERS_C_S,
        SSH_OPTIONS_CIPHERS_S_C,
        SSH_OPTIONS_COMPRESSION_C_S,
        SSH_OPTIONS_COMPRESSION_S_C,
        SSH_OPTIONS_PROXYCOMMAND,
        SSH_OPTIONS_BINDADDR,
        SSH_OPTIONS_STRICTHOSTKEYCHECK,
        SSH_OPTIONS_COMPRESSION,
        SSH_OPTIONS_COMPRESSION_LEVEL,
        SSH_OPTIONS_KEY_EXCHANGE,
        SSH_OPTIONS_HOSTKEYS,
        SSH_OPTIONS_GSSAPI_SERVER_IDENTITY,
        SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY,
        SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS,
        SSH_OPTIONS_HMAC_C_S,
        SSH_OPTIONS_HMAC_S_C,
        SSH_OPTIONS_PASSWORD_AUTH,
        SSH_OPTIONS_PUBKEY_AUTH,
        SSH_OPTIONS_KBDINT_AUTH,
        SSH_OPTIONS_GSSAPI_AUTH,
        SSH_OPTIONS_GLOBAL_KNOWNHOSTS,
        SSH_OPTIONS_NODELAY,
        SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES,
        SSH_OPTIONS_PROCESS_CONFIG,
        SSH_OPTIONS_REKEY_DATA,
        SSH_OPTIONS_REKEY_TIME
    enum:
        SSH_SCP_WRITE
        SSH_SCP_READ
        SSH_SCP_RECURSIVE
    enum ssh_scp_request_types:
        SSH_SCP_REQUEST_NEWDIR,
        SSH_SCP_REQUEST_NEWFILE,
        SSH_SCP_REQUEST_EOF,
        SSH_SCP_REQUEST_ENDDIR,
        SSH_SCP_REQUEST_WARNING
    enum ssh_connector_flags_e:
        SSH_CONNECTOR_STDOUT,
        SSH_CONNECTOR_STDERR,
        SSH_CONNECTOR_BOTH
    int ssh_blocking_flush(ssh_session session, int timeout)
    ssh_channel ssh_channel_accept_x11(ssh_channel channel, int timeout_ms)
    int ssh_channel_change_pty_size(ssh_channel channel, int cols, int rows)
    int ssh_channel_close(ssh_channel channel)
    void ssh_channel_free(ssh_channel channel)
    int ssh_channel_get_exit_status(ssh_channel channel)
    ssh_session ssh_channel_get_session(ssh_channel channel)
    int ssh_channel_is_closed(ssh_channel channel)
    int ssh_channel_is_eof(ssh_channel channel)
    int ssh_channel_is_open(ssh_channel channel)
    ssh_channel ssh_channel_new(ssh_session session)
    int ssh_channel_open_auth_agent(ssh_channel channel)
    int ssh_channel_open_forward(ssh_channel channel, const char *remotehost,
                                 int remoteport, const char *sourcehost,
                                 int localport)
    int ssh_channel_open_session(ssh_channel channel)
    int ssh_channel_open_x11(
        ssh_channel channel, const char *orig_addr, int orig_port)
    int ssh_channel_poll(ssh_channel channel, int is_stderr)
    int ssh_channel_poll_timeout(
        ssh_channel channel, int timeout, int is_stderr)
    int ssh_channel_read(
        ssh_channel channel, void *dest, uint32_t count, int is_stderr)
    int ssh_channel_read_timeout(ssh_channel channel, void *dest,
                                 uint32_t count, int is_stderr, int timeout_ms)
    int ssh_channel_read_nonblocking(
        ssh_channel channel, void *dest, uint32_t count, int is_stderr)
    int ssh_channel_request_env(
        ssh_channel channel, const char *name, const char *value)
    int ssh_channel_request_exec(ssh_channel channel, const char *cmd)
    int ssh_channel_request_pty(ssh_channel channel)
    int ssh_channel_request_pty_size(ssh_channel channel, const char *term,
                                     int cols, int rows)
    int ssh_channel_request_shell(ssh_channel channel)
    int ssh_channel_request_send_signal(ssh_channel channel, const char *signum)
    int ssh_channel_request_send_break(ssh_channel channel, uint32_t length)
    int ssh_channel_request_sftp(ssh_channel channel)
    int ssh_channel_request_subsystem(
        ssh_channel channel, const char *subsystem)
    int ssh_channel_request_x11(
        ssh_channel channel, int single_connection, const char *protocol,
        const char *cookie, int screen_number)
    int ssh_channel_request_auth_agent(ssh_channel channel)
    int ssh_channel_send_eof(ssh_channel channel)
    int ssh_channel_select(ssh_channel *readchans, ssh_channel *writechans,
                           ssh_channel *exceptchans, timeval * timeout)
    void ssh_channel_set_blocking(ssh_channel channel, int blocking)
    void ssh_channel_set_counter(ssh_channel channel,
                                 ssh_counter counter)
    int ssh_channel_write(ssh_channel channel, const void *data, uint32_t len)
    int ssh_channel_write_stderr(ssh_channel channel,
                                 const void *data,
                                 uint32_t len)
    uint32_t ssh_channel_window_size(ssh_channel channel)

    char *ssh_basename(const char *path)
    void ssh_clean_pubkey_hash(unsigned char **hash)
    int ssh_connect(ssh_session session)

    ssh_connector ssh_connector_new(ssh_session session)
    void ssh_connector_free(ssh_connector connector)
    int ssh_connector_set_in_channel(ssh_connector connector,
                                     ssh_channel channel,
                                     ssh_connector_flags_e flags)
    int ssh_connector_set_out_channel(ssh_connector connector,
                                      ssh_channel channel,
                                      ssh_connector_flags_e flags)
    void ssh_connector_set_in_fd(ssh_connector connector, socket_t fd)
    void ssh_connector_set_out_fd(ssh_connector connector, socket_t fd)

    const char *ssh_copyright()
    void ssh_disconnect(ssh_session session)
    char *ssh_dirname(const char *path)
    int ssh_finalize()

    # Reverse port forwarding
    ssh_channel ssh_channel_accept_forward(
        ssh_session session, int timeout_ms, int *destination_port)
    int ssh_channel_cancel_forward(
        ssh_session session, const char *address, int port)
    int ssh_channel_listen_forward(
        ssh_session session, const char *address, int port, int *bound_port)

    void ssh_free(ssh_session session)
    const char *ssh_get_disconnect_message(ssh_session session)
    const char *ssh_get_error(void *error)
    int ssh_get_error_code(void *error)
    socket_t ssh_get_fd(ssh_session session)
    char *ssh_get_hexa(const unsigned char *what, size_t len)
    char *ssh_get_issue_banner(ssh_session session)
    int ssh_get_openssh_version(ssh_session session)

    int ssh_get_server_publickey(ssh_session session, ssh_key *key)

    enum ssh_publickey_hash_type:
        SSH_PUBLICKEY_HASH_SHA1
        SSH_PUBLICKEY_HASH_MD5
    int ssh_get_publickey_hash(const ssh_key key,
                               ssh_publickey_hash_type type,
                               unsigned char **hash,
                               size_t *hlen)

    # deprecated functions
    int ssh_get_pubkey_hash(ssh_session session, unsigned char **hash)
    ssh_channel ssh_forward_accept(ssh_session session, int timeout_ms)
    int ssh_forward_cancel(ssh_session session, const char *address, int port)
    int ssh_forward_listen(ssh_session session, const char *address,
                           int port, int *bound_port)
    int ssh_get_publickey(ssh_session session, ssh_key *key)
    # End deprecated

    int ssh_get_random(void *where, int len, int strong)
    int ssh_get_version(ssh_session session)
    int ssh_get_status(ssh_session session)
    int ssh_get_poll_flags(ssh_session session)
    int ssh_init()
    int ssh_is_blocking(ssh_session session)
    int ssh_is_connected(ssh_session session)
    int ssh_is_server_known(ssh_session session)

    int ssh_set_log_level(int level)
    int ssh_get_log_level()
    void *ssh_get_log_userdata()
    int ssh_set_log_userdata(void *data)
    _ssh_log(int verbosity,
             const char *function,
             const char *format, int, int)

    # legacy
    ssh_log(ssh_session session,
            int prioriry,
            const char *format, int, int)

    ssh_channel ssh_message_channel_request_open_reply_accept(ssh_message msg)
    int ssh_message_channel_request_reply_success(ssh_message msg)
    void ssh_message_free(ssh_message msg)
    ssh_message ssh_message_get(ssh_session session)
    int ssh_message_subtype(ssh_message msg)
    int ssh_message_type(ssh_message msg)
    int ssh_mkdir(const char *pathname, mode_t mode)
    ssh_session ssh_new()

    int ssh_options_copy(ssh_session src, ssh_session *dest)
    int ssh_options_getopt(ssh_session session, int *argcptr, char **argv)
    int ssh_options_parse_config(ssh_session session, const char *filename)
    int ssh_options_set(ssh_session session, ssh_options_e type,
                        const void *value)
    int ssh_options_get(ssh_session session, ssh_options_e type,
                        char **value)
    int ssh_options_get_port(ssh_session session, unsigned int * port_target)
    int ssh_pcap_file_close(ssh_pcap_file pcap)
    void ssh_pcap_file_free(ssh_pcap_file pcap)
    ssh_pcap_file ssh_pcap_file_new()
    int ssh_pcap_file_open(ssh_pcap_file pcap, const char *filename)

    ctypedef int(*ssh_auth_callback)(
        const char *prompt, char *buf, size_t len,
        int echo, int verify, void *userdata)
    ssh_key ssh_key_new()
    void ssh_key_free(ssh_key key)
    ssh_keytypes_e ssh_key_type(const ssh_key key)
    const char *ssh_key_type_to_char(ssh_keytypes_e type)
    ssh_keytypes_e ssh_key_type_from_name(const char *name)
    int ssh_key_is_public(const ssh_key k)
    int ssh_key_is_private(const ssh_key k)
    int ssh_key_cmp(
        const ssh_key k1, const ssh_key k2, ssh_keycmp_e what)

    int ssh_pki_generate(ssh_keytypes_e type, int parameter,
                         ssh_key *pkey)
    int ssh_pki_import_privkey_base64(
        const char *b64_key, const char *passphrase,
        ssh_auth_callback auth_fn, void *auth_data, ssh_key *pkey)
    int ssh_pki_import_privkey_file(
        const char *filename, const char *passphrase,
        ssh_auth_callback auth_fn, void *auth_data, ssh_key *pkey)
    int ssh_pki_export_privkey_file(
        const ssh_key privkey, const char *passphrase,
        ssh_auth_callback auth_fn, void *auth_data, const char *filename)

    int ssh_pki_copy_cert_to_privkey(const ssh_key cert_key,
                                     ssh_key privkey)

    int ssh_pki_import_pubkey_base64(const char *b64_key,
                                     ssh_keytypes_e type,
                                     ssh_key *pkey)
    int ssh_pki_import_pubkey_file(const char *filename,
                                   ssh_key *pkey)

    int ssh_pki_import_cert_base64(const char *b64_cert,
                                   ssh_keytypes_e type,
                                   ssh_key *pkey)
    int ssh_pki_import_cert_file(const char *filename,
                                 ssh_key *pkey)

    int ssh_pki_export_privkey_to_pubkey(const ssh_key privkey,
                                         ssh_key *pkey)
    int ssh_pki_export_pubkey_base64(const ssh_key key,
                                     char **b64_key)
    int ssh_pki_export_pubkey_file(const ssh_key key,
                                   const char *filename)

    const char *ssh_pki_key_ecdsa_name(const ssh_key key)

    char *ssh_get_fingerprint_hash(ssh_publickey_hash_type type,
                                   unsigned char *hash,
                                   size_t len)
    void ssh_print_hash(ssh_publickey_hash_type type,
                        unsigned char *hash,
                        size_t len)
    void ssh_print_hexa(
        const char *descr, const unsigned char *what, size_t len)
    int ssh_send_ignore(ssh_session session, const char *data)
    int ssh_send_debug(
        ssh_session session, const char *message, int always_display)
    void ssh_gssapi_set_creds(
        ssh_session session, const ssh_gssapi_creds creds)
    int ssh_scp_accept_request(ssh_scp scp)
    int ssh_scp_close(ssh_scp scp)
    int ssh_scp_deny_request(ssh_scp scp, const char *reason)
    void ssh_scp_free(ssh_scp scp)
    int ssh_scp_init(ssh_scp scp)
    int ssh_scp_leave_directory(ssh_scp scp)
    ssh_scp ssh_scp_new(ssh_session session, int mode, const char *location)
    int ssh_scp_pull_request(ssh_scp scp)
    int ssh_scp_push_directory(ssh_scp scp, const char *dirname, int mode)
    int ssh_scp_push_file(
        ssh_scp scp, const char *filename, size_t size, int perms)
    int ssh_scp_push_file64(
        ssh_scp scp, const char *filename, uint64_t size, int perms)
    int ssh_scp_read(ssh_scp scp, void *buffer, size_t size)
    const char *ssh_scp_request_get_filename(ssh_scp scp)
    int ssh_scp_request_get_permissions(ssh_scp scp)
    size_t ssh_scp_request_get_size(ssh_scp scp)
    uint64_t ssh_scp_request_get_size64(ssh_scp scp)
    const char *ssh_scp_request_get_warning(ssh_scp scp)
    int ssh_scp_write(ssh_scp scp, const void *buffer, size_t len)
    int ssh_select(
        ssh_channel *channels, ssh_channel *outchannels,
        socket_t maxfd, fd_set *readfds, timeval *timeout)
    int ssh_service_request(ssh_session session, const char *service)
    int ssh_set_agent_channel(ssh_session session, ssh_channel channel)
    int ssh_set_agent_socket(ssh_session session, socket_t fd)
    void ssh_set_blocking(ssh_session session, int blocking)
    void ssh_set_counters(ssh_session session, ssh_counter scounter,
                          ssh_counter rcounter)
    void ssh_set_fd_except(ssh_session session)
    void ssh_set_fd_toread(ssh_session session)
    void ssh_set_fd_towrite(ssh_session session)
    void ssh_silent_disconnect(ssh_session session)
    int ssh_set_pcap_file(ssh_session session, ssh_pcap_file pcapfile)

    # Userauth
    int ssh_userauth_none(ssh_session session, const char *username)
    int ssh_userauth_list(ssh_session session, const char *username)
    int ssh_userauth_try_publickey(ssh_session session,
                                   const char *username,
                                   const ssh_key pubkey)
    int ssh_userauth_publickey(ssh_session session,
                               const char *username,
                               const ssh_key privkey)
    # #ifndef _WIN32
    int ssh_userauth_agent(ssh_session session,
                           const char *username)
    # #endif
    int ssh_userauth_publickey_auto(ssh_session session,
                                    const char *username,
                                    const char *passphrase)
    int ssh_userauth_password(ssh_session session,
                              const char *username,
                              const char *password)

    int ssh_userauth_kbdint(
        ssh_session session, const char *user, const char *submethods)
    const char *ssh_userauth_kbdint_getinstruction(ssh_session session)
    const char *ssh_userauth_kbdint_getname(ssh_session session)
    int ssh_userauth_kbdint_getnprompts(ssh_session session)
    const char *ssh_userauth_kbdint_getprompt(
        ssh_session session, unsigned int i, char *echo)
    int ssh_userauth_kbdint_getnanswers(ssh_session session)
    const char *ssh_userauth_kbdint_getanswer(
        ssh_session session, unsigned int i)
    int ssh_userauth_kbdint_setanswer(
        ssh_session session, unsigned int i, const char *answer)
    int ssh_userauth_gssapi(ssh_session session)
    const char *ssh_version(int req_version)
    int ssh_write_knownhost(ssh_session session)
    char *ssh_dump_knownhost(ssh_session session)

    void ssh_string_burn(ssh_string str)
    ssh_string ssh_string_copy(ssh_string str)
    void *ssh_string_data(ssh_string str)
    int ssh_string_fill(ssh_string str, const void *data, size_t len)
    void ssh_string_free(ssh_string str)
    ssh_string ssh_string_from_char(const char *what)
    size_t ssh_string_len(ssh_string str)
    ssh_string ssh_string_new(size_t size)
    const char *ssh_string_get_char(ssh_string str)
    char *ssh_string_to_char(ssh_string str)
    void ssh_string_free_char(char *s)

    int ssh_getpass(const char *prompt, char *buf, size_t len, int echo,
                    int verify)

    ctypedef int(*ssh_event_callback)(socket_t fd, int revents, void *userdata)

    ssh_event ssh_event_new()
    int ssh_event_add_fd(ssh_event event, socket_t fd, short events,
                         ssh_event_callback cb, void *userdata)
    int ssh_event_add_session(ssh_event event, ssh_session session)
    int ssh_event_add_connector(ssh_event event, ssh_connector connector)
    int ssh_event_dopoll(ssh_event event, int timeout)
    int ssh_event_remove_fd(ssh_event event, socket_t fd)
    int ssh_event_remove_session(ssh_event event, ssh_session session)
    int ssh_event_remove_connector(ssh_event event, ssh_connector connector)
    void ssh_event_free(ssh_event event)
    const char* ssh_get_clientbanner(ssh_session session)
    const char* ssh_get_serverbanner(ssh_session session)
    const char* ssh_get_kex_algo(ssh_session session)
    const char* ssh_get_cipher_in(ssh_session session)
    const char* ssh_get_cipher_out(ssh_session session)
    const char* ssh_get_hmac_in(ssh_session session)
    const char* ssh_get_hmac_out(ssh_session session)
    ssh_buffer ssh_buffer_new()
    void ssh_buffer_free(ssh_buffer buffer)
    int ssh_buffer_reinit(ssh_buffer buffer)
    int ssh_buffer_add_data(ssh_buffer buffer, const void *data, uint32_t len)
    uint32_t ssh_buffer_get_data(
        ssh_buffer buffer, void *data, uint32_t requestedlen)
    void *ssh_buffer_get(ssh_buffer buffer)
    uint32_t ssh_buffer_get_len(ssh_buffer buffer)
