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

from c_ssh cimport ssh_connector, ssh_event, ssh_buffer, ssh_session, \
    socket_t, ssh_key

cdef extern from "libssh/priv.h" nogil:
    struct timeval:
        pass
    int gettimeofday(timeval *__p, void *__t)
    struct ssh_common_struct:
        pass
    struct ssh_kex_struct:
        pass

    enum:
        MAX_PACKAT_LEN
        MAX_PACKET_LEN
        ERROR_BUFFERLEN
        KBDINT_MAX_PROMPT
        MAX_BUF_SIZE
    int ssh_get_key_params(ssh_session session, ssh_key *privkey)
    void ssh_log_function(int verbosity,
                          const char *function,
                          const char *buffer)
    struct error_struct:
        int error_code
        char error_buffer[ERROR_BUFFERLEN]
    int ssh_auth_reply_default(ssh_session session,int partial)
    int ssh_auth_reply_success(ssh_session session, int partial)
    int ssh_send_banner(ssh_session session, int is_server)
    socket_t ssh_connect_host(ssh_session session, const char *host,const char
                              *bind_addr, int port, long timeout, long usec)
    socket_t ssh_connect_host_nonblocking(ssh_session session, const char *host,
                                          const char *bind_addr, int port)
    ssh_buffer base64_to_bin(const char *source)
    unsigned char *bin_to_base64(const unsigned char *source, int len)
    int compress_buffer(ssh_session session,ssh_buffer buf)
    int decompress_buffer(ssh_session session,ssh_buffer buf, size_t maxlen)
    int match_hostname(const char *host, const char *pattern, unsigned int len)
    int ssh_connector_set_event(ssh_connector connector, ssh_event event)
    int ssh_connector_remove_event(ssh_connector connector)
    void ssh_agent_state_free(void *data)
