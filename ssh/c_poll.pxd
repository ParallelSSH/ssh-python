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

from c_ssh cimport ssh_session, ssh_buffer, ssh_string, uint32_t, uint8_t, ssh_event, socket_t
from c_callbacks cimport ssh_packet_callbacks, ssh_packet_callbacks_struct

cdef extern from "libssh/poll.h" nogil:
    ctypedef unsigned long int nfds_t
    void ssh_poll_init();
    void ssh_poll_cleanup();
    struct pollfd:
        pass
    ctypedef pollfd ssh_pollfd_t
    int ssh_poll(ssh_pollfd_t *fds, nfds_t nfds, int timeout);
    struct ssh_poll_handle_struct:
        pass
    struct ssh_poll_ctx_struct:
        pass
    ctypedef ssh_poll_ctx_struct *ssh_poll_ctx
    ctypedef ssh_poll_handle_struct *ssh_poll_handle
    ctypedef int (*ssh_poll_callback)(ssh_poll_handle p, socket_t fd, int revents,
                                      void *userdata)
    struct ssh_socket_struct:
        pass
    ssh_poll_handle ssh_poll_new(socket_t fd, short events, ssh_poll_callback cb,
                                 void *userdata)
    void ssh_poll_free(ssh_poll_handle p)
    ssh_poll_ctx ssh_poll_get_ctx(ssh_poll_handle p)
    short ssh_poll_get_events(ssh_poll_handle p)
    void ssh_poll_set_events(ssh_poll_handle p, short events)
    void ssh_poll_add_events(ssh_poll_handle p, short events)
    void ssh_poll_remove_events(ssh_poll_handle p, short events)
    socket_t ssh_poll_get_fd(ssh_poll_handle p)
    void ssh_poll_set_fd(ssh_poll_handle p, socket_t fd)
    void ssh_poll_set_callback(ssh_poll_handle p, ssh_poll_callback cb, void *userdata)
    ssh_poll_ctx ssh_poll_ctx_new(size_t chunk_size)
    void ssh_poll_ctx_free(ssh_poll_ctx ctx)
    int ssh_poll_ctx_add(ssh_poll_ctx ctx, ssh_poll_handle p)
    int ssh_poll_ctx_add_socket (ssh_poll_ctx ctx, ssh_socket_struct *s)
    void ssh_poll_ctx_remove(ssh_poll_ctx ctx, ssh_poll_handle p)
    int ssh_poll_ctx_dopoll(ssh_poll_ctx ctx, int timeout)
    ssh_poll_ctx ssh_poll_get_default_ctx(ssh_session session)
    int ssh_event_add_poll(ssh_event event, ssh_poll_handle p)
    void ssh_event_remove_poll(ssh_event event, ssh_poll_handle p)
