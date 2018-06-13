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

from c_ssh cimport ssh_session

cdef extern from "libssh/include/misc.h" nogil:
    char *ssh_get_user_home_dir()
    char *ssh_get_local_username()
    int ssh_file_readaccess_ok(const char *file)
    char *ssh_path_expand_tilde(const char *d)
    char *ssh_path_expand_escape(ssh_session session, const char *s)
    int ssh_analyze_banner(ssh_session session, int server, int *ssh1, int *ssh2)
    int ssh_is_ipaddr_v4(const char *str)
    int ssh_is_ipaddr(const char *str)
    struct ssh_iterator
    struct ssh_iterator:
        ssh_iterator *next
        const void *data
    struct ssh_list:
        ssh_iterator *root
        ssh_iterator *end
    struct ssh_timestamp:
        long seconds
        long useconds

    ssh_list *ssh_list_new()
    void ssh_list_free(ssh_list *list);
    ssh_iterator *ssh_list_get_iterator(const ssh_list *list)
    ssh_iterator *ssh_list_find(const ssh_list *list, void *value)
    int ssh_list_append(ssh_list *list, const void *data)
    int ssh_list_prepend(ssh_list *list, const void *data)
    void ssh_list_remove(ssh_list *list, ssh_iterator *iterator)
    char *ssh_lowercase(const char* str)
    char *ssh_hostport(const char *host, int port)
    const void *_ssh_list_pop_head(ssh_list *list)
    int ssh_make_milliseconds(long sec, long usec)
    void ssh_timestamp_init(ssh_timestamp *ts)
    int ssh_timeout_elapsed(ssh_timestamp *ts, int timeout)
    int ssh_timeout_update(ssh_timestamp *ts, int timeout)
    int ssh_match_group(const char *group, const char *object)
