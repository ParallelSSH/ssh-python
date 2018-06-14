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

from c_ssh cimport ssh_session, ssh_kex_types_e, uint32_t

cdef extern from "libssh/include/kex.h" nogil:
    enum:
        SSH_KEX_METHODS
    struct ssh_kex_struct:
        unsigned char cookie[16]
        char *methods[SSH_KEX_METHODS]
    int ssh_send_kex(ssh_session session, int server_kex)
    void ssh_list_kex(ssh_kex_struct *kex)
    int ssh_set_client_kex(ssh_session session)
    int ssh_kex_select_methods(ssh_session session)
    int ssh_verify_existing_algo(ssh_kex_types_e algo, const char *name)
    char *ssh_keep_known_algos(ssh_kex_types_e algo, const char *list)
    char **ssh_space_tokenize(const char *chain)
    int ssh_get_kex1(ssh_session session)
    char *ssh_find_matching(const char *in_d, const char *what_d)
    const char *ssh_kex_get_supported_method(uint32_t algo)
    const char *ssh_kex_get_description(uint32_t algo)
