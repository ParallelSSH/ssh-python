# This file is part of ssh-python.
#
# Copyright (C) 2017-2020 Panos Kittenis
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

from c_ssh cimport ssh_session, ssh_string

cdef bytes to_bytes(_str)
cdef object to_str(char *c_str)
cdef object to_str_len(char *c_str, int length)
cdef int handle_error_codes(int errcode, ssh_session) except -1
cdef int handle_auth_error_codes(int errcode, ssh_session) except -1
cdef bytes ssh_string_to_bytes(ssh_string _str)
