# This file is part of ssh-python.
# Copyright (C) 2017-2018 Panos Kittenis
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

from cpython.version cimport PY_MAJOR_VERSION


ENCODING='utf-8'


cdef bytes to_bytes(_str):
    if isinstance(_str, bytes):
        return _str
    elif isinstance(_str, unicode):
        return _str.encode(ENCODING)
    return _str


cdef object to_str(char *c_str):
    _len = len(c_str)
    if PY_MAJOR_VERSION < 3:
        return c_str[:_len]
    return c_str[:_len].decode(ENCODING)


cdef object to_str_len(char *c_str, int length):
    if PY_MAJOR_VERSION < 3:
        return c_str[:length]
    return c_str[:length].decode(ENCODING)


cpdef int handle_error_codes(int errcode) except -1:
    return errcode
