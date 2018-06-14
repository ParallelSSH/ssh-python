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

from c_ssh cimport uint64_t, uint32_t, uint8_t, ssh_string, ssh_buffer, \
    ssh_channel, ssh_session

cdef extern from "libssh/include/sftp.h" nogil:
    ctypedef sftp_attributes_struct* sftp_attributes
    ctypedef sftp_client_message_struct* sftp_client_message
    ctypedef sftp_dir_struct* sftp_dir
    # ctypedef sftp_ext_struct *sftp_ext
    ctypedef sftp_file_struct* sftp_file
    ctypedef sftp_message_struct* sftp_message
    ctypedef sftp_packet_struct* sftp_packet
    ctypedef sftp_request_queue_struct* sftp_request_queue
    ctypedef sftp_session_struct* sftp_session
    ctypedef sftp_status_message_struct* sftp_status_message
    ctypedef sftp_statvfs_struct* sftp_statvfs_t
    
    struct sftp_session_struct:
        ssh_session session
        ssh_channel channel
        int server_version
        int client_version
        int version
        sftp_request_queue queue
        uint32_t id_counter
        int errnum
        void **handles
        # sftp_ext ext

    struct sftp_packet_struct:
        sftp_session sftp
        uint8_t type
        ssh_buffer payload

    struct sftp_file_struct:
        sftp_session sftp
        char *name
        uint64_t offset
        ssh_string handle
        int eof
        int nonblocking

    struct sftp_dir_struct:
        sftp_session sftp
        char *name
        ssh_string handle
        ssh_buffer buffer
        uint32_t count
        int eof

    struct sftp_message_struct:
        sftp_session sftp
        uint8_t packet_type
        ssh_buffer payload
        uint32_t id

    struct sftp_client_message_struct:
        sftp_session sftp
        uint8_t type
        uint32_t id
        char *filename
        uint32_t flags
        sftp_attributes attr
        ssh_string handle
        uint64_t offset
        uint32_t len
        int attr_num
        ssh_buffer attrbuf
        ssh_string data
        ssh_buffer complete_message
        char *str_data

    struct sftp_request_queue_struct:
        sftp_request_queue _next "next"
        sftp_message message

    struct sftp_status_message_struct:
        uint32_t _id "id"
        uint32_t status
        ssh_string error_unused
        ssh_string lang_unused
        char *errormsg;
        char *langmsg;

    struct sftp_attributes_struct:
        char *name
        char *longname
        uint32_t flags
        uint8_t type
        uint64_t size
        uint32_t uid
        uint32_t gid
        char *owner
        char *group
        uint32_t permissions
        uint64_t atime64
        uint32_t atime
        uint32_t atime_nseconds
        uint64_t createtime
        uint32_t createtime_nseconds
        uint64_t mtime64
        uint32_t mtime
        uint32_t mtime_nseconds
        ssh_string acl
        uint32_t extended_count
        ssh_string extended_type
        ssh_string extended_data

    struct sftp_statvfs_struct:
        uint64_t f_bsize
        uint64_t f_frsize
        uint64_t f_blocks
        uint64_t f_bfree
        uint64_t f_bavail
        uint64_t f_files
        uint64_t f_ffree
        uint64_t f_favail
        uint64_t f_fsid
        uint64_t f_flag
        uint64_t f_namemax
