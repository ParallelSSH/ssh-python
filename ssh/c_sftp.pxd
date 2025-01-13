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

from .c_ssh cimport uint64_t, uint32_t, uint8_t, ssh_string, ssh_buffer, \
    ssh_channel, ssh_session, timeval


cdef extern from "libssh/sftp.h" nogil:
    ctypedef long mode_t
    ctypedef long uid_t
    ctypedef long gid_t
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
        char *errormsg
        char *langmsg

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
    sftp_session sftp_new(ssh_session session)
    sftp_session sftp_new_channel(ssh_session session, ssh_channel channel)
    void sftp_free(sftp_session sftp)
    int sftp_init(sftp_session sftp)
    int sftp_get_error(sftp_session sftp)
    unsigned int sftp_extensions_get_count(sftp_session sftp)
    const char *sftp_extensions_get_name(sftp_session sftp, unsigned int indexn)
    const char *sftp_extensions_get_data(sftp_session sftp, unsigned int indexn)
    int sftp_extension_supported(sftp_session sftp, const char *name,
                                 const char *data)
    sftp_dir sftp_opendir(sftp_session session, const char *path)
    sftp_attributes sftp_readdir(sftp_session session, sftp_dir dir)
    int sftp_dir_eof(sftp_dir dir)
    sftp_attributes sftp_stat(sftp_session session, const char *path)
    sftp_attributes sftp_lstat(sftp_session session, const char *path)
    sftp_attributes sftp_fstat(sftp_file file)
    void sftp_attributes_free(sftp_attributes file)
    int sftp_closedir(sftp_dir dir)
    int sftp_close(sftp_file file)
    sftp_file sftp_open(sftp_session session, const char *file, int accesstype,
                        mode_t mode)
    void sftp_file_set_nonblocking(sftp_file handle)
    void sftp_file_set_blocking(sftp_file handle)
    ssize_t sftp_read(sftp_file file, void *buf, size_t count)
    int sftp_async_read_begin(sftp_file file, uint32_t len)
    int sftp_async_read(sftp_file file, void *data, uint32_t len, uint32_t id)
    ssize_t sftp_write(sftp_file file, const void *buf, size_t count)
    int sftp_seek(sftp_file file, uint32_t new_offset)
    int sftp_seek64(sftp_file file, uint64_t new_offset)
    unsigned long sftp_tell(sftp_file file)
    uint64_t sftp_tell64(sftp_file file)
    void sftp_rewind(sftp_file file)
    int sftp_unlink(sftp_session sftp, const char *file)
    int sftp_rmdir(sftp_session sftp, const char *directory)
    int sftp_mkdir(sftp_session sftp, const char *directory, mode_t mode)
    int sftp_rename(
        sftp_session sftp, const char *original, const  char *newname)
    int sftp_setstat(sftp_session sftp, const char *file, sftp_attributes attr)
    int sftp_chown(
        sftp_session sftp, const char *file, uid_t owner, gid_t group)
    int sftp_chmod(sftp_session sftp, const char *file, mode_t mode)
    int sftp_utimes(sftp_session sftp, const char *file, const timeval *times)
    int sftp_symlink(sftp_session sftp, const char *target, const char *dest)
    char *sftp_readlink(sftp_session sftp, const char *path)
    sftp_statvfs_t sftp_statvfs(sftp_session sftp, const char *path)
    sftp_statvfs_t sftp_fstatvfs(sftp_file file)
    void sftp_statvfs_free(sftp_statvfs_t statvfs_o)
    int sftp_fsync(sftp_file file)
    char *sftp_canonicalize_path(sftp_session sftp, const char *path)
    int sftp_server_version(sftp_session sftp)

    # # Server
    # sftp_session sftp_server_new(ssh_session session, ssh_channel chan)
    # int sftp_server_init(sftp_session sftp)
    enum:
        SSH_FXP_INIT
        SSH_FXP_VERSION
        SSH_FXP_OPEN
        SSH_FXP_CLOSE
        SSH_FXP_READ
        SSH_FXP_WRITE
        SSH_FXP_LSTAT
        SSH_FXP_FSTAT
        SSH_FXP_SETSTAT
        SSH_FXP_FSETSTAT
        SSH_FXP_OPENDIR
        SSH_FXP_READDIR
        SSH_FXP_REMOVE
        SSH_FXP_MKDIR
        SSH_FXP_RMDIR
        SSH_FXP_REALPATH
        SSH_FXP_STAT
        SSH_FXP_RENAME
        SSH_FXP_READLINK
        SSH_FXP_SYMLINK
        SSH_FXP_STATUS
        SSH_FXP_HANDLE
        SSH_FXP_DATA
        SSH_FXP_NAME
        SSH_FXP_ATTRS
        SSH_FXP_EXTENDED
        SSH_FXP_EXTENDED_REPLY
    enum:
        SSH_FILEXFER_ATTR_SIZE
        SSH_FILEXFER_ATTR_PERMISSIONS
        SSH_FILEXFER_ATTR_ACCESSTIME
        SSH_FILEXFER_ATTR_ACMODTIME
        SSH_FILEXFER_ATTR_CREATETIME
        SSH_FILEXFER_ATTR_MODIFYTIME
        SSH_FILEXFER_ATTR_ACL
        SSH_FILEXFER_ATTR_OWNERGROUP
        SSH_FILEXFER_ATTR_SUBSECOND_TIMES
        SSH_FILEXFER_ATTR_EXTENDED
        SSH_FILEXFER_ATTR_UIDGID
    # Types
    enum:
        SSH_FILEXFER_TYPE_REGULAR
        SSH_FILEXFER_TYPE_DIRECTORY
        SSH_FILEXFER_TYPE_SYMLINK
        SSH_FILEXFER_TYPE_SPECIAL
        SSH_FILEXFER_TYPE_UNKNOWN
    enum:
        SSH_FX_OK
        SSH_FX_EOF
        SSH_FX_NO_SUCH_FILE
        SSH_FX_PERMISSION_DENIED
        SSH_FX_FAILURE
        SSH_FX_BAD_MESSAGE
        SSH_FX_NO_CONNECTION
        SSH_FX_CONNECTION_LOST
        SSH_FX_OP_UNSUPPORTED
        SSH_FX_INVALID_HANDLE
        SSH_FX_NO_SUCH_PATH
        SSH_FX_FILE_ALREADY_EXISTS
        SSH_FX_WRITE_PROTECT
        SSH_FX_NO_MEDIA
    enum:
        SSH_FXF_READ
        SSH_FXF_WRITE
        SSH_FXF_APPEND
        SSH_FXF_CREAT
        SSH_FXF_TRUNC
        SSH_FXF_EXCL
        SSH_FXF_TEXT
    enum:
        SSH_S_IFMT
        SSH_S_IFSOCK
        SSH_S_IFLNK
        SSH_S_IFREG
        SSH_S_IFBLK
        SSH_S_IFDIR
        SSH_S_IFCHR
        SSH_S_IFIFO
    enum:
        SSH_FXF_RENAME_OVERWRITE
        SSH_FXF_RENAME_ATOMIC
        SSH_FXF_RENAME_NATIVE
    enum:
        SFTP_OPEN
        SFTP_CLOSE
        SFTP_READ
        SFTP_WRITE
        SFTP_LSTAT
        SFTP_FSTAT
        SFTP_SETSTAT
        SFTP_FSETSTAT
        SFTP_OPENDIR
        SFTP_READDIR
        SFTP_REMOVE
        SFTP_MKDIR
        SFTP_RMDIR
        SFTP_REALPATH
        SFTP_STAT
        SFTP_RENAME
        SFTP_READLINK
        SFTP_SYMLINK
    enum:
        SSH_FXE_STATVFS_ST_RDONLY
        SSH_FXE_STATVFS_ST_NOSUID
