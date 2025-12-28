cimport c_ssh


SSH_LOG_NONE = c_ssh.SSH_LOG_NONE
SSH_LOG_WARN = c_ssh.SSH_LOG_WARN
SSH_LOG_INFO = c_ssh.SSH_LOG_INFO
SSH_LOG_DEBUG = c_ssh.SSH_LOG_DEBUG
SSH_LOG_TRACE = c_ssh.SSH_LOG_TRACE


def set_log_level(int level):
    """Set log level to one of SSH_LOG_*"""
    cdef int rc = c_ssh.ssh_set_log_level(level)
    return rc


def get_log_level():
    """Get current log level as one of SSH_LOG_*"""
    cdef int rc = c_ssh.ssh_get_log_level()
    if rc == SSH_LOG_NONE:
        return SSH_LOG_NONE
    elif rc == SSH_LOG_WARN:
        return SSH_LOG_WARN
    elif rc == SSH_LOG_INFO:
        return SSH_LOG_INFO
    elif rc == SSH_LOG_DEBUG:
        return SSH_LOG_DEBUG
    elif rc == SSH_LOG_TRACE:
        return SSH_LOG_TRACE
