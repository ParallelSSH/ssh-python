#define LIBSSH_STATIC

#include "config.h"

#include "torture.h"
#include "sftp.c"

#include <sys/types.h>
#include <pwd.h>

#define MAX_XFER_BUF_SIZE 16384

static int sshd_setup(void **state)
{
    torture_setup_sshd_server(state);

    return 0;
}

static int sshd_teardown(void **state) {
    torture_teardown_sshd_server(state);

    return 0;
}

static int session_setup(void **state)
{
    struct torture_state *s = *state;
    struct passwd *pwd;

    pwd = getpwnam("bob");
    assert_non_null(pwd);
    setuid(pwd->pw_uid);

    s->ssh.session = torture_ssh_session(TORTURE_SSH_SERVER,
                                         NULL,
                                         TORTURE_SSH_USER_ALICE,
                                         NULL);
    assert_non_null(s->ssh.session);

    s->ssh.tsftp = torture_sftp_session(s->ssh.session);
    assert_non_null(s->ssh.tsftp);

    return 0;
}

static int session_teardown(void **state)
{
    struct torture_state *s = *state;

    torture_rmdirs(s->ssh.tsftp->testdir);
    torture_sftp_close(s->ssh.tsftp);
    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

static void torture_sftp_read_blocking(void **state) {
    struct torture_state *s = *state;
    struct torture_sftp *t = s->ssh.tsftp;

    char libssh_tmp_file[] = "/tmp/libssh_sftp_test_XXXXXX";
    char buf[MAX_XFER_BUF_SIZE];
    ssize_t bytesread;
    ssize_t byteswritten;
    int fd;
    sftp_file file;
    mode_t mask;

    file = sftp_open(t->sftp, "/usr/bin/ssh", O_RDONLY, 0);
    assert_non_null(file);

    mask = umask(S_IRWXO | S_IRWXG);
    fd = mkstemp(libssh_tmp_file);
    umask(mask);
    unlink(libssh_tmp_file);

    for (;;) {
        bytesread = sftp_read(file, buf, MAX_XFER_BUF_SIZE);
        if (bytesread == 0) {
                break; /* EOF */
        }
        assert_false(bytesread < 0);

        byteswritten = write(fd, buf, bytesread);
        assert_int_equal(byteswritten, bytesread);
    }

    close(fd);
    sftp_close(file);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_sftp_read_blocking,
                                        session_setup,
                                        session_teardown)
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);
    ssh_finalize();

    return rc;
}
