#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"
#include <libssh/libssh.h>
#include "libssh/priv.h"

#include <sys/types.h>
#include <pwd.h>

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
    int verbosity = torture_libssh_verbosity();
    struct passwd *pwd;

    pwd = getpwnam("bob");
    assert_non_null(pwd);
    setuid(pwd->pw_uid);

    s->ssh.session = ssh_new();
    assert_non_null(s->ssh.session);

    ssh_options_set(s->ssh.session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(s->ssh.session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);

    ssh_options_set(s->ssh.session, SSH_OPTIONS_USER, TORTURE_SSH_USER_ALICE);

    return 0;
}

static int session_teardown(void **state)
{
    struct torture_state *s = *state;

    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

static void torture_options_set_proxycommand(void **state) {
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, "nc 127.0.0.10 22");
    assert_int_equal(rc, 0);
    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);
}

static void torture_options_set_proxycommand_notexist(void **state) {
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, "this_command_does_not_exist");
    assert_int_equal(rc, SSH_OK);
    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_ERROR);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_options_set_proxycommand,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_proxycommand_notexist,
                                        session_setup,
                                        session_teardown),
    };


    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);
    ssh_finalize();

    return rc;
}
