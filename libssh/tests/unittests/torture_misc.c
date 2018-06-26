#include "config.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#ifndef _WIN32

#define _POSIX_PTHREAD_SEMANTICS
#include <pwd.h>
#endif

#define LIBSSH_STATIC
#include <libssh/priv.h>

#include "torture.h"
#include "misc.c"
#include "error.c"

#define TORTURE_TEST_DIR "/usr/local/bin/truc/much/.."


static int setup(void **state)
{
    ssh_session session = ssh_new();
    *state = session;

    return 0;
}

static int teardown(void **state)
{
    ssh_free(*state);

    return 0;
}

static void torture_get_user_home_dir(void **state) {
#ifndef _WIN32
    struct passwd *pwd = getpwuid(getuid());
#endif /* _WIN32 */
    char *user;

    (void) state;

    user = ssh_get_user_home_dir();
    assert_false(user == NULL);
#ifndef _WIN32
    assert_string_equal(user, pwd->pw_dir);
#endif /* _WIN32 */

    SAFE_FREE(user);
}

static void torture_basename(void **state) {
    char *path;

    (void) state;

    path=ssh_basename(TORTURE_TEST_DIR "/test");
    assert_true(path != NULL);
    assert_string_equal(path, "test");
    SAFE_FREE(path);
    path=ssh_basename(TORTURE_TEST_DIR "/test/");
    assert_true(path != NULL);
    assert_string_equal(path, "test");
    SAFE_FREE(path);
}

static void torture_dirname(void **state) {
    char *path;

    (void) state;

    path=ssh_dirname(TORTURE_TEST_DIR "/test");
    assert_true(path != NULL);
    assert_string_equal(path, TORTURE_TEST_DIR );
    SAFE_FREE(path);
    path=ssh_dirname(TORTURE_TEST_DIR "/test/");
    assert_true(path != NULL);
    assert_string_equal(path, TORTURE_TEST_DIR);
    SAFE_FREE(path);
}

static void torture_ntohll(void **state) {
    uint64_t value = 0x0123456789abcdef;
    uint32_t sample = 1;
    unsigned char *ptr = (unsigned char *) &sample;
    uint64_t check;

    (void) state;

    if (ptr[0] == 1){
        /* we're in little endian */
        check = 0xefcdab8967452301;
    } else {
        /* big endian */
        check = value;
    }
    value = ntohll(value);
    assert_true(value == check);
}

#ifdef _WIN32

static void torture_path_expand_tilde_win(void **state) {
    char *d;

    (void) state;

    d = ssh_path_expand_tilde("~\\.ssh");
    assert_false(d == NULL);
    print_message("Expanded path: %s\n", d);
    free(d);

    d = ssh_path_expand_tilde("/guru/meditation");
    assert_string_equal(d, "/guru/meditation");
    free(d);
}

#else /* _WIN32 */

static void torture_path_expand_tilde_unix(void **state) {
    char h[256];
    char *d;
    char *user;
    char *home;

    (void) state;

    user = getenv("USER");
    if (user == NULL){
        user = getenv("LOGNAME");
    }
    /* in certain CIs there no such variables */
    if (!user){
        struct passwd *pw = getpwuid(getuid());
        if (pw){
            user = pw->pw_name;
        }
    }

    home = getenv("HOME");
    assert_non_null(home);
    snprintf(h, 256 - 1, "%s/.ssh", home);

    d = ssh_path_expand_tilde("~/.ssh");
    assert_non_null(d);
    assert_string_equal(d, h);
    free(d);

    d = ssh_path_expand_tilde("/guru/meditation");
    assert_non_null(d);
    assert_string_equal(d, "/guru/meditation");
    free(d);

    snprintf(h, 256 - 1, "~%s/.ssh", user);
    d = ssh_path_expand_tilde(h);
    assert_non_null(d);

    snprintf(h, 256 - 1, "%s/.ssh", home);
    assert_string_equal(d, h);
    free(d);
}

#endif /* _WIN32 */

static void torture_path_expand_escape(void **state) {
    ssh_session session = *state;
    const char *s = "%d/%h/by/%r";
    char *e;

    session->opts.sshdir = strdup("guru");
    session->opts.host = strdup("meditation");
    session->opts.username = strdup("root");

    e = ssh_path_expand_escape(session, s);
    assert_non_null(e);
    assert_string_equal(e, "guru/meditation/by/root");
    free(e);
}

static void torture_path_expand_known_hosts(void **state) {
    ssh_session session = *state;
    char *tmp;

    session->opts.sshdir = strdup("/home/guru/.ssh");

    tmp = ssh_path_expand_escape(session, "%d/known_hosts");
    assert_non_null(tmp);
    assert_string_equal(tmp, "/home/guru/.ssh/known_hosts");
    free(tmp);
}

static void torture_timeout_elapsed(void **state){
    struct ssh_timestamp ts;
    (void) state;
    ssh_timestamp_init(&ts);
    usleep(50000);
    assert_true(ssh_timeout_elapsed(&ts,25));
    assert_false(ssh_timeout_elapsed(&ts,30000));
    assert_false(ssh_timeout_elapsed(&ts,75));
    assert_true(ssh_timeout_elapsed(&ts,0));
    assert_false(ssh_timeout_elapsed(&ts,-1));
}

static void torture_timeout_update(void **state){
    struct ssh_timestamp ts;
    (void) state;
    ssh_timestamp_init(&ts);
    usleep(50000);
    assert_int_equal(ssh_timeout_update(&ts,25), 0);
    assert_in_range(ssh_timeout_update(&ts,30000),29000,29960);
    assert_in_range(ssh_timeout_update(&ts,75),1,40);
    assert_int_equal(ssh_timeout_update(&ts,0),0);
    assert_int_equal(ssh_timeout_update(&ts,-1),-1);
}

static void torture_ssh_analyze_banner(void **state) {
    int rc = 0;
    int ssh1 = 0;
    int ssh2 = 0;
    ssh_session session = NULL;
    (void) state;

#define reset_banner_test() \
    do {                           \
        rc = 0;                    \
        ssh1 = 0;                  \
        ssh2 = 0;                  \
        ssh_free(session);         \
        session = ssh_new();       \
        assert_non_null(session);  \
    } while (0)

#define assert_banner_rejected(is_server) \
    do {                                                            \
        rc = ssh_analyze_banner(session, is_server, &ssh1, &ssh2);  \
        assert_int_not_equal(0, rc);                                \
    } while (0);

#define assert_client_banner_rejected(banner) \
    do {                                         \
        reset_banner_test();                     \
        session->clientbanner = strdup(banner);  \
        assert_non_null(session->clientbanner);  \
        assert_banner_rejected(1 /*server*/);    \
        SAFE_FREE(session->clientbanner);        \
    } while (0)

#define assert_server_banner_rejected(banner) \
    do {                                         \
        reset_banner_test();                     \
        session->serverbanner = strdup(banner);  \
        assert_non_null(session->serverbanner);  \
        assert_banner_rejected(0 /*client*/);    \
        SAFE_FREE(session->serverbanner);        \
    } while (0)

#define assert_banner_accepted(is_server, expected_ssh1, expected_ssh2) \
    do {                                                            \
        rc = ssh_analyze_banner(session, is_server, &ssh1, &ssh2);  \
        assert_int_equal(0, rc);                                    \
        assert_int_equal(expected_ssh1, ssh1);                      \
        assert_int_equal(expected_ssh2, ssh2);                      \
    } while (0)

#define assert_client_banner_accepted(banner, e1, e2) \
    do {                                               \
        reset_banner_test();                           \
        session->clientbanner = strdup(banner);        \
        assert_non_null(session->clientbanner);        \
        assert_banner_accepted(1 /*server*/, e1, e2);  \
        SAFE_FREE(session->clientbanner);              \
    } while (0)

#define assert_server_banner_accepted(banner, e1, e2) \
    do {                                               \
        reset_banner_test();                           \
        session->serverbanner = strdup(banner);        \
        assert_non_null(session->serverbanner);        \
        assert_banner_accepted(0 /*client*/, e1, e2);  \
        SAFE_FREE(session->serverbanner);              \
    } while (0)

    /* no banner is set */
    reset_banner_test();
    assert_banner_rejected(0 /*client*/);
    reset_banner_test();
    assert_banner_rejected(1 /*server*/);

    /* banner is too short */
    assert_client_banner_rejected("abc");
    assert_server_banner_rejected("abc");

    /* banner doesn't start "SSH-" */
    assert_client_banner_rejected("abc-2.0");
    assert_server_banner_rejected("abc-2.0");

    /* SSH v1 */
    assert_client_banner_accepted("SSH-1.0", 1, 0);
    assert_server_banner_accepted("SSH-1.0", 1, 0);

    /* SSH v1.9 gets counted as both v1 and v2 */
    assert_client_banner_accepted("SSH-1.9", 1, 1);
    assert_server_banner_accepted("SSH-1.9", 1, 1);

    /* SSH v2 */
    assert_client_banner_accepted("SSH-2.0", 0, 1);
    assert_server_banner_accepted("SSH-2.0", 0, 1);

    /* OpenSSH banners: too short to extract major and minor versions */
    assert_client_banner_accepted("SSH-2.0-OpenSSH", 0, 1);
    assert_int_equal(0, session->openssh);
    assert_server_banner_accepted("SSH-2.0-OpenSSH", 0, 1);
    assert_int_equal(0, session->openssh);

    /* OpenSSH banners: big enough to extract major and minor versions */
    assert_client_banner_accepted("SSH-2.0-OpenSSH_5.9p1", 0, 1);
    assert_int_equal(SSH_VERSION_INT(5, 9, 0), session->openssh);
    assert_server_banner_accepted("SSH-2.0-OpenSSH_5.9p1", 0, 1);
    assert_int_equal(SSH_VERSION_INT(5, 9, 0), session->openssh);

    assert_client_banner_accepted("SSH-2.0-OpenSSH_1.99", 0, 1);
    assert_int_equal(SSH_VERSION_INT(1, 99, 0), session->openssh);
    assert_server_banner_accepted("SSH-2.0-OpenSSH_1.99", 0, 1);
    assert_int_equal(SSH_VERSION_INT(1, 99, 0), session->openssh);

    /* OpenSSH banners: major, minor version limits result in zero */
    assert_client_banner_accepted("SSH-2.0-OpenSSH_0.99p1", 0, 1);
    assert_int_equal(0, session->openssh);
    assert_server_banner_accepted("SSH-2.0-OpenSSH_0.99p1", 0, 1);
    assert_int_equal(0, session->openssh);
    assert_client_banner_accepted("SSH-2.0-OpenSSH_1.101p1", 0, 1);
    assert_int_equal(0, session->openssh);
    assert_server_banner_accepted("SSH-2.0-OpenSSH_1.101p1", 0, 1);
    assert_int_equal(0, session->openssh);

    /* OpenSSH banners: bogus major results in zero */
    assert_client_banner_accepted("SSH-2.0-OpenSSH_X.9p1", 0, 1);
    assert_int_equal(0, session->openssh);
    assert_server_banner_accepted("SSH-2.0-OpenSSH_X.9p1", 0, 1);
    assert_int_equal(0, session->openssh);

    /* OpenSSH banners: bogus minor results in zero */
    assert_server_banner_accepted("SSH-2.0-OpenSSH_5.Yp1", 0, 1);
    assert_int_equal(0, session->openssh);
    assert_client_banner_accepted("SSH-2.0-OpenSSH_5.Yp1", 0, 1);
    assert_int_equal(0, session->openssh);

    /* OpenSSH banners: ssh-keyscan(1) */
    assert_client_banner_accepted("SSH-2.0-OpenSSH-keyscan", 0, 1);
    assert_int_equal(0, session->openssh);
    assert_server_banner_accepted("SSH-2.0-OpenSSH-keyscan", 0, 1);
    assert_int_equal(0, session->openssh);

    ssh_free(session);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_get_user_home_dir),
        cmocka_unit_test(torture_basename),
        cmocka_unit_test(torture_dirname),
        cmocka_unit_test(torture_ntohll),
#ifdef _WIN32
        cmocka_unit_test(torture_path_expand_tilde_win),
#else
        cmocka_unit_test(torture_path_expand_tilde_unix),
#endif
        cmocka_unit_test_setup_teardown(torture_path_expand_escape, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_path_expand_known_hosts, setup, teardown),
        cmocka_unit_test(torture_timeout_elapsed),
        cmocka_unit_test(torture_timeout_update),
        cmocka_unit_test(torture_ssh_analyze_banner),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
