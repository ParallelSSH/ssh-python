#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"
#include "libssh/options.h"
#include "libssh/session.h"

extern LIBSSH_THREAD int ssh_log_level;

#define LIBSSH_TESTCONFIG1 "libssh_testconfig1.tmp"
#define LIBSSH_TESTCONFIG2 "libssh_testconfig2.tmp"
#define LIBSSH_TESTCONFIG3 "libssh_testconfig3.tmp"
#define LIBSSH_TESTCONFIG4 "libssh_testconfig4.tmp"
#define LIBSSH_TESTCONFIG5 "libssh_testconfig5.tmp"
#define LIBSSH_TESTCONFIG6 "libssh_testconfig6.tmp"
#define LIBSSH_TESTCONFIG7 "libssh_testconfig7.tmp"
#define LIBSSH_TESTCONFIG8 "libssh_testconfig8.tmp"
#define LIBSSH_TESTCONFIGGLOB "libssh_testc*[36].tmp"

#define USERNAME "testuser"
#define PROXYCMD "ssh -q -W %h:%p gateway.example.com"
#define ID_FILE "/etc/xxx"
#define KEXALGORITHMS "ecdh-sha2-nistp521,diffie-hellman-group14-sha1"
#define HOSTKEYALGORITHMS "ssh-ed25519,ecdsa-sha2-nistp521,ssh-rsa"
#define MACS "hmac-sha1,hmac-sha2-256"
#define USER_KNOWN_HOSTS "%d/my_known_hosts"
#define GLOBAL_KNOWN_HOSTS "/etc/ssh/my_ssh_known_hosts"
#define BIND_ADDRESS "::1"

static int setup_config_files(void **state)
{
    ssh_session session;

    unlink(LIBSSH_TESTCONFIG1);
    unlink(LIBSSH_TESTCONFIG2);
    unlink(LIBSSH_TESTCONFIG3);
    unlink(LIBSSH_TESTCONFIG4);
    unlink(LIBSSH_TESTCONFIG5);
    unlink(LIBSSH_TESTCONFIG6);
    unlink(LIBSSH_TESTCONFIG7);
    unlink(LIBSSH_TESTCONFIG8);

    torture_write_file(LIBSSH_TESTCONFIG1,
                       "User "USERNAME"\nInclude "LIBSSH_TESTCONFIG2"\n\n");
    torture_write_file(LIBSSH_TESTCONFIG2,
                       "Include "LIBSSH_TESTCONFIG3"\n"
                       "ProxyCommand "PROXYCMD"\n\n");
    torture_write_file(LIBSSH_TESTCONFIG3,
                       "\n\nIdentityFile "ID_FILE"\n"
                       "\n\nKexAlgorithms "KEXALGORITHMS"\n"
                       "\n\nHostKeyAlgorithms "HOSTKEYALGORITHMS"\n"
                       "\n\nMACs "MACS"\n");

    /* Multiple Port settings -> parsing returns early. */
    torture_write_file(LIBSSH_TESTCONFIG4,
                       "Port 123\nPort 456\n");

    /* Testing glob include */
    torture_write_file(LIBSSH_TESTCONFIG5,
                        "User "USERNAME"\nInclude "LIBSSH_TESTCONFIGGLOB"\n\n");

    torture_write_file(LIBSSH_TESTCONFIG6,
                        "ProxyCommand "PROXYCMD"\n\n");

    /* new options */
    torture_write_file(LIBSSH_TESTCONFIG7,
                        "\tBindAddress "BIND_ADDRESS"\n"
                        "\tConnectTimeout 30\n"
                        "\tLogLevel DEBUG3\n"
                        "\tGlobalKnownHostsFile "GLOBAL_KNOWN_HOSTS"\n"
                        "\tUserKnownHostsFile "USER_KNOWN_HOSTS"\n");

    /* authentication methods */
    torture_write_file(LIBSSH_TESTCONFIG8,
                        "Host gss\n"
                        "\tGSSAPIAuthentication yes\n"
                        "Host kbd\n"
                        "\tKbdInteractiveAuthentication yes\n"
                        "Host pass\n"
                        "\tPasswordAuthentication yes\n"
                        "Host pubkey\n"
                        "\tPubkeyAuthentication yes\n"
                        "Host nogss\n"
                        "\tGSSAPIAuthentication no\n"
                        "Host nokbd\n"
                        "\tKbdInteractiveAuthentication no\n"
                        "Host nopass\n"
                        "\tPasswordAuthentication no\n"
                        "Host nopubkey\n"
                        "\tPubkeyAuthentication no\n");

    session = ssh_new();
    *state = session;

    return 0;
}

static int teardown(void **state)
{
    unlink(LIBSSH_TESTCONFIG1);
    unlink(LIBSSH_TESTCONFIG2);
    unlink(LIBSSH_TESTCONFIG3);
    unlink(LIBSSH_TESTCONFIG4);
    unlink(LIBSSH_TESTCONFIG5);
    unlink(LIBSSH_TESTCONFIG6);
    unlink(LIBSSH_TESTCONFIG7);
    unlink(LIBSSH_TESTCONFIG8);

    ssh_free(*state);

    return 0;
}


/**
 * @brief tests ssh_config_parse_file with Include directives
 */
static void torture_config_from_file(void **state) {
    ssh_session session = *state;
    int ret;
    char *v;

    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG1);
    assert_true(ret == 0);

    /* Test the variable presence */

    ret = ssh_options_get(session, SSH_OPTIONS_PROXYCOMMAND, &v);
    assert_true(ret == 0);

    assert_string_equal(v, PROXYCMD);
    ssh_string_free_char(v);

    ret = ssh_options_get(session, SSH_OPTIONS_IDENTITY, &v);
    assert_true(ret == 0);

    assert_string_equal(v, ID_FILE);
    ssh_string_free_char(v);

    ret = ssh_options_get(session, SSH_OPTIONS_USER, &v);
    assert_true(ret == 0);

    assert_string_equal(v, USERNAME);
    ssh_string_free_char(v);

    assert_string_equal(session->opts.wanted_methods[SSH_KEX], KEXALGORITHMS);

    assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS], HOSTKEYALGORITHMS);

    assert_string_equal(session->opts.wanted_methods[SSH_MAC_C_S], MACS);
    assert_string_equal(session->opts.wanted_methods[SSH_MAC_S_C], MACS);
}

/**
 * @brief tests ssh_config_parse_file with multiple Port settings.
 */
static void torture_config_double_ports(void **state) {
    ssh_session session = *state;
    int ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG4);
    assert_true(ret == 0);
}

static void torture_config_glob(void **state) {
    ssh_session session = *state;
    int ret;
#ifdef HAVE_GLOB
    char *v;
#endif

    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG5);
    assert_true(ret == 0); /* non-existing files should not error */

    /* Test the variable presence */

#ifdef HAVE_GLOB
    ret = ssh_options_get(session, SSH_OPTIONS_PROXYCOMMAND, &v);
    assert_true(ret == 0);

    assert_string_equal(v, PROXYCMD);
    ssh_string_free_char(v);

    ret = ssh_options_get(session, SSH_OPTIONS_IDENTITY, &v);
    assert_true(ret == 0);

    assert_string_equal(v, ID_FILE);
    ssh_string_free_char(v);
#endif /* HAVE_GLOB */
}

/**
 * @brief Verify the new options are passed from configuration
 */
static void torture_config_new(void **state)
{
    ssh_session session = *state;
    int ret = 0;
    int verbosity = SSH_LOG_WARNING;

    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG7);
    assert_true(ret == 0);

    assert_string_equal(session->opts.knownhosts, USER_KNOWN_HOSTS);
    assert_string_equal(session->opts.global_knownhosts, GLOBAL_KNOWN_HOSTS);
    assert_int_equal(session->opts.timeout, 30);
    assert_string_equal(session->opts.bindaddr, BIND_ADDRESS);

    assert_int_equal(ssh_log_level, SSH_LOG_TRACE);
    assert_int_equal(session->common.log_verbosity, SSH_LOG_TRACE);

    /* reset to something sane */
    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
}

/**
 * @brief Verify the authentication methods from configuration are effective
 */
static void torture_config_auth_methods(void **state) {
    ssh_session session = *state;
    int ret = 0;

    /* gradually disable all the methods based on different hosts */
    ssh_options_set(session, SSH_OPTIONS_HOST, "nogss");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG8);
    assert_true(ret == 0);
    assert_false(session->opts.flags & SSH_OPT_FLAG_GSSAPI_AUTH);
    assert_true(session->opts.flags & SSH_OPT_FLAG_KBDINT_AUTH);

    ssh_options_set(session, SSH_OPTIONS_HOST, "nokbd");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG8);
    assert_true(ret == 0);
    assert_false(session->opts.flags & SSH_OPT_FLAG_KBDINT_AUTH);

    ssh_options_set(session, SSH_OPTIONS_HOST, "nopass");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG8);
    assert_true(ret == 0);
    assert_false(session->opts.flags & SSH_OPT_FLAG_PASSWORD_AUTH);

    ssh_options_set(session, SSH_OPTIONS_HOST, "nopubkey");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG8);
    assert_true(ret == 0);
    assert_false(session->opts.flags & SSH_OPT_FLAG_PUBKEY_AUTH);

    /* no method should be left enabled */
    assert_int_equal(session->opts.port, 0);

    /* gradually enable them again */
    ssh_options_set(session, SSH_OPTIONS_HOST, "gss");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG8);
    assert_true(ret == 0);
    assert_true(session->opts.flags & SSH_OPT_FLAG_GSSAPI_AUTH);
    assert_false(session->opts.flags & SSH_OPT_FLAG_KBDINT_AUTH);

    ssh_options_set(session, SSH_OPTIONS_HOST, "kbd");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG8);
    assert_true(ret == 0);
    assert_true(session->opts.flags & SSH_OPT_FLAG_KBDINT_AUTH);

    ssh_options_set(session, SSH_OPTIONS_HOST, "pass");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG8);
    assert_true(ret == 0);
    assert_true(session->opts.flags & SSH_OPT_FLAG_PASSWORD_AUTH);

    ssh_options_set(session, SSH_OPTIONS_HOST, "pubkey");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG8);
    assert_true(ret == 0);
    assert_true(session->opts.flags & SSH_OPT_FLAG_PUBKEY_AUTH);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_config_from_file,
                                        setup_config_files,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_double_ports,
                                        setup_config_files,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_glob,
                                        setup_config_files,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_new,
                                        setup_config_files,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_auth_methods,
                                        setup_config_files,
                                        teardown),
    };


    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
