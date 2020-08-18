#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"
#include "libssh/libssh.h"

static void torture_ssh_init(void **state) {
    int rc;

    (void) state;

    rc = ssh_init();
    assert_int_equal(rc, SSH_OK);
    rc = ssh_finalize();
    assert_int_equal(rc, SSH_OK);
}

static void torture_ssh_init_after_finalize(void **state) {

    int rc;

    (void) state;

    rc = ssh_init();
    assert_int_equal(rc, SSH_OK);
    rc = ssh_finalize();
    assert_int_equal(rc, SSH_OK);
    rc = ssh_init();
    assert_int_equal(rc, SSH_OK);
    rc = ssh_finalize();
    assert_int_equal(rc, SSH_OK);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_ssh_init),
        cmocka_unit_test(torture_ssh_init_after_finalize),
    };

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);

    return rc;
}
