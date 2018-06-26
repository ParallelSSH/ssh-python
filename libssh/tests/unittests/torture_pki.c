#include "config.h"

#define LIBSSH_STATIC

#include <sys/stat.h>
#include <fcntl.h>

#include "torture.h"
#include "torture_pki.h"
#include "pki.c"

static void torture_pki_keytype(void **state) {
    enum ssh_keytypes_e type;
    const char *type_c;

    (void) state; /* unused */

    type = ssh_key_type(NULL);
    assert_true(type == SSH_KEYTYPE_UNKNOWN);

    type = ssh_key_type_from_name(NULL);
    assert_true(type == SSH_KEYTYPE_UNKNOWN);

    type = ssh_key_type_from_name("42");
    assert_true(type == SSH_KEYTYPE_UNKNOWN);

    type_c = ssh_key_type_to_char(SSH_KEYTYPE_UNKNOWN);
    assert_true(type_c == NULL);

    type_c = ssh_key_type_to_char(42);
    assert_true(type_c == NULL);
}

static void torture_pki_signature(void **state)
{
    ssh_signature sig;

    (void) state; /* unused */

    sig = ssh_signature_new();
    assert_true(sig != NULL);

    ssh_signature_free(sig);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_pki_keytype),
        cmocka_unit_test(torture_pki_signature),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
