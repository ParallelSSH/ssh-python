#include "config.h"

#define LIBSSH_STATIC

#include <sys/stat.h>
#include <fcntl.h>

#include "torture.h"
#include "torture_key.h"
#include "torture_pki.h"
#include "pki.c"

#define LIBSSH_ECDSA_TESTKEY "libssh_testkey.id_ecdsa"
#define LIBSSH_ECDSA_TESTKEY_PASSPHRASE "libssh_testkey_passphrase.id_ecdsa"

const unsigned char ECDSA_HASH[] = "12345678901234567890";

static int setup_ecdsa_key(void **state, int ecdsa_bits)
{
    (void) state; /* unused */

    unlink(LIBSSH_ECDSA_TESTKEY);
    unlink(LIBSSH_ECDSA_TESTKEY_PASSPHRASE);
    unlink(LIBSSH_ECDSA_TESTKEY ".pub");

    torture_write_file(LIBSSH_ECDSA_TESTKEY,
                       torture_get_testkey(SSH_KEYTYPE_ECDSA, ecdsa_bits, 0));
    torture_write_file(LIBSSH_ECDSA_TESTKEY_PASSPHRASE,
                       torture_get_testkey(SSH_KEYTYPE_ECDSA, ecdsa_bits, 0));
    torture_write_file(LIBSSH_ECDSA_TESTKEY ".pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_ECDSA, ecdsa_bits));

    return 0;
}

static int setup_ecdsa_key_521(void **state)
{
    setup_ecdsa_key(state, 521);

    return 0;
}

static int setup_ecdsa_key_384(void **state)
{
    setup_ecdsa_key(state, 384);

    return 0;
}

static int setup_ecdsa_key_256(void **state)
{
    setup_ecdsa_key(state, 256);

    return 0;
}

static int teardown(void **state)
{
    (void) state; /* unused */

    unlink(LIBSSH_ECDSA_TESTKEY);
    unlink(LIBSSH_ECDSA_TESTKEY_PASSPHRASE);
    unlink(LIBSSH_ECDSA_TESTKEY ".pub");

    return 0;
}

static void torture_pki_ecdsa_import_privkey_base64(void **state)
{
    int rc;
    char *key_str;
    ssh_key key;
    const char *passphrase = torture_get_testkey_passphrase();

    (void) state; /* unused */

    key_str = torture_pki_read_file(LIBSSH_ECDSA_TESTKEY);
    assert_true(key_str != NULL);

    rc = ssh_pki_import_privkey_base64(key_str, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    free(key_str);
    ssh_key_free(key);
}

static void torture_pki_ecdsa_publickey_from_privatekey(void **state)
{
    int rc;
    char *key_str;
    ssh_key key;
    ssh_key pubkey;
    const char *passphrase = NULL;

    (void) state; /* unused */

    key_str = torture_pki_read_file(LIBSSH_ECDSA_TESTKEY);
    assert_true(key_str != NULL);

    rc = ssh_pki_import_privkey_base64(key_str, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);

    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_true(rc == SSH_OK);

    free(key_str);
    ssh_key_free(key);
    ssh_key_free(pubkey);
}

static void torture_pki_ecdsa_publickey_base64(void **state)
{
    enum ssh_keytypes_e type;
    char *b64_key, *key_buf, *p;
    const char *q;
    ssh_key key;
    int rc;

    (void) state; /* unused */

    key_buf = torture_pki_read_file(LIBSSH_ECDSA_TESTKEY ".pub");
    assert_true(key_buf != NULL);

    q = p = key_buf;
    while (*p != ' ') p++;
    *p = '\0';

    type = ssh_key_type_from_name(q);
    assert_true(type == SSH_KEYTYPE_ECDSA);

    q = ++p;
    while (*p != ' ') p++;
    *p = '\0';

    rc = ssh_pki_import_pubkey_base64(q, type, &key);
    assert_true(rc == 0);

    rc = ssh_pki_export_pubkey_base64(key, &b64_key);
    assert_true(rc == 0);

    assert_string_equal(q, b64_key);

    free(b64_key);
    free(key_buf);
    ssh_key_free(key);
}

static void torture_pki_ecdsa_generate_pubkey_from_privkey(void **state)
{
    char pubkey_original[4096] = {0};
    char pubkey_generated[4096] = {0};
    ssh_key privkey;
    ssh_key pubkey;
    int rc;
    int len;

    (void) state; /* unused */

    rc = torture_read_one_line(LIBSSH_ECDSA_TESTKEY ".pub",
                               pubkey_original,
                               sizeof(pubkey_original));
    assert_true(rc == 0);

    /* remove the public key, generate it from the private key and write it. */
    unlink(LIBSSH_ECDSA_TESTKEY ".pub");

    rc = ssh_pki_import_privkey_file(LIBSSH_ECDSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_file(pubkey, LIBSSH_ECDSA_TESTKEY ".pub");
    assert_true(rc == 0);

    rc = torture_read_one_line(LIBSSH_ECDSA_TESTKEY ".pub",
                               pubkey_generated,
                               sizeof(pubkey_generated));
    assert_true(rc == 0);
    len = torture_pubkey_len(pubkey_original);
    assert_int_equal(strncmp(pubkey_original, pubkey_generated, len), 0);

    ssh_key_free(privkey);
    ssh_key_free(pubkey);
}

static void torture_pki_ecdsa_duplicate_key(void **state)
{
    int rc;
    char *b64_key;
    char *b64_key_gen;
    ssh_key pubkey;
    ssh_key privkey;
    ssh_key privkey_dup;

    (void) state;

    rc = ssh_pki_import_pubkey_file(LIBSSH_ECDSA_TESTKEY ".pub", &pubkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key);
    assert_true(rc == 0);
    ssh_key_free(pubkey);

    rc = ssh_pki_import_privkey_file(LIBSSH_ECDSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    privkey_dup = ssh_key_dup(privkey);
    assert_true(privkey_dup != NULL);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key_gen);
    assert_true(rc == 0);

    assert_string_equal(b64_key, b64_key_gen);

    rc = ssh_key_cmp(privkey, privkey_dup, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    ssh_key_free(pubkey);
    ssh_key_free(privkey);
    ssh_key_free(privkey_dup);
    ssh_string_free_char(b64_key);
    ssh_string_free_char(b64_key_gen);
}

/* Test case for bug #147: Private ECDSA key duplication did not carry
 * over parts of the key that then caused subsequent key demotion to
 * fail.
 */
static void torture_pki_ecdsa_duplicate_then_demote(void **state)
{
    ssh_key pubkey;
    ssh_key privkey;
    ssh_key privkey_dup;
    int rc;

    (void) state;

    rc = ssh_pki_import_privkey_file(LIBSSH_ECDSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    privkey_dup = ssh_key_dup(privkey);
    assert_true(privkey_dup != NULL);
    assert_int_equal(privkey->ecdsa_nid, privkey_dup->ecdsa_nid);

    rc = ssh_pki_export_privkey_to_pubkey(privkey_dup, &pubkey);
    assert_true(rc == 0);
    assert_int_equal(pubkey->ecdsa_nid, privkey->ecdsa_nid);

    ssh_key_free(pubkey);
    ssh_key_free(privkey);
    ssh_key_free(privkey_dup);
}

static void torture_pki_generate_key_ecdsa(void **state)
{
    int rc;
    ssh_key key;
    ssh_signature sign;
    enum ssh_keytypes_e type = SSH_KEYTYPE_UNKNOWN;
    const char *type_char = NULL;
    const char *etype_char = NULL;
    ssh_session session=ssh_new();
    (void) state;

    rc = ssh_pki_generate(SSH_KEYTYPE_ECDSA, 256, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, ECDSA_HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,ECDSA_HASH,20);
    assert_true(rc == SSH_OK);
    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_ECDSA);
    type_char = ssh_key_type_to_char(type);
    assert_true(strcmp(type_char, "ssh-ecdsa") == 0);
    etype_char = ssh_pki_key_ecdsa_name(key);
    assert_true(strcmp(etype_char, "ecdsa-sha2-nistp256") == 0);

    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_ECDSA, 384, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, ECDSA_HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,ECDSA_HASH,20);
    assert_true(rc == SSH_OK);
    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_ECDSA);
    type_char = ssh_key_type_to_char(type);
    assert_true(strcmp(type_char, "ssh-ecdsa") == 0);
    etype_char =ssh_pki_key_ecdsa_name(key);
    assert_true(strcmp(etype_char, "ecdsa-sha2-nistp384") == 0);

    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_ECDSA, 512, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, ECDSA_HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,ECDSA_HASH,20);
    assert_true(rc == SSH_OK);
    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_ECDSA);
    type_char = ssh_key_type_to_char(type);
    assert_true(strcmp(type_char, "ssh-ecdsa") == 0);
    etype_char =ssh_pki_key_ecdsa_name(key);
    assert_true(strcmp(etype_char, "ecdsa-sha2-nistp521") == 0);

    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    ssh_free(session);
}

static void torture_pki_ecdsa_write_privkey(void **state)
{
    ssh_key origkey;
    ssh_key privkey;
    int rc;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_file(LIBSSH_ECDSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &origkey);
    assert_true(rc == 0);

    unlink(LIBSSH_ECDSA_TESTKEY);

    rc = ssh_pki_export_privkey_file(origkey,
                                     NULL,
                                     NULL,
                                     NULL,
                                     LIBSSH_ECDSA_TESTKEY);
    assert_true(rc == 0);

    rc = ssh_pki_import_privkey_file(LIBSSH_ECDSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_key_cmp(origkey, privkey, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    ssh_key_free(origkey);
    ssh_key_free(privkey);

    /* Test with passphrase */
    rc = ssh_pki_import_privkey_file(LIBSSH_ECDSA_TESTKEY_PASSPHRASE,
                                     torture_get_testkey_passphrase(),
                                     NULL,
                                     NULL,
                                     &origkey);
    assert_true(rc == 0);

    unlink(LIBSSH_ECDSA_TESTKEY_PASSPHRASE);
    rc = ssh_pki_export_privkey_file(origkey,
                                     torture_get_testkey_passphrase(),
                                     NULL,
                                     NULL,
                                     LIBSSH_ECDSA_TESTKEY_PASSPHRASE);
    assert_true(rc == 0);

    /* Test with invalid passphrase */
    rc = ssh_pki_import_privkey_file(LIBSSH_ECDSA_TESTKEY_PASSPHRASE,
                                     "invalid secret",
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == SSH_ERROR);

    rc = ssh_pki_import_privkey_file(LIBSSH_ECDSA_TESTKEY_PASSPHRASE,
                                     torture_get_testkey_passphrase(),
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_key_cmp(origkey, privkey, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    ssh_key_free(origkey);
    ssh_key_free(privkey);
}

static void torture_pki_ecdsa_name(void **state, const char *expected_name)
{
    int rc;
    ssh_key key;
    const char *etype_char = NULL;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_file(LIBSSH_ECDSA_TESTKEY, NULL, NULL, NULL, &key);
    assert_true(rc == 0);

    etype_char =ssh_pki_key_ecdsa_name(key);
    assert_true(strcmp(etype_char, expected_name) == 0);

    ssh_key_free(key);
}

static void torture_pki_ecdsa_name256(void **state)
{
    torture_pki_ecdsa_name(state, "ecdsa-sha2-nistp256");
}

static void torture_pki_ecdsa_name384(void **state)
{
    torture_pki_ecdsa_name(state, "ecdsa-sha2-nistp384");
}

static void torture_pki_ecdsa_name521(void **state)
{
    torture_pki_ecdsa_name(state, "ecdsa-sha2-nistp521");
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_import_privkey_base64,
                                        setup_ecdsa_key_256,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_import_privkey_base64,
                                        setup_ecdsa_key_384,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_import_privkey_base64,
                                        setup_ecdsa_key_521,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_publickey_from_privatekey,
                                        setup_ecdsa_key_256,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_publickey_from_privatekey,
                                        setup_ecdsa_key_384,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_publickey_from_privatekey,
                                        setup_ecdsa_key_521,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_duplicate_then_demote,
                                        setup_ecdsa_key_256,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_duplicate_then_demote,
                                        setup_ecdsa_key_384,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_duplicate_then_demote,
                                        setup_ecdsa_key_521,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_publickey_base64,
                                        setup_ecdsa_key_256,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_publickey_base64,
                                        setup_ecdsa_key_384,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_publickey_base64,
                                        setup_ecdsa_key_521,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_generate_pubkey_from_privkey,
                                        setup_ecdsa_key_256,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_generate_pubkey_from_privkey,
                                        setup_ecdsa_key_384,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_generate_pubkey_from_privkey,
                                        setup_ecdsa_key_521,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_duplicate_key,
                                        setup_ecdsa_key_256,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_duplicate_key,
                                        setup_ecdsa_key_384,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_duplicate_key,
                                        setup_ecdsa_key_521,
                                        teardown),
        cmocka_unit_test(torture_pki_generate_key_ecdsa),
#ifdef HAVE_LIBCRYPTO
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_write_privkey,
                                        setup_ecdsa_key_256,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_write_privkey,
                                        setup_ecdsa_key_384,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_write_privkey,
                                        setup_ecdsa_key_521,
                                        teardown),
#endif /* HAVE_LIBCRYPTO */
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_name256,
                                        setup_ecdsa_key_256,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_name384,
                                        setup_ecdsa_key_384,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_name521,
                                        setup_ecdsa_key_521,
                                        teardown),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
