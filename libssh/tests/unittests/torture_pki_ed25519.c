#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"
#include "torture_key.h"
#include "torture_pki.h"
#include "pki.c"
#include <sys/stat.h>
#include <fcntl.h>

#define LIBSSH_ED25519_TESTKEY "libssh_testkey.id_ed25519"
#define LIBSSH_ED25519_TESTKEY_PASSPHRASE "libssh_testkey_passphrase.id_ed25519"

const unsigned char HASH[] = "12345678901234567890";
const uint8_t ref_signature[ED25519_SIG_LEN]=
    "\xbb\x8d\x55\x9f\x06\x14\x39\x24\xb4\xe1\x5a\x57\x3d\x9d\xbe\x22"
    "\x1b\xc1\x32\xd5\x55\x16\x00\x64\xce\xb4\xc3\xd2\xe3\x6f\x5e\x8d"
    "\x10\xa3\x18\x93\xdf\xa4\x96\x81\x11\x8e\x1e\x26\x14\x8a\x08\x1b"
    "\x01\x6a\x60\x59\x9c\x4a\x55\xa3\x16\x56\xf6\xc4\x50\x42\x7f\x03";

static int setup_ed25519_key(void **state)
{
    (void) state; /* unused */

    unlink(LIBSSH_ED25519_TESTKEY);
    unlink(LIBSSH_ED25519_TESTKEY_PASSPHRASE);
    unlink(LIBSSH_ED25519_TESTKEY ".pub");

    torture_write_file(LIBSSH_ED25519_TESTKEY,
                       torture_get_testkey(SSH_KEYTYPE_ED25519, 0,0));
    torture_write_file(LIBSSH_ED25519_TESTKEY_PASSPHRASE,
                       torture_get_testkey(SSH_KEYTYPE_ED25519, 0,0));

    torture_write_file(LIBSSH_ED25519_TESTKEY ".pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_ED25519,0));

    return 0;
}

static int teardown(void **state) {
    (void) state; /* unused */

    unlink(LIBSSH_ED25519_TESTKEY);
    unlink(LIBSSH_ED25519_TESTKEY_PASSPHRASE);
    unlink(LIBSSH_ED25519_TESTKEY ".pub");

    return 0;
}

static void torture_pki_ed25519_import_privkey_base64(void **state)
{
    int rc;
    char *key_str;
    ssh_key key;
    const char *passphrase = torture_get_testkey_passphrase();
    enum ssh_keytypes_e type;

    (void) state; /* unused */

    key_str = torture_pki_read_file(LIBSSH_ED25519_TESTKEY);
    assert_true(key_str != NULL);

    rc = ssh_pki_import_privkey_base64(key_str, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);

    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_ED25519);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    rc = ssh_key_is_public(key);
    assert_true(rc == 1);

    free(key_str);
    ssh_key_free(key);

}

static void torture_pki_ed25519_publickey_from_privatekey(void **state)
{
    int rc;
    ssh_key key;
    ssh_key pubkey;
    const char *passphrase = NULL;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_ED25519, 0, 0),
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == 0);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_true(rc == SSH_OK);

    ssh_key_free(key);
    ssh_key_free(pubkey);
}

static void torture_pki_ed25519_publickey_base64(void **state)
{
    enum ssh_keytypes_e type;
    char *b64_key, *key_buf, *p;
    const char *q;
    ssh_key key;
    int rc;

    (void) state; /* unused */

    key_buf = strdup(torture_get_testkey_pub(SSH_KEYTYPE_ED25519, 0));
    assert_true(key_buf != NULL);

    q = p = key_buf;
    while (*p != ' ') p++;
    *p = '\0';

    type = ssh_key_type_from_name(q);
    assert_true(type == SSH_KEYTYPE_ED25519);

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

static void torture_pki_ed25519_generate_pubkey_from_privkey(void **state)
{
    char pubkey_generated[4096] = {0};
    ssh_key privkey;
    ssh_key pubkey;
    int rc;
    int len;

    (void) state; /* unused */

    /* remove the public key, generate it from the private key and write it. */
    unlink(LIBSSH_ED25519_TESTKEY ".pub");

    rc = ssh_pki_import_privkey_file(LIBSSH_ED25519_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_file(pubkey, LIBSSH_ED25519_TESTKEY ".pub");
    assert_true(rc == 0);

    rc = torture_read_one_line(LIBSSH_ED25519_TESTKEY ".pub",
                               pubkey_generated,
                               sizeof(pubkey_generated));
    assert_true(rc == 0);

    len = torture_pubkey_len(torture_get_testkey_pub(SSH_KEYTYPE_ED25519, 0));
    assert_memory_equal(torture_get_testkey_pub(SSH_KEYTYPE_ED25519, 0),
                        pubkey_generated,
                        len);

    ssh_key_free(privkey);
    ssh_key_free(pubkey);
}

static void torture_pki_ed25519_generate_key(void **state)
{
    int rc;
    ssh_key key;
    ssh_signature sign;
    enum ssh_keytypes_e type = SSH_KEYTYPE_UNKNOWN;
    const char *type_char = NULL;
    ssh_session session=ssh_new();
    (void) state;

    rc = ssh_pki_generate(SSH_KEYTYPE_ED25519, 256, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_ED25519);
    type_char = ssh_key_type_to_char(type);
    assert_true(strcmp(type_char, "ssh-ed25519") == 0);

    /* try an invalid signature */
    (*sign->ed25519_sig)[3]^= 0xff;
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_ERROR);

    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    ssh_free(session);
}

static void torture_pki_ed25519_write_privkey(void **state)
{
    ssh_key origkey;
    ssh_key privkey;
    int rc;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_file(LIBSSH_ED25519_TESTKEY,
            NULL,
            NULL,
            NULL,
            &origkey);
    assert_true(rc == 0);

    unlink(LIBSSH_ED25519_TESTKEY);

    rc = ssh_pki_export_privkey_file(origkey,
            NULL,
            NULL,
            NULL,
            LIBSSH_ED25519_TESTKEY);
    assert_true(rc == 0);

    rc = ssh_pki_import_privkey_file(LIBSSH_ED25519_TESTKEY,
            NULL,
            NULL,
            NULL,
            &privkey);
    assert_true(rc == 0);

    rc = ssh_key_cmp(origkey, privkey, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    unlink(LIBSSH_ED25519_TESTKEY);
    ssh_key_free(privkey);
    /* do the same with passphrase */
    rc = ssh_pki_export_privkey_file(origkey,
            torture_get_testkey_passphrase(),
            NULL,
            NULL,
            LIBSSH_ED25519_TESTKEY);
    assert_true(rc == 0);

    rc = ssh_pki_import_privkey_file(LIBSSH_ED25519_TESTKEY,
            NULL,
            NULL,
            NULL,
            &privkey);
    /* opening without passphrase should fail */
    assert_true(rc == SSH_ERROR);

    rc = ssh_pki_import_privkey_file(LIBSSH_ED25519_TESTKEY,
            torture_get_testkey_passphrase(),
            NULL,
            NULL,
            &privkey);
    assert_true(rc == 0);

    rc = ssh_key_cmp(origkey, privkey, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);
    unlink(LIBSSH_ED25519_TESTKEY);

    ssh_key_free(origkey);
    ssh_key_free(privkey);

    /* Test with passphrase */
    rc = ssh_pki_import_privkey_file(LIBSSH_ED25519_TESTKEY_PASSPHRASE,
                                     torture_get_testkey_passphrase(),
                                     NULL,
                                     NULL,
                                     &origkey);
    assert_true(rc == 0);

    unlink(LIBSSH_ED25519_TESTKEY_PASSPHRASE);
    rc = ssh_pki_export_privkey_file(origkey,
                                     torture_get_testkey_passphrase(),
                                     NULL,
                                     NULL,
                                     LIBSSH_ED25519_TESTKEY_PASSPHRASE);
    assert_true(rc == 0);

    /* Test with invalid passphrase */
    rc = ssh_pki_import_privkey_file(LIBSSH_ED25519_TESTKEY_PASSPHRASE,
                                     "invalid secret",
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == SSH_ERROR);

    rc = ssh_pki_import_privkey_file(LIBSSH_ED25519_TESTKEY_PASSPHRASE,
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

static void torture_pki_ed25519_sign(void **state){
    ssh_key privkey;
    ssh_signature sig = ssh_signature_new();
    ssh_string blob;
    int rc;
    (void)state;

    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_ED25519,0,0), NULL, NULL, NULL, &privkey);
    assert_true(rc == SSH_OK);

    sig->type = SSH_KEYTYPE_ED25519;
    rc = pki_ed25519_sign(privkey, sig, HASH, sizeof(HASH));
    assert_true(rc == SSH_OK);

    blob = pki_signature_to_blob(sig);
    assert_true(blob != NULL);

    assert_int_equal(ssh_string_len(blob), sizeof(ref_signature));
    assert_memory_equal(ssh_string_data(blob), ref_signature, sizeof(ref_signature));
    /* ssh_print_hexa("signature", ssh_string_data(blob), ssh_string_len(blob)); */
    ssh_signature_free(sig);
    ssh_key_free(privkey);
    ssh_string_free(blob);

}

static void torture_pki_ed25519_verify(void **state){
    ssh_key pubkey;
    ssh_signature sig;
    ssh_string blob = ssh_string_new(ED25519_SIG_LEN);
    char *pkey_ptr = strdup(strchr(torture_get_testkey_pub(SSH_KEYTYPE_ED25519,0), ' ') + 1);
    char *ptr;
    int rc;
    (void) state;

    /* remove trailing comment */
    ptr = strchr(pkey_ptr, ' ');
    if(ptr != NULL){
        *ptr = '\0';
    }
    rc = ssh_pki_import_pubkey_base64(pkey_ptr, SSH_KEYTYPE_ED25519, &pubkey);
    assert_true(rc == SSH_OK);

    ssh_string_fill(blob, ref_signature, ED25519_SIG_LEN);
    sig = pki_signature_from_blob(pubkey, blob, SSH_KEYTYPE_ED25519);
    assert_true(sig != NULL);

    rc = pki_ed25519_verify(pubkey, sig, HASH, sizeof(HASH));
    assert_true(rc == SSH_OK);

    ssh_signature_free(sig);
    /* alter signature and expect false result */

    ssh_key_free(pubkey);
    ssh_string_free(blob);
    free(pkey_ptr);
}

static void torture_pki_ed25519_verify_bad(void **state){
    ssh_key pubkey;
    ssh_signature sig;
    ssh_string blob = ssh_string_new(ED25519_SIG_LEN);
    char *pkey_ptr = strdup(strchr(torture_get_testkey_pub(SSH_KEYTYPE_ED25519,0), ' ') + 1);
    char *ptr;
    int rc;
    int i;
    (void) state;

    /* remove trailing comment */
    ptr = strchr(pkey_ptr, ' ');
    if(ptr != NULL){
        *ptr = '\0';
    }
    rc = ssh_pki_import_pubkey_base64(pkey_ptr, SSH_KEYTYPE_ED25519, &pubkey);
    assert_true(rc == SSH_OK);

    /* alter signature and expect false result */

    for (i=0; i < ED25519_SIG_LEN; ++i){
        ssh_string_fill(blob, ref_signature, ED25519_SIG_LEN);
        ((uint8_t *)ssh_string_data(blob))[i] ^= 0xff;
        sig = pki_signature_from_blob(pubkey, blob, SSH_KEYTYPE_ED25519);
        assert_true(sig != NULL);

        rc = pki_ed25519_verify(pubkey, sig, HASH, sizeof(HASH));
        assert_true(rc == SSH_ERROR);
        ssh_signature_free(sig);

    }
    ssh_key_free(pubkey);
    ssh_string_free(blob);
    free(pkey_ptr);
}

static void torture_pki_ed25519_import_privkey_base64_passphrase(void **state)
{
    int rc;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();

    (void) state; /* unused */

    /* same for ED25519 */
    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_ED25519, 0, 1),
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == 0);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    ssh_key_free(key);
    key = NULL;

    /* test if it returns -1 if passphrase is wrong */
    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_ED25519, 0, 1),
                                       "wrong passphrase !!",
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);
    ssh_key_free(key);
}

static void torture_pki_ed25519_privkey_dup(void **state)
{
    const char *passphrase = torture_get_testkey_passphrase();
    ssh_key key = NULL;
    ssh_key dup = NULL;
    int rc;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_ED25519, 0, 1),
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == 0);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    dup = ssh_key_dup(key);
    assert_non_null(dup);

    SAFE_FREE(key);
    SAFE_FREE(dup);
}

static void torture_pki_ed25519_pubkey_dup(void **state)
{
    ssh_key pubkey = NULL;
    ssh_key dup = NULL;
    const char *p = strchr(torture_get_testkey_pub(SSH_KEYTYPE_ED25519, 0), ' ');
    char *pub_str = NULL;
    char *q = NULL;
    int rc;

    (void) state; /* unused */

    pub_str = strdup(p + 1);
    assert_non_null(pub_str);

    q = strchr(pub_str, ' ');
    assert_non_null(q);
    *q = '\0';

    rc = ssh_pki_import_pubkey_base64(pub_str,
                                      SSH_KEYTYPE_ED25519,
                                      &pubkey);
    assert_true(rc == 0);

    rc = ssh_key_is_public(pubkey);
    assert_true(rc == 1);

    dup = ssh_key_dup(pubkey);
    assert_non_null(dup);

    rc = ssh_key_is_public(dup);
    assert_true(rc == 1);

    SAFE_FREE(pub_str);
    SAFE_FREE(pubkey);
    SAFE_FREE(dup);
}

int torture_run_tests(void) {
    int rc;
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_pki_ed25519_import_privkey_base64,
                                        setup_ed25519_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ed25519_publickey_from_privatekey,
                                        setup_ed25519_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ed25519_publickey_base64,
                                        setup_ed25519_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ed25519_generate_pubkey_from_privkey,
                                        setup_ed25519_key,
                                        teardown),
        cmocka_unit_test(torture_pki_ed25519_generate_key),
        cmocka_unit_test_setup_teardown(torture_pki_ed25519_write_privkey,
                                        setup_ed25519_key,
                                        teardown),
        cmocka_unit_test(torture_pki_ed25519_import_privkey_base64_passphrase),
        cmocka_unit_test(torture_pki_ed25519_sign),
        cmocka_unit_test(torture_pki_ed25519_verify),
        cmocka_unit_test(torture_pki_ed25519_verify_bad),
        cmocka_unit_test(torture_pki_ed25519_privkey_dup),
        cmocka_unit_test(torture_pki_ed25519_pubkey_dup),
    };

    ssh_init();
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
