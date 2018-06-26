/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2017 Sartura d.o.o.
 *
 * Author: Juraj Vijtiuk <juraj.vijtiuk@sartura.hr>
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"

#ifdef HAVE_LIBMBEDCRYPTO
#include <mbedtls/pk.h>
#include <mbedtls/error.h>

#include "libssh/priv.h"
#include "libssh/pki.h"
#include "libssh/pki_priv.h"
#include "libssh/buffer.h"
#include "libssh/bignum.h"

#define MAX_PASSPHRASE_SIZE 1024
#define MAX_KEY_SIZE 32

ssh_string pki_private_key_to_pem(const ssh_key key, const char *passphrase,
        ssh_auth_callback auth_fn, void *auth_data)
{
    (void) key;
    (void) passphrase;
    (void) auth_fn;
    (void) auth_data; return NULL;
}

static int pki_key_ecdsa_to_nid(mbedtls_ecdsa_context *ecdsa)
{
    mbedtls_ecp_group_id id;

    id = ecdsa->grp.id;
    if (id == MBEDTLS_ECP_DP_SECP256R1) {
        return NID_mbedtls_nistp256;
    } else if (id == MBEDTLS_ECP_DP_SECP384R1) {
        return NID_mbedtls_nistp384;
    } else if (id == MBEDTLS_ECP_DP_SECP521R1) {
        return NID_mbedtls_nistp521;
    }

    return -1;
}

ssh_key pki_private_key_from_base64(const char *b64_key, const char *passphrase,
        ssh_auth_callback auth_fn, void *auth_data)
{
    ssh_key key = NULL;
    mbedtls_pk_context *rsa = NULL;
    mbedtls_pk_context *ecdsa = NULL;
    ed25519_privkey *ed25519 = NULL;
    enum ssh_keytypes_e type;
    int valid;
    /* mbedtls pk_parse_key expects strlen to count the 0 byte */
    size_t b64len = strlen(b64_key) + 1;
    unsigned char tmp[MAX_PASSPHRASE_SIZE] = {0};

    if (ssh_init() < 0) {
        return NULL;
    }

    type = pki_privatekey_type_from_string(b64_key);
    if (type == SSH_KEYTYPE_UNKNOWN) {
        SSH_LOG(SSH_LOG_WARN, "Unknown or invalid private key.");
        return NULL;
    }

    switch (type) {
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            rsa = malloc(sizeof(mbedtls_pk_context));
            if (rsa == NULL) {
                return NULL;
            }

            mbedtls_pk_init(rsa);

            if (passphrase == NULL) {
                if (auth_fn) {
                    valid = auth_fn("Passphrase for private key:", (char *) tmp,
                            MAX_PASSPHRASE_SIZE, 0, 0, auth_data);
                    if (valid < 0) {
                        return NULL;
                    }
                    /* TODO fix signedness and strlen */
                    valid = mbedtls_pk_parse_key(rsa,
                            (const unsigned char *) b64_key,
                            b64len, tmp,
                            strnlen((const char *) tmp, MAX_PASSPHRASE_SIZE));
                } else {
                    valid = mbedtls_pk_parse_key(rsa,
                            (const unsigned char *) b64_key,
                            b64len, NULL,
                            0);
                }
            } else {
                valid = mbedtls_pk_parse_key(rsa,
                        (const unsigned char *) b64_key, b64len,
                        (const unsigned char *) passphrase,
                        strnlen(passphrase, MAX_PASSPHRASE_SIZE));
            }

            if (valid != 0) {
                char error_buf[100];
                mbedtls_strerror(valid, error_buf, 100);
                SSH_LOG(SSH_LOG_WARN,"Parsing private key %s", error_buf);
                goto fail;
            }
            break;
        case SSH_KEYTYPE_ECDSA:
            ecdsa = malloc(sizeof(mbedtls_pk_context));
            if (ecdsa == NULL) {
                return NULL;
            }

            mbedtls_pk_init(ecdsa);

            if (passphrase == NULL) {
                if (auth_fn) {
                    valid = auth_fn("Passphrase for private key:", (char *) tmp,
                            MAX_PASSPHRASE_SIZE, 0, 0, auth_data);
                    if (valid < 0) {
                        return NULL;
                    }
                    valid = mbedtls_pk_parse_key(ecdsa,
                            (const unsigned char *) b64_key,
                            b64len, tmp,
                            strnlen((const char *) tmp, MAX_PASSPHRASE_SIZE));
                } else {
                    valid = mbedtls_pk_parse_key(ecdsa,
                            (const unsigned char *) b64_key,
                            b64len, NULL,
                            0);
                }
            } else {
                valid = mbedtls_pk_parse_key(ecdsa,
                        (const unsigned char *) b64_key, b64len,
                        (const unsigned char *) passphrase,
                        strnlen(passphrase, MAX_PASSPHRASE_SIZE));
            }

            if (valid != 0) {
                char error_buf[100];
                mbedtls_strerror(valid, error_buf, 100);
                SSH_LOG(SSH_LOG_WARN,"Parsing private key %s", error_buf);
                goto fail;
            }
            break;
        case SSH_KEYTYPE_ED25519:
            /* Cannot open ed25519 keys with libmbedcrypto */
        default:
            SSH_LOG(SSH_LOG_WARN, "Unknown or invalid private key type %d",
                    type);
            return NULL;
    }

    key = ssh_key_new();
    if (key == NULL) {
        goto fail;
    }

    key->type = type;
    key->type_c = ssh_key_type_to_char(type);
    key->flags = SSH_KEY_FLAG_PRIVATE | SSH_KEY_FLAG_PUBLIC;
    key->rsa = rsa;
    if (ecdsa != NULL) {
        mbedtls_ecp_keypair *keypair = mbedtls_pk_ec(*ecdsa);

        key->ecdsa = malloc(sizeof(mbedtls_ecdsa_context));
        if (key->ecdsa == NULL) {
            goto fail;
        }

        mbedtls_ecdsa_init(key->ecdsa);
        mbedtls_ecdsa_from_keypair(key->ecdsa, keypair);
        mbedtls_pk_free(ecdsa);
        SAFE_FREE(ecdsa);
    } else {
        key->ecdsa = NULL;
    }
    key->ed25519_privkey = ed25519;
    rsa = NULL;
    ecdsa = NULL;
    if (key->type == SSH_KEYTYPE_ECDSA) {
        key->ecdsa_nid = pki_key_ecdsa_to_nid(key->ecdsa);
        key->type_c = pki_key_ecdsa_nid_to_name(key->ecdsa_nid);
    }

    return key;
fail:
    ssh_key_free(key);
    if (rsa != NULL) {
        mbedtls_pk_free(rsa);
        SAFE_FREE(rsa);
    }
    if (ecdsa != NULL) {
        mbedtls_pk_free(ecdsa);
        SAFE_FREE(ecdsa);
    }
    return NULL;
}

int pki_pubkey_build_rsa(ssh_key key, ssh_string e, ssh_string n)
{
    mbedtls_rsa_context *rsa = NULL;
    const mbedtls_pk_info_t *pk_info = NULL;
    int rc;

    key->rsa = malloc(sizeof(mbedtls_pk_context));
    if (key->rsa == NULL) {
        return SSH_ERROR;
    }

    mbedtls_pk_init(key->rsa);
    pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
    mbedtls_pk_setup(key->rsa, pk_info);

    if (mbedtls_pk_can_do(key->rsa, MBEDTLS_PK_RSA)) {
        rsa = mbedtls_pk_rsa(*key->rsa);
        rc = mbedtls_mpi_read_binary(&rsa->N, ssh_string_data(n),
                ssh_string_len(n));
        if (rc != 0) {
            return SSH_ERROR;
        }
        rc = mbedtls_mpi_read_binary(&rsa->E, ssh_string_data(e),
                ssh_string_len(e));
        if (rc != 0) {
            return SSH_ERROR;
        }

        rsa->len = (mbedtls_mpi_bitlen(&rsa->N) + 7) >> 3;
    } else {
        return SSH_ERROR;
    }

    return SSH_OK;
}

ssh_key pki_key_dup(const ssh_key key, int demote)
{
    ssh_key new = NULL;
    int rc;
    const mbedtls_pk_info_t *pk_info = NULL;


    new = ssh_key_new();
    if (new == NULL) {
        return NULL;
    }

    new->type = key->type;
    new->type_c = key->type_c;
    if (demote) {
        new->flags = SSH_KEY_FLAG_PUBLIC;
    } else {
        new->flags = key->flags;
    }


    switch(key->type) {
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1: {
            mbedtls_rsa_context *rsa, *new_rsa;

            new->rsa = malloc(sizeof(mbedtls_pk_context));
            if (new->rsa == NULL) {
                goto fail;
            }

            mbedtls_pk_init(new->rsa);
            pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
            mbedtls_pk_setup(new->rsa, pk_info);

            if (mbedtls_pk_can_do(key->rsa, MBEDTLS_PK_RSA) &&
                        mbedtls_pk_can_do(new->rsa, MBEDTLS_PK_RSA)) {
                rsa = mbedtls_pk_rsa(*key->rsa);
                new_rsa = mbedtls_pk_rsa(*new->rsa);

                rc = mbedtls_mpi_copy(&new_rsa->N, &rsa->N);
                if (rc != 0) {
                    goto fail;
                }

                rc = mbedtls_mpi_copy(&new_rsa->E, &rsa->E);
                if (rc != 0) {
                    goto fail;
                }
                new_rsa->len = (mbedtls_mpi_bitlen(&new_rsa->N) + 7) >> 3;

                if (!demote && (key->flags & SSH_KEY_FLAG_PRIVATE)) {
                    rc = mbedtls_mpi_copy(&new_rsa->D, &rsa->D);
                    if (rc != 0) {
                        goto fail;
                    }

                    rc = mbedtls_mpi_copy(&new_rsa->P, &rsa->P);
                    if (rc != 0) {
                        goto fail;
                    }

                    rc = mbedtls_mpi_copy(&new_rsa->Q, &rsa->Q);
                    if (rc != 0) {
                        goto fail;
                    }

                    rc = mbedtls_mpi_copy(&new_rsa->DP, &rsa->DP);
                    if (rc != 0) {
                        goto fail;
                    }

                    rc = mbedtls_mpi_copy(&new_rsa->DQ, &rsa->DQ);
                    if (rc != 0) {
                        goto fail;
                    }

                    rc = mbedtls_mpi_copy(&new_rsa->QP, &rsa->QP);
                    if (rc != 0) {
                        goto fail;
                    }
                }
            } else {
                goto fail;
            }

            break;
        }
        case SSH_KEYTYPE_ECDSA:
            new->ecdsa_nid = key->ecdsa_nid;

            new->ecdsa = malloc(sizeof(mbedtls_ecdsa_context));

            if (new->ecdsa == NULL) {
                goto fail;
            }

            mbedtls_ecdsa_init(new->ecdsa);

            if (demote && ssh_key_is_private(key)) {
                rc = mbedtls_ecp_copy(&new->ecdsa->Q, &key->ecdsa->Q);
                if (rc != 0) {
                    goto fail;
                }

                rc = mbedtls_ecp_group_copy(&new->ecdsa->grp, &key->ecdsa->grp);
                if (rc != 0) {
                    goto fail;
                }
            } else {
                mbedtls_ecdsa_from_keypair(new->ecdsa, key->ecdsa);
            }

            break;
        case SSH_KEYTYPE_ED25519:
            rc = pki_ed25519_key_dup(new, key);
            if (rc != SSH_OK) {
                goto fail;
            }
            break;
        default:
            goto fail;
    }

    return new;
fail:
    ssh_key_free(new);
    return NULL;
}

int pki_key_generate_rsa(ssh_key key, int parameter)
{
    int rc;
    const mbedtls_pk_info_t *info = NULL;

    key->rsa = malloc(sizeof(mbedtls_pk_context));
    if (key->rsa == NULL) {
        return SSH_ERROR;
    }

    mbedtls_pk_init(key->rsa);

    info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
    rc = mbedtls_pk_setup(key->rsa, info);
    if (rc != 0) {
        return SSH_ERROR;
    }

    if (mbedtls_pk_can_do(key->rsa, MBEDTLS_PK_RSA)) {
        rc = mbedtls_rsa_gen_key(mbedtls_pk_rsa(*key->rsa), mbedtls_ctr_drbg_random,
                &ssh_mbedtls_ctr_drbg, parameter, 65537);
        if (rc != 0) {
            mbedtls_pk_free(key->rsa);
            return SSH_ERROR;
        }
    }

    return SSH_OK;
}

int pki_key_compare(const ssh_key k1, const ssh_key k2, enum ssh_keycmp_e what)
{
    switch (k1->type) {
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1: {
            mbedtls_rsa_context *rsa1, *rsa2;
            if (mbedtls_pk_can_do(k1->rsa, MBEDTLS_PK_RSA) &&
                    mbedtls_pk_can_do(k2->rsa, MBEDTLS_PK_RSA)) {
                if (mbedtls_pk_get_type(k1->rsa) != mbedtls_pk_get_type(k2->rsa) ||
                        mbedtls_pk_get_bitlen(k1->rsa) !=
                        mbedtls_pk_get_bitlen(k2->rsa)) {
                    return 1;
                }

                rsa1 = mbedtls_pk_rsa(*k1->rsa);
                rsa2 = mbedtls_pk_rsa(*k2->rsa);
                if (mbedtls_mpi_cmp_mpi(&rsa1->N, &rsa2->N) != 0) {
                    return 1;
                }

                if (mbedtls_mpi_cmp_mpi(&rsa1->E, &rsa2->E) != 0) {
                    return 1;
                }

                if (what == SSH_KEY_CMP_PRIVATE) {
                    if (mbedtls_mpi_cmp_mpi(&rsa1->P, &rsa2->P) != 0) {
                        return 1;
                    }

                    if (mbedtls_mpi_cmp_mpi(&rsa1->Q, &rsa2->Q) != 0) {
                        return 1;
                    }
                }
            }
            break;
        }
        case SSH_KEYTYPE_ECDSA: {
            mbedtls_ecp_keypair *ecdsa1 = k1->ecdsa;
            mbedtls_ecp_keypair *ecdsa2 = k2->ecdsa;

            if (ecdsa1->grp.id != ecdsa2->grp.id) {
                return 1;
            }

            if (mbedtls_mpi_cmp_mpi(&ecdsa1->Q.X, &ecdsa2->Q.X)) {
                return 1;
            }

            if (mbedtls_mpi_cmp_mpi(&ecdsa1->Q.Y, &ecdsa2->Q.Y)) {
                return 1;
            }

            if (mbedtls_mpi_cmp_mpi(&ecdsa1->Q.Z, &ecdsa2->Q.Z)) {
                return 1;
            }

            if (what == SSH_KEY_CMP_PRIVATE) {
                if (mbedtls_mpi_cmp_mpi(&ecdsa1->d, &ecdsa2->d)) {
                    return 1;
                }
            }

            break;
        }
        case SSH_KEYTYPE_ED25519:
            /* ed25519 keys handled globally */
            return 0;
        default:
            return 1;
    }

    return 0;
}

ssh_string make_ecpoint_string(const mbedtls_ecp_group *g, const
        mbedtls_ecp_point *p)
{
    ssh_string s = NULL;
    size_t len = 1;
    int rc;

    s = ssh_string_new(len);
    if (s == NULL) {
        return NULL;
    }

    rc = mbedtls_ecp_point_write_binary(g, p, MBEDTLS_ECP_PF_UNCOMPRESSED,
                &len, ssh_string_data(s), ssh_string_len(s));
    if (rc == MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL) {
        ssh_string_free(s);

        s = ssh_string_new(len);
        if (s == NULL) {
            return NULL;
        }

        rc = mbedtls_ecp_point_write_binary(g, p, MBEDTLS_ECP_PF_UNCOMPRESSED,
                &len, ssh_string_data(s), ssh_string_len(s));
    }

    if (rc != 0) {
        ssh_string_free(s);
        return NULL;
    }

    if (len != ssh_string_len(s)) {
        ssh_string_free(s);
        return NULL;
    }

    return s;
}

static const char* pki_key_ecdsa_nid_to_char(int nid)
{
    switch (nid) {
        case NID_mbedtls_nistp256:
            return "nistp256";
        case NID_mbedtls_nistp384:
            return "nistp384";
        case NID_mbedtls_nistp521:
            return "nistp521";
        default:
            break;
    }

    return "unknown";
}

ssh_string pki_publickey_to_blob(const ssh_key key)
{
    ssh_buffer buffer = NULL;
    ssh_string type_s = NULL;
    ssh_string e = NULL;
    ssh_string n = NULL;
    ssh_string str = NULL;
    int rc;

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        return NULL;
    }

    if (key->cert != NULL) {
        rc = ssh_buffer_add_buffer(buffer, key->cert);
        if (rc < 0) {
            ssh_buffer_free(buffer);
            return NULL;
        }

        goto makestring;
    }

    type_s = ssh_string_from_char(key->type_c);
    if (type_s == NULL) {
        ssh_buffer_free(buffer);
        return NULL;
    }

    rc = ssh_buffer_add_ssh_string(buffer, type_s);
    ssh_string_free(type_s);
    if (rc < 0) {
        ssh_buffer_free(buffer);
        return NULL;
    }

    switch (key->type) {
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1: {
            mbedtls_rsa_context *rsa;
            if (mbedtls_pk_can_do(key->rsa, MBEDTLS_PK_RSA) == 0) {
                ssh_buffer_free(buffer);
                return NULL;
            }

            rsa = mbedtls_pk_rsa(*key->rsa);

            e = ssh_make_bignum_string(&rsa->E);
            if (e == NULL) {
                goto fail;
            }

            n = ssh_make_bignum_string(&rsa->N);
            if (n == NULL) {
                goto fail;
            }

            if (ssh_buffer_add_ssh_string(buffer, e) < 0) {
                goto fail;
            }

            if (ssh_buffer_add_ssh_string(buffer, n) < 0) {
                goto fail;
            }

            ssh_string_burn(e);
            ssh_string_free(e);
            e = NULL;
            ssh_string_burn(n);
            ssh_string_free(n);
            n = NULL;

            break;
        }
        case SSH_KEYTYPE_ECDSA:
            rc = ssh_buffer_reinit(buffer);
            if (rc < 0) {
                ssh_buffer_free(buffer);
                return NULL;
            }

            type_s =
                ssh_string_from_char(pki_key_ecdsa_nid_to_name(key->ecdsa_nid));
            if (type_s == NULL) {
                ssh_buffer_free(buffer);
                return NULL;
            }

            rc = ssh_buffer_add_ssh_string(buffer, type_s);
            ssh_string_free(type_s);
            if (rc < 0) {
                ssh_buffer_free(buffer);
                return NULL;
            }

            type_s =
                ssh_string_from_char(pki_key_ecdsa_nid_to_char(key->ecdsa_nid));
            if (type_s == NULL) {
                ssh_buffer_free(buffer);
                return NULL;
            }

            rc = ssh_buffer_add_ssh_string(buffer, type_s);
            ssh_string_free(type_s);
            if (rc < 0) {
                ssh_buffer_free(buffer);
                return NULL;
            }

            e = make_ecpoint_string(&key->ecdsa->grp, &key->ecdsa->Q);

            if (e == NULL) {
                ssh_buffer_free(buffer);
                return NULL;
            }

            rc = ssh_buffer_add_ssh_string(buffer, e);
            if (rc < 0) {
                goto fail;
            }

            ssh_string_burn(e);
            ssh_string_free(e);
            e = NULL;

            break;
        case SSH_KEYTYPE_ED25519:
            rc = pki_ed25519_public_key_to_blob(buffer, key);
            if (rc != SSH_OK) {
                goto fail;
            }
            break;
        default:
            goto fail;
    }
makestring:
    str = ssh_string_new(ssh_buffer_get_len(buffer));
    if (str == NULL) {
        goto fail;
    }

    rc = ssh_string_fill(str, ssh_buffer_get(buffer),
            ssh_buffer_get_len(buffer));
    if (rc < 0) {
        goto fail;
    }

    ssh_buffer_free(buffer);
    return str;
fail:
    ssh_buffer_free(buffer);
    ssh_string_burn(str);
    ssh_string_free(str);
    ssh_string_burn(e);
    ssh_string_free(e);
    ssh_string_burn(n);
    ssh_string_free(n);

    return NULL;
}

int pki_export_pubkey_rsa1(const ssh_key key, const char *host, char *rsa1,
        size_t rsa1_len)
{
    char *e = NULL;
    char *n = NULL;
    int rsa_size = mbedtls_pk_get_bitlen(key->rsa);
    mbedtls_rsa_context *rsa = NULL;

    if (!mbedtls_pk_can_do(key->rsa, MBEDTLS_PK_RSA)) {
        return SSH_ERROR;
    }

    rsa = mbedtls_pk_rsa(*key->rsa);

    n = bignum_bn2dec(&rsa->N);
    if (n == NULL) {
        return SSH_ERROR;
    }

    e = bignum_bn2dec(&rsa->E);
    if (e == NULL) {
        return SSH_ERROR;
    }

    snprintf(rsa1, rsa1_len, "%s %d %s %s\n",
            host, rsa_size << 3, e, n);

    SAFE_FREE(e);
    SAFE_FREE(n);
    return SSH_OK;
}

ssh_string pki_signature_to_blob(const ssh_signature sig)
{
    ssh_string sig_blob = NULL;

    switch(sig->type) {
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            sig_blob = ssh_string_copy(sig->rsa_sig);
            break;
        case SSH_KEYTYPE_ECDSA: {
            ssh_string r;
            ssh_string s;
            ssh_buffer b;
            int rc;

            b = ssh_buffer_new();
            if (b == NULL) {
                return NULL;
            }

            r = ssh_make_bignum_string(sig->ecdsa_sig.r);
            if (r == NULL) {
                ssh_buffer_free(b);
                return NULL;
            }

            rc = ssh_buffer_add_ssh_string(b, r);
            ssh_string_free(r);
            if (rc < 0) {
                ssh_buffer_free(b);
                return NULL;
            }

            s = ssh_make_bignum_string(sig->ecdsa_sig.s);
            if (s == NULL) {
                ssh_buffer_free(b);
                return NULL;
            }

            rc = ssh_buffer_add_ssh_string(b, s);
            ssh_string_free(s);
            if (rc < 0) {
                ssh_buffer_free(b);
                return NULL;
            }

            sig_blob = ssh_string_new(ssh_buffer_get_len(b));
            if (sig_blob == NULL) {
                ssh_buffer_free(b);
                return NULL;
            }

            ssh_string_fill(sig_blob, ssh_buffer_get(b), ssh_buffer_get_len(b));
            ssh_buffer_free(b);
            break;
        }
        case SSH_KEYTYPE_ED25519:
            sig_blob = pki_ed25519_sig_to_blob(sig);
            break;
        default:
            SSH_LOG(SSH_LOG_WARN, "Unknown signature key type: %s",
                    sig->type_c);
            return NULL;
    }

    return sig_blob;
}

static ssh_signature pki_signature_from_rsa_blob(const ssh_key pubkey, const
        ssh_string sig_blob, ssh_signature sig)
{
    size_t pad_len = 0;
    char *blob_orig = NULL;
    char *blob_padded_data = NULL;
    ssh_string sig_blob_padded = NULL;

    size_t rsalen = 0;
    size_t len = ssh_string_len(sig_blob);

    if (pubkey->rsa == NULL) {
        SSH_LOG(SSH_LOG_WARN, "Pubkey RSA field NULL");
        goto errout;
    }

    rsalen = mbedtls_pk_get_bitlen(pubkey->rsa) / 8;
    if (len > rsalen) {
        SSH_LOG(SSH_LOG_WARN,
                "Signature is too big: %lu > %lu",
                (unsigned long) len,
                (unsigned long) rsalen);
        goto errout;
    }
#ifdef DEBUG_CRYPTO
    SSH_LOG(SSH_LOG_WARN, "RSA signature len: %lu", (unsigned long)len);
    ssh_print_hexa("RSA signature", ssh_string_data(sig_blob), len);
#endif

    if (len == rsalen) {
        sig->rsa_sig = ssh_string_copy(sig_blob);
    } else {
        SSH_LOG(SSH_LOG_DEBUG, "RSA signature len %lu < %lu",
                (unsigned long) len,
                (unsigned long) rsalen);
        pad_len = rsalen - len;

        sig_blob_padded = ssh_string_new(rsalen);
        if (sig_blob_padded == NULL) {
            goto errout;
        }

        blob_padded_data = (char *) ssh_string_data(sig_blob_padded);
        blob_orig = (char *) ssh_string_data(sig_blob);

        explicit_bzero(blob_padded_data, pad_len);
        memcpy(blob_padded_data + pad_len, blob_orig, len);

        sig->rsa_sig = sig_blob_padded;
    }

    return sig;

errout:
    ssh_signature_free(sig);
    return NULL;
}
ssh_signature pki_signature_from_blob(const ssh_key pubkey, const ssh_string
        sig_blob, enum ssh_keytypes_e type)
{
    ssh_signature sig = NULL;
    int rc;

    sig = ssh_signature_new();
    if (sig == NULL) {
        return NULL;
    }

    sig->type = type;
    sig->type_c = ssh_key_type_to_char(type);

    switch(type) {
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            sig = pki_signature_from_rsa_blob(pubkey, sig_blob, sig);
            break;
        case SSH_KEYTYPE_ECDSA: {
            ssh_buffer b;
            ssh_string r;
            ssh_string s;
            size_t rlen;

            b = ssh_buffer_new();
            if (b == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }

            rc = ssh_buffer_add_data(b, ssh_string_data(sig_blob),
                    ssh_string_len(sig_blob));

            if (rc < 0) {
                ssh_buffer_free(b);
                ssh_signature_free(sig);
                return NULL;
            }

            r = ssh_buffer_get_ssh_string(b);
            if (r == NULL) {
                ssh_buffer_free(b);
                ssh_signature_free(sig);
                return NULL;
            }
#ifdef DEBUG_CRYPTO
            ssh_print_hexa("r", ssh_string_data(r), ssh_string_len(r));
#endif
            sig->ecdsa_sig.r = ssh_make_string_bn(r);
            ssh_string_burn(r);
            ssh_string_free(r);
            if (sig->ecdsa_sig.r == NULL) {
                ssh_buffer_free(b);
                ssh_signature_free(sig);
                return NULL;
            }

            s = ssh_buffer_get_ssh_string(b);
            rlen = ssh_buffer_get_len(b);
            ssh_buffer_free(b);
            if (s == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }

#ifdef DEBUG_CRYPTO
            ssh_print_hexa("s", ssh_string_data(s), ssh_string_len(s));
#endif
            sig->ecdsa_sig.s = ssh_make_string_bn(s);
            ssh_string_burn(s);
            ssh_string_free(s);
            if (sig->ecdsa_sig.s == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }

            if (rlen != 0) {
                SSH_LOG(SSH_LOG_WARN, "Signature has remaining bytes in inner "
                        "sigblob: %lu",
                        (unsigned long)rlen);
                ssh_signature_free(sig);
                return NULL;
            }

            break;
        }
        case SSH_KEYTYPE_ED25519:
            rc = pki_ed25519_sig_from_blob(sig, sig_blob);
            if (rc == SSH_ERROR) {
                ssh_signature_free(sig);
                return NULL;
            }
            break;
        default:
            SSH_LOG(SSH_LOG_WARN, "Unknown signature type");
            return NULL;
    }

    return sig;
}

int pki_signature_verify(ssh_session session, const ssh_signature sig, const
        ssh_key key, const unsigned char *hash, size_t hlen)
{
    int rc;

    switch (key->type) {
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            rc = mbedtls_pk_verify(key->rsa, MBEDTLS_MD_SHA1, hash, hlen,
                    ssh_string_data(sig->rsa_sig),
                    ssh_string_len(sig->rsa_sig));
            if (rc != 0) {
                char error_buf[100];
                mbedtls_strerror(rc, error_buf, 100);
                ssh_set_error(session, SSH_FATAL, "RSA error: %s", error_buf);
                return SSH_ERROR;
            }
            break;
        case SSH_KEYTYPE_ECDSA:
            rc = mbedtls_ecdsa_verify(&key->ecdsa->grp, hash, hlen,
                    &key->ecdsa->Q, sig->ecdsa_sig.r, sig->ecdsa_sig.s);
            if (rc != 0) {
                char error_buf[100];
                mbedtls_strerror(rc, error_buf, 100);
                ssh_set_error(session, SSH_FATAL, "RSA error: %s", error_buf);
                return SSH_ERROR;

            }
            break;
        case SSH_KEYTYPE_ED25519:
            rc = pki_ed25519_verify(key, sig, hash, hlen);
            if (rc != SSH_OK) {
                ssh_set_error(session, SSH_FATAL,
                        "ed25519 signature verification error");
                return SSH_ERROR;
            }
            break;
        default:
            ssh_set_error(session, SSH_FATAL, "Unknown public key type");
            return SSH_ERROR;
    }

    return SSH_OK;
}

static ssh_string rsa_do_sign(const unsigned char *digest, int dlen,
        mbedtls_pk_context *privkey)
{
    ssh_string sig_blob = NULL;
    unsigned char *sig = NULL;
    size_t slen;
    int ok;

    sig = malloc(mbedtls_pk_get_bitlen(privkey) / 8);
    if (sig == NULL) {
        return NULL;
    }

    ok = mbedtls_pk_sign(privkey, MBEDTLS_MD_SHA1, digest, dlen, sig, &slen,
            mbedtls_ctr_drbg_random, &ssh_mbedtls_ctr_drbg);

    if (ok != 0) {
        SAFE_FREE(sig);
        return NULL;
    }

    sig_blob = ssh_string_new(slen);
    if (sig_blob == NULL) {
        SAFE_FREE(sig);
        return NULL;
    }

    ssh_string_fill(sig_blob, sig, slen);
    memset(sig, 'd', slen);
    SAFE_FREE(sig);

    return sig_blob;
}


ssh_signature pki_do_sign(const ssh_key privkey, const unsigned char *hash,
        size_t hlen)
{
    ssh_signature sig = NULL;
    int rc;

    sig = ssh_signature_new();
    if (sig == NULL) {
        return NULL;
    }

    sig->type = privkey->type;
    sig->type_c = privkey->type_c;

    switch(privkey->type) {
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            sig->rsa_sig = rsa_do_sign(hash, hlen, privkey->rsa);
            if (sig->rsa_sig == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }
            break;
         case SSH_KEYTYPE_ECDSA:
            sig->ecdsa_sig.r = bignum_new();
            if (sig->ecdsa_sig.r == NULL) {
                return NULL;
            }

            sig->ecdsa_sig.s = bignum_new();
            if (sig->ecdsa_sig.s == NULL) {
                bignum_free(sig->ecdsa_sig.r);
                return NULL;
            }

            rc = mbedtls_ecdsa_sign(&privkey->ecdsa->grp, sig->ecdsa_sig.r,
                    sig->ecdsa_sig.s, &privkey->ecdsa->d, hash, hlen,
                    mbedtls_ctr_drbg_random, &ssh_mbedtls_ctr_drbg);
            if (rc != 0) {
                ssh_signature_free(sig);
                return NULL;
            }
            break;
        case SSH_KEYTYPE_ED25519:
            rc = pki_ed25519_sign(privkey, sig, hash, hlen);
            if (rc != SSH_OK) {
                ssh_signature_free(sig);
                return NULL;
            }
            break;
        default:
            ssh_signature_free(sig);
            return NULL;

    }

    return sig;
}

#ifdef WITH_SERVER
ssh_signature pki_do_sign_sessionid(const ssh_key key, const unsigned char
        *hash, size_t hlen)
{
    ssh_signature sig = NULL;
    int rc;

    sig = ssh_signature_new();
    if (sig == NULL) {
        return NULL;
    }
    sig->type = key->type;
    sig->type_c = key->type_c;

    switch (key->type) {
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            sig->rsa_sig = rsa_do_sign(hash, hlen, key->rsa);
            if (sig->rsa_sig == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }
            break;
        case SSH_KEYTYPE_ECDSA:
            sig->ecdsa_sig.r = bignum_new();
            if (sig->ecdsa_sig.r == NULL) {
                return NULL;
            }

            sig->ecdsa_sig.s = bignum_new();
            if (sig->ecdsa_sig.s == NULL) {
                bignum_free(sig->ecdsa_sig.r);
                return NULL;
            }

            rc = mbedtls_ecdsa_sign(&key->ecdsa->grp, sig->ecdsa_sig.r,
                    sig->ecdsa_sig.s, &key->ecdsa->d, hash, hlen,
                    mbedtls_ctr_drbg_random, &ssh_mbedtls_ctr_drbg);
            if (rc != 0) {
                ssh_signature_free(sig);
                return NULL;
            }
            break;
        case SSH_KEYTYPE_ED25519:
            /* ED25519 handled in caller */
        default:
            ssh_signature_free(sig);
            return NULL;
    }

    return sig;
}
#endif /* WITH_SERVER */

const char *pki_key_ecdsa_nid_to_name(int nid)
{
    switch (nid) {
        case NID_mbedtls_nistp256:
            return "ecdsa-sha2-nistp256";
        case NID_mbedtls_nistp384:
            return "ecdsa-sha2-nistp384";
        case NID_mbedtls_nistp521:
            return "ecdsa-sha2-nistp521";
        default:
            break;
    }

    return "unknown";
}

int pki_key_ecdsa_nid_from_name(const char *name)
{
    if (strcmp(name, "nistp256") == 0) {
        return NID_mbedtls_nistp256;
    } else if (strcmp(name, "nistp384") == 0) {
        return NID_mbedtls_nistp384;
    } else if (strcmp(name, "nistp521") == 0) {
        return NID_mbedtls_nistp521;
    }

    return -1;
}

static mbedtls_ecp_group_id pki_key_ecdsa_nid_to_mbed_gid(int nid)
{
    switch (nid) {
        case NID_mbedtls_nistp256:
            return MBEDTLS_ECP_DP_SECP256R1;
        case NID_mbedtls_nistp384:
            return MBEDTLS_ECP_DP_SECP384R1;
        case NID_mbedtls_nistp521:
            return MBEDTLS_ECP_DP_SECP521R1;
    }

    return MBEDTLS_ECP_DP_NONE;
}

int pki_pubkey_build_ecdsa(ssh_key key, int nid, ssh_string e)
{
    int rc;
    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_group group;
    mbedtls_ecp_point Q;

    key->ecdsa_nid = nid;
    key->type_c = pki_key_ecdsa_nid_to_name(nid);

    key->ecdsa = malloc(sizeof(mbedtls_ecdsa_context));
    if (key->ecdsa == NULL) {
        return SSH_ERROR;
    }

    mbedtls_ecdsa_init(key->ecdsa);
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_point_init(&Q);

    rc = mbedtls_ecp_group_load(&group,
            pki_key_ecdsa_nid_to_mbed_gid(nid));
    if (rc != 0) {
        goto fail;
    }

    rc = mbedtls_ecp_point_read_binary(&group, &Q, ssh_string_data(e),
            ssh_string_len(e));
    if (rc != 0) {
        goto fail;
    }

    rc = mbedtls_ecp_copy(&keypair.Q, &Q);
    if (rc != 0) {
        goto fail;
    }

    rc = mbedtls_ecp_group_copy(&keypair.grp, &group);
    if (rc != 0) {
        goto fail;
    }

    mbedtls_mpi_init(&keypair.d);

    rc = mbedtls_ecdsa_from_keypair(key->ecdsa, &keypair);
    if (rc != 0) {
        goto fail;
    }

    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&group);
    mbedtls_ecp_keypair_free(&keypair);
    return SSH_OK;
fail:
    mbedtls_ecdsa_free(key->ecdsa);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&group);
    mbedtls_ecp_keypair_free(&keypair);
    SAFE_FREE(key->ecdsa);
    return SSH_ERROR;
}

int pki_key_generate_ecdsa(ssh_key key, int parameter)
{
    int nid;
    int ok;

    switch (parameter) {
        case 384:
            nid = NID_mbedtls_nistp384;
            break;
        case 512:
            nid = NID_mbedtls_nistp521;
            break;
        case 256:
        default:
            nid = NID_mbedtls_nistp256;
            break;
    }

    key->ecdsa_nid = nid;
    key->type = SSH_KEYTYPE_ECDSA;
    key->type_c = pki_key_ecdsa_nid_to_name(nid);

    key->ecdsa = malloc(sizeof(mbedtls_ecdsa_context));
    if (key->ecdsa == NULL) {
        return SSH_ERROR;
    }

    mbedtls_ecdsa_init(key->ecdsa);

    ok = mbedtls_ecdsa_genkey(key->ecdsa, pki_key_ecdsa_nid_to_mbed_gid(nid),
            mbedtls_ctr_drbg_random, &ssh_mbedtls_ctr_drbg);

    if (ok != 0) {
        mbedtls_ecdsa_free(key->ecdsa);
        SAFE_FREE(key->ecdsa);
    }

    return SSH_OK;
}

int pki_pubkey_build_dss(ssh_key key, ssh_string p, ssh_string q, ssh_string g,
        ssh_string pubkey)
{
    (void) key;
    (void) p;
    (void) q;
    (void) g;
    (void) pubkey;
    return SSH_ERROR;
}

int pki_key_generate_dss(ssh_key key, int parameter)
{
    (void) key;
    (void) parameter;
    return SSH_ERROR;
}
#endif /* HAVE_LIBMBEDCRYPTO */
