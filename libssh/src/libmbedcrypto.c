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

#include "libssh/wrapper.h"
#include "libssh/crypto.h"
#include "libssh/priv.h"

#ifdef HAVE_LIBMBEDCRYPTO
#include <mbedtls/md.h>

struct ssh_mac_ctx_struct {
    enum ssh_mac_e mac_type;
    mbedtls_md_context_t ctx;
};

void ssh_reseed(void)
{
    mbedtls_ctr_drbg_reseed(&ssh_mbedtls_ctr_drbg, NULL, 0);
}

SHACTX sha1_init(void)
{
    SHACTX ctx = NULL;
    int rc;
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);

    if (md_info == NULL) {
        return NULL;
    }

    ctx = malloc(sizeof(mbedtls_md_context_t));
    if (ctx == NULL) {
        return NULL;
    }

    mbedtls_md_init(ctx);

    rc = mbedtls_md_setup(ctx, md_info, 0);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    rc = mbedtls_md_starts(ctx);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    return ctx;
}

void sha1_update(SHACTX c, const void *data, unsigned long len)
{
    mbedtls_md_update(c, data, len);
}

void sha1_final(unsigned char *md, SHACTX c)
{
    mbedtls_md_finish(c, md);
    mbedtls_md_free(c);
    SAFE_FREE(c);
}

void sha1(unsigned char *digest, int len, unsigned char *hash)
{
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    if (md_info != NULL) {
        mbedtls_md(md_info, digest, len, hash);
    }
}

static mbedtls_md_type_t nid_to_md_algo(int nid)
{
    switch (nid) {
        case NID_mbedtls_nistp256:
            return MBEDTLS_MD_SHA256;
        case NID_mbedtls_nistp384:
            return MBEDTLS_MD_SHA384;
        case NID_mbedtls_nistp521:
            return MBEDTLS_MD_SHA512;
    }
    return MBEDTLS_MD_NONE;
}

void evp(int nid, unsigned char *digest, int len,
        unsigned char *hash, unsigned int *hlen)
{
    mbedtls_md_type_t algo = nid_to_md_algo(nid);
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(algo);


    if (md_info != NULL) {
        *hlen = mbedtls_md_get_size(md_info);
        mbedtls_md(md_info, digest, len, hash);
    }
}

EVPCTX evp_init(int nid)
{
    EVPCTX ctx = NULL;
    int rc;
    mbedtls_md_type_t algo = nid_to_md_algo(nid);
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(algo);

    if (md_info == NULL) {
        return NULL;
    }

    ctx = malloc(sizeof(mbedtls_md_context_t));
    if (ctx == NULL) {
        return NULL;
    }

    mbedtls_md_init(ctx);

    rc = mbedtls_md_setup(ctx, md_info, 0);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    rc = mbedtls_md_starts(ctx);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    return ctx;
}

void evp_update(EVPCTX ctx, const void *data, unsigned long len)
{
    mbedtls_md_update(ctx, data, len);
}

void evp_final(EVPCTX ctx, unsigned char *md, unsigned int *mdlen)
{
    *mdlen = mbedtls_md_get_size(ctx->md_info);
    mbedtls_md_hmac_finish(ctx, md);
    mbedtls_md_free(ctx);
    SAFE_FREE(ctx);
}

SHA256CTX sha256_init(void)
{
    SHA256CTX ctx = NULL;
    int rc;
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    if (md_info == NULL) {
        return NULL;
    }

    ctx = malloc(sizeof(mbedtls_md_context_t));
    if(ctx == NULL) {
        return NULL;
    }

    mbedtls_md_init(ctx);

    rc = mbedtls_md_setup(ctx, md_info, 0);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    rc = mbedtls_md_starts(ctx);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    return ctx;
}

void sha256_update(SHA256CTX c, const void *data, unsigned long len)
{
    mbedtls_md_update(c, data, len);
}

void sha256_final(unsigned char *md, SHA256CTX c)
{
    mbedtls_md_finish(c, md);
    mbedtls_md_free(c);
    SAFE_FREE(c);
}

void sha256(unsigned char *digest, int len, unsigned char *hash)
{
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info != NULL) {
        mbedtls_md(md_info, digest, len, hash);
    }
}

SHA384CTX sha384_init(void)
{
    SHA384CTX ctx = NULL;
    int rc;
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);

    if (md_info == NULL) {
        return NULL;
    }

    ctx = malloc(sizeof(mbedtls_md_context_t));
    if (ctx == NULL) {
        return NULL;
    }

    mbedtls_md_init(ctx);

    rc = mbedtls_md_setup(ctx, md_info, 0);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    rc = mbedtls_md_starts(ctx);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    return ctx;
}

void sha384_update(SHA384CTX c, const void *data, unsigned long len)
{
    mbedtls_md_update(c, data, len);
}

void sha384_final(unsigned char *md, SHA384CTX c)
{
    mbedtls_md_finish(c, md);
    mbedtls_md_free(c);
    SAFE_FREE(c);
}

void sha384(unsigned char *digest, int len, unsigned char *hash)
{
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
    if (md_info != NULL) {
        mbedtls_md(md_info, digest, len, hash);
    }
}

SHA512CTX sha512_init(void)
{
    SHA512CTX ctx = NULL;
    int rc;
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    if (md_info == NULL) {
        return NULL;
    }

    ctx = malloc(sizeof(mbedtls_md_context_t));
    if (ctx == NULL) {
        return NULL;
    }

    mbedtls_md_init(ctx);

    rc = mbedtls_md_setup(ctx, md_info, 0);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    rc = mbedtls_md_starts(ctx);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    return ctx;
}

void sha512_update(SHA512CTX c, const void *data, unsigned long len)
{
    mbedtls_md_update(c, data, len);
}

void sha512_final(unsigned char *md, SHA512CTX c)
{
    mbedtls_md_finish(c, md);
    mbedtls_md_free(c);
    SAFE_FREE(c);
}

void sha512(unsigned char *digest, int len, unsigned char *hash)
{
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    if (md_info != NULL) {
        mbedtls_md(md_info, digest, len, hash);
    }
}

MD5CTX md5_init(void)
{
    MD5CTX ctx = NULL;
    int rc;
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
    if (md_info == NULL) {
        return NULL;
    }

    ctx = malloc(sizeof(mbedtls_md_context_t));
    if (ctx == NULL) {
        return NULL;
    }

    mbedtls_md_init(ctx);

    rc = mbedtls_md_setup(ctx, md_info, 0);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    rc = mbedtls_md_starts(ctx);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    return ctx;
}


void md5_update(MD5CTX c, const void *data, unsigned long len) {
    mbedtls_md_update(c, data, len);
}

void md5_final(unsigned char *md, MD5CTX c)
{
    mbedtls_md_finish(c, md);
    mbedtls_md_free(c);
    SAFE_FREE(c);
}

ssh_mac_ctx ssh_mac_ctx_init(enum ssh_mac_e type)
{
    ssh_mac_ctx ctx = malloc(sizeof (struct ssh_mac_ctx_struct));
    const mbedtls_md_info_t *md_info;
    int rc;
    if (ctx == NULL) {
        return NULL;
    }

    ctx->mac_type=type;
    switch(type) {
        case SSH_MAC_SHA1:
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
            break;
        case SSH_MAC_SHA256:
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            break;
        case SSH_MAC_SHA384:
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
            break;
        case SSH_MAC_SHA512:
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
            break;
        default:
            goto error;
    }

    if (md_info == NULL) {
        goto error;
    }

    mbedtls_md_init(&ctx->ctx);

    rc = mbedtls_md_setup(&ctx->ctx, md_info, 0);
    if (rc != 0) {
        goto error;
    }

    rc = mbedtls_md_starts(&ctx->ctx);
    if (rc != 0) {
        goto error;
    }

    return ctx;

error:
    SAFE_FREE(ctx);
    return NULL;
}

void ssh_mac_update(ssh_mac_ctx ctx, const void *data, unsigned long len)
{
    mbedtls_md_update(&ctx->ctx, data, len);
}

void ssh_mac_final(unsigned char *md, ssh_mac_ctx ctx)
{
    mbedtls_md_finish(&ctx->ctx, md);
    mbedtls_md_free(&ctx->ctx);
    SAFE_FREE(ctx);
}

HMACCTX hmac_init(const void *key, int len, enum ssh_hmac_e type)
{
    HMACCTX ctx = NULL;
    const mbedtls_md_info_t *md_info = NULL;
    int rc;

    ctx = malloc(sizeof(mbedtls_md_context_t));
    if (ctx == NULL) {
        return NULL;
    }

    switch (type) {
        case SSH_HMAC_SHA1:
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
            break;
        case SSH_HMAC_SHA256:
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            break;
        case SSH_HMAC_SHA384:
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
            break;
        case SSH_HMAC_SHA512:
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
            break;
        default:
            goto error;
    }

    mbedtls_md_init(ctx);

    if (md_info == NULL) {
        goto error;
    }

    rc = mbedtls_md_setup(ctx, md_info, 1);
    if (rc != 0) {
        goto error;
    }

    rc = mbedtls_md_hmac_starts(ctx, key, len);
    if (rc != 0) {
        goto error;
    }

    return ctx;

error:
    mbedtls_md_free(ctx);
    SAFE_FREE(ctx);
    return NULL;
}

void hmac_update(HMACCTX c, const void *data, unsigned long len)
{
    mbedtls_md_hmac_update(c, data, len);
}

void hmac_final(HMACCTX c, unsigned char *hashmacbuf, unsigned int *len)
{
    *len = mbedtls_md_get_size(c->md_info);
    mbedtls_md_hmac_finish(c, hashmacbuf);
    mbedtls_md_free(c);
    SAFE_FREE(c);
}

static int cipher_set_encrypt_key(struct ssh_cipher_struct *cipher, void *key,
        void *IV)
{

    const mbedtls_cipher_info_t *cipher_info = NULL;
    int rc;

    mbedtls_cipher_init(&cipher->encrypt_ctx);
    cipher_info = mbedtls_cipher_info_from_type(cipher->type);

    rc = mbedtls_cipher_setup(&cipher->encrypt_ctx, cipher_info);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_setup failed");
        goto error;
    }

    rc = mbedtls_cipher_setkey(&cipher->encrypt_ctx, key,
                               cipher_info->key_bitlen,
                               MBEDTLS_ENCRYPT);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_setkey failed");
        goto error;
    }

    rc = mbedtls_cipher_set_iv(&cipher->encrypt_ctx, IV, cipher_info->iv_size);

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_set_iv failed");
        goto error;
    }

    rc = mbedtls_cipher_reset(&cipher->encrypt_ctx);

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_reset failed");
        goto error;
    }

    return SSH_OK;
error:
    mbedtls_cipher_free(&cipher->encrypt_ctx);
    return SSH_ERROR;
}

static int cipher_set_encrypt_key_cbc(struct ssh_cipher_struct *cipher, void *key,
        void *IV)
{

    const mbedtls_cipher_info_t *cipher_info = NULL;
    int rc;

    mbedtls_cipher_init(&cipher->encrypt_ctx);
    cipher_info = mbedtls_cipher_info_from_type(cipher->type);

    rc = mbedtls_cipher_setup(&cipher->encrypt_ctx, cipher_info);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_setup failed");
        goto error;
    }

    rc = mbedtls_cipher_setkey(&cipher->encrypt_ctx, key,
                               cipher_info->key_bitlen,
                               MBEDTLS_ENCRYPT);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_setkey failed");
        goto error;
    }

    rc = mbedtls_cipher_set_iv(&cipher->encrypt_ctx, IV, cipher_info->iv_size);

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_set_iv failed");
        goto error;
    }

    /* libssh only encypts and decrypts packets that are multiples of a block
     * size, and no padding is used */
    rc = mbedtls_cipher_set_padding_mode(&cipher->encrypt_ctx,
            MBEDTLS_PADDING_NONE);

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_set_padding_mode failed");
        goto error;
    }

    rc = mbedtls_cipher_reset(&cipher->encrypt_ctx);

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_reset failed");
        goto error;
    }

    return SSH_OK;
error:
    mbedtls_cipher_free(&cipher->encrypt_ctx);
    return SSH_ERROR;
}

static int cipher_set_decrypt_key(struct ssh_cipher_struct *cipher, void *key,
        void *IV)
{
    const mbedtls_cipher_info_t *cipher_info = NULL;
    int rc;

    mbedtls_cipher_init(&cipher->decrypt_ctx);
    cipher_info = mbedtls_cipher_info_from_type(cipher->type);

    rc = mbedtls_cipher_setup(&cipher->decrypt_ctx, cipher_info);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_setkey failed");
        goto error;
    }

    rc = mbedtls_cipher_setkey(&cipher->decrypt_ctx, key,
                               cipher_info->key_bitlen,
                               MBEDTLS_DECRYPT);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_setkey failed");
        goto error;
    }

    rc = mbedtls_cipher_set_iv(&cipher->decrypt_ctx, IV, cipher_info->iv_size);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_set_iv failed");
        goto error;
    }

    mbedtls_cipher_reset(&cipher->decrypt_ctx);

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_reset failed");
        goto error;
    }

    return SSH_OK;
error:
    mbedtls_cipher_free(&cipher->decrypt_ctx);
    return SSH_ERROR;
}

static int cipher_set_decrypt_key_cbc(struct ssh_cipher_struct *cipher, void *key,
        void *IV)
{
    const mbedtls_cipher_info_t *cipher_info;
    int rc;

    mbedtls_cipher_init(&cipher->decrypt_ctx);
    cipher_info = mbedtls_cipher_info_from_type(cipher->type);

    rc = mbedtls_cipher_setup(&cipher->decrypt_ctx, cipher_info);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_setkey failed");
        goto error;
    }

    rc = mbedtls_cipher_setkey(&cipher->decrypt_ctx, key,
                               cipher_info->key_bitlen,
                               MBEDTLS_DECRYPT);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_setkey failed");
        goto error;
    }

    rc = mbedtls_cipher_set_iv(&cipher->decrypt_ctx, IV, cipher_info->iv_size);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_set_iv failed");
        goto error;
    }

    rc = mbedtls_cipher_set_padding_mode(&cipher->decrypt_ctx,
            MBEDTLS_PADDING_NONE);

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_set_padding_mode failed");
        goto error;
    }

    mbedtls_cipher_reset(&cipher->decrypt_ctx);

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_reset failed");
        goto error;
    }

    return SSH_OK;
error:
    mbedtls_cipher_free(&cipher->decrypt_ctx);
    return SSH_ERROR;
}

static void cipher_encrypt(struct ssh_cipher_struct *cipher, void *in, void *out,
        unsigned long len)
{
    size_t outlen = 0;
    size_t total_len = 0;
    int rc = 0;
    rc = mbedtls_cipher_update(&cipher->encrypt_ctx, in, len, out, &outlen);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update failed during encryption");
        return;
    }

    total_len += outlen;

    if (total_len == len) {
        return;
    }

    rc = mbedtls_cipher_finish(&cipher->encrypt_ctx, (unsigned char *) out + outlen,
            &outlen);

    total_len += outlen;

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_finish failed during encryption");
        return;
    }

    if (total_len != len) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update: output size %zu for %zu",
                outlen, len);
        return;
    }

}

static void cipher_encrypt_cbc(struct ssh_cipher_struct *cipher, void *in, void *out,
        unsigned long len)
{
    size_t outlen = 0;
    int rc = 0;
    rc = mbedtls_cipher_update(&cipher->encrypt_ctx, in, len, out, &outlen);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update failed during encryption");
        return;
    }

    if (outlen != len) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update: output size %zu for %zu",
                outlen, len);
        return;
    }

}

static void cipher_decrypt(struct ssh_cipher_struct *cipher, void *in, void *out,
        unsigned long len)
{
    size_t outlen = 0;
    int rc = 0;
    size_t total_len = 0;

    rc = mbedtls_cipher_update(&cipher->decrypt_ctx, in, len, out, &outlen);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update failed during decryption");
        return;
    }

    total_len += outlen;

    if (total_len == len) {
        return;
    }

    rc = mbedtls_cipher_finish(&cipher->decrypt_ctx, (unsigned char *) out +
            outlen, &outlen);

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_reset failed during decryption");
        return;
    }

    total_len += outlen;

    if (total_len != len) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update: output size %zu for %zu",
                outlen, len);
        return;
    }

}

static void cipher_decrypt_cbc(struct ssh_cipher_struct *cipher, void *in, void *out,
        unsigned long len)
{
    size_t outlen = 0;
    int rc = 0;
    rc = mbedtls_cipher_update(&cipher->decrypt_ctx, in, len, out, &outlen);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update failed during decryption");
        return;
    }

    /* MbedTLS caches the last block when decrypting with cbc.
     * By calling finish the block is flushed to out, however the unprocessed
     * data counter is not reset.
     * Calling mbedtls_cipher_reset resets the unprocessed data counter.
     */
    if (outlen == 0) {
        rc = mbedtls_cipher_finish(&cipher->decrypt_ctx, out, &outlen);
    } else if (outlen == len) {
        return;
    } else {
        rc = mbedtls_cipher_finish(&cipher->decrypt_ctx, (unsigned char *) out +
                outlen , &outlen);
    }

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_finish failed during decryption");
        return;
    }

    rc = mbedtls_cipher_reset(&cipher->decrypt_ctx);

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_reset failed during decryption");
        return;
    }

    if (outlen != len) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update: output size %zu for %zu",
                outlen, len);
        return;
    }

}

static void cipher_cleanup(struct ssh_cipher_struct *cipher)
{
    mbedtls_cipher_free(&cipher->encrypt_ctx);
    mbedtls_cipher_free(&cipher->decrypt_ctx);
}

static int des3_set_encrypt_key(struct ssh_cipher_struct *cipher, void *key,
        void *IV)
{
    const mbedtls_cipher_info_t *cipher_info = NULL;
    unsigned char *des3_key = NULL;
    size_t des_key_size = 0;
    int rc;

    mbedtls_cipher_init(&cipher->encrypt_ctx);
    cipher_info = mbedtls_cipher_info_from_type(cipher->type);

    rc = mbedtls_cipher_setup(&cipher->encrypt_ctx, cipher_info);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_setup failed");
        goto error;
    }

    des3_key = malloc(cipher_info->key_bitlen / 8);
    if (des3_key == NULL) {
        SSH_LOG(SSH_LOG_WARNING, "error allocating memory for key");
        goto error;
    }

    des_key_size = cipher_info->key_bitlen / (8 * 3);
    memcpy(des3_key, key, des_key_size);
    memcpy(des3_key + des_key_size, (unsigned char * )key + des_key_size,
            des_key_size);
    memcpy(des3_key + 2 * des_key_size,
            (unsigned char *) key + 2 * des_key_size, des_key_size);

    rc = mbedtls_cipher_setkey(&cipher->encrypt_ctx, des3_key,
                               cipher_info->key_bitlen,
                               MBEDTLS_ENCRYPT);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_setkey failed");
        goto error;
    }

    rc = mbedtls_cipher_set_iv(&cipher->encrypt_ctx, IV, cipher_info->iv_size);

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_set_iv failed");
        goto error;
    }

    rc = mbedtls_cipher_reset(&cipher->encrypt_ctx);

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_reset failed");
        goto error;
    }

    SAFE_FREE(des3_key);
    return SSH_OK;
error:
    mbedtls_cipher_free(&cipher->encrypt_ctx);
    SAFE_FREE(des3_key);
    return SSH_ERROR;
}

static int des3_set_decrypt_key(struct ssh_cipher_struct *cipher, void *key,
        void *IV)
{
    const mbedtls_cipher_info_t *cipher_info = NULL;
    unsigned char *des3_key = NULL;
    size_t des_key_size = 0;
    int rc;

    mbedtls_cipher_init(&cipher->decrypt_ctx);
    cipher_info = mbedtls_cipher_info_from_type(cipher->type);

    rc = mbedtls_cipher_setup(&cipher->decrypt_ctx, cipher_info);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_setup failed");
        goto error;
    }

    des3_key = malloc(cipher_info->key_bitlen / 8);
    if (des3_key == NULL) {
        SSH_LOG(SSH_LOG_WARNING, "error allocating memory for key");
        goto error;
    }

    des_key_size = cipher_info->key_bitlen / (8 * 3);
    memcpy(des3_key, key, des_key_size);
    memcpy(des3_key + des_key_size, (unsigned char *) key + des_key_size,
            des_key_size);
    memcpy(des3_key + 2 * des_key_size,
            (unsigned char *) key + 2 * des_key_size,
            des_key_size);

    rc = mbedtls_cipher_setkey(&cipher->decrypt_ctx, des3_key,
                               cipher_info->key_bitlen,
                               MBEDTLS_DECRYPT);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_setkey failed");
        goto error;
    }

    rc = mbedtls_cipher_set_iv(&cipher->decrypt_ctx, IV, cipher_info->iv_size);

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_set_iv failed");
        goto error;
    }

    rc = mbedtls_cipher_reset(&cipher->decrypt_ctx);

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_reset failed");
        goto error;
    }

    SAFE_FREE(des3_key);
    return SSH_OK;
error:
    mbedtls_cipher_free(&cipher->decrypt_ctx);
    if (des3_key != NULL) {
        SAFE_FREE(des3_key);
    }
    return SSH_ERROR;
}

static struct ssh_cipher_struct ssh_ciphertab[] = {
    {
        .name = "blowfish-cbc",
        .blocksize = 8,
        .keysize = 128,
        .type = MBEDTLS_CIPHER_BLOWFISH_CBC,
        .set_encrypt_key = cipher_set_encrypt_key_cbc,
        .set_decrypt_key = cipher_set_decrypt_key_cbc,
        .encrypt = cipher_encrypt_cbc,
        .decrypt = cipher_decrypt_cbc,
        .cleanup = cipher_cleanup
    },
    {
        .name = "aes128-ctr",
        .blocksize = 16,
        .keysize = 128,
        .type = MBEDTLS_CIPHER_AES_128_CTR,
        .set_encrypt_key = cipher_set_encrypt_key,
        .set_decrypt_key = cipher_set_decrypt_key,
        .encrypt = cipher_encrypt,
        .decrypt = cipher_decrypt,
        .cleanup = cipher_cleanup
    },
    {
        .name = "aes192-ctr",
        .blocksize = 16,
        .keysize = 192,
        .type = MBEDTLS_CIPHER_AES_192_CTR,
        .set_encrypt_key = cipher_set_encrypt_key,
        .set_decrypt_key = cipher_set_decrypt_key,
        .encrypt = cipher_encrypt,
        .decrypt = cipher_decrypt,
        .cleanup = cipher_cleanup
    },
    {
        .name = "aes256-ctr",
        .blocksize = 16,
        .keysize = 256,
        .type = MBEDTLS_CIPHER_AES_256_CTR,
        .set_encrypt_key = cipher_set_encrypt_key,
        .set_decrypt_key = cipher_set_decrypt_key,
        .encrypt = cipher_encrypt,
        .decrypt = cipher_decrypt,
        .cleanup = cipher_cleanup
    },
    {
        .name = "aes128-cbc",
        .blocksize = 16,
        .keysize = 128,
        .type = MBEDTLS_CIPHER_AES_128_CBC,
        .set_encrypt_key = cipher_set_encrypt_key_cbc,
        .set_decrypt_key = cipher_set_decrypt_key_cbc,
        .encrypt = cipher_encrypt_cbc,
        .decrypt = cipher_decrypt_cbc,
        .cleanup = cipher_cleanup
    },
    {
        .name = "aes192-cbc",
        .blocksize = 16,
        .keysize = 192,
        .type = MBEDTLS_CIPHER_AES_192_CBC,
        .set_encrypt_key = cipher_set_encrypt_key_cbc,
        .set_decrypt_key = cipher_set_decrypt_key_cbc,
        .encrypt = cipher_encrypt_cbc,
        .decrypt = cipher_decrypt_cbc,
        .cleanup = cipher_cleanup
    },
    {
        .name = "aes256-cbc",
        .blocksize = 16,
        .keysize = 256,
        .type = MBEDTLS_CIPHER_AES_256_CBC,
        .set_encrypt_key = cipher_set_encrypt_key_cbc,
        .set_decrypt_key = cipher_set_decrypt_key_cbc,
        .encrypt = cipher_encrypt_cbc,
        .decrypt = cipher_decrypt_cbc,
        .cleanup = cipher_cleanup
    },
    {
        .name = "3des-cbc",
        .blocksize = 8,
        .keysize = 192,
        .type = MBEDTLS_CIPHER_DES_EDE3_CBC,
        .set_encrypt_key = cipher_set_encrypt_key_cbc,
        .set_decrypt_key = cipher_set_decrypt_key_cbc,
        .encrypt = cipher_encrypt_cbc,
        .decrypt = cipher_decrypt_cbc,
        .cleanup = cipher_cleanup
    },
    {
        .name = "3des-cbc-ssh1",
        .blocksize = 8,
        .keysize = 192,
        .type = MBEDTLS_CIPHER_DES_CBC,
        .set_encrypt_key = des3_set_encrypt_key,
        .set_decrypt_key = des3_set_decrypt_key,
        .encrypt = cipher_encrypt_cbc,
        .decrypt = cipher_decrypt_cbc,
        .cleanup = cipher_cleanup
    },
    {
        .name = "des-cbc-ssh1",
        .blocksize = 8,
        .keysize = 64,
        .type = MBEDTLS_CIPHER_DES_CBC,
        .set_encrypt_key = cipher_set_encrypt_key_cbc,
        .set_decrypt_key = cipher_set_decrypt_key_cbc,
        .encrypt = cipher_encrypt_cbc,
        .decrypt = cipher_decrypt_cbc,
    },
    {
        .name = NULL,
        .blocksize = 0,
        .keysize = 0,
        .set_encrypt_key = NULL,
        .set_decrypt_key = NULL,
        .encrypt = NULL,
        .decrypt = NULL,
        .cleanup = NULL
    }
};

struct ssh_cipher_struct *ssh_get_ciphertab(void)
{
    return ssh_ciphertab;
}

void ssh_mbedtls_init(void)
{
    int rc;

    mbedtls_entropy_init(&ssh_mbedtls_entropy);
    mbedtls_ctr_drbg_init(&ssh_mbedtls_ctr_drbg);

    rc = mbedtls_ctr_drbg_seed(&ssh_mbedtls_ctr_drbg, mbedtls_entropy_func,
            &ssh_mbedtls_entropy, NULL, 0);
    if (rc != 0) {
        mbedtls_ctr_drbg_free(&ssh_mbedtls_ctr_drbg);
    }
}

int ssh_mbedtls_random(void *where, int len, int strong)
{
    int rc = 0;
    if (strong) {
        mbedtls_ctr_drbg_set_prediction_resistance(&ssh_mbedtls_ctr_drbg,
                MBEDTLS_CTR_DRBG_PR_ON);
        rc = mbedtls_ctr_drbg_random(&ssh_mbedtls_ctr_drbg, where, len);
        mbedtls_ctr_drbg_set_prediction_resistance(&ssh_mbedtls_ctr_drbg,
                MBEDTLS_CTR_DRBG_PR_OFF);
    } else {
        rc = mbedtls_ctr_drbg_random(&ssh_mbedtls_ctr_drbg, where, len);
    }

    return !rc;
}

void ssh_mbedtls_cleanup(void)
{
    mbedtls_ctr_drbg_free(&ssh_mbedtls_ctr_drbg);
    mbedtls_entropy_free(&ssh_mbedtls_entropy);
}

#endif /* HAVE_LIBMBEDCRYPTO */
