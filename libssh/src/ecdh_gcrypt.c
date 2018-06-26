/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2011-2013 by Aris Adamantiadis
 * Copyright (C) 2016 g10 Code GmbH
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
#include "libssh/session.h"
#include "libssh/ecdh.h"
#include "libssh/dh.h"
#include "libssh/buffer.h"
#include "libssh/ssh2.h"
#include "libssh/pki.h"
#include "libssh/bignum.h"
#include "libssh/libgcrypt.h"

#ifdef HAVE_ECDH
#include <gcrypt.h>

/** @internal
 * @brief Map the given key exchange enum value to its curve name.
 */
static const char *ecdh_kex_type_to_curve(enum ssh_key_exchange_e kex_type) {
    if (kex_type == SSH_KEX_ECDH_SHA2_NISTP256) {
        return "NIST P-256";
    } else if (kex_type == SSH_KEX_ECDH_SHA2_NISTP384) {
        return "NIST P-384";
    } else if (kex_type == SSH_KEX_ECDH_SHA2_NISTP521) {
        return "NIST P-521";
    }
    return NULL;
}

/** @internal
 * @brief Starts ecdh-sha2-nistp{256,384,521} key exchange.
 */
int ssh_client_ecdh_init(ssh_session session)
{
    int rc;
    gpg_error_t err;
    ssh_string client_pubkey = NULL;
    gcry_sexp_t param = NULL;
    gcry_sexp_t key = NULL;
    const char *curve = NULL;

    curve = ecdh_kex_type_to_curve(session->next_crypto->kex_type);
    if (curve == NULL) {
        rc = SSH_ERROR;
        goto out;
    }

    rc = ssh_buffer_add_u8(session->out_buffer, SSH2_MSG_KEX_ECDH_INIT);
    if (rc < 0) {
        rc = SSH_ERROR;
        goto out;
    }

    err = gcry_sexp_build(&param,
                          NULL,
                          "(genkey(ecdh(curve %s)))",
                          curve);
    if (err) {
        rc = SSH_ERROR;
        goto out;
    }

    err = gcry_pk_genkey(&key, param);
    if (err) {
        rc = SSH_ERROR;
        goto out;
    }

    client_pubkey = ssh_sexp_extract_mpi(key,
                                         "q",
                                         GCRYMPI_FMT_USG,
                                         GCRYMPI_FMT_STD);
    if (client_pubkey == NULL) {
        rc = SSH_ERROR;
        goto out;
    }

    rc = ssh_buffer_add_ssh_string(session->out_buffer, client_pubkey);
    if (rc < 0) {
        rc = SSH_ERROR;
        goto out;
    }

    session->next_crypto->ecdh_privkey = key;
    key = NULL;
    session->next_crypto->ecdh_client_pubkey = client_pubkey;
    client_pubkey = NULL;

    rc = ssh_packet_send(session);

 out:
    gcry_sexp_release(param);
    gcry_sexp_release(key);
    ssh_string_free(client_pubkey);
    return rc;
}

int ecdh_build_k(ssh_session session)
{
    gpg_error_t err;
    gcry_sexp_t data = NULL;
    gcry_sexp_t result = NULL;
    /* We need to get the x coordinate.  Libgcrypt 1.7 and above
       offers a suitable API for that.  */
#if (GCRYPT_VERSION_NUMBER >= 0x010700)
    gcry_mpi_t s = NULL;
    gcry_mpi_point_t point;
#else
    size_t k_len = 0;
    enum ssh_key_exchange_e kex_type = session->next_crypto->kex_type;
    ssh_string s;
#endif
    ssh_string pubkey_raw;
    gcry_sexp_t pubkey = NULL;
    ssh_string privkey = NULL;
    int rc = SSH_ERROR;
    const char *curve = NULL;

    curve = ecdh_kex_type_to_curve(session->next_crypto->kex_type);
    if (curve == NULL) {
        goto out;
    }

    pubkey_raw = session->server
        ? session->next_crypto->ecdh_client_pubkey
        : session->next_crypto->ecdh_server_pubkey;

    err = gcry_sexp_build(&pubkey,
                          NULL,
                          "(key-data(public-key(ecdh(curve %s)(q %b))))",
                          curve,
                          ssh_string_len(pubkey_raw),
                          ssh_string_data(pubkey_raw));
    if (err) {
        goto out;
    }

    privkey = ssh_sexp_extract_mpi(session->next_crypto->ecdh_privkey,
                                   "d",
                                   GCRYMPI_FMT_USG,
                                   GCRYMPI_FMT_STD);
    if (privkey == NULL) {
        goto out;
    }

    err = gcry_sexp_build(&data, NULL,
                          "(data(flags raw)(value %b))",
                          ssh_string_len(privkey),
                          ssh_string_data(privkey));
    if (err) {
        goto out;
    }

    err = gcry_pk_encrypt(&result, data, pubkey);
    if (err) {
        goto out;
    }

#if (GCRYPT_VERSION_NUMBER >= 0x010700)
    err = gcry_sexp_extract_param(result, "", "s", &s, NULL);
    if (err) {
        goto out;
    }

    point = gcry_mpi_point_new(0);
    if (point == NULL) {
        gcry_mpi_release(s);
        goto out;
    }

    err = gcry_mpi_ec_decode_point(point, s, NULL);
    gcry_mpi_release(s);
    if (err) {
        goto out;
    }

    session->next_crypto->k = gcry_mpi_new(0);
    gcry_mpi_point_snatch_get(session->next_crypto->k, NULL, NULL, point);
#else
    s = ssh_sexp_extract_mpi(result, "s", GCRYMPI_FMT_USG, GCRYMPI_FMT_USG);
    if (s == NULL) {
        goto out;
    }

    if (kex_type == SSH_KEX_ECDH_SHA2_NISTP256) {
        k_len = 65;
    } else if (kex_type == SSH_KEX_ECDH_SHA2_NISTP384) {
        k_len = 97;
    } else if (kex_type == SSH_KEX_ECDH_SHA2_NISTP521) {
        k_len = 133;
    } else {
        ssh_string_burn(s);
        ssh_string_free(s);
        goto out;
    }

    if (ssh_string_len(s) != k_len) {
        ssh_string_burn(s);
        ssh_string_free(s);
        goto out;
    }

    err = gcry_mpi_scan(&session->next_crypto->k,
                        GCRYMPI_FMT_USG,
                        (const char *)ssh_string_data(s) + 1,
                        k_len / 2,
                        NULL);
    ssh_string_burn(s);
    ssh_string_free(s);
    if (err) {
        goto out;
    }
#endif

    rc = SSH_OK;
    gcry_sexp_release(session->next_crypto->ecdh_privkey);
    session->next_crypto->ecdh_privkey = NULL;

#ifdef DEBUG_CRYPTO
    ssh_print_hexa("Session server cookie",
                   session->next_crypto->server_kex.cookie, 16);
    ssh_print_hexa("Session client cookie",
                   session->next_crypto->client_kex.cookie, 16);
    ssh_print_bignum("Shared secret key", session->next_crypto->k);
#endif

 out:
    gcry_sexp_release(pubkey);
    gcry_sexp_release(data);
    gcry_sexp_release(result);
    ssh_string_burn(privkey);
    ssh_string_free(privkey);
    return rc;
}

#ifdef WITH_SERVER

/** @brief Parse a SSH_MSG_KEXDH_INIT packet (server) and send a
 * SSH_MSG_KEXDH_REPLY
 */
int ssh_server_ecdh_init(ssh_session session, ssh_buffer packet) {
    gpg_error_t err;
    /* ECDH keys */
    ssh_string q_c_string;
    ssh_string q_s_string;
    gcry_sexp_t param = NULL;
    gcry_sexp_t key = NULL;
    /* SSH host keys (rsa,dsa,ecdsa) */
    ssh_key privkey;
    ssh_string sig_blob = NULL;
    int rc = SSH_ERROR;
    const char *curve = NULL;

    curve = ecdh_kex_type_to_curve(session->next_crypto->kex_type);
    if (curve == NULL) {
        goto out;
    }

    /* Extract the client pubkey from the init packet */
    q_c_string = ssh_buffer_get_ssh_string(packet);
    if (q_c_string == NULL) {
        ssh_set_error(session, SSH_FATAL, "No Q_C ECC point in packet");
        goto out;
    }
    session->next_crypto->ecdh_client_pubkey = q_c_string;

    /* Build server's keypair */
    err = gcry_sexp_build(&param, NULL, "(genkey(ecdh(curve %s)))",
                          curve);
    if (err) {
        goto out;
    }

    err = gcry_pk_genkey(&key, param);
    if (err)
        goto out;

    q_s_string = ssh_sexp_extract_mpi(key,
                                      "q",
                                      GCRYMPI_FMT_USG,
                                      GCRYMPI_FMT_STD);
    if (q_s_string == NULL) {
        goto out;
    }

    session->next_crypto->ecdh_privkey = key;
    key = NULL;
    session->next_crypto->ecdh_server_pubkey = q_s_string;

    /* build k and session_id */
    rc = ecdh_build_k(session);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Cannot build k number");
        goto out;
    }

    /* privkey is not allocated */
    rc = ssh_get_key_params(session, &privkey);
    if (rc != SSH_OK) {
        goto out;
    }

    rc = ssh_make_sessionid(session);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Could not create a session id");
        goto out;
    }

    sig_blob = ssh_srv_pki_do_sign_sessionid(session, privkey);
    if (sig_blob == NULL) {
        ssh_set_error(session, SSH_FATAL, "Could not sign the session id");
        rc = SSH_ERROR;
        goto out;
    }

    rc = ssh_buffer_pack(session->out_buffer,
                         "bSSS",
                         SSH2_MSG_KEXDH_REPLY,
                         session->next_crypto->server_pubkey, /* host's pubkey */
                         q_s_string, /* ecdh public key */
                         sig_blob); /* signature blob */

    ssh_string_free(sig_blob);

    if (rc != SSH_OK) {
        ssh_set_error_oom(session);
        goto out;
    }

    SSH_LOG(SSH_LOG_PROTOCOL, "SSH_MSG_KEXDH_REPLY sent");
    rc = ssh_packet_send(session);
    if (rc != SSH_OK) {
        goto out;
    }


    /* Send the MSG_NEWKEYS */
    rc = ssh_buffer_add_u8(session->out_buffer, SSH2_MSG_NEWKEYS);
    if (rc != SSH_OK) {
        goto out;
    }

    session->dh_handshake_state = DH_STATE_NEWKEYS_SENT;
    rc = ssh_packet_send(session);
    SSH_LOG(SSH_LOG_PROTOCOL, "SSH_MSG_NEWKEYS sent");

 out:
    gcry_sexp_release(param);
    gcry_sexp_release(key);
    return rc;
}

#endif /* WITH_SERVER */

#endif /* HAVE_ECDH */
