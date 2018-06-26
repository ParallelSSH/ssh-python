/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2011-2013 by Aris Adamantiadis
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

#ifdef HAVE_ECDH

/** @internal
 * @brief parses a SSH_MSG_KEX_ECDH_REPLY packet and sends back
 * a SSH_MSG_NEWKEYS
 */
int ssh_client_ecdh_reply(ssh_session session, ssh_buffer packet){
  ssh_string q_s_string = NULL;
  ssh_string pubkey_blob = NULL;
  ssh_string signature = NULL;
  int rc;

  pubkey_blob = ssh_buffer_get_ssh_string(packet);
  if (pubkey_blob == NULL) {
    ssh_set_error(session,SSH_FATAL, "No public key in packet");
    goto error;
  }

  rc = ssh_dh_import_next_pubkey_blob(session, pubkey_blob);
  ssh_string_free(pubkey_blob);
  if (rc != 0) {
      goto error;
  }

  q_s_string = ssh_buffer_get_ssh_string(packet);
  if (q_s_string == NULL) {
    ssh_set_error(session,SSH_FATAL, "No Q_S ECC point in packet");
    goto error;
  }
  session->next_crypto->ecdh_server_pubkey = q_s_string;
  signature = ssh_buffer_get_ssh_string(packet);
  if (signature == NULL) {
    ssh_set_error(session, SSH_FATAL, "No signature in packet");
    goto error;
  }
  session->next_crypto->dh_server_signature = signature;
  signature=NULL; /* ownership changed */
  /* TODO: verify signature now instead of waiting for NEWKEYS */
  if (ecdh_build_k(session) < 0) {
    ssh_set_error(session, SSH_FATAL, "Cannot build k number");
    goto error;
  }

  /* Send the MSG_NEWKEYS */
  if (ssh_buffer_add_u8(session->out_buffer, SSH2_MSG_NEWKEYS) < 0) {
    goto error;
  }

  rc=ssh_packet_send(session);
  SSH_LOG(SSH_LOG_PROTOCOL, "SSH_MSG_NEWKEYS sent");
  return rc;
error:
  return SSH_ERROR;
}

#endif /* HAVE_ECDH */
