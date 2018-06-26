/*
 * known_hosts: Host and public key verification.
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 by Aris Adamantiadis
 * Copyright (c) 2009-2017 by Andreas Schneider <asn@cryptomilk.org>
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

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include "libssh/priv.h"
#include "libssh/dh.h"
#include "libssh/session.h"
#include "libssh/options.h"
#include "libssh/misc.h"
#include "libssh/pki.h"
#include "libssh/dh.h"

static int hash_hostname(const char *name,
                         unsigned char *salt,
                         unsigned int salt_size,
                         unsigned char **hash,
                         unsigned int *hash_size)
{
    HMACCTX mac_ctx;

    mac_ctx = hmac_init(salt, salt_size, SSH_HMAC_SHA1);
    if (mac_ctx == NULL) {
        return SSH_ERROR;
    }

    hmac_update(mac_ctx, name, strlen(name));
    hmac_final(mac_ctx, *hash, hash_size);

    return SSH_OK;
}

static int match_hashed_hostname(const char *host, const char *hashed_host)
{
    char *hashed;
    char *b64_hash;
    ssh_buffer salt = NULL;
    ssh_buffer hash = NULL;
    unsigned char hashed_buf[256] = {0};
    unsigned char *hashed_buf_ptr = hashed_buf;
    unsigned int hashed_buf_size = sizeof(hashed_buf);
    int cmp;
    int rc;
    int match = 0;

    cmp = strncmp(hashed_host, "|1|", 3);
    if (cmp != 0) {
        return 0;
    }

    hashed = strdup(hashed_host + 3);
    if (hashed == NULL) {
        return 0;
    }

    b64_hash = strchr(hashed, '|');
    if (b64_hash == NULL) {
        goto error;
    }
    *b64_hash = '\0';
    b64_hash++;

    salt = base64_to_bin(hashed);
    if (salt == NULL) {
        goto error;
    }

    hash = base64_to_bin(b64_hash);
    if (hash == NULL) {
        goto error;
    }

    rc = hash_hostname(host,
                       ssh_buffer_get(salt),
                       ssh_buffer_get_len(salt),
                       &hashed_buf_ptr,
                       &hashed_buf_size);
    if (rc != SSH_OK) {
        goto error;
    }

    if (hashed_buf_size != ssh_buffer_get_len(hash)) {
        goto error;
    }

    cmp = memcmp(hashed_buf, ssh_buffer_get(hash), hashed_buf_size);
    if (cmp == 0) {
        match = 1;
    }

error:
    free(hashed);
    ssh_buffer_free(salt);
    ssh_buffer_free(hash);

    return match;
}

/**
 * @brief Free an allocated ssh_knownhosts_entry.
 *
 * Use SSH_KNOWNHOSTS_ENTRY_FREE() to set the pointer to NULL.
 *
 * @param[in]  entry     The entry to free.
 */
void ssh_knownhosts_entry_free(struct ssh_knownhosts_entry *entry)
{
    if (entry == NULL) {
        return;
    }

    SAFE_FREE(entry->hostname);
    SAFE_FREE(entry->unparsed);
    ssh_key_free(entry->publickey);
    SAFE_FREE(entry->comment);
    SAFE_FREE(entry);
}

static int known_hosts_read_line(FILE *fp,
                                 char *buf,
                                 size_t buf_size,
                                 size_t *buf_len,
                                 size_t *lineno)
{
    while (fgets(buf, buf_size, fp) != NULL) {
        size_t len;
        if (buf[0] == '\0') {
            continue;
        }

        *lineno += 1;
        len = strlen(buf);
        if (buf_len != NULL) {
            *buf_len = len;
        }
        if (buf[len - 1] == '\n' || feof(fp)) {
            return 0;
        } else {
            errno = E2BIG;
            return -1;
        }
    }

    return -1;
}

static int ssh_known_hosts_read_entries(const char *match,
                                        const char *filename,
                                        struct ssh_list **entries)
{
    struct ssh_list *entry_list;
    char line[8192];
    size_t lineno = 0;
    size_t len = 0;
    FILE *fp;
    int rc;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        return SSH_ERROR;
    }

    entry_list = ssh_list_new();
    if (entry_list == NULL) {
        fclose(fp);
        return SSH_ERROR;
    }

    for (rc = known_hosts_read_line(fp, line, sizeof(line), &len, &lineno);
         rc == 0;
         rc = known_hosts_read_line(fp, line, sizeof(line), &len, &lineno)) {
        struct ssh_knownhosts_entry *entry = NULL;
        char *p;

        if (line[len] != '\n') {
            len = strcspn(line, "\n");
        }
        line[len] = '\0';

        /* Skip leading spaces */
        for (p = line; isspace((int)p[0]); p++);

        /* Skip comments and empty lines */
        if (p[0] == '\0' || p[0] == '#') {
            continue;
        }

        rc = ssh_known_hosts_parse_line(match,
                                        line,
                                        &entry);
        if (rc == SSH_AGAIN) {
            continue;
        } else if (rc != SSH_OK) {
            goto error;
        }
        ssh_list_append(entry_list, entry);
    }

    *entries = entry_list;

    fclose(fp);
    return SSH_OK;
error:
    ssh_list_free(entry_list);
    fclose(fp);
    return SSH_ERROR;
}

static char *ssh_session_get_host_port(ssh_session session)
{
    char *host_port;
    char *host;

    if (session->opts.host == NULL) {
        ssh_set_error(session,
                      SSH_FATAL,
                      "Can't verify server inn known hosts if the host we "
                      "should connect to has not been set");

        return NULL;
    }

    host = ssh_lowercase(session->opts.host);
    if (host == NULL) {
        ssh_set_error_oom(session);
        return NULL;
    }

    if (session->opts.port == 0 || session->opts.port == 22) {
        host_port = host;
    } else {
        host_port = ssh_hostport(host, session->opts.port);
        SAFE_FREE(host);
        if (host_port == NULL) {
            ssh_set_error_oom(session);
            return NULL;
        }
    }

    return host_port;
}

/**
 * @brief Parse a line from a known_hosts entry into a structure
 *
 * This parses an known_hosts entry into a structure with the key in a libssh
 * consumeable form. You can use the PKI key function to further work with it.
 *
 * @param[in]  hostname     The hostname to match the line to
 *
 * @param[in]  line         The line to compare and parse if we have a hostname
 *                          match.
 *
 * @param[in]  entry        A pointer to store the the allocated known_hosts
 *                          entry structure. The user needs to free the memory
 *                          using SSH_KNOWNHOSTS_ENTRY_FREE().
 *
 * @return SSH_OK on success, SSH_ERROR otherwise.
 */
int ssh_known_hosts_parse_line(const char *hostname,
                               const char *line,
                               struct ssh_knownhosts_entry **entry)
{
    struct ssh_knownhosts_entry *e = NULL;
    char *known_host = NULL;
    char *p;
    enum ssh_keytypes_e key_type;
    int match = 0;
    int rc = SSH_OK;

    known_host = strdup(line);
    if (known_host == NULL) {
        return SSH_ERROR;
    }

    /* match pattern for hostname or hashed hostname */
    p = strtok(known_host, " ");
    if (p == NULL ) {
        free(known_host);
        return SSH_ERROR;
    }

    e = calloc(1, sizeof(struct ssh_knownhosts_entry));
    if (e == NULL) {
        free(known_host);
        return SSH_ERROR;
    }

    if (hostname != NULL) {
        char *match_pattern = NULL;
        char *q;

        /* Hashed */
        if (p[0] == '|') {
            match = match_hashed_hostname(hostname, p);
        }

        for (q = strtok(p, ",");
             q != NULL;
             q = strtok(NULL, ",")) {
            int cmp;

            cmp = match_hostname(hostname, q, strlen(q));
            if (cmp == 1) {
                match = 1;
                break;
            }
        }
        SAFE_FREE(match_pattern);

        if (match == 0) {
            rc = SSH_AGAIN;
            goto out;
        }

        e->hostname = strdup(hostname);
        if (e->hostname == NULL) {
            rc = SSH_ERROR;
            goto out;
        }
    }

    /* Restart parsing */
    SAFE_FREE(known_host);
    known_host = strdup(line);
    if (known_host == NULL) {
        rc = SSH_ERROR;
        goto out;
    }

    p = strtok(known_host, " ");
    if (p == NULL ) {
        rc = SSH_ERROR;
        goto out;
    }

    e->unparsed = strdup(p);
    if (e->unparsed == NULL) {
        rc = SSH_ERROR;
        goto out;
    }

    /* pubkey type */
    p = strtok(NULL, " ");
    if (p == NULL) {
        rc = SSH_ERROR;
        goto out;
    }

    key_type = ssh_key_type_from_name(p);
    if (key_type == SSH_KEYTYPE_UNKNOWN) {
        SSH_LOG(SSH_LOG_WARN, "key type '%s' unknown!", p);
        rc = SSH_ERROR;
        goto out;
    }

    /* public key */
    p = strtok(NULL, " ");
    if (p == NULL) {
        rc = SSH_ERROR;
        goto out;
    }

    rc = ssh_pki_import_pubkey_base64(p,
                                      key_type,
                                      &e->publickey);
    if (rc != SSH_OK) {
        SSH_LOG(SSH_LOG_WARN,
                "Failed to parse %s key for entry: %s!",
                ssh_key_type_to_char(key_type),
                e->unparsed);
        goto out;
    }

    /* comment */
    p = strtok(NULL, " ");
    if (p != NULL) {
        p = strstr(line, p);
        if (p != NULL) {
            e->comment = strdup(p);
            if (e->comment == NULL) {
                rc = SSH_ERROR;
                goto out;
            }
        }
    }

    *entry = e;
    SAFE_FREE(known_host);

    return SSH_OK;
out:
    SAFE_FREE(known_host);
    ssh_knownhosts_entry_free(e);
    return rc;
}

/**
 * @brief Check if the set hostname and port matches an entry in known_hosts.
 *
 * This check if the set hostname and port has an entry in the known_hosts file.
 * You need to set at least the hostname using ssh_options_set().
 *
 * @param[in]  session  The session with with the values set to check.
 *
 * @return A @ssh_known_hosts_e return value.
 */
enum ssh_known_hosts_e ssh_session_has_known_hosts_entry(ssh_session session)
{
    struct ssh_list *entry_list = NULL;
    struct ssh_iterator *it = NULL;
    char *host_port = NULL;
    int rc;

    if (session->opts.knownhosts == NULL) {
        if (ssh_options_apply(session) < 0) {
            ssh_set_error(session,
                          SSH_REQUEST_DENIED,
                          "Can't find a known_hosts file");

            return SSH_KNOWN_HOSTS_NOT_FOUND;
        }
    }

    host_port = ssh_session_get_host_port(session);
    if (host_port == NULL) {
        return SSH_KNOWN_HOSTS_NOT_FOUND;
    }

    rc = ssh_known_hosts_read_entries(host_port,
                                      session->opts.knownhosts,
                                      &entry_list);
    if (rc != 0) {
        return SSH_KNOWN_HOSTS_NOT_FOUND;
    }

    if (ssh_list_count(entry_list) == 0) {
        ssh_list_free(entry_list);
        return SSH_KNOWN_HOSTS_NOT_FOUND;
    }

    for (it = ssh_list_get_iterator(entry_list);
         it != NULL;
         it = ssh_list_get_iterator(entry_list)) {
        struct ssh_knownhosts_entry *entry = NULL;

        entry = ssh_iterator_value(struct ssh_knownhosts_entry *, it);
        ssh_knownhosts_entry_free(entry);
        ssh_list_remove(entry_list, it);
    }
    ssh_list_free(entry_list);

    return SSH_KNOWN_HOSTS_OK;
}

/**
 * @brief Export the current session information to a known_hosts string.
 *
 * This exports the current information of a session which is connected so a
 * ssh server into an entry line which can be added to a known_hosts file.
 *
 * @param[in]  session  The session with information to export.
 *
 * @param[in]  pentry_string A pointer to a string to store the alloocated
 *                           line of the entry. The user must free it using
 *                           ssh_string_free_char().
 *
 * @return SSH_OK on succcess, SSH_ERROR otherwise.
 */
int ssh_session_export_known_hosts_entry(ssh_session session,
                                         char **pentry_string)
{
    ssh_key server_pubkey = NULL;
    char *host = NULL;
    char entry_buf[4096] = {0};
    int rc;

    if (pentry_string == NULL) {
        ssh_set_error_invalid(session);
        return SSH_ERROR;
    }

    if (session->opts.host == NULL) {
        ssh_set_error(session, SSH_FATAL,
                      "Can't create known_hosts entry - hostname unknown");
        return SSH_ERROR;
    }

    host = ssh_session_get_host_port(session);
    if (host == NULL) {
        return SSH_ERROR;
    }

    if (session->current_crypto == NULL) {
        ssh_set_error(session, SSH_FATAL,
                      "No current crypto context, please connnect first");
        SAFE_FREE(host);
        return SSH_ERROR;
    }

    server_pubkey = ssh_dh_get_current_server_publickey(session);
    if (server_pubkey == NULL){
        ssh_set_error(session, SSH_FATAL, "No public key present");
        SAFE_FREE(host);
        return SSH_ERROR;
    }

    if (ssh_key_type(server_pubkey) == SSH_KEYTYPE_RSA1) {
        rc = ssh_pki_export_pubkey_rsa1(server_pubkey,
                                        host,
                                        entry_buf,
                                        sizeof(entry_buf));
        SAFE_FREE(host);
        if (rc < 0) {
            return SSH_ERROR;
        }
    } else {
        char *b64_key = NULL;

        rc = ssh_pki_export_pubkey_base64(server_pubkey, &b64_key);
        if (rc < 0) {
            SAFE_FREE(host);
            return SSH_ERROR;
        }

        snprintf(entry_buf, sizeof(entry_buf),
                    "%s %s %s\n",
                    host,
                    server_pubkey->type_c,
                    b64_key);

        SAFE_FREE(host);
        SAFE_FREE(b64_key);
    }

    *pentry_string = strdup(entry_buf);
    if (*pentry_string == NULL) {
        return SSH_ERROR;
    }

    return SSH_OK;
}

/**
 * @brief Add the current connected server to the known_hosts file.
 *
 * This adds the currently connected server to the known_hosts file by
 * appending a new line at the end.
 *
 * @param[in]  session  The session to use to write the entry.
 *
 * @return SSH_OK on success, SSH_ERROR otherwise.
 */
int ssh_session_update_known_hosts(ssh_session session)
{
    FILE *fp = NULL;
    char *entry = NULL;
    char *dir = NULL;
    size_t nwritten;
    size_t len;
    int rc;

    if (session->opts.knownhosts == NULL) {
        rc = ssh_options_apply(session);
        if (rc != SSH_OK) {
            ssh_set_error(session, SSH_FATAL, "Can't find a known_hosts file");
            return SSH_ERROR;
        }
    }

    /* Check if directory exists and create it if not */
    dir = ssh_dirname(session->opts.knownhosts);
    if (dir == NULL) {
        ssh_set_error(session, SSH_FATAL, "%s", strerror(errno));
        return SSH_ERROR;
    }

    rc = ssh_file_readaccess_ok(dir);
    if (rc == 0) {
        rc = ssh_mkdir(dir, 0700);
    } else {
        rc = 0;
    }
    SAFE_FREE(dir);
    if (rc != 0) {
        ssh_set_error(session, SSH_FATAL,
                      "Cannot create %s directory.", dir);
        return SSH_ERROR;
    }

    fp = fopen(session->opts.knownhosts, "a");
    if (fp == NULL) {
        ssh_set_error(session, SSH_FATAL,
                "Couldn't open known_hosts file %s for appending: %s",
                session->opts.knownhosts, strerror(errno));
        return SSH_ERROR;
    }

    rc = ssh_session_export_known_hosts_entry(session, &entry);
    if (rc != SSH_OK) {
        fclose(fp);
        return rc;
    }

    len = strlen(entry);
    nwritten = fwrite(entry, sizeof(char), len, fp);
    SAFE_FREE(entry);
    if (nwritten != len || ferror(fp)) {
        ssh_set_error(session, SSH_FATAL,
                      "Couldn't append to known_hosts file %s: %s",
                      session->opts.knownhosts, strerror(errno));
        fclose(fp);
        return SSH_ERROR;
    }

    fclose(fp);
    return SSH_OK;
}

static enum ssh_known_hosts_e
ssh_known_hosts_check_server_key(const char *hosts_entry,
                                 const char *filename,
                                 ssh_key server_key,
                                 struct ssh_knownhosts_entry **pentry)
{
    struct ssh_list *entry_list = NULL;
    struct ssh_iterator *it = NULL;
    enum ssh_known_hosts_e found = SSH_KNOWN_HOSTS_UNKNOWN;
    int rc;

    rc = ssh_known_hosts_read_entries(hosts_entry,
                                      filename,
                                      &entry_list);
    if (rc != 0) {
        return SSH_KNOWN_HOSTS_NOT_FOUND;
    }

    it = ssh_list_get_iterator(entry_list);
    if (it == NULL) {
        ssh_list_free(entry_list);
        return SSH_KNOWN_HOSTS_UNKNOWN;
    }

    for (;it != NULL; it = it->next) {
        struct ssh_knownhosts_entry *entry = NULL;
        int cmp;

        entry = ssh_iterator_value(struct ssh_knownhosts_entry *, it);

        cmp = ssh_key_cmp(server_key, entry->publickey, SSH_KEY_CMP_PUBLIC);
        if (cmp == 0) {
            found = SSH_KNOWN_HOSTS_OK;
            if (pentry != NULL) {
                *pentry = entry;
                ssh_list_remove(entry_list, it);
            }
            break;
        }

        if (ssh_key_type(server_key) == ssh_key_type(entry->publickey)) {
            found = SSH_KNOWN_HOSTS_CHANGED;
        } else {
            found = SSH_KNOWN_HOSTS_OTHER;
        }
    }

    for (it = ssh_list_get_iterator(entry_list);
         it != NULL;
         it = ssh_list_get_iterator(entry_list)) {
        struct ssh_knownhosts_entry *entry = NULL;

        entry = ssh_iterator_value(struct ssh_knownhosts_entry *, it);
        ssh_knownhosts_entry_free(entry);
        ssh_list_remove(entry_list, it);
    }
    ssh_list_free(entry_list);

    return found;
}

/**
 * @brief Get the known_hosts entry for the current connected session.
 *
 * @param[in]  session  The session to validate.
 *
 * @param[in]  pentry   A pointer to store the allocated known hosts entry.
 *
 * @returns SSH_KNOWN_HOSTS_OK:        The server is known and has not changed.\n
 *          SSH_KNOWN_HOSTS_CHANGED:   The server key has changed. Either you
 *                                     are under attack or the administrator
 *                                     changed the key. You HAVE to warn the
 *                                     user about a possible attack.\n
 *          SSH_KNOWN_HOSTS_OTHER:     The server gave use a key of a type while
 *                                     we had an other type recorded. It is a
 *                                     possible attack.\n
 *          SSH_KNOWN_HOSTS_UNKNOWN:   The server is unknown. User should
 *                                     confirm the public key hash is correct.\n
 *          SSH_KNOWN_HOSTS_NOT_FOUND: The known host file does not exist. The
 *                                     host is thus unknown. File will be
 *                                     created if host key is accepted.\n
 *          SSH_KNOWN_HOSTS_ERROR:     There had been an eror checking the host.
 *
 * @see ssh_knownhosts_entry_free()
 */
enum ssh_known_hosts_e
ssh_session_get_known_hosts_entry(ssh_session session,
                                  struct ssh_knownhosts_entry **pentry)
{
    ssh_key server_pubkey = NULL;
    char *host_port = NULL;
    enum ssh_known_hosts_e found = SSH_KNOWN_HOSTS_UNKNOWN;

    if (session->opts.knownhosts == NULL) {
        if (ssh_options_apply(session) < 0) {
            ssh_set_error(session,
                          SSH_REQUEST_DENIED,
                          "Can't find a known_hosts file");

            return SSH_KNOWN_HOSTS_NOT_FOUND;
        }
    }

    server_pubkey = ssh_dh_get_current_server_publickey(session);
    if (server_pubkey == NULL) {
        ssh_set_error(session,
                      SSH_FATAL,
                      "ssh_session_is_known_host called without a "
                      "server_key!");

        return SSH_KNOWN_HOSTS_ERROR;
    }

    host_port = ssh_session_get_host_port(session);
    if (host_port == NULL) {
        return SSH_KNOWN_HOSTS_ERROR;
    }

    found = ssh_known_hosts_check_server_key(host_port,
                                             session->opts.knownhosts,
                                             server_pubkey,
                                             pentry);

    return found;
}

/**
 * @brief Check if the servers public key for the connected session is known.
 *
 * This checks if we already know the public key of the server we want to
 * connect to. This allows to detect if there is a MITM attach going on
 * of if there have been changes on the server we don't know about.
 *
 * @param[in]  session  The SSH to validate.
 *
 * @returns SSH_KNOWN_HOSTS_OK:        The server is known and has not changed.\n
 *          SSH_KNOWN_HOSTS_CHANGED:   The server key has changed. Either you
 *                                     are under attack or the administrator
 *                                     changed the key. You HAVE to warn the
 *                                     user about a possible attack.\n
 *          SSH_KNOWN_HOSTS_OTHER:     The server gave use a key of a type while
 *                                     we had an other type recorded. It is a
 *                                     possible attack.\n
 *          SSH_KNOWN_HOSTS_UNKNOWN:   The server is unknown. User should
 *                                     confirm the public key hash is correct.\n
 *          SSH_KNOWN_HOSTS_NOT_FOUND: The known host file does not exist. The
 *                                     host is thus unknown. File will be
 *                                     created if host key is accepted.\n
 *          SSH_KNOWN_HOSTS_ERROR:     There had been an eror checking the host.
 */
enum ssh_known_hosts_e ssh_session_is_known_server(ssh_session session)
{
    return ssh_session_get_known_hosts_entry(session, NULL);
}
