/*
 * torture.c - torture library for testing libssh
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2008-2009 by Andreas Schneider <asn@cryptomilk.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#ifndef _WIN32
# include <dirent.h>
# include <errno.h>
# include <sys/socket.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "torture.h"
#include "torture_key.h"

/* for pattern matching */
#include "match.c"

#define TORTURE_SSHD_SRV_IPV4 "127.0.0.10"
/* socket wrapper IPv6 prefix  fd00::5357:5fxx */
#define TORTURE_SSHD_SRV_IPV6 "fd00::5357:5f0a"
#define TORTURE_SSHD_SRV_PORT 22

#define TORTURE_SOCKET_DIR "/tmp/test_socket_wrapper_XXXXXX"
#define TORTURE_SSHD_PIDFILE "sshd/sshd.pid"
#define TORTURE_SSHD_CONFIG "sshd/sshd_config"
#define TORTURE_PCAP_FILE "socket_trace.pcap"

static const char torture_rsa_certauth_pub[]=
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCnA2n5vHzZbs/GvRkGloJNV1CXHI"
        "S5Xnrm05HusUJSWyPq3I1iCMHdYA7oezHa9GCFYbIenaYPy+G6USQRjYQz8SvAZo06"
        "SFNeJSsa1kAIqxzdPT9kBrRrYK39PZQPsYVfRPqZBdmc+jwrfz97IFEJyXMI47FoTG"
        "kgEq7eu3z2px/tdIZ34I5Hr5DDBxicZi4jluyRUJHfSPoBxyhF7OkPX4bYkrc691je"
        "IQDxubl650WYLHgFfad0xTzBIFE6XUb55Dp5AgRdevSoso1Pe0IKFxxMVpP664LCbY"
        "K06Lv6kcotfFlpvUtR1yx8jToGcSoq5sSzTwvXSHCQQ9ZA1hvF "
        "torture_certauth_key";

static int verbosity = 0;
static const char *pattern = NULL;

#ifndef _WIN32

static int _torture_auth_kbdint(ssh_session session,
                               const char *password) {
    const char *prompt;
    char echo;
    int err;

    if (session == NULL || password == NULL) {
        return SSH_AUTH_ERROR;
    }

    err = ssh_userauth_kbdint(session, NULL, NULL);
    if (err == SSH_AUTH_ERROR) {
        return err;
    }

    if (ssh_userauth_kbdint_getnprompts(session) != 1) {
        return SSH_AUTH_ERROR;
    }

    prompt = ssh_userauth_kbdint_getprompt(session, 0, &echo);
    if (prompt == NULL) {
        return SSH_AUTH_ERROR;
    }

    if (ssh_userauth_kbdint_setanswer(session, 0, password) < 0) {
        return SSH_AUTH_ERROR;
    }
    err = ssh_userauth_kbdint(session, NULL, NULL);
    if (err == SSH_AUTH_INFO) {
        if (ssh_userauth_kbdint_getnprompts(session) != 0) {
            return SSH_AUTH_ERROR;
        }
        err = ssh_userauth_kbdint(session, NULL, NULL);
    }

    return err;
}

int torture_rmdirs(const char *path) {
    DIR *d;
    struct dirent *dp;
    struct stat sb;
    char *fname;

    if ((d = opendir(path)) != NULL) {
        while(stat(path, &sb) == 0) {
            /* if we can remove the directory we're done */
            if (rmdir(path) == 0) {
                break;
            }
            switch (errno) {
                case ENOTEMPTY:
                case EEXIST:
                case EBADF:
                    break; /* continue */
                default:
                    closedir(d);
                    return 0;
            }

            while ((dp = readdir(d)) != NULL) {
                size_t len;
                /* skip '.' and '..' */
                if (dp->d_name[0] == '.' &&
                        (dp->d_name[1] == '\0' ||
                         (dp->d_name[1] == '.' && dp->d_name[2] == '\0'))) {
                    continue;
                }

                len = strlen(path) + strlen(dp->d_name) + 2;
                fname = malloc(len);
                if (fname == NULL) {
                    closedir(d);
                    return -1;
                }
                snprintf(fname, len, "%s/%s", path, dp->d_name);

                /* stat the file */
                if (lstat(fname, &sb) != -1) {
                    if (S_ISDIR(sb.st_mode) && !S_ISLNK(sb.st_mode)) {
                        if (rmdir(fname) < 0) { /* can't be deleted */
                            if (errno == EACCES) {
                                closedir(d);
                                SAFE_FREE(fname);
                                return -1;
                            }
                            torture_rmdirs(fname);
                        }
                    } else {
                        unlink(fname);
                    }
                } /* lstat */
                SAFE_FREE(fname);
            } /* readdir */

            rewinddir(d);
        }
    } else {
        return -1;
    }

    closedir(d);
    return 0;
}

int torture_isdir(const char *path) {
    struct stat sb;

    if (lstat (path, &sb) == 0 && S_ISDIR(sb.st_mode)) {
        return 1;
    }

    return 0;
}

int torture_terminate_process(const char *pidfile)
{
    char buf[8] = {0};
    long int tmp;
    ssize_t rc;
    pid_t pid;
    int fd;
    int is_running = 1;
    int count;

    /* read the pidfile */
    fd = open(pidfile, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    rc = read(fd, buf, sizeof(buf));
    close(fd);
    if (rc <= 0) {
        return -1;
    }

    buf[sizeof(buf) - 1] = '\0';

    tmp = strtol(buf, NULL, 10);
    if (tmp == 0 || tmp > 0xFFFF || errno == ERANGE) {
        return -1;
    }

    pid = (pid_t)(tmp & 0xFFFF);

    for (count = 0; count < 10; count++) {
        /* Make sure the daemon goes away! */
        kill(pid, SIGTERM);

        usleep(10000);

        rc = kill(pid, 0);
        if (rc != 0) {
            is_running = 0;
            break;
        }
    }

    if (is_running) {
        fprintf(stderr,
                "WARNING: The process with pid %u is still running!\n", pid);
    }

    return 0;
}

ssh_session torture_ssh_session(const char *host,
                                const unsigned int *port,
                                const char *user,
                                const char *password) {
    ssh_session session;
    int method;
    int rc;

    if (host == NULL) {
        return NULL;
    }

    session = ssh_new();
    if (session == NULL) {
        return NULL;
    }

    if (ssh_options_set(session, SSH_OPTIONS_HOST, host) < 0) {
        goto failed;
    }

    if (port != NULL) {
      if (ssh_options_set(session, SSH_OPTIONS_PORT, port) < 0) {
        goto failed;
      }
    }

    if (user != NULL) {
        if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0) {
            goto failed;
        }
    }

    if (ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity) < 0) {
        goto failed;
    }

    if (ssh_connect(session)) {
        goto failed;
    }

    /* We are in testing mode, so consinder the hostkey as verified ;) */

    /* This request should return a SSH_REQUEST_DENIED error */
    rc = ssh_userauth_none(session, NULL);
    if (rc == SSH_ERROR) {
        goto failed;
    }
    method = ssh_userauth_list(session, NULL);
    if (method == 0) {
        goto failed;
    }

    if (password != NULL) {
        if (method & SSH_AUTH_METHOD_PASSWORD) {
            rc = ssh_userauth_password(session, NULL, password);
        } else if (method & SSH_AUTH_METHOD_INTERACTIVE) {
            rc = _torture_auth_kbdint(session, password);
        }
    } else {
        rc = ssh_userauth_publickey_auto(session, NULL, NULL);
        if (rc == SSH_AUTH_ERROR) {
            goto failed;
        }
    }
    if (rc != SSH_AUTH_SUCCESS) {
        goto failed;
    }

    return session;
failed:
    if (ssh_is_connected(session)) {
        ssh_disconnect(session);
    }
    ssh_free(session);

    return NULL;
}

#ifdef WITH_SERVER

ssh_bind torture_ssh_bind(const char *addr,
                          const unsigned int port,
                          enum ssh_keytypes_e key_type,
                          const char *private_key_file) {
    int rc;
    ssh_bind sshbind = NULL;
    enum ssh_bind_options_e opts = -1;

    sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        goto out;
    }

    rc = ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, addr);
    if (rc != 0) {
        goto out_free;
    }

    rc = ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    if (rc != 0) {
        goto out_free;
    }

    switch (key_type) {
#ifdef HAVE_DSA
        case SSH_KEYTYPE_DSS:
            opts = SSH_BIND_OPTIONS_DSAKEY;
            break;
#endif /* HAVE_DSA */
        case SSH_KEYTYPE_RSA:
            opts = SSH_BIND_OPTIONS_RSAKEY;
            break;
        case SSH_KEYTYPE_ECDSA:
            opts = SSH_BIND_OPTIONS_ECDSAKEY;
            break;
        default:
            goto out_free;
    }

    rc = ssh_bind_options_set(sshbind, opts, private_key_file);
    if (rc != 0) {
        goto out_free;
    }

    rc = ssh_bind_listen(sshbind);
    if (rc != SSH_OK) {
        goto out_free;
    }

    goto out;
 out_free:
    ssh_bind_free(sshbind);
    sshbind = NULL;
 out:
    return sshbind;
}

#endif /* WITH_SERVER */

#ifdef WITH_SFTP

struct torture_sftp *torture_sftp_session(ssh_session session) {
    struct torture_sftp *t;
    char template[] = "/tmp/ssh_torture_XXXXXX";
    char *p;
    int rc;

    if (session == NULL) {
        return NULL;
    }

    t = malloc(sizeof(struct torture_sftp));
    if (t == NULL) {
        return NULL;
    }

    t->ssh = session;
    t->sftp = sftp_new(session);
    if (t->sftp == NULL) {
        goto failed;
    }

    rc = sftp_init(t->sftp);
    if (rc < 0) {
        goto failed;
    }

    p = mkdtemp(template);
    if (p == NULL) {
        goto failed;
    }
    /* useful if TESTUSER is not the local user */
    chmod(template,0777);
    t->testdir = strdup(p);
    if (t->testdir == NULL) {
        goto failed;
    }

    return t;
failed:
    if (t->sftp != NULL) {
        sftp_free(t->sftp);
    }
    ssh_disconnect(t->ssh);
    ssh_free(t->ssh);
	free(t);

    return NULL;
}

void torture_sftp_close(struct torture_sftp *t) {
    if (t == NULL) {
        return;
    }

    if (t->sftp != NULL) {
        sftp_free(t->sftp);
    }

    free(t->testdir);
    free(t);
}
#endif /* WITH_SFTP */

int torture_server_port(void)
{
    char *env = getenv("TORTURE_SERVER_PORT");

    if (env != NULL && env[0] != '\0' && strlen(env) < 6) {
        int port = atoi(env);

        if (port > 0 && port < 65536) {
            return port;
        }
    }

    return TORTURE_SSHD_SRV_PORT;
}

const char *torture_server_address(int family)
{
    switch (family) {
    case AF_INET: {
        const char *ip4 = getenv("TORTURE_SERVER_ADDRESS_IPV4");

        if (ip4 != NULL && ip4[0] != '\0') {
            return ip4;
        }

        return TORTURE_SSHD_SRV_IPV4;
    }
    case AF_INET6: {
        const char *ip6 = getenv("TORTURE_SERVER_ADDRESS_IPV6");

        if (ip6 != NULL && ip6[0] != '\0') {
            return ip6;
        }

        return TORTURE_SSHD_SRV_IPV6;
    }
    default:
        return NULL;
    }

    return NULL;
}

void torture_setup_socket_dir(void **state)
{
    struct torture_state *s;
    const char *p;
    size_t len;
    char *env = getenv("TORTURE_GENERATE_PCAP");

    s = malloc(sizeof(struct torture_state));
    assert_non_null(s);

    s->socket_dir = strdup(TORTURE_SOCKET_DIR);
    assert_non_null(s->socket_dir);

    p = mkdtemp(s->socket_dir);
    assert_non_null(p);

    /* pcap file */
    len = strlen(p) + 1 + strlen(TORTURE_PCAP_FILE) + 1;

    s->pcap_file = malloc(len);
    assert_non_null(s->pcap_file);

    snprintf(s->pcap_file, len, "%s/%s", p, TORTURE_PCAP_FILE);

    /* pid file */
    len = strlen(p) + 1 + strlen(TORTURE_SSHD_PIDFILE) + 1;

    s->srv_pidfile = malloc(len);
    assert_non_null(s->srv_pidfile);

    snprintf(s->srv_pidfile, len, "%s/%s", p, TORTURE_SSHD_PIDFILE);

    /* config file */
    len = strlen(p) + 1 + strlen(TORTURE_SSHD_CONFIG) + 1;

    s->srv_config = malloc(len);
    assert_non_null(s->srv_config);

    snprintf(s->srv_config, len, "%s/%s", p, TORTURE_SSHD_CONFIG);

    setenv("SOCKET_WRAPPER_DIR", p, 1);
    setenv("SOCKET_WRAPPER_DEFAULT_IFACE", "170", 1);
    if (env != NULL && env[0] == '1') {
        setenv("SOCKET_WRAPPER_PCAP_FILE", s->pcap_file, 1);
    }

    *state = s;
}

static void torture_setup_create_sshd_config(void **state)
{
    struct torture_state *s = *state;
    char ed25519_hostkey[1024] = {0};
#ifdef HAVE_DSA
    char dsa_hostkey[1024];
#endif /* HAVE_DSA */
    char rsa_hostkey[1024];
    char ecdsa_hostkey[1024];
    char trusted_ca_pubkey[1024];
    char sshd_config[2048];
    char sshd_path[1024];
    struct stat sb;
    const char *sftp_server_locations[] = {
        "/usr/lib/ssh/sftp-server",
        "/usr/libexec/sftp-server",
        "/usr/libexec/openssh/sftp-server",
        "/usr/lib/openssh/sftp-server",     /* Debian */
    };
#ifndef OPENSSH_VERSION_MAJOR
#define OPENSSH_VERSION_MAJOR 7U
#define OPENSSH_VERSION_MINOR 0U
#endif /* OPENSSH_VERSION_MAJOR */
    const char config_string[]=
             "Port 22\n"
             "ListenAddress 127.0.0.10\n"
             "HostKey %s\n"
#ifdef HAVE_DSA
             "HostKey %s\n"
#endif /* HAVE_DSA */
             "HostKey %s\n"
             "HostKey %s\n"
             "\n"
             "TrustedUserCAKeys %s\n"
             "\n"
             "LogLevel DEBUG3\n"
             "Subsystem sftp %s -l DEBUG2\n"
             "\n"
             "PasswordAuthentication yes\n"
             "KbdInteractiveAuthentication yes\n"
             "PubkeyAuthentication yes\n"
             "\n"
             "UsePrivilegeSeparation no\n"
             "StrictModes no\n"
             "\n"
             "UsePAM yes\n"
             "\n"
#if (OPENSSH_VERSION_MAJOR == 6 && OPENSSH_VERSION_MINOR >= 7) || (OPENSSH_VERSION_MAJOR >= 7)
# ifdef HAVE_DSA
             "HostKeyAlgorithms +ssh-dss\n"
# else /* HAVE_DSA */
             "HostKeyAlgorithms +ssh-rsa\n"
# endif /* HAVE_DSA */
# if (OPENSSH_VERSION_MAJOR == 7 && OPENSSH_VERSION_MINOR < 6)
             "Ciphers +3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,blowfish-cbc\n"
# else /* OPENSSH_VERSION 7.0 - 7.5 */
             "Ciphers +3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc\n"
# endif /* OPENSSH_VERSION 7.0 - 7.6 */
             "KexAlgorithms +diffie-hellman-group1-sha1"
#else /* OPENSSH_VERSION >= 6.7 */
             "Ciphers 3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,aes128-ctr,"
                     "aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,"
                     "aes256-gcm@openssh.com,arcfour128,arcfour256,arcfour,"
                     "blowfish-cbc,cast128-cbc,chacha20-poly1305@openssh.com\n"
             "KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp256,"
                           "ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
                           "diffie-hellman-group-exchange-sha256,"
                           "diffie-hellman-group-exchange-sha1,"
                           "diffie-hellman-group14-sha1,"
                           "diffie-hellman-group1-sha1\n"
#endif /* OPENSSH_VERSION >= 6.7 */
             "\n"
             "AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES\n"
             "AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT\n"
             "AcceptEnv LC_IDENTIFICATION LC_ALL LC_LIBSSH\n"
             "\n"
             "PidFile %s\n";
    size_t sftp_sl_size = ARRAY_SIZE(sftp_server_locations);
    const char *sftp_server;
    size_t i;
    int rc;

    snprintf(sshd_path,
             sizeof(sshd_path),
             "%s/sshd",
             s->socket_dir);

    rc = mkdir(sshd_path, 0755);
    assert_return_code(rc, errno);

    snprintf(ed25519_hostkey,
             sizeof(ed25519_hostkey),
             "%s/sshd/ssh_host_ed25519_key",
             s->socket_dir);
    torture_write_file(ed25519_hostkey,
                       torture_get_testkey(SSH_KEYTYPE_ED25519, 0, 0));

#ifdef HAVE_DSA
    snprintf(dsa_hostkey,
             sizeof(dsa_hostkey),
             "%s/sshd/ssh_host_dsa_key",
             s->socket_dir);
    torture_write_file(dsa_hostkey, torture_get_testkey(SSH_KEYTYPE_DSS, 0, 0));
#endif /* HAVE_DSA */

    snprintf(rsa_hostkey,
             sizeof(rsa_hostkey),
             "%s/sshd/ssh_host_rsa_key",
             s->socket_dir);
    torture_write_file(rsa_hostkey, torture_get_testkey(SSH_KEYTYPE_RSA, 0, 0));

    snprintf(ecdsa_hostkey,
             sizeof(ecdsa_hostkey),
             "%s/sshd/ssh_host_ecdsa_key",
             s->socket_dir);
    torture_write_file(ecdsa_hostkey,
                       torture_get_testkey(SSH_KEYTYPE_ECDSA, 521, 0));

    snprintf(ed25519_hostkey,
             sizeof(ed25519_hostkey),
             "%s/sshd/ssh_host_ed25519_key",
             s->socket_dir);
    torture_write_file(ed25519_hostkey,
                       torture_get_testkey(SSH_KEYTYPE_ED25519, 0, 0));

    snprintf(trusted_ca_pubkey,
             sizeof(trusted_ca_pubkey),
             "%s/sshd/user_ca.pub",
             s->socket_dir);
    torture_write_file(trusted_ca_pubkey, torture_rsa_certauth_pub);

    assert_non_null(s->socket_dir);

    sftp_server = getenv("TORTURE_SFTP_SERVER");
    if (sftp_server == NULL) {
        for (i = 0; i < sftp_sl_size; i++) {
            sftp_server = sftp_server_locations[i];
            rc = lstat(sftp_server, &sb);
            if (rc == 0) {
                break;
            }
        }
    }
    assert_non_null(sftp_server);

#ifdef HAVE_DSA
    snprintf(sshd_config, sizeof(sshd_config),
             config_string,
             ed25519_hostkey,
             dsa_hostkey,
             rsa_hostkey,
             ecdsa_hostkey,
             trusted_ca_pubkey,
             sftp_server,
             s->srv_pidfile);
#else /* HAVE_DSA */
    snprintf(sshd_config, sizeof(sshd_config),
             config_string,
             ed25519_hostkey,
             rsa_hostkey,
             ecdsa_hostkey,
             trusted_ca_pubkey,
             sftp_server,
             s->srv_pidfile);
#endif /* HAVE_DSA */

    torture_write_file(s->srv_config, sshd_config);
}

void torture_setup_sshd_server(void **state)
{
    struct torture_state *s;
    char sshd_start_cmd[1024];
    int rc;

    torture_setup_socket_dir(state);
    torture_setup_create_sshd_config(state);

    /* Set the default interface for the server */
    setenv("SOCKET_WRAPPER_DEFAULT_IFACE", "10", 1);
    setenv("PAM_WRAPPER", "1", 1);

    s = *state;

    snprintf(sshd_start_cmd, sizeof(sshd_start_cmd),
             "/usr/sbin/sshd -r -f %s -E %s/sshd/daemon.log 2> %s/sshd/cwrap.log",
             s->srv_config, s->socket_dir, s->socket_dir);

    rc = system(sshd_start_cmd);
    assert_return_code(rc, errno);

    /* Give the process some time to start */
    usleep(10000);

    setenv("SOCKET_WRAPPER_DEFAULT_IFACE", "21", 1);
    unsetenv("PAM_WRAPPER");
}

void torture_teardown_socket_dir(void **state)
{
    struct torture_state *s = *state;
    char *env = getenv("TORTURE_SKIP_CLEANUP");
    int rc;

    if (env != NULL && env[0] == '1') {
        fprintf(stderr, "[ TORTURE  ] >>> Skipping cleanup of %s\n", s->socket_dir);
    } else {
        rc = torture_rmdirs(s->socket_dir);
        if (rc < 0) {
            fprintf(stderr,
                    "torture_rmdirs(%s) failed: %s",
                    s->socket_dir,
                    strerror(errno));
        }
    }

    free(s->srv_config);
    free(s->socket_dir);
    free(s->pcap_file);
    free(s->srv_pidfile);
    free(s);
}

void torture_teardown_sshd_server(void **state)
{
    struct torture_state *s = *state;
    int rc;

    rc = torture_terminate_process(s->srv_pidfile);
    if (rc != 0) {
        fprintf(stderr, "XXXXXX Failed to terminate sshd\n");
    }

    torture_teardown_socket_dir(state);
}

int torture_libssh_verbosity(void){
  return verbosity;
}

void _torture_filter_tests(struct CMUnitTest *tests, size_t ntests)
{
    size_t i,j;
    const char *name;
    if (pattern == NULL){
        return;
    }
    for (i=0; i < ntests; ++i){
        name = tests[i].name;
        /*printf("match(%s,%s)\n",name,pattern);*/
        if (!match_pattern(name, pattern)){
            for (j = i; j < ntests-1;++j){
                tests[j]=tests[j+1];
            }
            tests[ntests-1].name = NULL;
            tests[ntests-1].test_func = NULL;
            ntests--;
            --i;
        }
    }
    if (ntests != 0){
        printf("%d tests left\n",(int)ntests);
    } else {
        printf("No matching test left\n");
    }
}

#endif /* _WIN32 */

void torture_write_file(const char *filename, const char *data){
    int fd;
    int rc;

    assert_non_null(filename);
    assert_true(filename[0] != '\0');
    assert_non_null(data);

    fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT, 0600);
    assert_true(fd >= 0);

    rc = write(fd, data, strlen(data));
    assert_int_equal(rc, strlen(data));

    close(fd);
}


int main(int argc, char **argv) {
  struct argument_s arguments;
  char *env = getenv("LIBSSH_VERBOSITY");

  arguments.verbose=0;
  arguments.pattern=NULL;
  torture_cmdline_parse(argc, argv, &arguments);
  verbosity=arguments.verbose;
  pattern=arguments.pattern;

  if (verbosity == 0 && env != NULL && env[0] != '\0') {
      if (env[0] > '0' && env[0] < '9') {
          verbosity = atoi(env);
      }
  }

  return torture_run_tests();
}

/* vim: set ts=4 sw=4 et cindent syntax=c.doxygen: */
