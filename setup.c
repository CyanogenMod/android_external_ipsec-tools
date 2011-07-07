/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <fcntl.h>

#include "config.h"
#include "gcmalloc.h"
#include "libpfkey.h"
#include "var.h"
#include "isakmp_var.h"
#include "isakmp.h"
#include "vmbuf.h"
#include "crypto_openssl.h"
#include "oakley.h"
#include "ipsec_doi.h"
#include "algorithm.h"
#include "vendorid.h"
#include "schedule.h"
#include "pfkey.h"
#include "nattraversal.h"
#include "proposal.h"
#include "sainfo.h"
#include "localconf.h"
#include "remoteconf.h"
#include "sockmisc.h"
#include "grabmyaddr.h"
#include "plog.h"
#include "admin.h"
#include "privsep.h"
#include "throttle.h"
#include "misc.h"

static struct localconf localconf;
static struct sainfo sainfo;
static char *pre_shared_key;

static char *interface;
static struct sockaddr *target;
static struct {
    struct sockaddr *addr;
    int fd;
} myaddrs[2];

struct localconf *lcconf = &localconf;
char *script_names[SCRIPT_MAX + 1];
int f_local = 0;

/*****************************************************************************/

static void add_sainfo_algorithm(int class, int algorithm, int length)
{
    struct sainfoalg *p = calloc(1, sizeof(struct sainfoalg));
    p->alg = algorithm;
    p->encklen = length;

    if (!sainfo.algs[class]) {
        sainfo.algs[class] = p;
    } else {
        struct sainfoalg *q = sainfo.algs[class];
        while (q->next) {
            q = q->next;
        }
        q->next = p;
    }
}

static void set_globals(char *interfaze, char *server)
{
    struct addrinfo hints = {
        .ai_flags = AI_NUMERICSERV,
#ifndef INET6
        .ai_family = AF_INET,
#else
        .ai_family = AF_UNSPEC,
#endif
        .ai_socktype = SOCK_DGRAM,
    };
    struct addrinfo *info;

    if (getaddrinfo(server, "80", &hints, &info) != 0) {
        do_plog(LLV_ERROR, "Cannot resolve address: %s\n", server);
        exit(1);
    }
    if (info->ai_next) {
        do_plog(LLV_WARNING, "Found multiple addresses. Use the first one.\n");
    }
    target = dupsaddr(info->ai_addr);
    freeaddrinfo(info);

    interface = interfaze;
    myaddrs[0].addr = getlocaladdr(target);
    if (!myaddrs[0].addr) {
        do_plog(LLV_ERROR, "Cannot get local address\n");
        exit(1);
    }
    set_port(target, 0);
    set_port(myaddrs[0].addr, 0);
    myaddrs[0].fd = -1;
    myaddrs[1].addr = dupsaddr(myaddrs[0].addr);
    myaddrs[1].fd = -1;

    localconf.port_isakmp = PORT_ISAKMP;
    localconf.port_isakmp_natt = PORT_ISAKMP_NATT;
    localconf.default_af = AF_INET;
    localconf.pathinfo[LC_PATHTYPE_CERT] = "./";
    localconf.pad_random = LC_DEFAULT_PAD_RANDOM;
    localconf.pad_randomlen = LC_DEFAULT_PAD_RANDOM;
    localconf.pad_strict = LC_DEFAULT_PAD_STRICT;
    localconf.pad_excltail = LC_DEFAULT_PAD_EXCLTAIL;
    localconf.retry_counter = 10;
    localconf.retry_interval = 3;
    localconf.count_persend = LC_DEFAULT_COUNT_PERSEND;
    localconf.secret_size = LC_DEFAULT_SECRETSIZE;
    localconf.retry_checkph1 = LC_DEFAULT_RETRY_CHECKPH1;
    localconf.wait_ph2complete = LC_DEFAULT_WAIT_PH2COMPLETE;
    localconf.natt_ka_interval = LC_DEFAULT_NATT_KA_INTERVAL;

    sainfo.lifetime = IPSECDOI_ATTR_SA_LD_SEC_DEFAULT;
    sainfo.lifebyte = IPSECDOI_ATTR_SA_LD_KB_MAX;
    add_sainfo_algorithm(algclass_ipsec_auth, IPSECDOI_ATTR_AUTH_HMAC_SHA1, 0);
    add_sainfo_algorithm(algclass_ipsec_auth, IPSECDOI_ATTR_AUTH_HMAC_MD5, 0);
    add_sainfo_algorithm(algclass_ipsec_enc, IPSECDOI_ESP_3DES, 0);
    add_sainfo_algorithm(algclass_ipsec_enc, IPSECDOI_ESP_DES, 0);
    add_sainfo_algorithm(algclass_ipsec_enc, IPSECDOI_ESP_AES, 128);
}

/*****************************************************************************/

static int policy_match(struct sadb_address *address)
{
    if (address) {
        return cmpsaddr(PFKEY_ADDR_SADDR(address), target) < CMPSADDR_MISMATCH;
    }
    return 0;
}

/* flush; spdflush; */
static void flush()
{
    struct sadb_msg *p;
    int replies = 0;
    int key = pfkey_open();

    if (pfkey_send_dump(key, SADB_SATYPE_UNSPEC) <= 0 ||
        pfkey_send_spddump(key) <= 0) {
        do_plog(LLV_ERROR, "Cannot dump SAD and SPD");
        exit(1);
    }

    for (p = NULL; replies < 2 && (p = pfkey_recv(key)) != NULL; free(p)) {
        caddr_t q[SADB_EXT_MAX + 1];

        if (p->sadb_msg_type != SADB_DUMP &&
            p->sadb_msg_type != SADB_X_SPDDUMP) {
            continue;
        }
        replies += !p->sadb_msg_seq;

        if (p->sadb_msg_errno || pfkey_align(p, q) || pfkey_check(q)) {
            continue;
        }
        if (policy_match((struct sadb_address *)q[SADB_EXT_ADDRESS_SRC]) ||
            policy_match((struct sadb_address *)q[SADB_EXT_ADDRESS_DST])) {
            p->sadb_msg_type = (p->sadb_msg_type == SADB_DUMP) ?
                               SADB_DELETE : SADB_X_SPDDELETE;
            p->sadb_msg_reserved = 0;
            p->sadb_msg_seq = 0;
            pfkey_send(key, p, PFKEY_UNUNIT64(p->sadb_msg_len));
        }
    }

    pfkey_close(key);
}

/* flush; spdflush;
 * spdadd src dst protocol -P out ipsec esp/transport//require; OR
 * spdadd src any protocol -P out ipsec esp/tunnel/local-remote/require; */
static void spdadd(struct sockaddr *src, struct sockaddr *dst,
        int protocol, struct sockaddr *local, struct sockaddr *remote)
{
    struct __attribute__((packed)) {
        struct sadb_x_policy p;
        struct sadb_x_ipsecrequest q;
        char addresses[sizeof(struct sockaddr_storage) * 2];
    } policy;

    struct sockaddr_storage any = {
#ifndef __linux__
        .ss_len = src->sa_len,
#endif
        .ss_family = src->sa_family,
    };

    int src_prefix = (src->sa_family == AF_INET) ? 32 : 128;
    int dst_prefix = src_prefix;
    int length = 0;
    int key;

    /* Fill default values. */
    memset(&policy, 0, sizeof(policy));
    policy.p.sadb_x_policy_exttype = SADB_X_EXT_POLICY;
    policy.p.sadb_x_policy_type = IPSEC_POLICY_IPSEC;
    policy.p.sadb_x_policy_dir = IPSEC_DIR_OUTBOUND;
#ifdef HAVE_PFKEY_POLICY_PRIORITY
    policy.p.sadb_x_policy_priority = PRIORITY_DEFAULT;
#endif
    policy.q.sadb_x_ipsecrequest_proto = IPPROTO_ESP;
    policy.q.sadb_x_ipsecrequest_mode = IPSEC_MODE_TRANSPORT;
    policy.q.sadb_x_ipsecrequest_level = IPSEC_LEVEL_REQUIRE;

    /* Deal with tunnel mode. */
    if (!dst) {
        policy.q.sadb_x_ipsecrequest_mode = IPSEC_MODE_TUNNEL;
        dst = (struct sockaddr *)&any;
        dst_prefix = 0;

        length = sysdep_sa_len(local);
        memcpy(policy.addresses, local, length);
        memcpy(&policy.addresses[length], remote, length);
        length += length;

        /* Use the source address to flush policies. */
        racoon_free(target);
        target = dupsaddr(src);
    }

    /* Fix lengths. */
    length += sizeof(policy.q);
    policy.q.sadb_x_ipsecrequest_len = length;
    length += sizeof(policy.p);
    policy.p.sadb_x_policy_len = PFKEY_UNIT64(length);

    /* Always do a flush before adding the new policy. */
    flush();
    key = pfkey_open();
    if (pfkey_send_spdadd(key, src, src_prefix, dst, dst_prefix, protocol,
            (caddr_t)&policy, length, 0) <= 0) {
        do_plog(LLV_ERROR, "Cannot initialize SAD and SPD\n");
        exit(1);
    }
    pfkey_close(key);
    atexit(flush);
}

/*****************************************************************************/

static void add_proposal(struct remoteconf *remoteconf,
        int auth, int hash, int encryption, int length)
{
    struct isakmpsa *p = racoon_calloc(1, sizeof(struct isakmpsa));
    p->prop_no = 1;
    p->lifetime = OAKLEY_ATTR_SA_LD_SEC_DEFAULT;
    p->enctype = encryption;
    p->encklen = length;
    p->authmethod = auth;
    p->hashtype = hash;
    p->dh_group = OAKLEY_ATTR_GRP_DESC_MODP1024;
    p->vendorid = VENDORID_UNKNOWN;

    if (!remoteconf->proposal) {
      p->trns_no = 1;
      remoteconf->proposal = p;
    } else {
        struct isakmpsa *q = remoteconf->proposal;
        while (q->next) {
            q = q->next;
        }
        p->trns_no = q->trns_no + 1;
        q->next = p;
    }
}

void setup(int argc, char **argv)
{
    struct remoteconf *remoteconf;
    int auth;

    if (argc > 2) {
        set_globals(argv[1], argv[2]);

        /* Initialize everything else. */
        eay_init();
        initrmconf();
        oakley_dhinit();
        compute_vendorids();
        sched_init();
        if (pfkey_init() < 0 || isakmp_init() < 0) {
            exit(1);
        }
#ifdef ENABLE_NATT
        natt_keepalive_init();
#endif

        /* Create remote configuration. */
        remoteconf = newrmconf();
        remoteconf->etypes = racoon_calloc(1, sizeof(struct etypes));
        remoteconf->etypes->type = ISAKMP_ETYPE_IDENT;
        remoteconf->ike_frag = TRUE;
        remoteconf->pcheck_level = PROP_CHECK_OBEY;
        remoteconf->gen_policy = TRUE;
        remoteconf->nat_traversal = TRUE;
        remoteconf->remote = dupsaddr(target);
        set_port(remoteconf->remote, localconf.port_isakmp);
    }

    /* Set authentication method and credentials. */
    if (argc == 6 && !strcmp(argv[3], "udppsk")) {
        set_port(target, atoi(argv[4]));
        spdadd(myaddrs[0].addr, target, IPPROTO_UDP, NULL, NULL);
        pre_shared_key = argv[5];
        remoteconf->idvtype = IDTYPE_ADDRESS;
        auth = OAKLEY_ATTR_AUTH_METHOD_PSKEY;
    } else if (argc == 8 && !strcmp(argv[3], "udprsa")) {
        char path[PATH_MAX + 1];
        set_port(target, atoi(argv[4]));
        spdadd(myaddrs[0].addr, target, IPPROTO_UDP, NULL, NULL);
        remoteconf->myprivfile = argv[5];
        remoteconf->mycertfile = argv[6];
        getpathname(path, sizeof(path), LC_PATHTYPE_CERT, argv[6]);
        remoteconf->mycert = eay_get_x509cert(path);
        if (!remoteconf->mycert) {
            do_plog(LLV_ERROR, "Cannot load user certificate\n");
            exit(1);
        }
        if (!*argv[7]) {
            remoteconf->verify_cert = FALSE;
        } else {
            remoteconf->cacertfile = argv[7];
            getpathname(path, sizeof(path), LC_PATHTYPE_CERT, argv[7]);
            remoteconf->cacert = eay_get_x509cert(path);
            if (!remoteconf->cacert) {
                do_plog(LLV_ERROR, "Cannot load CA certificate\n");
                exit(1);
            }
        }
        remoteconf->idvtype = IDTYPE_ASN1DN;
        auth = OAKLEY_ATTR_AUTH_METHOD_RSASIG;
    } else {
        printf("Usage: %s <interface> <server> [...],\n"
               "    where [...] can be:\n"
               "    udppsk <port> <pre-shared-key>\n"
               "    udprsa <port> <user-private-key> <user-cert> <ca-cert>\n",
               argv[0]);
        exit(0);
    }

    /* Add proposals. */
    add_proposal(remoteconf, auth,
            OAKLEY_ATTR_HASH_ALG_SHA, OAKLEY_ATTR_ENC_ALG_3DES, 0);
    add_proposal(remoteconf, auth,
            OAKLEY_ATTR_HASH_ALG_MD5, OAKLEY_ATTR_ENC_ALG_3DES, 0);
    add_proposal(remoteconf, auth,
            OAKLEY_ATTR_HASH_ALG_SHA, OAKLEY_ATTR_ENC_ALG_DES, 0);
    add_proposal(remoteconf, auth,
            OAKLEY_ATTR_HASH_ALG_MD5, OAKLEY_ATTR_ENC_ALG_DES, 0);
    add_proposal(remoteconf, auth,
            OAKLEY_ATTR_HASH_ALG_SHA, OAKLEY_ATTR_ENC_ALG_AES, 128);
    add_proposal(remoteconf, auth,
            OAKLEY_ATTR_HASH_ALG_MD5, OAKLEY_ATTR_ENC_ALG_AES, 128);

    /* Install remote configuration. */
    insrmconf(remoteconf);

    /* Create ISAKMP sockets. */
    set_port(myaddrs[0].addr, localconf.port_isakmp);
    myaddrs[0].fd = isakmp_open(myaddrs[0].addr, FALSE);
    if (myaddrs[0].fd == -1) {
        do_plog(LLV_ERROR, "Cannot create ISAKMP socket");
        exit(1);
    }
#ifdef ENABLE_NATT
    set_port(myaddrs[1].addr, localconf.port_isakmp_natt);
    myaddrs[1].fd = isakmp_open(myaddrs[1].addr, TRUE);
    if (myaddrs[1].fd == -1) {
        do_plog(LLV_WARNING, "Cannot create ISAKMP socket for NAT-T");
    }
#endif
}

/*****************************************************************************/

/* localconf.h */

vchar_t *getpskbyaddr(struct sockaddr *addr)
{
    vchar_t *p = NULL;
    if (pre_shared_key && (p = vmalloc(strlen(pre_shared_key)))) {
        memcpy(p->v, pre_shared_key, p->l);
    }
    return p;
}

vchar_t *getpskbyname(vchar_t *name)
{
    return NULL;
}

void getpathname(char *path, int length, int type, const char *name)
{
    if (localconf.chroot) {
        snprintf(path, length, localconf.chroot, name);
    } else {
        strncpy(path, name, length);
    }
    path[length - 1] = '\0';
}

/* grabmyaddr.h */

int myaddr_getsport(struct sockaddr *addr)
{
    return 0;
}

int myaddr_getfd(struct sockaddr *addr)
{
#ifdef ENABLE_NATT
    if (myaddrs[1].fd != -1 &&
            cmpsaddr(addr, myaddrs[1].addr) == CMPSADDR_MATCH) {
        return myaddrs[1].fd;
    }
#endif
    if (cmpsaddr(addr, myaddrs[0].addr) < CMPSADDR_MISMATCH) {
        return myaddrs[0].fd;
    }
    return -1;
}

/* misc.h */

int racoon_hexdump(void *data, size_t length)
{
    return 0;
}

void close_on_exec(int fd)
{
    fcntl(fd, F_SETFD, FD_CLOEXEC);
}

/* sainfo.h */

struct sainfo *getsainfo(const vchar_t *src, const vchar_t *dst,
        const vchar_t *peer, const vchar_t *client, uint32_t remoteid)
{
    return &sainfo;
}

const char *sainfo2str(const struct sainfo *si)
{
    return "*";
}

/* privsep.h */

int privsep_socket(int domain, int type, int protocol)
{
    int fd = socket(domain, type, protocol);
    if ((domain == AF_INET || domain == AF_INET6) && setsockopt(
            fd, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface))) {
        do_plog(LLV_WARNING, "Cannot bind socket to %s", interface);
    }
    return fd;
}

int privsep_bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    return bind(fd, addr, addrlen);
}

vchar_t *privsep_eay_get_pkcs1privkey(char *file)
{
    return eay_get_pkcs1privkey(file);
}

int privsep_script_exec(char *script, int name, char * const *environ)
{
    return 0;
}

int privsep_accounting_system(int port, struct sockaddr *addr,
        char *user, int status)
{
    return 0;
}

int privsep_xauth_login_system(char *user, char *password)
{
    return -1;
}

/* throttle.h */

int throttle_host(struct sockaddr *addr, int fail)
{
    return 0;
}
