/*	$NetBSD: admin.c,v 1.17.6.2 2008/06/18 07:30:19 mgrooms Exp $	*/

/* Id: admin.c,v 1.25 2006/04/06 14:31:04 manubsd Exp */

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#ifndef ANDROID_CHANGES
#include <sys/signal.h>
#else
#include <cutils/sockets.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "cfparse_proto.h"
#define SIGHUP	1
#endif
#include <sys/stat.h>
#include <sys/un.h>

#include <net/pfkeyv2.h>

#include <netinet/in.h>
#include PATH_IPSEC_H


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef ENABLE_HYBRID
#include <resolv.h>
#endif

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "plog.h"
#include "sockmisc.h"
#include "debug.h"

#include "schedule.h"
#include "localconf.h"
#include "remoteconf.h"
#include "grabmyaddr.h"
#include "isakmp_var.h"
#include "isakmp.h"
#include "oakley.h"
#include "handler.h"
#include "evt.h"
#include "pfkey.h"
#include "ipsec_doi.h"
#include "admin.h"
#include "admin_var.h"
#include "isakmp_inf.h"
#ifdef ENABLE_HYBRID
#include "isakmp_cfg.h"
#endif
#include "session.h"
#include "gcmalloc.h"

#ifdef ENABLE_ADMINPORT
char *adminsock_path = ADMINSOCK_PATH;
uid_t adminsock_owner = 0;
gid_t adminsock_group = 0;
mode_t adminsock_mode = 0600;

static struct sockaddr_un sunaddr;
static int admin_process __P((int, char *));
static int admin_reply __P((int, struct admin_com *, vchar_t *));

int
admin_handler()
{
	int so2;
	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(from);
	struct admin_com com;
	char *combuf = NULL;
	int len, error = -1;

	so2 = accept(lcconf->sock_admin, (struct sockaddr *)&from, &fromlen);
	if (so2 < 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to accept admin command: %s\n",
			strerror(errno));
		return -1;
	}

	/* get buffer length */
	while ((len = recv(so2, (char *)&com, sizeof(com), MSG_PEEK)) < 0) {
		if (errno == EINTR)
			continue;
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to recv admin command: %s\n",
			strerror(errno));
		goto end;
	}

	/* sanity check */
	if (len < sizeof(com)) {
		plog(LLV_ERROR, LOCATION, NULL,
			"invalid header length of admin command\n");
		goto end;
	}

	/* get buffer to receive */
	if ((combuf = racoon_malloc(com.ac_len)) == 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to alloc buffer for admin command\n");
		goto end;
	}

	/* get real data */
	while ((len = recv(so2, combuf, com.ac_len, 0)) < 0) {
		if (errno == EINTR)
			continue;
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to recv admin command: %s\n",
			strerror(errno));
		goto end;
	}

	if (com.ac_cmd == ADMIN_RELOAD_CONF) {
		/* reload does not work at all! */
		signal_handler(SIGHUP);
		goto end;
	}

	error = admin_process(so2, combuf);

    end:
	(void)close(so2);
	if (combuf)
		racoon_free(combuf);

	return error;
}

/*
 * main child's process.
 */
static int
admin_process(so2, combuf)
	int so2;
	char *combuf;
{
	struct admin_com *com = (struct admin_com *)combuf;
	vchar_t *buf = NULL;
	vchar_t *id = NULL;
	vchar_t *key = NULL;
	int idtype = 0;
	int error = -1;

	com->ac_errno = 0;

	switch (com->ac_cmd) {
	case ADMIN_RELOAD_CONF:
		/* don't entered because of proccessing it in other place. */
		plog(LLV_ERROR, LOCATION, NULL, "should never reach here\n");
		goto out;

	case ADMIN_SHOW_SCHED:
	{
		caddr_t p = NULL;
		int len;

		com->ac_errno = -1;

		if (sched_dump(&p, &len) == -1)
			goto out2;

		if ((buf = vmalloc(len)) == NULL)
			goto out2;

		memcpy(buf->v, p, len);

		com->ac_errno = 0;
out2:
		racoon_free(p);
		break;
	}

	case ADMIN_SHOW_EVT:
		/* It's not really an error, don't force racoonctl to quit */
		if ((buf = evt_dump()) == NULL)
			com->ac_errno = 0;
		break;

	case ADMIN_SHOW_SA:
	case ADMIN_FLUSH_SA:
	    {
		switch (com->ac_proto) {
		case ADMIN_PROTO_ISAKMP:
			switch (com->ac_cmd) {
			case ADMIN_SHOW_SA:
				buf = dumpph1();
				if (buf == NULL)
					com->ac_errno = -1;
				break;
			case ADMIN_FLUSH_SA:
				flushph1();
				break;
			}
			break;
		case ADMIN_PROTO_IPSEC:
		case ADMIN_PROTO_AH:
		case ADMIN_PROTO_ESP:
			switch (com->ac_cmd) {
			case ADMIN_SHOW_SA:
			    {
				u_int p;
				p = admin2pfkey_proto(com->ac_proto);
				if (p == -1)
					goto out;
				buf = pfkey_dump_sadb(p);
				if (buf == NULL)
					com->ac_errno = -1;
			    }
				break;
			case ADMIN_FLUSH_SA:
				pfkey_flush_sadb(com->ac_proto);
				break;
			}
			break;

		case ADMIN_PROTO_INTERNAL:
			switch (com->ac_cmd) {
			case ADMIN_SHOW_SA:
				buf = NULL; /*XXX dumpph2(&error);*/
				if (buf == NULL)
					com->ac_errno = error;
				break;
			case ADMIN_FLUSH_SA:
				/*XXX flushph2();*/
				com->ac_errno = 0;
				break;
			}
			break;

		default:
			/* ignore */
			com->ac_errno = -1;
		}
	    }
		break;

	case ADMIN_DELETE_SA: {
		struct ph1handle *iph1;
		struct sockaddr *dst;
		struct sockaddr *src;
		char *loc, *rem;

		src = (struct sockaddr *)
			&((struct admin_com_indexes *)
			    ((caddr_t)com + sizeof(*com)))->src;
		dst = (struct sockaddr *)
			&((struct admin_com_indexes *)
			    ((caddr_t)com + sizeof(*com)))->dst;

		loc = racoon_strdup(saddrwop2str(src));
		rem = racoon_strdup(saddrwop2str(dst));
		STRDUP_FATAL(loc);
		STRDUP_FATAL(rem);

		if ((iph1 = getph1byaddrwop(src, dst)) == NULL) {
			plog(LLV_ERROR, LOCATION, NULL,
			    "phase 1 for %s -> %s not found\n", loc, rem);
		} else {
			if (iph1->status == PHASE1ST_ESTABLISHED)
				isakmp_info_send_d1(iph1);
			purge_remote(iph1);
		}

		racoon_free(loc);
		racoon_free(rem);

		break;
	}

#ifdef ENABLE_HYBRID
	case ADMIN_LOGOUT_USER: {
		struct ph1handle *iph1;
		char *user;
		int found = 0;

		if (com->ac_len > sizeof(com) + LOGINLEN + 1) {
			plog(LLV_ERROR, LOCATION, NULL,
			    "malformed message (login too long)\n");
			break;
		}

		user = (char *)(com + 1);
		found = purgeph1bylogin(user);
		plog(LLV_INFO, LOCATION, NULL,
		    "deleted %d SA for user \"%s\"\n", found, user);

		break;
	}
#endif

	case ADMIN_DELETE_ALL_SA_DST: {
		struct ph1handle *iph1;
		struct sockaddr *dst;
		char *loc, *rem;

		dst = (struct sockaddr *)
			&((struct admin_com_indexes *)
			    ((caddr_t)com + sizeof(*com)))->dst;

		rem = racoon_strdup(saddrwop2str(dst));
		STRDUP_FATAL(rem);

		plog(LLV_INFO, LOCATION, NULL,
		    "Flushing all SAs for peer %s\n", rem);

		while ((iph1 = getph1bydstaddrwop(dst)) != NULL) {
			loc = racoon_strdup(saddrwop2str(iph1->local));
			STRDUP_FATAL(loc);

			if (iph1->status == PHASE1ST_ESTABLISHED)
				isakmp_info_send_d1(iph1);
			purge_remote(iph1);

			racoon_free(loc);
		}

		racoon_free(rem);

		break;
	}

	case ADMIN_ESTABLISH_SA_PSK: {
		struct admin_com_psk *acp;
		char *data;

		com->ac_cmd = ADMIN_ESTABLISH_SA;

		acp = (struct admin_com_psk *)
		    ((char *)com + sizeof(*com) +
		    sizeof(struct admin_com_indexes));

		idtype = acp->id_type;

		if ((id = vmalloc(acp->id_len)) == NULL) {
			plog(LLV_ERROR, LOCATION, NULL,
			    "cannot allocate memory: %s\n",
			    strerror(errno));
			break;
		}
		data = (char *)(acp + 1);
		memcpy(id->v, data, id->l);

		if ((key = vmalloc(acp->key_len)) == NULL) {
			plog(LLV_ERROR, LOCATION, NULL,
			    "cannot allocate memory: %s\n",
			    strerror(errno));
			vfree(id);
			id = NULL;
			break;
		}
		data = (char *)(data + acp->id_len);
		memcpy(key->v, data, key->l);
	}
	/* FALLTHROUGH */
	case ADMIN_ESTABLISH_SA:
	    {
		struct sockaddr *dst;
		struct sockaddr *src;
		src = (struct sockaddr *)
			&((struct admin_com_indexes *)
			    ((caddr_t)com + sizeof(*com)))->src;
		dst = (struct sockaddr *)
			&((struct admin_com_indexes *)
			    ((caddr_t)com + sizeof(*com)))->dst;

		switch (com->ac_proto) {
		case ADMIN_PROTO_ISAKMP: {
			struct remoteconf *rmconf;
			struct sockaddr *remote = NULL;
			struct sockaddr *local = NULL;
			u_int16_t port;

			com->ac_errno = -1;

			/* search appropreate configuration */
			rmconf = getrmconf(dst);
			if (rmconf == NULL) {
				plog(LLV_ERROR, LOCATION, NULL,
					"no configuration found "
					"for %s\n", saddrwop2str(dst));
				goto out1;
			}

			/* get remote IP address and port number. */
			if ((remote = dupsaddr(dst)) == NULL)
				goto out1;

			port = extract_port(rmconf->remote);
			if (set_port(remote, port) == NULL)
				goto out1;

			/* get local address */
			if ((local = dupsaddr(src)) == NULL)
				goto out1;

			port = getmyaddrsport(local);
			if (set_port(local, port) == NULL)
				goto out1;

#ifdef ENABLE_HYBRID
			/* Set the id and key */
			if (id && key) {
				if (xauth_rmconf_used(&rmconf->xauth) == -1)
					goto out1;

				if (rmconf->xauth->login != NULL) {
					vfree(rmconf->xauth->login);
					rmconf->xauth->login = NULL;
				}
				if (rmconf->xauth->pass != NULL) {
					vfree(rmconf->xauth->pass);
					rmconf->xauth->pass = NULL;
				}

				rmconf->xauth->login = id;
				rmconf->xauth->pass = key;
			}
#endif

			plog(LLV_INFO, LOCATION, NULL,
				"accept a request to establish IKE-SA: "
				"%s\n", saddrwop2str(remote));

			/* begin ident mode */
			if (isakmp_ph1begin_i(rmconf, remote, local) < 0)
				goto out1;

			com->ac_errno = 0;
out1:
			if (local != NULL)
				racoon_free(local);
			if (remote != NULL)
				racoon_free(remote);
			break;
		}
		case ADMIN_PROTO_AH:
		case ADMIN_PROTO_ESP:
			break;
		default:
			/* ignore */
			com->ac_errno = -1;
		}
	    }
		break;

	default:
		plog(LLV_ERROR, LOCATION, NULL,
			"invalid command: %d\n", com->ac_cmd);
		com->ac_errno = -1;
	}

	if ((error = admin_reply(so2, com, buf)) != 0)
		goto out;

	error = 0;
out:
	if (buf != NULL)
		vfree(buf);

	return error;
}

static int
admin_reply(so, combuf, buf)
	int so;
	struct admin_com *combuf;
	vchar_t *buf;
{
	int tlen;
	char *retbuf = NULL;

	if (buf != NULL)
		tlen = sizeof(*combuf) + buf->l;
	else
		tlen = sizeof(*combuf);

	retbuf = racoon_calloc(1, tlen);
	if (retbuf == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to allocate admin buffer\n");
		return -1;
	}

	memcpy(retbuf, combuf, sizeof(*combuf));
	((struct admin_com *)retbuf)->ac_len = tlen;

	if (buf != NULL)
		memcpy(retbuf + sizeof(*combuf), buf->v, buf->l);

	tlen = send(so, retbuf, tlen, 0);
	racoon_free(retbuf);
	if (tlen < 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to send admin command: %s\n",
			strerror(errno));
		return -1;
	}

	return 0;
}

/* ADMIN_PROTO -> SADB_SATYPE */
int
admin2pfkey_proto(proto)
	u_int proto;
{
	switch (proto) {
	case ADMIN_PROTO_IPSEC:
		return SADB_SATYPE_UNSPEC;
	case ADMIN_PROTO_AH:
		return SADB_SATYPE_AH;
	case ADMIN_PROTO_ESP:
		return SADB_SATYPE_ESP;
	default:
		plog(LLV_ERROR, LOCATION, NULL,
			"unsupported proto for admin: %d\n", proto);
		return -1;
	}
	/*NOTREACHED*/
}

int
admin_init()
{
	if (adminsock_path == NULL) {
		lcconf->sock_admin = -1;
		return 0;
	}

	memset(&sunaddr, 0, sizeof(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	snprintf(sunaddr.sun_path, sizeof(sunaddr.sun_path),
		"%s", adminsock_path);

	lcconf->sock_admin = socket(AF_UNIX, SOCK_STREAM, 0);
	if (lcconf->sock_admin == -1) {
		plog(LLV_ERROR, LOCATION, NULL,
			"socket: %s\n", strerror(errno));
		return -1;
	}

	unlink(sunaddr.sun_path);
	if (bind(lcconf->sock_admin, (struct sockaddr *)&sunaddr,
			sizeof(sunaddr)) != 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"bind(sockname:%s): %s\n",
			sunaddr.sun_path, strerror(errno));
		(void)close(lcconf->sock_admin);
		return -1;
	}

	if (chown(sunaddr.sun_path, adminsock_owner, adminsock_group) != 0) {
		plog(LLV_ERROR, LOCATION, NULL,
		    "chown(%s, %d, %d): %s\n",
		    sunaddr.sun_path, adminsock_owner,
		    adminsock_group, strerror(errno));
		(void)close(lcconf->sock_admin);
		return -1;
	}

	if (chmod(sunaddr.sun_path, adminsock_mode) != 0) {
		plog(LLV_ERROR, LOCATION, NULL,
		    "chmod(%s, 0%03o): %s\n",
		    sunaddr.sun_path, adminsock_mode, strerror(errno));
		(void)close(lcconf->sock_admin);
		return -1;
	}

	if (listen(lcconf->sock_admin, 5) != 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"listen(sockname:%s): %s\n",
			sunaddr.sun_path, strerror(errno));
		(void)close(lcconf->sock_admin);
		return -1;
	}
	plog(LLV_DEBUG, LOCATION, NULL,
		"open %s as racoon management.\n", sunaddr.sun_path);

	return 0;
}

int
admin_close()
{
	close(lcconf->sock_admin);
	return 0;
}
#endif

#ifdef ANDROID_CHANGES
// Add the android specific control commands from VPN settings.
#define CMD_LOAD_CONFIG "LOAD_CONFIG "
#define CMD_SETKEY "SETKEY "
#define CMD_SET_CERTS "SET_CERTS "
#define RACOON_SOCKET "racoon"
#define PORT_L2TP 1701

// The following policy is supported for now.
#define INCOMING_POLICY "in ipsec esp/transport//require"
#define OUTGOING_POLICY "out ipsec esp/transport//require"

static inline int get_sockaddr_in(addr, port, sin)
    const char *addr;
    int port;
    struct sockaddr_in *sin;
{
    struct hostent *entry;

    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    sin->sin_addr.s_addr = inet_addr(addr);

    if ((int)sin->sin_addr.s_addr != -1) {
        return 0;
    }
    if ((entry = gethostbyname(addr)) != NULL) {
        memcpy(&sin->sin_addr, *entry->h_addr_list, sizeof(struct in_addr));
        if ((int)sin->sin_addr.s_addr != -1) {
            return 0;
        }
    }
    plog(LLV_ERROR, LOCATION, NULL,
         "ERROR: incorrect src or dst address(%s)", addr);
    return -1;
}

static int parse_addresses(buf, src, dst)
    char *buf;
    struct sockaddr_in *src, *dst;
{
    char *tokens[2], *argv = buf;
    int i = 0;
    while(i < 2) {
        if ((tokens[i++] = strtok(argv, " ")) == NULL) {
            return -1;
        }
        argv = NULL;
    }
    if ((get_sockaddr_in(tokens[0], 0, src) != 0) ||
        (get_sockaddr_in(tokens[1], PORT_L2TP, dst) != 0)) {
        return -1;
    }
    return 0;
}

static int spdadd(addresses)
    const char *addresses;
{
    struct sockaddr src, dst;
    char *outpolicy, *inpolicy;
    int inlen, outlen, plen;
    int so = -1;

    /* SETKEY src_ip dst_ip */
    if (parse_addresses(addresses, (struct sockaddr_in *)&src,
        (struct sockaddr_in *)&dst) < 0) {
        exit(1);
    }

    outpolicy = ipsec_set_policy(OUTGOING_POLICY, strlen(OUTGOING_POLICY));
    outlen = ipsec_get_policylen(outpolicy);
    inpolicy = ipsec_set_policy(INCOMING_POLICY, strlen(INCOMING_POLICY));
    inlen = ipsec_get_policylen(inpolicy);

    if ((so = pfkey_open()) < 0) {
        plog(LLV_ERROR, LOCATION, NULL, "ERROR: %s", ipsec_strerror());
        exit(1);
    }
    // spdflush()
    if (pfkey_send_spdflush(so) < 0) {
        plog(LLV_ERROR, LOCATION, NULL, "ERROR: %s", ipsec_strerror());
        exit(1);
    }
    plen = sizeof(struct in_addr) << 3;
    // add outgoing policy
    if (pfkey_send_spdadd(so, &src, plen, &dst, plen,
                17, outpolicy, outlen, 0) < 0) {
        plog(LLV_ERROR, LOCATION, NULL, "ERROR: %s", ipsec_strerror());
        exit(1);
    }
    // add incoming policy
    if (pfkey_send_spdadd(so, &dst, plen, &src, plen,
                17, inpolicy, inlen, 0) < 0) {
        plog(LLV_ERROR, LOCATION, NULL, "ERROR: %s", ipsec_strerror());
        exit(1);
    }

    pfkey_close(so);
    return 0;
}

static int setcerts(cmd)
    const char *cmd;
{
    /*
     * SET_CERTS has 4 arguments:
     * destip cacert_path usercert_path userkey_path
     */
    struct remoteconf *tplrmconf;
    struct sockaddr dst, anonymous;
    char *tokens[4], *buf = (char*)cmd;
    int i = 0;
    while(i < 4) {
        if ((tokens[i++] = strtok(buf, " ")) == NULL) {
            plog(LLV_ERROR, LOCATION, NULL,
                 "incorrect command SET_CERTS %s", cmd);
            return -1;
        }
        buf = NULL;
    }
    if (get_sockaddr_in(tokens[0], 0, (struct sockaddr_in *)&dst) != 0) {
        plog(LLV_ERROR, LOCATION, NULL, "incorrect dest address %s", tokens[0]);
        return -1;
    }
    anonymous.sa_family = AF_UNSPEC;
    if((tplrmconf = getrmconf(&anonymous)) == NULL) {
        plog(LLV_ERROR, LOCATION, NULL, "Can not find the remtoe template");
        return -1;
    }
    memcpy(tplrmconf->remote, &dst, sizeof(dst));
    tplrmconf->cacertfile = strdup(tokens[1]);
    tplrmconf->mycertfile = strdup(tokens[2]);
    tplrmconf->myprivfile = strdup(tokens[3]);
    return 0;
}

static int
control_process(buf)
    char *buf;
{
    plog(LLV_ERROR, LOCATION, NULL, "control command %s", buf);
    if(strncmp(buf, CMD_LOAD_CONFIG, strlen(CMD_LOAD_CONFIG)) == 0) {
        /* LOAD_CONFIG /data/misc/vpn/xxx/racoon.conf */
        lcconf->racoon_conf = strdup(buf + strlen(CMD_LOAD_CONFIG));
        return cfreparse();
    } else if (strncmp(buf, CMD_SETKEY, strlen(CMD_SETKEY)) == 0) {
        return spdadd(buf + strlen(CMD_SETKEY));
    } else if (strncmp(buf, CMD_SET_CERTS, strlen(CMD_SET_CERTS)) == 0) {
        return setcerts(buf + strlen(CMD_SET_CERTS));
    }
    plog(LLV_ERROR, LOCATION, NULL, "Unsupported command '%s'", buf);
    return -1;
}

int
control_init()
{
    lcconf->control_client = -1;
    lcconf->sock_control = android_get_control_socket(RACOON_SOCKET);
    if (lcconf->sock_control < 0) {
        plog(LLV_ERROR, LOCATION, NULL,
             "Obtaining file descriptor socket '%s' failed: %s",
             RACOON_SOCKET, strerror(errno));
        return -1;
    }
    if (listen(lcconf->sock_control, 5) < 0) {
        plog(LLV_ERROR, LOCATION, NULL,
             "Unable to listen on fd '%d' for socket '%s': %s",
             lcconf->sock_control, RACOON_SOCKET, strerror(errno));
        close(lcconf->sock_control);
        lcconf->sock_control = -1;
        return -1;
    }
    return 0;
}

int
control_newclient()
{
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);

    lcconf->control_client =
        accept(lcconf->sock_control, (struct sockaddr *)&from, &fromlen);
    if (lcconf->control_client < 0) {
        plog(LLV_ERROR, LOCATION, NULL,
            "failed to accept control command: %s\n",
            strerror(errno));
        return -1;
    }
    return 0;
}

int
control_handler()
{
    char buf[512], reply;
    int i, n, len, error = -1;

    /* get command */
    i = 0;
    len = sizeof(buf);
    while ((n = recv(lcconf->control_client, buf + i, len - i, 0)) > 0) {
        i += n;
        if (i >= len) {
            plog(LLV_ERROR, LOCATION, NULL,
                "command is too long: %s\n", buf);
            goto end;
        } else if (buf[i - 1] == 0) {
            error = control_process(buf);
            goto end;
        }
    }
    plog(LLV_ERROR, LOCATION, NULL,
        "failed to recv control command: %s\n", strerror(errno));

end:
    reply = error;
    if (send(lcconf->control_client, &reply, 1, 0) != 1) {
        plog(LLV_ERROR, LOCATION, NULL,
             "failed to send the reply(%d) back\n", reply);
    }
    (void)close(lcconf->control_client);
    lcconf->control_client = -1;
    return error;
}

int
control_close()
{
    close(lcconf->sock_control);
    return 0;
}

void test_commands(char *cmd)
{
  control_process(0, cmd);
}
#endif
