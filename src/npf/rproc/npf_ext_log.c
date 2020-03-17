/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 */

/*
 * Copyright (c) 2010-2012 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-2-Clause-NETBSD)
 *
 * This material is based upon work partially supported by The
 * NetBSD Foundation under a contract with Mindaugas Rasiukevicius.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * NPF logging extension.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <ether.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "compiler.h"
#include "if_var.h"
#include "ether.h"
#include "npf/npf.h"
#include "npf/config/npf_ruleset_type.h"
#include "npf/npf_ruleset.h"
#include "npf/rproc/npf_rproc.h"
#include "npf/npf_cache.h"
#include "npf/npf_session.h"
#include "npf/rproc/npf_ext_log.h"
#include "pktmbuf_internal.h"
#include "util.h"

#define BUF_SIZE        64
#define PRBUF_SIZE      128

#define NPF_LOG(type, fmt, args...)		      \
	rte_log(RTE_LOG_NOTICE, type, fmt "\n", ## args)

static char const *ecn_txt[] = {
	"Not",
	"ECT(1)",
	"ECT(0)",
	"CE",
};

static void
npf_log_mac_fields(const struct rte_mbuf *mbuf,
		   char const *mprefix, char *macs_buf,
		   char const *eprefix, char *etype_buf)
{
	if (dp_pktmbuf_l2_len(mbuf) != ETHER_HDR_LEN &&
	    dp_pktmbuf_l2_len(mbuf) != VLAN_HDR_LEN)
		return;

	const struct rte_ether_hdr *eth
		= rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

	unsigned int pl;
	char *bp;

	/* First do the MAC addresses */
	pl = strlen(mprefix);
	bp = macs_buf;

	memcpy(bp, mprefix, pl + 1);
	bp += pl;

	ether_ntoa_r(&eth->s_addr, bp);
	bp += strlen(bp);

	*bp++ = '-';
	*bp++ = '>';

	ether_ntoa_r(&eth->d_addr, bp);
	bp += strlen(bp);

	*bp++ = ' ';
	*bp++ = '\0';

	/* Now the ethertype */
	uint16_t etype = ntohs(ethtype(mbuf, ETHER_TYPE_VLAN));

	snprintf(etype_buf, BUF_SIZE, "%s%04X", eprefix, etype);
}

static void
npf_log_ipv4_header(const struct ip *ip, char *ip_buf, uint32_t buf_size)
{
	uint8_t tos = ip->ip_tos;
	char const *ecn = ecn_txt[tos & 3];
	snprintf(ip_buf, buf_size,
		 "v4=(len:%u,ttl:%u,tos:%02X,ecn:%s,prot:%u,hl:%u)",
		 ntohs(ip->ip_len), ip->ip_ttl, tos, ecn, ip->ip_p,
		 ip->ip_hl);
}

static void
npf_log_ipv6_header(const struct ip6_hdr *ip6, char *ip_buf, uint32_t buf_size)
{
	uint32_t flow = ntohl(ip6->ip6_flow);
	uint8_t tc = (flow>>20)&0xff;
	char const *ecn = ecn_txt[tc & 3];
	snprintf(ip_buf, buf_size,
		"v6=(len:%u,hlim:%u,tc:%02X,ecn:%s,nxt:%u,flow:%05x)",
		(ntohs(ip6->ip6_plen) + (unsigned int)sizeof(struct ip6_hdr)),
		ip6->ip6_hlim, tc, ecn, ip6->ip6_nxt, flow&0xfffff);
}

static void
npf_log_tcp_header(const struct tcphdr *th, char *buf, uint32_t buf_size)
{
	char tcp_flag[BUF_SIZE]; /* 12 flags, 4 chars each */
	tcp_flag[0] = '\0';

	if (th->fin)
		strcat(tcp_flag, "FIN,");
	if (th->syn)
		strcat(tcp_flag, "SYN,");
	if (th->rst)
		strcat(tcp_flag, "RST,");
	if (th->psh)
		strcat(tcp_flag, "PSH,");
	if (th->ack)
		strcat(tcp_flag, "ACK,");
	if (th->urg)
		strcat(tcp_flag, "URG,");
	if (th->th_flags & 0x40)
		strcat(tcp_flag, "ECE,");
	if (th->th_flags & 0x80)
		strcat(tcp_flag, "CWR,");

	/* Note bit 0 of res/x2 is experimental NS - RFC 3540 */
	if (th->th_x2 & 1)
		strcat(tcp_flag, "NS,");

	snprintf(buf, buf_size,
		"tcp=(%sres:%u,doff:%u,seq:%#x,ack:%#x,win:%u,urgp:%u)",
		tcp_flag, th->th_x2 >> 1, th->doff,
		ntohl(th->seq), ntohl(th->ack_seq),
		ntohs(th->window),
		ntohs(th->urg_ptr));
}

static void
npf_log_udp_header(const struct udphdr *uh, char *buf, uint32_t buf_size)
{
	/* print pkt length */
	snprintf(buf, buf_size, "udp=(len:%u)", ntohs(uh->len));
}

static void
npf_log_udplite_header(const struct udphdr *uh, char *buf, uint32_t buf_size)
{
	/* print pkt checksum coverage */
	snprintf(buf, buf_size, "udplite=(cov:%u)", ntohs(uh->len));
}

static void
npf_log_sctp_header(const struct npf_sctp *sh, char *buf, uint32_t buf_size)
{
	/* print pkt verification tag */
	snprintf(buf, buf_size, "sctp=(verif:%#x)", ntohl(sh->sc_verif_tag));
}

static void
npf_log_dccp_header(const struct npf_dccp *dh, char *buf, uint32_t buf_size)
{
	static char const *types[16] = {
		 [0] = "Request",
		 [1] = "Response",
		 [2] = "Data",
		 [3] = "Ack",
		 [4] = "DataAck",
		 [5] = "CloseReq",
		 [6] = "Close",
		 [7] = "Reset",
		 [8] = "Sync",
		 [9] = "SyncAck",
		[10] = "SyncAck",
		[11] = "Listen",
	};

	uint8_t type = (dh->dc_res_type_x >> 1) & 0x0f;

	char const *type_str = types[type];
	if (!type_str)
		type_str = "Reserved";

	snprintf(buf, buf_size, "dccp=(type:%s/%u,doff:%u,ccval:%u,cscov:%u)",
		 type_str, type, dh->dc_doff,
		 dh->dc_cc_cov >> 4, dh->dc_cc_cov & 0x0f);
}

static void
npf_log_icmp_header(const struct icmp *icmphdr,
		    bool err, char *icmp_buf, uint32_t buf_size)
{
	uint8_t type = icmphdr->icmp_type;
	char const *class;

	if (err)
		class = "Err";
	else if (type == ICMP_ECHO)
		class = "EchoRq";
	else if (type == ICMP_ECHOREPLY)
		class = "EchoRp";
	else
		class = "Info";

	snprintf(icmp_buf, buf_size,
		"icmp=(%s,type:%u,code:%u)",
		class, type, icmphdr->icmp_code);
}

static void
npf_log_icmpv6_header(const struct icmp6_hdr *icmp6,
		      char *icmpv6_buf, uint32_t buf_size)
{
	uint8_t type = icmp6->icmp6_type;
	char const *class;

	if (!(type & ICMP6_INFOMSG_MASK))
		class = "Err";
	else if (type == ICMP6_ECHO_REQUEST)
		class = "EchoRq";
	else if (type == ICMP6_ECHO_REPLY)
		class = "EchoRp";
	else
		class = "Info";

	snprintf(icmpv6_buf, buf_size,
		"icmpv6=(%s,type:%u,code:%u)",
		class, type, icmp6->icmp6_code);
}

/*
 * Log action data structure
 */
struct npf_log_data {
	char       *ld_rule_buf;
	uint32_t    ld_type;
	bool        ld_is_l2;
	bool        ld_is_nat44;

	/* The following are only set if rule attach point is an interface */
	bool        ld_has_ether;

	/*
	 * We make a copy of interface name.  This saves passing the name from
	 * the caller context.
	 */
	char        ld_ifname[IFNAMSIZ];
};

/*
 * Log creator
 *
 * Pre-compute as much as possible from the rule and its attach point.
 */
static int
npf_log_create(npf_rule_t *rl, const char *args __unused, void **handle)
{
	struct npf_log_data *ld;
	enum npf_ruleset_type rlset_type;
	const char *rstype_name;

	rlset_type = npf_type_of_ruleset(npf_ruleset(rl));
	rstype_name = npf_get_ruleset_type_log_name(rlset_type);

	if (!rstype_name)
		return -EINVAL;

	ld = calloc(1, sizeof(*ld));
	if (!ld)
		return -ENOMEM;

	const char *rlname = npf_rule_get_name(rl);
	const struct ifnet *ifp;
	int cc;

	ld->ld_type = npf_get_ruleset_type_log_level(rlset_type);
	if (ld->ld_type == 0) {
		free(ld);
		return -EINVAL;
	}

	ld->ld_is_nat44 =
		(rlset_type == NPF_RS_DNAT) || (rlset_type == NPF_RS_SNAT);
	ld->ld_is_l2 =
		(rlset_type == NPF_RS_QOS) ||
		(rlset_type == NPF_RS_BRIDGE) ||
		(rlset_type == NPF_RS_PORTMONITOR_IN) ||
		(rlset_type == NPF_RS_PORTMONITOR_OUT);

	cc = asprintf(&ld->ld_rule_buf, "%s rule %s:%u",
		      rstype_name, rlname ? : "", npf_rule_get_num(rl));
	if (cc < 0) {
		free(ld);
		return -ENOMEM;
	}

	ifp = npf_rule_get_ifp(rl);

	if (ifp) {
		/* Rule attach point is an interface */
		snprintf(ld->ld_ifname, IFNAMSIZ, "%s", ifp->if_name);

		/* Do we want to extract mac addresses from log packet? */
		if (ifp->if_type == IFT_ETHER ||
		    ifp->if_type == IFT_MACVLAN ||
		    ifp->if_type == IFT_BRIDGE ||
		    ifp->if_type == IFT_VXLAN ||
		    ifp->if_type == IFT_L2TPETH)
			ld->ld_has_ether = true;
	}

	*handle = ld;
	return 0;
}

/* Log destructor */
static void
npf_log_destroy(void *handle)
{
	struct npf_log_data *ld = handle;

	if (ld) {
		free(ld->ld_rule_buf);
		free(ld);
	}
}

/*
 * The per packet portion of a log line looks as follows
 * (here split over multiple lines):
 *
 * "proto=(tcp/6) addr=11.0.0.1->12.0.0.1 port=43430->4096 "
 * "macs=a6:e:22:94:94:b6->52:54:0:a7:e9:d0"
 * "v4=(len:52,ttl:64,tos:0,ecn:Not,prot:6)"
 * "tcp=(ACK,res:0,doff:8,seq:0xf1ffdee5,ack:0x262b9403,win:4,urgp:0)"
 */
static void
npf_log_ip_pkt(npf_cache_t *npc, char *out_buf, uint32_t buf_size,
	       char const *macs, bool const icmp_err)
{
	/* Fields extracted from the IP header, excluding addresses */
	int addr_family
		= (npc->npc_alen == sizeof(struct in_addr)) ? AF_INET : AF_INET6;
	char ip_buf[BUF_SIZE];
	if (addr_family == AF_INET) {
		const struct ip *ip = &npc->npc_ip.v4;
		npf_log_ipv4_header(ip, ip_buf, BUF_SIZE);
	} else {
		const struct ip6_hdr *ip6 = &npc->npc_ip.v6;
		npf_log_ipv6_header(ip6, ip_buf, BUF_SIZE);
	}

	/* get ip/ipv6 srcip and dstip */
	char s_ip_buf[INET6_ADDRSTRLEN], d_ip_buf[INET6_ADDRSTRLEN];
	inet_ntop(addr_family, npf_cache_srcip(npc),
			s_ip_buf, INET6_ADDRSTRLEN);
	inet_ntop(addr_family, npf_cache_dstip(npc),
			d_ip_buf, INET6_ADDRSTRLEN);

	/* Extract transport port fields */
	char ports_buf[BUF_SIZE];
	ports_buf[0] = '\0';

	if (npf_iscached(npc, NPC_L4PORTS)) {
		const struct npf_ports *ports = &npc->npc_l4.ports;

		snprintf(ports_buf, sizeof(ports_buf), " port=%u->%u",
			 ntohs(ports->s_port), ntohs(ports->d_port));
	}

	/* Extract terminal protocol info */
	char proto_buf[PRBUF_SIZE];
	proto_buf[0] = '\0';
	char const *prname;

	const void *l4_hdr = &npc->npc_l4;

	const uint8_t proto = npf_cache_ipproto(npc);
	switch (proto) {
	case IPPROTO_TCP:
		prname = "tcp";
		break;
	case IPPROTO_UDP:
		prname = "udp";
		break;
	case IPPROTO_SCTP:
		prname = "sctp";
		break;
	case IPPROTO_DCCP:
		prname = "dccp";
		break;
	case IPPROTO_UDPLITE:
		prname = "udplite";
		break;
	case IPPROTO_ICMP:
		prname = "icmp";
		break;
	case IPPROTO_ICMPV6:
		prname = "icmpv6";
		break;
	default:
		prname = "other";
		break;
	}

	/* If this is an error embedded packet, it may be truncated */
	if (!npf_iscached(npc, NPC_SHORT_ICMP_ERR)) {
		switch (proto) {
		case IPPROTO_TCP:
			npf_log_tcp_header(l4_hdr, proto_buf, PRBUF_SIZE);
			break;
		case IPPROTO_UDP:
			npf_log_udp_header(l4_hdr, proto_buf, PRBUF_SIZE);
			break;
		case IPPROTO_SCTP:
			npf_log_sctp_header(l4_hdr, proto_buf, PRBUF_SIZE);
			break;
		case IPPROTO_DCCP:
			npf_log_dccp_header(l4_hdr, proto_buf, PRBUF_SIZE);
			break;
		case IPPROTO_UDPLITE:
			npf_log_udplite_header(l4_hdr, proto_buf, PRBUF_SIZE);
			break;
		case IPPROTO_ICMP:
			npf_log_icmp_header(l4_hdr, icmp_err,
					    proto_buf, PRBUF_SIZE);
			break;
		case IPPROTO_ICMPV6:
			npf_log_icmpv6_header(l4_hdr, proto_buf, PRBUF_SIZE);
			break;
		}
	}

	snprintf(out_buf, buf_size,
		"proto=(%s/%u) "
		"addr=%s->%s" "%s "
		"%s%s %s",
		prname, proto,
		s_ip_buf, d_ip_buf, ports_buf,
		macs, ip_buf, proto_buf);
}

/*
 * A log line typically looks as follows
 *
 *    "Out:dp0s5 PASS fw rule stPassAllIn:10 "
 *
 * followed by the per packet information as shown above.
 */
void
npf_log_pkt(npf_cache_t *npc, struct rte_mbuf *mbuf, npf_rule_t *rl,
	    int dir)
{
	struct npf_log_data *ld = npf_rule_rproc_handle_for_logger(rl);
	if (!ld)
		return;

	char const *rule = ld->ld_rule_buf;
	uint32_t log_type = ld->ld_type;
	char const *if_name = ld->ld_ifname;
	char const *fate = npf_rule_get_pass(rl) ?
				(ld->ld_is_nat44 ? "TRAN" : "PASS") :
				(ld->ld_is_nat44 ? "EXCL" : "DROP");
	bool const want_mac =
		ld->ld_has_ether && (dir == PFIL_IN || ld->ld_is_l2);

	/* Get the MAC fields */
	char macs[ETH_ADDR_STR_LEN*2 + sizeof("-> ") + sizeof("macs=")];
	char etype[BUF_SIZE];
	macs[0] = '\0';
	etype[0] = '\0';

	if (want_mac)
		npf_log_mac_fields(mbuf, "macs=", macs, "etype=", etype);

	char const *dirn = (dir == PFIL_IN) ? " In" : "Out";

	/* Non IP packets handled here */
	if (!npf_iscached(npc, NPC_IP46)) {
		NPF_LOG(log_type,
			"%s:%s %s %s "
			"%s %s",
			dirn, if_name, fate, rule,
			macs, etype);
		return;
	}

	/* The following packet is IP only */

	bool const icmp_err = npf_iscached(npc, NPC_ICMP_ERR);

	char main_buf[1024];
	main_buf[0] = '\0';

	npf_log_ip_pkt(npc, main_buf, sizeof(main_buf), macs, icmp_err);

	/* The simple IP case, not an ICMP error */
	if (!icmp_err) {
simple_ip:
		NPF_LOG(log_type,
			"%s:%s %s %s "
			"%s",
			dirn, if_name, fate, rule,
			main_buf);

		return;
	}

	/* Process any embedded ICMP error packet */
	char err_buf[1024];
	err_buf[0] = '\0';

	uint16_t ether_proto;
	if (npf_iscached(npc, NPC_IP4))
		ether_proto = htons(ETHER_TYPE_IPv4);
	else
		ether_proto = htons(ETHER_TYPE_IPv6);

	void *n_ptr = dp_pktmbuf_mtol3(mbuf, char *) + npf_cache_hlen(npc);

	/* Find the start of the packet embedded in the ICMP error. */
	n_ptr = nbuf_advance(&mbuf, n_ptr, ICMP_MINLEN);
	if (!n_ptr)
		goto simple_ip;

	/* Init the embedded npc. */
	npf_cache_t enpc;
	npf_cache_init(&enpc);

	/* Inspect the embedded packet. */
	if (!npf_cache_all_at(&enpc, mbuf, n_ptr, ether_proto, true))
		goto simple_ip;

	npf_log_ip_pkt(&enpc, err_buf, sizeof(err_buf), "",
		       npf_iscached(&enpc, NPC_ICMP_ERR));

	NPF_LOG(log_type,
		"%s:%s %s %s "
		"%s >TRIGGER> %s",
		dirn, if_name, fate, rule,
		main_buf, err_buf);
}

static bool
npf_log(npf_cache_t *npc __unused, struct rte_mbuf **nbuf __unused,
	void *arg __unused, npf_session_t *se __unused,
	npf_rproc_result_t *result __unused)
{
	return true;
}

const npf_rproc_ops_t npf_log_ops = {
	.ro_name   = "log",
	.ro_type   = NPF_RPROC_TYPE_ACTION,
	.ro_id     = NPF_RPROC_ID_LOG,
	.ro_bidir  = true,
	.ro_logger = true,
	.ro_ctor   = npf_log_create,
	.ro_dtor   = npf_log_destroy,
	.ro_action = npf_log,
};
