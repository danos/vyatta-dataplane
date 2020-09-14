/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2013-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <rte_branch_prediction.h>
#include <rte_log.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#include "compiler.h"
#include "npf/npf.h"
#include "npf/npf_mbuf.h"
#include "npf/rproc/npf_rproc.h"
#include "npf/npf_ruleset.h"
#include "pktmbuf_internal.h"
#include "util.h"
#include "vplane_log.h"
#include "qos.h"
#include "ether.h"
#include <rte_string_fns.h>

struct ifnet;
struct rte_mbuf;

/*
 * Tag pattern stored within the argument 'pointer'.
 * The values are arbitrary,  yet distinct.
 */
#define MARK_TAG_MASK		0x00ffff00
#define MARK_TAG_DSCP		0x00D5C900
#define MARK_TAG_PCP		0x009C9700
#define MARK_PCP_INNER_REQ	0x10
#define MARK_PCP_INNER_ACK	0x20
#define MARK_PCP_INNER		(MARK_PCP_INNER_REQ|MARK_PCP_INNER_ACK)

/*
 * The actual real value portion of the tagged pointer.
 */
#define MARK_DSCP_MASK	0x3f
#define MARK_PCP_MASK	0x7
#define MARK_PCP_PARAMS	2

/*
 * Extract the parameter value,  and store it in a tagged pointer.
 */
static int
npf_mark_arg_create(npf_rule_t *rl, const char *params, uint32_t tag,
		    uint32_t max, void **handle)
{
	uintptr_t tagged_val = 0;

	if (tag == MARK_TAG_PCP) {
		union mark_cmd {
			struct {
				char *val;
				char *inner;
			};
			char *ptrs[MARK_PCP_PARAMS];
		} mark_info;
		int no_vars;
		int mark_inner;
		char *args;

		if (params)
			args = strdupa(params);
		else
			args = strdupa("");

		no_vars = rte_strsplit(args, strlen(args), mark_info.ptrs,
				       MARK_PCP_PARAMS, ',');
		if (no_vars < (MARK_PCP_PARAMS - 1)) {
			RTE_LOG(ERR, QOS,
				"Invalid input argument string for markpcp\n");
			return -EINVAL;
		}

		errno = 0;
		tagged_val = strtoull(mark_info.val, NULL, 10);
		mark_inner = !strcmp(mark_info.inner, "inner");
		if (errno != 0) {
			RTE_LOG(ERR, QOS,
				"Invalid input argument string %s\n",
				strerror(errno));
			return -EINVAL;
		}

		/* If it's a QinQ packet also mark the inner header */
		if (mark_inner) {
			enum npf_attach_type attach_type;
			const char *attach_point;
			int ret;
			struct ifnet *ifp;
			uint16_t vlan_id;
			uint16_t no_qinqs = 0;

			ret = npf_rule_get_attach_point(rl, &attach_type,
							&attach_point);
			if (ret || attach_type != NPF_ATTACH_TYPE_QOS) {
				RTE_LOG(ERR, QOS,
					"Invalid attach type\n");
				return -EINVAL;
			}

			/*
			 * We mark the REQ bit and check to see if the vlan
			 * interface has been created. It may not be created
			 * till later so we only set the ACK bit once verified.
			 */
			tagged_val |= MARK_PCP_INNER_REQ;

			ifp = qos_get_vlan_ifp(attach_point, &vlan_id);
			if (ifp && ifp->qinq_inner) {
				struct ifnet *pifp;

				tagged_val |= MARK_PCP_INNER_ACK;
				pifp = ifp->if_parent;
				if (pifp && pifp->if_parent)
					no_qinqs =
						pifp->if_parent->qinq_vif_cnt;
			}

			/*
			 * We'll store the requests on the subport.
			 * There'll be a callback from the vlan create
			 * code to qos which will complete the ACK
			 * which starts the inner marking if not already
			 * setup.
			 *
			 * Alternatively the inner vlan may be removed so
			 * we may need to stop the marking.
			 */
			qos_save_mark_req(attach_point, MARK, no_qinqs, handle);
		}
	} else if (params)
		tagged_val = strtoull(params, NULL, 10);

	/*
	 * Ensure that an invalid value will have no effect.
	 */
	if (tagged_val <= max)
		tagged_val |= tag;
	else {
		RTE_LOG(ERR, FIREWALL,
			"Invalid mark param %s; for tag=%x, max=%u\n",
			params, tag, max);
		return -EINVAL;
	}

	*handle = (void *)tagged_val;
	return 0;
}

void npf_remark_dscp(npf_cache_t *npc, struct rte_mbuf **m, uint8_t n,
		     npf_rproc_result_t *result)
{
	if (unlikely(!npf_iscached(npc, NPC_IP46)))
		return;

	if (unlikely(npf_prepare_for_l4_header_change(m, npc) != 0)) {
		if (net_ratelimit())
			RTE_LOG(ERR, FIREWALL,
				"Resource error remarking DSCP to %u\n", n),
		result->decision = NPF_DECISION_BLOCK;
		return;
	}

	struct rte_mbuf *mseg = *m;
	void *p = npf_iphdr(mseg);

	if (npf_iscached(npc, NPC_IP4)) {
		struct ip *ip = &npc->npc_ip.v4;
		uint8_t dscp = n << 2;
		uint8_t old_tos = ip->ip_tos;

		ip->ip_tos = (old_tos & 0x03) | dscp;

		if (ip->ip_tos != old_tos) {
			u_int offby = offsetof(struct ip, ip_tos);

			/* Advance to the TOS and rewrite it. */
			nbuf_advstore(&mseg, &p, offby, sizeof(ip->ip_tos),
				      &ip->ip_tos);

			npf_update_v4_cksum(npc, mseg, old_tos << 8,
					    ip->ip_tos << 8);
		}
	} else if (npf_iscached(npc, NPC_IP6)) {
		struct ip6_hdr *ip6 = &npc->npc_ip.v6;
		uint32_t offby = offsetof(struct ip6_hdr, ip6_flow);
		uint32_t flow = ntohl(ip6->ip6_flow);
		uint32_t dscpv6 = 0x0FC00000 & (n << 22);

		flow = flow & 0xF03FFFFF;
		ip6->ip6_flow = htonl(flow | dscpv6);
		nbuf_advstore(&mseg, &p, offby, sizeof(uint32_t),
			      &ip6->ip6_flow);
	}
}

static bool
npf_markdscp(npf_cache_t *npc, struct rte_mbuf **m, void *arg,
	     npf_session_t *se __unused, npf_rproc_result_t *result)
{
	if (result->decision == NPF_DECISION_BLOCK)
		return true;

	/* Ensure a parameter was set */
	uintptr_t tagged_val = (uintptr_t)arg;
	if ((tagged_val & MARK_TAG_MASK) != MARK_TAG_DSCP) {
		RTE_LOG(ERR, FIREWALL, "MARK DSCP value missing or invalid\n");
		return true;
	}

	npf_remark_dscp(npc, m, tagged_val & MARK_DSCP_MASK, result);
	return true;
}

static int
npf_markdscp_create(npf_rule_t *rl, const char *params, void **handle)
{
	return npf_mark_arg_create(rl, params, MARK_TAG_DSCP, MARK_DSCP_MASK,
				   handle);
}

const npf_rproc_ops_t npf_markdscp_ops = {
	.ro_name   = "markdscp",
	.ro_type   = NPF_RPROC_TYPE_ACTION,
	.ro_id     = NPF_RPROC_ID_MARKDSCP,
	.ro_bidir  = false,
	.ro_ctor   = npf_markdscp_create,
	.ro_action = npf_markdscp,
};

void markpcp_inner(struct rte_mbuf *m, uint16_t val)
{
	struct ether_vlan_hdr *vhdr;
	uint16_t pcp;

	vhdr = rte_pktmbuf_mtod(m, struct ether_vlan_hdr *);

	pcp = val << VLAN_PCP_SHIFT;
	/* Clear PCP bits incase mark has already set them */
	vhdr->vh.vlan_tci &= htons(VLAN_DE_VID_MASK);
	vhdr->vh.vlan_tci |= htons(pcp);
}

void mark_enable_inner_marking(void **markpcp_handle)
{
	uintptr_t tagged_val = (uintptr_t)*markpcp_handle;

	tagged_val |= MARK_PCP_INNER_ACK;
	RTE_LOG(DEBUG, QOS, "Enabling mark val %"PRIxPTR"\n", tagged_val);
	*markpcp_handle = (void *)tagged_val;
}

void mark_disable_inner_marking(void **markpcp_handle)
{
	uintptr_t tagged_val = (uintptr_t)*markpcp_handle;

	tagged_val &= ~MARK_PCP_INNER_ACK;
	RTE_LOG(DEBUG, QOS, "Disabling mark val %"PRIxPTR"\n", tagged_val);
	*markpcp_handle = (void *)tagged_val;
}

bool mark_inner(uintptr_t mark)
{
	return (mark & MARK_PCP_INNER);
}

bool mark_inner_state(uintptr_t mark)
{
	return ((mark & MARK_PCP_INNER) == MARK_PCP_INNER);
}

static bool
npf_markpcp(npf_cache_t *npc __unused, struct rte_mbuf **m, void *arg,
	    npf_session_t *se __unused, npf_rproc_result_t *result)
{
	if (result->decision == NPF_DECISION_BLOCK)
		return true;

	/* Ensure a parameter was set */
	uintptr_t tagged_val = (uintptr_t)arg;
	if ((tagged_val & MARK_TAG_MASK) != MARK_TAG_PCP) {
		RTE_LOG(ERR, FIREWALL, "MARK PCP value missing or invalid\n");
		return true;
	}

	pktmbuf_set_vlan_pcp(*m, tagged_val & MARK_PCP_MASK);

	/*
	 * If it's QinQ check to see if we're also marking the inner
	 * header and whether it's there
	 */
	if ((tagged_val & MARK_PCP_INNER) != MARK_PCP_INNER)
		return true;

	markpcp_inner(*m, (tagged_val & MARK_PCP_MASK));

	return true;
}

static int
npf_markpcp_create(npf_rule_t *rl, const char *params, void **handle)
{
	return npf_mark_arg_create(rl, params, MARK_TAG_PCP,
				   (MARK_PCP_MASK|MARK_PCP_INNER), handle);
}

/*
 * Mark PCP rproc JSON
 */
void
npf_markpcp_json(json_writer_t *json,
		 npf_rule_t *rl __unused,
		 const char *params __unused,
		 void *markpcp_handle)
{
	uintptr_t handle = (uintptr_t)markpcp_handle;

	bool type_inner = mark_inner(handle);
	bool type_state = false;

	if (type_inner)
		type_state = mark_inner_state(handle);

	jsonw_string_field(json, "type", type_inner ? "inner" : "outer");
	jsonw_string_field(json, "state", type_state ? "active" : "inactive");
}

const npf_rproc_ops_t npf_markpcp_ops = {
	.ro_name   = "markpcp",
	.ro_type   = NPF_RPROC_TYPE_ACTION,
	.ro_id     = NPF_RPROC_ID_MARKPCP,
	.ro_bidir  = false,
	.ro_ctor   = npf_markpcp_create,
	.ro_action = npf_markpcp,
	.ro_json   = npf_markpcp_json,
};
