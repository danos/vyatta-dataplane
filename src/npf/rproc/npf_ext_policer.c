/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2013-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>
#include <rte_string_fns.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "compiler.h"
#include "npf/npf.h"
#include "npf/config/npf_attach_point.h"
#include "npf/rproc/npf_rproc.h"
#include "npf/npf_ruleset.h"
#include "pktmbuf_internal.h"
#include "qos.h"
#include "util.h"
#include "vplane_log.h"

struct ifnet;

struct policer_cntrs {
	uint64_t excess;
	uint64_t bytes_excess;
	uint64_t pad[6];
};

struct npf_policer {
	uint64_t time;		/* Time of last update */
	uint32_t tc;		/* TC in ms */
	rte_atomic32_t credit;	/* Packets/bytes left to send this interval */
	rte_spinlock_t lock;
	struct policer_cntrs  *cntrs;
	uint32_t rate;		/* Packets/bytes per interval */
	uint32_t burst;		/* burst bytes */
	int16_t overhead;	/* L2 overhead per packet */

	enum {
		ACTION_DROP,
		ACTION_PASS,
		ACTION_MARKDSCP,
		ACTION_MARKPCP,
		ACTION_MARKPCP_INNER,
	} action;
	uint8_t mark_val;
	enum {
		POLICE_BYTES,
		POLICE_PACKETS
	} type;
};

#define	ONE_SECOND		1000
#define	POLICE_PARAMS		8
#define	POLICE_ENABLE_INNER	0x80
#define	POLICE_PCP_MASK		0x07

/* Expect "pps,rate,burst,action" */
static int
npf_policer_create(npf_rule_t *rl, const char *params, void **handle)
{
	struct npf_policer *po;
	uint64_t rate;
	uint64_t pps;
	uint32_t burst;
	uint32_t tcs_per_sec;
	int16_t overhead;
	uint32_t tc;
	union police_cmd {
		struct {
			char *pps;
			char *rate;
			char *burst;
			char *action;
			char *val;
			char *overhead;
			char *tc;
			char *inner;
		};
		char *ptrs[POLICE_PARAMS];
	} police_info;
	int no_vars;
	char *args;

	if (params)
		args = strdupa(params);
	else
		args = strdupa("");

	po = zmalloc_aligned(sizeof(struct npf_policer) +
			     (sizeof(struct policer_cntrs) *
					(get_lcore_max() + 1)));
	if (!po) {
		RTE_LOG(ERR, QOS, "out of memory\n");
		return -ENOMEM;
	}
	po->cntrs = (void *)&po[1];

	rte_spinlock_init(&po->lock);

	/*
	 * The policer can have up to 8 parameters, 7 is ok though
	 * since a value is only passed for marking.
	 */
	no_vars = rte_strsplit(args, strlen(args), police_info.ptrs,
			       POLICE_PARAMS, ',');
	if (no_vars < (POLICE_PARAMS - 1)) {
		RTE_LOG(ERR, QOS,
			"Invalid input argument string for policer\n");
		free(po);
		return -EINVAL;
	}

	errno = 0;
	pps = strtoull(police_info.pps, NULL, 10);
	rate = strtoull(police_info.rate, NULL, 10);
	burst = strtoul(police_info.burst, NULL, 10);
	tc = strtoul(police_info.tc, NULL, 10);
	if (errno != 0 || tc == 0) {
		RTE_LOG(ERR, QOS,
			"Invalid input argument string %s\n", strerror(errno));
		free(po);
		return -EINVAL;
	}

	po->time = soft_ticks;

	if (!pps) {
		if (!strcmp(police_info.overhead, "inherit")) {
			enum npf_attach_type attach_type;
			const char *attach_point;
			int ret;

			ret = npf_rule_get_attach_point(rl, &attach_type,
							&attach_point);
			if (ret || attach_type != NPF_ATTACH_TYPE_QOS) {
				RTE_LOG(ERR, QOS,
					"Invalid attach type\n");
				free(po);
				return -EINVAL;
			}
			po->overhead = qos_get_overhead(attach_point);
		} else {
			overhead = strtol(police_info.overhead, NULL, 10);
			if (errno != 0) {
				RTE_LOG(ERR, QOS,
					"Invalid input argument string %s\n",
					strerror(errno));
				free(po);
				return -EINVAL;
			}
			po->overhead = overhead;
		}

		/*
		 * We set the rate to 20ms intervals by default.
		 * If we can't send a full sized MTU then scale up
		 * the Tc till we can.
		 */
		po->tc = tc;
		tcs_per_sec = ONE_SECOND / tc;
		po->rate = rate / tcs_per_sec;
		if (po->rate < RTE_ETHER_MAX_VLAN_FRAME_LEN) {
			tcs_per_sec = rate / RTE_ETHER_MAX_VLAN_FRAME_LEN;
			if (!tcs_per_sec) {
				tcs_per_sec = 1;
				po->tc = ONE_SECOND;
			} else
				po->tc = ONE_SECOND / tcs_per_sec;

			po->rate = RTE_ETHER_MAX_VLAN_FRAME_LEN;
		}

		po->burst = burst;
		po->type = POLICE_BYTES;
		rte_atomic32_set(&po->credit, (po->rate + po->burst));

		RTE_LOG(DEBUG, QOS,
			"Policer rate %u  tcs_per_sec %d  Tc %d overhead %d\n",
			po->rate, tcs_per_sec, po->tc, po->overhead);

	} else {
		po->rate = pps;
		po->tc = tc;
		po->type = POLICE_PACKETS;
		rte_atomic32_set(&po->credit, po->rate);
	}

	if (strcmp(police_info.action, "pass") == 0)
		po->action = ACTION_PASS;
	else if (strcmp(police_info.action, "drop") == 0)
		po->action = ACTION_DROP;
	else if (strcmp(police_info.action, "markdscp") == 0) {
		po->action = ACTION_MARKDSCP;
		po->mark_val = strtoul(police_info.val, NULL, 10);
	} else if (strcmp(police_info.action, "markpcp") == 0) {
		po->mark_val = strtoul(police_info.val, NULL, 10);
		if (strcmp(police_info.inner, "inner") == 0) {
			po->action = ACTION_MARKPCP_INNER;
			qos_save_mark_v_pol(rl, po);
		} else
			po->action = ACTION_MARKPCP;
	} else {
		RTE_LOG(ERR, QOS, "unknown action %s\n", police_info.action);
		free(po);
		return -EINVAL;
	}

	RTE_LOG(DEBUG, QOS,
		"Policer create (%d%s, %u, %d, %d, %d, %u) %p\n",
		po->rate, (po->type == POLICE_BYTES ? "bytes/tc" : "pkts/tc"),
		po->burst, po->action, po->mark_val, po->overhead, po->tc, po);

	*handle = po;

	return 0;
}

static void
npf_policer_destroy(void *handle)
{
	struct npf_policer *po = handle;

	RTE_LOG(DEBUG, QOS, "Policer destroy %p\n", po);
	free(po);
}

static inline void
update_tokens(uint32_t credit, struct npf_policer *po, const uint64_t ticks)
{
	po->time += ticks;
	if (credit > (po->rate + po->burst))
		credit = po->rate + po->burst;
	rte_atomic32_set(&po->credit, credit);
}

static bool
npf_policer(npf_cache_t *npc, struct rte_mbuf **nbuf, void *arg,
	    npf_session_t *se __unused, npf_rproc_result_t *result)
{
	struct npf_policer	*po = arg;
	int32_t			tok_with_oh;
	uint32_t		tokens;
	unsigned int		core;

	/* Dropped packets do not count against policer */
	if (result->decision == NPF_DECISION_BLOCK)
		return true;

	/* Assume this is a setup problem */
	if (unlikely(po == NULL)) {
		result->decision = NPF_DECISION_BLOCK;
		return true;
	}

	if (po->type == POLICE_BYTES) {
		uint64_t	lapsed;
		unsigned int	intervals;

		rte_spinlock_lock(&po->lock);

		lapsed = soft_ticks - po->time;

		/*
		 * Try to add some tokens
		 * First we check how many intervals have passed since
		 * the last update.
		 */
		intervals = lapsed / po->tc;
		if (intervals > 2) {
			tokens = rte_atomic32_read(&po->credit);
			tokens += intervals * po->rate;
			update_tokens(tokens, po,
				      ((uint64_t)po->tc * intervals));
		/*
		 * This will hopefully be the normal case where we're
		 * processing multiple packets per TC.  In this path
		 * we don't do the complex operations.
		 */
		} else if (lapsed > po->tc) {
			tokens = rte_atomic32_read(&po->credit);
			tokens += po->rate;
			update_tokens(tokens, po, po->tc);
		}

		rte_spinlock_unlock(&po->lock);

		/*
		 * Now we can check the tokens and if we have enough credit
		 * subtract them and let the packet go.  NB for stats we
		 * report L3 bytes sent/dropped, for token bucket we include
		 * the L2 overhead if configured.
		 */
		tokens = rte_pktmbuf_pkt_len(*nbuf) - dp_pktmbuf_l2_len(*nbuf);
		tok_with_oh = tokens + po->overhead;
		if (tok_with_oh < 0)
			tok_with_oh = 1;
		if (tok_with_oh <= po->credit.cnt) {
			rte_atomic32_sub(&po->credit, tok_with_oh);
			return true;
		}
	} else {
		uint64_t tc_lapsed;

		/*
		 * If we have available bandwidth let the packet through.
		 */
		if (po->credit.cnt) {
			rte_atomic32_sub(&po->credit, 1);
			return true;
		}

		/*
		 * Try and replenish tokens
		 */
		rte_spinlock_lock(&po->lock);
		tc_lapsed = po->time + po->tc;
		if (soft_ticks >= tc_lapsed) {
			/*
			 * If more than 2 Tcs have lapsed
			 */
			if (soft_ticks >= (tc_lapsed + po->tc))
				po->time = soft_ticks;
			else
				po->time += po->tc;
			rte_atomic32_set(&po->credit, po->rate);
			rte_spinlock_unlock(&po->lock);
			return true;
		}
		rte_spinlock_unlock(&po->lock);

		tokens = rte_pktmbuf_pkt_len(*nbuf) - dp_pktmbuf_l2_len(*nbuf);
	}

	core = dp_lcore_id();
	po->cntrs[core].excess++;
	po->cntrs[core].bytes_excess += tokens;

	/* Over limit */
	switch (po->action) {
	case ACTION_PASS:
		break;
	case ACTION_DROP:
		result->decision = NPF_DECISION_BLOCK;
		break;
	case ACTION_MARKDSCP:
		npf_remark_dscp(npc, nbuf, po->mark_val, result);
		break;
	case ACTION_MARKPCP:
		pktmbuf_set_vlan_pcp(*nbuf, po->mark_val);
		break;
	case ACTION_MARKPCP_INNER:
		pktmbuf_set_vlan_pcp(*nbuf, (po->mark_val & POLICE_PCP_MASK));
		if (po->mark_val & POLICE_ENABLE_INNER)
			markpcp_inner(*nbuf, (po->mark_val & POLICE_PCP_MASK));
		break;
	}

	return true;
}

static void
policer_get_stats(void *arg, unsigned int *excess,
		  unsigned int *excess_bytes)
{
	struct npf_policer *po = arg;
	unsigned int id;

	*excess = *excess_bytes = 0;

	FOREACH_DP_LCORE(id) {
		*excess += po->cntrs[id].excess;
		*excess_bytes += po->cntrs[id].bytes_excess;
	}
}

void policer_show(json_writer_t *wr, void *arg)
{
	struct npf_policer *po = arg;
	unsigned int excess, excess_b;
	uint32_t credit;

	policer_get_stats(po, &excess, &excess_b);
	if (!excess)
		return;

	credit = rte_atomic32_read(&po->credit);
	jsonw_start_object(wr);
	jsonw_uint_field(wr, "time", po->time);
	jsonw_uint_field(wr, "tc", po->tc);
	jsonw_uint_field(wr, "credit", credit);
	jsonw_uint_field(wr, "rate", po->rate);
	jsonw_uint_field(wr, "burst", po->burst);
	jsonw_int_field(wr, "overhead", po->overhead);
	jsonw_int_field(wr, "action", po->action);
	jsonw_int_field(wr, "mark_val", po->mark_val);
	jsonw_int_field(wr, "loc", po->lock.locked);
	jsonw_uint_field(wr, "soft_ticks", soft_ticks);
	jsonw_uint_field(wr, "lapsed", (soft_ticks - po->time));
	jsonw_end_object(wr);
}

static void
npf_policer_clear_stats(void *arg)
{
	struct npf_policer *po = arg;
	unsigned int id;

	FOREACH_DP_LCORE(id) {
		po->cntrs[id].excess = 0;
		po->cntrs[id].bytes_excess = 0;
	}
}

void police_enable_inner_marking(void *arg)
{
	struct npf_policer *policer = arg;
	policer->mark_val |= POLICE_ENABLE_INNER;
	RTE_LOG(DEBUG, QOS, "markpcp inner via policer %p enabled\n", arg);
}

void police_disable_inner_marking(void *arg)
{
	struct npf_policer *policer = arg;
	policer->mark_val &= ~POLICE_ENABLE_INNER;
	RTE_LOG(DEBUG, QOS, "markpcp inner via policer %p disabled\n", arg);
}

/*
 * Policer rproc JSON
 */
void
npf_policer_json(json_writer_t *json,
		 npf_rule_t *rl __unused,
		 const char *params __unused,
		 void *handle)
{
	if (!handle)
		return;

	struct npf_policer *po = handle;

	unsigned int excess = 0, excess_bytes = 0;
	unsigned int id;

	FOREACH_DP_LCORE(id) {
		excess += po->cntrs[id].excess;
		excess_bytes += po->cntrs[id].bytes_excess;
	}

	jsonw_uint_field(json, "exceed-packets", excess);
	jsonw_uint_field(json, "exceed-bytes", excess_bytes);
}

const npf_rproc_ops_t npf_policer_ops = {
	.ro_name   = "policer",
	.ro_type   = NPF_RPROC_TYPE_ACTION,
	.ro_id     = NPF_RPROC_ID_POLICER,
	.ro_bidir  = false,
	.ro_ctor   = npf_policer_create,
	.ro_dtor   = npf_policer_destroy,
	.ro_action = npf_policer,
	.ro_json   = npf_policer_json,
	.ro_clear_stats = npf_policer_clear_stats,
};
