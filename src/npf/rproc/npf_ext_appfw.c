/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Implements the application firewall rproc.
 */

#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <urcu/list.h>

#include "compiler.h"
#include "npf/config/npf_rule_group.h"
#include "npf/dpi/dpi_internal.h"
#include "npf/npf.h"
#include "npf/rproc/npf_rproc.h"
#include "npf/npf_cache.h"
#include "npf/npf_session.h"
#include "util.h"

struct dpi_flow;
struct ifnet;
struct rte_mbuf;

/* Max pkts seen to make a decision */
#define APPFW_MAX_PKTS	10

/* decomposition of an application firewall rule */
struct appfw_rule {
	struct cds_list_head	ar_list;
	const char		*ar_group;	/* Name of this group */
	uint16_t		ar_rule_num;	/* Rule number */
	uint32_t		ar_protocol;	/* Qosmos integer ids */
	uint32_t		ar_name;
	uint64_t		ar_type;
	npf_decision_t		ar_decision;	/* accept/drop */
};

/* rproc handle.  'rules' are maintained as a list. */
struct appfw_handle {
	struct cds_list_head	ah_rules;
	int			ah_parse_rc; /* XXX group walk is a void */
	npf_decision_t		ah_no_match_action; /* no-match-action */
	int			ah_initial_dir;
};

static void appfw_free_handle(struct appfw_handle *ah)
{
	struct appfw_rule *ar;
	struct appfw_rule *tmp;

	cds_list_for_each_entry_safe(ar, tmp, &ah->ah_rules, ar_list) {
		cds_list_del(&ar->ar_list);
		free(ar);
	}
	free(ah);
}

static int appfw_parse_rule_elements(struct appfw_handle *ah,
		struct appfw_rule *ar, const char *r)
{
	char *rule;
	char *t;
	char *t_save;
	char *k;
	char *v;
	char *p;

	if (!r)
		return -ENOENT;

	rule = strdupa(r);
	if (!rule)
		return -ENOMEM;

	while ((t = strtok_r(rule, " ", &t_save)) != NULL) {
		/* parse "k=v" */
		k = t;
		p = strchr(t, '=');
		if (!p)
			return -EINVAL;
		*p = '\0';
		v = ++p;

		/* Convert to Qosmos integers */
		if (!strcmp(k, "protocol"))
			ar->ar_protocol = dpi_app_name_to_id(v) & DPI_APP_MASK;
		else if (!strcmp(k, "type")) {
			uint32_t tmp = dpi_app_type_name_to_id(v);
			ar->ar_type = tmp ? (1L << (tmp - 1)) : 0;
		} else if (!strcmp(k, "name"))
			ar->ar_name = dpi_app_name_to_id(v) & DPI_APP_MASK;
		else if (!strcmp(k, "action")) {
			if (!strcmp(v, "drop"))
				ar->ar_decision = NPF_DECISION_BLOCK;
			else
				ar->ar_decision = NPF_DECISION_PASS;
		} else if (!strcmp(k, "no-match-action"))
			/* If present, this is an accept */
			ah->ah_no_match_action = NPF_DECISION_PASS;
		else
			return -EINVAL;

		rule = NULL;
	}
	return 0;
}

/*
 * Parse an app-fw rule into its DPI components.
 * Note we translate the fields into their Qosmos integer
 * equivalents.
 */
static bool appfw_rule_parse(void *data, struct npf_cfg_rule_walk_state *state)
{
	struct appfw_handle *ah = data;
	struct appfw_rule *ar = malloc_aligned(sizeof(struct appfw_rule));

	ah->ah_parse_rc = -ENOMEM;
	if (!ar)
		goto fail;

	ar->ar_name = DPI_APP_NA;
	ar->ar_protocol = DPI_APP_NA;
	ar->ar_type = 0;
	ar->ar_rule_num = state->index;
	ar->ar_group = state->group;
	ar->ar_decision = NPF_DECISION_UNKNOWN;

	ah->ah_parse_rc = appfw_parse_rule_elements(ah, ar, state->rule);
	if (ah->ah_parse_rc)
		goto fail;

	cds_list_add_tail(&ar->ar_list, &ah->ah_rules);
	return true;
fail:
	free(ar);
	return false;
}

static bool appfw_match_rule(struct appfw_rule *ar, uint32_t proto,
		uint32_t name, uint64_t app_bits)
{
	/*
	 * Discard the engine bits from the app name and proto
	 * so we match nomatter which engine.
	 */
	name &= DPI_APP_MASK;
	proto &= DPI_APP_MASK;

	/* Match most-specific to least-specific */
	if (ar->ar_protocol != DPI_APP_NA && ar->ar_name != DPI_APP_NA) {
		if ((proto == ar->ar_protocol) && (name == ar->ar_name))
			return true;
	}
	if ((ar->ar_name != DPI_APP_NA) && (name == ar->ar_name))
		return true;
	if ((ar->ar_protocol != DPI_APP_NA) && (proto == ar->ar_protocol))
		return true;
	if (ar->ar_type & app_bits)
		return true;
	return false;
}

static uint32_t appfw_pkt_count(struct dpi_flow *df)
{
	uint32_t cnt;
	const struct dpi_flow_stats *ds = dpi_flow_get_stats(df, true);

	cnt = ds->pkts;
	ds = dpi_flow_get_stats(df, false);
	cnt += ds->pkts;

	return cnt;
}

static npf_decision_t appfw_decision(struct appfw_handle *ah,
		struct dpi_flow *dpi_flow)
{
	struct appfw_rule *ar;
	uint32_t proto = dpi_flow_get_app_proto(dpi_flow);

	/* These are terminal values that will not change */
	if (proto == DPI_APP_NA || proto == DPI_APP_ERROR)
		return ah->ah_no_match_action;

	/*
	 * If offloaded, or hit pkt limit, then run the app-fw
	 * rules, as we will shall make the decision.
	 */
	uint32_t pkt_count = appfw_pkt_count(dpi_flow);

	if (dpi_flow_get_offloaded(dpi_flow) || (pkt_count >= APPFW_MAX_PKTS)) {
		uint32_t name = dpi_flow_get_app_name(dpi_flow);
		uint64_t app_bits = dpi_flow_get_app_type(dpi_flow);

		cds_list_for_each_entry(ar, &ah->ah_rules, ar_list) {
			if (appfw_match_rule(ar, proto, name, app_bits))
				return ar->ar_decision;
		}
		return ah->ah_no_match_action;
	}

	return NPF_DECISION_UNKNOWN;
}

/* Save DPI information from the rule for later matching. */
static int
appfw_ctor(npf_rule_t *rl, const char *params, void **handle)
{
	struct appfw_handle *ah;
	char *str;
	char *tmp;
	char *token;
	int rc;

	if (!dpi_init())
		return -ENOMEM;

	/* create the handle for this rproc instance */
	ah = zmalloc_aligned(sizeof(struct appfw_handle));
	if (!ah)
		return -ENOMEM;

	CDS_INIT_LIST_HEAD(&ah->ah_rules);

	/*
	 * Assume we have multiple rule groups assigned to
	 * this rproc, each separated by a ','.
	 */
	rc = -ENOMEM;
	str = strdupa(params);
	if (!str)
		goto fail;

	/*
	 * Set the default for the no match action.
	 * Only if set to 'accept' does this come down.
	 */
	ah->ah_no_match_action = NPF_DECISION_BLOCK;

	while ((token = strtok_r(str, ",", &tmp)) != NULL) {
		npf_cfg_rule_group_walk(NPF_RULE_CLASS_APP_FW, token, ah,
				appfw_rule_parse);
		if (ah->ah_parse_rc) {
			rc = ah->ah_parse_rc;
			goto fail;
		}
		str = NULL;
	}
	ah->ah_initial_dir = npf_rule_get_dir(rl);

	*handle = ah;
	return 0;

fail:
	appfw_free_handle(ah);
	return rc;
}

/* Destroy previously saved DPI information. */
static void
appfw_dtor(void *handle)
{
	appfw_free_handle(handle);
}

/* Perform DPI inspection on this packet.  */
static bool
appfw_action(npf_cache_t *npc, struct rte_mbuf **nbuf, void *arg,
	     npf_session_t *se, npf_rproc_result_t *result)
{
	struct appfw_handle *ah = arg;
	npf_decision_t dec;
	struct dpi_flow *dpi_flow;
	int rc;

	/* Honor blocks (NAT, ALG, etc) */
	if (result->decision == NPF_DECISION_BLOCK)
		return true;

	if (!npf_iscached(npc, NPC_IP46))
		return true;

	/* Only TCP/UDP, ignore everything else */
	switch (npf_cache_ipproto(npc)) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		break;
	default:
		return true;
	}

	/* AppFW is stateful and can't run without a session. */
	if (!se) {
		result->decision = NPF_DECISION_BLOCK;
		return true;
	}

	/* Already reached a final decision? */
	dec = npf_session_get_appfw_decision(se);
	if (dec != NPF_DECISION_UNKNOWN) {
		if (dec != result->decision)
			result->decision = dec;
		return true;
	}

	/*
	 * Get the session dpi struct to determine whether
	 * this is a new flow.  Block on DPI engine errors.
	 */
	dpi_flow = npf_session_get_dpi(se);
	if (!dpi_flow) {
		rc = dpi_session_first_packet(se, npc, *nbuf,
					      ah->ah_initial_dir);
		if (rc)
			goto drop;
		dpi_flow = npf_session_get_dpi(se);
		if (!dpi_flow)
			goto drop;
	} else {
		if (dpi_flow_get_error(dpi_flow))
			goto drop;
	}

	/* Can we get a final decision? */
	dec = appfw_decision(ah, dpi_flow);
	if (dec != NPF_DECISION_UNKNOWN) {
		npf_session_set_appfw_decision(se, dec);
		if (dec != result->decision) {
			result->decision = dec;
			return true;
		}
	}

	return true;
drop:
	result->decision = NPF_DECISION_BLOCK;
	return false;
}

/* DPI RPROC ops. */
const npf_rproc_ops_t npf_appfw_ops = {
	.ro_name   = "app-firewall",
	.ro_type   = NPF_RPROC_TYPE_ACTION,
	.ro_id     = NPF_RPROC_ID_APPFW,
	.ro_bidir  = true,
	.ro_ctor   = appfw_ctor,
	.ro_dtor   = appfw_dtor,
	.ro_action = appfw_action,
};
