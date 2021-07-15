/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "compiler.h"
#include "npf/npf.h"
#include "npf/dpi/dpi_internal.h"
#include "npf/rproc/npf_rproc.h"
#include "npf/npf_cache.h"
#include "npf/npf_session.h"
#include "util.h"

struct ifnet;
struct rte_mbuf;

/* DPI information to be saved for later. */
struct dpi_info {
	uint32_t app_id;
	uint32_t app_type;
	uint8_t engine_id;
};

/* Save DPI information from the rule for later matching. */
static int
dpi_ctor(npf_rule_t *rl __unused, const char *params, void **handle)
{
	/*
	 * Application name and type are received from the config layer as
	 * strings, because the config layer doesn't have access to the C APIs.
	 *
	 * Here we convert the strings to IDs and save them for later matching.
	 */

	/*
	 * The name and type are comma-separated,
	 * so we find the comma at position X,
	 * overwrite it with a '\0'
	 * and get the type string at X+1.
	 */
	char *param_str = strdup(params);
	if (!param_str)
		return -ENOMEM;

	char *name = strchr(param_str, ',');
	if (!name) {
		free(param_str);
		return -EINVAL;
	}
	*name = '\0';
	name++;

	char *type = strchr(name, ',');
	if (!type) {
		free(param_str);
		return -EINVAL;
	}
	*type = '\0';
	type++;

	uint8_t engine_id = dpi_engine_name_to_id(param_str);

	/* Ensure the engine is enabled */
	int ret = dpi_init(engine_id);
	if (ret != 0) {
		free(param_str);
		return ret;
	}

	/* Memory to store the DPI info. */
	struct dpi_info *dpi_info =
		zmalloc_aligned(sizeof(struct dpi_info));

	if (!dpi_info) {
		free(param_str);
		return -ENOMEM;
	}

	dpi_info->engine_id = engine_id;
	dpi_info->app_id = dpi_app_name_to_id(engine_id, name) & DPI_APP_MASK;
	dpi_info->app_type = dpi_app_type_name_to_id(engine_id, type);

	*handle = dpi_info;
	free(param_str);

	dpi_refcount_inc(engine_id);

	return 0;
}

/* Destroy previously saved DPI information. */
static void
dpi_dtor(void *handle)
{
	if (!handle)
		return;

	struct dpi_info *dpi_info = handle;
	uint8_t engine_id = dpi_info->engine_id;

	if (dpi_refcount_dec(engine_id) == 0)
		dpi_terminate(engine_id);

	free(handle);
}

/*
 * Drop the packet if the match function failed.
 *
 * Else an attacker could overwhelm the DPI cache
 * before sending traffic which would bypass the expected DPI rules.
 */
static bool
dpi_action(npf_cache_t *npc, struct rte_mbuf **nbuf __unused,
	   void *arg __unused, npf_session_t *se __unused,
	   npf_rproc_result_t *result)
{
	if (npf_iscached(npc, NPC_DROP)) {
		npc->npc_info &= ~NPC_DROP;	// reset flag for next packet
		/*
		 * We're bombing out due to a DPI failure,
		 * so we don't know whether or not the packet matched the rule.
		 * So drop the packet and don't account it against this rule.
		 */
		result->decision = NPF_DECISION_BLOCK_UNACCOUNTED;
	}

	return true; // continue rproc processing
}

/* Match the mbuf against the rule. */
static bool
dpi_match(npf_cache_t *npc, struct rte_mbuf *mbuf, const struct ifnet *ifp,
	  int dir, npf_session_t *se, void *arg)
{
	/* Get the DPI info that we stashed away when the rule was created. */
	struct dpi_info *dpi_info = arg;

	/*
	 * The rule says to match DPI info, but the details are not available.
	 * "This should never happen", but drop the traffic if it does.
	 */
	if (!dpi_info)
		goto drop;

	/* We only have sessions for IP packets */
	if (!npf_iscached(npc, NPC_IP46))
		return false;

	/* We will only do DPI for TCP and UDP */
	const uint8_t ipproto = npf_cache_ipproto(npc);
	if (ipproto != IPPROTO_TCP && ipproto != IPPROTO_UDP)
		return false;

	/*
	 * Ensure we have an active session.
	 * This could find one previously created by the firewall/NAT,
	 * or create and activate one here.
	 */
	if (!se) {
		int error = 0;
		se = npf_session_find_or_create(npc, mbuf, ifp, dir, &error);
		if (!se || error)
			goto drop;
	}

	/* Find or attach the DPI flow info. Do first packet inspection */
	struct dpi_flow *dpi_flow = npf_session_get_dpi(se);
	if (!dpi_flow) {
#ifdef USE_NDPI
		uint8_t engines[] = {IANA_USER, IANA_NDPI};
		size_t engines_len = 2;
#else
		uint8_t engines[] = {IANA_USER};
		size_t engines_len = 1;
#endif /* USER_NDPI */
		int error = dpi_session_first_packet(se, npc, mbuf,
				dir, engines_len, engines);
		if (error)
			goto drop;
		dpi_flow = npf_session_get_dpi(se);
		if (!dpi_flow)
			goto drop;
	}

	/* If we have a problem with the engine, drop the packet flow */
	if (dpi_flow_get_error(dpi_flow))
		goto drop;

	/* Extract the previously cached result */
	const uint32_t app_id = dpi_flow_get_app_id(dpi_info->engine_id,
						    dpi_flow);
	uint32_t app_type = dpi_flow_get_app_type(dpi_info->engine_id,
						  dpi_flow);

	/*
	 * App ID only applies if set.
	 */
	bool r = (dpi_info->app_id &&
			(dpi_info->app_id == (app_id & DPI_APP_MASK))) ||
		 (dpi_info->app_type &&
			(dpi_info->app_type == app_type));

	return r;

drop:
	/*
	 * Force the packet to be dropped:
	 * Indicate that packet matches, so we get to the proc.
	 * But set the drop flag so the packet is dropped when we get there.
	 */
	npc->npc_info |= NPC_DROP;
	return true;
}

/* DPI RPROC ops. */
const npf_rproc_ops_t npf_dpi_ops = {
	.ro_name   = "dpi",
	.ro_type   = NPF_RPROC_TYPE_MATCH,
	.ro_id     = NPF_RPROC_ID_DPI,
	.ro_bidir  = true,
	.ro_ctor   = dpi_ctor,
	.ro_dtor   = dpi_dtor,
	.ro_action = dpi_action,
	.ro_match  = dpi_match,
};
