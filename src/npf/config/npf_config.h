/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_CONFIG_H
#define NPF_CONFIG_H

#include <rte_branch_prediction.h>
#include <stdbool.h>
#include <stdio.h>
#include <urcu.h>

#include "npf/config/npf_attach_point.h"
#include "npf/config/npf_ruleset_type.h"
#include "npf/config/npf_rule_group.h"
#include "npf/npf_ruleset.h"
#include "urcu.h"

/* Forward Declarations */
typedef uint16_t rule_no_t;
typedef struct npf_ruleset npf_ruleset_t;

/*
 * NB: only npf_config.c should access this structure directly - other
 * files must use the APIs given in this file to access relevant fields
 * in it.
 */
struct npf_config {
	unsigned long		nc_active_flags;
	npf_ruleset_t		*nc_rulesets[NPF_RS_TYPE_COUNT];

	unsigned long		nc_stateful;
	bool			nc_dirty_rulesets[NPF_RS_TYPE_COUNT];
	bool			nc_attached;
	enum npf_attach_type	nc_attach_type;
	const char		*nc_attach_point;
	struct rcu_head		nc_rcu;
};

#define BIT(x)	(1<<(x))

/**
 * Bits used with npf_active() to check if a ruleset is active.
 *
 * There are some combination entries where commonly used together.
 */
enum npf_active_bits {
	NPF_ACL_IN =		BIT(NPF_RS_ACL_IN),
	NPF_ACL_OUT =		BIT(NPF_RS_ACL_OUT),
	NPF_FW_IN =		BIT(NPF_RS_FW_IN),
	NPF_FW_OUT =		BIT(NPF_RS_FW_OUT),
	NPF_DNAT =		BIT(NPF_RS_DNAT),
	NPF_SNAT =		BIT(NPF_RS_SNAT),
	NPF_ZONE =		BIT(NPF_RS_ZONE),
	NPF_LOCAL =		BIT(NPF_RS_LOCAL),
	NPF_ORIGINATE =		BIT(NPF_RS_ORIGINATE),
	NPF_BRIDGE =		BIT(NPF_RS_BRIDGE),
	NPF_IPSEC =		BIT(NPF_RS_IPSEC),
	NPF_PBR =		BIT(NPF_RS_PBR),
	NPF_CUSTOM_TIMEOUT =	BIT(NPF_RS_CUSTOM_TIMEOUT),
	NPF_NAT64 =		BIT(NPF_RS_NAT64),
	NPF_NAT46 =		BIT(NPF_RS_NAT46),
	NPF_QOS =		BIT(NPF_RS_QOS),
	NPF_SESSION_RPROC =	BIT(NPF_RS_SESSION_RPROC),
	NPF_PORTMONITOR_IN =	BIT(NPF_RS_PORTMONITOR_IN),
	NPF_PORTMONITOR_OUT =	BIT(NPF_RS_PORTMONITOR_OUT),
	NPF_APPLICATION	=	BIT(NPF_RS_APPLICATION),
	NPF_NPTV6_IN =		BIT(NPF_RS_NPTV6_IN),
	NPF_NPTV6_OUT =		BIT(NPF_RS_NPTV6_OUT),

	/* The following are state bits not corresponding to rulesets */
	NPF_FW_STATE_IN =	BIT(NPF_RS_TYPE_COUNT+1),
	NPF_FW_STATE_OUT =	BIT(NPF_RS_TYPE_COUNT+2),
	NPF_IF_SESSION =	BIT(NPF_RS_TYPE_COUNT+3),

	/* All causes for calling npf_hook_track() */
	NPF_V4_TRACK_IN =	NPF_FW_STATE_OUT | NPF_FW_IN | NPF_DNAT,
	NPF_V4_TRACK_OUT =	NPF_FW_STATE_IN |
					NPF_FW_OUT | NPF_ZONE | NPF_SNAT,
	NPF_V6_TRACK_IN =	NPF_FW_STATE_OUT | NPF_FW_IN,
	NPF_V6_TRACK_OUT =	NPF_FW_STATE_IN |
					NPF_FW_OUT | NPF_ZONE,
};

#define NAT64_OR_NAT46(_eth_type) ((_eth_type == htons(RTE_ETHER_TYPE_IPV4)) ? \
				   NPF_NAT46 : NPF_NAT64)

/**
 * Free the npf config attach point.
 *
 * @param npf_conf Pointer to structure registered earlier with
 *	  npf_attpt_item_set_up(), which is used to point to rulesets when
 *	  they are in use. This is associated with the attach point.
 */
void npf_config_release(struct npf_config *npf_conf);

/**
 * Initialise the configuration code.
 *
 * This should be called a single time, before any other APIs in this file
 * are called.
 */
void npf_config_init(void);

/**
 * This is called to check whether certain ruleset types or other npf
 * features are active on an attach point.
 *
 * @param npf_conf Pointer to structure registered earlier with
 *	  npf_attpt_item_set_up(), which is used to point to rulesets when
 *	  they are in use. This is associated with the attach point.
 * @param bitmask The bits representing the ruleset types or bits associated
 *        with other npf features to be checked.
 *        For rulesets they should be values from *enum npf_active* which
 *        represent values of type *enum ruleset_type* converted into bit
 *        positions.
 *
 * @return True if the features are active or false if they are not active
 *
 * Example:
 *   if (npf_active(ifp->npf_config, NPF_FW | NPF_NAT)) ...
 *
 */
static inline bool npf_active(const struct npf_config *npf_conf,
			      unsigned long bitmask)
{
	/*
	 * Whether this is true or not depends on configuration and thus
	 * can't actually be predicted at compile time. However, it
	 * benefits performance with NPF configuration to force this
	 * condition to be considered unlikely without harming performance
	 * with no NPF configuration.
	 */
	if (unlikely(npf_conf == NULL))
		return false;

	if (npf_conf->nc_active_flags & bitmask)
		return true;

	return false;
}

/**
 * This is called to get a pointer to the structure representing a ruleset
 * of a certain ruleset type.
 *
 * @param npf_conf Pointer to structure registered earlier with
 *	  npf_attpt_item_set_up(), which is used to point to rulesets when
 *	  they are in use. This is associated with the attach point.
 * @param ruleset_type This is the ruleset type to get the rules from.
 *
 * @return A pointer to the npf_ruleset_t which holds the ruleset of the
 *         requested type being used on the attach point. If this is NULL
 *	   then it means there are no rules of that type active.
 */
static inline const npf_ruleset_t *npf_get_ruleset(
	const struct npf_config *npf_conf, enum npf_ruleset_type ruleset_type)
{
	if (likely(npf_conf == NULL))
		return NULL;

	return rcu_dereference(npf_conf->nc_rulesets[ruleset_type]);
}

/**
 * This is called to recreate rulesets for all attachment points
 * which have had config changes made to their rulesets.
 *
 */
void npf_cfg_commit_all(void);

/*
 * This dirties rulesets matching the specified selector.
 *
 * @param sel This selects the attachment point and rulesets to dirty.
 * @return Returns 0 on success, or negative errno on failure.
 */
int npf_dirty_selected_rulesets(struct ruleset_select *sel);

/*
 * This shows the active rulesets using the specified selector.
 *
 * @param fp This is the file pointer to write results to. They will be
 *	    written in JSON format.
 * @param sel This selects the attachment point and rulesets to show.
 * @return Returns 0 on success, or negative errno on failure.
 */
int npf_show_selected_rulesets(FILE *fp, struct ruleset_select *sel);

/*
 * This clears statistics of the active rulesets using the specified selector.
 *
 * @param sel This selects the attachment point and rulesets to clear.
 * @return Returns 0 on success, or negative errno on failure.
 */
int npf_clear_selected_rulesets(struct ruleset_select *sel);

#include "json_writer.h"

void npf_show_attach_point_rulesets(json_writer_t *json,
				    struct npf_attpt_item *ap,
				    unsigned long rulesets);

#endif /* NPF_CONFIG_H */
