/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h> /* htons */
#include <netinet/icmp6.h>

#include "compiler.h"
#include "util.h"
#include "fal.h"
#include "if_var.h"
#include "netinet6/in6_var.h"
#include "npf/config/gpc_db_query.h"
#include "npf/config/gpc_cntr_query.h"
#include "npf/config/pmf_rule.h"
#include "npf/config/pmf_hw.h"
#include "vplane_log.h"
#include "vplane_debug.h"

#define ACL_LOG(ok, t, ...) \
	rte_log((ok) ? RTE_LOG_DEBUG : RTE_LOG_ERR, \
		RTE_LOGTYPE_ ## t, # t ": " __VA_ARGS__)

static bool pmf_hw_commit_needed;

/* ---- */

bool
pmf_hw_rule_add(struct gpc_rule *gprl)
{
	struct gpc_group *gprg = gpc_rule_get_group(gprl);
	struct gpc_rlset *gprs = gpc_group_get_rlset(gprg);
	char const *ifname = gpc_rlset_get_ifname(gprs);
	struct gpc_cntr *gprk = gpc_rule_get_cntr(gprl);
	uintptr_t ctrobj = gpc_cntr_get_objid(gprk);
	uintptr_t grpobj = gpc_group_get_objid(gprg);
	bool grp_was_created = (grpobj != FAL_NULL_OBJECT_ID);
	uintptr_t rlobj = FAL_NULL_OBJECT_ID;
	uint16_t index = gpc_rule_get_index(gprl);
	bool ingress = gpc_group_is_ingress(gprg);
	bool is_v6 = gpc_group_is_v6(gprg);
	char const *rgname = gpc_group_get_name(gprg);
	struct pmf_rule *rule = gpc_rule_get_rule(gprl);
	uint32_t summary = rule->pp_summary;
	bool ok = true;
	char const *ok_str = "SK";
	enum gpc_feature feat = gpc_group_get_feature(gprg);
	char const *feat_str = gpc_feature_get_name(feat);
	int rc = 0; /* Success */

	/* Nothing to do if no FAL object - e.g. vrouter */
	if (!grp_was_created)
		goto log_add;

#define FAL_ENTRY_FIX_FIELDS 3
#define FAL_ENTRY_VAR_FIELDS (5 + 7 + 5)
#define FAL_ENTRY_TOT_FIELDS (FAL_ENTRY_FIX_FIELDS + FAL_ENTRY_VAR_FIELDS)
	struct fal_attribute_t ent_attrs[FAL_ENTRY_TOT_FIELDS] = {
		[0] = {
			.id = FAL_ACL_ENTRY_ATTR_TABLE_ID,
			.value.objid = grpobj,
		},
		[1] = {
			.id = FAL_ACL_ENTRY_ATTR_RULE_NUMBER,
			.value.u32 = index,
		},
		[2] = {
			.id = FAL_ACL_ENTRY_ATTR_ADMIN_STATE,
			.value.booldata = true,
		},
	};
	unsigned int nattr = FAL_ENTRY_FIX_FIELDS;

	/* Actions */
	uint32_t num_actions
		= 1
		+ !!(summary & (PMF_RAS_DROP|PMF_RAS_PASS))
		+ !!(summary & PMF_RAS_COUNT_REF)
		+ !!(summary & PMF_RAS_QOS_HW_DESIG)
		+ !!(summary & PMF_RAS_QOS_COLOUR)
		+ !!(summary & PMF_RAS_QOS_POLICE);
	struct fal_acl_action_data_t *actions
		= calloc(1, num_actions * sizeof(*actions));
	if (!actions)
		return false;

	/* Encode 'pass' or 'drop' */
	num_actions = 0;
	if (summary & (PMF_RAS_DROP|PMF_RAS_PASS)) {
		ent_attrs[nattr].id = FAL_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION;
		ent_attrs[nattr].value.aclaction = &actions[num_actions];

		bool is_drop = summary & PMF_RAS_DROP;

		actions[num_actions].enable = true;
		actions[num_actions].parameter.s32
			= is_drop ? FAL_PACKET_ACTION_DROP
				  : FAL_PACKET_ACTION_FORWARD;

		summary &= ~(PMF_RAS_DROP|PMF_RAS_PASS);
		++nattr;
		++num_actions;
	}

	/* Encode use of a rule counter */
	if (ctrobj != FAL_NULL_OBJECT_ID) {
		ent_attrs[nattr].id = FAL_ACL_ENTRY_ATTR_ACTION_COUNTER;
		ent_attrs[nattr].value.aclaction = &actions[num_actions];

		actions[num_actions].enable = true;
		actions[num_actions].parameter.objid = ctrobj;

		summary &= ~PMF_RAS_COUNT_REF;
		++nattr;
		++num_actions;
	}

	/* Encode a designation (0..7) to set */
	if (summary & PMF_RAS_QOS_HW_DESIG) {
		ent_attrs[nattr].id = FAL_ACL_ENTRY_ATTR_ACTION_SET_DESIGNATION;
		ent_attrs[nattr].value.aclaction = &actions[num_actions];

		int32_t set_designation = 8; /* Invalid */
		struct pmf_qos_mark const *qos_mark = rule->pp_action.qos_mark;

		if (qos_mark && qos_mark->paqm_has_desig == PMV_TRUE)
			set_designation = qos_mark->paqm_desig;

		actions[num_actions].enable = true;
		actions[num_actions].parameter.s32 = set_designation;

		summary &= ~PMF_RAS_QOS_HW_DESIG;

		/* Skip if invalid */
		if (set_designation < 8) {
			++nattr;
			++num_actions;
		}
	}

	/* Encode a colour (red/green/yellow) to set */
	if (summary & PMF_RAS_QOS_COLOUR) {
		ent_attrs[nattr].id = FAL_ACL_ENTRY_ATTR_ACTION_SET_COLOUR;
		ent_attrs[nattr].value.aclaction = &actions[num_actions];

		enum pmf_mark_colour cfg_colour = PMMC_UNSET;
		struct pmf_qos_mark const *qos_mark = rule->pp_action.qos_mark;
		if (qos_mark)
			cfg_colour = qos_mark->paqm_colour;

		enum fal_packet_colour set_colour = FAL_NUM_PACKET_COLOURS;
		switch (cfg_colour) {
		case PMMC_GREEN:
			set_colour = FAL_PACKET_COLOUR_GREEN;
			break;
		case PMMC_YELLOW:
			set_colour = FAL_PACKET_COLOUR_YELLOW;
			break;
		case PMMC_RED:
			set_colour = FAL_PACKET_COLOUR_RED;
			break;
		default:
			break;
		}

		actions[num_actions].enable = true;
		actions[num_actions].parameter.s32 = set_colour;

		summary &= ~PMF_RAS_QOS_COLOUR;

		/* Skip if invalid */
		if (set_colour < FAL_NUM_PACKET_COLOURS) {
			++nattr;
			++num_actions;
		}
	}

	/* Encode use of a rule policer */
	if (summary & PMF_RAS_QOS_POLICE) {
		ent_attrs[nattr].id = FAL_ACL_ENTRY_ATTR_ACTION_POLICER;
		ent_attrs[nattr].value.aclaction = &actions[num_actions];

		fal_object_t policer_obj = rule->pp_action.qos_policer;

		actions[num_actions].enable = true;
		actions[num_actions].parameter.objid = policer_obj;

		summary &= ~PMF_RAS_QOS_POLICE;

		/* Skip if invalid */
		if (policer_obj != FAL_NULL_OBJECT_ID) {
			++nattr;
			++num_actions;
		}
	}

	summary &= ~PMF_RAS_COUNT_DEF;


	/* Fields */
	uint32_t num_fields = 1;

	/* count set bits - a slight over estimate */
	for (; summary; summary >>= 1) {
		if (summary & 1)
			++num_fields;
	}

	struct fal_acl_field_data_t *fields
		= calloc(1, num_fields * sizeof(*fields));
	if (!fields) {
		free(actions);
		return false;
	}
	struct fal_acl_field_data_t *curfld = fields;

	summary = rule->pp_summary;

	/* L3 pieces (7) */

	if (summary & PMF_RMS_L3_SRC) {
		ent_attrs[nattr].value.aclfield = curfld;
		curfld->enable = true;

		if (is_v6) {
			ent_attrs[nattr].id = FAL_ACL_ENTRY_ATTR_FIELD_SRC_IPV6;

			struct pmf_attr_v6_prefix *v6pfx
				= rule->pp_match.l3[PMF_L3F_SRC].pm_l3v6;
			struct in6_addr mask;

			static_assert(sizeof(v6pfx->pm_bytes) == 16,
				      "unexpected size of IPv6 addr structure");
			memcpy(curfld->data.ip6, v6pfx->pm_bytes, 16);
			in6_prefixlen2mask(&mask, v6pfx->pm_plen);
			memcpy(curfld->mask.ip6, mask.s6_addr, 16);
		} else {
			ent_attrs[nattr].id = FAL_ACL_ENTRY_ATTR_FIELD_SRC_IPV4;

			struct pmf_attr_v4_prefix *v4pfx
				= rule->pp_match.l3[PMF_L3F_SRC].pm_l3v4;
			uint32_t mask = prefixlen_to_mask(v4pfx->pm_plen);

			static_assert(sizeof(v4pfx->pm_bytes) == 4,
				      "unexpected size of IPv4 addr structure");
			memcpy(curfld->data.ip4, v4pfx->pm_bytes, 4);
			memcpy(curfld->mask.ip4, (void *)&mask, 4);
		}

		++nattr;
		++curfld;
	}

	if (summary & PMF_RMS_L3_DST) {
		ent_attrs[nattr].value.aclfield = curfld;
		curfld->enable = true;

		if (is_v6) {
			ent_attrs[nattr].id = FAL_ACL_ENTRY_ATTR_FIELD_DST_IPV6;

			struct pmf_attr_v6_prefix *v6pfx
				= rule->pp_match.l3[PMF_L3F_DST].pm_l3v6;
			struct in6_addr mask;

			static_assert(sizeof(v6pfx->pm_bytes) == 16,
				      "unexpected size of IPv6 addr structure");
			memcpy(curfld->data.ip6, v6pfx->pm_bytes, 16);
			in6_prefixlen2mask(&mask, v6pfx->pm_plen);
			memcpy(curfld->mask.ip6, mask.s6_addr, 16);
		} else {
			ent_attrs[nattr].id = FAL_ACL_ENTRY_ATTR_FIELD_DST_IPV4;

			struct pmf_attr_v4_prefix *v4pfx
				= rule->pp_match.l3[PMF_L3F_DST].pm_l3v4;
			uint32_t mask = prefixlen_to_mask(v4pfx->pm_plen);

			static_assert(sizeof(v4pfx->pm_bytes) == 4,
				      "unexpected size of IPv4 addr structure");
			memcpy(curfld->data.ip4, v4pfx->pm_bytes, 4);
			memcpy(curfld->mask.ip4, (void *)&mask, 4);
		}

		++nattr;
		++curfld;
	}

	if (summary & PMF_RMS_L3_PROTO_BASE) {
		ent_attrs[nattr].value.aclfield = curfld;
		ent_attrs[nattr].id = FAL_ACL_ENTRY_ATTR_FIELD_IP_PROTO_BASE;

		struct pmf_attr_proto *proto
			= rule->pp_match.l3[PMF_L3F_PROTOB].pm_l3proto;

		curfld->enable = true;
		curfld->mask.u8 = 0xff;
		curfld->data.u8 = proto->pm_proto;

		++nattr;
		++curfld;
	}

	if (summary & PMF_RMS_L3_PROTO_FINAL) {
		ent_attrs[nattr].value.aclfield = curfld;
		ent_attrs[nattr].id = FAL_ACL_ENTRY_ATTR_FIELD_IP_PROTO_FINAL;

		struct pmf_attr_proto *proto
			= rule->pp_match.l3[PMF_L3F_PROTOF].pm_l3proto;

		curfld->enable = true;
		curfld->mask.u8 = 0xff;
		curfld->data.u8 = proto->pm_proto;

		++nattr;
		++curfld;
	}

	if (summary & PMF_RMS_L3_TTL) {
		ent_attrs[nattr].value.aclfield = curfld;
		ent_attrs[nattr].id = FAL_ACL_ENTRY_ATTR_FIELD_IP_TTL;

		struct pmf_attr_ttl *ttl
			= rule->pp_match.l3[PMF_L3F_TTL].pm_l3ttl;

		curfld->enable = true;
		curfld->mask.u8 = 0xff;
		curfld->data.u8 = ttl->pm_ttl;

		++nattr;
		++curfld;
	}

	if (summary & PMF_RMS_L3_DSCP) {
		ent_attrs[nattr].value.aclfield = curfld;
		ent_attrs[nattr].id = FAL_ACL_ENTRY_ATTR_FIELD_IP_DSCP;

		struct pmf_attr_dscp *dscp
			= rule->pp_match.l3[PMF_L3F_DSCP].pm_l3dscp;

		curfld->enable = true;
		curfld->mask.u8 = 0x3f;
		curfld->data.u8 = dscp->pm_dscp;

		++nattr;
		++curfld;
	}

	if (summary & PMF_RMS_L3_FRAG) {
		ent_attrs[nattr].value.aclfield = curfld;
		ent_attrs[nattr].id = FAL_ACL_ENTRY_ATTR_FIELD_IP_FRAG;

		curfld->enable = true;
		curfld->data.s32 = FAL_ACL_IP_FRAG_ANY;

		++nattr;
		++curfld;
	}

	/* L4 pieces (5) */

	if (summary & PMF_RMS_L4_SRC) {
		ent_attrs[nattr].value.aclfield = curfld;
		ent_attrs[nattr].id = FAL_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT;

		struct pmf_attr_l4port_range *ports =
			rule->pp_match.l4[PMF_L4F_SRC].pm_l4port_range;
		curfld->enable = true;
		curfld->mask.u16 = 0xffff;
		curfld->data.u16 = htons(ports->pm_loport);

		++nattr;
		++curfld;
	}

	if (summary & PMF_RMS_L4_DST) {
		ent_attrs[nattr].value.aclfield = curfld;
		ent_attrs[nattr].id = FAL_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT;

		struct pmf_attr_l4port_range *ports =
			rule->pp_match.l4[PMF_L4F_DST].pm_l4port_range;
		curfld->enable = true;
		curfld->mask.u16 = 0xffff;
		curfld->data.u16 = htons(ports->pm_loport);


		++nattr;
		++curfld;
	}

	if (summary & PMF_RMS_L4_TCPFL) {
		ent_attrs[nattr].value.aclfield = curfld;
		ent_attrs[nattr].id = FAL_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS;

		struct pmf_attr_l4tcp_flags *tcpflg =
			rule->pp_match.l4[PMF_L4F_TCP_FLAGS].pm_l4tcp_flags;
		curfld->enable = true;
		curfld->mask.u16 = htons(tcpflg->pm_mask);
		curfld->data.u16 = htons(tcpflg->pm_match);

		++nattr;
		++curfld;
	}

	if (summary & PMF_RMS_L4_ICMP_TYPE) {
		ent_attrs[nattr].value.aclfield = curfld;
		uint32_t aid = is_v6 ? FAL_ACL_ENTRY_ATTR_FIELD_ICMPV6_TYPE
				     : FAL_ACL_ENTRY_ATTR_FIELD_ICMP_TYPE;
		ent_attrs[nattr].id = aid;

		struct pmf_attr_l4icmp_vals *icmp =
			rule->pp_match.l4[PMF_L4F_ICMP_VALS].pm_l4icmp_vals;
		curfld->enable = true;
		curfld->mask.u8 = icmp->pm_class ? ICMP6_INFOMSG_MASK : 0xff;
		curfld->data.u8 = icmp->pm_type;

		++nattr;
		++curfld;
	}

	if (summary & PMF_RMS_L4_ICMP_CODE) {
		ent_attrs[nattr].value.aclfield = curfld;
		uint32_t aid = is_v6 ? FAL_ACL_ENTRY_ATTR_FIELD_ICMPV6_CODE
				     : FAL_ACL_ENTRY_ATTR_FIELD_ICMP_CODE;
		ent_attrs[nattr].id = aid;

		struct pmf_attr_l4icmp_vals *icmp =
			rule->pp_match.l4[PMF_L4F_ICMP_VALS].pm_l4icmp_vals;
		curfld->enable = true;
		curfld->mask.u8 = 0xff;
		curfld->data.u8 = icmp->pm_code;

		++nattr;
		++curfld;
	}

#undef FAL_ENTRY_FIX_FIELDS
#undef FAL_ENTRY_VAR_FIELDS
#undef FAL_ENTRY_TOT_FIELDS

	pmf_hw_commit_needed = true;

	/* Call the FAL, and clean up */
	rc = fal_acl_create_entry(nattr, ent_attrs, &rlobj);
	free(fields);
	free(actions);

	if (!rc)
		gpc_rule_set_objid(gprl, rlobj);

	ok = (!rc || (rc == -EOPNOTSUPP && !grp_was_created));
	ok_str = ok ? ((!rc) ? "OK" : "UN") : "NO";

log_add:
	if (!ok || DP_DEBUG_ENABLED(NPF)) {
		ACL_LOG(ok, ACL_HW,
			"HW-GPC(%s)v%s RL Add %s/%s|%s:%u [%lx] %x => %s(%d) [%lx]\n",
			feat_str, (is_v6) ? "6" : "4",
			(ingress) ? " In" : "Out", ifname, rgname, index,
			grpobj, summary,
			ok_str, rc, rlobj);
	}


	return (!rc && (rlobj != FAL_NULL_OBJECT_ID));
}

void
pmf_hw_rule_del(struct gpc_rule *gprl)
{
	struct gpc_group *gprg = gpc_rule_get_group(gprl);
	struct gpc_rlset *gprs = gpc_group_get_rlset(gprg);
	char const *ifname = gpc_rlset_get_ifname(gprs);
	uintptr_t rlobj = gpc_rule_get_objid(gprl);
	bool was_created = (rlobj != FAL_NULL_OBJECT_ID);
	uint16_t index = gpc_rule_get_index(gprl);
	bool ingress = gpc_group_is_ingress(gprg);
	bool is_v6 = gpc_group_is_v6(gprg);
	char const *rgname = gpc_group_get_name(gprg);
	bool ok = true;
	char const *ok_str = "SK";
	enum gpc_feature feat = gpc_group_get_feature(gprg);
	char const *feat_str = gpc_feature_get_name(feat);
	int rc = 0; /* Success */

	/* Nothing to do if no FAL object - e.g. vrouter */
	if (!was_created)
		goto log_delete;

	pmf_hw_commit_needed = true;

	rc = fal_acl_delete_entry(rlobj);
	if (!rc)
		gpc_rule_set_objid(gprl, FAL_NULL_OBJECT_ID);

	ok = (!rc || (rc == -EOPNOTSUPP && !was_created));
	ok_str = ok ? ((!rc) ? "OK" : "UN") : "NO";

log_delete:
	if (!ok || DP_DEBUG_ENABLED(NPF)) {
		ACL_LOG(ok, ACL_HW,
			"HW-GPC(%s)v%s RL Delete %s/%s|%s:%u [%lx] => %s(%d)\n",
			feat_str, (is_v6) ? "6" : "4",
			(ingress) ? " In" : "Out", ifname, rgname, index, rlobj,
			ok_str, rc);
	}
}

/*
 * Not currently triggered from config, can be triggered by
 * manual vplsh stimulus.  We need to give this some more
 * consideration wrt how modifies should behave.
 *
 * The current delete and re-add makes for easier handling in
 * the FAL until such time as we generate proper modifies.
 */
void
pmf_hw_rule_mod(struct gpc_rule *gprl, struct pmf_rule *old_rule __unused)
{
	struct gpc_group *gprg = gpc_rule_get_group(gprl);
	struct gpc_rlset *gprs = gpc_group_get_rlset(gprg);
	char const *ifname = gpc_rlset_get_ifname(gprs);
	uintptr_t rlobj = gpc_rule_get_objid(gprl);
	uint16_t index = gpc_rule_get_index(gprl);
	bool ingress = gpc_group_is_ingress(gprg);
	bool is_v6 = gpc_group_is_v6(gprg);
	char const *rgname = gpc_group_get_name(gprg);
	enum gpc_feature feat = gpc_group_get_feature(gprg);
	char const *feat_str = gpc_feature_get_name(feat);
	bool ok = true;

	if (!ok || DP_DEBUG_ENABLED(NPF)) {
		ACL_LOG(ok, ACL_HW,
			"HW-GPC(%s)v%s RL Modify %s/%s|%s:%u [%lx]\n",
			feat_str, (is_v6) ? "6" : "4",
			(ingress) ? " In" : "Out", ifname, rgname, index,
			rlobj);
	}

	pmf_hw_rule_del(gprl);
	pmf_hw_rule_add(gprl);
}

/* -- group FAL notification -- */

bool
pmf_hw_group_create(struct gpc_group *gprg)
{
	struct gpc_rlset *gprs = gpc_group_get_rlset(gprg);
	char const *ifname = gpc_rlset_get_ifname(gprs);
	uintptr_t grpobj = FAL_NULL_OBJECT_ID;
	bool ingress = gpc_group_is_ingress(gprg);
	bool is_v6 = gpc_group_is_v6(gprg);
	char const *rgname = gpc_group_get_name(gprg);
	uint32_t summary = gpc_group_get_summary(gprg);
	enum gpc_feature feat = gpc_group_get_feature(gprg);
	char const *feat_str = gpc_feature_get_name(feat);

	/* Bind point list */
	struct fal_object_list_t *bp_list
		= calloc(1, sizeof(*bp_list) + sizeof(bp_list->list[0]));
	if (!bp_list)
		return false;
	bp_list->count = 1;
	bp_list->list[0] = FAL_ACL_BIND_POINT_TYPE_ROUTER_INTERFACE;

	/* Action list */
	uint32_t num_actions
		= !!(summary & (PMF_RAS_DROP|PMF_RAS_PASS))
		+ !!(summary & PMF_RAS_COUNT_REF)
		+ !!(summary & PMF_RAS_QOS_HW_DESIG)
		+ !!(summary & PMF_RAS_QOS_COLOUR)
		+ !!(summary & PMF_RAS_QOS_POLICE);
	struct fal_object_list_t *act_list
		= calloc(1, sizeof(*act_list) +
			    num_actions * sizeof(act_list->list[0]));
	if (!act_list) {
		free(bp_list);
		return false;
	}
	act_list->count = num_actions;
	fal_object_t * const actions = &act_list->list[0];
	num_actions = 0;
	if (summary & (PMF_RAS_DROP|PMF_RAS_PASS))
		actions[num_actions++] = FAL_ACL_ACTION_TYPE_PACKET_ACTION;
	if (summary & PMF_RAS_COUNT_REF)
		actions[num_actions++] = FAL_ACL_ACTION_TYPE_COUNTER;
	if (summary & PMF_RAS_QOS_HW_DESIG)
		actions[num_actions++] = FAL_ACL_ACTION_TYPE_SET_DESIGNATION;
	if (summary & PMF_RAS_QOS_COLOUR)
		actions[num_actions++] = FAL_ACL_ACTION_TYPE_SET_COLOUR;
	if (summary & PMF_RAS_QOS_POLICE)
		actions[num_actions++] = FAL_ACL_ACTION_TYPE_POLICER;

#define FAL_TABLE_FIX_FIELDS 5
#define FAL_TABLE_VAR_FIELDS (7 + 5)
#define FAL_TABLE_TOT_FIELDS (FAL_TABLE_FIX_FIELDS + FAL_TABLE_VAR_FIELDS)
	struct fal_attribute_t tbl_attrs[FAL_TABLE_TOT_FIELDS] = {
		[0] = {
			.id = FAL_ACL_TABLE_ATTR_STAGE,
			.value.u32 = ingress ? FAL_ACL_STAGE_INGRESS
					     : FAL_ACL_STAGE_EGRESS,
		},
		[1] = {
			.id = FAL_ACL_TABLE_ATTR_IP_TYPE,
			.value.u32 = is_v6 ? FAL_ACL_IP_TYPE_IPV6ANY
					   : FAL_ACL_IP_TYPE_IPV4ANY,
		},
		[2] = {
			.id = FAL_ACL_TABLE_ATTR_BIND_POINT_TYPE_LIST,
			.value.objlist = bp_list,
		},
		[3] = {
			.id = FAL_ACL_TABLE_ATTR_ACTION_TYPE_LIST,
			.value.objlist = act_list,
		},
		[4] = {
			.id = FAL_ACL_TABLE_ATTR_NAME,
			.value.ptr = rgname,
		},
	};
	unsigned int nattr = FAL_TABLE_FIX_FIELDS;

	/* Encode the summary data for the group */

	/* L3 pieces (7) */

	if (summary & PMF_RMS_L3_SRC) {
		tbl_attrs[nattr].value.booldata = true;
		tbl_attrs[nattr].id = is_v6 ? FAL_ACL_TABLE_ATTR_FIELD_SRC_IPV6
					    : FAL_ACL_TABLE_ATTR_FIELD_SRC_IPV4;
		++nattr;
	}

	if (summary & PMF_RMS_L3_DST) {
		tbl_attrs[nattr].value.booldata = true;
		tbl_attrs[nattr].id = is_v6 ? FAL_ACL_TABLE_ATTR_FIELD_DST_IPV6
					    : FAL_ACL_TABLE_ATTR_FIELD_DST_IPV4;
		++nattr;
	}

	if (summary & PMF_RMS_L3_PROTO_BASE) {
		tbl_attrs[nattr].value.booldata = true;
		tbl_attrs[nattr].id = FAL_ACL_TABLE_ATTR_FIELD_IP_PROTO_BASE;
		++nattr;
	}

	if (summary & PMF_RMS_L3_PROTO_FINAL) {
		tbl_attrs[nattr].value.booldata = true;
		tbl_attrs[nattr].id = FAL_ACL_TABLE_ATTR_FIELD_IP_PROTO_FINAL;
		++nattr;
	}

	if (summary & PMF_RMS_L3_TTL) {
		tbl_attrs[nattr].value.booldata = true;
		tbl_attrs[nattr].id = FAL_ACL_TABLE_ATTR_FIELD_IP_TTL;
		++nattr;
	}

	if (summary & PMF_RMS_L3_DSCP) {
		tbl_attrs[nattr].value.booldata = true;
		tbl_attrs[nattr].id = FAL_ACL_TABLE_ATTR_FIELD_IP_DSCP;
		++nattr;
	}

	if (summary & PMF_RMS_L3_FRAG) {
		tbl_attrs[nattr].value.booldata = true;
		tbl_attrs[nattr].id = FAL_ACL_TABLE_ATTR_FIELD_IP_FRAG;
		++nattr;
	}

	/* L4 pieces (5) */

	if (summary & PMF_RMS_L4_SRC) {
		tbl_attrs[nattr].value.booldata = true;
		tbl_attrs[nattr].id = FAL_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT;
		++nattr;
	}

	if (summary & PMF_RMS_L4_DST) {
		tbl_attrs[nattr].value.booldata = true;
		tbl_attrs[nattr].id = FAL_ACL_TABLE_ATTR_FIELD_L4_DST_PORT;
		++nattr;
	}

	if (summary & PMF_RMS_L4_TCPFL) {
		tbl_attrs[nattr].value.booldata = true;
		tbl_attrs[nattr].id = FAL_ACL_TABLE_ATTR_FIELD_TCP_FLAGS;
		++nattr;
	}

	if (summary & PMF_RMS_L4_ICMP_TYPE) {
		tbl_attrs[nattr].value.booldata = true;
		uint32_t aid = is_v6 ? FAL_ACL_TABLE_ATTR_FIELD_ICMPV6_TYPE
				     : FAL_ACL_TABLE_ATTR_FIELD_ICMP_TYPE;
		tbl_attrs[nattr].id = aid;
		++nattr;
	}

	if (summary & PMF_RMS_L4_ICMP_CODE) {
		tbl_attrs[nattr].value.booldata = true;
		uint32_t aid = is_v6 ? FAL_ACL_TABLE_ATTR_FIELD_ICMPV6_CODE
				     : FAL_ACL_TABLE_ATTR_FIELD_ICMP_CODE;
		tbl_attrs[nattr].id = aid;
		++nattr;
	}

#undef FAL_TABLE_FIX_FIELDS
#undef FAL_TABLE_VAR_FIELDS
#undef FAL_TABLE_TOT_FIELDS

	pmf_hw_commit_needed = true;

	/* Call the FAL, and clean up */
	int rc = fal_acl_create_table(nattr, tbl_attrs, &grpobj);
	free(bp_list);
	free(act_list);

	if (!rc)
		gpc_group_set_objid(gprg, grpobj);

	bool const ok = (!rc || rc == -EOPNOTSUPP);
	char const *ok_str = ok ? ((!rc) ? "OK" : "UN") : "NO";

	if (!ok || DP_DEBUG_ENABLED(NPF)) {
		ACL_LOG(ok, ACL_HW,
			"HW-GPC(%s)v%s GP Create %s/%s|%s %x => %s(%d) [%lx]\n",
			feat_str, (is_v6) ? "6" : "4",
			(ingress) ? " In" : "Out", ifname, rgname, summary,
			ok_str, rc, grpobj);
	}

	return (!rc && (grpobj != FAL_NULL_OBJECT_ID));
}

void
pmf_hw_group_delete(struct gpc_group *gprg)
{
	struct gpc_rlset *gprs = gpc_group_get_rlset(gprg);
	char const *ifname = gpc_rlset_get_ifname(gprs);
	uintptr_t grpobj = gpc_group_get_objid(gprg);
	bool was_created = (grpobj != FAL_NULL_OBJECT_ID);
	bool ingress = gpc_group_is_ingress(gprg);
	bool is_v6 = gpc_group_is_v6(gprg);
	char const *rgname = gpc_group_get_name(gprg);
	bool ok = true;
	char const *ok_str = "SK";
	enum gpc_feature feat = gpc_group_get_feature(gprg);
	char const *feat_str = gpc_feature_get_name(feat);
	int rc = 0; /* Success */

	/* Nothing to do if no FAL object - e.g. vrouter */
	if (!was_created)
		goto log_delete;

	pmf_hw_commit_needed = true;

	rc = fal_acl_delete_table(grpobj);
	if (!rc)
		gpc_group_set_objid(gprg, FAL_NULL_OBJECT_ID);

	ok = (!rc || (rc == -EOPNOTSUPP && !was_created));
	ok_str = ok ? ((!rc) ? "OK" : "UN") : "NO";

log_delete:
	if (!ok || DP_DEBUG_ENABLED(NPF)) {
		ACL_LOG(ok, ACL_HW,
			"HW-GPC(%s)v%s GP Delete %s/%s|%s [%lx] => %s(%d)\n",
			feat_str, (is_v6) ? "6" : "4",
			(ingress) ? " In" : "Out", ifname, rgname, grpobj,
			ok_str, rc);
	}
}

/*
 * Not currently triggered from config, can be triggered by
 * manual vplsh stimulus.  We need to give this some more
 * consideration wrt how modifies should behave.
 *
 * Given that the FAL does not make use of the various summary
 * fields, treating this as a NO-OP is currently safe.
 */
void
pmf_hw_group_mod(struct gpc_group *gprg, uint32_t new)
{
	struct gpc_rlset *gprs = gpc_group_get_rlset(gprg);
	char const *ifname = gpc_rlset_get_ifname(gprs);
	uintptr_t grpobj = gpc_group_get_objid(gprg);
	bool ingress = gpc_group_is_ingress(gprg);
	bool is_v6 = gpc_group_is_v6(gprg);
	char const *rgname = gpc_group_get_name(gprg);
	uint32_t old = gpc_group_get_summary(gprg);
	uint32_t chg = old ^ new;
	uint32_t set = chg &  new;
	uint32_t clr = chg & ~new;
	bool ok = true;
	enum gpc_feature feat = gpc_group_get_feature(gprg);
	char const *feat_str = gpc_feature_get_name(feat);

	if (!ok || DP_DEBUG_ENABLED(NPF)) {
		ACL_LOG(ok, ACL_HW,
			"HW-GPC(%s)v%s GP Modify %s/%s|%s [%lx] old %x set %x clr %x\n",
			feat_str, (is_v6) ? "6" : "4",
			(ingress) ? " In" : "Out", ifname, rgname, grpobj,
			old, set, clr);
	}
}

/* ---- */

static uint32_t
pmf_hw_rtr_intf_attr_acl(bool ingress, bool is_v6)
{
	uint32_t acl_type;

	if (ingress) {
		if (is_v6)
			acl_type = FAL_ROUTER_INTERFACE_ATTR_V6_INGRESS_ACL;
		else
			acl_type = FAL_ROUTER_INTERFACE_ATTR_V4_INGRESS_ACL;
	} else {
		if (is_v6)
			acl_type = FAL_ROUTER_INTERFACE_ATTR_V6_EGRESS_ACL;
		else
			acl_type = FAL_ROUTER_INTERFACE_ATTR_V4_EGRESS_ACL;
	}

	return acl_type;
}

static uint32_t
pmf_hw_rtr_intf_attr_qos(bool is_v6)
{
	uint32_t qos_type;

	if (is_v6)
		qos_type = FAL_ROUTER_INTERFACE_ATTR_V6_INGRESS_QOS;
	else
		qos_type = FAL_ROUTER_INTERFACE_ATTR_V4_INGRESS_QOS;

	return qos_type;
}

bool
pmf_hw_group_attach(struct gpc_group *gprg, struct ifnet *ifp)
{
	uintptr_t grpobj = gpc_group_get_objid(gprg);
	bool is_attached = gpc_group_is_ll_attached(gprg);
	bool ingress = gpc_group_is_ingress(gprg);
	bool is_v6 = gpc_group_is_v6(gprg);
	char const *rgname = gpc_group_get_name(gprg);
	char const *ifname = ifp->if_name;
	bool ok = false;
	char const *ok_str = "ER";
	enum gpc_feature feat = gpc_group_get_feature(gprg);
	char const *feat_str = gpc_feature_get_name(feat);
	int rc = -EINVAL;

	/* Validate group feature, and not already attached */
	switch (feat) {
	case GPC_FEAT_ACL:
		break;
	case GPC_FEAT_QOS:
		if (!ingress)
			goto log_attach;
		break;
	default:
		goto log_attach;
	}
	if (is_attached)
		goto log_attach;

	ok = true;
	ok_str = "SK";
	rc = 0; /* Success */

	/* Nothing to do if no FAL object - e.g. vrouter */
	if (grpobj == FAL_NULL_OBJECT_ID)
		goto log_attach;

	struct fal_attribute_t acl;

	acl.value.objid = grpobj;

	switch (feat) {
	case GPC_FEAT_ACL:
		acl.id = pmf_hw_rtr_intf_attr_acl(ingress, is_v6);
		break;
	case GPC_FEAT_QOS:
		acl.id = pmf_hw_rtr_intf_attr_qos(is_v6);
		break;
	}

	pmf_hw_commit_needed = true;

	rc = if_set_l3_intf_attr(ifp, &acl);

	ok = (!rc || rc == -EOPNOTSUPP);
	ok_str = ok ? ((!rc) ? "OK" : "UN") : "NO";

log_attach:
	if (!ok || DP_DEBUG_ENABLED(NPF)) {
		ACL_LOG(ok, ACL_HW,
			"HW-GPC(%s)v%s GP Attach %s/%s|%s [%lx] => %s(%d)\n",
			feat_str, (is_v6) ? "6" : "4",
			(ingress) ? " In" : "Out", ifname, rgname, grpobj,
			ok_str, rc);
	}

	return (!rc && (grpobj != FAL_NULL_OBJECT_ID));
}

void
pmf_hw_group_detach(struct gpc_group *gprg, struct ifnet *ifp)
{
	uintptr_t grpobj = gpc_group_get_objid(gprg);
	bool was_attached = gpc_group_is_ll_attached(gprg);
	bool ingress = gpc_group_is_ingress(gprg);
	bool is_v6 = gpc_group_is_v6(gprg);
	char const *rgname = gpc_group_get_name(gprg);
	char const *ifname = ifp->if_name;
	bool ok = false;
	char const *ok_str = "ER";
	enum gpc_feature feat = gpc_group_get_feature(gprg);
	char const *feat_str = gpc_feature_get_name(feat);
	int rc = -EINVAL;

	/* Validate group feature, and not already attached */
	switch (feat) {
	case GPC_FEAT_ACL:
		break;
	case GPC_FEAT_QOS:
		if (!ingress)
			goto log_detach;
		break;
	default:
		goto log_detach;
	}

	ok = true;
	ok_str = "SK";
	rc = 0; /* Success */

	/* Nothing to do if attach failed or skipped */
	if (!was_attached)
		goto log_detach;

	struct fal_attribute_t acl;

	acl.value.objid = FAL_NULL_OBJECT_ID;

	switch (feat) {
	case GPC_FEAT_ACL:
		acl.id = pmf_hw_rtr_intf_attr_acl(ingress, is_v6);
		break;
	case GPC_FEAT_QOS:
		acl.id = pmf_hw_rtr_intf_attr_qos(is_v6);
		break;
	}

	pmf_hw_commit_needed = true;

	rc = if_set_l3_intf_attr(ifp, &acl);

	ok = (!rc || (rc == -EOPNOTSUPP && !was_attached));
	ok_str = ok ? ((!rc) ? "OK" : "UN") : "NO";

log_detach:
	if (!ok || DP_DEBUG_ENABLED(NPF)) {
		ACL_LOG(ok, ACL_HW,
			"HW-GPC(%s)v%s GP Detach %s/%s|%s [%lx] => %s(%d)\n",
			feat_str, (is_v6) ? "6" : "4",
			(ingress) ? " In" : "Out", ifname, rgname, grpobj,
			ok_str, rc);
	}
}

/* ---- */

bool
pmf_hw_counter_create(struct gpc_cntr *gprk)
{
	struct gpc_cntg *cntg = gpc_cntr_get_cntg(gprk);
	struct gpc_group *gprg = gpc_cntg_get_group(cntg);
	struct gpc_rlset *gprs = gpc_group_get_rlset(gprg);
	char const *ifname = gpc_rlset_get_ifname(gprs);
	uintptr_t grpobj = gpc_group_get_objid(gprg);
	bool grp_was_created = (grpobj != FAL_NULL_OBJECT_ID);
	uintptr_t ctrobj = FAL_NULL_OBJECT_ID;
	char const *ctname = gpc_cntr_get_name(gprk);
	bool ingress = gpc_group_is_ingress(gprg);
	bool is_v6 = gpc_group_is_v6(gprg);
	char const *rgname = gpc_group_get_name(gprg);
	bool cnt_pkt = gpc_cntr_pkt_enabled(gprk);
	bool cnt_byt = gpc_cntr_byt_enabled(gprk);
	bool ok = true;
	char const *ok_str = "SK";
	enum gpc_feature feat = gpc_group_get_feature(gprg);
	char const *feat_str = gpc_feature_get_name(feat);
	int rc = 0; /* Success */

	/* Do not allocate a useless counter */
	if (!cnt_pkt && !cnt_byt)
		return false;

	/* Nothing to do if no FAL object - e.g. vrouter */
	if (!grp_was_created)
		goto log_create;

#define FAL_COUNTER_FIX_FIELDS 1
#define FAL_COUNTER_VAR_FIELDS (2)
#define FAL_COUNTER_TOT_FIELDS (FAL_COUNTER_FIX_FIELDS + FAL_COUNTER_VAR_FIELDS)
	struct fal_attribute_t cnt_attrs[FAL_COUNTER_TOT_FIELDS] = {
		[0] = {
			.id = FAL_ACL_COUNTER_ATTR_TABLE_ID,
			.value.objid = grpobj,
		},
	};
	unsigned int nattr = FAL_COUNTER_FIX_FIELDS;

	/* count items (2) */

	if (cnt_pkt) {
		cnt_attrs[nattr].value.booldata = true;
		cnt_attrs[nattr].id = FAL_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT;

		++nattr;
	}

	if (cnt_byt) {
		cnt_attrs[nattr].value.booldata = true;
		cnt_attrs[nattr].id = FAL_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT;

		++nattr;
	}

#undef FAL_COUNTER_FIX_FIELDS
#undef FAL_COUNTER_VAR_FIELDS
#undef FAL_COUNTER_TOT_FIELDS

	pmf_hw_commit_needed = true;

	/* Call the FAL, and clean up */
	rc = fal_acl_create_counter(nattr, cnt_attrs, &ctrobj);

	if (!rc)
		gpc_cntr_set_objid(gprk, ctrobj);

	ok = (!rc || (rc == -EOPNOTSUPP && !grp_was_created));
	ok_str = ok ? ((!rc) ? "OK" : "UN") : "NO";

log_create:
	if (!ok || DP_DEBUG_ENABLED(NPF)) {
		ACL_LOG(ok, ACL_HW,
			"HW-GPC(%s)v%s CT Add %s/%s|%s:%s [%lx]%s%s => %s(%d) [%lx]\n",
			feat_str, (is_v6) ? "6" : "4",
			(ingress) ? " In" : "Out", ifname, rgname, ctname,
			grpobj,
			(cnt_pkt) ? " Pkt" : "",
			(cnt_byt) ? " Byt" : "",
			ok_str, rc, ctrobj);
	}


	return (!rc && (ctrobj != FAL_NULL_OBJECT_ID));
}

void
pmf_hw_counter_delete(struct gpc_cntr *gprk)
{
	struct gpc_cntg *cntg = gpc_cntr_get_cntg(gprk);
	struct gpc_group *gprg = gpc_cntg_get_group(cntg);
	struct gpc_rlset *gprs = gpc_group_get_rlset(gprg);
	char const *ifname = gpc_rlset_get_ifname(gprs);
	uintptr_t ctrobj = gpc_cntr_get_objid(gprk);
	bool was_created = (ctrobj != FAL_NULL_OBJECT_ID);
	char const *ctname = gpc_cntr_get_name(gprk);
	bool ingress = gpc_group_is_ingress(gprg);
	bool is_v6 = gpc_group_is_v6(gprg);
	char const *rgname = gpc_group_get_name(gprg);
	bool ok = true;
	char const *ok_str = "SK";
	enum gpc_feature feat = gpc_group_get_feature(gprg);
	char const *feat_str = gpc_feature_get_name(feat);
	int rc = 0; /* Success */

	/* Nothing to do if no FAL object - e.g. vrouter */
	if (!was_created)
		goto log_delete;

	pmf_hw_commit_needed = true;

	rc = fal_acl_delete_counter(ctrobj);
	if (!rc)
		gpc_cntr_set_objid(gprk, FAL_NULL_OBJECT_ID);

	ok = (!rc || (rc == -EOPNOTSUPP && !was_created));
	ok_str = ok ? ((!rc) ? "OK" : "UN") : "NO";

log_delete:
	if (!ok || DP_DEBUG_ENABLED(NPF)) {
		ACL_LOG(ok, ACL_HW,
			"HW-GPC(%s)v%s CT Delete %s/%s|%s:%s [%lx] => %s(%d)\n",
			feat_str, (is_v6) ? "6" : "4",
			(ingress) ? " In" : "Out", ifname, rgname, ctname,
			ctrobj,
			ok_str, rc);
	}
}

bool
pmf_hw_counter_clear(struct gpc_cntr const *gprk)
{
	struct gpc_cntg *cntg = gpc_cntr_get_cntg(gprk);
	struct gpc_group *gprg = gpc_cntg_get_group(cntg);
	struct gpc_rlset *gprs = gpc_group_get_rlset(gprg);
	char const *ifname = gpc_rlset_get_ifname(gprs);
	uintptr_t ctrobj = gpc_cntr_get_objid(gprk);
	bool was_created = (ctrobj != FAL_NULL_OBJECT_ID);
	char const *ctname = gpc_cntr_get_name(gprk);
	bool ingress = gpc_group_is_ingress(gprg);
	bool is_v6 = gpc_group_is_v6(gprg);
	char const *rgname = gpc_group_get_name(gprg);
	bool cnt_pkt = gpc_cntr_pkt_enabled(gprk);
	bool cnt_byt = gpc_cntr_byt_enabled(gprk);
	bool ok = true;
	char const *ok_str_pkt = "SK";
	char const *ok_str_byt = "SK";
	enum gpc_feature feat = gpc_group_get_feature(gprg);
	char const *feat_str = gpc_feature_get_name(feat);
	int rc_pkt = 0, rc_byt = 0; /* Success */

	/* Nothing to do if no FAL object - e.g. vrouter */
	if (!was_created)
		goto log_clear;

	struct fal_attribute_t cnt_attr;

	/* Clear packet count */
	if (cnt_pkt) {
		cnt_attr.id = FAL_ACL_COUNTER_ATTR_PACKETS;
		cnt_attr.value.u64 = 0;

		rc_pkt = fal_acl_set_counter_attr(ctrobj, &cnt_attr);
	}

	/* Clear byte count */
	if (cnt_byt) {
		cnt_attr.id = FAL_ACL_COUNTER_ATTR_BYTES;
		cnt_attr.value.u64 = 0;

		rc_byt = fal_acl_set_counter_attr(ctrobj, &cnt_attr);
	}

	bool ok_pkt = (!rc_pkt || (rc_pkt == -EOPNOTSUPP && !was_created));
	bool ok_byt = (!rc_byt || (rc_byt == -EOPNOTSUPP && !was_created));
	ok_str_pkt = ok_pkt ? ((!rc_pkt) ? "OK" : "UN") : "NO";
	ok_str_byt = ok_byt ? ((!rc_byt) ? "OK" : "UN") : "NO";
	ok = ok_pkt && ok_byt;

log_clear:
	if (!ok || DP_DEBUG_ENABLED(NPF)) {
		ACL_LOG(ok, ACL_HW,
			"HW-GPC(%s)v%s CT Clr %s/%s|%s:%s [%lx]%s%s =>"
				" P:%s(%d) B:%s(%d)\n",
			feat_str, (is_v6) ? "6" : "4",
			(ingress) ? " In" : "Out", ifname, rgname, ctname,
			ctrobj,
			(cnt_pkt) ? " Pkt" : "",
			(cnt_byt) ? " Byt" : "",
			ok_str_pkt, rc_pkt,
			ok_str_byt, rc_byt);
	}

	return ok;
}

bool
pmf_hw_counter_read(struct gpc_cntr const *gprk,
		    uint64_t *pkts, uint64_t *bytes)
{
	struct gpc_cntg *cntg = gpc_cntr_get_cntg(gprk);
	struct gpc_group *gprg = gpc_cntg_get_group(cntg);
	struct gpc_rlset *gprs = gpc_group_get_rlset(gprg);
	char const *ifname = gpc_rlset_get_ifname(gprs);
	uintptr_t ctrobj = gpc_cntr_get_objid(gprk);
	bool was_created = (ctrobj != FAL_NULL_OBJECT_ID);
	char const *ctname = gpc_cntr_get_name(gprk);
	bool ingress = gpc_group_is_ingress(gprg);
	bool is_v6 = gpc_group_is_v6(gprg);
	char const *rgname = gpc_group_get_name(gprg);
	bool cnt_pkt = gpc_cntr_pkt_enabled(gprk);
	bool cnt_byt = gpc_cntr_byt_enabled(gprk);
	bool ok = true;
	char const *ok_str = "SK";
	enum gpc_feature feat = gpc_group_get_feature(gprg);
	char const *feat_str = gpc_feature_get_name(feat);
	int rc = 0; /* Success */

	/* Nothing to do if no FAL object - e.g. vrouter */
	if (!was_created)
		goto log_read;

	struct fal_attribute_t cnt_attrs[2];
	unsigned int nattr = 0;
	unsigned int pkt_idx = 0;
	unsigned int byt_idx = 0;

	/* Get packet count */
	if (cnt_pkt) {
		cnt_attrs[nattr].id = FAL_ACL_COUNTER_ATTR_PACKETS;
		pkt_idx = nattr++;
	}

	/* Get byte count */
	if (cnt_byt) {
		cnt_attrs[nattr].id = FAL_ACL_COUNTER_ATTR_BYTES;
		byt_idx = nattr++;
	}

	/* Call the FAL */
	rc = fal_acl_get_counter_attr(ctrobj, nattr, cnt_attrs);
	if (!rc) {
		if (cnt_pkt)
			*pkts = cnt_attrs[pkt_idx].value.u64;
		if (cnt_byt)
			*bytes = cnt_attrs[byt_idx].value.u64;
	}

	ok = (!rc || rc == -EOPNOTSUPP);
	ok_str = ok ? ((!rc) ? "OK" : "UN") : "NO";

log_read:
	if (!ok || DP_DEBUG_ENABLED(NPF)) {
		ACL_LOG(ok, ACL_HW,
			"HW-GPC(%s)v%s CT Get %s/%s|%s:%s [%lx]%s%s => %s(%d)\n",
			feat_str, (is_v6) ? "6" : "4",
			(ingress) ? " In" : "Out", ifname, rgname, ctname,
			ctrobj,
			(cnt_pkt) ? " Pkt" : "",
			(cnt_byt) ? " Byt" : "",
			ok_str, rc);
	}

	if (!was_created)
		return true;

	return ok;
}

/* ---- */

void
pmf_hw_commit(void)
{
	bool ok = true;
	int rc = 0;
	char const *ok_str = "SK";

	if (!pmf_hw_commit_needed)
		goto log_commit;

	static uint32_t commit_counter;

	struct fal_attribute_t commit_attr[1] = {
		[0] = {
			.id = FAL_SWITCH_ATTR_ACL_COMMIT,
			.value.u32 = ++commit_counter,
		},
	};

	rc = fal_set_switch_attr(commit_attr);

	ok = (!rc || rc == -EOPNOTSUPP);
	ok_str = ok ? ((!rc) ? "OK" : "UN") : "NO";

log_commit:
	if (!ok || DP_DEBUG_ENABLED(NPF)) {
		ACL_LOG(ok, ACL_HW,
			"HW-ACL Commit %u => %s(%d)\n",
			commit_counter, ok_str, rc);
	}

	pmf_hw_commit_needed = false;
}
