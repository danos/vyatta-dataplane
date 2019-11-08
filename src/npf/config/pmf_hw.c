#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h> /* htons */

#include "compiler.h"
#include "util.h"
#include "fal.h"
#include "if_var.h"
#include "npf/config/pmf_att_rlgrp.h"
#include "npf/config/pmf_rule.h"
#include "npf/config/pmf_hw.h"
#include "vplane_log.h"
#include "vplane_debug.h"

#define ACL_LOG(ok, t, ...) \
	rte_log((ok) ? RTE_LOG_DEBUG : RTE_LOG_ERR, \
		RTE_LOGTYPE_ ## t, # t ": " __VA_ARGS__)

static bool pmf_hw_commit_needed;

/* ---- */

static void
pmf_hw_rule_gen_mask(uint8_t *mask, uint8_t plen, uint8_t blen)
{
	/* set bytes */
	for (; blen && plen >= 8; --blen, plen -= 8)
		*mask++ = 0xff;

	/* mixed byte */
	if (plen)
		*mask++ = (0xff << (8 - plen));

	/* clear bytes */
	while (blen--)
		*mask++ = 0;
}

bool
pmf_hw_rule_add(struct pmf_attrl *earl, struct pmf_rule *rule)
{
	struct pmf_group_ext *earg = pmf_arlg_attrl_get_grp(earl);
	struct pmf_rlset_ext *ears = pmf_arlg_grp_get_rls(earg);
	char const *ifname = pmf_arlg_rls_get_ifname(ears);
	struct pmf_cntr *eark = pmf_arlg_attrl_get_cntr(earl);
	uintptr_t ctrobj = pmf_arlg_cntr_get_objid(eark);
	uintptr_t grpobj = pmf_arlg_grp_get_objid(earg);
	bool grp_was_created = (grpobj != FAL_NULL_OBJECT_ID);
	uintptr_t rlobj = FAL_NULL_OBJECT_ID;
	uint16_t index = pmf_arlg_attrl_get_index(earl);
	bool ingress = pmf_arlg_grp_is_ingress(earg);
	bool is_v6 = pmf_arlg_grp_is_v6(earg);
	char const *rgname = pmf_arlg_grp_get_name(earg);
	uint32_t summary = rule->pp_summary;
	bool ok = true;
	char const *ok_str = "SK";
	int rc = 0; /* Success */

	/* Nothing to do if no FAL object - e.g. vrouter */
	if (!grp_was_created)
		goto log_add;

#define FAL_ENTRY_PRIORITY_TOP	(16384u)

#define FAL_ENTRY_FIX_FIELDS 3
#define FAL_ENTRY_VAR_FIELDS (2 + 7 + 5)
#define FAL_ENTRY_TOT_FIELDS (FAL_ENTRY_FIX_FIELDS + FAL_ENTRY_VAR_FIELDS)
	struct fal_attribute_t ent_attrs[FAL_ENTRY_TOT_FIELDS] = {
		[0] = {
			.id = FAL_ACL_ENTRY_ATTR_TABLE_ID,
			.value.objid = grpobj,
		},
		[1] = {
			.id = FAL_ACL_ENTRY_ATTR_PRIORITY,
			.value.u32 = FAL_ENTRY_PRIORITY_TOP - index,
		},
		[2] = {
			.id = FAL_ACL_ENTRY_ATTR_ADMIN_STATE,
			.value.booldata = true,
		},
	};
	unsigned int nattr = FAL_ENTRY_FIX_FIELDS;

	/* Actions */
	uint32_t num_actions
		= !!(summary & (PMF_RAS_DROP|PMF_RAS_PASS))
		+ !!(summary & PMF_RAS_COUNT_REF);
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
			uint8_t blen = sizeof(v6pfx->pm_bytes);
			uint8_t plen = v6pfx->pm_plen;

			memcpy(curfld->data.ip6, v6pfx->pm_bytes, blen);
			pmf_hw_rule_gen_mask(curfld->mask.ip6, plen, blen);
		} else {
			ent_attrs[nattr].id = FAL_ACL_ENTRY_ATTR_FIELD_SRC_IPV4;

			struct pmf_attr_v4_prefix *v4pfx
				= rule->pp_match.l3[PMF_L3F_SRC].pm_l3v4;
			uint8_t blen = sizeof(v4pfx->pm_bytes);
			uint8_t plen = v4pfx->pm_plen;

			memcpy(curfld->data.ip4, v4pfx->pm_bytes, blen);
			pmf_hw_rule_gen_mask(curfld->mask.ip4, plen, blen);
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
			uint8_t blen = sizeof(v6pfx->pm_bytes);
			uint8_t plen = v6pfx->pm_plen;

			memcpy(curfld->data.ip6, v6pfx->pm_bytes, blen);
			pmf_hw_rule_gen_mask(curfld->mask.ip6, plen, blen);
		} else {
			ent_attrs[nattr].id = FAL_ACL_ENTRY_ATTR_FIELD_DST_IPV4;

			struct pmf_attr_v4_prefix *v4pfx
				= rule->pp_match.l3[PMF_L3F_DST].pm_l3v4;
			uint8_t blen = sizeof(v4pfx->pm_bytes);
			uint8_t plen = v4pfx->pm_plen;

			memcpy(curfld->data.ip4, v4pfx->pm_bytes, blen);
			pmf_hw_rule_gen_mask(curfld->mask.ip4, plen, blen);
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
		curfld->mask.u8 = 0xff;
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
		pmf_arlg_attrl_set_objid(earl, rlobj);

	ok = (!rc || (rc == -EOPNOTSUPP && !grp_was_created));
	ok_str = ok ? ((!rc) ? "OK" : "UN") : "NO";

log_add:
	if (!ok || DP_DEBUG_ENABLED(NPF)) {
		ACL_LOG(ok, ACL_HW,
			"HW-ACLv%s RL Add %s/%s|%s:%u [%lx] %x => %s(%d) [%lx]\n",
			(is_v6) ? "6" : "4",
			(ingress) ? " In" : "Out", ifname, rgname, index,
			grpobj, summary,
			ok_str, rc, rlobj);
	}


	return (!rc && (rlobj != FAL_NULL_OBJECT_ID));
}

void
pmf_hw_rule_del(struct pmf_attrl *earl)
{
	struct pmf_group_ext *earg = pmf_arlg_attrl_get_grp(earl);
	struct pmf_rlset_ext *ears = pmf_arlg_grp_get_rls(earg);
	char const *ifname = pmf_arlg_rls_get_ifname(ears);
	uintptr_t rlobj = pmf_arlg_attrl_get_objid(earl);
	bool was_created = (rlobj != FAL_NULL_OBJECT_ID);
	uint16_t index = pmf_arlg_attrl_get_index(earl);
	bool ingress = pmf_arlg_grp_is_ingress(earg);
	bool is_v6 = pmf_arlg_grp_is_v6(earg);
	char const *rgname = pmf_arlg_grp_get_name(earg);
	bool ok = true;
	char const *ok_str = "SK";
	int rc = 0; /* Success */

	/* Nothing to do if no FAL object - e.g. vrouter */
	if (!was_created)
		goto log_delete;

	pmf_hw_commit_needed = true;

	rc = fal_acl_delete_entry(rlobj);
	if (!rc)
		pmf_arlg_attrl_set_objid(earl, FAL_NULL_OBJECT_ID);

	ok = (!rc || (rc == -EOPNOTSUPP && !was_created));
	ok_str = ok ? ((!rc) ? "OK" : "UN") : "NO";

log_delete:
	if (!ok || DP_DEBUG_ENABLED(NPF)) {
		ACL_LOG(ok, ACL_HW,
			"HW-ACLv%s RL Delete %s/%s|%s:%u [%lx] => %s(%d)\n",
			(is_v6) ? "6" : "4",
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
pmf_hw_rule_mod(struct pmf_attrl *earl, struct pmf_rule *rule)
{
	struct pmf_group_ext *earg = pmf_arlg_attrl_get_grp(earl);
	struct pmf_rlset_ext *ears = pmf_arlg_grp_get_rls(earg);
	char const *ifname = pmf_arlg_rls_get_ifname(ears);
	uintptr_t rlobj = pmf_arlg_attrl_get_objid(earl);
	uint16_t index = pmf_arlg_attrl_get_index(earl);
	bool ingress = pmf_arlg_grp_is_ingress(earg);
	bool is_v6 = pmf_arlg_grp_is_v6(earg);
	char const *rgname = pmf_arlg_grp_get_name(earg);
	bool ok = true;

	if (!ok || DP_DEBUG_ENABLED(NPF)) {
		ACL_LOG(ok, ACL_HW,
			"HW-ACLv%s RL Modify %s/%s|%s:%u [%lx]\n",
			(is_v6) ? "6" : "4",
			(ingress) ? " In" : "Out", ifname, rgname, index,
			rlobj);
	}

	pmf_hw_rule_del(earl);
	pmf_hw_rule_add(earl, rule);
}

/* ---- */

bool
pmf_hw_group_create(struct pmf_group_ext *earg)
{
	struct pmf_rlset_ext *ears = pmf_arlg_grp_get_rls(earg);
	char const *ifname = pmf_arlg_rls_get_ifname(ears);
	uintptr_t grpobj = FAL_NULL_OBJECT_ID;
	bool ingress = pmf_arlg_grp_is_ingress(earg);
	bool is_v6 = pmf_arlg_grp_is_v6(earg);
	char const *rgname = pmf_arlg_grp_get_name(earg);
	uint32_t summary = pmf_arlg_grp_get_summary(earg);

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
		+ !!(summary & PMF_RAS_COUNT_REF);
	struct fal_object_list_t *act_list
		= calloc(1, sizeof(*act_list) +
			    num_actions * sizeof(act_list->list[0]));
	if (!act_list) {
		free(bp_list);
		return false;
	}
	act_list->count = num_actions;
	num_actions = 0;
	if (summary & (PMF_RAS_DROP|PMF_RAS_PASS))
		act_list->list[num_actions++]
				= FAL_ACL_ACTION_TYPE_PACKET_ACTION;
	if (summary & PMF_RAS_COUNT_REF)
		act_list->list[num_actions++] = FAL_ACL_ACTION_TYPE_COUNTER;

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
		pmf_arlg_grp_set_objid(earg, grpobj);

	bool const ok = (!rc || rc == -EOPNOTSUPP);
	char const *ok_str = ok ? ((!rc) ? "OK" : "UN") : "NO";

	if (!ok || DP_DEBUG_ENABLED(NPF)) {
		ACL_LOG(ok, ACL_HW,
			"HW-ACLv%s GP Create %s/%s|%s %x => %s(%d) [%lx]\n",
			(is_v6) ? "6" : "4",
			(ingress) ? " In" : "Out", ifname, rgname, summary,
			ok_str, rc, grpobj);
	}

	return (!rc && (grpobj != FAL_NULL_OBJECT_ID));
}

void
pmf_hw_group_delete(struct pmf_group_ext *earg)
{
	struct pmf_rlset_ext *ears = pmf_arlg_grp_get_rls(earg);
	char const *ifname = pmf_arlg_rls_get_ifname(ears);
	uintptr_t grpobj = pmf_arlg_grp_get_objid(earg);
	bool was_created = (grpobj != FAL_NULL_OBJECT_ID);
	bool ingress = pmf_arlg_grp_is_ingress(earg);
	bool is_v6 = pmf_arlg_grp_is_v6(earg);
	char const *rgname = pmf_arlg_grp_get_name(earg);
	bool ok = true;
	char const *ok_str = "SK";
	int rc = 0; /* Success */

	/* Nothing to do if no FAL object - e.g. vrouter */
	if (!was_created)
		goto log_delete;

	pmf_hw_commit_needed = true;

	rc = fal_acl_delete_table(grpobj);
	if (!rc)
		pmf_arlg_grp_set_objid(earg, FAL_NULL_OBJECT_ID);

	ok = (!rc || (rc == -EOPNOTSUPP && !was_created));
	ok_str = ok ? ((!rc) ? "OK" : "UN") : "NO";

log_delete:
	if (!ok || DP_DEBUG_ENABLED(NPF)) {
		ACL_LOG(ok, ACL_HW,
			"HW-ACLv%s GP Delete %s/%s|%s [%lx] => %s(%d)\n",
			(is_v6) ? "6" : "4",
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
pmf_hw_group_mod(struct pmf_group_ext *earg, uint32_t new)
{
	struct pmf_rlset_ext *ears = pmf_arlg_grp_get_rls(earg);
	char const *ifname = pmf_arlg_rls_get_ifname(ears);
	uintptr_t grpobj = pmf_arlg_grp_get_objid(earg);
	bool ingress = pmf_arlg_grp_is_ingress(earg);
	bool is_v6 = pmf_arlg_grp_is_v6(earg);
	char const *rgname = pmf_arlg_grp_get_name(earg);
	uint32_t old = pmf_arlg_grp_get_summary(earg);
	uint32_t chg = old ^ new;
	uint32_t set = chg &  new;
	uint32_t clr = chg & ~new;
	bool ok = true;

	if (!ok || DP_DEBUG_ENABLED(NPF)) {
		ACL_LOG(ok, ACL_HW,
			"HW-ACLv%s GP Modify %s/%s|%s [%lx] old %x set %x clr %x\n",
			(is_v6) ? "6" : "4",
			(ingress) ? " In" : "Out", ifname, rgname, grpobj,
			old, set, clr);
	}
}

/* ---- */

bool
pmf_hw_group_attach(struct pmf_group_ext *earg, struct ifnet *ifp)
{
	uintptr_t grpobj = pmf_arlg_grp_get_objid(earg);
	bool ingress = pmf_arlg_grp_is_ingress(earg);
	bool is_v6 = pmf_arlg_grp_is_v6(earg);
	char const *rgname = pmf_arlg_grp_get_name(earg);
	char const *ifname = ifp->if_name;
	bool ok = true;
	char const *ok_str = "SK";
	int rc = 0; /* Success */

	/* Nothing to do if no FAL object - e.g. vrouter */
	if (grpobj == FAL_NULL_OBJECT_ID)
		goto log_attach;

	struct fal_attribute_t acl;

	acl.value.objid = grpobj;

	if (ingress) {
		if (is_v6)
			acl.id = FAL_ROUTER_INTERFACE_ATTR_V6_INGRESS_ACL;
		else
			acl.id = FAL_ROUTER_INTERFACE_ATTR_V4_INGRESS_ACL;
	} else {
		if (is_v6)
			acl.id = FAL_ROUTER_INTERFACE_ATTR_V6_EGRESS_ACL;
		else
			acl.id = FAL_ROUTER_INTERFACE_ATTR_V4_EGRESS_ACL;
	}

	pmf_hw_commit_needed = true;

	rc = if_set_l3_intf_attr(ifp, &acl);

	ok = (!rc || rc == -EOPNOTSUPP);
	ok_str = ok ? ((!rc) ? "OK" : "UN") : "NO";

log_attach:
	if (!ok || DP_DEBUG_ENABLED(NPF)) {
		ACL_LOG(ok, ACL_HW,
			"HW-ACLv%s GP Attach %s/%s|%s [%lx] => %s(%d)\n",
			(is_v6) ? "6" : "4",
			(ingress) ? " In" : "Out", ifname, rgname, grpobj,
			ok_str, rc);
	}

	return (!rc && (grpobj != FAL_NULL_OBJECT_ID));
}

void
pmf_hw_group_detach(struct pmf_group_ext *earg, struct ifnet *ifp)
{
	uintptr_t grpobj = pmf_arlg_grp_get_objid(earg);
	bool was_attached = pmf_arlg_grp_is_ll_attached(earg);
	bool ingress = pmf_arlg_grp_is_ingress(earg);
	bool is_v6 = pmf_arlg_grp_is_v6(earg);
	char const *rgname = pmf_arlg_grp_get_name(earg);
	char const *ifname = ifp->if_name;
	bool ok = true;
	char const *ok_str = "SK";
	int rc = 0; /* Success */

	/* Nothing to do if attach failed or skipped */
	if (!was_attached)
		goto log_detach;

	struct fal_attribute_t acl;

	acl.value.objid = FAL_NULL_OBJECT_ID;

	if (ingress) {
		if (is_v6)
			acl.id = FAL_ROUTER_INTERFACE_ATTR_V6_INGRESS_ACL;
		else
			acl.id = FAL_ROUTER_INTERFACE_ATTR_V4_INGRESS_ACL;
	} else {
		if (is_v6)
			acl.id = FAL_ROUTER_INTERFACE_ATTR_V6_EGRESS_ACL;
		else
			acl.id = FAL_ROUTER_INTERFACE_ATTR_V4_EGRESS_ACL;
	}

	pmf_hw_commit_needed = true;

	rc = if_set_l3_intf_attr(ifp, &acl);

	ok = (!rc || (rc == -EOPNOTSUPP && !was_attached));
	ok_str = ok ? ((!rc) ? "OK" : "UN") : "NO";

log_detach:
	if (!ok || DP_DEBUG_ENABLED(NPF)) {
		ACL_LOG(ok, ACL_HW,
			"HW-ACLv%s GP Detach %s/%s|%s [%lx] => %s(%d)\n",
			(is_v6) ? "6" : "4",
			(ingress) ? " In" : "Out", ifname, rgname, grpobj,
			ok_str, rc);
	}
}

/* ---- */

bool
pmf_hw_counter_create(struct pmf_cntr *eark)
{
	struct pmf_group_ext *earg = pmf_arlg_cntr_get_grp(eark);
	struct pmf_rlset_ext *ears = pmf_arlg_grp_get_rls(earg);
	char const *ifname = pmf_arlg_rls_get_ifname(ears);
	uintptr_t grpobj = pmf_arlg_grp_get_objid(earg);
	bool grp_was_created = (grpobj != FAL_NULL_OBJECT_ID);
	uintptr_t ctrobj = FAL_NULL_OBJECT_ID;
	char const *ctname = pmf_arlg_cntr_get_name(eark);
	bool ingress = pmf_arlg_grp_is_ingress(earg);
	bool is_v6 = pmf_arlg_grp_is_v6(earg);
	char const *rgname = pmf_arlg_grp_get_name(earg);
	bool cnt_pkt = pmf_arlg_cntr_pkt_enabled(eark);
	bool cnt_byt = pmf_arlg_cntr_byt_enabled(eark);
	bool ok = true;
	char const *ok_str = "SK";
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
		pmf_arlg_cntr_set_objid(eark, ctrobj);

	ok = (!rc || (rc == -EOPNOTSUPP && !grp_was_created));
	ok_str = ok ? ((!rc) ? "OK" : "UN") : "NO";

log_create:
	if (!ok || DP_DEBUG_ENABLED(NPF)) {
		ACL_LOG(ok, ACL_HW,
			"HW-ACLv%s CT Add %s/%s|%s:%s [%lx]%s%s => %s(%d) [%lx]\n",
			(is_v6) ? "6" : "4",
			(ingress) ? " In" : "Out", ifname, rgname, ctname,
			grpobj,
			(cnt_pkt) ? " Pkt" : "",
			(cnt_byt) ? " Byt" : "",
			ok_str, rc, ctrobj);
	}


	return (!rc && (ctrobj != FAL_NULL_OBJECT_ID));
}

void
pmf_hw_counter_delete(struct pmf_cntr *eark)
{
	struct pmf_group_ext *earg = pmf_arlg_cntr_get_grp(eark);
	struct pmf_rlset_ext *ears = pmf_arlg_grp_get_rls(earg);
	char const *ifname = pmf_arlg_rls_get_ifname(ears);
	uintptr_t ctrobj = pmf_arlg_cntr_get_objid(eark);
	bool was_created = (ctrobj != FAL_NULL_OBJECT_ID);
	char const *ctname = pmf_arlg_cntr_get_name(eark);
	bool ingress = pmf_arlg_grp_is_ingress(earg);
	bool is_v6 = pmf_arlg_grp_is_v6(earg);
	char const *rgname = pmf_arlg_grp_get_name(earg);
	bool ok = true;
	char const *ok_str = "SK";
	int rc = 0; /* Success */

	/* Nothing to do if no FAL object - e.g. vrouter */
	if (!was_created)
		goto log_delete;

	pmf_hw_commit_needed = true;

	rc = fal_acl_delete_counter(ctrobj);
	if (!rc)
		pmf_arlg_cntr_set_objid(eark, FAL_NULL_OBJECT_ID);

	ok = (!rc || (rc == -EOPNOTSUPP && !was_created));
	ok_str = ok ? ((!rc) ? "OK" : "UN") : "NO";

log_delete:
	if (!ok || DP_DEBUG_ENABLED(NPF)) {
		ACL_LOG(ok, ACL_HW,
			"HW-ACLv%s CT Delete %s/%s|%s:%s [%lx] => %s(%d)\n",
			(is_v6) ? "6" : "4",
			(ingress) ? " In" : "Out", ifname, rgname, ctname,
			ctrobj,
			ok_str, rc);
	}
}

bool
pmf_hw_counter_clear(struct pmf_cntr const *eark)
{
	struct pmf_group_ext *earg = pmf_arlg_cntr_get_grp(eark);
	struct pmf_rlset_ext *ears = pmf_arlg_grp_get_rls(earg);
	char const *ifname = pmf_arlg_rls_get_ifname(ears);
	uintptr_t ctrobj = pmf_arlg_cntr_get_objid(eark);
	bool was_created = (ctrobj != FAL_NULL_OBJECT_ID);
	char const *ctname = pmf_arlg_cntr_get_name(eark);
	bool ingress = pmf_arlg_grp_is_ingress(earg);
	bool is_v6 = pmf_arlg_grp_is_v6(earg);
	char const *rgname = pmf_arlg_grp_get_name(earg);
	bool cnt_pkt = pmf_arlg_cntr_pkt_enabled(eark);
	bool cnt_byt = pmf_arlg_cntr_byt_enabled(eark);
	bool ok = true;
	char const *ok_str_pkt = "SK";
	char const *ok_str_byt = "SK";
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
			"HW-ACLv%s CT Clr %s/%s|%s:%s [%lx]%s%s =>"
				" P:%s(%d) B:%s(%d)\n",
			(is_v6) ? "6" : "4",
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
pmf_hw_counter_read(struct pmf_cntr const *eark,
		    uint64_t *pkts, uint64_t *bytes)
{
	struct pmf_group_ext *earg = pmf_arlg_cntr_get_grp(eark);
	struct pmf_rlset_ext *ears = pmf_arlg_grp_get_rls(earg);
	char const *ifname = pmf_arlg_rls_get_ifname(ears);
	uintptr_t ctrobj = pmf_arlg_cntr_get_objid(eark);
	bool was_created = (ctrobj != FAL_NULL_OBJECT_ID);
	char const *ctname = pmf_arlg_cntr_get_name(eark);
	bool ingress = pmf_arlg_grp_is_ingress(earg);
	bool is_v6 = pmf_arlg_grp_is_v6(earg);
	char const *rgname = pmf_arlg_grp_get_name(earg);
	bool cnt_pkt = pmf_arlg_cntr_pkt_enabled(eark);
	bool cnt_byt = pmf_arlg_cntr_byt_enabled(eark);
	bool ok = true;
	char const *ok_str = "SK";
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
			"HW-ACLv%s CT Get %s/%s|%s:%s [%lx]%s%s => %s(%d)\n",
			(is_v6) ? "6" : "4",
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
