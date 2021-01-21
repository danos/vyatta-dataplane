/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "pmf_rule.h"

/* Manipulate a parsed rule */

void
pmf_rule_extension_free(struct pmf_pext_list **ext_p)
{
	struct pmf_pext_list *rpexts = *ext_p;

	if (!rpexts)
		return;

	unsigned int num_rprocs = rpexts->pm_num;

	/* Free per rproc */
	for (uint32_t idx = 0; idx < num_rprocs; ++idx) {
		union pmf_proc *proc = &rpexts->pm_procs[idx];

		free(proc->pp_any);
		proc->pp_any = NULL;
	}

	free(rpexts);
	*ext_p = NULL;
}

static void
pmf_rule_dealloc(struct pmf_rule *rule)
{
	if (!rule)
		return;

	/* Free any match elements */
	pmf_rule_extension_free(&rule->pp_match.extend);
	for (uint32_t idx = 0; idx < PMF_L2F__LEN; ++idx)
		if (rule->pp_match.l2[idx].pm_any) {
			free(rule->pp_match.l2[idx].pm_any);
			rule->pp_match.l2[idx].pm_any = NULL;
		}

	for (uint32_t idx = 0; idx < PMF_L3F__LEN; ++idx)
		if (rule->pp_match.l3[idx].pm_any) {
			free(rule->pp_match.l3[idx].pm_any);
			rule->pp_match.l3[idx].pm_any = NULL;
		}

	for (uint32_t idx = 0; idx < PMF_L4F__LEN; ++idx)
		if (rule->pp_match.l4[idx].pm_any) {
			free(rule->pp_match.l4[idx].pm_any);
			rule->pp_match.l4[idx].pm_any = NULL;
		}

	/* Free any action elements */
	pmf_rule_extension_free(&rule->pp_action.extend);
	pmf_rule_extension_free(&rule->pp_action.handle);

	/* Free any nat elements */
	if (rule->pp_action.nat) {
		struct pmf_nat *nat = rule->pp_action.nat;

		if (nat->pan_taddr.any) {
			free(nat->pan_taddr.any);
			nat->pan_taddr.any = NULL;
		}
		if (nat->pan_tports) {
			free(nat->pan_tports);
			nat->pan_tports = NULL;
		}
		free(nat);
		rule->pp_action.nat = NULL;
	}

	/* Free any qos mark elements */
	if (rule->pp_action.qos_mark) {
		struct pmf_qos_mark *qos_mark = rule->pp_action.qos_mark;

		free(qos_mark);
		rule->pp_action.qos_mark = NULL;
	}

	free(rule);
}

void
pmf_rule_free(struct pmf_rule *rule)
{
	if (!rule)
		return;
	if (!rule->pp_refcnt)
		return;

	if (!--rule->pp_refcnt)
		pmf_rule_dealloc(rule);
}

/* This only copies leaf elements */
void *
pmf_leaf_attr_copy(void *attr)
{
	struct pmf_attr_any *a_any = attr;
	struct pmf_attr_group_ref *a_ref = attr;
	struct pmf_proc_raw *a_praw = attr;

	enum pmf_mtag attr_tag = a_any->pm_tag;
	uint32_t attr_size;

	switch (attr_tag) {
	case PMAT_ETH_MAC:
		attr_size = sizeof(struct pmf_attr_emac);
		break;
	case PMAT_ETH_TYPE:
		attr_size = sizeof(struct pmf_attr_etype);
		break;
	case PMAT_ETH_PCP:
		attr_size = sizeof(struct pmf_attr_epcp);
		break;
	case PMAT_IP_FAMILY:
		attr_size = sizeof(struct pmf_attr_ip_family);
		break;
	case PMAT_IPV4_PREFIX:
		attr_size = sizeof(struct pmf_attr_v4_prefix);
		break;
	case PMAT_IPV6_PREFIX:
		attr_size = sizeof(struct pmf_attr_v6_prefix);
		break;
	case PMAT_IPV4_RANGE:
		attr_size = sizeof(struct pmf_attr_v4_range);
		break;
	case PMAT_IP_PROTO:
		attr_size = sizeof(struct pmf_attr_proto);
		break;
	case PMAT_IP_DSCP:
		attr_size = sizeof(struct pmf_attr_dscp);
		break;
	case PMAT_IP_TTL:
		attr_size = sizeof(struct pmf_attr_ttl);
		break;
	case PMAT_IP_FRAG:
		attr_size = sizeof(struct pmf_attr_frag);
		break;
	case PMAT_IPV6_RH:
		attr_size = sizeof(struct pmf_attr_v6_rh);
		break;
	case PMAT_L4_PORT_RANGE:
		attr_size = sizeof(struct pmf_attr_l4port_range);
		break;
	case PMAT_L4_TCP_FLAGS:
		attr_size = sizeof(struct pmf_attr_l4tcp_flags);
		break;
	case PMAT_L4_ICMP_V4_VALS:
	case PMAT_L4_ICMP_V6_VALS:
		attr_size = sizeof(struct pmf_attr_l4icmp_vals);
		break;
	case PMAT_GROUP_REF:
		attr_size = sizeof(struct pmf_attr_group_ref);
		attr_size += a_ref->pm_nlen;
		break;
	case PMAT_RPROC_RAW:
		attr_size = sizeof(struct pmf_proc_raw);
		attr_size += a_praw->pm_dlen;
		break;
	case PMAT_L4_ICMP_V4_GROUP:
	case PMAT_L4_ICMP_V6_GROUP:
	case PMAT_IP_ADDR_GROUP:
	case PMAT_IP_PROTO_GROUP:
	case PMAT_IP_DSCP_GROUP:
	case PMAT_L4_PORT_GROUP:
	case PMAT_MEXTENSION:
	case PMAT_AEXTENSION:
	case PMAT_HEXTENSION:
	default:
		return NULL;
	}

	void *attr_copy = malloc(attr_size);
	if (!attr_copy)
		return NULL;

	memcpy(attr_copy, attr, attr_size);

	return attr_copy;
}

/* This copies an proc extension element and its leaves */
struct pmf_pext_list *
pmf_pexts_attr_copy(struct pmf_pext_list *old_exts)
{
	switch (old_exts->pm_tag) {
	case PMAT_MEXTENSION:
	case PMAT_AEXTENSION:
	case PMAT_HEXTENSION:
		break;
	default:
		return NULL;
	}

	uint32_t nprocs = old_exts->pm_num;
	uint32_t attr_size = sizeof(*old_exts)
				+ nprocs * sizeof(old_exts->pm_procs[0]);

	struct pmf_pext_list *new_exts = malloc(attr_size);
	if (!new_exts)
		return NULL;

	/* Re-init to avoid stale pointers */
	memset(new_exts, 0, attr_size);
	new_exts->pm_tag = old_exts->pm_tag;
	new_exts->pm_unknown = old_exts->pm_unknown;
	new_exts->pm_num = old_exts->pm_num;

	for (uint32_t idx = 0; idx < nprocs; ++idx) {
		union pmf_proc *proc = &old_exts->pm_procs[idx];
		struct pmf_proc_any *p_any = proc->pp_any;
		if (!p_any)
			continue;
		void *proc_new = pmf_leaf_attr_copy(p_any);
		if (!proc_new) {
			pmf_rule_extension_free(&new_exts);
			return NULL;
		}
		new_exts->pm_procs[idx].pp_any = proc_new;
	}

	return new_exts;
}

static struct pmf_rule *
pmf_rule_slow_copy(struct pmf_rule *old_rule)
{
	if (!old_rule)
		return NULL;

	struct pmf_rule *new_rule = pmf_rule_alloc();
	if (!new_rule) {
error_exit:
		pmf_rule_dealloc(new_rule);
		return NULL;
	}

	/* Copy any match elements */
	for (uint32_t idx = 0; idx < PMF_L2F__LEN; ++idx) {
		void *old_attr = old_rule->pp_match.l2[idx].pm_any;
		if (!old_attr)
			continue;
		void *new_attr = pmf_leaf_attr_copy(old_attr);
		if (!new_attr)
			goto error_exit;

		new_rule->pp_match.l2[idx].pm_any = new_attr;
	}

	for (uint32_t idx = 0; idx < PMF_L3F__LEN; ++idx) {
		void *old_attr = old_rule->pp_match.l3[idx].pm_any;
		if (!old_attr)
			continue;
		void *new_attr = pmf_leaf_attr_copy(old_attr);
		if (!new_attr)
			goto error_exit;

		new_rule->pp_match.l3[idx].pm_any = new_attr;
	}

	for (uint32_t idx = 0; idx < PMF_L4F__LEN; ++idx) {
		void *old_attr = old_rule->pp_match.l4[idx].pm_any;
		if (!old_attr)
			continue;
		void *new_attr = pmf_leaf_attr_copy(old_attr);
		if (!new_attr)
			goto error_exit;

		new_rule->pp_match.l4[idx].pm_any = new_attr;
	}

	/* Copy any nat elements */
	if (old_rule->pp_action.nat) {
		struct pmf_nat *old_nat = old_rule->pp_action.nat;

		struct pmf_nat *new_nat = malloc(sizeof(*new_nat));
		if (!new_nat)
			goto error_exit;

		memcpy(new_nat, old_nat, sizeof(*new_nat));
		new_nat->pan_tports = NULL;
		new_nat->pan_taddr.any = NULL;
		new_rule->pp_action.nat = new_nat;

		if (old_nat->pan_taddr.any) {
			void *old_attr = old_nat->pan_taddr.any;
			void *new_attr = pmf_leaf_attr_copy(old_attr);
			if (!new_attr)
				goto error_exit;
			new_nat->pan_taddr.any = new_attr;
		}
		if (old_nat->pan_tports) {
			void *old_attr = old_nat->pan_tports;
			void *new_attr = pmf_leaf_attr_copy(old_attr);
			if (!new_attr)
				goto error_exit;
			new_nat->pan_tports = new_attr;
		}
	}

	/* Copy any qos mark elements */
	if (old_rule->pp_action.qos_mark) {
		struct pmf_qos_mark *old_mark = old_rule->pp_action.qos_mark;

		struct pmf_qos_mark *new_mark = malloc(sizeof(*new_mark));
		if (!new_mark)
			goto error_exit;

		memcpy(new_mark, old_mark, sizeof(*new_mark));
		new_rule->pp_action.qos_mark = new_mark;
	}

	/* Copy values */
	new_rule->pp_action.fate = old_rule->pp_action.fate;
	new_rule->pp_action.stateful = old_rule->pp_action.stateful;

	/* Now copy rprocs */

	if (old_rule->pp_match.extend) {
		struct pmf_pext_list *old_ext = old_rule->pp_match.extend;
		struct pmf_pext_list *new_ext = pmf_pexts_attr_copy(old_ext);
		if (!new_ext)
			goto error_exit;
		new_rule->pp_match.extend = new_ext;
	}

	if (old_rule->pp_action.extend) {
		struct pmf_pext_list *old_ext = old_rule->pp_action.extend;
		struct pmf_pext_list *new_ext = pmf_pexts_attr_copy(old_ext);
		if (!new_ext)
			goto error_exit;
		new_rule->pp_action.extend = new_ext;
	}

	if (old_rule->pp_action.handle) {
		struct pmf_pext_list *old_ext = old_rule->pp_action.handle;
		struct pmf_pext_list *new_ext = pmf_pexts_attr_copy(old_ext);
		if (!new_ext)
			goto error_exit;
		new_rule->pp_action.handle = new_ext;
	}

	return new_rule;
}

struct pmf_rule *
pmf_rule_copy(struct pmf_rule *old_rule)
{
	if (!old_rule)
		return NULL;

	if (old_rule->pp_refcnt == UINT32_MAX)
		return pmf_rule_slow_copy(old_rule);

	++old_rule->pp_refcnt;

	return old_rule;
}

struct pmf_attr_v6_prefix *
pmf_v6_prefix_create(bool invert, uint8_t plen, void *bytes)
{
	struct pmf_attr_v6_prefix *pfx = malloc(sizeof(*pfx));
	if (!pfx)
		return NULL;

	pfx->pm_tag = PMAT_IPV6_PREFIX;
	pfx->pm_invert = invert;
	pfx->pm_plen = plen;

	memcpy(pfx->pm_bytes, bytes, sizeof(pfx->pm_bytes));

	return pfx;
}

struct pmf_attr_v4_prefix *
pmf_v4_prefix_create(bool invert, uint8_t plen, void *bytes)
{
	struct pmf_attr_v4_prefix *pfx = malloc(sizeof(*pfx));
	if (!pfx)
		return NULL;

	pfx->pm_tag = PMAT_IPV4_PREFIX;
	pfx->pm_invert = invert;
	pfx->pm_plen = plen;

	memcpy(pfx->pm_bytes, bytes, sizeof(pfx->pm_bytes));

	return pfx;
}

static struct pmf_attr_group_ref *
pmf_group_ref_alloc(char const *name, uint8_t ref_tag)
{
	uint32_t name_len = 1 + strlen(name);
	if (name_len > UINT8_MAX)
		return NULL;

	struct pmf_attr_group_ref *ref = malloc(sizeof(*ref) + name_len);
	if (!ref)
		return NULL;

	ref->pm_tag = PMAT_GROUP_REF;
	ref->pm_ref = ref_tag;
	ref->pm_nlen = name_len;

	memcpy(&ref->pm_name, name, name_len);

	return ref;
}

struct pmf_attr_group_ref *
pmf_create_addr_group_ref(char const *name)
{
	return pmf_group_ref_alloc(name, PMAT_IP_ADDR_GROUP);
}

struct pmf_attr_group_ref *
pmf_create_proto_group_ref(char const *name)
{
	return pmf_group_ref_alloc(name, PMAT_IP_PROTO_GROUP);
}

struct pmf_attr_group_ref *
pmf_create_dscp_group_ref(char const *name)
{
	return pmf_group_ref_alloc(name, PMAT_IP_DSCP_GROUP);
}

struct pmf_attr_group_ref *
pmf_create_port_group_ref(char const *name)
{
	return pmf_group_ref_alloc(name, PMAT_L4_PORT_GROUP);
}

struct pmf_attr_group_ref *
pmf_create_icmp_group_ref(char const *name, bool is_v6)
{
	if (is_v6)
		return pmf_group_ref_alloc(name, PMAT_L4_ICMP_V6_GROUP);

	return pmf_group_ref_alloc(name, PMAT_L4_ICMP_V4_GROUP);
}

struct pmf_nat *
pmf_nat_create(void)
{
	struct pmf_nat *nat = malloc(sizeof(*nat));
	if (!nat)
		return NULL;

	nat->pan_type = PMN_UNSET;
	nat->pan_pinhole = PMV_UNSET;
	nat->pan_exclude = PMV_UNSET;
	nat->pan_masquerade = PMV_UNSET;
	nat->pan_taddr.any = NULL;
	nat->pan_tports = NULL;

	return nat;
}

struct pmf_qos_mark *
pmf_qos_mark_create(void)
{
	struct pmf_qos_mark *qos_mark = malloc(sizeof(*qos_mark));
	if (!qos_mark)
		return NULL;

	qos_mark->paqm_has_desig = PMV_UNSET;
	qos_mark->paqm_desig = 0;
	qos_mark->paqm_colour = PMMC_UNSET;

	return qos_mark;
}

static struct pmf_pext_list *
pmf_rproc_list_create(uint32_t num, uint8_t tag)
{
	if (num > UINT8_MAX)
		return NULL;

	struct pmf_pext_list *rpexts =
		calloc(1, sizeof(*rpexts) + num * sizeof(rpexts->pm_procs[0]));
	if (!rpexts)
		return NULL;

	rpexts->pm_num = num;
	rpexts->pm_unknown = num;
	rpexts->pm_tag = tag;

	return rpexts;
}

struct pmf_pext_list *
pmf_rproc_mlist_create(uint32_t num)
{
	return pmf_rproc_list_create(num, PMAT_MEXTENSION);
}

struct pmf_pext_list *
pmf_rproc_alist_create(uint32_t num)
{
	return pmf_rproc_list_create(num, PMAT_AEXTENSION);
}

struct pmf_pext_list *
pmf_rproc_hlist_create(uint32_t num)
{
	return pmf_rproc_list_create(num, PMAT_HEXTENSION);
}

struct pmf_proc_raw *
pmf_rproc_raw_create(uint32_t data_len, void *data)
{
	if (data_len > UINT16_MAX)
		return NULL;

	struct pmf_proc_raw *praw = calloc(1, sizeof(*praw) + data_len);
	if (!praw)
		return NULL;

	praw->pm_tag = PMAT_RPROC_RAW;
	praw->pm_id = PMP_RAW_ID_UNSET;
	praw->pm_dlen = data_len;
	praw->pm_argoff = 0;
	memcpy(praw->pm_name, data, data_len);

	return praw;
}

struct pmf_rule *
pmf_rule_alloc(void)
{
	struct pmf_rule *rule = calloc(1, sizeof(*rule));

	rule->pp_refcnt = 1;

	return rule;
}
