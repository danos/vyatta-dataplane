/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * vlan_modify.c  Build lists of tc filter and actions  to apply
 * as ingress and egress vlan modifications
 *
 *
 * <chain_head>
 *       \
 *     <chain_entry>-----<chain_entry>-----<chain_entry>
 *          |                 |			|
 *          |                 |			|
 *    <filter_entry>    <filter_entry>    <filter_entry>
 *                            |			|
 *                            |			|
 *                      <filter_entry>    <filter_entry>
 *                            |
 *                            |
 *                      <filter_entry>
 *
 *
 *  Key of chain entry  is a less specific of  the key
 *  for filter entry.
 *
 *   <filter_entry>
 *    classify_entry[]
 *    action_entry>[]
 *
 *  A filter classification is the compound of all the
 *  classify_entries attached.  A filter action is the compound of all
 *  the action_entries attached.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <zmq.h>
#include <errno.h>
#include "urcu.h"
#include <czmq.h>
#include <inttypes.h>
#include <libmnl/libmnl.h>
#include <netinet/in.h>
#include <rte_debug.h>
#include <rte_log.h>
#include <linux/pkt_cls.h>
#include <linux/tc_act/tc_vlan.h>
#include "vplane_debug.h"
#include "vplane_log.h"
#include "json_writer.h"
#include "if_var.h"
#include "util.h"
#include "vlan_modify.h"
#include "pipeline/nodes/pl_nodes_common.h"
#include "pl_node.h"
#include "pl_common.h"

#define VLAN_MOD_FLT_KEY_STR_LEN 64
#define MAX_TC_FLT_CLS 2

struct vlan_mod_ft_cls_u32_sel {
	bool valid;
	uint32_t val;
	uint32_t mask;
	int offmask; // Is this needed
	int off;
};

struct vlan_mod_tc_filter_key {
	int ifindex;
	uint32_t parent;
	uint32_t chain;
	uint16_t priority;
};

struct  vlan_mod_filter_list_head {
	struct cds_list_head list_head;
	uint32_t list_count;
};

struct  vlan_mod_chain_list_entry {
	struct cds_list_head  chain_next;
	struct vlan_mod_tc_filter_key key;
	struct rcu_head chain_rcu;
	struct vlan_mod_filter_list_head filter_head;
	struct vlan_mod_tbl_entry *tbl;
	struct vlan_mod_tbl_entry *vlan_mod_default;
	void *lookup_table;
};

struct  vlan_mod_filter_list_entry {
	struct cds_list_head list_next;
	struct vlan_mod_tc_filter_key key;
	struct vlan_mod_chain_list_entry *parent;
	struct rcu_head list_rcu;
	struct vlan_mod_ft_cls_u32_sel classify[MAX_TC_FLT_CLS];
	struct vlan_mod_ft_cls_action actions[VLAN_MOD_MAX_TC_FLT_ACT];
};

/*
 * Head of the list of chains.
 */
static struct vlan_mod_filter_list_head *filter_chain_head;

static void
vlan_mod_flt_log_u32_key(const struct vlan_mod_ft_cls_u32_sel *entry)
{
	RTE_LOG(INFO, DATAPLANE,
		"vlan_mod: match %08x/%08x at %s%d\n",
		(unsigned int)ntohl(entry->val),
		(unsigned int)ntohl(entry->mask),
		entry->offmask ? "nexthdr+" : "",
		entry->off);
}

static void
vlan_mod_flt_log_act_vlan(const struct vlan_mod_ft_cls_act_vlan *entry)
{
	RTE_LOG(INFO, DATAPLANE,
		"vlan_mod:Act_vlan rule %u act %u vlan %u %d, %d\n",
		entry->rule, entry->action, entry->vlan_id, entry->proto,
		entry->prio);
}

static void
vlan_mod_flt_log_action(struct vlan_mod_ft_cls_action *action)
{
	switch (action->action_type) {
	case VLAN_MOD_FILTER_CLS_ACTION_VLAN:
		vlan_mod_flt_log_act_vlan(&action->data.vlan);
		break;
	case VLAN_MOD_FILTER_CLS_ACTION_MIRRED:
		RTE_LOG(NOTICE, DATAPLANE, "Act_mirred:\n");
		break;
	default:
		RTE_LOG(NOTICE, DATAPLANE, "Act_unknown:\n");
	}
}

static void
extract_u32_keys(const struct tc_u32_key *key,
		 struct vlan_mod_ft_cls_u32_sel *entry)
{
	entry->valid = true;
	entry->val = key->val;
	entry->mask = key->mask;
	entry->offmask = key->offmask;
	entry->off = key->off;

	vlan_mod_flt_log_u32_key(entry);
}

static int
vlan_mod_flt_attr_cmn(const struct nlattr *attr, void *data, uint max)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attr to avoid issues with newer kernels */
	if (mnl_attr_type_valid(attr, max) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

static int
vlan_mod_flt_u32_attr(const struct nlattr *attr, void *data)
{
	return vlan_mod_flt_attr_cmn(attr, data, TCA_U32_MAX);
}

static int
vlan_mod_flt_act_vlan_attr(const struct nlattr *attr, void *data)
{
	return vlan_mod_flt_attr_cmn(attr, data, TCA_VLAN_MAX);
}

static int
vlan_mod_flt_act_attr(const struct nlattr *attr, void *data)
{
	return vlan_mod_flt_attr_cmn(attr, data, TCA_ACT_MAX_PRIO);
}

static int
vlan_mod_flt_act_attrs(const struct nlattr *attr, void *data)
{
	return vlan_mod_flt_attr_cmn(attr, data, TCA_ACT_MAX);
}

static int vlan_mod_mod_filter_attr(const struct nlattr *attr, void *data)
{
	return vlan_mod_flt_attr_cmn(attr, data, TCA_MAX);
}

static void
vlan_mod_flt_extr_cls_act_vlan_act(struct vlan_mod_ft_cls_act_vlan *vlan_act,
				   struct nlattr *tb[],
				   struct tc_vlan *parm,
				   int action)
{
	vlan_act->action = action;

	if (tb[TCA_VLAN_PUSH_VLAN_ID])
		vlan_act->vlan_id =
			mnl_attr_get_u32(tb[TCA_VLAN_PUSH_VLAN_ID]);
	else
		vlan_act->vlan_id = 0;

	if (tb[TCA_VLAN_PUSH_VLAN_PROTOCOL])
		vlan_act->proto = ntohs(
			mnl_attr_get_u32(tb[TCA_VLAN_PUSH_VLAN_PROTOCOL]));
	else
		vlan_act->proto = 0;

	if (tb[TCA_VLAN_PUSH_VLAN_PRIORITY])
		vlan_act->prio =
			mnl_attr_get_u32(tb[TCA_VLAN_PUSH_VLAN_PRIORITY]);
	else
		vlan_act->prio = -1;

	vlan_act->rule =  parm->index;
}

static int
vlan_mod_flt_parse_act_vlan(const struct nlattr *base_tb,
			     struct vlan_mod_ft_cls_action *vlan_act)
{
	struct nlattr *tb[TCA_VLAN_MAX + 1] = { NULL };
	struct tc_vlan *parm;

	if (mnl_attr_parse_nested(base_tb, vlan_mod_flt_act_vlan_attr,
				  tb) != MNL_CB_OK) {
		RTE_LOG(ERR, DATAPLANE, "vlan_mod: parse vlan attr failed\n");
		return MNL_CB_ERROR;
	}

	if (!tb[TCA_VLAN_PARMS]) {
		RTE_LOG(ERR, DATAPLANE, "vlan_mod: no vlan actions\n");
		return MNL_CB_ERROR;
	}

	vlan_act->action_type = VLAN_MOD_FILTER_CLS_ACTION_VLAN;

	parm = mnl_attr_get_payload(tb[TCA_VLAN_PARMS]);

	switch (parm->v_action) {
	case TCA_VLAN_ACT_POP:
		vlan_mod_flt_extr_cls_act_vlan_act(
			&vlan_act->data.vlan, tb, parm,
			VLAN_MOD_FILTER_ACT_VLAN_POP);
		break;
	case TCA_VLAN_ACT_PUSH:
		vlan_mod_flt_extr_cls_act_vlan_act(
			&vlan_act->data.vlan, tb, parm,
			VLAN_MOD_FILTER_ACT_VLAN_PUSH);
		break;
	case TCA_VLAN_ACT_MODIFY:
		vlan_mod_flt_extr_cls_act_vlan_act(
			&vlan_act->data.vlan, tb, parm,
			VLAN_MOD_FILTER_ACT_VLAN_MOD);
		break;
	default:
		RTE_LOG(ERR, DATAPLANE,
			"vlan_mod: unsupported vlan_act\n");
		return MNL_CB_ERROR;
	}

	vlan_mod_flt_log_action(vlan_act);

	return MNL_CB_OK;
}

static int
vlan_mod_flt_parse_act_generic(uint32_t action_type,
				struct vlan_mod_ft_cls_action *action)
{
	action->action_type = action_type;

	vlan_mod_flt_log_action(action);

	return MNL_CB_OK;
}

static int vlan_mod_flt_parse_cls_one_action(const struct nlattr *action_attr,
				       struct vlan_mod_ft_cls_action *entry)
{
	struct nlattr *tb[TCA_ACT_MAX + 1] = { NULL };
	const char *kind;

	if (mnl_attr_parse_nested(action_attr, vlan_mod_flt_act_attrs,
				  tb) != MNL_CB_OK) {
		RTE_LOG(ERR, DATAPLANE, "vlan_mod: parse vlan attrs failed\n");
		return MNL_CB_ERROR;
	}

	if (tb[TCA_ACT_KIND] == NULL) {
		RTE_LOG(ERR, DATAPLANE, "vlan_mod: parse vlan attrs failed\n");
		return MNL_CB_ERROR;
	}

	kind = mnl_attr_get_str(tb[TCA_KIND]);

	entry->eos = false;

	if (!strcmp(kind, "vlan"))
		return vlan_mod_flt_parse_act_vlan(tb[TCA_ACT_OPTIONS],
							  entry);

	if (!strcmp(kind, "mirred"))
		return vlan_mod_flt_parse_act_generic(
			VLAN_MOD_FILTER_CLS_ACTION_MIRRED, entry);

	RTE_LOG(INFO, DATAPLANE,
		"vlan_mod: unsupported action kind %s\n", kind);

	return vlan_mod_flt_parse_act_generic(
		VLAN_MOD_FILTER_CLS_ACTION_UNKNOWN, entry);
}

static int vlan_mod_flt_parse_acts(struct vlan_mod_filter_list_entry *ft_entry,
				    const struct nlattr *action_attr)
{
	struct nlattr *tb[TCA_ACT_MAX_PRIO + 1] = { NULL };
	int i, ret, index = 0;

	if (mnl_attr_parse_nested(action_attr, vlan_mod_flt_act_attr,
				  tb) != MNL_CB_OK) {
		RTE_LOG(ERR, DATAPLANE, "vlan_mod: parse vlan attr failed\n");
		return MNL_CB_ERROR;
	}

	/*
	 * Parse the actions. Need to keep a separate index into the
	 * ft_entry->actions[] as valid tb[] entries don't start from 0,
	 * and might not be densely populated.
	 */
	for (i = 0; i <= MIN(TCA_ACT_MAX_PRIO, VLAN_MOD_MAX_TC_FLT_ACT); i++) {
		if (tb[i]) {
			if (index == VLAN_MOD_MAX_TC_FLT_ACT) {
				RTE_LOG(ERR, DATAPLANE,
					"vlan_mod: excess actions\n");
				return MNL_CB_ERROR;
			}
			ret = vlan_mod_flt_parse_cls_one_action(tb[i],
						  &ft_entry->actions[index]);
			if (ret == MNL_CB_OK)
				index++;
			else
				return ret;
		}
	}

	/* No attr found */
	if (index == 0)
		return MNL_CB_ERROR;

	ft_entry->actions[index - 1].eos = true;

	return MNL_CB_OK;
}

static int
vlan_mod_flt_extr_base_attr(struct vlan_mod_filter_list_entry *ft_entry,
		      struct tcmsg *tcm __unused,
		      struct nlattr *base_tb[])
{
	const struct nlattr *tb[TCA_U32_MAX + 1] = { NULL };
	struct tc_u32_sel *sel = NULL;

	if (mnl_attr_parse_nested(base_tb[TCA_OPTIONS], vlan_mod_flt_u32_attr,
				  tb) != MNL_CB_OK) {
		RTE_LOG(NOTICE, DATAPLANE,
			"vlan_mod: parse u32_attr failed\n");
		return MNL_CB_OK;
	}
	/* should check action type supported */
	if (!tb[TCA_U32_ACT] || !tb[TCA_U32_SEL]) {
		RTE_LOG(NOTICE, DATAPLANE,
			"vlan_mod: filter no cls or act\n");
		return MNL_CB_ERROR;
	}

	if (mnl_attr_get_payload_len(tb[TCA_U32_SEL])  < sizeof(*sel))
		return MNL_CB_OK;
	sel = mnl_attr_get_payload(tb[TCA_U32_SEL]);

	if (sel) {
		if (sel->nkeys && (sel->nkeys <= MAX_TC_FLT_CLS)) {
			int i;

			for (i = 0; i < sel->nkeys; i++) {
				extract_u32_keys(sel->keys + i,
					&ft_entry->classify[i]);
			}
		} else {
			RTE_LOG(NOTICE, DATAPLANE,
				"vlan_mod: cls u32 sel keys %u\n",
				sel->nkeys);
			return MNL_CB_ERROR;
		}
	} else {
		RTE_LOG(NOTICE, DATAPLANE, "vlan_mod: no cls u32 sel\n");
		return MNL_CB_ERROR;
	}

	return vlan_mod_flt_parse_acts(ft_entry, tb[TCA_U32_ACT]);
}

static int
vlan_mod_flt_get_classify_vlan(struct vlan_mod_filter_list_entry *entry,
			       uint16_t *vlan)
{
	uint16_t value, mask;

	value = ntohs(entry->classify->val);
	mask = ntohs(entry->classify->mask);

	/* AND in a safety mask to ensure within 4k */
	*vlan = (value & mask) & 0xFFF;
	return MNL_CB_OK;
}

static bool
vlan_mod_enable_fwding(struct vlan_mod_chain_list_entry *entry)
{
	struct ifnet *intf = dp_ifnet_byifindex(entry->key.ifindex);
	struct vlan_mod_tbl_entry *vlan_mod_tbl;
	static struct vlan_mod_tbl_entry *vlan_mod_default;

	if (!intf) {
		RTE_LOG(ERR, DATAPLANE,
			"vlan_mod: no intf %d\n", entry->key.ifindex);

		return false;
	}

	vlan_mod_tbl = intf->vlan_mod_tbl;
	vlan_mod_default = intf->vlan_mod_default;

	if (vlan_mod_tbl) {
		entry->tbl = vlan_mod_tbl;
		entry->vlan_mod_default = vlan_mod_default;
		return true;
	}

	vlan_mod_tbl =
		zmalloc_aligned(sizeof(*vlan_mod_tbl) * VLAN_N_VID);
	if (!vlan_mod_tbl) {
		RTE_LOG(ERR, DATAPLANE,
			"vlan_mod: vlan mod table alloc fail\n");
		return false;
	}

	vlan_mod_default =
		zmalloc_aligned(sizeof(*vlan_mod_default));
	if (!vlan_mod_default) {
		RTE_LOG(ERR, DATAPLANE,
			"vlan_mod: vlan mod default alloc fail\n");
		free(vlan_mod_tbl);
		return false;
	}

	entry->tbl = vlan_mod_tbl;
	entry->vlan_mod_default = vlan_mod_default;

	rcu_assign_pointer(intf->vlan_mod_tbl, vlan_mod_tbl);
	rcu_assign_pointer(intf->vlan_mod_default, vlan_mod_default);
	intf->vlan_modify = true;

	pl_node_add_feature_by_inst(&vlan_mod_in_feat, intf);

	return true;
}

static char *vlan_mod_flt_key_str(char *buf, struct vlan_mod_tc_filter_key *key)
{
	snprintf(buf, VLAN_MOD_FLT_KEY_STR_LEN, "%d %x %x %x", key->ifindex,
		 key->parent, key->chain, key->priority);
	return buf;
}

static void
vlan_mod_flt_add_fwd_tbl_entry(uint16_t vlan,
			       struct vlan_mod_filter_list_entry *entry,
			       struct vlan_mod_ft_cls_action *act)
{
	struct vlan_mod_tbl_entry *tbl_entry = entry->parent->tbl;
	char key_string[VLAN_MOD_FLT_KEY_STR_LEN + 1];

	if (!tbl_entry) {
		RTE_LOG(ERR, DATAPLANE,
			"vlan_mod: no fwd table %s\n",
			vlan_mod_flt_key_str(key_string, &entry->key));
		return;
	}

	if (vlan != VLAN_N_VID  - 1) {
		if (entry->key.parent == VLAN_MOD_INGRESS_HANDLE)
			rcu_assign_pointer(tbl_entry[vlan].ingress, act);
		else
			rcu_assign_pointer(tbl_entry[vlan].egress, act);
		return;
	}

	if (entry->key.parent == VLAN_MOD_INGRESS_HANDLE)
		rcu_assign_pointer(entry->parent->vlan_mod_default->ingress,
				   act);
	else
		rcu_assign_pointer(entry->parent->vlan_mod_default->egress,
				   act);

}

static struct vlan_mod_filter_list_head *
vlan_mod_flt_head_init(struct vlan_mod_filter_list_head *head)
{
	CDS_INIT_LIST_HEAD(&head->list_head);
	head->list_count = 0;

	return head;
}

static struct vlan_mod_filter_list_head *vlan_mod_flt_create_chain_head(void)
{
	struct vlan_mod_filter_list_head *head;

	head = zmalloc_aligned(sizeof(*head));
	if (!head) {
		RTE_LOG(ERR, DATAPLANE,
			"vlan_mod: can not create chain head\n");
		return NULL;
	}
	return vlan_mod_flt_head_init(head);
}

/*
 * filter_key_compare
 *
 * Compare two keys, if exact is true then look for matching chain
 * values, else look for  a less specific match, i.e. a sibling
 * with a common ifindex and parent.
 */
static int vlan_mod_flt_key_cmp(struct vlan_mod_tc_filter_key *key1,
			      struct vlan_mod_tc_filter_key *key2, bool exact)
{
	if ((key1->ifindex == key2->ifindex) &&
	    (key1->parent == key2->parent) &&
	    (key1->priority == key2->priority) &&
	    ((exact && key1->chain == key2->chain) || !exact))
		return 0;
	return -1;
}

static void vlan_mod_flt_init_key(struct vlan_mod_tc_filter_key *key,
			       struct tcmsg *tcm,
			       uint32_t chain_id)
{
	key->ifindex = tcm->tcm_ifindex;
	key->parent =  tcm->tcm_parent >> 16;
	key->chain = chain_id;
	key->priority = tcm->tcm_info >> 16;
}
static void
vlan_mod_chain_insert_ordered_rcu(struct vlan_mod_filter_list_head *head,
				  struct  vlan_mod_chain_list_entry *entry)
{
	struct vlan_mod_chain_list_entry *pos;

	cds_list_for_each_entry_rcu(pos,
				    &head->list_head,
				    chain_next) {
		if (pos->key.ifindex > entry->key.ifindex)
			break;
		if (pos->key.ifindex < entry->key.ifindex)
			continue;

		if (pos->key.parent > entry->key.parent)
			break;
		if (pos->key.parent < entry->key.parent)
			continue;

		if (pos->key.chain < entry->key.chain)
			continue;
		break;
	}

	if (&pos->chain_next == &head->list_head) {
		entry->chain_next.next = &head->list_head;
		entry->chain_next.prev = head->list_head.prev;
	} else {
		entry->chain_next.next = &pos->chain_next;
		entry->chain_next.prev = pos->chain_next.prev;
	}

	pos->chain_next.prev = &entry->chain_next;
	rcu_assign_pointer(entry->chain_next.prev->next, &entry->chain_next);
}

static void vlan_mod_flt_list_rcu_free_cb(struct rcu_head *head)
{
	static struct vlan_mod_filter_list_entry *entry;

	entry = caa_container_of(head, struct vlan_mod_filter_list_entry,
				 list_rcu);
	free(entry);
}

static struct vlan_mod_filter_list_entry *
vlan_mod_flt_alloc_filter_entry(struct vlan_mod_tc_filter_key *key)
{
	struct vlan_mod_filter_list_entry *entry;

	entry = zmalloc_aligned(sizeof(*entry));
	if (!entry)
		return NULL;
	entry->key = *key;

	return entry;
}

static struct vlan_mod_filter_list_entry *
vlan_mod_flt_lookup_filter(struct  vlan_mod_filter_list_head *list_head,
		     struct vlan_mod_tc_filter_key *key)
{
	struct vlan_mod_filter_list_entry *entry;

	cds_list_for_each_entry_rcu(entry, &list_head->list_head,
				    list_next) {
		if (!vlan_mod_flt_key_cmp(key, &entry->key, true))
			return entry;
	}

	return NULL;
}

static struct vlan_mod_chain_list_entry *
vlan_mod_flt_lookup_chain(struct vlan_mod_tc_filter_key *key,
			  bool create, bool exact)
{
	struct vlan_mod_chain_list_entry *entry;
	struct vlan_mod_tc_filter_key s_key;
	char key_string[VLAN_MOD_FLT_KEY_STR_LEN + 1];

	/* The chain list is search with a less specific key
	 * than the filter has, so copy the key, and mask out
	 * the appropriate bits
	 */
	s_key = *key;
	s_key.priority = 0;

	if (!filter_chain_head)
		return NULL;

	cds_list_for_each_entry_rcu(entry,
				    &filter_chain_head->list_head,
				    chain_next) {
		if (!vlan_mod_flt_key_cmp(&s_key, &entry->key, exact))
			return entry;
	}

	if (!create)
		return NULL;

	entry = zmalloc_aligned(sizeof(*entry));
	if (!entry) {
		RTE_LOG(ERR, DATAPLANE,
			"vlan_mod: can not create chain entry\n");
		return NULL;
	}

	/*
	 * Init the list head for the filter that hang off this chain entry,
	 * setting the key to the less specific key.
	 */
	vlan_mod_flt_head_init(&entry->filter_head);
	entry->key = s_key;

	RTE_LOG(INFO, DATAPLANE, "vlan_mod: new chain entry: %s\n",
		vlan_mod_flt_key_str(key_string, &entry->key));

	filter_chain_head->list_count++;

	if (!vlan_mod_enable_fwding(entry)) {
		RTE_LOG(ERR, DATAPLANE,
			"vlan_mod: can not enable fwding\n");
		free(entry);
		return NULL;
	}

	vlan_mod_chain_insert_ordered_rcu(filter_chain_head,
					  entry);
	return entry;
}

static int vlan_mod_flt_add_entry(struct vlan_mod_tc_filter_key *key,
			    struct tcmsg *tcm,
			    struct nlattr *tb[])
{
	struct vlan_mod_chain_list_entry *chain_entry;
	struct vlan_mod_filter_list_entry *old, *new;
	struct vlan_mod_filter_list_head *list_head;
	char key_string[VLAN_MOD_FLT_KEY_STR_LEN + 1];
	uint16_t old_vlan, new_vlan;

	if (!filter_chain_head) {
		filter_chain_head = vlan_mod_flt_create_chain_head();
		if (!filter_chain_head)
			return MNL_CB_ERROR;
	}

	chain_entry = vlan_mod_flt_lookup_chain(key, true, true);

	if (!chain_entry)
		return MNL_CB_ERROR;

	list_head = &chain_entry->filter_head;

	old = vlan_mod_flt_lookup_filter(list_head, key);
	new = vlan_mod_flt_alloc_filter_entry(key);
	if (!new) {
		RTE_LOG(ERR, DATAPLANE,
			"vlan_mod: Failed creating filter entry\n");
		return MNL_CB_ERROR;
	}

	/*
	 * To save looking up the chain head when dealing with an filter
	 * entry stash it.
	 */
	new->parent = chain_entry;

	RTE_LOG(INFO, DATAPLANE, "vlan_mod: %s chain entry: %s\n",
		old ? "update" : "new",
		vlan_mod_flt_key_str(key_string, &new->key));

	if (vlan_mod_flt_extr_base_attr(new, tcm, tb) != MNL_CB_OK) {
		RTE_LOG(INFO, DATAPLANE,
			"vlan_mod: %s chain entry: update ignore\n",
			vlan_mod_flt_key_str(key_string, &new->key));
		free(new);
		return MNL_CB_OK;
	}

	if (new->actions[0].action_type != VLAN_MOD_FILTER_CLS_ACTION_VLAN) {
		free(new);
		return MNL_CB_OK;
	}

	if (vlan_mod_flt_get_classify_vlan(new, &new_vlan) != MNL_CB_OK) {
		free(new);
		return MNL_CB_ERROR;
	}

	if (old) {
		if (vlan_mod_flt_get_classify_vlan(old,
						   &old_vlan) != MNL_CB_OK) {
			free(new);
			return MNL_CB_ERROR;
		}
		vlan_mod_flt_add_fwd_tbl_entry(old_vlan, old, NULL);
	}
	vlan_mod_flt_add_fwd_tbl_entry(new_vlan, new, new->actions);

	if (!old) {
		cds_list_add_tail_rcu(&new->list_next, &list_head->list_head);
		list_head->list_count++;
	} else {
		cds_list_replace_rcu(&old->list_next, &new->list_next);
		call_rcu(&old->list_rcu, vlan_mod_flt_list_rcu_free_cb);
	}

	return MNL_CB_OK;
}

static void
vlan_mod_flt_del_fwd_tbl_entry(struct vlan_mod_filter_list_entry *entry)
{
	uint16_t vlan;
	char key_string[VLAN_MOD_FLT_KEY_STR_LEN + 1];

	if (vlan_mod_flt_get_classify_vlan(entry, &vlan) != MNL_CB_OK) {
		RTE_LOG(INFO, DATAPLANE,
			"vlan_mod: delete filter no vlan: %s\n",
			vlan_mod_flt_key_str(key_string, &entry->key));

		return;
	}

	vlan_mod_flt_add_fwd_tbl_entry(vlan, entry, NULL);
}

static void
vlan_mod_flt_delete_entry_common(struct vlan_mod_filter_list_entry *entry,
				 struct vlan_mod_filter_list_head *list_head)
{
	char key_string[VLAN_MOD_FLT_KEY_STR_LEN + 1];

	vlan_mod_flt_del_fwd_tbl_entry(entry);

	cds_list_del_rcu(&entry->list_next);

	list_head->list_count--;

	RTE_LOG(INFO, DATAPLANE,
		"vlan_mod: delete filter entry: %s\n",
		vlan_mod_flt_key_str(key_string, &entry->key));
	call_rcu(&entry->list_rcu, vlan_mod_flt_list_rcu_free_cb);
}

static int vlan_mod_flt_delete_entry(struct vlan_mod_tc_filter_key *key)
{
	struct vlan_mod_chain_list_entry *chain_entry;
	struct vlan_mod_filter_list_entry *filter_entry;
	struct vlan_mod_filter_list_head *list_head;

	if (!filter_chain_head)
		return MNL_CB_OK;
	chain_entry = vlan_mod_flt_lookup_chain(key, false, true);

	if (!chain_entry)
		return MNL_CB_OK;

	list_head = &chain_entry->filter_head;

	filter_entry = vlan_mod_flt_lookup_filter(list_head, key);

	if (!filter_entry)
		return MNL_CB_OK;

	vlan_mod_flt_del_fwd_tbl_entry(filter_entry);

	vlan_mod_flt_delete_entry_common(filter_entry, list_head);

	return MNL_CB_OK;
}

static void vlan_mod_flt_chain_rcu_free_cb(struct rcu_head *head)
{
	struct vlan_mod_chain_list_entry *entry;
	char key_string[VLAN_MOD_FLT_KEY_STR_LEN + 1];

	entry = caa_container_of(head, struct vlan_mod_chain_list_entry,
				 chain_rcu);
	/* If there is no table entry on the chain entry then the
	 * sibling chain must still be active so we we can't free the
	 * fwding table.
	 */
	if (entry->tbl) {
		RTE_LOG(INFO, DATAPLANE,
		"vlan_mod: Freeing fwding table %p %s\n",
			entry->tbl,
			vlan_mod_flt_key_str(key_string, &entry->key));
		free(entry->tbl);
	}

	if (entry->vlan_mod_default)
		free(entry->vlan_mod_default);

	free(entry);
}
/*
 * vlan_mod_flt_find_sibling_chain
 *
 * Sibling chains are chains that are on the same interface.
 * Currenty we can have an ingress and an egress chain per interface.
 * If we have an ingress chain, we need to look for the corresponding
 * egress chain, for ingress becomes egress in the chain handle.
 */
static struct vlan_mod_chain_list_entry *
vlan_mod_flt_find_sibling_chain(
	struct vlan_mod_chain_list_entry *chain_entry)
{
	struct vlan_mod_tc_filter_key key;

	key = chain_entry->key;

	if (key.parent == VLAN_MOD_INGRESS_HANDLE)
		key.parent = VLAN_MOD_EGRESS_HANDLE;
	else
		key.parent = VLAN_MOD_INGRESS_HANDLE;

	return vlan_mod_flt_lookup_chain(&key, false, false);
}

static int
vlan_mod_flt_chain_entry_delete(struct vlan_mod_chain_list_entry *chain_entry)
{
	char key_string[VLAN_MOD_FLT_KEY_STR_LEN + 1];

	cds_list_del_rcu(&chain_entry->chain_next);
	filter_chain_head->list_count--;

	/*
	 * If the sibling is still in the table, then it is not
	 * currently being deleted and so we do not attempt to destroy
	 * the table on the rcu callback. If not in the table then this
	 * chain is the last one referencing the table so clean up
	 */
	if (vlan_mod_flt_find_sibling_chain(chain_entry)) {
		chain_entry->tbl = NULL;
		chain_entry->vlan_mod_default = NULL;
	} else {
		struct ifnet *intf;

		intf = dp_ifnet_byifindex(chain_entry->key.ifindex);
		if (!intf) {
			RTE_LOG(ERR, DATAPLANE,
				"vlan_mod: no intf %d\n",
				chain_entry->key.ifindex);
			return MNL_CB_ERROR;
		}
		pl_node_remove_feature_by_inst(&vlan_mod_in_feat, intf);
		intf->vlan_modify = false;
		rcu_assign_pointer(intf->vlan_mod_tbl, NULL);
		rcu_assign_pointer(intf->vlan_mod_default, NULL);
	}

	RTE_LOG(INFO, DATAPLANE,
		"vlan_mod: chain scheduled for delete %s\n",
		vlan_mod_flt_key_str(key_string, &chain_entry->key));
	call_rcu(&chain_entry->chain_rcu, vlan_mod_flt_chain_rcu_free_cb);

	return MNL_CB_OK;
}


static int vlan_mod_flt_chain_purge(struct vlan_mod_tc_filter_key *key)
{
	struct vlan_mod_chain_list_entry *chain_entry;
	struct vlan_mod_filter_list_entry *filter_entry, *safe;
	struct vlan_mod_filter_list_head *list_head;

	if (!filter_chain_head)
		return MNL_CB_OK;

	chain_entry = vlan_mod_flt_lookup_chain(key, false, true);

	if (!chain_entry)
		return MNL_CB_OK;

	list_head = &chain_entry->filter_head;

	cds_list_for_each_entry_safe(filter_entry, safe,
				     &list_head->list_head,
				     list_next) {
		vlan_mod_flt_delete_entry_common(filter_entry,
						 list_head);
	}

	assert(list_head->list_count == 0);

	return vlan_mod_flt_chain_entry_delete(chain_entry);
}

static int vlan_mod_flt_parse_core_nlattr(const struct nlmsghdr *nlh,
				    struct nlattr *tb[],
				    uint32_t *chain_id,
				    char **filter_type)
{
	int ret;

	ret = mnl_attr_parse(nlh, sizeof(struct tcmsg),
			     vlan_mod_mod_filter_attr, tb);
	if (ret != MNL_CB_OK) {
		RTE_LOG(ERR, DATAPLANE,
			"vlan_mod: unparseable attr\n");
		return ret;
	}

	if (chain_id) {
		if  (tb[TCA_CHAIN]) {
			*chain_id = mnl_attr_get_u32(tb[TCA_CHAIN]);
		} else {
			RTE_LOG(ERR, DATAPLANE,
				"vlan_mod: can't parse TCA_CHAIN attr\n");
			return MNL_CB_OK;
		}
	}

	if (filter_type) {
		if (!tb[TCA_KIND]) {
			RTE_LOG(ERR, DATAPLANE,
				"vlan_mod: can't parse TCA_KIND attr\n");
			return MNL_CB_OK;
		}

		*filter_type = (char *)mnl_attr_get_str(tb[TCA_KIND]);
	}

	return MNL_CB_OK;
}

#define VALUE_LEN_IN_HEXCHARS (3 + 8 + 1)

static void value_to_hexstr(char *buf, uint32_t val)
{
	snprintf(buf, VALUE_LEN_IN_HEXCHARS, "0x%.4x", val);
}

static const char *vlan_mod_act_to_str(uint8_t val)
{
	switch (val) {
	case VLAN_MOD_FILTER_ACT_VLAN_POP:
		return "pop";
	case VLAN_MOD_FILTER_ACT_VLAN_PUSH:
		return "push";
	case VLAN_MOD_FILTER_ACT_VLAN_MOD:
		return "swap";
	}

	return "unknown";
}

static void vlan_mod_show_cls_u32(json_writer_t *wr,
				  struct vlan_mod_ft_cls_u32_sel *sel)
{
	uint16_t vlan_id = ntohs(sel->val) & ntohs(sel->mask);

	jsonw_name(wr, "selector");
	jsonw_start_object(wr);

	if (vlan_id == VLAN_N_VID - 1)
		jsonw_string_field(wr, "vlan-id", "any");
	else
		jsonw_int_field(wr, "vlan-id", vlan_id);

	jsonw_end_object(wr);
}

static void vlan_mod_show_cls_act_vlan(json_writer_t *wr,
				       struct vlan_mod_ft_cls_act_vlan *act)
{
	char hex_string[VALUE_LEN_IN_HEXCHARS];

	jsonw_start_object(wr);

	jsonw_string_field(wr, "type",
			   vlan_mod_act_to_str(act->action));
	if (act->action != VLAN_MOD_FILTER_ACT_VLAN_POP) {
		jsonw_int_field(wr, "vlan-id", act->vlan_id);
		value_to_hexstr(hex_string, act->proto);
		jsonw_string_field(wr, "tag-protocol-id", hex_string);
		jsonw_int_field(wr, "pcp", act->prio);
	}
	jsonw_end_object(wr);
}

static bool
vlan_mod_show_cls_action(json_writer_t *wr,
			 struct vlan_mod_ft_cls_action *act)
{
	switch (act->action_type) {
	case VLAN_MOD_FILTER_CLS_ACTION_VLAN:
		vlan_mod_show_cls_act_vlan(wr, &act->data.vlan);
		break;
	case VLAN_MOD_FILTER_CLS_ACTION_MIRRED:
		jsonw_start_object(wr);
		jsonw_name(wr, "action-mirred");
		jsonw_end_object(wr);
		break;
	default:
		jsonw_start_object(wr);
		jsonw_name(wr, "action-unsupported");
		jsonw_end_object(wr);
	}

	return act->eos;
}

static void vlan_mod_show_list_filters(json_writer_t *wr,
				 struct vlan_mod_filter_list_entry *filter)
{
	struct vlan_mod_ft_cls_u32_sel *sel;

	jsonw_start_object(wr);

	jsonw_int_field(wr, "priority-val", filter->key.priority);
	jsonw_string_field(wr, "direction", (filter->key.parent ==
					     VLAN_MOD_EGRESS_HANDLE) ?
			   "egress" : "ingress");
	sel = &filter->classify[0];

	if (sel->valid)
		vlan_mod_show_cls_u32(wr, sel);

	jsonw_name(wr, "action");
	vlan_mod_show_cls_action(wr, &filter->actions[0]);

	jsonw_end_object(wr);
}

static void vlan_mod_show_entry_chain(json_writer_t *wr,
				      struct vlan_mod_chain_list_entry *chain,
				      bool append)
{
	struct vlan_mod_filter_list_entry *entry;
	struct vlan_mod_filter_list_head *list_head = &chain->filter_head;
	struct ifnet *intf;

	if (!append) {
		intf = dp_ifnet_byifindex(chain->key.ifindex);
		if (!intf) {
			RTE_LOG(ERR, DATAPLANE, "vlan_mod: no intf %d\n",
				chain->key.ifindex);
			return;
		}
		jsonw_string_field(wr, "name", intf->if_name);

		jsonw_name(wr, "rule");
		jsonw_start_array(wr);
	}
	cds_list_for_each_entry_rcu(entry, &list_head->list_head,
				list_next) {
		vlan_mod_show_list_filters(wr, entry);
	}
}
static void vlan_mod_show_fwd_tlb_entry(json_writer_t *wr, uint16_t vlan,
					 struct vlan_mod_ft_cls_action *act)
{
	jsonw_uint_field(wr, "vlan_id", vlan);
	vlan_mod_show_cls_action(wr, act);

};

static void vlan_mod_show_fwding_table(json_writer_t *wr,
				       struct vlan_mod_chain_list_entry *entry,
				       bool first_pass)
{
	struct ifnet *intf;
	uint32_t i;
	char key_string[VLAN_MOD_FLT_KEY_STR_LEN + 1];
	struct vlan_mod_tbl_entry *vlan_mod_tbl, *vlan_mod_default;
	struct vlan_mod_ft_cls_action *act;

	intf = dp_ifnet_byifindex(entry->key.ifindex);
	if (!intf) {
		RTE_LOG(ERR, DATAPLANE, "vlan_mod: no intf %d\n",
			entry->key.ifindex);
		return;
	}

	vlan_mod_tbl = rcu_dereference(intf->vlan_mod_tbl);
	if (!vlan_mod_tbl)
		return;

	jsonw_start_object(wr);
	if (first_pass) {
		jsonw_string_field(wr, "interface", intf->if_name);
		vlan_mod_default = rcu_dereference(intf->vlan_mod_default);
		if (!vlan_mod_tbl) {
			jsonw_end_object(wr);
			return;
		}
		jsonw_name(wr, "default enties");
		jsonw_start_object(wr);

		if (entry->key.parent == VLAN_MOD_INGRESS_HANDLE) {
			act = rcu_dereference(vlan_mod_default->ingress);
			if (act)
				vlan_mod_show_fwd_tlb_entry(wr, 0, act);
		} else {
			act = rcu_dereference(vlan_mod_default->egress);
			if (act)
				vlan_mod_show_fwd_tlb_entry(wr, 0, act);
		}

		jsonw_end_object(wr);
	}

	jsonw_string_field(wr, "chain",
			   vlan_mod_flt_key_str(key_string, &entry->key));

	jsonw_start_array(wr);

	for (i = 0; i < VLAN_N_VID; i++) {
		if (entry->key.parent == VLAN_MOD_INGRESS_HANDLE) {
			act = rcu_dereference(vlan_mod_tbl[i].ingress);
			if (act)
				vlan_mod_show_fwd_tlb_entry(wr, i, act);
		} else {
			act = rcu_dereference(vlan_mod_tbl[i].egress);
			if (act)
				vlan_mod_show_fwd_tlb_entry(wr, i, act);
			}
	}

	jsonw_end_array(wr);
	jsonw_end_object(wr);
}

static void vlan_mod_show_fwding_entries(json_writer_t *wr)
{
	struct vlan_mod_chain_list_entry *entry;
	int ifindex = -1;

	jsonw_start_array(wr);

	cds_list_for_each_entry_rcu(entry,
				    &filter_chain_head->list_head,
				    chain_next) {
		if (entry->tbl) {
			if (ifindex != entry->key.ifindex)
				vlan_mod_show_fwding_table(wr, entry, true);
			else
				vlan_mod_show_fwding_table(wr, entry, false);
			ifindex = entry->key.ifindex;
		}
	}

	jsonw_end_array(wr);

}

void vlan_mod_cmd(FILE *f, int argc, char **argv)
{
	struct vlan_mod_chain_list_entry *entry;
	int ifindex = -1;
	json_writer_t *wr;
	bool intf_mode = false;

	wr = jsonw_new(f);
	if (!wr)
		return;
	if ((argc == 2) && (streq(argv[1], "intf")))
		intf_mode = true;

	jsonw_pretty(wr, true);

	if (!intf_mode) {
		jsonw_name(wr, "vlan-mod");
		jsonw_start_object(wr);

		jsonw_uint_field(wr, "total chains", filter_chain_head ?
				 filter_chain_head->list_count : 0);
		jsonw_end_object(wr);
	}
	jsonw_name(wr, "intfs");
	jsonw_start_array(wr);

	if (!filter_chain_head) {
		jsonw_end_array(wr);
		jsonw_destroy(&wr);
		return;
	}

	cds_list_for_each_entry_rcu(entry,
				    &filter_chain_head->list_head,
				    chain_next) {
		if (ifindex == entry->key.ifindex) {
			/* continuation of interface */
			vlan_mod_show_entry_chain(wr, entry, true);
		} else {
			/* new interface */
			if (ifindex != -1) {
				jsonw_end_array(wr);
				jsonw_end_object(wr);
			}
			jsonw_start_object(wr);
			vlan_mod_show_entry_chain(wr, entry, false);
		}
		ifindex = entry->key.ifindex;
	}

	if (ifindex != -1)
		jsonw_end_array(wr);

	jsonw_end_object(wr);
	jsonw_end_array(wr);

	if (!intf_mode) {
		jsonw_name(wr, "forwarding entries");
		vlan_mod_show_fwding_entries(wr);
	}

	jsonw_destroy(&wr);
}

int vlan_mod_flt_entry_add(const struct nlmsghdr *nlh)
{
	struct vlan_mod_tc_filter_key s_key;
	struct tcmsg *tcm = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[TCA_MAX+1] = { NULL };
	char *filter_type = NULL;
	uint32_t chain_id = 0;
	int ret;

	if (tcm == NULL)
		return MNL_CB_OK;

	ret = vlan_mod_flt_parse_core_nlattr(nlh, tb, &chain_id,
				       &filter_type);
	if (ret != MNL_CB_OK)
		return ret;

	if (!filter_type || strcmp(filter_type, "u32")) {
		RTE_LOG(NOTICE, DATAPLANE,
			"Unsupported tc filter type %s\n",
			filter_type);
		return MNL_CB_OK;
	}

	vlan_mod_flt_init_key(&s_key, tcm, chain_id);

	vlan_mod_flt_add_entry(&s_key, tcm, tb);

	return MNL_CB_OK;
}

int vlan_mod_flt_entry_delete(const struct nlmsghdr *nlh)
{
	struct vlan_mod_tc_filter_key s_key;
	struct tcmsg *tcm = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[TCA_MAX+1] = { NULL };
	uint32_t chain_id = 0;
	int ret;

	if (tcm == NULL || !filter_chain_head)
		return MNL_CB_OK;

	ret = vlan_mod_flt_parse_core_nlattr(nlh, tb, &chain_id, NULL);
	if (ret != MNL_CB_OK)
		return ret;

	vlan_mod_flt_init_key(&s_key, tcm, chain_id);

	vlan_mod_flt_delete_entry(&s_key);

	return MNL_CB_OK;
}

int vlan_mod_flt_chain_delete(const struct nlmsghdr *nlh __unused)
{
	struct vlan_mod_tc_filter_key s_key;
	struct tcmsg *tcm = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[TCA_MAX+1] = { NULL };
	uint32_t chain_id = 0;
	int ret;

	if (tcm == NULL || !filter_chain_head)
		return MNL_CB_OK;

	ret = vlan_mod_flt_parse_core_nlattr(nlh, tb, &chain_id, NULL);
	if (ret != MNL_CB_OK)
		return ret;

	vlan_mod_flt_init_key(&s_key, tcm, chain_id);

	vlan_mod_flt_chain_purge(&s_key);

	return MNL_CB_OK;
}

struct rte_mbuf *
vlan_modify_egress(struct ifnet *ifp, struct rte_mbuf **m)
{
	uint16_t vlan;
	struct vlan_mod_ft_cls_action *action;
	struct rte_mbuf *buf = *m;

	vlan = vlan_mod_get_vlan(buf, ifp, VLAN_MOD_DIR_EGRESS);
	if (vlan == 0)
		return *m;
	action = vlan_modify_get_action(ifp, vlan, VLAN_MOD_DIR_EGRESS);
	if (!action)
		return *m;

	switch (action->data.vlan.action) {
	case VLAN_MOD_FILTER_ACT_VLAN_POP:
		return vlan_mod_tag_pop(ifp, m, VLAN_MOD_DIR_EGRESS);
	case VLAN_MOD_FILTER_ACT_VLAN_PUSH:
		return vlan_mod_tag_push(ifp, m, action, VLAN_MOD_DIR_EGRESS);
	case VLAN_MOD_FILTER_ACT_VLAN_MOD:
		return vlan_mod_tag_modify(ifp, m, action, VLAN_MOD_DIR_EGRESS);
	default:
		return NULL;
	}

	return *m;
}
