/*-
 * Copyright (c) 2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * SFP permit list feature handling
 */

#include <errno.h>
#include <rte_jhash.h>
#include <dp_event.h>
#include <vplane_log.h>
#include <vplane_debug.h>
#include <fal.h>
#include <if_var.h>
#include <urcu/list.h>
#include "feature_commands.h"
#include "protobuf.h"
#include "protobuf/SFPMonitor.pb-c.h"


#define SFP_MAX_NAME_SIZE 64
#define SFP_MAX_PART_ID 16
#define SFP_MAX_VENDOR_NAME 16
#define SFP_MAX_VENDOR_OUI 9
#define SFP_MAX_VENDOR_REV 4

#define SFP_PART_VENDOR_NAME 1
#define SFP_PART_VENDOR_OUI  2
#define SFP_PART_VENDOR_REV  4
#define SFP_PART_WILDCARD    8

struct cds_list_head  sfp_permit_list_head;
struct cds_list_head  sfp_permit_parts_list_head;
bool sfp_pl_cfg_init;

struct sfp_part {
	/* Search list ,contains all parts*/
	struct cds_list_head search_list;
	/* permit_list contains all parts in a particular list.
	 * Unordered
	 */
	struct cds_list_head permit_list;
	uint32_t flags;

	char part_id[SFP_MAX_PART_ID + 1];

	/* optional, as indicated by flags */
	char vendor_name[SFP_MAX_VENDOR_NAME + 1];
	char vendor_oui[SFP_MAX_VENDOR_OUI + 1];
	char vendor_rev[SFP_MAX_VENDOR_REV + 1];
};

struct sfp_permit_list {
	struct cds_list_head permit_list_link;
	struct cds_list_head sfp_part_list_head;

	char list_name[SFP_MAX_NAME_SIZE + 1];
	uint8_t num_parts;
};

static struct sfp_permit_list *sfp_find_permit_list(char *name)
{
	struct sfp_permit_list *entry, *next;

	cds_list_for_each_entry_safe(entry, next, &sfp_permit_list_head,
				     permit_list_link) {
		if (strcmp(entry->list_name, name) == 0)
			return entry;
	}
	return NULL;
}

static struct sfp_permit_list *sfp_list_add_entry(char *name)
{
	struct sfp_permit_list *entry;

	entry = calloc(1, sizeof(*entry));
	if (!entry) {
		RTE_LOG(ERR, DATAPLANE,
			"SFP-PL:Failed to alloc sfp permit list entry\n");
		return NULL;
	}

	strncpy(entry->list_name, name, sizeof(entry->list_name));

	cds_list_add_tail(&entry->permit_list_link, &sfp_permit_list_head);

	DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
		 "SFP-PL:Allocated entry for list %s\n", name);

	return entry;
}

static int
sfp_permit_list_cfg(SfpPermitConfig__SfpPermitListConfig *list)
{
	SfpPermitConfig__SfpPart **parts;
	struct sfp_permit_list *entry;
	uint32_t i = 0;

	DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
		"SFP-PL:Permit_list:%s %s\n", list->name,
		list->action == SFP_PERMIT_CONFIG__ACTION__SET ?
		"Set" : "Delete");

	if (list->vendor)
		DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
			"SFP-PL:Permit_list:%s vendor: %s\n", list->name,
			list->vendor);

	if (list->vendor_oui)
		DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
			"SFP-PL:Permit_list:%s vendor oui: %s\n", list->name,
			list->vendor_oui);

	if (list->vendor_rev)
		DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
			"SFP-PL:Permit_list:%s vendor rev:  %s\n", list->name,
			list->vendor_rev);

	if (list->n_vendor_parts) {
		parts = list->vendor_parts;
		while (i < list->n_vendor_parts) {
			DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
				 "SFP-PL:Permit_list:%s vendor Part:%s\n",
				 list->name, parts[i]->part);
			i++;
		}
	}

	entry = sfp_find_permit_list(list->name);
	if (!entry)
		entry = sfp_list_add_entry(list->name);

	return 0;
}

static int
sfp_permit_mismatch_cfg(SfpPermitConfig__SfpPermitMisMatchConfig *mismatch)
{
	DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
		 "SFP-PL:mismatch enforcement delay %d\n", mismatch->delay);
	DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
		"SFP-PL:mismatch logging %d\n", mismatch->logging);
	DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
		"SFP-PL:mismatch enforcement %d\n", mismatch->enforcement);
	return 0;
}
static void dump_lists(void) __attribute__((unused));
static void dump_lists(void)
{
	struct sfp_permit_list *entry, *next;

	cds_list_for_each_entry_safe(entry, next, &sfp_permit_list_head,
				     permit_list_link) {
		DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
			"SFP-PL:List Name: %s\n", entry->list_name);
	}
}

static int
cmd_sfp_permit_list_cfg(struct pb_msg *msg)
{
	SfpPermitConfig *sfpmsg =
	       sfp_permit_config__unpack(NULL, msg->msg_len, msg->msg);

	int ret = 0;

	if (!sfpmsg) {
		RTE_LOG(ERR, DATAPLANE,
			"SFP-PL:failed to read SfpPermitConfig protobuf command\n");
		return -1;
	}

	if (!sfp_pl_cfg_init) {
		CDS_INIT_LIST_HEAD(&sfp_permit_list_head);
		sfp_pl_cfg_init = true
	}

	switch (sfpmsg->mtype_case) {
	case SFP_PERMIT_CONFIG__MTYPE_LIST:
		ret = sfp_permit_list_cfg(sfpmsg->list);
		break;
	case SFP_PERMIT_CONFIG__MTYPE_MISMATCH:
		ret = sfp_permit_mismatch_cfg(sfpmsg->mismatch);
		break;
	default:
		RTE_LOG(ERR, DATAPLANE,
			"SFP-PL:unknown protobuf command %d\n", sfpmsg->mtype_case);
		ret = 0;
		break;
	}

	sfp_permit_config__free_unpacked(sfpmsg, NULL);

	return ret;
}

PB_REGISTER_CMD(sfppermitlist_cmd) = {
	.cmd = "vyatta:sfppermitlist",
	.handler = cmd_sfp_permit_list_cfg,
};
