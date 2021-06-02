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

#include "sfp_permit_list.h"

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
	/* Search list ,contains all parts, in an ordered
	 * list
	 */
	struct cds_list_head search_list;
	/* permit_list contains all parts in a particular list.
	 * Unordered
	 */
	struct cds_list_head permit_list;

	uint16_t flags;
	uint16_t len;

	char part_id[SFP_MAX_PART_ID + 1];

	/* optional, as indicated by flags */
	char vendor_name[SFP_MAX_VENDOR_NAME + 1];
	char vendor_oui[SFP_MAX_VENDOR_OUI + 1];
	char vendor_rev[SFP_MAX_VENDOR_REV + 1];

	struct rcu_head rcu;
};

struct sfp_permit_list {
	struct cds_list_head permit_list_link;
	struct cds_list_head sfp_part_list_head;

	char list_name[SFP_MAX_NAME_SIZE + 1];
	uint8_t num_parts;
	struct rcu_head rcu;
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

static struct sfp_part *
sfp_list_add_partid(SfpPermitConfig__SfpPermitListConfig *list,  char *part)
{
	struct sfp_part *entry;
	uint32_t flags;

	entry = calloc(1, sizeof(*entry));
	if (!entry) {
		RTE_LOG(ERR, DATAPLANE,
			"SFP-PL:Failed to alloc sfp permit list entry");
		return NULL;
	}

	strncpy(entry->part_id, part, sizeof(entry->part_id));
	entry->len = strlen(entry->part_id);

	if (strstr(part, "*")) {
		flags = SFP_PART_WILDCARD;
		entry->len -= 1;
	} else {
		flags = 0;
	}

	if (list->vendor) {
		strncpy(entry->vendor_name, list->vendor,
			sizeof(entry->vendor_name));
		flags |= SFP_PART_VENDOR_NAME;
	}

	if (list->vendor_oui) {
		strncpy(entry->vendor_oui, list->vendor_oui,
			sizeof(entry->vendor_oui));
		flags |= SFP_PART_VENDOR_OUI;
	}

	if (list->vendor_rev) {
		strncpy(entry->vendor_rev, list->vendor_rev,
			sizeof(entry->vendor_rev));
		flags |= SFP_PART_VENDOR_REV;
	}

	entry->flags = flags;
	return entry;
}

static void sfp_ordered_list_add(struct sfp_part *part)
{
	int32_t rc;
	struct sfp_part *entry;

	cds_list_for_each_entry(entry, &sfp_permit_parts_list_head,
				search_list) {
		rc = strncmp(entry->part_id, part->part_id, part->len);
		if (part->flags & SFP_PART_WILDCARD) {
			if (rc >  0) {
				cds_list_add_tail(&part->search_list,
						  &entry->search_list);
				return;
			}
		} else {
			if (rc >=  0) {
				cds_list_add_tail(&part->search_list,
						  &entry->search_list);
			return;
			}
		}
	}
	cds_list_add_tail(&part->search_list, &sfp_permit_parts_list_head);
}

static struct sfp_permit_list *
sfp_list_add_entry(SfpPermitConfig__SfpPermitListConfig *list)
{
	struct sfp_permit_list *entry;
	struct sfp_part *part;
	SfpPermitConfig__SfpPart **parts;
	uint32_t i = 0;

	entry = calloc(1, sizeof(*entry));
	if (!entry) {
		RTE_LOG(ERR, DATAPLANE,
			"SFP-PL:Failed to alloc sfp permit list entry\n");
		return NULL;
	}

	strncpy(entry->list_name, list->name, sizeof(entry->list_name));

	CDS_INIT_LIST_HEAD(&entry->sfp_part_list_head);

	parts = list->vendor_parts;

	if (list->n_vendor_parts) {
		while (i < list->n_vendor_parts) {
			part = sfp_list_add_partid(list,
						   parts[i]->part);
			i++;
			entry->num_parts++;
			cds_list_add_tail(&part->permit_list,
					  &entry->sfp_part_list_head);
			sfp_ordered_list_add(part);
		}
	} else {
	}

	cds_list_add_tail(&entry->permit_list_link, &sfp_permit_list_head);

	DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
		 "SFP-PL:Allocated entry for list %s\n", list->name);

	return entry;
}

static void sfp_list_part_cb_free(struct rcu_head *head)
{
	struct sfp_part *entry;

	entry = caa_container_of(head, struct sfp_part, rcu);
	free(entry);
}

static void sfp_list_cb_free(struct rcu_head *head)
{
	struct sfp_permit_list *entry;

	entry = caa_container_of(head, struct sfp_permit_list, rcu);
	free(entry);
}

static struct sfp_permit_list *
sfp_list_remove_entry(struct sfp_permit_list *entry)
{
	struct sfp_part *part_entry, *part_next;

	cds_list_del(&entry->permit_list_link);

	cds_list_for_each_entry_safe(part_entry, part_next,
				     &entry->sfp_part_list_head,
				     permit_list) {
		cds_list_del(&part_entry->search_list);
		cds_list_del(&part_entry->permit_list);
		call_rcu(&part_entry->rcu, sfp_list_part_cb_free);
	}

	call_rcu(&entry->rcu, sfp_list_cb_free);

	return NULL;
}

static void
sfp_list_display(SfpPermitConfig__SfpPermitListConfig *list)
{
	SfpPermitConfig__SfpPart **parts;
	uint32_t i = 0;
	bool set = list->action ==
		SFP_PERMIT_CONFIG__ACTION__SET ? true : false;

	DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
		"SFP-PL:Permit_list:%s %s\n", list->name, set  ? "Set" : "Delete");

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
}

static int
sfp_permit_list_cfg(SfpPermitConfig__SfpPermitListConfig *list)
{
	struct sfp_permit_list *entry;
	bool set = list->action ==
		SFP_PERMIT_CONFIG__ACTION__SET ? true : false;

	DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
		"SFP-PL:Permit_list:%s %s\n", list->name,
		set ? "SET" : "DELETE");
	if (set)
		sfp_list_display(list);

	entry = sfp_find_permit_list(list->name);
	if (!entry) {
		if (set)
			entry = sfp_list_add_entry(list);
		else
			DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
				 "SFP-PL:Delete %s failed\n",
				 list->name);
	} else {
		/* Updates to the list are performed by deleting
		 * the list and then adding a new one.
		 */
		sfp_list_remove_entry(entry);
		if (set)
			entry = sfp_list_add_entry(list);
	}

	if (set && !entry) {
		RTE_LOG(ERR, DATAPLANE,
			"SFP-PL:Set/update %s cfg entry failed\n",
			list->name);
		return -1;
	}

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
	struct sfp_part *part_entry, *part_next;

	if (cds_list_empty(&sfp_permit_list_head)) {
		DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
			"SFP-PL:List Name: EMPTY\n");
		return;
	}

	DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE, "SFP-PL:Permit Lists\n");

	cds_list_for_each_entry_safe(entry, next,
				     &sfp_permit_list_head,
				     permit_list_link) {
		DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
			"  SFP-PL:List Name: %s\n", entry->list_name);

		cds_list_for_each_entry_safe(part_entry, part_next,
					     &entry->sfp_part_list_head,
					     permit_list) {
			DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
				 "      part %s\n", part_entry->part_id);
			DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
				 "        flags %x\n", part_entry->flags);
			if (strlen(part_entry->vendor_name) != 0)
				DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
					 "        vendor_name %s\n",
					 part_entry->vendor_name);
			if (strlen(part_entry->vendor_oui) != 0)
				DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
					 "        vendor_oui %s\n",
					 part_entry->vendor_oui);
			if (strlen(part_entry->vendor_rev) != 0)
				DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
					 "        vendor_rev %s\n",
					 part_entry->vendor_rev);
		}
	}

	if (cds_list_empty(&sfp_permit_parts_list_head)) {
		DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
			 "Parts search List: EMPTY\n");
		return;
	}

	DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE, " SFP-PL:Parts search List\n");

	cds_list_for_each_entry_safe(part_entry, part_next,
				     &sfp_permit_parts_list_head,
				     search_list) {
		DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
			 "      part %s\n", part_entry->part_id);
		DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
			 "        flags %x\n", part_entry->flags);
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
		CDS_INIT_LIST_HEAD(&sfp_permit_parts_list_head);
		sfp_pl_cfg_init = true;
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

static void sfp_permit_dump_list(FILE *f)
{
	struct sfp_permit_list *entry;
	struct sfp_part *part_entry;
	json_writer_t *wr;

	if (f == NULL)
		f = stderr;

	wr = jsonw_new(f);
	jsonw_name(wr, "sfp-permit-list");
	jsonw_start_object(wr);
	jsonw_name(wr, "lists");
	jsonw_start_array(wr);
	if (sfp_permit_list_head)
		cds_list_for_each_entry_rcu(entry, sfp_permit_list_head,
					    permit_list_link) {
			jsonw_start_object(wr);
			jsonw_string_field(wr, "Name", entry->list_name);
			jsonw_name(wr, "lists");
			jsonw_start_array(wr);

			cds_list_for_each_entry_rcu(part_entry,
						    &entry->sfp_part_list_head,
						    permit_list) {
				jsonw_start_object(wr);

				jsonw_string_field(wr, "vendor_part",
						   part_entry->part_id);
				jsonw_uint_field(wr, "flags", part_entry->flags);
				if (strlen(part_entry->vendor_name) != 0)
					jsonw_string_field(wr, "vendor",
							   part_entry->vendor_name);
				if (strlen(part_entry->vendor_oui) != 0)
					jsonw_string_field(wr, "vendor_oui",
							   part_entry->vendor_oui);
				if (strlen(part_entry->vendor_rev) != 0)
					jsonw_string_field(wr, "vendor_rev",
							   part_entry->vendor_rev);
				jsonw_end_object(wr);
			}
			jsonw_end_array(wr);
			jsonw_end_object(wr);
		}
	jsonw_end_array(wr);

	jsonw_end_object(wr);
	jsonw_destroy(&wr);
}
static void sfp_permit_dump_search_list(FILE *f)
{
	struct sfp_part *part_entry;

	json_writer_t *wr;

	if (f == NULL)
		f = stderr;

	wr = jsonw_new(f);
	jsonw_name(wr, "sfp-search-list");
	jsonw_start_object(wr);
	jsonw_name(wr, "list");

	jsonw_start_array(wr);

	cds_list_for_each_entry_rcu(part_entry,
				    &sfp_permit_parts_list_head,
				    search_list) {
		jsonw_start_object(wr);
		jsonw_string_field(wr, "vendor_part",
				   part_entry->part_id);
		jsonw_string_field(wr, "vendor_rev",
				   part_entry->vendor_rev);
		jsonw_uint_field(wr, "flags", part_entry->flags);
		jsonw_end_object(wr);
	}

	jsonw_end_array(wr);

	jsonw_end_object(wr);

	jsonw_destroy(&wr);
}

int cmd_sfp_permit_op(FILE *f, int argc __unused, char **argv)
{
	if (!strcmp(argv[1], "dump")) {
		if (!strcmp(argv[2], "list")) {
			sfp_permit_dump_list(f);
			return 0;
		}

		if (!strcmp(argv[2], "search-list")) {
			sfp_permit_dump_search_list(f);
			return 0;
		}

	}

	return 0;
}
