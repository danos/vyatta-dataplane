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
#include <ini.h>

#include "config_internal.h"
#include "feature_commands.h"
#include "protobuf.h"
#include "protobuf/SFPMonitor.pb-c.h"

#include "sfp_permit_list.h"
#include "transceiver.h"

#define SFP_MAX_NAME_SIZE 64
#define SFP_MAX_PART_ID 16
#define SFP_MAX_VENDOR_NAME 16
#define SFP_MAX_VENDOR_OUI 9
#define SFP_MAX_VENDOR_REV 4

#define SFP_PART_VENDOR_NAME 1
#define SFP_PART_VENDOR_OUI  2
#define SFP_PART_VENDOR_REV  4
#define SFP_PART_WILDCARD    8

#define SFPD_PORTS_MIN 32
#define SFPD_PORTS_MAX 1024

static bool sfp_permit_list_running;
struct cds_list_head  sfp_permit_list_head;
struct cds_list_head  sfp_permit_parts_list_head;
bool sfp_pl_cfg_init;

static uint32_t sfp_permit_list_epoch;

struct sfp_mismatch_global {
	bool logging_enabled;
	bool enforcement_enabled;
	uint32_t enforcement_delay;
};

struct sfp_mismatch_global sfp_mismatch_cfg;

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

enum sfp_status {
	SFP_STATUS_APPROVED = 1,
	SFP_STATUS_UNAPPROVED = 2,
};

enum sfp_action {
	SFP_ACTION_MONITOR = 1,
	SFP_ACTION_DISABLED = 2
};

struct sfp_intf_record {
	struct cds_lfht_node hnode;
	uint32_t epoch;
	uint16_t port;
	char intf_name[IFNAMSIZ];
	struct ifnet *intf;

	/* SFP info */
	uint64_t time_of_detection; /* secs since boot */
	char part_id[SFP_MAX_PART_ID + 1];
	char vendor_name[SFP_MAX_VENDOR_NAME + 1];
	char vendor_oui[SFP_MAX_VENDOR_OUI + 1];
	char vendor_rev[SFP_MAX_VENDOR_REV + 1];

	/* Permit list outcome*/
	enum sfp_status status;
	enum sfp_action action;

	struct rcu_head rcu;
};


struct cds_lfht *sfp_ports_tbl;

static inline uint32_t sfpd_record_hash(struct sfp_intf_record *rec)
{
	return rec->port;
}

static int sfpd_record_match_fn(struct cds_lfht_node *node,
				const void *arg)
{
	struct sfp_intf_record *rec;
	uint32_t port = *(uint32_t *)arg;

	rec = caa_container_of(node, struct sfp_intf_record, hnode);

	if (rec->port == port)
		return 1;

	return 0;
}

static struct sfp_intf_record *sfpd_record_store(struct cds_lfht *hash_tbl,
						 struct sfp_intf_record *rec)
{
	uint32_t hash;
	struct cds_lfht_node *ret_node;

	cds_lfht_node_init(&rec->hnode);

	hash = sfpd_record_hash(rec);
	ret_node = cds_lfht_add_unique(hash_tbl, hash, sfpd_record_match_fn,
				       &rec->port,
				       &rec->hnode);
	if (ret_node !=  &rec->hnode) {
		RTE_LOG(ERR, DATAPLANE,
			"SFP-PL: Failed to insert SFP %s into hash table\n",
			rec->intf_name);
		return NULL;
	}
	return rec;
}

static struct sfp_intf_record *
sfpd_record_find(struct cds_lfht *hash_tbl, uint32_t port)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	if (!hash_tbl)
		return NULL;

	cds_lfht_lookup(hash_tbl, port, sfpd_record_match_fn,
			&port, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (node)
		return caa_container_of(node, struct sfp_intf_record, hnode);

	return NULL;
}

static void
sfp_permit_list_lists_inits(void)
{
	if (!sfp_pl_cfg_init) {
		CDS_INIT_LIST_HEAD(&sfp_permit_list_head);
		CDS_INIT_LIST_HEAD(&sfp_permit_parts_list_head);
		sfp_pl_cfg_init = true;
	}
}

static void sfp_permit_list_init(void)
{
	sfp_permit_list_lists_inits();

	if (sfp_permit_list_running)
		return;

	if (!config.sfpd_status_file || !config.sfpd_status_upd_url) {
		RTE_LOG(ERR, DATAPLANE,
			"SFP-PL:No sfp permit list ports SFPD update URL\n");
		return;
	}

	/*
	 * We only allocate the empty table and not the elements within
	 */
	sfp_ports_tbl = cds_lfht_new(SFPD_PORTS_MIN,
				 SFPD_PORTS_MIN,
				 SFPD_PORTS_MAX,
				 CDS_LFHT_AUTO_RESIZE,
				 NULL);
	if (!sfp_ports_tbl) {
		RTE_LOG(ERR, MAC_LIMIT,
			"Could not allocate SFPd hash table\n");
		return;
	}

	sfpd_open_socket();

	sfp_permit_list_running = true;
}

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

	if (mismatch->logging == SFP_PERMIT_CONFIG__LOGGING__ENABLE)
		sfp_mismatch_cfg.logging_enabled = true;
	else
		sfp_mismatch_cfg.logging_enabled = false;

	if (mismatch->enforcement == SFP_PERMIT_CONFIG__ENFORCEMENT__ENFORCE)
		sfp_mismatch_cfg.enforcement_enabled = true;
	else
		sfp_mismatch_cfg.enforcement_enabled = false;

	sfp_mismatch_cfg.enforcement_delay = mismatch->delay;

	return 0;
}
static void dump_lists(void) __attribute__((unused));
static void dump_lists(void)
{
	struct sfp_permit_list *entry, *next;
	struct sfp_part *part_entry, *part_next;

	DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
		 "Permit Lists Cfg Dump\n Permit Lists Global Cfg\n");

	DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
		 "   logging enabled %s\n",
		 sfp_mismatch_cfg.logging_enabled
		 == true ? "True" : "False");

	DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
		 "   enforcement enabled %s\n",
		 sfp_mismatch_cfg.enforcement_enabled
			 == true ? "True" : "False");

	DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
		 "   enforcement delay %d Secs\n",
		 sfp_mismatch_cfg.enforcement_delay);

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

static struct sfp_part *
sfp_permit_match_by_name(struct sfp_intf_record *sfp)
{
	struct sfp_part *part_entry;
	int rc;

	cds_list_for_each_entry_rcu(part_entry,
				    &sfp_permit_parts_list_head,
				    search_list) {
		if (part_entry->flags & SFP_PART_WILDCARD) {
			rc = strncmp(sfp->part_id, part_entry->part_id,
				     part_entry->len);
		} else {
			rc = strcmp(part_entry->part_id, sfp->part_id);
		}

		if (rc == 0)
			return part_entry;
	}

	return NULL;
}

static bool sfp_permit_match_check(struct sfp_intf_record *sfp)
{
	struct sfp_part *part_entry;

	part_entry = sfp_permit_match_by_name(sfp);
	if (part_entry)
		return true;

	return false;
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

	sfp_permit_list_init();

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

static void sfp_clear_holddown(struct ifnet *intf)
{
	if (intf->sfp_holddown == true) {
		intf->sfp_holddown = false;
		dpdk_eth_if_start_port(intf);
	}
}

static void
sfp_clear_holddown_cb(struct ifnet *intf, void *arg __unused)
{
	sfp_clear_holddown(intf);
}

static void sfp_set_holddown(struct ifnet *intf)
{
	if (intf->sfp_holddown == false) {
		intf->sfp_holddown = true;
		dpdk_eth_if_stop_port(intf);
	}
}

static void sfp_clear_all_holddown(void)
{
	dp_ifnet_walk(sfp_clear_holddown_cb, NULL);
}

static void sfp_scan_for_holddown(void)
{
	struct sfp_intf_record *sfp;
	struct cds_lfht_iter iter;

	cds_lfht_for_each_entry(sfp_ports_tbl, &iter, sfp, hnode) {
		if (!sfp->intf) {
			RTE_LOG(ERR, DATAPLANE,
				"SFP: Can't find intf for port %d : %s\n",
				sfp->port, sfp->intf_name);
			continue;
		}
		sfp_validate_sfp_against_pl(sfp);
	}
}

/*
 * Callback from inih library for each name value
 * return 0 = error, 1 = ok
 */
static int parse_sfpd_upd(void *user, const char *section,
			  const char *name, const char *value)
{
	struct cds_lfht *hash_tbl = user;
	struct sfp_intf_record *sfpd_section, *rc;
	uint32_t port;

	if (strcmp(section, "epoch") == 0)
		return 1;

	port  = atoi(section);

	sfpd_section = sfpd_record_find(hash_tbl, port);
	if (!sfpd_section) {
		sfpd_section = calloc(1, sizeof(*sfpd_section));
		if (!sfpd_section)
			goto error;
		sfpd_section->port = port;
		rc = sfpd_record_store(hash_tbl, sfpd_section);
		if (!rc)
			goto error;
	}

	sfpd_section->port = port;

	if (strcmp(name, "port_name") == 0) {
		snprintf(sfpd_section->intf_name, sizeof(sfpd_section->intf_name),
			 "%s", value);
		return 1;
	}
	if (strcmp(name, "part_id") == 0) {
		snprintf(sfpd_section->part_id, sizeof(sfpd_section->part_id),
			 "%s", value);
		return 1;
	}

	if (strcmp(name, "vendor_name") == 0) {
		snprintf(sfpd_section->vendor_name, sizeof(sfpd_section->vendor_name),
			 "%s", value);
		return 1;
	}
	if (strcmp(name, "vendor_oui") == 0) {
		snprintf(sfpd_section->vendor_oui, sizeof(sfpd_section->vendor_oui),
			 "%s", value);
		return 1;
	}
	if (strcmp(name, "vendor_rev") == 0) {
		snprintf(sfpd_section->vendor_rev, sizeof(sfpd_section->vendor_rev),
			 "%s", value);
		return 1;
	}
	if (strcmp(name, "detection_time") == 0)
		sfpd_section->time_of_detection = atoi(value);

	return 1;

error:
	RTE_LOG(ERR, DATAPLANE,
		"Failed to allocate SFP update section %d\n", port);
	if (sfpd_section)
		free(sfpd_section);
	return 0;
}

static struct cds_lfht *
sfpd_parse_status(const char *updfile, struct cds_lfht *hash_tbl)
{
	FILE *f;
	int rc;

	if (!updfile) {
		RTE_LOG(ERR, DATAPLANE, "SFP: No status file\n");
		return NULL;
	}

	hash_tbl = cds_lfht_new(SFPD_PORTS_MIN,
				 SFPD_PORTS_MIN,
				 SFPD_PORTS_MAX,
				 CDS_LFHT_AUTO_RESIZE,
				 NULL);
	if (!hash_tbl) {
		RTE_LOG(ERR, MAC_LIMIT,
			"Could not allocate SFPd cfg table\n");
		return NULL;
	}

	f = fopen(updfile, "r");
	if (f == NULL) {
		RTE_LOG(ERR, DATAPLANE,
			"Can't open SFPd update file: %s\n",
			updfile);
		return NULL;
	}

	rc = ini_parse_file(f, parse_sfpd_upd, hash_tbl);
	if (rc)
		RTE_LOG(ERR, DATAPLANE,
			"Can't parse SFPd update file: %s\n",
			updfile);
	fclose(f);

	return hash_tbl;
}

static void sfp_delete_cb_free(struct rcu_head *head)
{
	struct sfp_intf_record *sfp;

	sfp = caa_container_of(head, struct sfp_intf_record, rcu);
	free(sfp);
}

static void
sfp_delete(struct cds_lfht *hash_tbl, struct sfp_intf_record *sfp)
{
	if (hash_tbl)
		cds_lfht_del(hash_tbl, &sfp->hnode);

	call_rcu(&sfp->rcu, sfp_delete_cb_free);
}

static struct sfp_intf_record *
sfp_insertion(struct sfp_intf_record *insert_sfp)
{
	struct sfp_intf_record *sfp;
	struct ifnet *intf;

	DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
		 "New SFP for hw port %s\n", insert_sfp->intf_name);

	sfp = calloc(1, sizeof(*sfp));
	if (!sfp) {
		RTE_LOG(ERR, DATAPLANE,
			"SFP: Can't allocate SFD record for %s\n",
			insert_sfp->intf_name);
		return NULL;
	}
	sfp->epoch = sfp_permit_list_epoch;
	sfp->port = insert_sfp->port;
	intf =  dp_ifnet_byifname(insert_sfp->intf_name);
	if (!intf) {
		RTE_LOG(ERR, DATAPLANE,
			"SFP: Can't find intf for port %d : %s\n",
			insert_sfp->port, insert_sfp->intf_name);
		goto error;
	}
	sfp->intf = intf;

	strncpy(sfp->intf_name, insert_sfp->intf_name,
		sizeof(sfp->intf_name));
	strncpy(sfp->part_id, insert_sfp->part_id,
		sizeof(sfp->part_id));
	strncpy(sfp->vendor_name, insert_sfp->vendor_name,
		sizeof(sfp->vendor_name));
	strncpy(sfp->vendor_oui, insert_sfp->vendor_oui,
		sizeof(sfp->vendor_oui));
	strncpy(sfp->vendor_rev, insert_sfp->vendor_rev,
		sizeof(sfp->vendor_rev));
	sfp->time_of_detection = insert_sfp->time_of_detection;

	return sfp;

error:
	free(sfp);
	return NULL;
}

void sfpd_process_presence_update(void)
{
	struct sfp_intf_record *section, *rc;
	struct cds_lfht *hash_tbl = NULL, *sfpd_status;
	struct cds_lfht_iter iter;
	struct sfp_intf_record *sfp;

	if (!sfp_permit_list_running)
		return;

	DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
		 "SFP: SFPD status update: %s\n", config.sfpd_status_file);

	sfpd_status = sfpd_parse_status(config.sfpd_status_file, hash_tbl);
	if (!sfpd_status)
		return;

	/*
	 * Increment the epoch to allow a mark and sweep
	 * of delete SFPs.
	 */
	sfp_permit_list_epoch++;

	cds_lfht_for_each_entry(sfpd_status, &iter, section, hnode) {
		sfp = sfpd_record_find(sfp_ports_tbl, section->port);
		if (!sfp) {
			sfp = sfp_insertion(section);
			if (!sfp)
				continue;
			rc = sfpd_record_store(sfp_ports_tbl, sfp);
			if (!rc)
				free(sfp);
		} else {
			/* Refresh current SFP epoch */
			sfp->epoch = sfp_permit_list_epoch;
		}
		sfp_delete(sfpd_status, section);
	}

	cds_lfht_destroy(sfpd_status, NULL);

	/* Delete any removed SFPs */
	cds_lfht_for_each_entry(sfp_ports_tbl, &iter,
				sfp, hnode)
		if (sfp->epoch != sfp_permit_list_epoch)
			sfp_delete(sfp_ports_tbl, sfp);
}

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
	cds_list_for_each_entry_rcu(entry, &sfp_permit_list_head,
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

#define YES_NO(_x_) (((_x_)  ==  true) ? "True" : "False")

static void sfp_permit_dump_mismatch(FILE *f)
{
	json_writer_t *wr;

	if (f == NULL)
		f = stderr;

	wr = jsonw_new(f);
	jsonw_name(wr, "sfp-permit-list-mismatch");
	jsonw_start_object(wr);
	jsonw_string_field(wr, "logging enabled",
			   YES_NO(sfp_mismatch_cfg.logging_enabled));
	jsonw_string_field(wr, "enforcement enabled",
			   YES_NO(sfp_mismatch_cfg.enforcement_enabled));
	jsonw_uint_field(wr, "enforcement delay",
				 sfp_mismatch_cfg.enforcement_delay);
	jsonw_end_object(wr);
	jsonw_destroy(&wr);
}

static void
sfp_permit_match_check_cmd(FILE *f, const char *match_string)
{
	struct sfp_intf_record sfp;
	json_writer_t *wr;
	bool rc;

	memset(&sfp, 0, sizeof(sfp));
	strncpy((char *)&sfp.part_id, match_string, sizeof(sfp.part_id));

	rc = sfp_permit_match_check(&sfp);

	if (f == NULL) {
		RTE_LOG(ERR, DATAPLANE,
			"%s no file\n", __func__);
		f = stderr;
	}
	wr = jsonw_new(f);
	jsonw_name(wr, "sfp-permit-match");
	jsonw_start_object(wr);
	jsonw_string_field(wr, match_string,
			   YES_NO(rc));
	jsonw_end_object(wr);
	jsonw_destroy(&wr);
}

int cmd_sfp_permit_op(FILE *f, int argc __unused, char **argv)
{
	/* Init list heads if not aleady done, so we don't
	 * need to check they are setup.
	 */
	sfp_permit_list_lists_inits();

	if (!strcmp(argv[1], "dump")) {
		if (!strcmp(argv[2], "list")) {
			sfp_permit_dump_list(f);
			return 0;
		}

		if (!strcmp(argv[2], "mismatch")) {
			sfp_permit_dump_mismatch(f);
			return 0;
		}

		if (!strcmp(argv[2], "search-list")) {
			sfp_permit_dump_search_list(f);
			return 0;
		}

	}

	if (!strcmp(argv[1], "match")) {
		sfp_permit_match_check_cmd(f, argv[2]);
		return 0;
	}

	return 0;
}
