/*-
 * Copyright (c) 2020, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * mac limit feature handling
 */

#include <errno.h>
#include <rte_jhash.h>
#include <dp_event.h>
#include <vplane_log.h>
#include <fal.h>
#include <if_var.h>
#include <urcu/list.h>
#include "feature_commands.h"
#include "mac_limit.h"
#include "if/bridge/bridge.h"
#include "protobuf.h"
#include "protobuf/MacLimitConfig.pb-c.h"

static struct cds_lfht *mac_limit_profile_tbl;
static struct cds_list_head *mac_limit_list;

#define MAC_LIMIT_PROFILE_TABLE_MIN 8
#define MAC_LIMIT_PROFILE_TABLE_MAX 1024

struct mac_limit_profile {
	struct cds_lfht_node mlp_node;
	struct cds_list_head mlp_list;
	struct rcu_head      mlp_rcu;
	char                 *mlp_name;
	uint32_t             mlp_limit;
};

struct mac_limit_entry {
	struct cds_list_head     mle_list;
	struct cds_list_head     mle_profile_list;
	struct ifnet             *mle_ifp;
	uint16_t                 mle_vlan;
	struct mac_limit_profile *mle_profile;
	struct rcu_head          mle_rcu;
};

static bool mac_limit_check_vlan(struct ifnet *ifp, uint16_t vlan)
{
	return ifp->if_brport &&
		bridge_port_is_vlan_member(ifp->if_brport, vlan);
}

static int mac_limit_fal_apply(struct mac_limit_entry *entry,
			       bool update)
{
	int rv = 0;
	uint32_t limit;
	struct if_vlan_feat *vlan_feat;
	uint16_t vlan = entry->mle_vlan;
	struct ifnet *ifp = entry->mle_ifp;
	struct mac_limit_profile *profile = entry->mle_profile;

	/*
	 * If vlan does not yet exist, we'll handle it when created.
	 */
	if (!mac_limit_check_vlan(ifp, vlan))
		return 0;

	RTE_LOG(DEBUG, MAC_LIMIT,
		"%s update %d int %s profile %s limit %d\n",
		__func__, update, ifp->if_name, profile->mlp_name,
		profile->mlp_limit);

	limit = profile->mlp_limit;

	struct fal_attribute_t vlan_attr[3] = {
		{ .id = FAL_VLAN_FEATURE_INTERFACE_ID,
		  .value.u32 = entry->mle_ifp->if_index },
		{ .id = FAL_VLAN_FEATURE_VLAN_ID,
		  .value.u16 = vlan },
		{ .id = FAL_VLAN_FEATURE_ATTR_MAC_LIMIT,
		  .value.u32 = limit }
	};

	vlan_feat = if_vlan_feat_get(ifp, vlan);
	if (!vlan_feat) {
		RTE_LOG(DEBUG, MAC_LIMIT,
			"Create vlan feature for Intf: %s, vlan: %d\n",
			ifp->if_name, vlan);
		rv = if_vlan_feat_create(ifp, vlan, FAL_NULL_OBJECT_ID);
		if (rv) {
			RTE_LOG(ERR, MAC_LIMIT,
				"Could not create VLAN feature block for intf %s, vlan %d\n",
				ifp->if_name, vlan);
			return rv;
		}
		vlan_feat = if_vlan_feat_get(ifp, vlan);
		if (!vlan_feat)
			return -ENOENT;

		rv = fal_vlan_feature_create(ARRAY_SIZE(vlan_attr),
					     vlan_attr,
					     &vlan_feat->fal_vlan_feat);
		if (rv) {
			if (rv != -EOPNOTSUPP) {
				RTE_LOG(ERR, MAC_LIMIT,
					"Could not create vlan_feat for vlan %d in fal (%d)\n",
					vlan, rv);
				if_vlan_feat_delete(ifp, vlan);
				return rv;
			}
		}
	} else {
		RTE_LOG(DEBUG, MAC_LIMIT, "Found vlan feature\n");
		rv = fal_vlan_feature_set_attr(vlan_feat->fal_vlan_feat,
					       &vlan_attr[2]);
		if (rv) {
			RTE_LOG(ERR, MAC_LIMIT,
				"Could not associate mac limit for intf %s vlan %d\n",
				ifp->if_name, vlan);
			return rv;
		}
	}
	if (!update)
		vlan_feat->refcount++;

	return rv;
}

static int mac_limit_fal_unapply(struct mac_limit_entry *entry)
{
	int rv = 0;
	struct if_vlan_feat *vlan_feat;
	uint16_t vlan = entry->mle_vlan;
	struct ifnet *ifp = entry->mle_ifp;

	/*
	 * vlan may never have existed and so limit was never applied.
	 */
	if (!mac_limit_check_vlan(entry->mle_ifp, vlan))
		return 0;

	struct fal_attribute_t vlan_attr[1] = {
		{ .id = FAL_VLAN_FEATURE_ATTR_MAC_LIMIT,
		  .value.u32 = 0 }
	};

	/*
	 * Remove the vlan feature.
	 */
	vlan_feat = if_vlan_feat_get(ifp, vlan);
	if (!vlan_feat) {
		RTE_LOG(ERR, MAC_LIMIT,
				"Could not find vlan feat for intf %s vlan %d\n",
				ifp->if_name, vlan);
		return -ENOENT;
	}

	rv = fal_vlan_feature_set_attr(vlan_feat->fal_vlan_feat,
				       &vlan_attr[0]);
	if (rv) {
		RTE_LOG(ERR, MAC_LIMIT,
				"Could not disassociate mac limit for intf %s vlan %d\n",
				ifp->if_name, vlan);
		return rv;
	}

	vlan_feat->refcount--;

	if (vlan_feat && !vlan_feat->refcount) {
		RTE_LOG(DEBUG, MAC_LIMIT, "Remove vlan feature\n");
		rv = fal_vlan_feature_delete(vlan_feat->fal_vlan_feat);
		if (rv) {
			RTE_LOG(ERR, MAC_LIMIT,
				"Could not destroy fal vlan feature obj for %s vlan %d (%d)\n",
				ifp->if_name, vlan, rv);
			return rv;
		}

		rv = if_vlan_feat_delete(ifp, vlan);
		if (rv) {
			RTE_LOG(ERR, MAC_LIMIT,
				"Could not destroy vlan feature obj for %s vlan %d (%d)\n",
				ifp->if_name, vlan, rv);
			return rv;
		}
		RTE_LOG(INFO, MAC_LIMIT,
			"Destroyed vlan feature obj for %s vlan %d\n",
			ifp->if_name, vlan);
	}

	return rv;
}

/* MAC limit profile functions*/
static int mac_limit_setup_profile_table(void)
{
	mac_limit_profile_tbl = cds_lfht_new(MAC_LIMIT_PROFILE_TABLE_MIN,
					     MAC_LIMIT_PROFILE_TABLE_MIN,
					     MAC_LIMIT_PROFILE_TABLE_MAX,
					     CDS_LFHT_AUTO_RESIZE,
					     NULL);
	if (!mac_limit_profile_tbl) {
		RTE_LOG(ERR, MAC_LIMIT,
			"Could not allocate mac limit profile table\n");
		return -ENOMEM;
	}
	return 0;
}

static inline uint32_t mac_limit_profile_hash(const char *profile_name)
{
	int len = strlen(profile_name);
	char copy[len+3];

	memcpy(copy, profile_name, len);
	return rte_jhash(copy, len, 0);
}

static inline int mac_limit_profile_match_fn(struct cds_lfht_node *node,
					     const void *arg)
{
	const char *profile_name = arg;
	const struct mac_limit_profile *profile;

	profile = caa_container_of(node, const struct mac_limit_profile,
				   mlp_node);

	if (strcmp(profile_name, profile->mlp_name) == 0)
		return 1;

	return 0;
}

static struct mac_limit_profile *
mac_limit_add_profile(const char *name)
{
	struct mac_limit_profile *profile = NULL;
	unsigned long name_hash;
	struct cds_lfht_node *ret_node;
	int rc;

	if (!mac_limit_profile_tbl) {
		rc = mac_limit_setup_profile_table();
		if (rc) {
			RTE_LOG(ERR, MAC_LIMIT,
				"Failed to add profile %s, no profile tbl\n",
				name);
			return NULL;
		}
	}

	profile = calloc(1, sizeof(*profile));
	if (!profile) {
		RTE_LOG(ERR, MAC_LIMIT,
			"Could not allocate mac limit profile %s\n",
			name);
		return NULL;
	}

	profile->mlp_name = strdup(name);
	if (!profile->mlp_name) {
		free(profile);
		RTE_LOG(ERR, MAC_LIMIT,
			"Could not allocate mac limit profile %s\n",
			name);
		return NULL;
	}

	cds_lfht_node_init(&profile->mlp_node);
	name_hash = mac_limit_profile_hash(name);
	ret_node = cds_lfht_add_unique(mac_limit_profile_tbl, name_hash,
				       mac_limit_profile_match_fn, name,
				       &profile->mlp_node);

	if (ret_node != &profile->mlp_node) {
		free(profile->mlp_name);
		free(profile);
		profile = caa_container_of(ret_node, struct mac_limit_profile,
					   mlp_node);
		RTE_LOG(DEBUG, MAC_LIMIT,
			"Found an existing profile %s (%lx)\n",
			name, (unsigned long)profile);
	} else {
		CDS_INIT_LIST_HEAD(&profile->mlp_list);
		RTE_LOG(DEBUG, MAC_LIMIT, "Added profile %s (%lx)\n", name,
			(unsigned long)profile);
	}

	return profile;
}


static void mac_limit_free_profile(struct rcu_head *head)
{
	struct mac_limit_profile *profile;

	profile = caa_container_of(head, struct mac_limit_profile, mlp_rcu);
	free(profile->mlp_name);
	free(profile);
}

static void mac_limit_delete_profile(struct mac_limit_profile *profile)
{
	RTE_LOG(INFO, MAC_LIMIT, "Delete profile %s\n", profile->mlp_name);

	cds_lfht_del(mac_limit_profile_tbl, &profile->mlp_node);
	call_rcu(&profile->mlp_rcu, mac_limit_free_profile);
}

static struct mac_limit_profile *
mac_limit_find_profile(const char *name)
{
	struct mac_limit_profile *profile = NULL;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	if (!mac_limit_profile_tbl)
		return NULL;

	cds_lfht_lookup(mac_limit_profile_tbl,
			mac_limit_profile_hash(name),
			mac_limit_profile_match_fn,
			name, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (node)
		profile = caa_container_of(node, struct mac_limit_profile,
					   mlp_node);

	return profile;
}

static void
mac_limit_profile_set_limit(struct mac_limit_profile *profile, uint32_t limit)
{
	struct mac_limit_entry *entry;

	profile->mlp_limit = limit;

	RTE_LOG(DEBUG, MAC_LIMIT, "mac limit profile %s %s limit %d\n",
		profile->mlp_name, limit ? "set" : "delete",
		profile->mlp_limit);

	/* For all the places where the profile is bound */
	cds_list_for_each_entry_rcu(entry, &profile->mlp_list,
				    mle_profile_list) {
		if (limit == 0)
			mac_limit_fal_unapply(entry);
		else
			mac_limit_fal_apply(entry, true);
	}
}

static int mac_limit_set_profile(MacLimitConfig__MacLimitProfileConfig *cfg)
{
	char *profile_name;
	struct mac_limit_profile *profile;
	bool set = cfg->action == MAC_LIMIT_CONFIG__ACTION__SET;

	profile_name = cfg->profile;
	if (!profile_name) {
		RTE_LOG(ERR, MAC_LIMIT,
			"Missing profile name in profile update\n");
		return 0;
	}

	profile = mac_limit_find_profile(profile_name);
	if (!profile) {
		if (set) {
			profile = mac_limit_add_profile(profile_name);
			if (!profile) {
				RTE_LOG(INFO, MAC_LIMIT,
					"Could not create mac limit profile %s\n",
					profile_name);
				return -ENOMEM;
			}
		} else {
			RTE_LOG(INFO, MAC_LIMIT,
				"Could not find profile %s\n", profile_name);
			return -ENOENT;
		}
	}

	if (!set)
		mac_limit_profile_set_limit(profile, 0);
	else
		mac_limit_profile_set_limit(profile, cfg->limit);

	if (!set) {
		if (!cds_list_empty(&profile->mlp_list)) {
			RTE_LOG(DEBUG, MAC_LIMIT,
				"Not deleting profile %s, list not EMPTY\n",
				profile->mlp_name);
			return 0;
		}
		/* Delete the profile if it is not referred to by anythign */
		mac_limit_delete_profile(profile);
	}

	return 0;
}

/*
 * MAC limit Entry functions
 */
static struct mac_limit_entry *mle_find_entry(struct ifnet *ifp,
					      uint16_t vlan)
{
	struct mac_limit_entry *entry;
	struct mac_limit_entry *next;

	if (!mac_limit_list)
		return NULL;

	cds_list_for_each_entry_safe(entry, next, mac_limit_list, mle_list) {
		if ((entry->mle_ifp == ifp) && (entry->mle_vlan == vlan))
			return entry;
	}
	return NULL;
}

static struct mac_limit_entry *mle_add_entry(struct ifnet *ifp,
					     uint16_t vlan)
{
	struct mac_limit_entry *entry;

	if (!mac_limit_list) {
		mac_limit_list = calloc(1, sizeof(*mac_limit_list));
		if (!mac_limit_list)
			return NULL;

		CDS_INIT_LIST_HEAD(mac_limit_list);
	}
	entry = calloc(1, sizeof(*entry));
	if (!entry) {
		RTE_LOG(ERR, MAC_LIMIT,
			"Failed to alloc mac limit_list entry");
		return NULL;
	}
	entry->mle_vlan = vlan;
	entry->mle_ifp = ifp;
	cds_list_add_tail(&entry->mle_list, mac_limit_list);
	RTE_LOG(DEBUG, MAC_LIMIT,
		"Allocated entry %lx for Intf: %s, vlan: %d\n",
		(unsigned long)entry, ifp->if_name, vlan);
	return entry;
}

static void mle_entry_free(struct rcu_head *head)
{
	struct mac_limit_entry *entry;

	entry = caa_container_of(head, struct mac_limit_entry, mle_rcu);
	free(entry);
}

static void mle_delete_entry(struct mac_limit_entry *entry)
{
	if (!entry)
		return;

	cds_list_del(&entry->mle_list);
	cds_list_del(&entry->mle_profile_list);
	RTE_LOG(DEBUG, MAC_LIMIT, "Freeing entry %lx\n",
		(unsigned long)entry);
	call_rcu(&entry->mle_rcu, mle_entry_free);
}

/*
 * mac-limit <SET|DELETE> <ifname> <vlan> <profile>
 */
static int mac_limit_set_intf_cfg(MacLimitConfig__MacLimitIfVLANConfig *cfg)
{
	bool set = cfg->action == MAC_LIMIT_CONFIG__ACTION__SET;
	char *ifname, *pname;
	struct ifnet *ifp = NULL;
	struct mac_limit_entry *entry = NULL;
	struct mac_limit_profile *profile = NULL;
	uint16_t vlan;
	bool update = false;

	ifname = cfg->ifname;
	vlan = cfg->vlan;
	pname = cfg->profile;

	RTE_LOG(DEBUG, MAC_LIMIT,
		"set_intf_cfg: %s intf %s vlan %u profile %s\n",
		set ? "Set" : "Delete",
		ifname, vlan, pname);

	ifp = dp_ifnet_byifname(ifname);
	if (!ifp) {
		RTE_LOG(ERR, MAC_LIMIT, "No interface %s\n", ifname);
		return -1;
	}

	entry = mle_find_entry(ifp, vlan);

	if (set) {
		profile = mac_limit_find_profile(pname);
		if (!profile) {
			RTE_LOG(ERR, MAC_LIMIT, "Invalid profile %s\n", pname);
			return -1;
		}
		if (entry) {
			update = true;
			/*
			 * Existing entry. If the profile name differs from the
			 * one we are adding, need to undo the existing one
			 * first.
			 */
			if (entry->mle_profile != profile) {
				cds_list_del(&entry->mle_profile_list);
				entry->mle_profile = NULL;
			}
		} else {
			entry = mle_add_entry(ifp, vlan);
			if (!entry)
				return -1;
		}
		entry->mle_profile = profile;
		cds_list_add_rcu(&entry->mle_profile_list,
				 &profile->mlp_list);
		mac_limit_fal_apply(entry, update);
	} else {
		/* Nothing to delete */
		if (!entry)
			return 0;

		if (entry->mle_profile->mlp_limit)
			mac_limit_fal_unapply(entry);

		mle_delete_entry(entry);
	}

	return 0;
}

/*
 * mac-limit SET profile <profile> <limit>
 * mac-limit DELETE profile <profile> <limit>
 *
 * mac-limit SET <interface> <vlan> <name>
 * mac-limit DELETE <interface> <vlan> <name>
 *
 */
static int
cmd_mac_limit_cfg(struct pb_msg *msg)
{
	MacLimitConfig *mlmsg = mac_limit_config__unpack(NULL, msg->msg_len,
							 msg->msg);
	int ret;

	if (!mlmsg) {
		RTE_LOG(ERR, DATAPLANE,
			"failed to read MacLimitConfig protobuf command\n");
		return -1;
	}

	switch (mlmsg->mtype_case) {
	case MAC_LIMIT_CONFIG__MTYPE_PROFILE:
		ret = mac_limit_set_profile(mlmsg->profile);
		break;
	case MAC_LIMIT_CONFIG__MTYPE_IFVLAN:
		ret = mac_limit_set_intf_cfg(mlmsg->ifvlan);
		break;
	default:
		RTE_LOG(INFO, MAC_LIMIT,
			"unhandled MacLimitConfig message type %d\n",
			mlmsg->mtype_case);
		ret = 0;
		break;
	}

	mac_limit_config__free_unpacked(mlmsg, NULL);
	return ret;
}

PB_REGISTER_CMD(maclimit_cmd) = {
	.cmd = "vyatta:maclimit",
	.handler = cmd_mac_limit_cfg,
};

static int mac_limit_entry_get_count(struct mac_limit_entry *entry)
{
	uint16_t vlan;
	struct ifnet *ifp;
	struct if_vlan_feat *vlan_feat;
	struct fal_attribute_t vlan_attr;

	vlan = entry->mle_vlan;
	ifp =  entry->mle_ifp;
	vlan_attr.id = FAL_VLAN_FEATURE_ATTR_MAC_COUNT;

	vlan_feat = if_vlan_feat_get(ifp, vlan);
	if (!vlan_feat) {
		RTE_LOG(ERR, MAC_LIMIT,
				"Failed to retrieve mac count for intf %s vlan %d\n",
				ifp->if_name, vlan);
		return 0;
	}
	if (!fal_vlan_feature_get_attr(vlan_feat->fal_vlan_feat, 1,
								   &vlan_attr))
		return vlan_attr.value.u32;

	return 0;
}

/*
 * Dump all structures or specific info.
 */
static void mac_limit_dump(FILE *f, const char *intf,
			   uint16_t vlan, const char *profile)
{
	struct mac_limit_entry *entry;
	struct mac_limit_entry *next;
	struct mac_limit_profile *instance;
	struct cds_lfht_iter iter;
	json_writer_t *wr;

	if (!intf || !profile)
		return;

	if (!mac_limit_profile_tbl)
		return;

	if (f == NULL)
		f = stderr;

	wr = jsonw_new(f);
	jsonw_name(wr, "mac-limit");
	jsonw_start_object(wr);
	if (strcmp(intf, "none")) {
		jsonw_name(wr, "instance");
		if (mac_limit_list) {
			jsonw_start_array(wr);
			cds_list_for_each_entry_safe(entry, next,
						     mac_limit_list, mle_list) {
				if (!strcmp(intf, "all") ||
					(!strcmp(intf,
						 entry->mle_ifp->if_name) &&
					 entry->mle_vlan == vlan)) {
					jsonw_start_object(wr);
					jsonw_string_field(
						wr, "interface",
						entry->mle_ifp->if_name);
					jsonw_uint_field(wr, "vlan",
							 entry->mle_vlan);
					jsonw_string_field(
						wr, "profile",
						entry->mle_profile->mlp_name);
					jsonw_end_object(wr);
				}
			}
			jsonw_end_array(wr);
		}
	}

	if (strcmp(profile, "none")) {
		jsonw_name(wr, "profile");
		jsonw_start_array(wr);
		cds_lfht_for_each_entry(mac_limit_profile_tbl, &iter,
					instance, mlp_node) {
			if (!strcmp(profile, "all")
				|| !strcmp(instance->mlp_name, profile)) {
				jsonw_start_object(wr);
				jsonw_string_field(wr, "name",
						   instance->mlp_name);
				jsonw_uint_field(wr, "limit",
						 instance->mlp_limit);
				jsonw_end_object(wr);
			}
		}
		jsonw_end_array(wr);
	}
	jsonw_end_object(wr);
	jsonw_destroy(&wr);
}

/*
 * mac-limit show status <intf> <vlan>
 * mac-limit dump (internal use)
 */
int cmd_mac_limit_op(FILE *f, int argc, char **argv)
{
	int count;
	char *ifname;
	uint16_t vlan;
	struct ifnet *ifp;
	json_writer_t *wr;
	struct mac_limit_profile *mlp;
	struct mac_limit_entry *mac_limit;

	if (argc < 5)
		goto error;

	if (!strcmp(argv[1], "dump")) {
		mac_limit_dump(f, argv[2], atoi(argv[3]),  argv[4]);
		return 0;
	}

	/*
	 * "status" replaces "mac-count" which is retained only on a temporary
	 * basis.
	 */
	if ((strcmp(argv[1], "show") ||
	     (strcmp(argv[2], "mac-count") && strcmp(argv[2], "status"))))
		goto error;

	ifname = argv[3];
	vlan = atoi(argv[4]);

	ifp = dp_ifnet_byifname(ifname);
	if (!ifp) {
		fprintf(f, "No interface %s\n", ifname);
		return -1;
	}

	mac_limit = mle_find_entry(ifp, vlan);
	if (!mac_limit) {
		fprintf(f, "No mac-limit configuration found for %s %d\n",
			ifname, vlan);
		return -1;
	}

	mlp = mac_limit->mle_profile;
	if (mlp == NULL) {
		fprintf(f, "Failed to find profile intf:%s, vlan %d\n",
				ifname, vlan);
		return -1;
	}

	count = mac_limit_entry_get_count(mac_limit);
	wr = jsonw_new(f);
	jsonw_name(wr, "statistics");
	jsonw_start_object(wr);
	jsonw_uint_field(wr, "limit", mlp->mlp_limit);
	jsonw_uint_field(wr, "count", count);
	jsonw_end_object(wr);
	jsonw_destroy(&wr);

	return 0;

error:
	fprintf(f, "Usage: mac-limit show <port> <vlan>");
	return -1;
}

static void
mac_limit_if_vlan_add(struct ifnet *ifp, uint16_t vlan)
{
	struct mac_limit_entry *entry;

	entry = mle_find_entry(ifp, vlan);
	if (!entry)
		return;

	RTE_LOG(DEBUG, MAC_LIMIT,
		"%s: Found entry for intf %s, vlan %d\n",
		__func__, ifp->if_name, vlan);

	mac_limit_fal_apply(entry, false);
}

static void
mac_limit_if_vlan_del(struct ifnet *ifp, uint16_t vlan)
{
	struct mac_limit_entry *entry;

	entry = mle_find_entry(ifp, vlan);
	if (!entry)
		return;

	RTE_LOG(DEBUG, MAC_LIMIT,
		"%s: Found entry for intf %s vlan %d\n",
			__func__, ifp->if_name, vlan);

	mac_limit_fal_unapply(entry);
}

static const struct dp_event_ops mac_limit_events = {
	.if_vlan_add = mac_limit_if_vlan_add,
	.if_vlan_del = mac_limit_if_vlan_del,
};

DP_STARTUP_EVENT_REGISTER(mac_limit_events);
