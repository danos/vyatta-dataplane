/*
 * Port Monitoring Command Processing
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <czmq.h>
#include <errno.h>
#include <linux/if.h>
#include <rte_config.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <urcu/list.h>
#include <urcu/uatomic.h>

#include "commands.h"
#include "dp_event.h"
#include "if_var.h"
#include "json_writer.h"
#include "pipeline/nodes/pl_nodes_common.h"
#include "pl_node.h"
#include "portmonitor/portmonitor.h"
#include "urcu.h"
#include "util.h"
#include "vplane_log.h"
#include "fal.h"

#define ERSPAN_SESSION(pmsess) \
		((pmsess->session_type == PORTMONITOR_ERSPAN_SOURCE) || \
		(pmsess->session_type == PORTMONITOR_ERSPAN_DESTINATION))

static CDS_LIST_HEAD(pmsrcif_list);
static CDS_LIST_HEAD(pmsession_list);

static uint8_t num_sessions;
static uint8_t num_srcif_for_all_sessions;

static struct cfg_if_list *portmonitor_cfg_list;

static void
portmonitor_event_if_index_set(struct ifnet *ifp);
static void
portmonitor_event_if_index_unset(struct ifnet *ifp, uint32_t ifindex);

static const struct dp_event_ops portmonitor_event_ops = {
	.if_index_set = portmonitor_event_if_index_set,
	.if_index_unset = portmonitor_event_if_index_unset,
};

static void
portmonitor_event_if_index_set(struct ifnet *ifp)
{
	struct cfg_if_list_entry *le;

	if (!portmonitor_cfg_list)
		return;

	le = cfg_if_list_lookup(portmonitor_cfg_list, ifp->if_name);
	if (!le)
		return;

	RTE_LOG(INFO, DATAPLANE,
		"Replaying portmonitor %s for interface %s\n",
		le->le_buf, ifp->if_name);

	char *outbuf = NULL;
	size_t outsize = 0;
	FILE *f = open_memstream(&outbuf, &outsize);

	if (f == NULL)
		RTE_LOG(ERR, DATAPLANE, "PM: open_memstream() failed\n");
	else {
		if (cmd_portmonitor(f, le->le_argc, le->le_argv) < 0)
			RTE_LOG(ERR, DATAPLANE,
				"PM: replay failed: %s\n", outbuf);
		free(outbuf);
	}

	cfg_if_list_del(portmonitor_cfg_list, ifp->if_name);

	if (!portmonitor_cfg_list->if_list_count) {
		cfg_if_list_destroy(&portmonitor_cfg_list);
		dp_event_unregister(&portmonitor_event_ops);
	}
}

static void
portmonitor_event_if_index_unset(struct ifnet *ifp, uint32_t ifindex __unused)
{
	if (!portmonitor_cfg_list)
		return;

	cfg_if_list_del(portmonitor_cfg_list, ifp->if_name);
	if (!portmonitor_cfg_list->if_list_count) {
		dp_event_unregister(&portmonitor_event_ops);
		cfg_if_list_destroy(&portmonitor_cfg_list);
	}
}

static int portmonitor_replay_init(void)
{
	if (!portmonitor_cfg_list) {
		portmonitor_cfg_list = cfg_if_list_create();
		if (!portmonitor_cfg_list)
			return -ENOMEM;

		dp_event_register(&portmonitor_event_ops);
	}
	return 0;
}

static struct portmonitor_info *portmonitor_info_alloc(struct ifnet *ifp)
{
	struct portmonitor_info *pminfo;

	if (ifp->pminfo)
		return ifp->pminfo;  /* already allocated */

	pminfo = rte_zmalloc_socket("if_pminfo",
					sizeof(struct portmonitor_info),
					RTE_CACHE_LINE_SIZE, ifp->if_socket);
	return pminfo;
}

static void portmonitor_pminfo_free(struct rcu_head *head)
{
	rte_free(caa_container_of(head, struct portmonitor_info, pminfo_rcu));
}

static void portmonitor_info_deinit(struct ifnet *ifp)
{
	struct portmonitor_info *pminfo = ifp->pminfo;

	if (pminfo && !ifp->portmonitor) {
		rcu_assign_pointer(ifp->pminfo, NULL);
		call_rcu(&pminfo->pminfo_rcu, portmonitor_pminfo_free);
	}
}

static void set_srcif_enabled(struct ifnet *ifp,
				struct portmonitor_session *pmsess,
				bool enabled)
{
	ifp->portmonitor = 0;
	pl_node_remove_feature_by_inst(&portmonitor_in_feat, ifp);
	pl_node_remove_feature_by_inst(&portmonitor_out_feat, ifp);
	if (enabled && pmsess->session_type && pmsess->dest_ifp) {
		if (ERSPAN_SESSION(pmsess)) {
			if (!pmsess->erspan_id || !pmsess->erspan_hdr_type)
				return;
		}

		ifp->portmonitor = 1;
		pl_node_add_feature_by_inst(&portmonitor_in_feat, ifp);
		pl_node_add_feature_by_inst(&portmonitor_out_feat, ifp);

		if (pmsess->session_type == PORTMONITOR_ERSPAN_SOURCE) {
			if (pmsess->erspan_hdr_type == ERSPAN_TYPE_II)
				pmsess->gre_proto = ERSPAN_TYPE_II_GRE_PROTOCOL_TYPE;
			else if (pmsess->erspan_hdr_type == ERSPAN_TYPE_III)
				pmsess->gre_proto = ERSPAN_TYPE_III_GRE_PROTOCOL_TYPE;
		}
	}
}


static void portmonitor_session_srcif_set_enabled(uint8_t session_id,
							bool enabled)
{
	struct portmonitor_srcif *pmsrcif;
	struct portmonitor_session *pmsess;

	cds_list_for_each_entry_rcu(pmsrcif, &pmsrcif_list, srcif_list) {
		pmsess = pmsrcif->pm_session;
		if (pmsess && pmsess->session_id == session_id)
			set_srcif_enabled(pmsrcif->ifp, pmsess, enabled);
	}
}

static void set_issrcif(struct ifnet *ifp, struct portmonitor_session *pmsess)
{
	struct portmonitor_info *pminfo = rcu_dereference(ifp->pminfo);
	if (!pminfo)
		return;

	if (pmsess->session_type == PORTMONITOR_SPAN ||
		pmsess->session_type == PORTMONITOR_RSPAN_SOURCE ||
		pmsess->session_type == PORTMONITOR_ERSPAN_SOURCE) {
		pminfo->pm_iftype = PM_SRC_SESSION_SRC_IF;
	} else if (pmsess->session_type == PORTMONITOR_RSPAN_DESTINATION ||
		pmsess->session_type == PORTMONITOR_ERSPAN_DESTINATION) {
		pminfo->pm_iftype = PM_DST_SESSION_SRC_IF;
	}
}

static void portmonitor_session_set_issrcif(uint8_t session_id)
{
	struct portmonitor_srcif *pmsrcif;
	struct portmonitor_session *pmsess;

	cds_list_for_each_entry_rcu(pmsrcif, &pmsrcif_list, srcif_list) {
		pmsess = pmsrcif->pm_session;
		if (pmsess && pmsess->session_id == session_id)
			set_issrcif(pmsrcif->ifp, pmsess);
	}
}

static struct portmonitor_srcif *get_pmsrcif_byifindex(uint32_t if_index)
{
	struct portmonitor_srcif *pmsrcif;

	cds_list_for_each_entry_rcu(pmsrcif, &pmsrcif_list, srcif_list) {
		if (pmsrcif->ifp->if_index == if_index)
			return pmsrcif;
	}
	return NULL;
}

static struct portmonitor_session *get_pmsession_bysessionid(uint8_t session_id)
{
	struct portmonitor_session *pmsess;

	cds_list_for_each_entry_rcu(pmsess, &pmsession_list, session_list) {
		if (pmsess->session_id == session_id)
			return pmsess;
	}
	return NULL;
}

static struct portmonitor_session *portmonitor_add_session(uint8_t session_id)
{
	struct portmonitor_session *pmsess;

	if (num_sessions > MAX_PORTMONITOR_SESSIONS) {
		RTE_LOG(NOTICE, DATAPLANE,
			"Portmonitor: Exceeded maximum number of sessions %d\n",
			MAX_PORTMONITOR_SESSIONS);
		return NULL;
	}
	pmsess = zmalloc_aligned(sizeof(*pmsess));
	if (!pmsess)
		return NULL;

	pmsess->session_id = session_id;

	pmsess->filter_list = zlist_new();
	if (!pmsess->filter_list) {
		free(pmsess);
		return NULL;
	}

	cds_list_add_tail_rcu(&pmsess->session_list, &pmsession_list);
	num_sessions++;
	return pmsess;
}

static void portmonitor_info_delete(struct ifnet *ifp)
{
	ifp->portmonitor = 0;
	pl_node_remove_feature_by_inst(&portmonitor_in_feat, ifp);
	pl_node_remove_feature_by_inst(&portmonitor_out_feat, ifp);
	portmonitor_info_deinit(ifp);
}

void portmonitor_cleanup(struct ifnet *ifp)
{
	struct portmonitor_info *pminfo = ifp->pminfo;
	struct portmonitor_session *pmsess;

	if (pminfo == NULL)
		return;

	if (pminfo->pm_iftype == PM_SESSION_DST_IF) {
		pmsess = pminfo->pm_session;
		if (pmsess != NULL && pmsess->dest_ifp != NULL)
			rcu_assign_pointer(pmsess->dest_ifp, NULL);
	} else {
		ifp->portmonitor = 0;
		pl_node_remove_feature_by_inst(&portmonitor_in_feat, ifp);
		pl_node_remove_feature_by_inst(&portmonitor_out_feat, ifp);
	}

	rcu_assign_pointer(ifp->pminfo, NULL);
	call_rcu(&pminfo->pminfo_rcu, portmonitor_pminfo_free);
}

static void portmonitor_srcif_free(struct rcu_head *head)
{
	free(caa_container_of(head, struct portmonitor_srcif, srcif_rcu));
}

static void portmonitor_session_free(struct rcu_head *head)
{
	free(caa_container_of(head, struct portmonitor_session, session_rcu));
}

static void
pm_if_update_hw_mirroring(const struct ifnet *ifp)
{
	struct portmonitor_info *pminfo = rcu_dereference(ifp->pminfo);
	struct fal_attribute_t attr = {
		.id = FAL_PORT_ATTR_HW_MIRRORING,
		.value.booldata = false
	};

	if (!pminfo)
		return;
	/* Query plugin to check if hardware is mirroring this interface
	 * Get attribute to see if hardware will mirror for this interface
	 * This will later be used in forwarding path to avoid double mirroring
	 * in dataplane.
	 */
	if (!fal_l2_get_attrs(ifp->if_index, 1, &attr))
		pminfo->hw_mirroring = attr.value.booldata;
	else
		pminfo->hw_mirroring = false;

	RTE_LOG(INFO, DATAPLANE,
		"Portmonitor(%s):Intf %s, hw forwarding %s, hw mirroring %s\n",
		__func__,
		ifp->if_name,
		ifp->hw_forwarding ? "enabled" : "disabled",
		pminfo->hw_mirroring ? "enabled" : "disabled");
}

static void pm_fal_src_update(const struct ifnet *ifp,
			      const struct portmonitor_session *pmsess,
			      uint32_t id, bool delete)
{

	struct fal_object_list_t *obj_list;

	/* Only 1 portmonitor session is supported per source */
	obj_list = alloca(sizeof(*obj_list) + (1 * sizeof(fal_object_t)));

	/* Count is marked 0 for delete */
	if (delete)
		obj_list->count = 0;
	else
		obj_list->count = 1;

	obj_list->list[0] = pmsess->fal_obj;

	struct fal_attribute_t attr = {
		.id = id,
		.value.objlist = obj_list
	};
	fal_l2_upd_port(ifp->if_index, &attr);

	pm_if_update_hw_mirroring(ifp);
}

static void portmonitor_srcif_delete(struct portmonitor_srcif *pmsrcif)

{
	const struct portmonitor_session *pmsess;
	const struct portmonitor_info *pminfo;
	struct ifnet *ifp;

	ifp = dp_ifnet_byifname(pmsrcif->ifname);
	if (ifp == NULL) {
		RTE_LOG(ERR, DATAPLANE,
			"PM: cannot delete source, no such interface %s\n",
			pmsrcif->ifname);
		return;
	}

	pmsess = pmsrcif->pm_session;
	pminfo = ifp->pminfo;
	if (pminfo->direction & PORTMONITOR_DIRECTION_RX)
		pm_fal_src_update(ifp, pmsess,
				  FAL_PORT_ATTR_INGRESS_MIRROR_SESSION, true);

	if (pminfo->direction & PORTMONITOR_DIRECTION_TX)
		pm_fal_src_update(ifp, pmsess,
				  FAL_PORT_ATTR_EGRESS_MIRROR_SESSION, true);

	if (ifp == pmsrcif->ifp)
		portmonitor_info_delete(ifp);
}

static void
pm_event_if_feat_mode_change(struct ifnet *ifp,
			     enum if_feat_mode_event event)
{
	bool enable;

	if (event == IF_FEAT_MODE_EVENT_L2_FAL_ENABLED)
		enable = true;
	else if (event == IF_FEAT_MODE_EVENT_L2_FAL_DISABLED)
		enable = false;
	else
		return;

	RTE_LOG(INFO, DATAPLANE,
		"Portmonitor(%s):Intf %s, hw forwarding changed to %s\n",
		__func__,
		ifp->if_name,
		enable ? "enabled" : "disabled");
}

static const struct dp_event_ops pm_event_ops = {
	.if_feat_mode_change = pm_event_if_feat_mode_change,
};

static void portmonitor_del_all_srcif(uint8_t session_id)
{
	struct portmonitor_srcif *pmsrcif;

	cds_list_for_each_entry_rcu(pmsrcif, &pmsrcif_list, srcif_list) {
		if (pmsrcif->pm_session->session_id == session_id) {
			portmonitor_srcif_delete(pmsrcif);
			num_srcif_for_all_sessions--;
			cds_list_del_rcu(&pmsrcif->srcif_list);
			call_rcu(&pmsrcif->srcif_rcu, portmonitor_srcif_free);
		}
	}
	if (!num_srcif_for_all_sessions)
		dp_event_unregister(&pm_event_ops);
}

static int portmonitor_del_srcif(uint8_t session_id, const char *ifname)
{
	struct portmonitor_srcif *pmsrcif;
	struct portmonitor_session *pmsess;

	cds_list_for_each_entry_rcu(pmsrcif, &pmsrcif_list, srcif_list) {
		pmsess = pmsrcif->pm_session;
		if (pmsess->session_id == session_id &&
			strncmp(pmsrcif->ifname, ifname, strlen(ifname)) == 0) {
			portmonitor_srcif_delete(pmsrcif);
			cds_list_del_rcu(&pmsrcif->srcif_list);
			call_rcu(&pmsrcif->srcif_rcu, portmonitor_srcif_free);
			return 0;
		}
	}
	return -1;
}

static struct ifnet *get_vif(const char *ifname, uint16_t vid)
{
	char if_name[IFNAMSIZ];

	snprintf(if_name, IFNAMSIZ, "%s.%d", ifname, vid);
	return dp_ifnet_byifname(if_name);
}

static int portmonitor_session_del_srcif(struct portmonitor_session *pmsess,
					const char *ifname, uint16_t vid)
{
	char if_name[IFNAMSIZ];
	int ret;

	if (vid) {
		snprintf(if_name, IFNAMSIZ, "%s.%d", ifname, vid);
		ret = portmonitor_del_srcif(pmsess->session_id, if_name);
	} else
		ret = portmonitor_del_srcif(pmsess->session_id, ifname);
	if (ret < 0)
		return -1;

	num_srcif_for_all_sessions--;
	pmsess->srcif_cnt--;

	if (!num_srcif_for_all_sessions)
		dp_event_unregister(&pm_event_ops);

	return 0;
}

static void portmonitor_destifp_cleanup(struct portmonitor_session *pmsess)
{
	if (pmsess != NULL && pmsess->dest_ifp != NULL) {
		struct ifnet *dest_ifp = pmsess->dest_ifp;
		struct fal_attribute_t attr[] = {
			{ .id = FAL_MIRROR_SESSION_ATTR_MONITOR_PORT,
			  .value.u32 = 0 }
		};
		int rc;

		/* Call FAL plugin API to delete dstif from session */
		rc = fal_mirror_session_set_attr(pmsess->fal_obj, attr);
		if (rc && rc != -EOPNOTSUPP)
			RTE_LOG(ERR, DATAPLANE,
				"PM :Set session destination if failed(%d)\n",
				rc);

		rcu_assign_pointer(pmsess->dest_ifp, NULL);
		portmonitor_info_delete(dest_ifp);
		memset(pmsess->dest_ifname, 0, sizeof(pmsess->dest_ifname));
	}

}

static int portmonitor_session_del_dstif(struct portmonitor_session *pmsess,
					const char *ifname, uint16_t vid)
{
	char if_name[IFNAMSIZ];
	int ret;

	if (vid) {
		snprintf(if_name, IFNAMSIZ, "%s.%d", ifname, vid);
		ret = strncmp(pmsess->dest_ifname, if_name, strlen(if_name));
	} else
		ret = strncmp(pmsess->dest_ifname, ifname, strlen(ifname));
	if (ret != 0)
		return -1;

	portmonitor_session_srcif_set_enabled(pmsess->session_id, false);
	portmonitor_destifp_cleanup(pmsess);
	return 0;
}

static void portmonitor_del_session(uint8_t session_id)
{
	struct portmonitor_session *pmsess;
	int rc;

	pmsess = get_pmsession_bysessionid(session_id);
	if (!pmsess)
		return;

	zlist_destroy(&pmsess->filter_list);
	if (pmsess->srcif_cnt > 0)
		portmonitor_del_all_srcif(session_id);

	portmonitor_destifp_cleanup(pmsess);

	rc = fal_mirror_session_delete(pmsess->fal_obj);
	if (rc && rc != -EOPNOTSUPP)
		RTE_LOG(ERR, DATAPLANE,
			"PM : FAL session(%d) del failed(%d)\n",
			session_id, rc);

	num_sessions--;
	cds_list_del_rcu(&pmsess->session_list);
	call_rcu(&pmsess->session_rcu, portmonitor_session_free);
}

static void portmonitor_session_set_type(struct portmonitor_session *pmsess,
					uint8_t session_type)
{
	pmsess->session_type = session_type;
	if (pmsess->srcif_cnt > 0) {
		portmonitor_session_set_issrcif(pmsess->session_id);
		portmonitor_session_srcif_set_enabled(pmsess->session_id,
							true);
	}
}

static void portmonitor_session_set_erspan_id(struct portmonitor_session *pmsess,
						uint16_t erspan_id)
{
	pmsess->erspan_id = erspan_id;
	if (pmsess->srcif_cnt > 0) {
		portmonitor_session_set_issrcif(pmsess->session_id);
		portmonitor_session_srcif_set_enabled(pmsess->session_id,
							true);
	}
}

static void portmonitor_session_set_erspan_hdr_type(struct portmonitor_session *pmsess,
							uint8_t erspan_hdr_type)
{
	pmsess->erspan_hdr_type = erspan_hdr_type;
	if (pmsess->srcif_cnt > 0) {
		portmonitor_session_set_issrcif(pmsess->session_id);
		portmonitor_session_srcif_set_enabled(pmsess->session_id,
							true);
	}
}

static void portmonitor_filter_free(void *item)
{
	struct portmonitor_filter *filter = item;

	if (!item)
		return;

	free(filter->name);
	free(filter);
}

static struct portmonitor_filter *portmonitor_filter_create(const char *name,
								uint8_t type)
{
	struct portmonitor_filter *filter;

	filter = malloc(sizeof(*filter));
	if (filter == NULL)
		return NULL;

	filter->name = strdup(name);
	if (filter->name != NULL && (type == PORTMONITOR_IN_FILTER ||
		type == PORTMONITOR_OUT_FILTER)) {
		filter->type = type;
		return filter;
	}
	portmonitor_filter_free(filter);
	return NULL;
}

static bool check_portmonitor_filter_type(uint8_t type)
{
	return type == PORTMONITOR_IN_FILTER ||
		type == PORTMONITOR_OUT_FILTER;
}

static struct portmonitor_filter *portmonitor_filter_find(
					struct portmonitor_session *pmsess,
					const char *name, uint8_t type)
{
	struct portmonitor_filter *filter;

	if (pmsess->filter_list == NULL)
		return NULL;
	for (filter = zlist_first(pmsess->filter_list);
			filter != NULL;
			filter = zlist_next(pmsess->filter_list))
		if (filter->type == type && streq(filter->name, name))
			return filter;
	return NULL;
}

static int portmonitor_session_config_filter(struct portmonitor_session *pmsess,
						char *name, uint8_t type,
						uint8_t action)
{
	struct portmonitor_filter *filter;

	if (pmsess->session_type == PORTMONITOR_RSPAN_DESTINATION ||
		pmsess->session_type == PORTMONITOR_ERSPAN_DESTINATION)
		return -1;
	if (!name)
		return -1;
	if (!check_portmonitor_filter_type(type))
		return -1;

	if (action == PORTMONITOR_FILTER_SET) {
		filter = portmonitor_filter_create(name, type);
		if (filter == NULL)
			return -1;
		zlist_append(pmsess->filter_list, filter);
		zlist_freefn(pmsess->filter_list, filter,
				portmonitor_filter_free, true);
	} else if (action == PORTMONITOR_FILTER_DELETE) {
		filter = portmonitor_filter_find(pmsess, name, type);
		if (filter == NULL)
			return -1;
		zlist_remove(pmsess->filter_list, filter);
	} else
		return -1;
	return 0;
}

static int portmonitor_add_srcif(struct ifnet *ifp,
				struct portmonitor_session *pmsess,
				uint8_t direction)
{
	struct portmonitor_srcif *pmsrcif;
	struct portmonitor_info *pminfo;

	if (num_srcif_for_all_sessions > MAX_PORTMONITOR_SRC_INTF) {
		RTE_LOG(NOTICE, DATAPLANE,
		"Portmonitor: Exceeded maximum number of source interfaces %d\n",
		MAX_PORTMONITOR_SRC_INTF);
		return -1;
	}
	pmsrcif = calloc(1, sizeof(struct portmonitor_srcif));
	if (!pmsrcif)
		return -1;

	pminfo = portmonitor_info_alloc(ifp);
	if (!pminfo) {
		free(pmsrcif);
		return -1;
	}

	pmsrcif->ifp = ifp;
	snprintf(pmsrcif->ifname, sizeof(pmsrcif->ifname), "%s", ifp->if_name);
	pmsrcif->pm_session = pmsess;

	pmsess->srcif_cnt++;
	cds_list_add_tail_rcu(&pmsrcif->srcif_list, &pmsrcif_list);

	if (!num_srcif_for_all_sessions)
		dp_event_register(&pm_event_ops);

	num_srcif_for_all_sessions++;

	if (!direction)
		pminfo->direction = PORTMONITOR_DIRECTION_RX |
					PORTMONITOR_DIRECTION_TX;
	else
		pminfo->direction = direction;
	pminfo->pm_session = pmsess;
	rcu_assign_pointer(ifp->pminfo, pminfo);
	set_issrcif(ifp, pmsess);

	set_srcif_enabled(ifp, pmsess, true);

	/* FAL plugin API */
	if (pminfo->direction & PORTMONITOR_DIRECTION_RX)
		pm_fal_src_update(ifp, pmsess,
				  FAL_PORT_ATTR_INGRESS_MIRROR_SESSION, false);

	if (pminfo->direction & PORTMONITOR_DIRECTION_TX)
		pm_fal_src_update(ifp, pmsess,
				  FAL_PORT_ATTR_EGRESS_MIRROR_SESSION, false);

	return 0;
}

static int portmonitor_session_set_srcif(FILE *f,
					struct portmonitor_session *pmsess,
					const char *ifname, uint16_t vid,
					uint8_t direction)
{
	struct ifnet *ifp;
	struct portmonitor_srcif *pmsrcif;
	struct portmonitor_info *pminfo;

	if (vid) {
		ifp = get_vif(ifname, vid);
		if (!ifp) {
			fprintf(f, "Unknown source VIF interface %s.%d\n",
					ifname, vid);
			return -1;
		}
	} else {
		ifp = dp_ifnet_byifname(ifname);
		if (!ifp) {
			fprintf(f, "Unknown source interface %s\n", ifname);
			return -1;
		}
	}

	switch (pmsess->session_type) {
	case PORTMONITOR_NONE:
		break;
	case PORTMONITOR_RSPAN_DESTINATION:
		if (ifp->if_type != IFT_L2VLAN) {
			fprintf(f, "Source interface must be a VIF\n");
			return -1;
		}
		break;
	case PORTMONITOR_ERSPAN_DESTINATION:
		if (ifp->if_type != IFT_TUNNEL_GRE) {
			fprintf(f, "Source interface must be ERSPAN tunnel\n");
			return -1;
		}
		break;
	default:
		if (ifp->if_type != IFT_ETHER && ifp->if_type != IFT_L2VLAN) {
			fprintf(f, "Source interface must be physical or VIF\n");
			return -1;
		}
	}

	pmsrcif = get_pmsrcif_byifindex(ifp->if_index);
	if (pmsrcif) {
		/* Existing entry */
		pminfo = rcu_dereference(pmsrcif->ifp->pminfo);

		uint8_t old_direction = pminfo->direction;
		if (!direction)
			pminfo->direction = PORTMONITOR_DIRECTION_RX |
						PORTMONITOR_DIRECTION_TX;
		else
			pminfo->direction = direction;
		/* Update FAL direction */
		if ((old_direction & PORTMONITOR_DIRECTION_RX) &&
			!(pminfo->direction & PORTMONITOR_DIRECTION_RX))
			/* Delete for ingress mirroring */
			pm_fal_src_update(ifp, pmsess,
					  FAL_PORT_ATTR_INGRESS_MIRROR_SESSION,
					  true);
		if ((old_direction & PORTMONITOR_DIRECTION_TX) &&
			!(pminfo->direction & PORTMONITOR_DIRECTION_TX))
			/* Delete for egress mirroring */
			pm_fal_src_update(ifp, pmsess,
					  FAL_PORT_ATTR_EGRESS_MIRROR_SESSION,
					  true);
		if (!(old_direction & PORTMONITOR_DIRECTION_RX) &&
			(pminfo->direction & PORTMONITOR_DIRECTION_RX))
			/* Add for ingress mirroring */
			pm_fal_src_update(ifp, pmsess,
					  FAL_PORT_ATTR_INGRESS_MIRROR_SESSION,
					  false);
		if (!(old_direction & PORTMONITOR_DIRECTION_TX) &&
			(pminfo->direction & PORTMONITOR_DIRECTION_TX))
			/* Add for egress mirroring */
			pm_fal_src_update(ifp, pmsess,
					  FAL_PORT_ATTR_EGRESS_MIRROR_SESSION,
					  false);

	} else if (portmonitor_add_srcif(ifp, pmsess, direction) < 0) {
		fprintf(f, "Cannot create source interface %s\n", ifp->if_name);
		return -1;
	}
	return 0;
}

static int portmonitor_session_set_dstif(FILE *f,
					struct portmonitor_session *pmsess,
					const char *ifname, uint16_t vid)
{
	struct ifnet *ifp;
	struct portmonitor_info *pminfo;
	int rc;

	if (vid) {
		ifp = get_vif(ifname, vid);
		if (!ifp) {
			fprintf(f, "Unknown destination VIF interface %s.%d\n",
					ifname, vid);
			return -1;
		}
	} else {
		ifp = dp_ifnet_byifname(ifname);
		if (!ifp) {
			fprintf(f, "Unknown destination interface %s\n", ifname);
			return -1;
		}
	}

	switch (pmsess->session_type) {
	case PORTMONITOR_NONE:
		break;
	case PORTMONITOR_RSPAN_SOURCE:
		if (ifp->if_type != IFT_L2VLAN) {
			fprintf(f, "Destination interface must be a VIF\n");
			return -1;
		}
		break;
	case PORTMONITOR_ERSPAN_SOURCE:
		if (ifp->if_type != IFT_TUNNEL_GRE) {
			fprintf(f, "Destination interface must be ERSPAN tunnel\n");
			return -1;
		}
		break;
	default:
		if (ifp->if_type != IFT_ETHER) {
			fprintf(f, "Destination interface must be physical interface\n");
			return -1;
		}
	}

	pminfo = portmonitor_info_alloc(ifp);
	if (!pminfo)
		return -1;

	snprintf(pmsess->dest_ifname,
		 sizeof(pmsess->dest_ifname), "%s", ifp->if_name);
	rcu_assign_pointer(pmsess->dest_ifp, ifp);

	pminfo->pm_session = pmsess;
	pminfo->pm_iftype = PM_SESSION_DST_IF;
	rcu_assign_pointer(ifp->pminfo, pminfo);

	struct fal_attribute_t attr[] = {
		{ .id = FAL_MIRROR_SESSION_ATTR_MONITOR_PORT,
		.value.u32 = ifp->if_index }
	};

	/* Call FAL plugin API to delete dstif from session */
	rc = fal_mirror_session_set_attr(pmsess->fal_obj, attr);
	if (rc && rc != -EOPNOTSUPP)
		RTE_LOG(ERR, DATAPLANE,
			"PM :FAL Set session attr (monitor) failed(%d)\n", rc);

	if (pmsess->srcif_cnt > 0)
		portmonitor_session_srcif_set_enabled(pmsess->session_id, true);
	return 0;
}

static void show_one_session(struct portmonitor_session *s, json_writer_t *wr)
{
	struct portmonitor_srcif *pmsrcif;
	struct portmonitor_info *pminfo;
	struct portmonitor_filter *filter;

	jsonw_start_object(wr);
	jsonw_uint_field(wr, "session", s->session_id);
	if (s->session_type == PORTMONITOR_SPAN)
		jsonw_string_field(wr, "type", "span");
	else if (s->session_type == PORTMONITOR_RSPAN_SOURCE)
		jsonw_string_field(wr, "type", "rspan-source");
	else if (s->session_type == PORTMONITOR_RSPAN_DESTINATION)
		jsonw_string_field(wr, "type", "rspan-destination");
	else if (s->session_type == PORTMONITOR_ERSPAN_SOURCE)
		jsonw_string_field(wr, "type", "erspan-source");
	else if (s->session_type == PORTMONITOR_ERSPAN_DESTINATION)
		jsonw_string_field(wr, "type", "erspan-destination");
	else
		jsonw_string_field(wr, "type", "not defined");
	if (s->disabled)
		jsonw_string_field(wr, "state", "disabled");
	else
		jsonw_string_field(wr, "state", "enabled");
	if (s->erspan_id)
		jsonw_int_field(wr, "erspanid", s->erspan_id);
	if (s->erspan_hdr_type == ERSPAN_TYPE_II)
		jsonw_int_field(wr, "erspanhdr", ERSPAN_TYPE_II);
	else if (s->erspan_hdr_type == ERSPAN_TYPE_III)
		jsonw_int_field(wr, "erspanhdr", ERSPAN_TYPE_III);
	jsonw_name(wr, "source_interfaces");
	jsonw_start_array(wr);
	cds_list_for_each_entry_rcu(pmsrcif, &pmsrcif_list, srcif_list) {
		if (pmsrcif->pm_session->session_id != s->session_id)
			continue;
		pminfo = rcu_dereference(pmsrcif->ifp->pminfo);
		if (!pminfo)
			continue;
		jsonw_start_object(wr);
		jsonw_string_field(wr, "name", pmsrcif->ifp->if_name);
		if (pminfo->pm_iftype == PM_SRC_SESSION_SRC_IF) {
			if ((pminfo->direction & PORTMONITOR_DIRECTION_RX) &&
				(pminfo->direction & PORTMONITOR_DIRECTION_TX))
				jsonw_string_field(wr, "direction", "both");
			else if (pminfo->direction & PORTMONITOR_DIRECTION_RX)
				jsonw_string_field(wr, "direction", "rx");
			else if (pminfo->direction & PORTMONITOR_DIRECTION_TX)
				jsonw_string_field(wr, "direction", "tx");
		}
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
	if (s->dest_ifname[0] != '\0')
		jsonw_string_field(wr, "destination_interface",
					s->dest_ifname);
	if (zlist_size(s->filter_list) != 0 &&
		s->session_type != PORTMONITOR_RSPAN_DESTINATION &&
		s->session_type != PORTMONITOR_ERSPAN_DESTINATION) {
		jsonw_name(wr, "filters");
		jsonw_start_array(wr);
		for (filter = zlist_first(s->filter_list); filter != NULL;
			filter = zlist_next(s->filter_list)) {
			jsonw_start_object(wr);
			jsonw_string_field(wr, "name", filter->name);
			if (filter->type == PORTMONITOR_IN_FILTER)
				jsonw_string_field(wr, "type", "in");
			else if (filter->type == PORTMONITOR_OUT_FILTER)
				jsonw_string_field(wr, "type", "out");
			jsonw_end_object(wr);
		}
		jsonw_end_array(wr);
	}
	jsonw_end_object(wr);
}

static void portmonitor_show(FILE *f, uint8_t session_id)
{
	struct portmonitor_session *pmsess;
	json_writer_t *wr = jsonw_new(f);

	if (!wr)
		return;

	jsonw_name(wr, "portmonitor_information");
	jsonw_start_array(wr);

	if (session_id) {
		pmsess = get_pmsession_bysessionid(session_id);
		if (!pmsess) {
			jsonw_start_object(wr);
			jsonw_int_field(wr, "error_invalid_session",
						session_id);
			jsonw_end_object(wr);
		} else {
			show_one_session(pmsess, wr);
		}
	} else {
		cds_list_for_each_entry_rcu(pmsess, &pmsession_list,
						session_list) {
			show_one_session(pmsess, wr);
		}
	}
	jsonw_end_array(wr);
	jsonw_destroy(&wr);
}

static bool get_value(char *strval, uint32_t *val)
{
	char *endptr;

	errno = 0;
	*val = strtoul(strval, &endptr, 0);

	if (*endptr == '\0' && strval != endptr && errno != ERANGE)
		return true;

	return false;
}

int cmd_portmonitor(FILE *f, int argc, char **argv)
{
	uint32_t session_id;
	uint32_t vid;
	uint32_t type;
	uint32_t direction;
	uint32_t erspan_id;
	uint32_t erspan_hdr_type;
	struct portmonitor_session *pmsess;
	int rc;

	if (argc < 3)
		goto bad_command;

	if (strcmp(argv[1], "show") == 0) {
		session_id = 0;
		if (argc == 4) {
			if (!get_value(argv[3], &session_id)) {
				fprintf(f, "Invalid session id %s\n", argv[3]);
				return -1;
			}
		}
		portmonitor_show(f, session_id);
		return 0;
	}

	if (argc < 8)
		goto bad_command;

	if (strcmp(argv[1], "del") == 0) {
		if (!get_value(argv[3], &session_id)) {
			fprintf(f, "Invalid portmonitor session id %s\n",
					argv[3]);
			return -1;
		}
		if (strcmp(argv[4], "0") == 0)
			portmonitor_del_session(session_id);
		else {
			pmsess = get_pmsession_bysessionid(session_id);
			if (!pmsess) {
				fprintf(f, "Invalid portmonitor session id %s\n",
						argv[3]);
				return -1;
			}
			if (strcmp(argv[4], "srcif") == 0) {
				if (!get_value(argv[6], &vid)) {
					fprintf(f, "Invalid vid %s\n", argv[6]);
					return -1;
				}
				cfg_if_list_del(portmonitor_cfg_list, argv[5]);
				if (portmonitor_session_del_srcif(pmsess,
							argv[5], vid) < 0) {
					fprintf(f, "Cannot delete source interface %s\n",
						argv[5]);
					return -1;
				}
			} else if (strcmp(argv[4], "dstif") == 0) {
				if (!get_value(argv[6], &vid)) {
					fprintf(f, "Invalid vid %s\n", argv[6]);
					return -1;
				}
				cfg_if_list_del(portmonitor_cfg_list, argv[5]);
				if (portmonitor_session_del_dstif(pmsess,
							argv[5], vid) < 0) {
					fprintf(f, "Cannot delete destination interface %s\n",
						argv[5]);
					return -1;
				}
			} else if (strcmp(argv[4], "disable") == 0) {
				pmsess->disabled = false;
				/* Call FAL plugin API */
				int rc;
				struct fal_attribute_t attr[] = {
				{ .id = FAL_MIRROR_SESSION_ATTR_STATE_DISABLE,
				  .value.booldata = false }
				};

				rc = fal_mirror_session_set_attr(
						pmsess->fal_obj,
						attr);
				if (rc && rc != -EOPNOTSUPP)
					RTE_LOG(ERR, DATAPLANE,
					"PM : Set session state failed(%d)\n",
					rc);

			} else if (strcmp(argv[4], "filter-in") == 0) {
				if (portmonitor_session_config_filter(
					pmsess, argv[5], PORTMONITOR_IN_FILTER,
					PORTMONITOR_FILTER_DELETE) < 0) {
					fprintf(f,
						"Cannot delete \"in\" filter %s\n",
						argv[5]);
					return -1;
				}
			} else if (strcmp(argv[4], "filter-out") == 0) {
				if (portmonitor_session_config_filter(pmsess,
					argv[5], PORTMONITOR_OUT_FILTER,
					PORTMONITOR_FILTER_DELETE) < 0) {
					fprintf(f,
						"Cannot delete \"out\" filter %s\n",
						argv[5]);
					return -1;
				}
			}
		}
		return 0;
	}

	if (strcmp(argv[1], "set") != 0)
		goto bad_command;

	if (strcmp(argv[2], "session") == 0) {
		if (!get_value(argv[3], &session_id)) {
			fprintf(f, "Invalid portmonitor session id %s\n",
					argv[3]);
			return -1;
		}
		pmsess = get_pmsession_bysessionid(session_id);
		if (!pmsess) {
			pmsess = portmonitor_add_session(session_id);
			if (!pmsess) {
				RTE_LOG(NOTICE, DATAPLANE,
				"Portmonitor: Cannot create session %s\n", argv[3]);
				fprintf(f, "Cannot create session %s\n", argv[3]);
				return -1;
			}
			if (strcmp(argv[4], "type") != 0) {
				fprintf(f, "Missing mandatory param type %s\n",
					argv[4]);
				return -1;
			}
			if (!get_value(argv[5], &type)) {
				fprintf(f, "Invalid session type %s\n",
						argv[5]);
				return -1;
			}
			portmonitor_session_set_type(pmsess, type);

			uint32_t fal_type;

			switch (pmsess->session_type) {

			case PORTMONITOR_SPAN:
				fal_type = FAL_MIRROR_SESSION_TYPE_LOCAL;
				break;

			case PORTMONITOR_RSPAN_SOURCE:
			case PORTMONITOR_RSPAN_DESTINATION:
				fal_type = FAL_MIRROR_SESSION_TYPE_REMOTE;
				break;

			case PORTMONITOR_ERSPAN_SOURCE:
			case PORTMONITOR_ERSPAN_DESTINATION:
				fal_type =
				FAL_MIRROR_SESSION_TYPE_ENHANCED_REMOTE;
				break;

			default:
				RTE_LOG(ERR, DATAPLANE,
				"PM: FAL unknown type(%d)\n",
				pmsess->session_type);

				return 0;

			}
			/* Call FAL plugin API to create session */
			struct fal_attribute_t attr_list[] = {
				{ .id = FAL_MIRROR_SESSION_ATTR_ID,
				  .value.u8 = session_id },
				{ .id =  FAL_MIRROR_SESSION_ATTR_TYPE,
				  .value.u32 = fal_type }
			};
			rc = fal_mirror_session_create(ARRAY_SIZE(attr_list),
						       attr_list,
						       &pmsess->fal_obj);
			if (rc && rc != -EOPNOTSUPP) {
				RTE_LOG(ERR, DATAPLANE,
				"PM: FAL create session failed(%d)\n", rc);
				pmsess->fal_obj = 0;
			}

			return 0;
		}
		if (strcmp(argv[4], "type") == 0) {
			if (!get_value(argv[5], &type)) {
				fprintf(f, "Invalid session type %s\n",
						argv[5]);
				return -1;
			}
			if (pmsess->session_type != type) {
				fprintf(f, "Session type cannot be changed\n");
				return -1;
			}
		} else if (strcmp(argv[4], "srcif") == 0) {
			if (!get_value(argv[6], &vid)) {
				fprintf(f, "Invalid vid %s\n", argv[6]);
				return -1;
			}
			if (!get_value(argv[7], &direction)) {
				fprintf(f, "Invalid direction %s\n", argv[7]);
				return -1;
			}
			if (!dp_ifnet_byifname(argv[5])) {
				if (portmonitor_replay_init() < 0) {
					RTE_LOG(ERR, DATAPLANE,
						"Portmonitor could not set up replay cache\n");
					return -ENOMEM;
				}
				RTE_LOG(INFO, DATAPLANE,
					"Caching portmonitor srcif for %s\n",
					argv[5]);
				cfg_if_list_add(portmonitor_cfg_list,
						argv[5], argc, argv);
				return 0;
			}
			if (portmonitor_session_set_srcif(f, pmsess, argv[5],
				vid, direction) < 0)
				return -1;
		} else if (strcmp(argv[4], "dstif") == 0) {
			if (!get_value(argv[6], &vid)) {
				fprintf(f, "Invalid vid %s\n", argv[6]);
				return -1;
			}
			if (!dp_ifnet_byifname(argv[5])) {
				if (portmonitor_replay_init() < 0) {
					RTE_LOG(ERR, DATAPLANE,
						"Portmonitor could not set up replay cache\n");
					return -ENOMEM;
				}
				RTE_LOG(INFO, DATAPLANE,
					"Caching portmonitor dstif for %s\n",
					argv[5]);
				cfg_if_list_add(portmonitor_cfg_list,
						argv[5], argc, argv);
				return 0;
			}
			if (portmonitor_session_set_dstif(f, pmsess, argv[5],
								vid) < 0)
				return -1;
		} else if (strcmp(argv[4], "erspanid") == 0) {
			if (!get_value(argv[5], &erspan_id)) {
				fprintf(f, "Invalid ERSPAN id %s\n",
						argv[5]);
				return -1;
			}
			portmonitor_session_set_erspan_id(pmsess, erspan_id);
		} else if (strcmp(argv[4], "erspanhdr") == 0) {
			if (!get_value(argv[5], &erspan_hdr_type)) {
				fprintf(f, "Invalid ERSPAN header type %s\n",
						argv[5]);
				return -1;
			}
			portmonitor_session_set_erspan_hdr_type(pmsess,
								erspan_hdr_type);
		} else if (strcmp(argv[4], "disable") == 0) {
			pmsess->disabled = true;
			struct fal_attribute_t attr[] = {
				{ .id = FAL_MIRROR_SESSION_ATTR_STATE_DISABLE,
				.value.booldata = true }
			};

			/* Call FAL plugin API to create session */
			rc = fal_mirror_session_set_attr(pmsess->fal_obj,
							 attr);
			if (rc && rc != -EOPNOTSUPP)
				RTE_LOG(ERR, DATAPLANE,
				"PM : FAL Set session state failed(%d)\n",
				rc);

		} else if (strcmp(argv[4], "filter-in") == 0) {
			if (portmonitor_session_config_filter(pmsess, argv[5],
						PORTMONITOR_IN_FILTER,
						PORTMONITOR_FILTER_SET) < 0) {
				fprintf(f, "Cannot set \"in\" filter %s\n",
					argv[5]);
				return -1;
			}
		} else if (strcmp(argv[4], "filter-out") == 0) {
			if (portmonitor_session_config_filter(pmsess, argv[5],
						PORTMONITOR_OUT_FILTER,
						PORTMONITOR_FILTER_SET) < 0) {
				fprintf(f, "Cannot set \"out\" filter %s\n",
					argv[5]);
				return -1;
			}
		} else
			goto bad_command;
	}

	return 0;

bad_command:
	RTE_LOG(NOTICE, DATAPLANE, "Portmonitor: Unknown command %s\n", argv[1]);
	fprintf(f, "Unknown portmonitor command: %s\n", argv[1]);
	return -1;
}
