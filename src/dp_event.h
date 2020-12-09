/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef DP_EVENT_H
#define DP_EVENT_H

#include <stdint.h>

#include "if_var.h"
#include "control.h"
#include "control.h"
#include "event.h"

/*
 * Maximum size of the event operations structs array.
 */
#define DP_EVENT_MAX_OPS 64

/* Specific dataplane events */
enum dp_evt {
	DP_EVT_VRF_CREATE = 1,
	DP_EVT_VRF_DELETE,
	DP_EVT_IF_RENAME,
	DP_EVT_IF_VRF_SET,
	DP_EVT_IF_ADDR_ADD,
	DP_EVT_IF_ADDR_DEL,
	DP_EVT_IF_CREATE,
	DP_EVT_IF_DELETE,
	DP_EVT_IF_INDEX_SET,
	DP_EVT_IF_INDEX_UNSET,
	DP_EVT_IF_MAC_ADDR_CHANGE,
	DP_EVT_IF_LINK_CHANGE,
	DP_EVT_IF_VLAN_ADD,
	DP_EVT_IF_VLAN_DEL,
	DP_EVT_IF_FEAT_MODE_CHANGE,
	DP_EVT_IF_MTU_CHANGE,
	DP_EVT_RESET_CONFIG,
	DP_EVT_INIT,
	DP_EVT_UNINIT,
	DP_EVT_IF_LAG_ADD_MEMBER,
	DP_EVT_IF_LAG_DELETE_MEMBER,
	DP_EVT_IF_LAG_CHANGE,
};

_Static_assert((int)DP_EVT_VRF_CREATE == (int)DP_EVENT_VRF_CREATE,
	       "public and internal vrf event create events differ");
_Static_assert((int)DP_EVT_VRF_DELETE == (int)DP_EVENT_VRF_DELETE,
	       "public and internal vrf event delete events differ");
_Static_assert((int)DP_EVT_IF_RENAME == (int)DP_EVENT_IF_RENAME,
		"public and internal if event rename events differ");
_Static_assert((int)DP_EVT_IF_VRF_SET == (int)DP_EVENT_IF_VRF_SET,
		"public and internal if vrf event set events differ");
_Static_assert((int)DP_EVT_IF_ADDR_ADD == (int)DP_EVENT_IF_ADDR_ADD,
		"public and internal if addr event add events differ");
_Static_assert((int)DP_EVT_IF_ADDR_DEL == (int)DP_EVENT_IF_ADDR_DEL,
		"public and internal if addr event delete events differ");

enum if_feat_mode_event {
	IF_FEAT_MODE_EVENT_L3_FAL_ENABLED,
	IF_FEAT_MODE_EVENT_L3_FAL_DISABLED,
	IF_FEAT_MODE_EVENT_L3_ENABLED,
	IF_FEAT_MODE_EVENT_L3_DISABLED,
	/* interface-embellishing feature set changed */
	IF_FEAT_MODE_EVENT_EMB_FEAT_CHANGED,
	IF_FEAT_MODE_EVENT_L2_FAL_ENABLED,
	IF_FEAT_MODE_EVENT_L2_FAL_DISABLED,
	IF_FEAT_MODE_EVENT_L2_CREATED,
	IF_FEAT_MODE_EVENT_L2_DELETED,
};

/* Event operations - 1:1 correspondence with above events */
struct dp_event_ops {
	void (*if_create)(struct ifnet *ifp);
	void (*if_delete)(struct ifnet *ifp);
	void (*if_index_set)(struct ifnet *ifp);
	void (*if_feat_mode_change)(struct ifnet *ifp,
				    enum if_feat_mode_event event);
	void (*if_index_unset)(struct ifnet *ifp, uint32_t idx);
	void (*if_rename)(struct ifnet *ifp, const char *old_name);
	void (*if_vrf_set)(struct ifnet *ifp);
	void (*if_addr_add)(enum cont_src_en cont_src, struct ifnet *ifp,
			uint32_t ifindex, int af, const void *addr);
	void (*if_addr_delete)(enum cont_src_en cont_src, struct ifnet *ifp,
			uint32_t ifindex, int af, const void *addr);
	void (*if_mac_addr_change)(struct ifnet *ifp, const void *mac_addr);
	void (*if_link_change)(struct ifnet *ifp, bool up, uint32_t speed);
	void (*if_vlan_add)(struct ifnet *ifp, uint16_t vlan);
	void (*if_vlan_del)(struct ifnet *ifp, uint16_t vlan);
	void (*if_mtu_change)(struct ifnet *ifp, uint32_t mtu);
	void (*if_lag_change)(struct ifnet *ifp, enum dp_if_lag_event event);
	void (*if_lag_add_member)(struct ifnet *team, struct ifnet *ifp);
	void (*if_lag_delete_member)(struct ifnet *team, struct ifnet *ifp);
	void (*reset_config)(enum cont_src_en cont_src);
	void (*vrf_create)(struct vrf *vrf);
	void (*vrf_delete)(struct vrf *vrf);
	void (*init)(void);
	void (*uninit)(void);

	const struct dp_events_ops *public_ops;
	struct rcu_head rcu;
};

#define DP_STARTUP_EVENT_REGISTER(x)			  \
	static __attribute__((__constructor__))		  \
	void __dp_startup_event_reg_##x(void)		  \
	{						  \
		dp_event_register(&x);			  \
	}						  \


/*
 * Protos
 */
void dp_event(enum dp_evt evt, uint32_t cont_src, void *obj,
		uint32_t val, uint32_t val2, const void *data);
void dp_event_register(const struct dp_event_ops *ops);
void dp_event_unregister(const struct dp_event_ops *ops);

#endif /* DP_EVENT_H */
