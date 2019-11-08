/*-
 * Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <libmnl/libmnl.h>
#include <linux/if_link.h>

#include "fal.h"
#include "if_var.h"
#include "vlan_if.h"
#include "vplane_log.h"

static int vlaninfo_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attr to avoid issues with newer kernels */
	if (mnl_attr_type_valid(attr, IFLA_VLAN_MAX) < 0)
		return MNL_CB_OK;

	if (type == IFLA_VLAN_ID) {
		if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0) {
			RTE_LOG(NOTICE, DATAPLANE,
				"invalid vlan id attribute %d\n", type);
			return MNL_CB_ERROR;
		}
	}

	tb[type] = attr;
	return MNL_CB_OK;

}

/* Examine vlan info to lookup/create vlan */
struct ifnet *vlan_nl_create(struct ifnet *parent_ifp,
			     const char *ifname, int ifindex,
			     struct nlattr *lb)
{
	struct nlattr *vlaninfo[IFLA_VLAN_MAX+1] = { NULL };
	uint16_t vlan;
	uint16_t vlan_proto = ETH_P_8021Q;

	if (!lb) {
		RTE_LOG(NOTICE, DATAPLANE, "missing vlan attributes\n");
		return NULL;
	}

	if (mnl_attr_parse_nested(lb, vlaninfo_attr, vlaninfo) != MNL_CB_OK) {
		RTE_LOG(NOTICE, DATAPLANE, "unparseable vlan attributes\n");
		return NULL;
	}

	if (!vlaninfo[IFLA_VLAN_ID]) {
		RTE_LOG(NOTICE, DATAPLANE, "missing vlan id\n");
		return NULL;
	}

	vlan = mnl_attr_get_u16(vlaninfo[IFLA_VLAN_ID]);

	if (vlaninfo[IFLA_VLAN_PROTOCOL])
		vlan_proto = ntohs(
			mnl_attr_get_u16(vlaninfo[IFLA_VLAN_PROTOCOL]));

	return vlan_if_create(parent_ifp, vlan, ifname, ifindex, vlan_proto);
}

static bool change_vlan(struct ifnet *ifp, struct nlattr *tb[],
			char const *kind, struct nlattr *kdata,
			enum cont_src_en cont_src)
{
	bool changed = false;
	struct ifnet *parent_ifp = NULL;
	struct nlattr *vlaninfo[IFLA_VLAN_MAX+1] = { NULL };
	uint16_t vlan;
	uint16_t vlan_proto = ETH_P_8021Q;

	if (tb[IFLA_LINK]) {
		unsigned int iflink = cont_src_ifindex(cont_src,
					      mnl_attr_get_u32(tb[IFLA_LINK]));
		if (iflink == 0)
			/* not associated with specific downlink */
			return changed;

		parent_ifp = ifnet_byifindex(iflink);
	}

	if (mnl_attr_parse_nested(kdata, vlaninfo_attr, vlaninfo) != MNL_CB_OK)
		return changed;

	if (!vlaninfo[IFLA_VLAN_ID])
		return changed;

	vlan = mnl_attr_get_u16(vlaninfo[IFLA_VLAN_ID]);

	if (vlaninfo[IFLA_VLAN_PROTOCOL])
		vlan_proto = ntohs(mnl_attr_get_u16(
					   vlaninfo[IFLA_VLAN_PROTOCOL]));

	if (strcmp(kind, "vlan") == 0) {
		struct fal_attribute_t vlan_attr = {
			.id = FAL_ROUTER_INTERFACE_ATTR_VLAN_ID,
			.value.u16 = vlan,
		};

		if (parent_ifp) {
			if (parent_ifp != ifp->if_parent)
				/*
				 * if-parent change should not set
				 * changed to true.
				 */
				vlan_if_change(parent_ifp, vlan,
					       ifp, vlan_proto);
		} else
			parent_ifp = ifp->if_parent;

		if (!vlan && ifp->if_vlan) {
			vlan_if_delete(ifp);
			ifp->if_vlan = 0;
			if_set_l3_intf_attr(ifp, &vlan_attr);
		} else if (vlan != ifp->if_vlan) {
			vlan_if_change(parent_ifp, vlan,
				       ifp, vlan_proto);

			if (!ifp->qinq_inner)
				changed = true;
			if_set_l3_intf_attr(ifp, &vlan_attr);
		} else if (vlan_proto != ifp->tpid) {
			if_vlan_proto_set(ifp, vlan_proto);
		}
	}

	return changed;
}

void vlan_nl_modify(struct ifnet *ifp,
		    struct nlattr *tb[],
		    char const *kind, struct nlattr *kdata,
		    enum cont_src_en cont_src)
{
	struct ifnet *pifp = ifp->if_parent;
	bool vlan_changed = false;
	struct fal_attribute_t vlan_attr = {
			FAL_PORT_ATTR_VLAN_ID, };

	if (pifp && kind && kdata)
		vlan_changed = change_vlan(ifp, tb, kind, kdata, cont_src);
	else if (tb[IFLA_LINK]) {
		pifp = ifnet_byifindex(
				cont_src_ifindex(cont_src,
					mnl_attr_get_u32(tb[IFLA_LINK])));

		if (pifp)
			vlan_if_change(pifp, ifp->if_vlan,
				       ifp, ETH_P_8021Q);
	}

	if (!vlan_changed)
		return;

	if (ifp->if_flags & IFF_UP)
		if_set_vlan_filter(pifp, ifp->if_vlan, true);

	vlan_attr.value.u16 = ifp->if_vlan;
	fal_l2_upd_port(ifp->if_index, &vlan_attr);
}
