/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include "fal.h"
#include "fal_plugin.h"
#include "vrf_internal.h"
#include "vplane_debug.h"
#include "ip_mcast_fal_interface.h"

static int fal_create_mvrf_xg_rpf_group(struct cds_lfht *viftable,
					vrfid_t vrf_id,
					fal_object_t *fal_rpf,
					struct fal_object_list_t **rpf_lst)
{
	uint32_t *ifindex_list;
	struct vif *vifp;
	struct cds_lfht_iter iter;
	uint32_t index = 0;
	uint32_t int_cnt = 0;
	int ret;

	cds_lfht_for_each_entry(viftable, &iter, vifp, node) {
		if (vifp->v_ifp && vifp->v_ifp->fal_l3 &&
		    (vrf_id == vifp->v_ifp->if_vrfid))
			int_cnt++;
	}

	if (int_cnt == 0)
		return -EINVAL;

	ifindex_list = calloc(int_cnt, sizeof(uint32_t));
	if (!ifindex_list)
		return -ENOMEM;

	cds_lfht_for_each_entry(viftable, &iter, vifp, node) {
		if (vifp->v_ifp && vifp->v_ifp->fal_l3 &&
		     (vrf_id == vifp->v_ifp->if_vrfid))
			ifindex_list[index++] = vifp->v_if_index;
	}

	ret = fal_create_ipmc_rpf_group(ifindex_list,
					int_cnt,
					fal_rpf,
					rpf_lst);
	if (ret != 0) {
		if (ret != -EOPNOTSUPP)
			DP_DEBUG(MULTICAST, ERR, MCAST,
				 "FAL punt entry failed to create RPF group.\n");
	}
	free(ifindex_list);
	return ret;
}

static int fal_mcast_int_enable(vrfid_t vrf_id, struct cds_lfht *viftable,
				fal_object_t *fal_obj, fal_object_t *fal_rpf,
				struct fal_object_list_t **rpf_lst,
				fal_object_t fal_l3, unsigned char af)
{
	struct fal_attribute_t ipmc_group_attr[2] =  { { 0 } };
	int ret;
	struct fal_ip_address_t source = { .addr.ip6 = { 0 } };
	struct fal_ip_address_t group;
	struct fal_ipmc_entry_t mentry;

	/* create (*,G) if it does not exist*/
	if (0 == *fal_rpf && 0 == *fal_obj) {
		/* create RPF group */
		ret = fal_create_mvrf_xg_rpf_group(viftable, vrf_id,
						   fal_rpf, rpf_lst);
		if (ret != 0)
			return ret;

		ipmc_group_attr[0].id = FAL_IPMC_ENTRY_ATTR_PACKET_ACTION;
		ipmc_group_attr[0].value.u32 = FAL_PACKET_ACTION_TRAP;
		ipmc_group_attr[1].id = FAL_IPMC_ENTRY_ATTR_RPF_GROUP_ID;
		ipmc_group_attr[1].value.objid = *fal_rpf;

		/* create entry */
		if (af == AF_INET) {
			source.addr_family = FAL_IP_ADDR_FAMILY_IPV4;

			group.addr_family = FAL_IP_ADDR_FAMILY_IPV4;
			group.addr.ip4 = htonl(0xE0000000); /*224.0.0.0 */

			mentry.type = FAL_IPMC_ENTRY_TYPE_XG;
			mentry.vrf_id = vrf_id;
			mentry.destination = group;
			mentry.source = source;
		} else {
			source.addr_family = FAL_IP_ADDR_FAMILY_IPV6;

			group.addr_family = FAL_IP_ADDR_FAMILY_IPV6;
			inet_pton(AF_INET6, "FF00::", (void *) &group.addr.ip6);

			mentry.type = FAL_IPMC_ENTRY_TYPE_XG;
			mentry.vrf_id = vrf_id;
			mentry.destination = group;
			mentry.source = source;
		}
		ret = fal_create_ip_mcast_entry(&mentry, 2, ipmc_group_attr,
						fal_obj);
		if (ret != 0) {
			DP_DEBUG(MULTICAST, ERR, MCAST,
				 "%s FAILED to create mcast entry\n",
				 __func__);
			goto cleanup;
		}
	} else {
	/* we already have the (*,G) simply add the interface to the
	 * RPF list.
	 */
		struct fal_attribute_t rpf_attr[2];
		struct fal_attribute_t entry_attr[1];
		fal_object_t rpf_member;
		struct fal_object_list_t *new_rpf_lst;
		uint32_t i;

		/* resize the and copy rpf list for cleanup */
		new_rpf_lst = calloc(1, sizeof(struct fal_object_list_t) +
			(((*rpf_lst)->count + 1) * sizeof(fal_object_t)));
		for (i = 0; i < (*rpf_lst)->count; i++)
			new_rpf_lst->list[i] = (*rpf_lst)->list[i];

		rpf_attr[0].id = FAL_RPF_GROUP_MEMBER_ATTR_RPF_GROUP_ID;
		rpf_attr[0].value.objid = *fal_rpf;
		rpf_attr[1].id = FAL_RPF_GROUP_MEMBER_ATTR_RPF_INTERFACE_ID;
		rpf_attr[1].value.objid = fal_l3;

		ret = fal_create_rpf_group_member(2, rpf_attr, &rpf_member);
		if (ret != 0) {
			DP_DEBUG(MULTICAST, ERR, MCAST,
				 "FAL fal_create_rpf_group_member FAILED\n");
			free(new_rpf_lst);
			goto cleanup;
		}
		new_rpf_lst->list[i] = rpf_member;
		new_rpf_lst->count = (*rpf_lst)->count + 1;
		free(*rpf_lst);
		*rpf_lst = new_rpf_lst;
		/* Apply to entry */
		entry_attr[0].id = FAL_IPMC_ENTRY_ATTR_RPF_GROUP_ID;
		entry_attr[0].value.objid = *fal_rpf;

		ret = fal_set_ip_mcast_entry_attr(*fal_obj, entry_attr);

		if (ret != 0) {
			DP_DEBUG(MULTICAST, ERR, MCAST,
				 "FAL fal_set_ip_mcast_entry_attr FAILED\n");
			goto cleanup;
		}
	}
	return ret;
 cleanup:
	fal_cleanup_ipmc_rpf_group(fal_rpf, rpf_lst);
	return ret;
}

int ip_mcast_fal_int_enable(struct vif *vifp, struct cds_lfht *viftable)
{
	struct vrf *vrf;
	struct mcast_vrf *mvrf4;
	vrfid_t vrf_id;

	if (!fal_plugins_present())
		return 0;

	if (!vifp->v_ifp || !vifp->v_ifp->fal_l3)
		return 0;

	/* get the vrf struct */
	vrf_id = vifp->v_ifp->if_vrfid;
	vrf = vrf_get_rcu(vrf_id);
	if (vrf == NULL) {
		DP_DEBUG(MULTICAST, ERR, MCAST,
			 "FAL failed to get VRF %d\n", vrf_id);
		return -EINVAL;
	}
	mvrf4 = &vrf->v_mvrf4;

	return  fal_mcast_int_enable(vrf_id, viftable,
				     &mvrf4->v_fal_obj, &mvrf4->v_fal_rpf,
				     &mvrf4->v_fal_rpf_lst,
				     vifp->v_ifp->fal_l3, AF_INET);
}


int ip6_mcast_fal_int_enable(struct mif6 *mifp, struct cds_lfht *mif6table)
{
	struct vrf *vrf;
	struct mcast6_vrf *mvrf6;
	vrfid_t vrf_id;

	if (!fal_plugins_present())
		return 0;

	if (!mifp->m6_ifp || !mifp->m6_ifp->fal_l3)
		return 0;

	/* get the vrf struct */
	vrf_id = mifp->m6_ifp->if_vrfid;
	vrf = vrf_get_rcu(vrf_id);
	if (vrf == NULL) {
		DP_DEBUG(MULTICAST, ERR, MCAST,
			 "FAL failed to get VRF %d\n", vrf_id);
		return -EINVAL;
	}
	mvrf6 = &vrf->v_mvrf6;

	return  fal_mcast_int_enable(vrf_id, mif6table,
				     &mvrf6->v_fal_obj, &mvrf6->v_fal_rpf,
				     &mvrf6->v_fal_rpf_lst,
				     mifp->m6_ifp->fal_l3, AF_INET6);
}

static int fal_mcast_int_disable(struct cds_lfht *viftable, vrfid_t vrf_id,
				 fal_object_t *fal_obj, fal_object_t *fal_rpf,
				 struct fal_object_list_t **rpf_lst)
{
	int ret;

	if ((*rpf_lst)->count == 1) {
		fal_cleanup_ipmc_rpf_group(fal_rpf, rpf_lst);

		/* all interfaces gone for this vrf. Delete the *,G */
		ret = fal_delete_ip_mcast_entry(*fal_obj);
		if (ret != 0)
			DP_DEBUG(MULTICAST, ERR, MCAST,
				 "FAL failed to delete ipmc entry %d\n", ret);
		*fal_obj = 0;

	} else {
		/*
		 * we have a deletion but there are still interfaces on the *,G
		 * create a new rpf group, link it and then delete the old one
		 */
		struct fal_attribute_t entry_attr[1];
		fal_object_t old_rpf_group;
		struct fal_object_list_t *old_rpf_lst;

		old_rpf_group = *fal_rpf;
		old_rpf_lst = *rpf_lst;
		ret = fal_create_mvrf_xg_rpf_group(viftable, vrf_id, fal_rpf,
						   rpf_lst);
		if (ret != 0)
			return ret;
		/* Apply to entry */
		entry_attr[0].id = FAL_IPMC_ENTRY_ATTR_RPF_GROUP_ID;
		entry_attr[0].value.objid = *fal_rpf;

		ret = fal_set_ip_mcast_entry_attr(*fal_obj, entry_attr);

		if (ret != 0) {
			DP_DEBUG(MULTICAST, ERR, MCAST,
				 "FAL fal_set_ip_mcast_entry_attr FAILED\n");
		}
		fal_cleanup_ipmc_rpf_group(&old_rpf_group, &old_rpf_lst);
	}
	return 0;
}

int ip_mcast_fal_int_disable(struct vif *vifp, struct cds_lfht *viftable)
{
	vrfid_t vrf_id;
	struct vrf *vrf;
	struct mcast_vrf *mvrf4;

	if (!vifp->v_ifp)
		return 0;

	/* get the vrf struct */
	vrf_id = vifp->v_ifp->if_vrfid;
	vrf = vrf_get_rcu(vrf_id);
	if (vrf == NULL) {
		DP_DEBUG(MULTICAST, ERR, MCAST,
			 "FAL failed to get VRF %d\n", vrf_id);
		return -EINVAL;
	}
	mvrf4 = &vrf->v_mvrf4;

	if (!mvrf4->v_fal_obj)
		return 0;

	return fal_mcast_int_disable(viftable, vrf_id, &mvrf4->v_fal_obj,
				     &mvrf4->v_fal_rpf, &mvrf4->v_fal_rpf_lst);
}

int ip6_mcast_fal_int_disable(struct mif6 *mifp, struct cds_lfht *mif6table)
{
	vrfid_t vrf_id;
	struct vrf *vrf;
	struct mcast6_vrf *mvrf6;

	if (!mifp->m6_ifp)
		return 0;

	/* get the vrf struct */
	vrf_id = mifp->m6_ifp->if_vrfid;
	vrf = vrf_get_rcu(vrf_id);
	if (vrf == NULL) {
		DP_DEBUG(MULTICAST, ERR, MCAST,
			 "FAL failed to get VRF %d\n", vrf_id);
		return -EINVAL;
	}
	mvrf6 = &vrf->v_mvrf6;

	if (!mvrf6->v_fal_obj)
		return 0;

	return fal_mcast_int_disable(mif6table, vrf_id, &mvrf6->v_fal_obj,
				     &mvrf6->v_fal_rpf, &mvrf6->v_fal_rpf_lst);
}
