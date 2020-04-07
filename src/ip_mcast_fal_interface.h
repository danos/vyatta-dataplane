/*
 * Copyright (c) 2019, AT&T Intellectual Property.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef __IP_MCAST_FAL_INTERFACE_H__
#define __IP_MCAST_FAL_INTERFACE_H__

int ip_mcast_fal_int_enable(struct vif *vifp, struct cds_lfht *viftable);
int ip_mcast_fal_int_disable(struct vif *vifp, struct cds_lfht *viftable);
int ip6_mcast_fal_int_enable(struct mif6 *mifp, struct cds_lfht *mif6table);
int ip6_mcast_fal_int_disable(struct mif6 *mifp, struct cds_lfht *mif6table);

#endif
