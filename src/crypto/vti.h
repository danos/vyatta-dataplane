/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef VTI_H
#define VTI_H

#include "netlink.h"

struct rte_ether_addr;
struct ifnet;
struct nlattr;
struct rte_mbuf;
#include <linux/xfrm.h>
#include <stdint.h>

struct vrf;
struct vti_ctxt_table;

struct ifnet *
vti_tunnel_create(int ifindex, const char *ifname,
		   const struct rte_ether_addr *addr, const unsigned int mtu,
		   struct nlattr *data);
void vti_tunnel_modify(struct ifnet *ifp, struct nlattr *data);
void vti_tunnel_out(struct ifnet *input_ifp, struct ifnet *nxt_ifp,
		    struct rte_mbuf *m, uint16_t proto);
int vti_handle_inbound(const xfrm_address_t *dst, const uint8_t family,
		       const uint32_t mark, struct rte_mbuf *m,
		       struct ifnet **vti_ifp);
int vti_table_init(struct vrf *vrf);
void vti_table_uninit(struct vrf *vrf);
int vti_set_output_vrf(const struct ifnet *ifp, struct rte_mbuf *m);
int vti_get_peer_addr(const struct ifnet *ifp, uint32_t *af, void **addr);

#endif /* VTI_H */
