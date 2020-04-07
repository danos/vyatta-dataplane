/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * IPIP tunnel interface implementation
 */

#include <stdint.h>
#include <rte_debug.h>

#include "dp_event.h"
#include "if_var.h"
#include "ip_ttl.h"
#include "netinet6/ip6_funcs.h"

void unsup_tunnel_output(struct ifnet *ifp, struct rte_mbuf *m,
			 struct ifnet *input_ifp, uint16_t proto)
{
	if (!input_ifp) {
		rte_pktmbuf_free(m);
		if_incr_dropped(ifp);
		return;
	}

	switch (proto) {
	case ETH_P_IP:
		/*
		 * Assume the packet has been forwarded and thus its
		 * ttl has been decremented.
		 */
		increment_ttl(iphdr(m));
		ip_local_deliver(ifp, m);
		break;
	case ETH_P_IPV6:
		ip6hdr(m)->ip6_hlim += IPV6_HLIMDEC;
		ip6_local_deliver(ifp, m);
		break;
	default:
		local_packet(ifp, m);
		break;
	}
}

static enum dp_ifnet_iana_type
ipip_iana_type(struct ifnet *ifp __unused)
{
	return DP_IFTYPE_IANA_TUNNEL;
}

static const struct ift_ops ipip_tun_if_ops = {
	.ifop_iana_type = ipip_iana_type,
};

static void ipip_tun_init(void)
{
	int ret = if_register_type(IFT_TUNNEL_OTHER, &ipip_tun_if_ops);
	if (ret < 0)
		rte_panic("Failed to register IPIP tunnel type: %s",
			  strerror(-ret));
}

static const struct dp_event_ops ipip_tun_events = {
	.init = ipip_tun_init,
};

DP_STARTUP_EVENT_REGISTER(ipip_tun_events);
