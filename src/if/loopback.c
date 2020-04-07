/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Loopback interface implementation
 */

#include <stdint.h>
#include <rte_debug.h>

#include "crypto/crypto_forward.h"
#include "dp_event.h"
#include "if_var.h"

/* Packet on virtual feature point */
void vfp_output(struct ifnet *ifp, struct rte_mbuf *m,
		struct ifnet *input_ifp, uint16_t proto)
{
	struct vfp_softc *vsc = ifp->if_softc;

	switch (vsc->vfp_type) {
	case VFP_S2S_CRYPTO:
		crypto_policy_post_features_outbound(ifp, input_ifp, m, proto);
		break;
	case VFP_NONE:
		/* Packet on loopback shouldn't reach here */
		assert(0);
		rte_pktmbuf_free(m);
		if_incr_dropped(ifp);
		break;
	}
}

static enum dp_ifnet_iana_type
lo_iana_type(struct ifnet *ifp __unused)
{
	return DP_IFTYPE_IANA_SOFTWARELOOPBACK;
}

static const struct ift_ops lo_if_ops = {
	.ifop_iana_type = lo_iana_type,
};

static void lo_type_init(void)
{
	int ret = if_register_type(IFT_LOOP, &lo_if_ops);
	if (ret < 0)
		rte_panic("Failed to register loopback type: %s",
			  strerror(-ret));
}

static const struct dp_event_ops loopback_events = {
	.init = lo_type_init,
};

DP_STARTUP_EVENT_REGISTER(loopback_events);
