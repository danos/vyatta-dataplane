/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <rte_mbuf.h>
#include <vyatta_swport.h>
#include <linux/if_ether.h>
#include <fal_plugin.h>
#include "fal_plugin_sw_port.h"
#include "fal_plugin_framer.h"

#define DSA_GET_TAG_TYPE(_x) \
	((((_x)->tag[0]) & 0xc0) >> 6)

#define DSA_GET_DEVICE(_x) \
	((_x)->tag[0] & 0x1f)

#define DSA_SET_DEVICE(_x, _y)			\
	((_x)->tag[0] |= ((_y) &  0x1f))

#define DSA_GET_PORT(_x)  \
	(((_x)->tag[1] >> 3) & 0x1f)

#define DSA_SET_PORT(_x, _y)			\
	(((_x)->tag[1]) |=  ((_y) & 0x1f) << 3)

#define DSA_GET_IS_TAGGED(_x) \
	(((_x)->tag[0] >> 5) & 0x1)

#define DSA_SET_IS_TAGGED(_x)			\
	(((_x)->tag[0]) |=  0x20)

#define DSA_CLEAR_IS_TAGGED(_x)			\
	(((_x)->tag[0]) &=  ~0x20)

#define DSA_GET_CFI(_x)	 \
	((_x)->tag[1] & 0x1)

#define DSA_SET_CFI(_x)	 \
	((_x)->tag[1] |= 0x1)

static inline struct rte_ether_hdr *ethhdr(struct rte_mbuf *m)
{
	return rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
}

int plugin_framer_rcv(struct rte_mbuf *mbuf, uint16_t *dpdk_port,
		      union fal_pkt_feature_info *feat_info)
{
	struct rte_ether_hdr *eh = ethhdr(mbuf);
	struct  edsa_hdr *edsa = (struct edsa_hdr *)&eh->ether_type;
	uint8_t hw_device, hw_port;
	int rc;

	if ((DSA_GET_TAG_TYPE(edsa) != DSA_TAG_TYPE_TO_CPU) &&
	    DSA_GET_TAG_TYPE(edsa) != DSA_TAG_TYPE_FORWARD)
		return false;

	hw_device = DSA_GET_DEVICE(edsa);
	hw_port = DSA_GET_PORT(edsa);

	if (DSA_GET_IS_TAGGED(edsa)) {
		uint8_t new_hdr[DSA_TAG_LEN];

		memset(new_hdr, htons(ETH_P_8021Q), 2);

		/* copy PRI and VID fields */
		new_hdr[2] = edsa->tag[2];
		new_hdr[3] = edsa->tag[3];

		if (DSA_GET_CFI(edsa))
			new_hdr[2] |= 0x10;
		else
			new_hdr[2] &= ~0x10;

		memcpy(edsa, new_hdr, DSA_TAG_LEN);
	}

	memmove((uint8_t *)eh + EDSA_HLEN, (uint8_t *)eh, ETH_ALEN  + ETH_ALEN);

	rte_pktmbuf_adj(mbuf, EDSA_HLEN);
	/* No need to adjust the l2 len, as it is still the same */
	rc = sw_port_from_hw_port(hw_device, hw_port, dpdk_port);

	if (!rc)
		return FAL_RET_ETHER_INPUT;
	return -1;
}

int32_t plugin_framer_tx(void *sw_port, void *fal_info, struct rte_mbuf **mbuf)
{
	struct rte_ether_hdr *eh = ethhdr(*mbuf);

	uint16_t proto;
	uint8_t dev, port;

	if (fal_plugin_get_sw_port_info(fal_info, &proto, &dev, &port) != 0)
		return -1;

	if (eh->ether_type == htons(ETH_P_8021Q)) {
		char *new_eh;
		struct edsa_hdr *edsa_hdr;

		new_eh = rte_pktmbuf_prepend(*mbuf, DSA_TAG_LEN);
		if (!new_eh)
			return -1;

		memmove(new_eh, new_eh + DSA_TAG_LEN, 2 * ETH_ALEN);

		edsa_hdr = (struct edsa_hdr *)(new_eh + (2 * ETH_ALEN));
		edsa_hdr->ether_type = htons(proto);
		edsa_hdr->reserved = 0;
		/* Clean any old data */
		memset(edsa_hdr->tag, 0, 2);
		DSA_SET_IS_TAGGED(edsa_hdr);
		DSA_SET_TAG_TYPE(edsa_hdr, DSA_TAG_TYPE_FROM_CPU);
		DSA_SET_DEVICE(edsa_hdr, dev);
		DSA_SET_PORT(edsa_hdr, port);

		/*
		 * Copy CFI field from overlayed vlan tag.
		 */
		if (edsa_hdr->tag[2] & 0x10) {
			DSA_SET_CFI(edsa_hdr);
			/* Do we need to really clear it ? */
			edsa_hdr->tag[2] &= ~0x10;
		}
	} else {
		char *new_eh;
		struct edsa_hdr *edsa_hdr;

		new_eh = rte_pktmbuf_prepend(*mbuf, EDSA_HLEN);
		memmove(new_eh, new_eh + EDSA_HLEN, 2 * ETH_ALEN);
		/*
		 * Construct untagged FROM_CPU DSA tag.
		 */
		edsa_hdr = (struct edsa_hdr *)(new_eh + (2 * ETH_ALEN));
		edsa_hdr->ether_type = htons(proto);
		edsa_hdr->reserved = 0;
		/* Clean any old data */
		memset(edsa_hdr->tag, 0, 4);
		DSA_CLEAR_IS_TAGGED(edsa_hdr);
		DSA_SET_TAG_TYPE(edsa_hdr, DSA_TAG_TYPE_FROM_CPU);
		DSA_SET_DEVICE(edsa_hdr, dev);
		DSA_SET_PORT(edsa_hdr, port);
	}

	return 0;
}


