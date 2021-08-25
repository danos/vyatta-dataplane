/*
 * Copyright (c) 2018-2019,2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef _FAL_PLUGIN_FAL_FRAME_H_
#define _FAL_PLUGIN_FAL_FRAME_H_

#define DSA_TAG_TYPE_TO_CPU 0
#define DSA_TAG_TYPE_FROM_CPU 1
#define DSA_TAG_TYPE_SNIFFER 2
#define DSA_TAG_TYPE_FORWARD 3
#define DSA_TAG_LEN 4
#define EDSA_HLEN 8

struct edsa_hdr {
	uint16_t ether_type;
	uint16_t reserved; /* Must be written 0*/
	uint8_t tag[DSA_TAG_LEN];
};

#define DSA_SET_TAG_TYPE(_x, _y) \
	do {					\
		(_x)->tag[0] &= ~0x3f;		\
		(_x)->tag[0] |= (_y & 0x3) << 6;\
	} while (0)

int plugin_framer_rcv(struct rte_mbuf *mbuf, uint16_t *dpdk_port,
		      union fal_pkt_feature_info *feat_info);
int32_t plugin_framer_tx(void *sw_port, void *fal_info, struct rte_mbuf **mbuf);

#endif /* FAL_PLUGIN_FRAMER_H */
