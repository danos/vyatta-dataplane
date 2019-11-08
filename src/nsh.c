/*-
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 * Copyright (c) 2017, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <errno.h>
#include <netinet/in.h>
#include <rte_branch_prediction.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <stddef.h>

#include "compat.h"
#include "nsh.h"
#include "vplane_debug.h"
#include "vplane_log.h"

static void nsh_write_base_hdr(void *nsh_start, enum nsh_np nxtproto,
			       int md_type, unsigned int mdata_size)
{
	struct nsh *nsh_base = nsh_start;

	nsh_base->bh_u.bh = nsh_base->sph_u.sph = 0;
	nsh_base->nsh_ver = NSH_V0;
	nsh_base->nsh_oam = 0;
	nsh_base->nsh_crit = 1;
	nsh_base->nsh_mdtype = md_type;
	nsh_base->nsh_len = mdata_size/NSH_LEN_UNIT;
	nsh_base->nsh_nxtproto = nxtproto;
	nsh_base->nsh_spi = 0;
	nsh_base->nsh_si = 1;
	nsh_base->bh_u.bh = htonl(nsh_base->bh_u.bh);
	nsh_base->sph_u.sph = htonl(nsh_base->sph_u.sph);
}

/* add hdr with Type 1 metadata */
int nsh_add_t1_hdr(struct rte_mbuf *pak, enum nsh_np nxtproto,
		   struct nsh_md_t1 *t1_hdr)
{
	unsigned int nsh_size = sizeof(struct nsh) + sizeof(struct nsh_md_t1);
	char *nsh_start;
	struct nsh_md_t1 *nsh_md;

	nsh_start = rte_pktmbuf_prepend(pak, nsh_size);
	if (nsh_start == NULL) {
		DP_DEBUG(NSH, ERR, NSH,
			 "Insufficient space for NSH Type 1\n");
		return -ENOMEM;
	}

	nsh_write_base_hdr(nsh_start, nxtproto, NSH_MD_T1, nsh_size);
	nsh_md = (struct nsh_md_t1 *)(nsh_start + sizeof(struct nsh));
	nsh_md->u1.md1_npc = htonl(t1_hdr->u1.md1_npc);
	nsh_md->u2.md1_nsc = htonl(t1_hdr->u2.md1_nsc);
	nsh_md->u3.md1_spc = htonl(t1_hdr->u3.md1_spc);
	nsh_md->u4.md1_ssc = htonl(t1_hdr->u4.md1_ssc);

	return 0;
}

/* get expected metadata size */
int nsh_get_metadata_size(struct nsh_tlv *tlv_arr, unsigned int num_tlvs,
			  unsigned int *nsh_size)
{
	unsigned int i;
	unsigned int attr_size = 0;

	for (i = 0; i < num_tlvs; i++) {
		if (tlv_arr[i].ntlv_len % NSH_LEN_UNIT) {
			DP_DEBUG(NSH, ERR, NSH,
				 "Invalid length %d specified for attribute %d\n",
				 tlv_arr[i].ntlv_len, i);
			return -EINVAL;
		}
		attr_size += sizeof(struct nsh_md_t2) + tlv_arr[i].ntlv_len;
	}
	*nsh_size = sizeof(struct nsh) + attr_size;

	return 0;
}

/* add hdr with Type 2 metadata */
int nsh_add_t2_hdr(char *buf, unsigned int len, enum nsh_np nxtproto,
		   struct nsh_tlv *tlv_arr, unsigned int num_tlvs)
{
	struct nsh *nsh_start = (struct nsh *)buf;
	unsigned int i;
	struct nsh_md_t2 *md2h;
	char *cursor;
	uint32_t *attr_ptr;

	nsh_write_base_hdr(nsh_start, nxtproto, NSH_MD_T2, len);
	cursor = (char *)((uintptr_t)nsh_start + sizeof(struct nsh));
	md2h = (struct nsh_md_t2 *)cursor;
	attr_ptr = (uint32_t *)(cursor + sizeof(*md2h));
	for (i = 0; i < num_tlvs; i++) {

		if ((uintptr_t)md2h >= ((uintptr_t)nsh_start + len)) {
			DP_DEBUG(NSH, ERR, NSH,
				 "Insufficient space to add TLV %d\n", i);
			return -ENOMEM;
		}

		md2h->md2_tlvc = tlv_arr[i].ntlv_class;
		md2h->md2_crit = 1;
		md2h->md2_rsvd = 0;
		md2h->md2_type = tlv_arr[i].ntlv_type;

		if (md2h->md2_tlvc !=  NSH_MD_CLASS_BROCADE_VROUTER)
			return -EINVAL;

		switch (md2h->md2_type) {
		case NSH_MD_TYPE_IFINDEX_IN:
		case NSH_MD_TYPE_IFINDEX_OUT:
		case NSH_MD_TYPE_MWID:
		case NSH_MD_TYPE_VRF_ID:
			md2h->md2_len = sizeof(uint32_t)/NSH_LEN_UNIT;
			*attr_ptr = htonl(*(uint32_t *)(tlv_arr[i].ntlv_val));
			break;

		case NSH_MD_TYPE_ADDR_IPv4_NH:
			md2h->md2_len =
				sizeof(struct in_addr)/NSH_LEN_UNIT;
			*attr_ptr = htonl(*((uint32_t *)tlv_arr[i].ntlv_val));
			break;
		case NSH_MD_TYPE_ADDR_IPv6_NH:
			{
				uint32_t *addr =
					(uint32_t *)tlv_arr[i].ntlv_val;
				int j;

				md2h->md2_len =
					sizeof(struct in6_addr)/NSH_LEN_UNIT;

				for (j = 0; j < NSH_MD_LEN_ADDR_IPv6; j++)
					attr_ptr[j] = htonl(addr[j]);
			}
			break;
		default:
			return -EINVAL;
		}
		cursor += sizeof(*md2h) + (md2h->md2_len * NSH_LEN_UNIT);
		md2h->md2_hdr = htonl(md2h->md2_hdr);
		md2h = (struct nsh_md_t2 *)cursor;
		attr_ptr = (uint32_t *)(cursor + sizeof(*md2h));
	}
	return 0;
}


static int nsh_extract_t1_md(struct nsh *nsh_base, struct nsh_tlv *tlv_arr,
			     unsigned int max_tlvs, unsigned int *num_tlvs)
{
	int i;
	uint32_t *attr_ptr;

	if (nsh_base->nsh_len != NSH_T1_LEN)
		return -EINVAL;

	if (max_tlvs < NSH_MD1_NUM_ATTRS)
		return -ENOMEM;

	attr_ptr = (uint32_t *)((uintptr_t)nsh_base +
				sizeof(*nsh_base));
	for (i = 0; i < NSH_MD1_NUM_ATTRS; i++) {
		*attr_ptr = ntohl(*attr_ptr);
		tlv_arr[i].ntlv_type = NSH_TLVC_UINT32;
		tlv_arr[i].ntlv_len = sizeof(uint32_t);
		tlv_arr[i].ntlv_val = attr_ptr;
		attr_ptr++;
	}
	*num_tlvs = NSH_MD1_NUM_ATTRS;

	return 0;
}

static int nsh_extract_t2_md(struct nsh *nsh_base, struct nsh_tlv *tlv_arr,
			     unsigned int max_tlvs, unsigned int *num_tlvs)
{
	unsigned int i;
	uint32_t *attr_ptr;
	char *cursor, *attr_end;
	struct nsh_md_t2 *md2h;
	uint16_t attr_size;

	if (nsh_base->nsh_len < NSH_T2_MIN_LEN)
		return -EINVAL;

	cursor = (char *)((uintptr_t)nsh_base + sizeof(*nsh_base));
	attr_end = (char *)((uintptr_t)nsh_base + (nsh_base->nsh_len *
						   NSH_LEN_UNIT));
	i = 0;
	while (cursor < attr_end) {
		if (i >= max_tlvs)
			return -ENOMEM;

		md2h = (struct nsh_md_t2 *)cursor;
		attr_ptr = (uint32_t *)(cursor + sizeof(*md2h));
		md2h->md2_hdr = ntohl(md2h->md2_hdr);
		attr_size = md2h->md2_len * NSH_LEN_UNIT;
		if (md2h->md2_tlvc !=  NSH_MD_CLASS_BROCADE_VROUTER)
			return -EINVAL;

		switch (md2h->md2_type) {
		case NSH_MD_TYPE_IFINDEX_IN:
		case NSH_MD_TYPE_IFINDEX_OUT:
		case NSH_MD_TYPE_MWID:
		case NSH_MD_TYPE_VRF_ID:
			if (unlikely(attr_size != sizeof(uint32_t)))
				return -EINVAL;

			*attr_ptr = ntohl(*attr_ptr);
			break;

		case NSH_MD_TYPE_ADDR_IPv4_NH:
			if (attr_size != sizeof(struct in_addr))
				return -EINVAL;
			*attr_ptr = ntohl(*attr_ptr);
			break;
		case NSH_MD_TYPE_ADDR_IPv6_NH:
			{
				uint32_t *addr = (uint32_t *) attr_ptr;
				int j;

				if (attr_size != sizeof(struct in6_addr))
					return -EINVAL;

				for (j = 0; j < NSH_MD_LEN_ADDR_IPv6; j++)
					addr[j] = htonl(addr[j]);
			}
			break;
		default:
			return -EINVAL;
		}
		tlv_arr[i].ntlv_class = md2h->md2_tlvc;
		tlv_arr[i].ntlv_type = md2h->md2_type;
		tlv_arr[i].ntlv_len =
			(md2h->md2_len * NSH_LEN_UNIT);
		tlv_arr[i].ntlv_val = attr_ptr;
		cursor += (sizeof(*md2h) + tlv_arr[i].ntlv_len);
		i++;
	}
	*num_tlvs = i;
	return 0;
}


/* parse hdr and extract fields into tlv array.
 * No additional memory is allocated. TLV value pointers point
 * into payload of buffer
 */
int nsh_extract(struct rte_mbuf *pak, struct nsh **nsh, struct nsh_tlv *tlv_arr,
		unsigned int max_tlvs, unsigned int *num_tlvs)
{
	int err;
	struct nsh *nsh_start;

	nsh_start = rte_pktmbuf_mtod(pak, struct nsh *);

	nsh_start->bh_u.bh = ntohl(nsh_start->bh_u.bh);
	nsh_start->sph_u.sph = ntohl(nsh_start->sph_u.sph);

	if (nsh_start->nsh_mdtype == NSH_MD_T1)
		err = nsh_extract_t1_md(nsh_start, tlv_arr, max_tlvs, num_tlvs);
	else if (nsh_start->nsh_mdtype == NSH_MD_T2)
		err = nsh_extract_t2_md(nsh_start, tlv_arr, max_tlvs, num_tlvs);
	else
		err = -EINVAL;

	if (err != 0)
		return err;

	DP_DEBUG(NSH, INFO, NSH,
		 "Rcvd NSH (%d TLVs, Size %ld): BH = 0x%x, SPH = 0x%x\n",
		 *num_tlvs, (nsh_start->nsh_len * NSH_LEN_UNIT),
		 nsh_start->bh_u.bh, nsh_start->sph_u.sph);

	*nsh = nsh_start;
	if (nsh_start->nsh_nxtproto == NSH_NP_IPv4 ||
	    nsh_start->nsh_nxtproto == NSH_NP_IPv6)
		pak->l2_len = 0;
	rte_pktmbuf_adj(pak, (nsh_start->nsh_len * NSH_LEN_UNIT));
	return 0;
}

int nsh_get_payload(struct nsh *nsh_start, enum nsh_np *nxtproto,
		    void **nsh_payload)
{
	struct nsh nsh_local;

	nsh_local.bh_u.bh = ntohl(nsh_start->bh_u.bh);
	if (nsh_local.nsh_nxtproto == NSH_NP_NONE ||
	    nsh_local.nsh_nxtproto >= NSH_NP_MAX) {
		DP_DEBUG(NSH, ERR, NSH,
			 "Invalid next protocol %d\n", nsh_local.nsh_nxtproto);
			return -EINVAL;
	}
	*nsh_payload = (uint8_t *)nsh_start +
		(nsh_local.nsh_len * NSH_LEN_UNIT);
	*nxtproto = nsh_local.nsh_nxtproto;
	return 0;
}
