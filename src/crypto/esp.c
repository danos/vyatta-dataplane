/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <assert.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet6/ip6_funcs.h>
#include <openssl/evp.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_memcpy.h>
#include <rte_mbuf.h>

#include "compiler.h"
#include "crypto/crypto_sadb.h"
#include "in6.h"
#include "ip_funcs.h"
#include "util.h"
#include "vplane_log.h"
#include "vrf_internal.h"

#include <linux/xfrm.h>
#include <string.h>

#include "../in_cksum.h"
#include "../iptun_common.h"
#include "../pktmbuf_internal.h"
#include "crypto.h"
#include "crypto_internal.h"
#include "esp.h"

struct ifnet;

#ifdef CRYPTO_LOG_NOTICE_FOR_DEBUG
#define ESP_DEBUG(args...)				\
	RTE_LOG(NOTICE, DATAPLANE, "ESP: " args)
#else
#define ESP_DEBUG(args...)			\
	RTE_LOG(DEBUG, DATAPLANE, "ESP: " args)
#endif

#define ESP_ERR(args...)			\
	RTE_LOG(ERR, DATAPLANE, "ESP: " args)

#define ESP_PKT_ERR(args...)			\
	RTE_LOG(ERR, DATAPLANE, "ESP: " args)

#define ESP_INFO(args...)				\
	RTE_LOG(NOTICE, DATAPLANE, "ESP: " args)

/*
 * AF-independent L3 header context used when encrypting.
 */
struct esp_hdr_ctx {
	unsigned int (*out_new_hdr)(bool transport, uint8_t orig_family,
				    void *l3hdr, void *new_l3hdr,
				    unsigned int pre_len, unsigned int udp_size,
				    struct sadb_sa *sa);
	unsigned int out_hdr_len;
	unsigned int pre_len;
	unsigned int tot_len;
	unsigned int out_align_val;
	uint16_t out_ethertype;
	uint8_t proto_ip;
	uint8_t out_proto_nxt;
};

/*
 * from RFC 4303. "If anti-replay is enabled (the default), the sender
 * checks to ensure that the counter has not cycled before inserting
 * the new value in the Sequence Number field.  In other words, the
 * sender MUST NOT send a packet on an SA if doing so would cause the
 * sequence number to cycle."
 *
 * How close to rollover should we allow an SA's sequence number to
 * get? Pick an arbitrary trigger point that's about 95% of the way to
 * rollover.
 */
#define ESP_SEQ_SA_REKEY_THRESHOLD 0xF3333300u
#define ESP_SEQ_SA_BLOCK_LIMIT       0xFFFFFFFFu

static struct rte_mbuf *buf_tail_free(struct rte_mbuf *m)
{
	struct rte_mbuf *p = NULL, *m2 = m;

	__rte_mbuf_sanity_check(m, 1);
	while (m2->next != NULL) {
		p = m2;
		m2 = m2->next;
	}

	if (m2->data_len != 0) {
		ESP_ERR("Free on non empty seg\n");
		return NULL;
	}

	if ((p == NULL) || (m2 == m)) {
		ESP_ERR("Can not free only segment\n");
		return NULL;
	}
	p->next = NULL;
	m->nb_segs -= 1;
	rte_pktmbuf_free_seg(m2);

	return p;
}

/*
 * Read the last char from the buffer then reduce the length by 1 and
 * free the last segment if it has become empty.
 */
static int buf_tail_read_char(struct rte_mbuf *m, char *ptr, int err)
{
	struct rte_mbuf *m_last;

	if (err)
		return err;

	__rte_mbuf_sanity_check(m, 1);

	m_last = rte_pktmbuf_lastseg(m);
	*ptr = *((char *)m_last->buf_addr + m_last->data_off +
		 m_last->data_len - 1);
	m_last->data_len = (uint16_t)(m_last->data_len - 1);
	m->pkt_len  -= 1;

	if (m_last->data_len == 0)
		if (!buf_tail_free(m))
			return -1;
	return 0;
}

static int buf_tail_trim(struct rte_mbuf *m, uint16_t len, int err)
{
	struct rte_mbuf *m_last;

	if (err)
		return err;

	m_last = rte_pktmbuf_lastseg(m);
	m->pkt_len  -= len;
	while (len != 0) {
		if (m_last->data_len <= len) {
			len -= m_last->data_len;
		} else {
			m_last->data_len -= len;
			return 0;
		}
		m_last->data_len = 0;
		m_last = buf_tail_free(m);
		if (!m_last) {
			ESP_ERR("Buffer tail trim failed\n");
			return -1;
		}
	}
	return 0;
}

static uint32_t esp_icv_len(struct sadb_sa *sa)
{
	return crypto_session_digest_len(sa->session);
}

static uint32_t esp_hdr_len(struct sadb_sa *sa)
{
	/* Esp contains SPI (4), Seq (4), IV (IV_len) */
	return crypto_session_iv_len(sa->session) + 4 + 4;
}

uint16_t esp_payload_padded_len(const struct crypto_overhead *overhead,
				uint16_t tot_len)
{
	const uint16_t esp_trailer_len = 2;

	return RTE_ALIGN(tot_len + esp_trailer_len, overhead->block_size)
		- esp_trailer_len;
}

/*
 * Replay detection is implemented using a sliding window. We remember
 * the highest sequence number so far received. To pass the check, a
 * new packet must either
 *
 *   have a higher sequence number than the stored number
 *
 *   OR
 *
 *   be within replay_window_size of the stored sequence number
 *
 *   AND
 *
 *   not have been previously checked and accepted [by
 *   esp_replay_advance]
 *
 * we detect previously received sequence numbers using a bitmask. The
 * MSB of the bitmask corresponds to the stored highest sequence
 * number so far received. Less significant bits correspond to
 * sequence numbers S in the range:
 *
 * highest_received >= S > (highest_received - replay_window_size)
 *
 */
int esp_replay_check(const uint8_t *esp,
		     const struct sadb_sa *sa)
{
	const uint32_t replay_window = sa->replay_window;
	const uint32_t pkt_seq = ntohl(*(const uint32_t *)(esp+4));
	uint32_t delta;
	int ret = 0;

	if (unlikely(!pkt_seq)) {
		ret = -1; /* Invalid seq in packet. Auditable event? */
		goto err;
	}

	if (likely(pkt_seq > sa->seq))
		return 0;

	delta = sa->seq - pkt_seq;

	if (delta >= replay_window) {
		ret = -2; /* Wrap or replay. Auditable event? */
		goto err;
	}

	if (sa->replay_bitmap & (1U << delta)) {
		ret = -3; /* Replay. Auditable event? */
		goto err;
	}

	return 0;

err:
	if (net_ratelimit())
		ESP_INFO("Replay check failed for SPI %#x."
			" (Packet seq: %#x / SA seq: %#x / Replay Bitmap: %#lx)\n",
			sa->spi, pkt_seq, sa->seq, sa->replay_bitmap);
	return ret;
}

/*
 * The most significant bit in the mask represents the right hand edge
 * of the sliding window. As the window moves, the bitmask is shifted
 * left. If a packet is received with a sequence number more than
 * replay_window ahead of the current right hand edge, then the
 * bitmask is cleared, and a single bit set to indicate that we've
 * started afresh.
 */
void esp_replay_advance(const uint8_t *esp,
			struct sadb_sa *sa)
{
	const uint32_t replay_window = sa->replay_window;
	uint32_t delta;

	if (unlikely(!replay_window))
		return;

	const uint32_t pkt_seq = ntohl(*(const uint32_t *)(esp+4));

	if (pkt_seq > sa->seq) {
		delta = pkt_seq - sa->seq;
		if (delta < replay_window)
			sa->replay_bitmap =
				((sa->replay_bitmap) << delta) | 1;
		else
			sa->replay_bitmap = 1;
		sa->seq = pkt_seq;
	} else {
		delta = sa->seq - pkt_seq;
		sa->replay_bitmap |= (1U << delta);
	}
}

static struct rte_mbuf *esp_get_next_seg(struct rte_mbuf *current,
					 unsigned int *seg_data_len,
					 unsigned char **data_start,
					 unsigned int min_data)
{
	struct rte_mbuf *next;

	next = current->next;
	if (!next) {
		ESP_ERR("No next seg");
		return NULL;
	}

	*seg_data_len = rte_pktmbuf_data_len(next);
	if (*seg_data_len < min_data) {
		ESP_ERR("Data underrun in next seg, need %d\n", min_data);
		return NULL;
	}

	*data_start = rte_pktmbuf_mtod(next, unsigned char *);

	return next;
}

static int esp_process_authdata(struct crypto_chain *chain,
				unsigned char *esp)
{
	unsigned int esp_len = 8;

	/* FIXME: the length of the authdata depends on ESN */
	crypto_chain_add_element(chain, esp, NULL, esp_len, ENG_DIGEST_BLOCK);

	return crypto_chain_walk(chain);
}

/*
 * Process the cipher payload
 *
 * sa_ctx - sa_ctx
 * mbuf   - ptr to segment containing text to be processed,
 *          Returns the segment containing the next byte of data following
 *          processing of cipher_data_len bytes.
 * cipher_data_len - Amount of text to run cipher on.
 * encrpy - Encrypt or Decrypt.
 * cipher_data -  prt to first byte of text to process.
 *          Returns ptr to next byte of data following processing of
 *          cipher_data_len bytes.
 * seg_data_remaining - Amount of data left in segment, based from
 *                      cipher_data_ptr.
 *                      Returns data left based upon values returned
 *                      in head_p and cipher_data_ptr
 */
static int esp_process_text(struct crypto_chain *chain,
			    struct rte_mbuf *mbuf,
			    uint32_t cipher_data_len,
			    unsigned char *cipher_data)
{
	unsigned int cipher_blocks, seg_cipher_blocks, seg_cipher_len;
	unsigned int block_size = crypto_session_block_size(chain->ctx);
	unsigned int head_frag_size = 0, tail_frag_size = 0;
	unsigned char *head_cipher_data;
	unsigned int seg_data_len;
	unsigned int md_mask = crypto_session_digest_len(chain->ctx) ?
		ENG_DIGEST_BLOCK : 0;

	seg_data_len = rte_pktmbuf_data_len(mbuf) -
		(cipher_data - rte_pktmbuf_mtod(mbuf, unsigned char *));

	/* How many blocks of cipher text are there to be processed */
	cipher_blocks = cipher_data_len / block_size;

	/*
	 * Loop over blocks of cipher text generating engine commands
	 * for each large block of cipher text. For each segment setup
	 * an entry as large as possible. If a block of cipher text
	 * spans two segments, copy it out into a buffer for
	 * processing and then copy it back.
	 */
	while (cipher_blocks) {
		/* A quick sanity check */
		if (cipher_data_len == 0) {
			ESP_PKT_ERR("text underrun");
			return -1;
		}
		if (seg_data_len == 0) {
			mbuf = esp_get_next_seg(mbuf, &seg_data_len,
						&cipher_data,
						block_size);
			if (!mbuf)
				return -1;
		}

		/*
		 * Calculate how many blocks of cipher text are there
		 * in this segment (seg_cipher_blocks) and create a chain
		 * elememt for them
		 */
		seg_cipher_blocks = seg_data_len / block_size;

		/* Check if thesSegment contains all of remaining data */
		if (cipher_blocks <= seg_cipher_blocks) {
			seg_cipher_len = cipher_blocks * block_size;
			if (seg_data_len < seg_cipher_len) {
				ESP_PKT_ERR("Segment data underrun %d",
					    seg_data_len);
			return -1;
			}
			seg_data_len -= seg_cipher_len;
			head_frag_size = 0;
			cipher_blocks = 0;
		} else {
			/*
			 * Not all text to process is in this segment,
			 * so work out how many bytes there are in
			 * this segment*/
			seg_cipher_len = seg_cipher_blocks * block_size;
			if (seg_data_len < seg_cipher_len) {
				ESP_PKT_ERR("Segment data underrun %d",
					    seg_data_len);
				return -1;
			}
			seg_data_len -= seg_cipher_len;
			/*
			 * If there is any data left in the segment,
			 * i.e seg_data_len none zero then a cipher
			 * block is spanning two segments.
			 */
			head_frag_size = seg_data_len;
			cipher_blocks -= seg_cipher_blocks;
		}

		/* Queue up a large a block of cipher text as possible */
		if (seg_cipher_blocks) {
			cipher_data_len -= seg_cipher_len;
			crypto_chain_add_element(chain,
						 cipher_data, cipher_data,
						 seg_cipher_len,
						 ENG_CIPHER_BLOCK | md_mask);
			cipher_data += seg_cipher_len;
		}

		/*
		 * Do we have a fragment of cipher text left in this
		 * segment if so we need to coalesce it with text
		 * from the next segment into a temporary buffer for
		 * processing.
		 */
		if (head_frag_size != 0) {
			tail_frag_size = block_size - head_frag_size;
			head_cipher_data = cipher_data;

			mbuf = esp_get_next_seg(mbuf, &seg_data_len,
						&cipher_data,
						tail_frag_size);
			if (!mbuf)
				return -1;

			memcpy(chain->slop_buffer, head_cipher_data,
			       head_frag_size);
			memcpy(chain->slop_buffer + head_frag_size,
			       cipher_data, tail_frag_size);

			crypto_chain_add_element(chain, chain->slop_buffer,
						 chain->slop_buffer,
						 block_size,
						 ENG_CIPHER_BLOCK | md_mask);
			cipher_blocks--;

			/*
			 * Since we have copied the data into a
			 * temporary buffer, it is best to process it
			 * now, so we don't have to remember all the
			 * copy back details.
			 */
			if (crypto_chain_walk(chain) < 0)
				return -1;

			memcpy(head_cipher_data, chain->slop_buffer,
			       head_frag_size);
			memcpy(cipher_data,
			       chain->slop_buffer + head_frag_size,
			       tail_frag_size);

			/* seg_data_len size check performed above */
			seg_data_len -= tail_frag_size;

			cipher_data += tail_frag_size;
			if (cipher_data_len < block_size) {
				ESP_PKT_ERR("Segment data underrun %d",
					    seg_data_len);
				return -1;
			}
			cipher_data_len -= block_size;
		}
	}

	crypto_chain_add_element(chain, NULL, cipher_data, 0,
				 ENG_CIPHER_FINALISE);

	return crypto_chain_walk(chain);
}

/*
* Process the message digest, generating and either storing  or verifiying it
*
* sa_ctx - SA context.
* mbuf - ptr to the segment where the MD starts, or it will be written.
* create - Generate and write MD, or Verify MD.
* md_data_ptr - ptr to  where the MD will be written to (create),
*               or will be compated with (verify).
* seg_data_left - Amount of data remaining in segment passed
*/
static int esp_process_digest(struct crypto_chain *chain)
{
	uint32_t icv_len = crypto_session_digest_len(chain->ctx);

	if (!icv_len)
		return 0;

	/* FIXME: support for ESN missing */

	chain->index = 0;
	crypto_chain_add_element(chain, chain->slop_buffer, chain->slop_buffer,
				 icv_len, ENG_DIGEST_FINALISE);

	return crypto_chain_walk(chain);
}

static int update_icv_cb(struct crypto_chain *chain, struct rte_mbuf *mbuf)
{
	int offset = chain->icv_offset;
	unsigned int length = crypto_session_digest_len(chain->ctx);

	if (!memcpy_to_mbuf(mbuf, chain->slop_buffer, offset, length)) {
		ESP_ERR("ICV out-of-packet: %d@%d\n", length, offset);
		return -1;
	}

	return 0;
}

static int check_icv_cb(struct crypto_chain *chain, struct rte_mbuf *mbuf)
{
	int offset = chain->icv_offset;
	unsigned int length = crypto_session_digest_len(chain->ctx);
	unsigned char md[EVP_MAX_MD_SIZE] = {0};

	if (!memcpy_from_mbuf(md, mbuf, offset, length)) {
		ESP_ERR("ICV out-of-packet: %d@%#x\n", length, offset);
		return -1;
	}

	/* calculated ICV already present in the chains slop_buffer */
	return memcmp(md, chain->slop_buffer, length);
}

static int null_icv_cb(struct crypto_chain *chain __rte_unused,
		       struct rte_mbuf *mbuf __rte_unused)
{
	return 0;
}

/*
 * esp_generate_chain
 *
 * Generate and process a chain of actions for the crypto engine.
 */
static int esp_generate_chain(struct sadb_sa *sa,
			      struct rte_mbuf *mbuf,
			      unsigned int l3_hdr_len,
			      unsigned char *esp,
			      unsigned char *iv,
			      uint32_t text_total_len, int8_t encrypt)
{
	struct crypto_chain chain;
	unsigned int esp_len = esp_hdr_len(sa);
	unsigned int iv_len = crypto_session_iv_len(sa->session);
	unsigned int icv_len = esp_icv_len(sa);
	struct crypto_visitor_ctx ctx = {
		.session = sa->session,
	};

	crypto_session_set_direction(sa, encrypt);

	if (crypto_chain_init(&chain, sa->session))
		return -1;

	chain.v_ctx = &ctx;

	/* set IV */
	if (iv_len)
		chain.v_ops->set_iv(chain.v_ctx, iv_len, iv);

	/* set ICV and callback */
	chain.icv_offset = dp_pktmbuf_l2_len(mbuf) + l3_hdr_len +
		text_total_len;

	if (sa->udp_encap)
		chain.icv_offset += sizeof(struct udphdr);

	if (!encrypt) {
		chain.icv_callback = icv_len ? check_icv_cb : null_icv_cb;
		memcpy_from_mbuf(chain.slop_buffer, mbuf, chain.icv_offset,
				 icv_len);
		chain.v_ops->set_icv(chain.v_ctx, icv_len,
					  chain.slop_buffer);
	} else {
		chain.icv_callback = icv_len ? update_icv_cb : null_icv_cb;
		chain.v_ops->set_icv(chain.v_ctx, 0, NULL);
	}

	/* process plaintext ESP header (w/o IV) */
	if (esp_process_authdata(&chain, esp) < 0)
		return -1;

	/* process plaintext ESP payload IV ptr & len*/
	if (iv_len) {
		crypto_chain_add_element(&chain, iv, NULL, iv_len,
					 ENG_CIPHER_INIT | ENG_DIGEST_BLOCK);
	}

	text_total_len -= esp_len;
	if (esp_process_text(&chain, mbuf, text_total_len, esp + esp_len) < 0)
		return -1;

	if (esp_process_digest(&chain) < 0)
		return -1;

	return chain.icv_callback(&chain, mbuf);
}

static unsigned int
esp_input_tunl_fixup4(struct sadb_sa *sa,
		      void *l3, void *new_l3)
{
	struct iphdr *ip = l3;
	struct iphdr *new_ip = new_l3;

	if (sa->flags & XFRM_STATE_DECAP_DSCP) {
		ip_dscp_set(ip->tos, new_ip);
		new_ip->check = 0;
		new_ip->check = dp_in_cksum_hdr(new_ip);
	}
	if (!(sa->flags & XFRM_STATE_NOECN)) {
		if (ip_tos_ecn_decap(ip->tos, (char *)new_ip,
				     ETH_P_IP)) {
			return -1;
		}
	}
	return ntohs(new_ip->tot_len);
}

static unsigned int
esp_input_tunl_fixup6(struct sadb_sa *sa, void *l3, void *new_l3)
{
	struct ip6_hdr *new_ip6 = new_l3;
	struct ip6_hdr *ip6 = l3;

	if (sa->flags & XFRM_STATE_DECAP_DSCP)
		ip6_tos_copy_outer_noecn(&ip6->ip6_flow, &new_ip6->ip6_flow);

	if (!(sa->flags & XFRM_STATE_NOECN)) {
		uint8_t tos = (ntohl(ip6->ip6_flow) >> 20) & 0xff;

		if (ip_tos_ecn_decap(tos, (char *)new_ip6,
				     ETH_P_IPV6)) {
			return -1;
		}
	}
	return ntohs(new_ip6->ip6_plen) + sizeof(struct ip6_hdr);
}

static void esp_input_tran_fixup4(void *new_l3, unsigned int new_total,
				  char next_hdr, unsigned int prev_off __unused)
{
	struct iphdr *ip = new_l3;

	ip->protocol = next_hdr;
	ip->tot_len = htons(new_total);
	ip->check = 0;
	ip->check = dp_in_cksum_hdr(ip);
}

static void esp_input_tran_fixup6(void *new_l3, unsigned int new_total,
				  char next_hdr, unsigned int prev_off)
{
	struct ip6_hdr *ip6 = new_l3;
	unsigned char *p_proto;

	p_proto = (unsigned char *)ip6 + prev_off;
	*p_proto = next_hdr;
	ip6->ip6_plen = htons(new_total - sizeof(struct ip6_hdr));
}

static void esp_input_nat_l4cksum_fixup(int family, struct rte_mbuf *m)
{
	void *l3_hdr;
	uint16_t protocol;
	struct udphdr *udp;
	struct tcphdr *tcp;

	/*
	 * RFC 3948: Section 3.1.2
	 * IPsec transport mode with NAT-T checksum handling.
	 * UDP fixup = option #3
	 * TCP fixup = option #2
	 */
	l3_hdr = dp_pktmbuf_mtol3(m, void *);
	if (family == AF_INET)
		protocol = ((struct iphdr *)l3_hdr)->protocol;
	else
		protocol = ((struct ip6_hdr *)l3_hdr)->ip6_nxt;
	switch (protocol) {
	case IPPROTO_UDP:
		if (pktmbuf_udp_header_is_usable(m)) {
			udp = dp_pktmbuf_mtol4(m, struct udphdr *);
			udp->check = 0;
		}
		break;
	case IPPROTO_TCP:
		if (pktmbuf_tcp_header_is_usable(m)) {
			tcp = dp_pktmbuf_mtol4(m, struct tcphdr *);
			tcp->check = 0;
			if (family == AF_INET)
				tcp->check = dp_in4_cksum_mbuf(m, l3_hdr, tcp);
			else
				tcp->check = dp_in6_cksum_mbuf(m, l3_hdr, tcp);
		}
		break;
	default:
		break;
	}
}

static int esp_input_inner(int family, struct rte_mbuf *m, void *l3_hdr,
			   struct sadb_sa *sa, uint32_t *bytes,
			   uint8_t *new_family)
{
	int rc = 0, head_trim  = 0, tail_trim = 0;
	unsigned int esp_len, ciphertext_len, udp_len = 0;
	unsigned int iphlen, icv_len, counter_modify = 0;
	unsigned int base_len;
	char next_hdr = 0, padding_size = 0;
	unsigned char *iv = NULL, *esp = NULL;
	unsigned int seg_data_remaining;
	unsigned int new_total;
	uint16_t ethertype, prev_off = 0;
	char *new_l3_hdr;
	uint8_t post_decrypt_family;
	void (*tran_fixup)(void *, unsigned int, char, unsigned int);
	unsigned int (*tunl_fixup)(struct sadb_sa *, void *, void *);

	if (!sa) {
		ESP_ERR("No SA for the inbound packet\n");
		return -1;
	}

	if (family == AF_INET) {
		struct iphdr *ip = l3_hdr;

		if (ip_is_fragment(ip)) {
			ESP_ERR("IP Frag\n");
			return -1;
		}

		base_len = ntohs(ip->tot_len);
		iphlen = ip->ihl << 2;
	} else {
		struct ip6_hdr *ip6 = l3_hdr;

		base_len = ntohs(ip6->ip6_plen) + sizeof(struct ip6_hdr);
		iphlen = dp_pktmbuf_l3_len(m);
		if (sa->mode == XFRM_MODE_TRANSPORT)
			prev_off = ip6_findprevoff(m);
	}

	esp =  dp_pktmbuf_mtol4(m, unsigned char *);
	if (sa->udp_encap) {
		esp += sizeof(struct udphdr);
		udp_len = sizeof(struct udphdr);
	}

	if (unlikely(sa->replay_window &&
		     esp_replay_check(esp, sa) < 0)) {
		crypto_sadb_seq_drop_inc(sa);
		return -1;
	}

	esp_len = esp_hdr_len(sa);

	/*
	 * Now much data is there left in the segment after the ip/udp
	 * hdr. Assumption here is that esp hdr is in the first
	 * segment.
	 */
	seg_data_remaining = rte_pktmbuf_data_len(m) -
		(esp - rte_pktmbuf_mtod(m, unsigned char *));

	if (seg_data_remaining < esp_len) {
		ESP_ERR("ESP not in first buffer\n");
		return -1;
	}

	/* iv is after the SPI(4) and the SEQ(4) */
	iv = esp + 8;

	/* ESP length = SPI(4) + SEQ(4) + IV_LEN */
	head_trim = esp_len + udp_len;
	icv_len = esp_icv_len(sa);
	ciphertext_len = base_len - iphlen - esp_len - udp_len - icv_len;

	if (ciphertext_len  % crypto_session_block_size(sa->session)) {
		ESP_ERR("Invalid ctext len %d block_size %d",
			ciphertext_len,
			crypto_session_block_size(sa->session));
		return -1;
	}

	if (unlikely(esp_generate_chain(sa, m, iphlen, esp, iv,
					ciphertext_len + esp_len,
					0) != 0))
		return -1;

	esp_replay_advance(esp, sa);

	rc = buf_tail_trim(m, icv_len, rc);
	rc = buf_tail_read_char(m, &next_hdr, rc);
	rc = buf_tail_read_char(m, &padding_size, rc);
	if (rc != 0) {
		ESP_ERR("ESP tail trim failed\n");
		return -1;
	}

	if (padding_size != 0)
		buf_tail_trim(m, padding_size, rc);
	/* Trim the tail of  next_hdr(1), padding_size(1),
	 * icv and padding
	 */
	tail_trim = 2 + padding_size + icv_len;

	/*
	 * We know what the next hdr type is now, so set up based on that.
	 * In case of transport mode, the next hdr doesn't matter the 'family'
	 * itself tells us the address family of the payload.
	 */
	if (((sa->mode == XFRM_MODE_TRANSPORT) && (family == AF_INET)) ||
	    (next_hdr == IPPROTO_IPIP)) {
		ethertype = ETH_P_IP;
		tran_fixup = esp_input_tran_fixup4;
		tunl_fixup = esp_input_tunl_fixup4;
		post_decrypt_family = AF_INET;
	} else {
		ethertype = ETH_P_IPV6;
		tran_fixup = esp_input_tran_fixup6;
		tunl_fixup = esp_input_tunl_fixup6;
		post_decrypt_family = AF_INET6;
	}

	if (sa->mode == XFRM_MODE_TRANSPORT) {
		new_l3_hdr = (char *)((char *)l3_hdr + esp_len + udp_len);
		memmove(new_l3_hdr, l3_hdr, iphlen);
		new_total = base_len - esp_len - udp_len - tail_trim;
		(*tran_fixup)(new_l3_hdr, new_total, next_hdr, prev_off);

		counter_modify = iphlen;
	} else if (sa->mode == XFRM_MODE_TUNNEL) {
		if (next_hdr != IPPROTO_IPV6 &&
		    next_hdr != IPPROTO_IPIP) {
			ESP_PKT_ERR("IPSEC: Invalid next_hdr proto %d\n",
				next_hdr);
			return -1;
		}

		head_trim += iphlen;
		new_l3_hdr = (char *)(esp + esp_len);
		new_total = (*tunl_fixup)(sa, l3_hdr, new_l3_hdr);
	} else {
		ESP_ERR("IPSEC: Unsupported mode");
		return -1;
	}

	rc = iptun_eth_hdr_fixup(m, ethertype, head_trim);
	if (rc < 0) {
		ESP_ERR("Ethernet header fixup failed\n");
		return -1;
	}

	/*
	 * RFC 3948: Section 3.1.2
	 */
	if (unlikely(sa->udp_encap == 1 && sa->mode == XFRM_MODE_TRANSPORT))
		esp_input_nat_l4cksum_fixup(family, m);

	/* Count the decapped payload against the receiving SA */
	crypto_sadb_increment_counters(sa, new_total - counter_modify, 1);
	*bytes = new_total - counter_modify;

	*new_family = post_decrypt_family;
	return 0;
}

static unsigned int esp_out_new_hdr6(bool transport, uint8_t orig_family,
				     void *l3hdr, void *new_l3hdr,
				     unsigned int pre_len,
				     unsigned int udp_size,
				     struct sadb_sa *sa)
{
	struct ip6_hdr *new_ip6 = (struct ip6_hdr *)new_l3hdr;
	unsigned int counter_modify = 0;

	if (transport) {
		/*
		 * Move the old L3 header and extensions down
		 * to make room for the ESP. We can't change AF
		 * in transport mode as we don't add a new ip hdr.
		 */
		memmove(new_l3hdr, l3hdr, pre_len);
		counter_modify = pre_len;
		new_ip6->ip6_nxt = sa->udp_encap ?
			IPPROTO_UDP : IPPROTO_ESP;
	} else {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)l3hdr;

		memcpy(new_l3hdr, &sa->ip6_hdr,
		       sizeof(sa->ip6_hdr));
		if (!(sa->extra_flags & XFRM_SA_XFLAG_DONT_ENCAP_DSCP)) {
			if (orig_family == AF_INET6)
				ip6_tos_copy_inner(&new_ip6->ip6_flow,
						   &ip6->ip6_flow);
			else
				ip6_ip_dscp_copy_inner(
					&new_ip6->ip6_flow,
					((struct iphdr *)l3hdr)->tos);
		}

		if (!(sa->flags & XFRM_STATE_NOECN)) {
			if (orig_family == AF_INET6)
				ip6_tos_ecn_encap(&new_ip6->ip6_flow,
						  &ip6->ip6_flow);
			else
				ip6_ip_ecn_encap(
					&new_ip6->ip6_flow,
					((struct iphdr *)l3hdr)->tos);
		}
	}

	new_ip6->ip6_plen = htons(udp_size);

	return counter_modify;
}

static unsigned int esp_out_new_hdr4(bool transport, uint8_t orig_family,
				     void *l3hdr,
				     void *new_l3hdr, unsigned int pre_len,
				     unsigned int udp_size,
				     struct sadb_sa *sa)
{
	struct iphdr *new_ip = (struct iphdr *)new_l3hdr;
	struct iphdr *ip = (struct iphdr *)l3hdr;
	unsigned int counter_modify = 0;
	uint16_t old_tot_len;

	if (transport) {
		uint16_t old_protocol;

		old_protocol = ip->protocol;
		memmove(new_l3hdr, l3hdr, pre_len);
		counter_modify = pre_len;
		new_ip->protocol =
			sa->udp_encap ? IPPROTO_UDP : IPPROTO_ESP;
		new_ip->check = ip_fixup16_cksum(new_ip->check,
						 old_protocol << 8,
						 new_ip->protocol << 8);
	} else {
		uint8_t new_tos = sa->iphdr.tos;

		memcpy(new_ip, &sa->iphdr, sizeof(sa->iphdr));
		if (!(sa->extra_flags & XFRM_SA_XFLAG_DONT_ENCAP_DSCP)) {
			if (orig_family == AF_INET)
				new_tos = ip->tos;
			else
				ip_ip6_dscp_copy_inner(
					&new_tos,
					&((struct ip6_hdr *)l3hdr)->ip6_flow);
		}

		if (!(sa->flags & XFRM_STATE_NOECN)) {
			if (orig_family == AF_INET)
				ip_tos_ecn_encap(&new_tos, ip->tos);
			else
				ip_ip6_ecn_encap(
					&new_tos,
					&((struct ip6_hdr *)l3hdr)->ip6_flow);
		}

		ip_tos_ecn_set(new_ip, new_tos);

		if (!(sa->flags & XFRM_STATE_NOPMTUDISC)) {
			new_ip->frag_off = ip->frag_off & htons(IP_DF);
			if (new_ip->frag_off != sa->iphdr.frag_off)
				new_ip->check =
					ip_fixup16_cksum(new_ip->check,
							 sa->iphdr.frag_off,
							 new_ip->frag_off);
		}
		new_ip->id =  sa->id++;
		assert(sa->iphdr.id == 0);
		new_ip->check = ip_fixup16_cksum(new_ip->check, 0, new_ip->id);
	}
	old_tot_len = new_ip->tot_len;
	new_ip->tot_len = htons(pre_len + udp_size);
	new_ip->check = ip_fixup16_cksum(new_ip->check, old_tot_len,
					 new_ip->tot_len);
	return counter_modify;
}

/*
 * Determine ESP header insertion point as an offset
 * from the ipv6 header. Also return next protocol.
 * Headers must be in first fragment. Returns -1 on failure.
 * ESP should be after HBH, Routing, Fragment, Dest(1), AH
 * ESP should precede Dest(2)
 * Dest(1) is a Dest immediately followed by Routing
 * Dest(2) is a Dest without a following Routing
 */
static int esp_out_proc_exthdr6(struct rte_mbuf *m, struct ip6_hdr *ip6,
				uint8_t *proto, unsigned int *offset)
{
	struct ip6_ext *ip6e;
	struct ip6_frag *ip6f;
	uint16_t off, base;

	*proto = ip6->ip6_nxt;
	base = dp_pktmbuf_l2_len(m);
	off = base + sizeof(struct ip6_hdr);

	for (;;) {
		switch (*proto) {
		case IPPROTO_FRAGMENT:
			ip6f = ip6_exthdr(m, off, sizeof(*ip6f));
			if (!ip6f)
				return -1;
			off += sizeof(struct ip6_frag);
			*proto = ip6f->ip6f_nxt;
			break;
		case IPPROTO_AH:
			ip6e = ip6_exthdr(m, off, sizeof(*ip6e));
			if (!ip6e)
				return -1;
			off += (ip6e->ip6e_len + 2) << 2;
			*proto = ip6e->ip6e_nxt;
			break;
		case IPPROTO_DSTOPTS:
			ip6e = ip6_exthdr(m, off, sizeof(*ip6e));
			if (!ip6e)
				return -1;
			if (ip6e->ip6e_nxt != IPPROTO_ROUTING) {
				*offset = off - base;
				return 0;
			}
			off += (ip6e->ip6e_len + 1) << 3;
			*proto = ip6e->ip6e_nxt;
			break;
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
			ip6e = ip6_exthdr(m, off, sizeof(*ip6e));
			if (!ip6e)
				return -1;
			off += (ip6e->ip6e_len + 1) << 3;
			*proto = ip6e->ip6e_nxt;
			break;
		default:
			*offset = off - base;
			return 0;
		}
	}
	return 0;
}

static int esp_out_hdr_parse6(struct rte_mbuf *m, void *l3hdr,
			      struct esp_hdr_ctx *h,
			      uint8_t new_family,
			      bool transport)
{
	struct ip6_hdr *ip6 = l3hdr;

	if (new_family == AF_INET) {
		h->out_new_hdr = esp_out_new_hdr4;
		h->out_hdr_len = sizeof(struct iphdr);
		h->out_ethertype = ETH_P_IP;
		h->out_align_val = 8;
		h->out_proto_nxt = IPPROTO_IP;  /* for transport mode */
	} else {
		h->out_new_hdr = esp_out_new_hdr6;
		h->out_hdr_len = sizeof(struct ip6_hdr);
		h->out_ethertype = ETH_P_IPV6;
		h->out_align_val = 8;
		h->out_proto_nxt = IPPROTO_IPV6;  /* for transport mode */
	}

	h->proto_ip = IPPROTO_IPV6;

	if (transport) {
		if (esp_out_proc_exthdr6(m, ip6, &h->out_proto_nxt,
					 &h->pre_len) < 0)
			return -1;
	} else {
		h->pre_len = sizeof(struct ip6_hdr);
	}
	h->tot_len = ntohs(ip6->ip6_plen) + sizeof(struct ip6_hdr);

	return 0;
}

static void esp_out_hdr_parse4(void *l3hdr, struct esp_hdr_ctx *h,
			       uint8_t new_family)
{
	struct iphdr *ip = l3hdr;

	if (new_family == AF_INET) {
		h->out_new_hdr = esp_out_new_hdr4;
		h->out_hdr_len = sizeof(struct iphdr);
		h->out_ethertype = ETH_P_IP;
		h->out_align_val = 4;
		h->out_proto_nxt = ip->protocol; /* for transport mode */
	} else {
		h->out_new_hdr = esp_out_new_hdr6;
		h->out_hdr_len = sizeof(struct ip6_hdr);
		h->out_ethertype = ETH_P_IPV6;
		h->out_align_val = 8;
		h->out_proto_nxt = IPPROTO_IPV6;  /* for transport mode */
	}

	h->proto_ip = IPPROTO_IPIP;
	h->pre_len = ip->ihl << 2;
	h->tot_len = ntohs(ip->tot_len);
}

static int esp_output_inner(int new_family, struct sadb_sa *sa,
			    struct rte_mbuf *m, uint8_t orig_family,
			    void *l3hdr, uint32_t *bytes)
{
	int block_size;
	unsigned int icv_size, tail_len, padding, enc_inc, udp_size = 0;
	unsigned int i, counter_modify = 0;
	unsigned int esp_size, plaintext_size, plaintext_size_orig;
	bool transport;
	unsigned char *plaintext = NULL, *esp_base, *esp_ptr = NULL;
	unsigned char *udp_base;
	char *hdr,  *tail = NULL;
	struct udphdr *udp = NULL;
	struct rte_ether_hdr *eth_hdr;
	unsigned char *new_l3hdr;
	struct esp_hdr_ctx h;

	if (!sa) {
		ESP_ERR("No SA for the outbound pkt\n");
		return -1;
	}

	transport = (sa->mode == XFRM_MODE_TRANSPORT) ? 1 : 0;

	if (orig_family == AF_INET) {
		esp_out_hdr_parse4(l3hdr, &h, new_family);
	} else {
		if (esp_out_hdr_parse6(m, l3hdr, &h, new_family, transport) < 0)
			return -1;
		if (!transport)
			m->l3_len = sizeof(struct ip6_hdr);
	}

	icv_size = esp_icv_len(sa);
	esp_size = esp_hdr_len(sa);

	plaintext = l3hdr;
	plaintext_size_orig = plaintext_size = h.tot_len;

	if (transport) {
		/*
		 * ESP follows header options
		 */
		plaintext += h.pre_len;
		plaintext_size -= h.pre_len;
		enc_inc = 0;
	} else {
		/*
		 * Taking whole packet from start of l3 and encrypting.
		 */
		h.pre_len = h.out_hdr_len;
		enc_inc = h.out_hdr_len;
	}

	udp_base = esp_base = esp_ptr = plaintext - esp_size;
	enc_inc += esp_size;

	if (sa->udp_encap) {
		udp_size = sizeof(struct udphdr);
		enc_inc += udp_size;
		udp_base -= udp_size;
		udp = (struct udphdr *) udp_base;
	}

	hdr = rte_pktmbuf_prepend(m, enc_inc);
	if (!hdr) {
		ESP_ERR("Head room inc failed (requested %d bytes)\n", enc_inc);
		return -1;
	}

	/* The ESP payload block needs to be aligned dependent on AF */
	block_size = RTE_ALIGN(crypto_session_block_size(sa->session),
			       h.out_align_val);
	/*
	 * Workout the padding and tail bytes required, based upon the
	 * plain text and the minimum two tail bytes, padding len and next_hdr
	 */
	padding = RTE_ALIGN(plaintext_size + 2, block_size) -
		(plaintext_size + 2);

	tail_len =  padding + 2 + icv_size;
	tail = pktmbuf_append_alloc(m, tail_len);
	if (!tail) {
		ESP_PKT_ERR("Tail room inc failed (requested %d bytes)\n",
			    tail_len);
		return -1;
	}

	/* Set the padding using RFC specified pattern */
	for (i = 1; i <= padding; i++)
		*tail++ = i;
	*tail++ = padding;
	*tail++ = transport ? h.out_proto_nxt : h.proto_ip;
	plaintext_size += padding + 2;

	new_l3hdr = udp_base - h.out_hdr_len;
	udp_size += esp_size + plaintext_size + icv_size;

	counter_modify = (*h.out_new_hdr)(transport, orig_family, l3hdr,
					  new_l3hdr, h.pre_len, udp_size, sa);

	if (udp) {
		udp->dest = sa->udp_dport;
		udp->source = sa->udp_sport;
		udp->check = 0;
		udp->len = htons(udp_size);
	}
	/* Add Spi, sequence and IV */
	*(uint32_t *)esp_ptr = (sa->spi);
	esp_ptr += 4;
	*(uint32_t *)esp_ptr = htonl(++(sa->seq));
	esp_ptr += 4;

	crypto_session_generate_iv(sa->session, (char *)esp_ptr);

	if (unlikely(sa->seq == ESP_SEQ_SA_REKEY_THRESHOLD)) {
		crypto_rekey_requests++;
		crypto_expire_request(sa->spi,
				      crypto_sadb_get_reqid(sa),
				      IPPROTO_ESP, 0 /* hard */);
	}
	if (unlikely(sa->seq > (ESP_SEQ_SA_BLOCK_LIMIT - 1)))
		crypto_sadb_mark_as_blocked(sa);

	if (unlikely(esp_generate_chain(sa, m, h.out_hdr_len, esp_base, esp_ptr,
					plaintext_size + esp_size, 1) != 0))
		return -1;

	crypto_session_set_iv(sa->session,
			      crypto_session_iv_len(sa->session),
			      tail - crypto_session_iv_len(sa->session));

	eth_hdr = (struct rte_ether_hdr *)hdr;
	eth_hdr->ether_type = htons(h.out_ethertype);

	crypto_sadb_increment_counters(sa, plaintext_size_orig -
				       counter_modify, 1);
	*bytes = plaintext_size_orig - counter_modify;
	return 0;
}

int esp_output(struct rte_mbuf *m, uint8_t orig_family, void *ip,
	       struct sadb_sa *sa, uint32_t *bytes)
{
	return esp_output_inner(AF_INET, sa, m, orig_family, ip, bytes);
}

int esp_output6(struct rte_mbuf *m, uint8_t orig_family, void *ip6,
		struct sadb_sa *sa, uint32_t *bytes)
{
	return esp_output_inner(AF_INET6, sa, m, orig_family, ip6, bytes);
}

int esp_input(struct rte_mbuf *m, struct sadb_sa *sa,
	      uint32_t *bytes, uint8_t *new_family)
{
	struct iphdr *ip = iphdr(m);

	return esp_input_inner(AF_INET, m, ip, sa,
			       bytes, new_family);
}

int esp_input6(struct rte_mbuf *m, struct sadb_sa *sa,
	       uint32_t *bytes, uint8_t *new_family)
{
	struct ip6_hdr *ip6 = ip6hdr(m);

	return esp_input_inner(AF_INET6, m, ip6, sa,
			       bytes, new_family);
}

bool udp_esp_dp_interesting(const struct udphdr *udp,
			    uint32_t *spi)
{
	const uint32_t *esp;

	/* Will need to replace this with a hash lookup
	 * in the longer run, but for IKE v1 we only look
	 * for 4500
	 */
	if ((udp->dest != htons(ESP_PORT)) && (udp->source != htons(ESP_PORT)))
		return false;

	/* Check for a keepalive packet, size is 1 byte, so anything
	 * less than a spi field size we are not interested in
	 */
	if ((ntohs(udp->len) - sizeof(*udp)) < 4)
		return false;
	esp = (const uint32_t *)(udp+1);
	/* Check for ike packet */
	if (*esp == 0x00000000)
		return false;

	if (spi)
		*spi = *esp;
	return true;
}

int udp_esp_dp(struct rte_mbuf *m,
	       void *ip,
	       struct udphdr *udp,
	       struct ifnet *ifp)
{
	uint32_t spi;

	if (udp_esp_dp_interesting(udp, &spi))
		return crypto_enqueue_inbound_v4(m, ip,
						 ifp, spi);

	return 1;
}

int udp_esp_dp6(struct rte_mbuf *m,
		void *ip6 __unused,
		struct udphdr *udp,
		struct ifnet *ifp)
{
	uint32_t spi;

	if (pktmbuf_get_vrf(m) != VRF_DEFAULT_ID)
		return 1;

	if (udp_esp_dp_interesting(udp, &spi))
		return crypto_enqueue_inbound_v6(m, ifp, spi);

	return 1;
}
