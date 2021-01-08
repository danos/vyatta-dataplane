/*
 * Copyright (c) 2017,2019-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Making a SIP call
 */

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "netinet6/ip6_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "npf/npf.h"

#include "dp_test_lib_internal.h"
#include "dp_test_str.h"
#include "dp_test_npf_nat_lib.h"
#include "dp_test_npf_alg_lib.h"
#include "dp_test_npf_alg_sip_parse.h"
#include "dp_test_npf_alg_sip_lib.h"
#include "dp_test_npf_alg_sip_call.h"

/*
 * A wrapper around _dp_test_pak_receive that sets up the pre- and post-
 * process packets and expectation.
 *
 * If NAT is taking place, then setup the validation callback, else just parse
 * the SIP payloads to check for correctness.
 */
void
_dp_test_npf_sip_pak_receive(uint seq, const char *descr,
			     struct dp_test_pkt_desc_t *pre,
			     const char *pre_payload,
			     struct dp_test_pkt_desc_t *post,
			     const char *post_payload,
			     enum dp_test_sip_dir sdir,
			     enum dp_test_nat_dir ndir,
			     enum dp_test_trans_type ttype,
			     bool verify_sess,
			     const char *file, int line)
{
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;
	int l = 0;
	bool debug = false;
	struct dp_test_alg_sip_ctx sip_ctx = {};
	struct dp_test_nat_ctx nat_context;

	if (pre_payload && debug)
		printf("%s", pre_payload);

	/*
	 * Setup the pre-NAT packet from the pre-NAT packet descriptor and the
	 * pre-NAT SIP payload string.
	 */
	pre_pak = dp_test_npf_alg_sip_pak(pre, pre_payload);

	/*
	 * Setup the post-NAT packet from the post-NAT packet descriptor and
	 * the post-NAT SIP payload string.
	 */
	post_pak = dp_test_npf_alg_sip_pak(post, post_payload);

	/* Setup the dp test 'expectation' structure */
	test_exp = _dp_test_exp_from_desc(post_pak, post, NULL, 0, false,
					  file, line);

	l = spush(test_exp->description, sizeof(test_exp->description),
		  "[%u] SIP %s %s (%s)", seq,
		  dp_test_npf_sip_msg_is_req(pre_payload) ? "REQ" : "RESP",
		  descr, sdir == DP_TEST_SIP_DIR_FORW ? "Forw" : "Back");

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/*
	 * If NAT is configured then setup the SIP and NAT callback context
	 */
	if (ttype == DP_TEST_TRANS_SNAT || ttype == DP_TEST_TRANS_DNAT) {
		struct dp_test_nat_ctx *nctx = &nat_context;

		l += spush(test_exp->description + l,
			   sizeof(test_exp->description) - l,
			   ", %s %s",
			   ttype == DP_TEST_TRANS_SNAT ? "SNAT" : "DNAT",
			   ndir == DP_TEST_NAT_DIR_FORW ? "Forw" : "Back");

		(void) l;

		memset(nctx, 0, sizeof(*nctx));

		nctx->verify_session = true;

		sip_ctx.nat = nctx,
		sip_ctx.saved_cb = dp_test_pak_verify,

		/* Parse the SIP packets, and setup the validation callback */
		dp_test_nat_set_ctx(nctx, ndir, ttype, pre, post,
				    verify_sess);
		_dp_test_alg_sip_set_validation(&sip_ctx, pre_pak, post_pak,
						test_exp, file, line);
	} else {
		/*
		 * No NAT.  Just verify SIP message as best we can before
		 * sending the packet.
		 */
		struct sip_alg_request *sr;
		char err[240];

		sr = dp_test_sip_alg_parse(pre_pak, false, err, sizeof(err));
		_dp_test_fail_unless(sr, file, line,
				     "%s\npre SIP parse error (%s)",
				     descr, err);
		dp_test_sip_alg_request_free(sr);

		sr = dp_test_sip_alg_parse(post_pak, false, err, sizeof(err));
		_dp_test_fail_unless(sr, file, line,
				     "%s\npost SIP parse error (%s)",
				     descr, err);
		dp_test_sip_alg_request_free(sr);
	}

	rte_pktmbuf_free(post_pak);

	/* Run the test */
	_dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp,
			     file, __func__, line);
}

/*
 * Duplicate a SIP call array.  Typically we would call this to make a copy of
 * a SIP call template that contains const strings, such that we can then
 * modify it.
 */
void
dp_test_npf_sip_call_dup(struct dp_test_sip_pkt_t *sip_call, uint nmsgs)
{
	uint i;

	for (i = 0; i < nmsgs; i++) {
		if (sip_call[i].msg_pre == NULL)
			sip_call[i].msg_pre = strdup(sip_call[i].msg);

		if (sip_call[i].msg_post == NULL)
			sip_call[i].msg_post = strdup(sip_call[i].msg);
	}
}

/*
 * Free a SIP call array that was previously created by
 * dp_test_npf_sip_call_dup
 */
void
dp_test_npf_sip_call_free(struct dp_test_sip_pkt_t *sip_call, uint nmsgs)
{
	uint i;

	for (i = 0; i < nmsgs; i++) {
		if (sip_call[i].msg_pre) {
			free(sip_call[i].msg_pre);
			sip_call[i].msg_pre = NULL;
		}
		if (sip_call[i].msg_post) {
			free(sip_call[i].msg_post);
			sip_call[i].msg_post = NULL;
		}
	}
}

/*
 * Change the FQDNs to IP addresses for inside hosts in all SIP msgs of a call
 */
void
dp_test_sip_call_replace_ins_fqdn(struct dp_test_sip_pkt_t *sip_call,
				  uint sip_call_sz, bool snat,
				  const char *ins_fqdn, const char *ins_ip,
				  const char *tgt, const char *trans)
{
	uint i;

	dp_test_npf_sip_call_dup(sip_call, sip_call_sz);

	for (i = 0; i < sip_call_sz; i++) {
		if (sip_call[i].msg_pre)
			dp_test_sip_replace_ins_fqdn(
				&sip_call[i].msg_pre, snat,
				sip_call[i].dir == DP_TEST_SIP_DIR_FORW,
				ins_fqdn, ins_ip, tgt, trans);

		if (sip_call[i].msg_post)
			dp_test_sip_replace_ins_fqdn(
				&sip_call[i].msg_post, snat,
				sip_call[i].dir == DP_TEST_SIP_DIR_FORW,
				ins_fqdn, ins_ip, tgt, trans);
	}
}

/*
 * Change the FQDNs to IP addresses for outside hosts in all SIP msgs of a
 * call
 */
void
dp_test_sip_call_replace_outs_fqdn(struct dp_test_sip_pkt_t *sip_call,
				   uint sip_call_sz, bool snat,
				   const char *outs_fqdn, const char *outs_ip,
				   const char *tgt, const char *trans)
{
	uint i;

	dp_test_npf_sip_call_dup(sip_call, sip_call_sz);

	for (i = 0; i < sip_call_sz; i++) {
		if (sip_call[i].msg_pre)
			dp_test_sip_replace_outs_fqdn(
				&sip_call[i].msg_pre, snat,
				sip_call[i].dir == DP_TEST_SIP_DIR_FORW,
				outs_fqdn, outs_ip, tgt, trans);

		if (sip_call[i].msg_post)
			dp_test_sip_replace_outs_fqdn(
				&sip_call[i].msg_post, snat,
				sip_call[i].dir == DP_TEST_SIP_DIR_FORW,
				outs_fqdn, outs_ip, tgt, trans);
	}
}

void
dp_test_sip_pkt_via_replace_str(struct dp_test_sip_pkt_t *sip_pkt,
				const char *old, const char *new)
{
	if (sip_pkt->msg_pre == NULL)
		sip_pkt->msg_pre = strdup(sip_pkt->msg);

	if (sip_pkt->msg_post == NULL)
		sip_pkt->msg_post = strdup(sip_pkt->msg);

	if (sip_pkt->msg_pre)
		dp_test_sip_via_replace_str(&sip_pkt->msg_pre, old, new);

	if (sip_pkt->msg_post)
		dp_test_sip_via_replace_str(&sip_pkt->msg_post, old, new);
}

/*
 * Adjust the pre-SNAT message to what we need it to be such that the correct
 * translation occur.
 *
 * FORW - Nothing to do.
 *
 * BACK - Any dest addr matching the SNAT target addr should
 * be changed to the SNAT trans addr.
 */
static void
dp_test_npf_sip_adj_pre_snat(char **strp, int part, bool req, bool forw,
			      const char *tgt, const char *trans)
{
	/* Placeholder */
}

/*
 * Adjust the post-SNAT message to what we expect it to be after it has been
 * translated.
 *
 * FORW - Any src addr matching SNAT target addr should be changed to the SNAT
 * trans addr.
 *
 * BACK - Nothing to do.  (Dest addrs will already be SNAT target)
 */
static void
dp_test_npf_sip_adj_post_snat(char **strp, int part, bool req, bool forw,
			      const char *tgt, const char *trans)
{
	if (req && forw) {
		if (strstr(*strp, "From") == *strp ||
		    strstr(*strp, "Call-ID") == *strp ||
		    strstr(*strp, "Via") == *strp ||
		    strstr(*strp, "Contact") == *strp ||
		    strstr(*strp, "Route") == *strp ||
		    strstr(*strp, "Record-Route") == *strp ||
		    strstr(*strp, "P-asserted-identity") == *strp ||
		    strstr(*strp, "P-preferred-identity") == *strp ||
		    strstr(*strp, "c=") == *strp ||
		    strstr(*strp, "o=") == *strp ||
		    strstr(*strp, "a=") == *strp)
			dp_test_npf_sip_replace_ptr(strp, tgt, trans);
	}
	if (req && !forw) {
		/* part 0 is the request/response bit */
		if (part == 0)
			dp_test_npf_sip_replace_ptr(strp, trans, tgt);
	}

	if (!req && forw) {
		/* Response forw */
		if (strstr(*strp, "To") == *strp ||
		    strstr(*strp, "Contact") == *strp ||
		    strstr(*strp, "Record-Route") == *strp)
			dp_test_npf_sip_replace_ptr(strp, tgt, trans);
	}

	if (!req && !forw) {
		/* Response back */
		if (strstr(*strp, "From") == *strp ||
		    strstr(*strp, "Call-ID") == *strp ||
		    strstr(*strp, "Via") == *strp ||
		    strstr(*strp, "Route") == *strp ||
		    strstr(*strp, "Record-Route") == *strp ||
		    strstr(*strp, "c=") == *strp ||
		    strstr(*strp, "o=") == *strp ||
		    strstr(*strp, "a=") == *strp)
			dp_test_npf_sip_replace_ptr(strp, trans, tgt);
	}
}

/*
 * Adjust the pre-DNAT message to what we need it to be such that the correct
 * translations occur.
 *
 * FORW - Any dest addrs that match the DNAT trans addr should be changed to
 * the DNAT target addr.
 *
 * BACK - Nothing to do
 */
static void
dp_test_npf_sip_adj_pre_dnat(char **strp, int part, bool req, bool forw,
			     const char *tgt, const char *trans)
{
	if (strstr(*strp, "Contact") == *strp) {
		if (forw)
			dp_test_npf_sip_replace_ptr(strp, trans, tgt);
	}

	if (strstr(*strp, "c=") == *strp) {
		if (forw)
			dp_test_npf_sip_replace_ptr(strp, trans, tgt);
	}
}

/*
 * Adjust the post-DNAT message to what we expect it to be after it has been
 * translated.
 *
 * FORW - Nothing to do.
 *
 * BACK - Any src addrs that match the DNAT trans should be changed to the
 * DNAT target.
 */
static void
dp_test_npf_sip_adj_post_dnat(char **strp, int part, bool req, bool forw,
			      const char *tgt, const char *trans)
{
	if (req && forw) {
		if (part == 0 ||
		    strstr(*strp, "To") == *strp ||
		    strstr(*strp, "o=") == *strp)
			dp_test_npf_sip_replace_ptr(strp, tgt, trans);
	}

	if (req && !forw) {
		if (part == 0 ||
		    strstr(*strp, "Contact") == *strp ||
		    strstr(*strp, "To") == *strp ||
		    strstr(*strp, "P-asserted-identity") == *strp ||
		    strstr(*strp, "P-preferred-identity") == *strp)
			dp_test_npf_sip_replace_ptr(strp, trans, tgt);
	}

	if (!req && forw) {
		/* Response forw */
		if (strstr(*strp, "To") == *strp ||
		    strstr(*strp, "Route") == *strp ||
		    strstr(*strp, "Record-Route") == *strp)
			dp_test_npf_sip_replace_ptr(strp, tgt, trans);
	}

	if (!req && !forw) {
		/* Response back */
		if (part == 0 ||
		    strstr(*strp, "To") == *strp ||
		    strstr(*strp, "Contact") == *strp ||
		    strstr(*strp, "Route") == *strp ||
		    strstr(*strp, "Record-Route") == *strp ||
		    strstr(*strp, "c=") == *strp)
			dp_test_npf_sip_replace_ptr(strp, trans, tgt);
	}
}

static void
dp_test_npf_sip_adj_part(char **strp, int part, bool req, bool pre, bool snat,
			 bool forw, const char *tgt, const char *trans)
{
	if (pre && snat)
		dp_test_npf_sip_adj_pre_snat(strp, part, req, forw,
					     tgt, trans);

	if (!pre && snat)
		dp_test_npf_sip_adj_post_snat(strp, part, req, forw,
					      tgt, trans);

	if (pre && !snat)
		dp_test_npf_sip_adj_pre_dnat(strp, part, req, forw,
					     tgt, trans);

	if (!pre && !snat)
		dp_test_npf_sip_adj_post_dnat(strp, part, req, forw,
					      tgt, trans);
}

/*
 * Adjust SIP message.  We do two types of ajustment:
 *
 * 1. Adjust pre-NAT msg so that the NAT target address is in the msg, or
 * 2. Adjust post-NAT msg so that the NAT translation addr in in the msg
 */
static void
dp_test_npf_sip_adj(char **msgp, bool pre, bool snat, bool forw,
		    const char *tgt, const char *trans)
{
	char **result;
	int count, i;
	char *msg = *msgp;
	bool req;

	req = dp_test_npf_sip_msg_is_req(*msgp);

	result = dp_test_npf_sip_split(msg, &count);

	for (i = 0; i < count; i++) {
		if (strlen(result[i]) > 0)
			dp_test_npf_sip_adj_part(&result[i], i, req, pre,
						 snat, forw, tgt, trans);
	}

	char *new = dp_test_npf_sip_combine(result, count);
	if (new) {
		/*
		 * This frees the param passed in, so we can safely assign to
		 * 'new'
		 */
		new = dp_test_npf_sip_reset_content_length(new);
		free(msg);
	}
	*msgp = new;

	dp_test_npf_sip_split_free(result, count);
}

static void
dp_test_npf_sip_display(char *msg, uint indent, bool display)
{
	if (!display)
		return;

	char **result;
	int count, i;

	result = dp_test_npf_sip_split(msg, &count);

	dp_test_npf_sip_debug("%*cSIP:", indent, ' ');
	for (i = 0; i < count; i++)
		dp_test_npf_sip_debug("%*c\"%s\"", indent+2, ' ', result[i]);

	dp_test_npf_sip_split_free(result, count);
}

/*
 * Make a complete SIP call, with SIP, NAT and packet verification.
 *
 * The 'ins' and 'outs' prefixes relate to the direction of the traffic flow
 * relative to the parent NAT session.
 *
 * 'pre' and 'post' refer to packets before and after the UUT. e.g.
 *
 *				    SNAT ->
 *				 +-----+
 *		 ----------------|     |-----------------
 *				 +-----+
 * Forw flow:	ins_pre    ------------> ins_post
 * Back flow:	outs_post  <------------ outs_pre
 *
 * sip_call	Array of SIP messages
 * sip_call_sz	Array size
 * ins_pre	pre-NAT packet descriptor, inside to outside
 * ins_post	post-NAT packet descriptor, inside to outside
 * outs_pre	pre-NAT packet descriptor, outside to inside
 * outs_post	post-NAT packet descriptor, outside to inside
 * ttype	SNAT or DNAT
 */
void
_dpt_npf_sip_call(struct dp_test_sip_pkt_t *sip_call,
		  uint sip_call_sz, uint first, uint last,
		  enum dp_test_sip_loc uut_loc,
		  struct dp_test_pkt_desc_t *ins_pre,
		  struct dp_test_pkt_desc_t *ins_post,
		  struct dp_test_pkt_desc_t *outs_pre,
		  struct dp_test_pkt_desc_t *outs_post,
		  enum dp_test_trans_type ttype,
		  uint vrfid,
		  const char *file, int line)
{
	struct dp_test_pkt_desc_t *pre, *post;
	enum dp_test_nat_dir ndir;
	bool snat = (ttype == DP_TEST_TRANS_SNAT);
	uint i, sent = 0;

	if (last >= sip_call_sz)
		last = sip_call_sz - 1;

	if (first > last)
		first = last;

	/*
	 * Loop though each SIP message
	 */
	for (i = first; i <= last; i++) {

		bool forw = (sip_call[i].dir == DP_TEST_SIP_DIR_FORW);
		const char *tgt = NULL, *trans = NULL;

		/*
		 * The call array may contain two versions of a msg, for
		 * example if there is a proxy in the msg path.  We only use
		 * one of these, and that is dependent upon the UT location.
		 */
		if (sip_call[i].loc != DP_TEST_SIP_LOC_DIRECT &&
		    sip_call[i].loc != uut_loc)
			continue;

		/*
		 * Determine from the packet descriptors what the NAT target
		 * and NAT translation addresses are
		 */
		if (ttype == DP_TEST_TRANS_SNAT) {
			if (forw) {
				/* SNAT Forw */
				tgt = ins_pre->l3_src;
				trans = ins_post->l3_src;
			} else {
				/* SNAT Back */
				trans = outs_pre->l3_dst;
				tgt = outs_post->l3_dst;
			}
		} else if (ttype == DP_TEST_TRANS_DNAT) {
			if (forw) {
				/* DNAT Forw */
				tgt = ins_pre->l3_dst;
				trans = ins_post->l3_dst;
			} else {
				/* DNAT Back */
				trans = outs_pre->l3_src;
				tgt = outs_post->l3_src;
			}
		}

		/*
		 * For now, the NAT direction is the same as the SIP
		 * direction.  This may change.
		 */
		if (forw) {
			ndir = DP_TEST_NAT_DIR_FORW;
			pre = ins_pre;
			post = ins_post;
		} else {
			ndir = DP_TEST_NAT_DIR_BACK;
			pre = outs_pre;
			post = outs_post;
		}

		char str[200];

		snprintf(str, sizeof(str),
			 "[%u] %-12s %s, src=%s:%u, dst=%s:%u tgt=%s, trans=%s",
			 ++sent, sip_call[i].descr,
			 forw ? "Forw":"Back",
			 pre->l3_src, pre->l4.udp.sport,
			 pre->l3_dst, pre->l4.udp.dport,
			 tgt, trans);

		dp_test_npf_sip_debug("  %s", str);

		/*
		 * Need pre and post adjustment here.
		 *
		 * pre-msg is the one we will be translating.  This needs
		 * adjusted to allow the translations to take place.
		 *
		 * post-msg is what we expect the msg to be after translation.
		 *
		 *
		 * Pre-msg, DNAT Forw: Any dest addrs that match the DNAT
		 * trans addr should be changed to the DNAT target addr
		 *
		 * Post-msg, DNAT Back: Any src addrs that match the DNAT
		 * trans should be changed to the DNAT target.
		 *
		 * Post-msg, SNAT Forw: Any src addr matching SNAT target addr
		 * should be changed to the SNAT trans addr.
		 *
		 * Pre-msg, SNAT Back: Any dest addr matching the SNAT target
		 * addr should be changed to the SNAT trans addr.
		 */

		/*
		 * SIP pre and post msg copies start the same, but may be
		 * adjusted.  They may be allocated and adjusted before this
		 * function is called, in which case we let the caller free
		 * the copied msgs.
		 */
		bool msg_pre_allocd = false;
		bool msg_post_allocd = false;

		if (sip_call[i].msg_pre == NULL) {
			sip_call[i].msg_pre = strdup(sip_call[i].msg);
			msg_pre_allocd = true;
		}

		if (sip_call[i].msg_post == NULL) {
			sip_call[i].msg_post = strdup(sip_call[i].msg);
			msg_post_allocd = true;
		}

		if (tgt && trans) {
			dp_test_npf_sip_adj(&sip_call[i].msg_pre, true,
					    snat, forw, tgt, trans);

			dp_test_npf_sip_adj(&sip_call[i].msg_post, false,
					    snat, forw, tgt, trans);
		}

		dp_test_npf_sip_display(sip_call[i].msg_pre, 4,
					DP_TEST_SIP_DEBUG_DETAIL);

		/*
		 * Extra check to ensure that NAT target or trans address has
		 * not leaked into the post-NAT messages
		 */
		if (snat && forw) {
			if (tgt && strstr(sip_call[i].msg_post, tgt)) {
				printf("%s\n", sip_call[i].msg_post);
				_dp_test_fail(
					file, line,
					"NAT tgt %s present in post-SNAT "
					"forw msg", tgt);
			}
		}
		if (snat && !forw) {
			if (trans && strstr(sip_call[i].msg_post, trans)) {
				printf("%s\n", sip_call[i].msg_post);
				_dp_test_fail(
					file, line,
					"NAT trans %s present in post-SNAT "
					"back msg", trans);
			}
		}
		if (!snat && forw) {
			if (tgt && strstr(sip_call[i].msg_post, tgt)) {
				printf("%s\n", sip_call[i].msg_post);
				_dp_test_fail(
					file, line,
					"NAT tgt %s present in post-DNAT "
					"forw msg", tgt);
			}
		}

		_dp_test_npf_sip_pak_receive(
			i + 1, sip_call[i].descr,
			pre, sip_call[i].msg_pre,
			post, sip_call[i].msg_post,
			sip_call[i].dir,
			ndir, ttype,
			false, file, line);

		if (sip_call[i].msg_pre && msg_pre_allocd) {
			free(sip_call[i].msg_pre);
			sip_call[i].msg_pre = NULL;
		}
		if (sip_call[i].msg_post && msg_post_allocd) {
			free(sip_call[i].msg_post);
			sip_call[i].msg_post = NULL;
		}
	}
}
