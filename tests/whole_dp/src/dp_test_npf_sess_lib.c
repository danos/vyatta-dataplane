/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane test npf session library
 */

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "npf/npf_cache.h"
#include "npf/npf_state.h"
#include "session/session.h"

#include "dp_test.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test/dp_test_cmd_check.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_nat_lib.h"
#include "dp_test_npf_sess_lib.h"
#include "dp_test_session_internal_lib.h"

/*
 * Parameters required to identify a session
 */
struct dp_test_npf_json_session_match_t {
	const char *saddr;
	uint16_t    src_id;
	const char *daddr;
	uint16_t    dst_id;
	const char *taddr; /* NAT only */
	uint16_t    tport; /* NAT only */
	uint16_t    trans_type; /* NAT only */
	uint8_t     proto;
	const char *intf;
	uint32_t    flags;
	uint32_t    flags_mask;
	bool        debug;
};


/*
 * Verify the npf global session count
 */
void
_dp_test_session_count_verify(uint exp_count, bool warn,
				  const char *file, const char *func, int line)
{
	uint count = 0;
	bool rv;

	rv = dp_test_npf_session_count(&count);

	_dp_test_fail_unless(rv, file, line,
			     "Failed to get session count (%s)\n", func);

	if (count != exp_count) {
		char str[80];

		snprintf(str, sizeof(str),
			 "FW  session count expected %d, actual %d (%s)",
			 exp_count, count, func);

		if (warn)
			printf("\nWarning: %s %s %d %s\n",
			       file, func, line, str);
		else
			_dp_test_fail(file, line, "\n%s (%s)\n", str, func);
	}
}

/*
 * Verify the npf global TCP session count
 */
void
_dp_test_npf_tcp_session_count_verify(uint exp_count, bool warn,
				      const char *file, int line)
{
	uint count = 0;
	bool rv;

	rv = dp_test_npf_tcp_session_count(&count);

	_dp_test_fail_unless(rv, file, line,
			     "Failed to get TCP session count\n");

	if (count != exp_count) {
		char str[80];

		snprintf(str, sizeof(str),
			 "TCP session count expected %d, actual %d",
			 exp_count, count);

		if (warn)
			printf("\nWarning: %s %d %s\n", file, line, str);
		else
			_dp_test_fail(file, line, "\n%s\n", str);
	}
}

/*
 * Verify the npf global UDP session count
 */
void
_dp_test_session_udp_count_verify(uint exp_count, bool warn,
				  const char *file, int line)
{
	uint count = 0;
	bool rv;

	rv = dp_test_npf_udp_session_count(&count);

	_dp_test_fail_unless(rv, file, line,
			     "Failed to get UDP session count\n");

	if (count != exp_count) {
		char str[80];

		snprintf(str, sizeof(str),
			 "UDP session count expected %d, actual %d",
			 exp_count, count);

		if (warn)
			printf("\nWarning: %s %d %s\n", file, line, str);
		else
			_dp_test_fail(file, line, "\n%s\n", str);
	}
}

/*
 * Verify the npf NAT session count
 */
void
_dp_test_npf_nat_session_count_verify(uint exp_count, bool warn,
				      const char *file, int line)
{
	uint count = 0;
	bool rv;

	rv = dp_test_npf_nat_session_count(&count);

	_dp_test_fail_unless(rv, file, line, "Failed to get session count\n");

	if (count != exp_count) {
		char str[80];

		snprintf(str, sizeof(str),
			 "NAT session count expected %d, actual %d",
			 exp_count, count);

		if (warn)
			printf("\nWarning: %s %d %s\n", file, line, str);
		else
			_dp_test_fail(file, line, "\n%s\n", str);
	}
}

/*
 * Mark all active sessions as 'expired'
 */
void
dp_test_npf_expire_sessions(void)
{
	dp_test_console_request_reply("session-op clear session all",
				      false);
}

/*
 * Clear all npf sessions
 */
void
dp_test_sessions_clear(void)
{

	/*
	 * Mark all sessions as expired and
	 * enable GC to clean them up.
	 */
	dp_test_session_reset();
}

/**
 * Extract source and destination IDs from a packet descriptor. e.g. for TCP
 * and UDP this is the source and dest ports.  IDs are in host byte order.
 *
 * @param pkt        [in]  Unit-test packet descriptor
 * @param src_id     [out] Pointer to src_id
 * @param dst_id     [out] Pointer to dst_id
 */
void
dp_test_npf_extract_ids_from_pkt_desc(struct dp_test_pkt_desc_t *pkt,
				      uint16_t *src_id, uint16_t *dst_id)
{
	*src_id = 0;
	*dst_id = 0;

	switch (pkt->proto) {
	case IPPROTO_ICMP:
		if (pkt->l4.icmp.type == ICMP_ECHO ||
		    pkt->l4.icmp.type == ICMP_ECHOREPLY) {
			*src_id = pkt->l4.icmp.udata16[0];
			*dst_id = pkt->l4.icmp.udata16[0];
		}
		break;
	case IPPROTO_ICMPV6:
		if (pkt->l4.icmp.type == ICMP6_ECHO_REQUEST ||
		    pkt->l4.icmp.type == ICMP6_ECHO_REPLY) {
			*src_id = pkt->l4.icmp.udata16[0];
			*dst_id = pkt->l4.icmp.udata16[0];
		}
		break;
	case IPPROTO_GRE:
		*src_id = pkt->l4.gre.prot;
		*dst_id = pkt->l4.gre.prot;
		break;
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	default:
		*src_id = pkt->l4.tcp.sport;
		*dst_id = pkt->l4.tcp.dport;
		break;
	}
}

static uint32_t
dp_test_npf_session_flags_from_json(json_object *jobj)
{
	uint32_t flags = 0;

	dp_test_json_int_field_from_obj(jobj, "flags", (int *)&flags);
	return flags;
}

static uint
dp_test_npf_session_state_from_json(json_object *jobj)
{
	uint32_t state = 0;

	dp_test_json_int_field_from_obj(jobj, "state", (int *)&state);
	return state;
}

/**
 * Verify the presence/absence of an npf session
 *
 * @param desc       [in] Optional text to be prepended to any error message
 * @param saddr      [in] Source address string
 * @param src_id     [in] Source ID in host order (TCP port, ICMP id)
 * @param daddr      [in] Dest address string
 * @param dst_id     [in] Dest ID in host order (TCP port, ICMP id)
 * @param proto      [in] IP protocol
 * @param intf       [in] Interface string, e.g. "dp2T1"
 * @param exp_flags  [in] Expected flags, e.g. SE_ACTIVE | SE_PASS
 * @param flags_mask [in] Flags mask, e.g. SE_FLAGS_MASK
 * @param exists      [in] true if we expect to find the session
 *
 * @return true if found
 **/
bool
_dp_test_session_verify(char *desc,
			    const char *saddr, uint16_t src_id,
			    const char *daddr, uint16_t dst_id,
			    uint8_t proto, const char *intf,
			    uint32_t exp_flags, uint32_t flags_mask,
			    bool exists, const char *file, int line)
{
	char real_ifname[IFNAMSIZ];
	char sess_str[256];
	char err_str[256];
	json_object *jobj;
	unsigned int index = 0;
	bool ok;
	int l = 0;

	dp_test_intf_real(intf, real_ifname);

	jobj = dp_test_npf_json_get_session(saddr, src_id,
					    daddr, dst_id,
					    proto,
					    real_ifname,
					    exp_flags, flags_mask, &index);

	ok = (jobj != NULL) == !!exists;

	if (desc)
		l = spush(sess_str, sizeof(sess_str), "  \"%s\"\n", desc);

	l += spush(sess_str+l, sizeof(sess_str)-l,
		   "  Src [%s, %d] Dst [%s, %d] proto %d %s",
		   saddr, src_id, daddr, dst_id, proto, intf);

	if (!ok) {
		printf("not ok\n");
		spush(err_str, sizeof(err_str),
		      "\nFW session %sfound:\n%s\n",
		      exists ? "not ":"", sess_str);
		goto error;
	}

	if (jobj)
		json_object_put(jobj);

	return true;

error:
	if (jobj)
		json_object_put(jobj);

	dp_test_npf_print_sessions(desc);

	_dp_test_fail(file, line, "%s", err_str);

	return false;
}

struct dp_test_npf_poll_cmd {
	int poll_cnt;
	bool result;
	json_object *response;
	/* fields to match on */
	const char *saddr;
	uint16_t src_id;
	const char *daddr;
	uint16_t dst_id;
	uint8_t proto;
	const char *intf;
	uint32_t exp_flags;
	uint32_t flags_mask;
	int pkts_in;
	int bytes_in;
	int pkts_out;
	int bytes_out;
};

static int
_dp_test_npf_session_verify_count_internal(zloop_t *loop, int poller,
					   void *arg)
{
	struct dp_test_npf_poll_cmd *cmd = arg;
	char real_ifname[IFNAMSIZ];
	json_object *jobj;
	json_object *counter_obj;
	unsigned int index = 0;
	int found_pkts_in;
	int found_bytes_in;
	int found_pkts_out;
	int found_bytes_out;

	--(cmd->poll_cnt);

	dp_test_intf_real(cmd->intf, real_ifname);

	jobj = dp_test_npf_json_get_session(cmd->saddr, cmd->src_id,
					    cmd->daddr, cmd->dst_id,
					    cmd->proto, real_ifname,
					    cmd->exp_flags, cmd->flags_mask,
					    &index);

	if (cmd->response)
		json_object_put(cmd->response);
	cmd->response = jobj;
	if (jobj) {
		if (!json_object_object_get_ex(jobj, "counters", &counter_obj))
			goto done;

		if (!dp_test_json_int_field_from_obj(counter_obj, "packets_in",
						     &found_pkts_in))
			goto done;
		if (!dp_test_json_int_field_from_obj(counter_obj, "bytes_in",
						     &found_bytes_in))
			goto done;
		if (!dp_test_json_int_field_from_obj(counter_obj, "packets_out",
						     &found_pkts_out))
			goto done;
		if (!dp_test_json_int_field_from_obj(counter_obj, "bytes_out",
						     &found_bytes_out))
			goto done;
		/* We have values for all of them */
		if (cmd->pkts_in == found_pkts_in &&
		    cmd->bytes_in == found_bytes_in &&
		    cmd->pkts_out == found_pkts_out &&
		    cmd->bytes_out == found_bytes_out) {
			cmd->result = true;
			return -1;
		}
	}
done:
	cmd->result = false;
	if (cmd->poll_cnt == 0)
		return -1;
	return 0;
}

/*
 * Verify the presence/absence of an npf session. the counts must match as
 * well as the values identifying the session.  Poll for a matching session
 * for the standard poll delay and record a test failure if not found.
 *
 * @param desc       [in] Optional text to be prepended to any error message
 * @param saddr      [in] Source address string
 * @param src_id     [in] Source ID in host order (TCP port, ICMP id)
 * @param daddr      [in] Dest address string
 * @param dst_id     [in] Dest ID in host order (TCP port, ICMP id)
 * @param proto      [in] IP protocol
 * @param intf       [in] Interface string, e.g. "dp2T1"
 * @param exp_flags  [in] Expected flags, e.g. SE_ACTIVE | SE_PASS
 * @param flags_mask [in] Flags mask, e.g. SE_FLAGS_MASK
 * @param pkts_in    [in] expected count
 * @param bytes_in   [in] expected count
 * @param pkts_out   [in] expected count
 * @param bytes_out  [in] expected count
 *
 * @return true if found
 */
void
_dp_test_session_verify_count(char *desc,
				  const char *saddr, uint16_t src_id,
				  const char *daddr, uint16_t dst_id,
				  uint8_t proto, const char *intf,
				  uint32_t exp_flags,
				  uint32_t flags_mask,
				  int pkts_in, int bytes_in,
				  int pkts_out,
				  int bytes_out, const char *file,
				  int line)
{
	zloop_t *loop = zloop_new();
	int timer;
	struct dp_test_npf_poll_cmd cmd = {
		.poll_cnt = DP_TEST_POLL_COUNT,
		.saddr = saddr,
		.src_id = src_id,
		.daddr = daddr,
		.dst_id = dst_id,
		.proto = proto,
		.intf = intf,
		.exp_flags = exp_flags,
		.flags_mask = flags_mask,
		.pkts_in = pkts_in,
		.bytes_in = bytes_in,
		.pkts_out = pkts_out,
		.bytes_out = bytes_out,
	};
	const char *str;

	timer = zloop_timer(loop, dp_test_wait_sec, 0,
			    _dp_test_npf_session_verify_count_internal, &cmd);
	dp_test_assert_internal(timer >= 0);

	zloop_start(loop);
	zloop_destroy(&loop);

	if (cmd.result) {
		json_object_put(cmd.response);
		return;
	}

	str = json_object_to_json_string_ext(cmd.response,
					     JSON_C_TO_STRING_PRETTY);
	_dp_test_fail(file, line, "Did not find the expected counts:\n%s\n",
		      str ? str : "");
}


/**
 * Verify the presence/absence of an npf session.  The 5-tuple is derived from
 * a packet descriptor.
 *
 * @param desc       [in] Optional text to be prepended to any error message
 * @param pkt        [in] Unit-test packet descriptor
 * @param intf       [in] Interface string, e.g. "dp2T1"
 * @param exp_flags  [in] Expected flags, e.g. SE_ACTIVE | SE_PASS
 * @param flags_mask [in] Flags mask, e.g. SE_FLAGS_MASK
 * @param exists      [in] true if we expect to find the session
 *
 * @return true if found
 **/
bool
_dp_test_npf_session_verify_desc(char *text, struct dp_test_pkt_desc_t *pkt,
				const char *intf, uint32_t exp_flags,
				uint32_t flags_mask, bool exists,
				const char *file, int line)
{
	uint16_t src_id;
	uint16_t dst_id;

	dp_test_npf_extract_ids_from_pkt_desc(pkt, &src_id, &dst_id);

	return _dp_test_session_verify(text,
					   pkt->l3_src, src_id,
					   pkt->l3_dst, dst_id,
					   pkt->proto, intf,
					   exp_flags, flags_mask,
					   exists, file, line);
}

/**
 * Verify the presence/absence of an npf NAT session
 *
 * @param desc       [in] Optional text to be prepended to any error message
 * @param sasr_ddr   [in] Source address string
 * @param src_id     [in] Source ID in host order (TCP port, ICMP id)
 * @param dst_addr   [in] Dest address string
 * @param dst_id     [in] Dest ID in host order (TCP port, ICMP id)
 * @param proto      [in] IP protocol
 * @param trans_addr [in] NAT translation address string
 * @param trans_port [in] NAT translation port in host order
 * @param trans_type [in] TRANS_TYPE_NATOUT (snat) or TRANS_TYPE_NATIN (dnat)
 * @param intf       [in] Interface string, e.g. "dp2T1"
 * @param exp_flags  [in] Expected flags, e.g. SE_ACTIVE | SE_PASS
 * @param flags_mask [in] Flags mask, e.g. SE_FLAGS_MASK
 * @param exists      [in] true if we expect to find the session
 * @param str        [in] Optional string to write error message to
 * @param strlen     [in] Length of str
 * @param file       [in] filename
 *
 * @return true if found
 *
 * This function is used in two ways:
 * 1. 'str' is non-NULL and 'file' is NULL.   Calling function does the
 *     dp_test_fail.
 * 2. 'str' is NULL and 'file' is non-NULL.  This function does the
 *     dp_test_fail.
 **/
bool
_dp_test_npf_nat_session_verify(char *desc,
				const char *src_addr, uint16_t src_id,
				const char *dst_addr, uint16_t dst_id,
				uint8_t proto,
				const char *trans_addr, uint16_t trans_port,
				int trans_type,
				const char *intf,
				uint32_t exp_flags, uint32_t flags_mask,
				bool exists,
				char *str, int strlen,
				const char *file, int line)
{
	char real_ifname[IFNAMSIZ];
	char sess_str[256];
	char err_str[256];
	json_object *jobj;
	unsigned int index = 0;
	bool ok;
	int l = 0;

	dp_test_intf_real(intf, real_ifname);

	/*
	 * For the moment ports are only meaningful for TCP, UDP and ICMP.
	 */
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP &&
	    proto != IPPROTO_ICMP) {
		src_id = 0;
		dst_id = 0;
	}

	jobj = dp_test_npf_json_get_nat_session(src_addr, src_id,
						dst_addr, dst_id,
						trans_addr, trans_port,
						proto,
						real_ifname,
						exp_flags, flags_mask,
						trans_type, &index);

	ok = (jobj != NULL) == !!exists;

	if (desc)
		l = spush(sess_str, sizeof(sess_str), "  \"%s\"\n", desc);

	l += spush(sess_str+l, sizeof(sess_str)-l,
		   "  Src [%s, %d] Dst [%s, %d]",
		   src_addr, src_id, dst_addr, dst_id);

	if (trans_addr || trans_port)
		l += spush(sess_str+l, sizeof(sess_str)-l, " Trans [%s, %d]",
			   trans_addr ? trans_addr : "-", trans_port);
	l += spush(sess_str+l, sizeof(sess_str)-l, " proto %d %s",
		   proto, intf);
	l += spush(sess_str+l, sizeof(sess_str)-l, " ttype %d", trans_type);

	if (!ok) {
		spush(err_str, sizeof(err_str),
		      "\nNAT session %sfound:\n%s\n",
		      exists ? "not ":"", sess_str);
		goto error;
	}

	/*
	 * Verify session flags
	 */
#if 0
	if (exists && flags_mask) {
		uint32_t flags = dp_test_npf_session_flags_from_json(jobj);

		if ((flags & flags_mask) != (exp_flags & flags_mask)) {
			spush(err_str, sizeof(err_str),
			      "\nNAT session, exp flags 0x%08X "
			      "actual flags 0x%08X:\n"
			      "%s\n",
			      (exp_flags & flags_mask),
			      (flags & flags_mask), sess_str);
			goto error;
		}
	}
#endif

	if (jobj)
		json_object_put(jobj);

	return true;

error:
	if (jobj)
		json_object_put(jobj);

	if (str)
		spush(str, strlen, "%s", err_str);
	if (file) {
		dp_test_npf_print_nat_sessions(desc);
		_dp_test_fail(file, line, "%s", err_str);
	}
	return false;
}

/**
 * Verify the presence/absence of an npf NAT session.  The 5-tuple and NAT
 * info is derived from pre and post packet descriptors.
 *
 * @param snat       [in] true if snat, false if dnat
 * @param pre        [in] Pre-NAT packet descriptor
 * @param post       [in] Pre-NAT packet descriptor
 *
 **/
void
_dp_test_nat_session_verify_desc(bool snat, uint32_t extra_flags,
				 struct dp_test_pkt_desc_t *pre,
				 struct dp_test_pkt_desc_t *post,
				 const char *file, int line)
{
	uint32_t flags = SE_ACTIVE | extra_flags;
	uint16_t pre_src_id, pre_dst_id;
	uint16_t post_src_id, post_dst_id;

	dp_test_npf_extract_ids_from_pkt_desc(pre, &pre_src_id,
					      &pre_dst_id);
	dp_test_npf_extract_ids_from_pkt_desc(post, &post_src_id,
					      &post_dst_id);

	_dp_test_npf_nat_session_verify(
		NULL,
		pre->l3_src, pre_src_id,
		pre->l3_dst, pre_dst_id,
		pre->proto,
		snat ? post->l3_src : post->l3_dst,
		snat ? post_src_id : post_dst_id,
		snat ? TRANS_TYPE_NATOUT : TRANS_TYPE_NATIN,
		snat ? pre->tx_intf : pre->rx_intf,
		flags, SE_FLAGS_MASK, true, NULL, 0,
		file, line);
}

/*
 * Get the count of all npf sessions
 */
bool
dp_test_npf_session_count(uint *count)
{
	uint32_t used;
	uint32_t max;
	struct session_counts sc = { 0 };

	session_counts(&used, &max, &sc);

	*count = sc.sc_feature_counts[SESSION_FEATURE_NPF];

	return true;
}

/*
 * Get the count of all npf NAT sessions
 */
bool
dp_test_npf_nat_session_count(uint *count)
{
	uint32_t used;
	uint32_t max;
	struct session_counts sc = { 0 };

	session_counts(&used, &max, &sc);

	*count = sc.sc_nat;

	return true;
}

/*
 * Get the count of all npf TCP sessions
 */
bool
dp_test_npf_tcp_session_count(uint *count)
{
	uint32_t used;
	uint32_t max;
	struct session_counts sc = { 0 };

	session_counts(&used, &max, &sc);

	*count = sc.sc_tcp;

	return true;
}

/*
 * Get the count of all npf UDP sessions
 */
bool
dp_test_npf_udp_session_count(uint *count)
{
	uint32_t used;
	uint32_t max;
	struct session_counts sc = { 0 };

	session_counts(&used, &max, &sc);

	*count = sc.sc_udp;

	return true;
}

/*
 * Get the count of all non TCP/UDP/NAT sessions
 */
bool
dp_test_npf_other_session_count(uint *count)
{
	uint32_t used;
	uint32_t max;
	struct session_counts sc = { 0 };

	session_counts(&used, &max, &sc);

	*count = sc.sc_icmp + sc.sc_icmp6 + sc.sc_other;

	return true;
}

/*
 * Utilities for parsing the json output of "npf-op fw session list"
 */

/*
 * Compare the flags field of two identical session table entries.  Return
 * true if 'jnew' is a better match than 'jcur'.  A sessions lifecycle should
 * be:
 *
 * Event:     flags:
 * created:   0
 * activated: SE_ACTIVE
 * expired:   SE_ACTIVE | SE_EXPIRE
 * GC pass 1: SE_ACTIVE | SE_EXPIRE | SE_GC_PASS_TWO
 * GC pass 2: deleted
 */
static bool
dp_test_npf_sess_match_flags(json_object *jnew, json_object *jcur,
			     uint32_t flags, uint32_t mask)
{
	uint32_t flags_new = dp_test_npf_session_flags_from_json(jnew);
	uint32_t flags_cur = dp_test_npf_session_flags_from_json(jcur);

	return true;

	/* flags preference, most preferred to least preferred */
	uint32_t pref[] = {
		SE_ACTIVE,
		(SE_ACTIVE | SE_EXPIRE),
		(SE_ACTIVE | SE_EXPIRE | SE_GC_PASS_TWO),
		/*
		 * The following apply to sessions created but not activated
		 */
		0,
		SE_EXPIRE,
		(SE_EXPIRE | SE_GC_PASS_TWO) };

	/*
	 * If a flags_mask has been specified then we first look for an exact
	 * match.
	 */
	if (mask) {
		if ((flags_cur & mask) == (flags & mask))
			return false;
		if ((flags_new & mask) == (flags & mask))
			return true;
	}

	/*
	 * Exact match not found, so look for best match
	 */
	mask = (SE_ACTIVE | SE_EXPIRE | SE_GC_PASS_TWO);

	uint i;
	for (i = 0; i < ARRAY_SIZE(pref); i++) {
		if ((flags_cur & mask) == pref[i])
			return false;
		if ((flags_new & mask) == pref[i])
			return true;
	}
	return false;
}

/*
 * Iterate over npf firewall sessions.  Callback function may return true to
 * terminate the iteration, in which case the current session is returned to
 * the caller.
 *
 * If a json object is returned then it will have its ref count incremented.
 *
 * Unlike firewall groups, the sessions are *not* stored as a json array.
 * Instead, the session table is an "object of objects".  Each objects name is
 * a number (the session ID).  This always increments for every new session,
 * so remember the ID of the first session each time, and use that as the
 * starting ID to search for next time.
 */
typedef bool (*dp_test_npf_json_session_cb)(json_object *jvalue, void *arg);

#define DP_TEST_SESSION_MAX 400

static uint first_session_id;
static uint first_nat_session_id;

json_object *
dp_test_npf_json_fw_session_iterate(dp_test_npf_json_session_cb cb, void *arg,
				    unsigned int *index)
{
	json_object *jresp, *jobj, *jbest = NULL;
	uint nsessions, i, found, ibest, id;
	struct dp_test_npf_json_session_match_t *match = arg;
	struct dp_test_json_find_key key[] = { {"config", NULL},
					       {"sessions", NULL} };
	char *response;
	bool err;

	if (index)
		*index = 0;

	if (!dp_test_npf_session_count(&nsessions))
		return NULL;

	response = dp_test_console_request_w_err(
			"session-op show sessions full", &err, false);
	if (!response || err)
		return NULL;

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);

	if (!jresp)
		return NULL;

	jobj = dp_test_json_find(jresp, key, ARRAY_SIZE(key));
	json_object_put(jresp);

	if (!jobj)
		return NULL;

	/* Print session table if true */
	if (0) {
		const char *str;

		str = json_object_to_json_string_ext(jobj,
						     JSON_C_TO_STRING_PRETTY);
		if (str)
			printf("%s\n", str);
	}
	bool first = true;

	/*
	 * Sessions are identified by a number string, but this is neither
	 * in order or contiguous.
	 *
	 * Allow for finding 2 more sessions than the summary session count
	 */
	for (found = 0, i = 0, id = first_session_id;
	     found < (nsessions + 2) && i < DP_TEST_SESSION_MAX;
	     i++, id++) {
		char snum[20];
		json_object *jvalue;

		snprintf(snum, sizeof(snum), "%d", id);

		if (!json_object_object_get_ex(jobj, snum, &jvalue))
			continue;
		found++;

		/*
		 * Remember the number of the first session found for next time
		 * we do this iteration.
		 */
		if (first && id > first_session_id) {
			first = false;
			first_session_id = id - 1;
		}

		if ((*cb)(jvalue, match)) {
			if (!jbest) {
				jbest = json_object_get(jvalue);
				ibest = id;
			} else {
				/* Pick best match */
				if (dp_test_npf_sess_match_flags(
					    jvalue, jbest,
					    match->flags, match->flags_mask)) {
					json_object_put(jbest);
					jbest = json_object_get(jvalue);
					ibest = id;
				}
			}
		}
	}

	json_object_put(jobj);

	if (jbest) {
		if (index)
			*index = ibest;
		return jbest;
	}
	if (nsessions > found && i == DP_TEST_SESSION_MAX) {
		printf("\nWarning - failed to iterate over all sessions (%d)\n",
		       first_session_id);
	}

	return NULL;
}

json_object *
dp_test_npf_json_nat_session_iterate(dp_test_npf_json_session_cb cb,
				     void *arg, unsigned int *index)
{
	json_object *jresp, *jobj, *jbest = NULL;
	uint nsessions, i, found, ibest, id;
	struct dp_test_npf_json_session_match_t *match = arg;
	struct dp_test_json_find_key key[] = { {"config", NULL},
					       {"sessions", NULL} };
	char *response;
	bool err;

	if (index)
		*index = 0;

	if (!dp_test_npf_nat_session_count(&nsessions))
		return NULL;

	response = dp_test_console_request_w_err(
			"session-op show sessions full", &err, false);
	if (!response || err)
		return NULL;

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);

	if (!jresp)
		return NULL;

	jobj = dp_test_json_find(jresp, key, ARRAY_SIZE(key));
	json_object_put(jresp);

	if (!jobj)
		return NULL;

	bool first = true;

	/*
	 * Sessions are identified by a number string, but this is neither
	 * in order or contiguous
	 *
	 * Allow for finding 2 more sessions than the summary session count
	 */
	for (found = 0, i = 0, id = first_nat_session_id;
	     found < (nsessions + 2) && i < DP_TEST_SESSION_MAX;
	     i++, id++) {
		char snum[20];
		json_object *jvalue;

		snprintf(snum, sizeof(snum), "%d", id);

		if (!json_object_object_get_ex(jobj, snum, &jvalue))
			continue;
		found++;

		/*
		 * Remember the number of the first session found for next time
		 * we do this iteration.
		 */
		if (first && id > first_nat_session_id) {
			first = false;
			first_nat_session_id = id - 1;
		}

		if ((*cb)(jvalue, match)) {
			if (!jbest) {
				jbest = json_object_get(jvalue);
				ibest = id;
			} else {
				/* Pick best match */
				if (dp_test_npf_sess_match_flags(
					    jvalue, jbest,
					    match->flags, match->flags_mask)) {
					json_object_put(jbest);
					jbest = json_object_get(jvalue);
					ibest = id;
				}
			}
		}
	}
	json_object_put(jobj);

	if (jbest) {
		if (index)
			*index = ibest;
		return jbest;
	}
	if (nsessions > found && i == DP_TEST_SESSION_MAX)
		printf("\nWarning - "
		       "failed to iterate over all NAT sessions (%d)\n",
		       first_nat_session_id);

	return NULL;
}
typedef bool (*dp_test_json_array_iterate_cb)(json_object *jvalue, void *arg);

/* Nat matching function */
static bool dp_test_npf_json_nat_match(json_object *jobj, void *data)
{
	int ival;
	const char *str;
	json_object *jvalue;
	bool rv;
	struct dp_test_npf_json_session_match_t *m = data;

	struct dp_test_json_find_key keys[] = {
		{"nat", NULL}
	};

	/* Only NPF features */
	rv = dp_test_json_int_field_from_obj(jobj, "type", &ival);
	if (!rv || ival != SESSION_FEATURE_NPF) {
		if (m->debug)
			printf("feature type: %d != %u\n",
					ival, SESSION_FEATURE_NPF);
		return false;
	}

	/* Match interface */
	if (m->intf) {
		rv = dp_test_json_string_field_from_obj(jobj,
				"interface", &str);
		if (!rv || strcmp(m->intf, str) != 0) {
			if (m->debug)
				printf("Interface: %s != %s\n", str, m->intf);
			return false;
		}
	}

	/* get nat object */
	jvalue = dp_test_json_find(jobj, keys, 1);
	if (!jvalue) {
		if (m->debug)
			printf("Nat object not found!\n");
		return false;
	}

	/* Match trans type (SNAT/DNAT) */
	rv = dp_test_json_int_field_from_obj(jvalue, "trans_type", &ival);
	if (!rv || (uint16_t) ival != m->trans_type) {
		if (m->debug)
			printf("Trans type: %d != %u\n", ival, m->trans_type);
		json_object_put(jvalue);
		return false;
	}

	if (m->taddr) {
		rv = dp_test_json_string_field_from_obj(jvalue,
				"trans_addr", &str);
		if (!rv || strcmp(str, m->taddr) != 0) {
			if (m->debug)
				printf("Trans addr: %s != %s\n", str, m->taddr);
			json_object_put(jvalue);
			return false;
		}
	}

	if (m->tport) {
		rv = dp_test_json_int_field_from_obj(jvalue,
				"trans_port", &ival);
		if (!rv || (uint16_t) ival != m->tport) {
			if (m->debug)
				printf("Trans port: %d != %u\n",
						ival, m->tport);
			json_object_put(jvalue);
			return false;
		}
	}

	json_object_put(jvalue);
	return true;
}

/* Interface matching function */
static bool dp_test_npf_json_interface_match(json_object *jobj, void *data)
{
	struct dp_test_npf_json_session_match_t *m = data;
	int ival;
	const char *str;
	bool rv;

	/* Only NPF features */
	rv = dp_test_json_int_field_from_obj(jobj, "type", &ival);
	if (!rv || ival != SESSION_FEATURE_NPF) {
		if (m->debug)
			printf("feature type: %d != %u\n",
					ival, SESSION_FEATURE_NPF);
		return false;
	}

	/* Match interface */
	if (m->intf) {
		rv = dp_test_json_string_field_from_obj(jobj,
				"interface", &str);
		if (!rv || strcmp(m->intf, str) != 0) {
			if (m->debug)
				printf("Interface: %s != %s\n", str, m->intf);
			return false;
		}
	}
	return true;
}
/*
 * Iterator callback.  Returns true if a session is matched.
 */
static bool
dp_test_npf_json_session_match(json_object *jobj, void *arg)
{
	struct dp_test_npf_json_session_match_t *m = arg;
	const char *str;
	int ival;
	struct json_object *jarray;
	struct json_object *jvalue;
	bool rv;

	if (m->saddr) {
		rv = dp_test_json_string_field_from_obj(jobj,
							"src_addr", &str);
		if (!rv || strcmp(str, m->saddr) != 0) {
			if (m->debug)
				printf("Src addr: %s != %s\n", str, m->saddr);
			return false;
		}
	}

	if (m->src_id) {
		rv = dp_test_json_int_field_from_obj(jobj,
						     "src_port", &ival);
		if (!rv || (uint16_t)ival != m->src_id) {
			if (m->debug)
				printf("Src id: %d != %d\n", ival, m->src_id);
			return false;
		}
	}

	if (m->daddr) {
		rv = dp_test_json_string_field_from_obj(jobj,
							"dst_addr", &str);
		if (!rv || strcmp(str, m->daddr) != 0) {
			if (m->debug)
				printf("Dst addr: %s != %s\n", str, m->daddr);
			return false;
		}
	}

	if (m->dst_id) {
		rv = dp_test_json_int_field_from_obj(jobj,
						     "dst_port", &ival);
		if (!rv || (uint16_t)ival != m->dst_id) {
			if (m->debug)
				printf("Dst id: %d != %d\n", ival, m->dst_id);
			return false;
		}
	}

	if (m->proto) {
		rv = dp_test_json_int_field_from_obj(jobj,
						     "proto", &ival);
		if (!rv || (uint8_t)ival != m->proto) {
			if (m->debug)
				printf("Proto: %d != %d\n", ival, m->proto);
			return false;
		}
	}

	/*
	 * Special case:
	 *
	 * The npf tcp state test wants to match against an interface, however
	 * for certain tcp state transitions, the session's feature list
	 * will be zero. So we cannot match against the interface below.
	 *
	 * Expired NPF sessions are immediately removed from the dataplane
	 * session's feature list.
	 *
	 * So detect this and deal with it here.
	 */
	rv = dp_test_json_int_field_from_obj(jobj, "features_count", &ival);
	if (rv && !ival) {
		/* Match interface */
		rv = true;
		if (m->intf) {
			rv = dp_test_json_string_field_from_obj(jobj,
					"interface", &str);
			if (!rv || strcmp(m->intf, str) != 0) {
				if (m->debug)
					printf("Interface: %s != %s\n", str,
							m->intf);
				return false;
			}
		}

		return rv;
	}



	/*
	 * Deal with matches to NAT and/or specific interfaces
	 * (eg: stateful FW).
	 *
	 * To do this we must run through the feature's json array.
	 */
	struct dp_test_json_find_key keys[] = {
		{"features", NULL}
	};

	/* Get features array */
	jarray = dp_test_json_find(jobj, keys, ARRAY_SIZE(keys));
	if (!jarray)
		return false;

	rv = false;

	/*
	 * Now look for a match on either the NAT, or
	 * a stateful interface instance
	 */
	if (m->trans_type) {
		jvalue = dp_test_json_array_iterate(jarray,
				dp_test_npf_json_nat_match, m);
	} else {
		jvalue = dp_test_json_array_iterate(jarray,
				dp_test_npf_json_interface_match, m);
	}
	if (jvalue)
		rv = true;

	json_object_put(jarray);

	return rv;
}

/*
 * Find a specific session by iterating over all sessions looking for a
 * match of the specified parameter.   NULL or 0 values are not matched.
 *
 * The returned json object has its ref count incremented, so json_object_put
 * should be called once the caller has finished with the object.
 *
 * If a session has been expired, then its possible for a duplicate entry to
 * be created, hence we need to also match on the flags field.
 *
 * If flags_mask is non-zero then the iterator will return the first match it
 * finds.   If zero then it will return the best match.
 */
json_object *
dp_test_npf_json_get_session(const char *saddr, uint16_t src_id,
			     const char *daddr, uint16_t dst_id,
			     uint8_t proto,
			     const char *intf, uint32_t flags,
			     uint32_t flags_mask, unsigned int *index)
{
	json_object *jobj;
	struct dp_test_npf_json_session_match_t m = {
		.saddr	= saddr,
		.src_id	= src_id,
		.daddr	= daddr,
		.dst_id	= dst_id,
		.taddr	= NULL,
		.tport	= 0,
		.trans_type = 0,
		.proto	= proto,
		.intf	= intf,
		.flags  = flags,
		.flags_mask = flags_mask,
		.debug	= false
	};

	jobj = dp_test_npf_json_fw_session_iterate(
		&dp_test_npf_json_session_match, &m, index);
	return jobj;
}

json_object *
dp_test_npf_json_get_nat_session(const char *saddr, uint16_t src_id,
				 const char *daddr, uint16_t dst_id,
				 const char *taddr, uint16_t tport,
				 uint8_t proto, const char *intf,
				 uint32_t flags, uint32_t flags_mask,
				 uint16_t trans_type, unsigned int *index)
{
	json_object *jobj;
	struct dp_test_npf_json_session_match_t m = {
		.saddr	= saddr,
		.src_id	= src_id,
		.daddr	= daddr,
		.dst_id	= dst_id,
		.taddr	= taddr,
		.tport	= tport,
		.trans_type = trans_type,
		.proto	= proto,
		.intf	= intf,
		.flags  = flags,
		.flags_mask = flags_mask,
		.debug	= false
	};

	jobj = dp_test_npf_json_nat_session_iterate(
		&dp_test_npf_json_session_match, &m, index);
	return jobj;
}

/*
 * NPF instance ID
 *
 * VRF aware json objects will contain an instance array, where each array
 * element is identified by an "npf_id" integer field.
 */

/*
 * Find a specific instance in a json array
 */
struct dp_test_npf_json_instance_match_t {
	uint npf_id;
};

static bool
dp_test_npf_json_instance_match(json_object *jobj, void *arg)
{
	struct dp_test_npf_json_instance_match_t *vals = arg;
	int npf_id;

	if (!dp_test_json_int_field_from_obj(jobj, "vrfid", &npf_id) ||
	    (uint)npf_id != vals->npf_id)
		return false;

	return true;
}

json_object *
dp_test_npf_json_array_get_instance(json_object *jarray, uint npf_id)
{
	struct dp_test_npf_json_instance_match_t arg;
	json_object *jobj, *jret = NULL;

	if (!jarray)
		return NULL;

	arg.npf_id = npf_id;

	jobj = dp_test_json_array_iterate(jarray,
					  &dp_test_npf_json_instance_match,
					  &arg);

	if (jobj)
		jret = json_object_get(jobj);
	json_object_put(jarray);

	return jret;
}

bool
dp_test_npf_session_state(const char *saddr, uint16_t src_id,
			  const char *daddr, uint16_t dst_id,
			  uint8_t proto, const char *intf,
			  uint *state)
{
	char real_ifname[IFNAMSIZ];
	json_object *jobj;
	uint index;

	dp_test_intf_real(intf, real_ifname);

	jobj = dp_test_npf_json_get_session(saddr, src_id,
					    daddr, dst_id,
					    proto,
					    real_ifname,
					    0, 0, &index);
	if (!jobj)
		return false;

	*state = dp_test_npf_session_state_from_json(jobj);

	json_object_put(jobj);
	return true;
}

const char *
dp_test_npf_sess_state_str(uint8_t proto, uint state)
{
	if (proto == IPPROTO_TCP)
		return npf_state_get_state_name(state, NPF_PROTO_IDX_TCP);

	return npf_state_get_state_name(state, NPF_PROTO_IDX_OTHER);
}

void
dp_test_npf_print_session(const char *saddr, uint16_t src_id,
			  const char *daddr, uint16_t dst_id,
			  uint8_t proto, const char *intf)
{
	char real_ifname[IFNAMSIZ];
	json_object *jobj;
	const char *str;
	uint index;

	dp_test_intf_real(intf, real_ifname);

	jobj = dp_test_npf_json_get_session(saddr, src_id,
					    daddr, dst_id,
					    proto,
					    real_ifname,
					    0, 0, &index);
	if (!jobj) {
		printf("Session not found "
		       "(src=%s:%u dst=%s:%u proto=%u intf=%s)\n",
		       saddr, src_id, daddr, dst_id, proto, intf);
		return;
	}

	str = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PRETTY);
	if (str)
		printf("\"%u\":%s\n", index, str);
	json_object_put(jobj);
}

/*
 * List all session table entries in prettied json format
 */
void
dp_test_npf_print_session_table(bool nat)
{
	json_object *jobj;
	char *str;
	const char *const_str;
	bool err;

	if (nat)
		str = dp_test_console_request_w_err(
			"session-op show sessions full", &err, false);
	else
		str = dp_test_console_request_w_err(
			"session-op show sessions", &err, false);

	if (!str || err)
		return;

	jobj = parse_json(str, parse_err_str, sizeof(parse_err_str));
	free(str);

	if (!jobj)
		return;

	const_str = json_object_to_json_string_ext(jobj,
						   JSON_C_TO_STRING_PRETTY);
	if (const_str)
		printf("%s\n", const_str);

	json_object_put(jobj);
}
