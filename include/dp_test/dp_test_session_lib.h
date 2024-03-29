/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * session UT test lib
 */

#ifndef __DP_TEST_SESSION_LIB_H__
#define __DP_TEST_SESSION_LIB_H__

#define DP_TEST_MAX_TEST_SESSIONS 5
#define DP_TEST_MAX_PKTS_PER_SESSION 20

/**
 * Used to keep a list of sessions
 */
struct dp_test_session {
	uint64_t se_id; /**< session_id retrieved from packed session */
	bool completed; /**< Is the received packed message complete */
};

void *_dp_test_session_msg_unpack_pb(void *buf, uint32_t size,
				  const char *file, int line);
#define dp_test_session_msg_unpack_pb(buf, size) \
	_dp_test_session_msg_unpack_pb(buf, size, __FILE__, __LINE__)


void _dp_test_session_msg_free_unpack_pb(void *buf, const char *file, int line);
#define dp_test_session_msg_free_unpack_pb(buf) \
	_dp_test_session_msg_free_unpack_pb(buf, __FILE__, __LINE__)

void _dp_test_session_msg_valid(void *msg, uint32_t size,
				const char *file, int line);
#define dp_test_session_msg_valid(msg, size)     \
	_dp_test_session_msg_valid(msg, size, __FILE__, __LINE__)

uint64_t _dp_test_session_msg_get_id(void *msg, const char *file, int line);
#define dp_test_session_msg_get_id(msg)	\
	_dp_test_session_msg_get_id(msg, __FILE__, __LINE__)

void _dp_test_session_msg_check_rcvd(void *msg,
				     uint64_t pkts_per_session,
				     struct dp_test_session sess[],
				     const char *file, int line);
#define dp_test_session_msg_check_rcvd(msg, pkts_per_session, sess)	\
	_dp_test_session_msg_check_rcvd(msg, pkts_per_session,	sess,	\
						__FILE__, __LINE__)

bool _dp_test_session_msg_pulled_all(void *msg,
				     uint64_t pkts_per_session,
				     struct dp_test_session sess[],
				     const char *file, int line);
#define dp_test_session_msg_pulled_all(msg, pkts_per_session, sess) \
	_dp_test_session_msg_pulled_all(msg, pkts_per_session,	\
						sess, __FILE__, __LINE__)


/* Count and clear sessions */

#define SC_WARN_ONLY	true
#define SC_FAIL		false

/*
 * sessions flags - verify the presence/absence of a session.
 */
#define SE_ACTIVE	0x0004
#define SE_PASS		0x0008
#define SE_EXPIRE	0x0010
#define SE_GC_PASS_TWO	0x0020
#define SE_BYPASS	0x0040

#define SE_FLAGS_MASK (SE_ACTIVE | SE_PASS | SE_EXPIRE | SE_BYPASS)
#define SE_FLAGS_AE (SE_ACTIVE | SE_EXPIRE)

/* Clear all npf sessions.  */
void
dp_test_sessions_clear(void);

/**
 * Verify the presence/absence of a session
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
 * @param state      [in] true if we expect to find the session
 *
 * @return true if found
 **/
bool _dp_test_session_verify(char *desc,
				 const char *saddr, uint16_t src_id,
				 const char *daddr, uint16_t dst_id,
				 uint8_t proto,
				 const char *intf,
				 uint32_t exp_flags, uint32_t flags_mask,
				 bool exists, const char *file, int line);

#define dp_test_session_verify(desc, saddr, src_id, daddr, dst_id, proto, \
				   intf, flgs, msk, exists)		\
	_dp_test_session_verify(desc, saddr, src_id, daddr, dst_id, \
				    proto, intf, flgs, msk, exists,	\
				    __FILE__, __LINE__)

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
 * @param pkts_in    [in] expected count, as an int due to json limitations
 * @param bytes_in   [in] expected count, as an int due to json limitations
 * @param pkts_out   [in] expected count, as an int due to json limitations
 * @param bytes_out  [in] expected count, as an int due to json limitations
 *
 * @return true if found
 */
void _dp_test_session_verify_count(char *desc,
				       const char *saddr, uint16_t src_id,
				       const char *daddr, uint16_t dst_id,
				       uint8_t proto,
				       const char *intf,
				       uint32_t exp_flags, uint32_t flags_mask,
				       int pkts_in, int bytes_in,
				       int pkts_out, int bytes_out,
				       const char *file, int line);

#define dp_test_session_verify_count(desc, saddr, src_id, daddr, dst_id, \
					 proto, intf, flgs, msk,	\
					 pkts_in, bytes_in, pkts_out,	\
					 bytes_out)			\
	_dp_test_session_verify_count(desc, saddr, src_id, daddr, dst_id, \
					  proto, intf, flgs, msk,	\
					  pkts_in, bytes_in, pkts_out,	\
					  bytes_out,			\
					  __FILE__, __LINE__)

/*
 * Verify the global session count
 */
void
_dp_test_session_count_verify(uint exp_count, bool warn,
				  const char *file, const char *func, int line);

#define dp_test_session_count_verify(count)				\
	_dp_test_session_count_verify(count, SC_FAIL,		\
					  __FILE__, __func__, __LINE__)

/*
 * Verify the global UDP session count
 */
void
_dp_test_session_udp_count_verify(uint exp_count, bool warn,
				  const char *file, int line);

#define dp_test_session_udp_count_verify(count)				\
	_dp_test_session_udp_count_verify(count, SC_FAIL,		\
					  __FILE__, __LINE__)

/*
 * Return counters for one session.  Session filter should be fully specified,
 * e.g.
 *
 * uint32_t pkts_in = 0, pkts_out = 0;
 * uint32_t bytes_in = 0, bytes_out = 0;
 * uint32_t sess_id = 0;
 *
 * dp_test_session_counters("start 0 count 1 "
 *			"src-addr 192.0.2.103 src-port 10000 "
 *			"dst-addr 203.0.113.203 dst-port 60000 "
 *			"proto 17 dir out intf dpT21",
 *                      &pkts_in, &pkts_out, &bytes_in, &bytes_out,
 *                      &sess_id);
 */
int dp_test_session_counters(const char *options,
			 uint32_t *pkts_in, uint32_t *pkts_out,
			 uint32_t *bytes_in, uint32_t *bytes_out,
			 uint32_t *sess_id);

#endif /* DP_TEST_SESSION_LIB_H */
