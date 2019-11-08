/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane test npf session library
 */

#ifndef __DP_TEST_NPF_SESS_LIB_H__
#define __DP_TEST_NPF_SESS_LIB_H__

#include <stdint.h>
#include <stdbool.h>
#include <json-c/json.h>
#include "dp_test_lib_pkt.h"
#include "dp_test_npf_lib.h"

#define SC_WARN_ONLY true
#define SC_FAIL	     false

/*
 * Verify the npf global session count
 */
void
_dp_test_npf_session_count_verify(uint exp_count, bool warn,
				  const char *file, int line);

#define dp_test_npf_session_count_verify(count)			 \
	_dp_test_npf_session_count_verify(count, SC_FAIL,	 \
					  __FILE__, __LINE__)

/*
 * Verify the npf global TCP session count
 */
void
_dp_test_npf_tcp_session_count_verify(uint exp_count, bool warn,
				      const char *file, int line);

#define dp_test_npf_tcp_session_count_verify(count)		     \
	_dp_test_npf_tcp_session_count_verify(count, SC_FAIL,   \
					      __FILE__, __LINE__)

/*
 * Verify the npf global UDP session count
 */
void
_dp_test_npf_udp_session_count_verify(uint exp_count, bool warn,
				      const char *file, int line);

#define dp_test_npf_udp_session_count_verify(count)		     \
	_dp_test_npf_udp_session_count_verify(count, SC_FAIL,   \
					      __FILE__, __LINE__)

/*
 * Verify the npf NAT session count
 */
void
_dp_test_npf_nat_session_count_verify(uint exp_count, bool warn,
				      const char *file, int line);

#define dp_test_npf_nat_session_count_verify(count)		     \
	_dp_test_npf_nat_session_count_verify(count, SC_FAIL,   \
					      __FILE__, __LINE__)

/* Clear all npf sessions.  */
void
dp_test_npf_clear_sessions(void);

/* Expire active sessions */
void
dp_test_npf_expire_sessions(void);


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
				      uint16_t *src_id, uint16_t *dst_id);

/*
 * Verify the presence/absence of an npf session. Source/dest addresses, ports
 * and protocol are taken from a packet template
 */
#define	SE_ACTIVE		0x0004
#define	SE_PASS			0x0008
#define	SE_EXPIRE		0x0010
#define	SE_GC_PASS_TWO		0x0020
#define	SE_BYPASS		0x0040

#define SE_FLAGS_MASK (SE_ACTIVE | SE_PASS | SE_EXPIRE | SE_BYPASS)
#define SE_FLAGS_AE (SE_ACTIVE | SE_EXPIRE)

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
 * @param state      [in] true if we expect to find the session
 *
 * @return true if found
 **/
bool _dp_test_npf_session_verify(char *desc,
				 const char *saddr, uint16_t src_id,
				 const char *daddr, uint16_t dst_id,
				 uint8_t proto,
				 const char *intf,
				 uint32_t exp_flags, uint32_t flags_mask,
				 bool exists, const char *file, int line);

#define dp_test_npf_session_verify(desc, saddr, src_id, daddr, dst_id, proto, \
				   intf, flgs, msk, exists)		\
	_dp_test_npf_session_verify(desc, saddr, src_id, daddr, dst_id, \
				    proto, intf, flgs, msk, exists,	\
				    __FILE__, __LINE__)

/**
 * Verify the presence/absence of an npf session.  The 5-tuple is derived from
 * a packet descriptor.
 *
 * @param desc       [in] Optional text to be prepended to any error message
 * @param pkt        [in] Unit-test packet descriptor
 * @param intf       [in] Interface string, e.g. "dp2T1"
 * @param exp_flags  [in] Expected flags, e.g. SE_ACTIVE | SE_PASS
 * @param flags_mask [in] Flags mask, e.g. SE_FLAGS_MASK
 * @param exists     [in] true if we expect to find the session
 *
 * @return true if found
 **/
bool
_dp_test_npf_session_verify_desc(char *text,
				 struct dp_test_pkt_desc_t *pkt,
				 const char *intf, uint32_t exp_flags,
				 uint32_t flags_mask, bool exists,
				 const char *file, int line);

#define dp_test_npf_session_verify_desc(text, pkt, intf, flgs, msk, exists) \
	_dp_test_npf_session_verify_desc(text, pkt, intf, flgs, msk, exists, \
					__FILE__, __LINE__)

#define TRANS_TYPE_NATIN  1
#define TRANS_TYPE_NATOUT 2

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
 * @param exists     [in] true if we expect to find the session
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
				const char *ddt_addr, uint16_t dst_id,
				uint8_t proto,
				const char *trans_addr, uint16_t trans_port,
				int trans_type,
				const char *intf,
				uint32_t exp_flags, uint32_t flags_mask,
				bool exists,
				char *str, int strlen,
				const char *file, int line);

#define dp_test_npf_nat_session_verify(desc, saddr, sport, daddr, dport, \
				       proto, taddr, tport, ttype,	\
				       intf, flgs, msk, exists)		\
	_dp_test_npf_nat_session_verify(desc, saddr, sport, daddr, dport, \
					proto, taddr, tport, ttype, intf, \
					flgs, msk, exists, NULL, 0,	\
					__FILE__, __LINE__)

#define dp_test_npf_nat_session_check(desc, saddr, sport, daddr, dport, \
				      proto, taddr, tport, ttype,	\
				      intf, flgs, msk, exists, str, strlen) \
	_dp_test_npf_nat_session_verify(desc, saddr, sport, daddr, dport, \
					proto, taddr, tport, ttype, intf, \
					flgs, msk, exists, str, strlen,	\
					NULL, 0)

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
				 const char *file, int line);

#define dp_test_nat_session_verify_desc(snat, flags, pre, post)	 \
	_dp_test_nat_session_verify_desc(snat, flags, pre, post, \
					 __FILE__, __LINE__)


/*
 * Get the count of all npf sessions
 */
bool
dp_test_npf_session_count(uint *count);

/*
 * Get the number of NAT sessions
 */
bool
dp_test_npf_nat_session_count(uint *count);

/*
 * Get the number of UDP sessions
 */
bool
dp_test_npf_udp_session_count(uint *count);

/*
 * Get the number of TCP sessions
 */
bool
dp_test_npf_tcp_session_count(uint *count);

/*
 * Get the number of non-UDP/TCP sessions
 */
bool
dp_test_npf_other_session_count(uint *count);

/*
 * Iterate over all npf fw or nat sessions.  Callback function may return true
 * to terminate the iteration, in which case the current session is returned
 * to the caller
 */
typedef bool (*dp_test_npf_json_session_cb)(json_object *jvalue, void *arg);

json_object *
dp_test_npf_json_fw_session_iterate(dp_test_npf_json_session_cb cb,
				    void *arg, unsigned int *index);

json_object *
dp_test_npf_json_nat_session_iterate(dp_test_npf_json_session_cb cb,
				     void *arg, unsigned int *index);

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
			     uint8_t proto, const char *intf,
			     uint32_t flags, uint32_t flags_mask,
			     unsigned int *index);

json_object *
dp_test_npf_json_get_nat_session(const char *saddr, uint16_t src_id,
				 const char *daddr, uint16_t dst_id,
				 const char *taddr, uint16_t tport,
				 uint8_t proto, const char *intf,
				 uint32_t flags, uint32_t flags_mask,
				 uint16_t trans_type, unsigned int *index);

/*
 * NPF instance ID
 *
 * VRF aware json objects will contain an instance array, where each array
 * element is identified by an "npf_id" integer field.
 */

/*
 * Find a specific instance in a json array
 */
json_object *
dp_test_npf_json_array_get_instance(json_object *jarray, uint npf_id);

/*
 * Return the protocol-specific state for a session.  Returns true if the
 * session was found.
 */
bool
dp_test_npf_session_state(const char *saddr, uint16_t src_id,
			  const char *daddr, uint16_t dst_id,
			  uint8_t proto, const char *intf,
			  uint *state);

/*
 * Get string from protocol and state
 */
const char *dp_test_npf_sess_state_str(uint8_t proto, uint state);

void dp_test_npf_print_session(const char *saddr, uint16_t src_id,
			       const char *daddr, uint16_t dst_id,
			       uint8_t proto, const char *intf);

/*
 * List all session table entries in prettied json format
 */
void dp_test_npf_print_session_table(bool nat);

#endif
