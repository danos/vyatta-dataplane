/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef DP_TEST_PPP_H
#define DP_TEST_PPP_H

struct rte_mbuf;

#define CREATE true
#define NO_CREATE false
#define VERIFY true
#define NO_VERIFY false
#define SESS_VALID true
#define SESS_INVALID false

void
_dp_test_create_pppoe_session(const char *ppp_intf, const char *under_intf,
			      uint16_t session_id, const char *src_mac,
			      const char *dst_mac, bool create, bool verify,
			      bool valid,
			      const char *file, const char *func, int line);

#define dp_test_create_pppoe_session(ppp_intf, under_intf, session_id, \
				     src_mac, dst_mac)		       \
	_dp_test_create_pppoe_session(ppp_intf, under_intf, session_id,	\
				      src_mac, dst_mac, CREATE,		\
				      VERIFY, SESS_VALID,		\
				      __FILE__, __func__, __LINE__)

#define dp_test_create_pppoe_session_nv(ppp_intf, under_intf, session_id, \
					src_mac, dst_mac)		\
	_dp_test_create_pppoe_session(ppp_intf, under_intf, session_id,	\
				      src_mac, dst_mac, CREATE,		\
				      NO_VERIFY, SESS_VALID,		\
				      __FILE__, __func__, __LINE__)

#define dp_test_verify_pppoe_session(ppp_intf, under_intf, session_id, \
				     src_mac, dst_mac, valid)		\
	_dp_test_create_pppoe_session(ppp_intf, under_intf, session_id,	\
				      src_mac, dst_mac, NO_CREATE,	\
				      VERIFY, valid,			\
				      __FILE__, __func__, __LINE__)


struct pppoe_packet *
dp_test_ipv4_pktmbuf_ppp_prepend(struct rte_mbuf *m,
				 const char *dst_mac,
				 const char *src_mac,
				 int v4_len,
				 uint16_t session);

#endif /* DP_TEST_PPP_H */
