/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Check dataplane internal state using operational commands
 */
#ifndef _DP_TEST_CMD_CHECK_H_
#define _DP_TEST_CMD_CHECK_H_

#include <stdbool.h>
#include <json-c/json.h>
#include <regex.h>

#include "../vrf.h"
#include "dp_test_lib.h"

#define DP_TEST_POLL_INTERVAL 1 /* ms */
#define DP_TEST_POLL_TOTAL_TIME 2000 /* ms */
#define DP_TEST_POLL_COUNT (DP_TEST_POLL_TOTAL_TIME / DP_TEST_POLL_INTERVAL)

#define DP_TEST_WAIT_SEC_DEFAULT 1

extern uint32_t dp_test_wait_sec;

#define TEST_MAX_CMD_LEN    1000
#define TEST_MAX_REPLY_LEN  10000

/* String to be used to store errors when parsing json */
extern char parse_err_str[10000];

typedef enum dp_test_check_str_type_ {
	DP_TEST_CHECK_STR_SUBSET,
	DP_TEST_CHECK_STR_EXACT,
} dp_test_check_str_type;

struct dp_test_cmd_check {
	const char *cmd;
	const char *expected;
	char *actual;
	bool exp_err;
	bool negate_match;
	bool print;
	bool result;
	dp_test_check_str_type type;
	int poll_cnt;
	regex_t regex; /* compiled regular expression */
};

unsigned int dp_test_default_vrf_clean_count(void);

void dp_test_wait_set(uint8_t wait_sec);

void
_dp_test_check_state_poll_show(const char *file, int line,
			  const char *cmd, const char *expected,
			  bool exp_ok, bool print, int poll_cnt,
			  dp_test_check_str_type type);
#define dp_test_check_state_poll_show(cmd, expected, exp_ok, print, poll_cnt) \
	_dp_test_check_state_poll_show(__FILE__, __LINE__, cmd, expected, \
				exp_ok, print, poll_cnt,		  \
				DP_TEST_CHECK_STR_SUBSET)

void
_dp_test_check_state_show(const char *file, int line, const char *cmd,
			  const char *expected, bool print,
			  dp_test_check_str_type type);
#define dp_test_check_state_show(cmd, expected, print) \
	_dp_test_check_state_show(__FILE__, __LINE__, cmd, expected, \
				  print, DP_TEST_CHECK_STR_SUBSET)

void
_dp_test_check_state_gone_show(const char *file, int line, const char *cmd,
			       const char *expected, bool print,
			       dp_test_check_str_type type);
#define dp_test_check_state_gone_show(cmd, expected, print) \
	_dp_test_check_state_gone_show(__FILE__, __LINE__, cmd, expected, \
				       print, DP_TEST_CHECK_STR_SUBSET)

void
_dp_test_check_state_clean(const char *file, int line, bool print);
#define dp_test_check_state_clean(print) \
	_dp_test_check_state_clean(__FILE__, __LINE__, print)


json_object *dp_test_json_create(const char *fmt_str, ...)
	__attribute__ ((__format__(printf, 1, 2)));

enum dp_test_check_json_mode {
	DP_TEST_JSON_CHECK_SUBSET,
	DP_TEST_JSON_CHECK_EXACT,
	DP_TEST_JSON_CHECK_SUPERSET,
};

void
_dp_test_check_json_poll_state(const char *cmd_str,
			       json_object *expected_json,
			       json_object *filter_json,
			       enum dp_test_check_json_mode mode,
			       bool negate_match, int poll_cnt,
			       const char *file, const char *func, int line);
#define dp_test_check_json_poll_state(cmd, expected, mode, gone, poll_cnt) \
	_dp_test_check_json_poll_state(cmd, expected, NULL, mode,	   \
				       gone, poll_cnt,			   \
				       __FILE__, __func__, __LINE__)

void
_dp_test_check_json_poll_state_interval(const char *cmd_str,
					json_object * expected_json,
					json_object * filter_json,
					enum dp_test_check_json_mode mode,
					bool negate_match, int poll_cnt,
					unsigned int poll_interval,
					const char *file, const char *func,
					int line);
#define dp_test_check_json_poll_state_interval(cmd, expected, mode, gone, \
					       poll_cnt, poll_interval)   \
	_dp_test_check_json_poll_state_interval(cmd, expected, NULL, mode, \
						gone, poll_cnt, poll_interval, \
						__FILE__, __func__, __LINE__)

typedef bool (*dp_test_state_pb_cb)(void *data, int len, void *arg);

void
_dp_test_check_pb_poll_state(char *cmd, int len,
			     dp_test_state_pb_cb cb,
			     void *arg,
			     int poll_cnt,
			     const char *file, const char *func, int line);
#define dp_test_check_pb_poll_state(cmd, len, cb, arg, gone, poll_cnt) \
	_dp_test_check_pb_poll_state(cmd, len, cb, arg,		\
				       gone, poll_cnt,			   \
				       __FILE__, __func__, __LINE__)

void
_dp_test_check_json_state(const char *cmd_str, json_object *expected_json,
			  json_object *filter_json,
			  enum dp_test_check_json_mode mode,
			  bool negate_match,
			  const char *file, const char *func,
			  int line);
#define dp_test_check_json_state(cmd_str, expected_json, mode, gone)	\
	_dp_test_check_json_state(cmd_str, expected_json, NULL, mode,	\
				  gone, __FILE__, __func__, __LINE__)

void
_dp_test_check_pb_state(char *buf, int len,
			     dp_test_state_pb_cb cb,
			     void *arg,
			     const char *file, const char *func,
			     int line);
#define dp_test_check_pb_state(buf, len, cb, arg) \
	_dp_test_check_pb_state(buf, len, cb, arg, \
				  __FILE__, __func__, __LINE__)

void _dp_test_wait_for_route(const char *route_string, bool match_nh, bool all,
			     const char *file, const char *func, int line);
#define dp_test_wait_for_route(route_string, match_nh)		\
	_dp_test_wait_for_route(route_string, match_nh, false,	\
				__FILE__, __func__, __LINE__)

void dp_test_wait_for_route_gone(const char *route_string, bool match_nh,
				 const char *file, const char *func, int line);

#define dp_test_wait_for_route_lookup(route_string, match_nh)		\
	_dp_test_wait_for_route_lookup(route_string, match_nh,		\
				       __FILE__, __func__, __LINE__)
void
_dp_test_wait_for_route_lookup(const char *route_string, bool match_nh,
			       const char *file, const char *func, int line);

void
_dp_test_lookup_nh(const struct dp_test_addr *ip_dst, uint32_t vrf_id,
		   char *ip_nh, size_t ip_nh_sz,
		   const char *file, const char *func, int line);
#define dp_test_lookup_nh(ip_dst, vrf_id, ip_nh, ip_nh_sz) \
	_dp_test_lookup_nh(ip_dst, vrf_id, ip_nh, ip_nh_sz, \
			   __FILE__, __func__, __LINE__)
void
_dp_test_lookup_neigh(const struct dp_test_addr *ip_nh, const char *ifname,
		      char *mac_str, size_t mac_str_sz,
		      const char *file, const char *func, int line);
#define dp_test_lookup_neigh(ip_nh, ifname, mac_str, mac_str_sz) \
	_dp_test_lookup_neigh(ip_nh, ifname, mac_str, mac_str_sz, \
			      __FILE__, __func__, __LINE__)

json_object *dp_test_json_intf_set_create(void);
json_object *dp_test_json_route_set_create(bool lookup, int family);

json_object *dp_test_json_intf_add(json_object *intf_set, const char *ifname,
				   const char *addr_prefix, bool uplink);
json_object *dp_test_json_intf_add_lo(json_object *intf_set,
				      const char *ifname);
json_object *dp_test_json_route_add(json_object *route_set,
				    const struct dp_test_route *route,
				    bool lookup);
void dp_test_json_route_add_nh(json_object *route_show, int route_family,
			       struct dp_test_nh *nh);
void dp_test_set_expected_ifconfig(json_object *intf_set);
void dp_test_set_expected_route(json_object *route_set);
void dp_test_set_expected_npf_fw_portmap(void);
void dp_test_set_expected_vrf(void);
void dp_test_set_expected_route_stats(void);
#define dp_test_wait_for_vrf(vrf_id, expected_refcount)		\
	_dp_test_wait_for_vrf(vrf_id, expected_refcount,	\
			      __FILE__, __func__, __LINE__)
#define dp_test_wait_for_vrf_gone(vrf_id)			\
	_dp_test_wait_for_vrf(vrf_id, 0,			\
			      __FILE__, __func__, __LINE__)
void
_dp_test_wait_for_vrf(uint32_t vrf_id, unsigned int expected_refcount,
		      const char *file, const char *func, int line);

#define dp_test_wait_for_local_addr(expected_addr, vrf_id)		\
	_dp_test_wait_for_local_addr(expected_addr, vrf_id, false,	\
				     __FILE__, __func__, __LINE__)
#define dp_test_wait_for_local_addr_gone(expected_addr, vrf_id)		\
	_dp_test_wait_for_local_addr(expected_addr, vrf_id, false,	\
				     __FILE__, __func__, __LINE__)
void
_dp_test_wait_for_local_addr(const char *addr_str, uint32_t vrf_id,
			     bool gone, const char *file, const char *func,
			     int line);

extern char expected_npf_fw_portmap_str[];

void
_dp_test_wait_for_pl_feat(const char *intf, const char *feature, const
			  char *feature_point, bool gone,
			  const char *file, const char *func, int line);

#define dp_test_wait_for_pl_feat(intf, feature, feature_point)		\
	_dp_test_wait_for_pl_feat(intf, feature, feature_point, false,	\
				  __FILE__, __func__, __LINE__)
#define dp_test_wait_for_pl_feat_gone(intf, feature, feature_point)	\
	_dp_test_wait_for_pl_feat(intf, feature, feature_point, true,	\
				  __FILE__, __func__, __LINE__)

void _dp_test_verify_neigh_present_count(int count, int af, const char *file,
					 const char *func, int line);
#define dp_test_verify_neigh_present_count(count) \
	_dp_test_verify_neigh_present_count(count, AF_INET,  __FILE__, \
					    __func__, __LINE__)
#define dp_test_verify_neigh6_present_count(count) \
	_dp_test_verify_neigh_present_count(count, AF_INET6,  __FILE__, \
					    __func__, __LINE__)

void _dp_test_verify_route_no_neigh_present(const char *route,
					    const char *file,
					    const char *func, int line);
#define dp_test_verify_route_no_neigh_present(route)  \
	_dp_test_verify_route_no_neigh_present(route,			\
					    __FILE__, __func__, __LINE__)

void _dp_test_verify_route_neigh_present(const char *route, const char *ifp,
					 bool set, const char *file,
					 const char *func, int line);
#define dp_test_verify_route_neigh_present(route, interface, set)  \
	_dp_test_verify_route_neigh_present(route, interface, set, \
					    __FILE__, __func__, __LINE__)

void _dp_test_verify_neigh_created_count(int count, int af, const char *file,
					 const char *func, int line);
#define dp_test_verify_neigh_created_count(count) \
	_dp_test_verify_neigh_created_count(count, AF_INET, __FILE__, \
					    __func__, __LINE__)
#define dp_test_verify_neigh6_created_count(count) \
	_dp_test_verify_neigh_created_count(count, AF_INET6, __FILE__, \
					    __func__, __LINE__)

void _dp_test_verify_route_no_neigh_created(const char *route,
					    const char *file,
					    const char *func, int line);
#define dp_test_verify_route_no_neigh_created(route)  \
	_dp_test_verify_route_no_neigh_created(route, \
					       __FILE__, __func__, __LINE__)

void _dp_test_verify_route_neigh_created(const char *route, const char *ifp,
					 bool set, const char *file,
					 const char *func, int line);
#define dp_test_verify_route_neigh_created(route, interface, set)  \
	_dp_test_verify_route_neigh_created(route, interface, set, \
					    __FILE__, __func__, __LINE__)

int _dp_test_get_nh_idx(const char *route, const char *file,
			const char *func, int line);
#define dp_test_get_nh_idx(route)  \
	_dp_test_get_nh_idx(route, __FILE__, __func__, __LINE__)

int _dp_test_get_vrf_stat(vrfid_t vrfid, int af, int stat,
			  const char *file, int line);
#define dp_test_get_vrf_stat(vrfid, af, stat) \
	_dp_test_get_vrf_stat(vrfid, af, stat, __FILE__, __LINE__)

#endif /* _DP_TEST_CMD_CHECK_H_ */
