/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane test QoS library
 */

#ifndef __DP_TEST_QOS_LIB_H__
#define __DP_TEST_QOS_LIB_H__

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

#include "dp_test_json_utils.h"

/*
 * Note, the dataplane has changed to only accept protocol numbers. and
 * not strings
 */
#define QOS_PROTO_TCP		"proto=6"
#define QOS_PROTO_UDP		"proto=17"


struct tc_queue_pair {
	uint tc;
	uint queue;
	uint dp;
};

struct des_dp_pair {
	uint des;
	uint dp;
};

/*
 * Enable/disable QoS debugging in the dataplane
 */
void dp_test_qos_debug(bool enable);

/*
 * Send QoS op-mode request to the dataplane via the console. It failed if the
 * returned dataplane status is "ERROR".  If 'debug' is true, then print the
 * command before it is sent.
 */
void
_dp_test_qos_op_cmd(const char *cmd, bool debug, const char *file,
		    const int line);

#define dp_test_qos_op_cmd(cmd, debug)			    \
	_dp_test_qos_op_cmd(cmd, debug, __FILE__, __LINE__)

void
_dp_test_qos_op_cmd_fmt(bool debug, const char *file, const int line,
			const char *fmt_str, ...)
	__attribute__((__format__(printf, 4, 5)));

#define dp_test_qos_op_cmd_fmt(debug, fmt_str, ...)	   \
	_dp_test_qos_op_cmd_fmt(debug, __FILE__, __LINE__, \
				fmt_str, ##__VA_ARGS__)

void
dp_test_qos_json_dump(json_object *j_obj);

void
dp_test_qos_show(void);

void
dp_test_qos_ingress_maps_show(void);
/*
 * Functions that handle the JSON output from "qos show"
 */
#define dp_test_qos_get_json(key, key_size, debug)			\
	_dp_test_qos_get_json(key, key_size, __func__, debug, __FILE__, \
			      __LINE__)

json_object *
_dp_test_qos_get_json_shaper(const char *if_name, bool debug, const char *file,
			     const int line);

#define dp_test_qos_get_json_shaper(if_name, debug)                      \
	_dp_test_qos_get_json_shaper(if_name, debug, __FILE__, __LINE__)

bool
_dp_test_qos_get_json_shaper_no_fail(const char *if_name, bool debug,
				     const char *file, const int line);

#define dp_test_qos_get_json_shaper_no_fail(if_name, debug)            \
	_dp_test_qos_get_json_shaper_no_fail(if_name, debug, __FILE__, \
					     __LINE__)

json_object *
_dp_test_qos_get_json_subports(const char *if_name, bool debug,
			       const char *file, const int line);

#define dp_test_qos_get_json_subports(if_name, debug)                      \
	_dp_test_qos_get_json_subports(if_name, debug, __FILE__, __LINE__)

json_object *
_dp_test_qos_get_json_vlans(const char *if_name, bool debug, const char *file,
			    const int line);

#define dp_test_qos_get_json_vlans(if_name, debug)                      \
	_dp_test_qos_get_json_vlans(if_name, debug, __FILE__, __LINE__)

bool
_dp_test_qos_vlan_iterator(json_object *j_obj, void *arg);

bool
_dp_test_qos_get_json_vlan_subport(const char *if_name, const uint vlan,
				   int *subport_id, bool debug,
				   const char *file, const int line);

#define dp_test_qos_get_json_vlan_subport(if_name, vlan, subport, debug)  \
	_dp_test_qos_get_json_vlan_subport(if_name, vlan, subport, debug, \
					   __FILE__, __LINE__)

json_object *
_dp_test_qos_get_json_subport_tc(const char *if_name, const uint subport,
				 const uint tc, bool debug, const char *file,
				 const int line);

#define dp_test_qos_get_json_subport_tc(if_name, subport, tc, debug)  \
	_dp_test_qos_get_json_subport_tc(if_name, subport, tc, debug, \
					 __FILE__, __LINE__)

bool
_dp_test_qos_get_json_subport_tc_no_fail(const char *if_name,
					 const uint subport, const uint tc,
					 bool debug, const char *file,
					 const int line);

json_object *
_dp_test_qos_get_json_pipe(const char *if_name, const uint subport,
			   const uint pipe, bool debug, const char *file,
			   const int line);

#define dp_test_qos_get_json_pipe(if_name, subport, pipe, debug)  \
	_dp_test_qos_get_json_pipe(if_name, subport, pipe, debug, \
				   __FILE__, __LINE__)

json_object *
_dp_test_qos_get_json_params(const char *if_name, const uint subport,
			     const uint pipe, bool debug, const char *file,
			     const int line);

#define dp_test_qos_get_json_params(if_name, subport, pipe, debug)  \
	_dp_test_qos_get_json_params(if_name, subport, pipe, debug, \
				     __FILE__, __LINE__)

json_object *
_dp_test_qos_get_json_tc_rate(const char *if_name, const uint subport,
			      const uint pipe, const int tc, bool debug,
			      const char *file, const int line);

#define dp_test_qos_get_json_tc_rate(if_name, subport, pipe, tc, debug)  \
	_dp_test_qos_get_json_tc_rate(if_name, subport, pipe, tc, debug, \
				      __FILE__, __LINE__)

json_object *
_dp_test_qos_get_json_wrr_weight(const char *if_name, const uint subport,
				 const uint pipe, const int queue, bool debug,
				 const char *file, const int line);

#define dp_test_qos_get_json_wrr_weight(if_name, subport, pipe, queue, debug) \
	_dp_test_qos_get_json_wrr_weight(if_name, subport, pipe, queue,       \
					 debug, __FILE__, __LINE__)

json_object *
_dp_test_qos_get_json_dscp2q(const char *if_name, const uint subport,
			     const uint pipe, const int dscp, bool debug,
			     const char *file, const int line);

#define dp_test_qos_get_json_dscp2q(if_name, subport, pipe, dscp, debug) \
	_dp_test_qos_get_json_dscp2q(if_name, subport, pipe, dscp, debug, \
				     __FILE__, __LINE__)

json_object *
_dp_test_qos_get_json_pcp2q(const char *if_name, const uint subport,
			    const uint pipe, const int pcp, bool debug,
			    const char *file, const int line);

#define dp_test_qos_get_json_pcp2q(if_name, subport, pipe, pcp, debug)	\
	_dp_test_qos_get_json_pcp2q(if_name, subport, pipe, pcp, debug,	\
				    __FILE__, __LINE__)

json_object *
_dp_test_qos_get_json_pipe_tc(const char *if_name, const uint subport,
			      const uint pipe, const uint tc, bool debug,
			      const char *file, const int line);

#define dp_test_qos_get_json_pipe_tc(if_name, subport, pipe, tc, debug)  \
	_dp_test_qos_get_json_pipe_tc(if_name, subport, pipe, tc, debug, \
				      __FILE__, __LINE__)

json_object *
_dp_test_qos_get_json_array_element(json_object *j_array, uint index,
				    bool debug, const char *file,
				    const int line);

#define dp_test_qos_get_json_array_element(j_array, index, debug)            \
	_dp_test_qos_get_json_array_element(j_array, index, debug, __FILE__, \
					    __LINE__)

json_object *
_dp_test_qos_get_json_queue(const char *if_name, const uint subport,
			    const uint pipe, const uint tc, const uint queue,
			    bool debug, const char *file, const int line);

#define dp_test_qos_get_json_queue(if_name, subport, pipe, tc, queue, debug)  \
	_dp_test_qos_get_json_queue(if_name, subport, pipe, tc, queue, debug, \
				    __FILE__, __LINE__)

json_object *
_dp_test_qos_get_json_rules(const char *if_name, const uint subport,
			    bool debug, const char *file, const int line);

#define dp_test_qos_get_json_rules(if_name, subport, debug)  \
	_dp_test_qos_get_json_rules(if_name, subport, debug, \
				    __FILE__, __LINE__)

json_object *
_dp_test_qos_get_json_groups(const char *if_name, const uint subport,
			     bool debug, const char *file, const int line);

#define dp_test_qos_get_json_groups(if_name, subport, debug)  \
	_dp_test_qos_get_json_groups(if_name, subport, debug, \
				     __FILE__, __LINE__)

json_object *
_dp_test_qos_get_json_groups_rules(const char *if_name, const uint subport,
				   bool debug, const char *file,
				   const int line);

#define dp_test_qos_get_json_groups_rules(if_name, subport, debug)  \
	_dp_test_qos_get_json_groups_rules(if_name, subport, debug, \
					   __FILE__, __LINE__)

/*
 * Functions that handle the JSON output from "qos hw"
 */
void
dp_test_qos_hw(void);

#define dp_test_qos_hw_get_json(key, key_size, debug)			   \
	_dp_test_qos_hw_get_json(key, key_size, __func__, debug, __FILE__, \
				 __LINE__)

json_object *
_dp_test_qos_hw_get_json_sched_group(uint32_t level, const char *if_name,
				     uint32_t subport, uint32_t pipe,
				     uint32_t tc, bool debug, const char *file,
				     const int line);

#define dp_test_qos_hw_get_json_sched_group(level, if_name, subport, pipe, tc, \
					    debug)			       \
	_dp_test_qos_hw_get_json_sched_group(level, if_name, subport, pipe,    \
					     tc, debug,	__FILE__,  __LINE__)

json_object *
_dp_test_qos_hw_get_json_queue(const char *if_name, uint32_t subport,
			       uint32_t pipe, uint32_t tc, uint32_t queue,
			       bool debug, const char *file, const int line);

#define dp_test_qos_hw_get_json_queue(if_name, subport, pipe, tc, queue,  \
				      debug)				  \
	_dp_test_qos_hw_get_json_queue(if_name, subport, pipe, tc, queue, \
				       debug, __FILE__,  __LINE__)

json_object *
_dp_test_qos_hw_get_json_child(json_object *j_parent, const char *name,
			       bool debug, const char *file, const int line);

#define dp_test_qos_hw_get_json_child(j_parent, name, debug)		\
	_dp_test_qos_hw_get_json_child(j_parent, name, debug, __FILE__,	\
				       __LINE__)

void
_dp_test_qos_hw_check_sched_group(json_object *j_obj, int32_t level,
				  int32_t max_children,
				  int32_t current_children, uint8_t lpq,
				  bool debug, const char *file, const int line);

#define dp_test_qos_hw_check_sched_group(j_obj, level, max_children,	     \
					 current_children, lpq, debug)	     \
	_dp_test_qos_hw_check_sched_group(j_obj, level, max_children,	     \
					  current_children, lpq, debug,      \
					  __FILE__, __LINE__)

void
_dp_test_qos_hw_check_ingress_map(json_object *j_map_obj, int32_t map_type,
				  struct des_dp_pair *map_list,
				  bool debug,
				  const char *file, const int line);

#define dp_test_qos_hw_check_ingress_map(j_map_obj, map_type, map_list, debug)\
	_dp_test_qos_hw_check_ingress_map(j_map_obj, map_type, map_list,   \
					  debug, __FILE__, __LINE__)

void
_dp_test_qos_hw_check_egress_map(json_object *j_map_obj, int32_t map_type,
				 const uint8_t *map_list, bool debug,
				 const char *file, const int line);

#define dp_test_qos_hw_check_egress_map(j_map_obj, map_type, map_list, debug) \
	_dp_test_qos_hw_check_egress_map(j_map_obj, map_type, map_list,       \
					 debug, __FILE__, __LINE__)

void
_dp_test_qos_hw_check_scheduler(json_object *j_obj, const char *type,
				const char *meter_type, int32_t weight,
				int64_t max_bandwidth, int32_t max_burst,
				int8_t overhead, bool debug, const char *file,
				const int line);

#define dp_test_qos_hw_check_scheduler(j_obj, type, meter_type, weight,  \
				       max_bandwidth, max_burst, overhead, \
				       debug)  \
	_dp_test_qos_hw_check_scheduler(j_obj, type, meter_type, weight, \
					max_bandwidth, max_burst, overhead, \
					debug, __FILE__, __LINE__)

void
_dp_test_qos_hw_check_queue(json_object *j_obj, int32_t id,
			    int32_t queue_limit, int32_t queue_index,
			    uint8_t designation,
			    bool debug, const char *file, const int line);

#define dp_test_qos_hw_check_queue(j_obj, id, queue_limit, queue_index,  \
				   designation, debug)	 \
	_dp_test_qos_hw_check_queue(j_obj, id, queue_limit, queue_index, \
				    designation, debug,  \
				    __FILE__, __LINE__)

void
_dp_test_qos_hw_check_wred_colour(json_object *j_obj, const char *colour,
				  int32_t enabled, int32_t min_threshold,
				  int32_t max_threshold,
				  int32_t drop_probability,
				  int32_t filter_weight,
				  bool debug, const char *file, const int line);

#define dp_test_qos_hw_check_wred_colour(j_obj, colour, enabled,	   \
					 min_threshold,	max_threshold,	   \
					 drop_probability, filter_weight,  \
					 debug)				   \
	_dp_test_qos_hw_check_wred_colour(j_obj, colour, enabled,	   \
					  min_threshold, max_threshold,	   \
					  drop_probability, filter_weight, \
					  debug, __FILE__, __LINE__)

void
_dp_test_qos_check_mark_map(const char *map_name, int8_t *pcp_values,
			    bool debug, const char *file, const int line);

#define dp_test_qos_check_mark_map(map_name, pcp_values, debug)  \
	_dp_test_qos_check_mark_map(map_name, pcp_values, debug, \
				    __FILE__, __LINE__)
/*
 * QoS JSON object checking functions
 */
void
_dp_test_qos_check_counter(json_object *j_obj, const char *counter_name,
			   const int expected_value, bool debug,
			   const char *file, const int line);

void
_dp_test_qos_check_subport_tc_counter(const char *if_name, const uint subport,
				      const uint tc, const char *counter_name,
				      const int expected_value, bool debug,
				      const char *file, const int line);

#define dp_test_qos_check_subport_tc_counter(if_name, subport, tc,          \
					     counter_name,                  \
					     expected_value, debug)         \
	_dp_test_qos_check_subport_tc_counter(if_name, subport, tc,         \
					      counter_name, expected_value, \
					      debug, __FILE__, __LINE__)

void
_dp_test_qos_check_queue_counter(const char *if_name, const uint subport,
				 const uint pipe, const uint tc,
				 const uint queue, const char *counter_name,
				 const int expected_value, bool debug,
				 const char *file, const int line);

#define dp_test_qos_check_queue_counter(if_name, subport, pipe, tc, q,        \
					counter_name, expected_value, debug)  \
	_dp_test_qos_check_queue_counter(if_name, subport, pipe, tc, q,       \
					 counter_name, expected_value, debug, \
					 __FILE__, __LINE__)

bool
_dp_test_qos_counters_check_for_zero(json_object *j_counters, void *arg);

bool
_dp_test_qos_tc_q_check_for_zero(json_object *j_q, void *arg);

bool
_dp_test_qos_pipe_tc_check_for_zero(json_object *j_tc, void *arg);

bool
_dp_test_qos_pipes_check_for_zero(json_object *j_pipe, void *arg);

bool
_dp_test_qos_subport_check_for_zero(json_object *j_subport, void *arg);

void
_dp_test_qos_check_for_zero_counters(const char *if_name, bool debug,
				     const char *file, const int line);

#define dp_test_qos_check_for_zero_counters(if_name, debug)	 \
	_dp_test_qos_check_for_zero_counters(if_name, debug,	 \
					     __FILE__, __LINE__)

void
_dp_test_qos_check_rule(json_object *j_obj, const char *action,
			const char *config, const char *match,
			const char *operation, int bytes, int packets,
			bool debug,
			const char *file, const int line);

#define dp_test_qos_check_rule(j_obj, action, config, match, operation, bytes,\
			       packets, debug)          \
	_dp_test_qos_check_rule(j_obj, action, config, match, operation,      \
				bytes, packets, debug,  \
				__FILE__, __LINE__)

/*
 * Clear QoS counters for one or more interfaces
 *
 * e.g. dp_test_qos_clear_counters(NULL, true)
 *      dp_test_qos_clear_counters("dp0s5", true);
 *      dp_test_qos_clear_counters("dp0s5.30", false);
 */
void
_dp_test_qos_clear_counters(const char *if_name, bool debug,
			    const char *file, const int line);

#define dp_test_qos_clear_counters(if_name, debug)			\
	_dp_test_qos_clear_counters(if_name, debug, __FILE__, __LINE__)

/*
 * QoS configuration functions
 */
void
_dp_test_qos_delete_config_from_if(const char *if_name, bool debug,
				   const char *file, const int line);

#define dp_test_qos_delete_config_from_if(if_name, debug)	       \
	_dp_test_qos_delete_config_from_if(if_name, debug, __FILE__, __LINE__)

void
_dp_test_qos_attach_config_to_if(const char *if_name, const char *cmd_list[],
				 bool debug, const char *file, const int line);

#define dp_test_qos_attach_config_to_if(if_name, cmd_list, debug)  \
	_dp_test_qos_attach_config_to_if(if_name, cmd_list, debug, \
					 __FILE__, __LINE__)

void
_dp_test_qos_send_config(const char *cmd_list[],
		const char *expected_json_str,
		const char *verify_cmd, int num_cmds,
		bool debug, const char *file, const int line);

#define dp_test_qos_send_config(cmd_list, exp_json_str, verify_cmd, \
		num_cmds, debug)  \
		_dp_test_qos_send_config(cmd_list, exp_json_str, verify_cmd, \
				num_cmds, debug, __FILE__, __LINE__)


void _dp_test_qos_verify_config(const char *expected_json_str,
		const char *verify_cmd,
		bool negate_match, bool debug);

void
_dp_test_qos_send_cmd(const char *cmd,
		const char *expected_cmd_str,
		const char *verify_cmd,
		bool debug,
		const char *file, const int line);

#define dp_test_qos_send_cmd(cmd, exp_json_str, verify_cmd,  \
		debug)  \
		_dp_test_qos_send_cmd(cmd, exp_json_str,  \
				verify_cmd,  \
				debug, __FILE__, __LINE__)

void
_dp_test_qos_send_if_cmd(const char *if_name, const char *cmd, bool debug,
		      const char *file, const int line);

#define dp_test_qos_send_if_cmd(if_name, cmd, debug)  \
	_dp_test_qos_send_if_cmd(if_name, cmd, debug, __FILE__, __LINE__)

/*
 * QoS packet test functions
 */
void
_dp_test_qos_pkt_forw_test(const char *ifname, const uint vlan_id,
			   const char *l3_src, const char *l3_dst,
			   const uint dscp, const uint subport, const uint pipe,
			   const uint tc, const uint queue, bool debug,
			   const char *file, const int line);

#define dp_test_qos_pkt_forw_test(ifname, vlan_id, l3src, l3_dst, dscp,  \
				  subport, pipe, tc, queue, debug)	 \
	_dp_test_qos_pkt_forw_test(ifname, vlan_id, l3src, l3_dst, dscp, \
				   subport, pipe, tc, queue, debug,      \
				   __FILE__,  __LINE__)

void
_dp_test_qos_pkt_remark_test(const char *ifname, const uint vlan_id,
			     const char *l3_src, const char *l3_dst,
			     const uint dscp, const uint remark,
			     const uint subport, const uint pipe, const uint tc,
			     const uint queue, bool debug, const char *file,
			     const int line);

#define dp_test_qos_pkt_remark_test(ifname, vlan_id, l3src, l3_dst, dscp,     \
				    remark, subport, pipe, tc, queue, debug)  \
	_dp_test_qos_pkt_remark_test(ifname, vlan_id, l3src, l3_dst, dscp,    \
				     remark, subport, pipe, tc, queue, debug, \
				     __FILE__, __LINE__)

void
_dp_test_qos_pkt_force_drop(const char *ifname, const uint vlan_id,
			    const char *l3_src, const char *l3_dst,
			    const uint dscp, const uint queue_limit,
			    const uint subport, const uint pipe, const uint tc,
			    const uint queue, bool debug, const char *file,
			    const int line);

#define dp_test_qos_pkt_force_drop(ifname, vlan_id, l3src, l3_dst, dscp,   \
				   queue_limit, subport, pipe, tc, queue,  \
				   debug)				   \
	_dp_test_qos_pkt_force_drop(ifname, vlan_id, l3src, l3_dst, dscp,  \
				    queue_limit, subport, pipe, tc, queue, \
				    debug, __FILE__, __LINE__)

/*
 * Helper functions
 */
void qos_lib_test_setup(void);

void qos_lib_test_teardown(void);

#endif
