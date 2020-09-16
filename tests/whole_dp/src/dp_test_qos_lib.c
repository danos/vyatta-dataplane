/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane test qos library
 */

#include <libmnl/libmnl.h>
#include <string.h>
#include <unistd.h>
#include <czmq.h>
#include <rte_log.h>
#include <rte_sched.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "fal_plugin.h"

#include "dp_test.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_console.h"
#include "dp_test_controller.h"
#include "dp_test_json_utils.h"

#include "dp_test_qos_lib.h"

static bool dp_test_qos_debug_state;

/*
 * Enable/disable QoS debugging in the dataplane
 */
void dp_test_qos_debug(bool enable)
{
	char cmd[TEST_MAX_CMD_LEN];

	if (enable != dp_test_qos_debug_state) {
		snprintf(cmd, TEST_MAX_CMD_LEN, "debug %sqos", enable ? "":"-");
		dp_test_console_request_reply(cmd, false);

		snprintf(cmd, TEST_MAX_CMD_LEN, "debug %sqos_hw",
							enable ? "":"-");
		dp_test_console_request_reply(cmd, false);

		rte_log_set_level(RTE_LOGTYPE_SCHED,
				  enable ? RTE_LOG_DEBUG : RTE_LOG_INFO);

		dp_test_qos_debug_state = enable;
	}
}

/*
 * Issue qos command to dataplane
 */
void
_dp_test_qos_op_cmd(const char *cmd, bool debug, const char *file,
		    const int line)
{
	char *reply;
	bool err;

	reply = dp_test_console_request_w_err(cmd, &err, debug);

	/*
	 * Returned string for qos commands is just an empty string, which is
	 * of no interest
	 */
	free(reply);

	_dp_test_fail_unless(!err, file, line,
			     "qos cmd failed: \"%s\"", cmd);
}

void
_dp_test_qos_op_cmd_fmt(bool debug, const char *file, const int line,
			const char *fmt_str, ...)
{
	char cmd[TEST_MAX_CMD_LEN];
	va_list ap;

	va_start(ap, fmt_str);
	vsnprintf(cmd, TEST_MAX_CMD_LEN, fmt_str, ap);
	_dp_test_qos_op_cmd(cmd, debug, file, line);
	va_end(ap);
}

void
dp_test_qos_json_dump(json_object *j_obj)
{
	const char *str;

	str = json_object_to_json_string_ext(j_obj,
					     JSON_C_TO_STRING_PRETTY);
	if (str)
		printf("%s\n", str);
}

__attribute__((format(printf, 5, 6)))
static void
_dp_test_qos_json_error(bool debug, const char *file, const int line,
			json_object *j_obj, const char *format, ...)
{
	char err_str[DP_TEST_TMP_BUF];
	va_list ap;

	if (debug)
		dp_test_qos_json_dump(j_obj);

	va_start(ap, format);
	vsnprintf(err_str, sizeof(err_str), format, ap);
	va_end(ap);
	printf("%s\n", err_str);

	_dp_test_fail(file, line, "qos-test failed\n");
	json_object_put(j_obj);
}

static json_object *
_dp_test_qos_get_json(struct dp_test_json_search_key *key, uint32_t key_size,
		      const char *func, bool debug, const char *file,
		      const int line)
{
	json_object *j_show_obj;
	json_object *j_obj = NULL;
	struct dp_test_json_mismatches *mismatches = NULL;

	j_show_obj = dp_test_json_do_show_cmd("qos show", &mismatches, debug);
	if (j_show_obj) {
		j_obj = dp_test_json_search(j_show_obj, key, key_size);
		if (!j_obj) {
			(void)dp_test_json_mismatch_print(mismatches, 2, NULL,
							  0);
			_dp_test_qos_json_error(debug, file, line, j_show_obj,
						"%s failed to find json object",
						func);
		}
		json_object_put(j_show_obj);
	}
	return j_obj;
}

/*
 * The naming convention used for the _dp_test_qos_get_json_... functions is
 * to end the function name with a suffix that uniquely identifies a node
 * within the JSON tree returned by "qos show".
 *
 * ..._shaper - because shaper only appears one place in the tree
 * ..._subports_tc and ..._pipes_tc - because tc appears in two locations
 */
json_object *
_dp_test_qos_get_json_shaper(const char *if_name, bool debug, const char *file,
			     const int line)
{
	char real_if_name[IFNAMSIZ];

	/* Convert the test if-name into a real if-name */
	dp_test_intf_real(if_name, real_if_name);

	/* Search for shaper object from named interface */
	struct dp_test_json_search_key key[] = {
		{ real_if_name, NULL, 0 },
		{ "shaper", NULL, 0 },
	};

	return _dp_test_qos_get_json(key, ARRAY_SIZE(key), __func__, debug,
				     file, line);
}

json_object *
_dp_test_qos_get_json_vlans(const char *if_name, bool debug, const char *file,
			    const int line)
{
	char real_if_name[IFNAMSIZ];

	/* Convert the test if-name into a real if-name */
	dp_test_intf_real(if_name, real_if_name);

	/* Search for shaper object from named interface */
	struct dp_test_json_search_key key[] = {
		{ real_if_name, NULL, 0 },
		{ "shaper", NULL, 0 },
		{ "vlans", NULL, -1 },
	};

	return _dp_test_qos_get_json(key, ARRAY_SIZE(key), __func__, debug,
				     file, line);
}

bool
_dp_test_qos_vlan_iterator(json_object *j_obj, void *arg)
{
	uint *vlan_id = arg;
	int value;
	bool rc;

	rc = dp_test_json_int_field_from_obj(j_obj, "tag", &value);
	return (rc && *vlan_id == (uint)value) ? true : false;
}

bool
_dp_test_qos_get_json_vlan_subport(const char *if_name, const uint vlan_id,
				   int *subport_id, bool debug,
				   const char *file, const int line)
{
	json_object *j_vlans;
	json_object *j_vlan;
	uint id = vlan_id;
	bool rc = false;

	j_vlans = _dp_test_qos_get_json_vlans(if_name, debug, file, line);
	if (j_vlans) {
		j_vlan = dp_test_json_array_iterate(j_vlans,
						    _dp_test_qos_vlan_iterator,
						    &id);
		if (j_vlan)
			rc = dp_test_json_int_field_from_obj(j_vlan, "subport",
							     subport_id);

		json_object_put(j_vlans);
	}
	return rc;
}

json_object *
_dp_test_qos_get_json_subports(const char *if_name, bool debug,
			       const char *file, const int line)
{
	char real_if_name[IFNAMSIZ];

	/* Convert the test if-name into a real if-name */
	dp_test_intf_real(if_name, real_if_name);

	/* Build the key for the required object */
	struct dp_test_json_search_key key[] = {
		{ real_if_name, NULL, 0 },
		{ "shaper", NULL, 0 },
		{ "subports", NULL, 0 },
	};

	return _dp_test_qos_get_json(key, ARRAY_SIZE(key), __func__, debug,
				     file, line);
}

json_object *
_dp_test_qos_get_json_subport_tc(const char *if_name, const uint subport,
				 const uint tc, bool debug, const char *file,
				 const int line)
{
	char real_if_name[IFNAMSIZ];

	/* Convert the test if-name into a real if-name */
	dp_test_intf_real(if_name, real_if_name);

	/* Build the key for the required object */
	struct dp_test_json_search_key key[] = {
		{ real_if_name, NULL, 0 },
		{ "shaper", NULL, 0 },
		{ "subports", NULL, subport },
		{ "tc", NULL, tc },
	};

	return _dp_test_qos_get_json(key, ARRAY_SIZE(key), __func__, debug,
				     file, line);
}

/*
 * We need a version of _dp_test_qos_get_json_subport_tc that doesn't fail when
 * it can't find the required subport tc JSON object.  We use this function
 * immediately after applying the QoS configuration to an interface to
 * determine when configuration has been complete.
 */

bool
_dp_test_qos_get_json_subport_tc_no_fail(const char *if_name,
					 const uint subport, const uint tc,
					 bool debug, const char *file,
					 const int line)
{
	json_object *j_obj;
	json_object *j_tc = NULL;
	struct dp_test_json_mismatches *mismatches = NULL;
	char real_if_name[IFNAMSIZ];

	/* Convert the test if-name into a real if-name */
	dp_test_intf_real(if_name, real_if_name);

	/* Build the key for the required object */
	struct dp_test_json_search_key key[] = {
		{ real_if_name, NULL, 0 },
		{ "shaper", NULL, 0 },
		{ "subports", NULL, subport },
		{ "tc", NULL, tc },
	};

	j_obj = dp_test_json_do_show_cmd("qos show", &mismatches, debug);
	if (j_obj) {
		j_tc = dp_test_json_search(j_obj, key, ARRAY_SIZE(key));
		json_object_put(j_obj);
		if (j_tc) {
			json_object_put(j_tc);
			return true;
		}
	}
	return false;
}

json_object *
_dp_test_qos_get_json_pipe(const char *if_name, const uint subport,
			   const uint pipe, bool debug, const char *file,
			   const int line)
{
	char real_if_name[IFNAMSIZ];

	/* Convert the test if-name into a real if-name */
	dp_test_intf_real(if_name, real_if_name);

	/* Build the key for the required object */
	struct dp_test_json_search_key key[] = {
		{ real_if_name, NULL, 0 },
		{ "shaper", NULL, 0 },
		{ "subports", NULL, subport },
		{ "pipes", NULL, pipe },
	};

	return _dp_test_qos_get_json(key, ARRAY_SIZE(key), __func__, debug,
				     file, line);
}

json_object *
_dp_test_qos_get_json_params(const char *if_name, const uint subport,
			     const uint pipe, bool debug, const char *file,
			     const int line)
{
	char real_if_name[IFNAMSIZ];

	/* Convert the test if-name into a real if-name */
	dp_test_intf_real(if_name, real_if_name);

	/* Build the key for the required object */
	struct dp_test_json_search_key key[] = {
		{ real_if_name, NULL, 0 },
		{ "shaper",  NULL, 0 },
		{ "subports", NULL, subport },
		{ "pipes", NULL, pipe },
		{ "params", NULL, 0 },
	};

	return _dp_test_qos_get_json(key, ARRAY_SIZE(key), __func__, debug,
				     file, line);
}

json_object *
_dp_test_qos_get_json_tc_rate(const char *if_name, const uint subport,
			      const uint pipe, const int tc, bool debug,
			      const char *file, const int line)
{
	char real_if_name[IFNAMSIZ];

	/* Convert the test if-name into a real if-name */
	dp_test_intf_real(if_name, real_if_name);

	/* Build the key for the required object */
	struct dp_test_json_search_key key[] = {
		{ real_if_name, NULL, 0 },
		{ "shaper",  NULL, 0 },
		{ "subports", NULL, subport },
		{ "pipes", NULL, pipe },
		{ "params", NULL, 0 },
		{ "tc_rates", NULL, tc },
	};

	return _dp_test_qos_get_json(key, ARRAY_SIZE(key), __func__, debug,
				     file, line);
}

json_object *
_dp_test_qos_get_json_wrr_weight(const char *if_name, const uint subport,
				 const uint pipe, const int queue, bool debug,
				 const char *file, const int line)
{
	char real_if_name[IFNAMSIZ];

	/* Convert the test if-name into a real if-name */
	dp_test_intf_real(if_name, real_if_name);

	/* Build the key for the required object */
	struct dp_test_json_search_key key[] = {
		{ real_if_name, NULL, 0 },
		{ "shaper",  NULL, 0 },
		{ "subports", NULL, subport },
		{ "pipes", NULL, pipe },
		{ "params", NULL, 0 },
		{ "wrr_weights", NULL, queue },
	};

	return _dp_test_qos_get_json(key, ARRAY_SIZE(key), __func__, debug,
				     file, line);
}

json_object *
_dp_test_qos_get_json_dscp2q(const char *if_name, const uint subport,
			     const uint pipe, const int dscp, bool debug,
			     const char *file, const int line)
{
	char real_if_name[IFNAMSIZ];

	/* Convert the test if-name into a real if-name */
	dp_test_intf_real(if_name, real_if_name);

	/* Build the key for the required object */
	struct dp_test_json_search_key key[] = {
		{ real_if_name, NULL, 0 },
		{ "shaper",  NULL, 0 },
		{ "subports", NULL, subport },
		{ "pipes", NULL, pipe },
		{ "dscp2q", NULL, dscp },
	};

	return _dp_test_qos_get_json(key, ARRAY_SIZE(key), __func__, debug,
				     file, line);
}

json_object *
_dp_test_qos_get_json_pcp2q(const char *if_name, const uint subport,
			    const uint pipe, const int pcp, bool debug,
			    const char *file, const int line)
{
	char real_if_name[IFNAMSIZ];

	/* Convert the test if-name into a real if-name */
	dp_test_intf_real(if_name, real_if_name);

	/* Build the key for the required object */
	struct dp_test_json_search_key key[] = {
		{ real_if_name, NULL, 0 },
		{ "shaper",  NULL, 0 },
		{ "subports", NULL, subport },
		{ "pipes", NULL, pipe },
		{ "pcp2q", NULL, pcp },
	};

	return _dp_test_qos_get_json(key, ARRAY_SIZE(key), __func__, debug,
				     file, line);
}

json_object *
_dp_test_qos_get_json_pipe_tc(const char *if_name, const uint subport,
			      const uint pipe, const uint tc, bool debug,
			      const char *file, const int line)
{
	char real_if_name[IFNAMSIZ];

	/* Convert the test if-name into a real if-name */
	dp_test_intf_real(if_name, real_if_name);

	/* Build the key for the required object */
	struct dp_test_json_search_key key[] = {
		{ real_if_name, NULL, 0 },
		{ "shaper", NULL, 0 },
		{ "subports", NULL, subport },
		{ "pipes", NULL, pipe },
		{ "tc", NULL, tc },
	};

	return _dp_test_qos_get_json(key, ARRAY_SIZE(key), __func__, debug,
				     file, line);
}

json_object *
_dp_test_qos_get_json_array_element(json_object *j_array, uint index,
				    bool debug, const char *file,
				    const int line)
{
	uint arraylen;

	if (json_object_get_type(j_array) != json_type_array)
		_dp_test_fail(file, line, "%s json-object isn't array\n",
			      __func__);

	arraylen = json_object_array_length(j_array);
	if (index >= arraylen) {
		bool saved_dp_test_abort_on_fail = dp_test_abort_on_fail;

		dp_test_abort_on_fail = false;
		_dp_test_fail(file, line, "%s %u index >= array length %u\n",
			      __func__, index, arraylen);
		dp_test_abort_on_fail = saved_dp_test_abort_on_fail;
		return NULL;
	}

	return json_object_get(json_object_array_get_idx(j_array, index));
}

json_object *
_dp_test_qos_get_json_queue(const char *if_name, const uint subport,
			    const uint pipe, const uint tc, const uint queue,
			    bool debug, const char *file, const int line)
{
	json_object *j_tc_obj;
	json_object *j_q_obj = NULL;

	j_tc_obj = _dp_test_qos_get_json_pipe_tc(if_name, subport, pipe, tc,
						 debug, file, line);
	if (j_tc_obj) {
		j_q_obj = _dp_test_qos_get_json_array_element(j_tc_obj, queue,
							      debug, file,
							      line);
		json_object_put(j_tc_obj);
	}
	return j_q_obj;
}

json_object *
_dp_test_qos_get_json_rules(const char *if_name, const uint subport,
			    bool debug, const char *file, const int line)
{
	char real_if_name[IFNAMSIZ];

	/* Convert the test if-name into a real if-name */
	dp_test_intf_real(if_name, real_if_name);

	/* Build the key for the required object */
	struct dp_test_json_search_key key[] = {
		{ real_if_name, NULL, 0 },
		{ "shaper", NULL, 0 },
		{ "subports", NULL, subport },
		{ "rules", NULL, 0 },
	};

	return _dp_test_qos_get_json(key, ARRAY_SIZE(key), __func__, debug,
				     file, line);
}

json_object *
_dp_test_qos_get_json_groups_rules(const char *if_name, const uint subport,
				   bool debug, const char *file, const int line)
{
	char real_if_name[IFNAMSIZ];

	/* Convert the test if-name into a real if-name */
	dp_test_intf_real(if_name, real_if_name);

	/* Build the key for the required object */
	struct dp_test_json_search_key key[] = {
		{ real_if_name, NULL, 0 },
		{ "shaper", NULL, 0 },
		{ "subports", NULL, subport },
		{ "rules", NULL, 0 },
		{ "groups", NULL, 0 },
		{ "rules", NULL, -1 },
	};

	return _dp_test_qos_get_json(key, ARRAY_SIZE(key), __func__, debug,
				     file, line);
}

/*
 * JSON Checking functions
 * Check to see that a JSON field has the correct expected value.
 */
void
_dp_test_qos_check_counter(json_object *j_obj, const char *counter_name,
			   const int expected_value, bool debug,
			   const char *file, const int line)
{
	int returned_value;

	if (!dp_test_json_int_field_from_obj(j_obj, counter_name,
					     &returned_value)) {
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail(file, line,
			      "%s failed to find counter %s\n",
			      __func__, counter_name);
	} else if (returned_value != expected_value) {
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail(file, line,
			      "%s unexpected %s counter value %d versus %d\n",
			      __func__, counter_name, returned_value,
			      expected_value);
	}
}

void
_dp_test_qos_check_subport_tc_counter(const char *if_name, const uint subport,
				      const uint tc, const char *counter_name,
				      const int expected_value, bool debug,
				      const char *file, const int line)
{
	json_object *j_tc;

	j_tc = _dp_test_qos_get_json_subport_tc(if_name, subport, tc, debug,
						file, line);

	_dp_test_qos_check_counter(j_tc, counter_name, expected_value, debug,
				   file, line);
	json_object_put(j_tc);
}

void
_dp_test_qos_check_queue_counter(const char *if_name, const uint subport,
				 const uint pipe, uint tc, const uint queue,
				 const char *counter_name,
				 const int expected_value, bool debug,
				 const char *file, const int line)
{
	json_object *j_q;

	j_q = _dp_test_qos_get_json_queue(if_name, subport, pipe, tc, queue,
					  debug, file, line);

	_dp_test_qos_check_counter(j_q, counter_name, expected_value, debug,
				   file, line);
	json_object_put(j_q);
}

/*
 * QoS counter checking for zero functions
 */
struct dp_test_qos_json_array_iterate_argblk {
	bool debug;
	char *file;
	int line;
	uint32_t count;
	int8_t *pcp_values;
};

bool _dp_test_qos_counters_check_for_zero(json_object *j_counters, void *arg)
{
	struct dp_test_qos_json_array_iterate_argblk *argblk = arg;

	_dp_test_qos_check_counter(j_counters, "packets", 0, argblk->debug,
				   argblk->file, argblk->line);
	_dp_test_qos_check_counter(j_counters, "bytes", 0, argblk->debug,
				   argblk->file, argblk->line);
	_dp_test_qos_check_counter(j_counters, "dropped", 0, argblk->debug,
				   argblk->file, argblk->line);
	_dp_test_qos_check_counter(j_counters, "random_drop", 0, argblk->debug,
				   argblk->file, argblk->line);
	return false;  /* Iterate to the end of the array */
}

bool _dp_test_qos_tc_q_check_for_zero(json_object *j_q, void *arg)
{
	dp_test_json_array_iterate(j_q,
				   _dp_test_qos_counters_check_for_zero,
				   arg);
	return false;  /* Iterate to the end of the array */
}

bool _dp_test_qos_pipe_tc_check_for_zero(json_object *j_tc, void *arg)
{
	dp_test_json_array_iterate(j_tc,
				   _dp_test_qos_tc_q_check_for_zero,
				   arg);
	return false;  /* Iterate to the end of the array */
}

bool _dp_test_qos_pipes_check_for_zero(json_object *j_pipe, void *arg)
{
	struct dp_test_qos_json_array_iterate_argblk *argblk = arg;
	json_object *j_tcs;

	struct dp_test_json_find_key tc_key[] = {
		{ "tc", NULL }
	};

	j_tcs = dp_test_json_find(j_pipe, tc_key, ARRAY_SIZE(tc_key));
	if (!j_tcs)
		_dp_test_fail(argblk->file, argblk->line,
			      "%s failed to get pipes tcs\n",
			      __func__);

	dp_test_json_array_iterate(j_tcs,
				   _dp_test_qos_pipe_tc_check_for_zero,
				   arg);

	json_object_put(j_tcs);
	return false;  /* Iterate to the end of the array */
}

bool _dp_test_qos_subport_check_for_zero(json_object *j_subport, void *arg)
{
	struct dp_test_qos_json_array_iterate_argblk *argblk = arg;
	json_object *j_tcs;
	json_object *j_pipes;
	struct dp_test_json_find_key tc_key[] = {
		{ "tc", NULL }
	};
	struct dp_test_json_find_key pipes_key[] = {
		{ "pipes", NULL }
	};

	j_tcs = dp_test_json_find(j_subport, tc_key, ARRAY_SIZE(tc_key));
	if (!j_tcs)
		_dp_test_fail(argblk->file, argblk->line,
			      "%s failed to get subport tcs\n",
			      __func__);

	dp_test_json_array_iterate(j_tcs,
				   _dp_test_qos_counters_check_for_zero,
				   arg);

	j_pipes = dp_test_json_find(j_subport, pipes_key,
				    ARRAY_SIZE(pipes_key));
	if (!j_pipes)
		_dp_test_fail(argblk->file, argblk->line,
			      "%s failed to get subport pipes\n",
			      __func__);

	dp_test_json_array_iterate(j_pipes,
				   _dp_test_qos_pipes_check_for_zero,
				   arg);

	json_object_put(j_tcs);
	json_object_put(j_pipes);
	return false;  /* Iterate to the end of the array */
}

void _dp_test_qos_check_for_zero_counters(const char *if_name, bool debug,
					  const char *file, const int line)
{
	struct dp_test_qos_json_array_iterate_argblk argblk;
	json_object *j_subports;

	argblk.debug = debug;
	argblk.file = (char *)file;
	argblk.line = (int)line;

	j_subports = _dp_test_qos_get_json_subports(if_name, debug, file, line);
	if (!j_subports) {
		_dp_test_fail(file, line, "%s failed to get subports\n",
			      __func__);
	}
	dp_test_json_array_iterate(j_subports,
				   _dp_test_qos_subport_check_for_zero,
				   &argblk);
	json_object_put(j_subports);
}

/*
 * If any of the string arguments have a NULL pointer, or any of the numerical
 * arguments have a negative value, then the caller doesn't want them checked.
 */
void
_dp_test_qos_check_rule(json_object *j_obj, const char *action,
			const char *config, const char *match,
			const char *operation, int bytes, int packets,
			bool debug, const char *file, const int line)
{
	const char *str_value;
	int int_value;
	bool rc;

	if (action) {
		rc = dp_test_json_string_field_from_obj(j_obj, "action",
							&str_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && strncmp(str_value, action,
						   strlen(action)) == 0,
				     file, line,
				     "%s failed to match action %s\n",
				     __func__, action);
	}
	if (config) {
		rc = dp_test_json_string_field_from_obj(j_obj, "config",
							&str_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && strncmp(str_value, config,
						   strlen(config)) == 0,
				     file, line,
				     "%s failed to match config %s\n",
				     __func__, config);
	}
	if (match) {
		rc = dp_test_json_string_field_from_obj(j_obj, "match",
							&str_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && strncmp(str_value, match,
						   strlen(match)) == 0,
				     file, line,
				     "%s failed to match match %s\n",
				     __func__, match);
	}
	if (operation) {
		rc = dp_test_json_string_field_from_obj(j_obj, "operation",
							&str_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && strncmp(str_value, operation,
						   strlen(operation)) == 0,
				     file, line,
				     "%s failed to match operation %s\n",
				     __func__, match);
	}
	if (bytes >= 0) {
		rc = dp_test_json_int_field_from_obj(j_obj, "bytes",
						     &int_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && bytes == int_value,
				     file, line,
				     "%s failed to match bytes %d\n",
				     __func__, bytes);
	}
	if (packets >= 0) {
		rc = dp_test_json_int_field_from_obj(j_obj, "packets",
						     &int_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && packets == int_value,
				     file, line,
				     "%s failed to match packets %d\n",
				     __func__, packets);
	}
}

/*
 * Clear QoS counters
 */
void _dp_test_qos_clear_counters(const char *if_name, bool debug,
				 const char *file, const int line)
{
	char real_if_name[IFNAMSIZ];

	/* Convert the test if-name into a real if-name */
	if (if_name)
		dp_test_intf_real(if_name, real_if_name);

	dp_test_qos_op_cmd_fmt(debug, "qos clear %s",
			       if_name ? real_if_name : "");
}

static json_object *
_dp_test_qos_hw_get_json(struct dp_test_json_search_key *key, uint32_t key_size,
			 const char *func, bool debug, const char *file,
			 const int line)
{
	json_object *j_show_obj;
	json_object *j_obj = NULL;
	struct dp_test_json_mismatches *mismatches = NULL;

	j_show_obj = dp_test_json_do_show_cmd("qos hw", &mismatches, debug);
	if (j_show_obj) {
		if (debug)
			dp_test_qos_json_dump(j_show_obj);

		j_obj = dp_test_json_search(j_show_obj, key, key_size);
		if (!j_obj) {
			(void)dp_test_json_mismatch_print(mismatches, 2, NULL,
							  0);
			_dp_test_qos_json_error(debug, file, line, j_show_obj,
						"%s failed to find json object",
						func);
		}
		json_object_put(j_show_obj);
	}
	return j_obj;
}

json_object *
_dp_test_qos_hw_get_json_sched_group(uint32_t level, const char *if_name,
				     uint32_t subport, uint32_t pipe,
				     uint32_t tc, bool debug, const char *file,
				     const int line)
{
	char real_if_name[IFNAMSIZ];

	/* Convert the test if-name into a real if-name */
	dp_test_intf_real(if_name, real_if_name);

	/* Search for sched-group object from named interface */
	struct dp_test_json_search_key key[] = {
		{ real_if_name, NULL, 0 },
		{ "sched-group", NULL, 0 },
		{ "children", NULL, subport },
		{ "sched-group", NULL, 0 },
		{ "children", NULL, pipe },
		{ "sched-group", NULL, 0 },
		{ "children", NULL, tc },
		{ "sched-group", NULL, 0 },
	};

	return _dp_test_qos_hw_get_json(key, level * 2, __func__, debug,
					file, line);
}

json_object *
_dp_test_qos_hw_get_json_queue(const char *if_name, uint32_t subport,
			       uint32_t pipe, uint32_t tc, uint32_t queue,
			       bool debug, const char *file, const int line)
{
	char real_if_name[IFNAMSIZ];

	/* Convert the test if-name into a real if-name */
	dp_test_intf_real(if_name, real_if_name);

	/* Search for sched-group object from named interface */
	struct dp_test_json_search_key key[] = {
		{ real_if_name, NULL, 0 },
		{ "sched-group", NULL, 0 },
		{ "children", NULL, subport },
		{ "sched-group", NULL, 0 },
		{ "children", NULL, pipe },
		{ "sched-group", NULL, 0 },
		{ "children", NULL, tc },
		{ "sched-group", NULL, 0 },
		{ "children", NULL, queue },
		{ "queue", NULL, 0 },
	};

	return _dp_test_qos_hw_get_json(key, 10, __func__, debug,
					file, line);
}

json_object *
_dp_test_qos_hw_get_json_child(json_object *j_parent, const char *name,
			       bool debug, const char *file, const int line)
{
	json_object *j_obj;

	struct dp_test_json_search_key key[] = {
		{ name, NULL, 0 },
	};

	j_obj = dp_test_json_search(j_parent, key, 1);
	if (!j_obj)
		_dp_test_qos_json_error(debug, file, line, j_parent,
					"%s failed to find %s child object",
					__func__, name);

	return j_obj;
}

void
_dp_test_qos_hw_check_sched_group(json_object *j_obj, int32_t level,
				  int32_t max_children,
				  int32_t current_children, uint8_t lpq,
				  bool debug, const char *file, const int line)
{
	int32_t int_value;
	bool rc;

	_dp_test_fail_unless(j_obj != NULL, file, line, "null sched-group\n");

	if (level >= 0) {
		rc = dp_test_json_int_field_from_obj(j_obj, "level",
						     &int_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && level == int_value, file, line,
				     "%s failed to match level %d\n",
				     __func__, level);
	}

	if (max_children >= 0) {
		rc = dp_test_json_int_field_from_obj(j_obj, "max-children",
						     &int_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && max_children == int_value, file,
				     line,
				     "%s failed to match max-children %d int_val %d\n",
				     __func__, max_children, int_value);
	}

	if (current_children >= 0) {
		rc = dp_test_json_int_field_from_obj(j_obj, "current-children",
						     &int_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && current_children == int_value, file,
				     line,
				     "%s failed to match current-children %d int_val %d\n",
				     __func__, current_children, int_value);
	}

	if (lpq > 0) {
		rc = dp_test_json_int_field_from_obj(j_obj,
						     "local-priority-des",
						     &int_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && lpq == int_value, file,
				     line,
				     "%s failed to match lpq %d int_val %d\n",
				     __func__, lpq, int_value);
	}
}

void
_dp_test_qos_hw_check_egress_map(json_object *j_map_obj, int32_t map_type,
				 const uint8_t *map_list, bool debug,
				 const char *file, const int line)
{
	json_object *j_map_list_obj;
	int32_t int_value;
	uint32_t length;
	uint8_t cp;
	uint8_t i;
	bool rc;

	_dp_test_fail_unless(j_map_obj != NULL, file, line, "null map\n");
	_dp_test_fail_unless(map_list != NULL, file, line, "null map-list\n");

	if (map_type >= 0) {
		rc = dp_test_json_int_field_from_obj(j_map_obj, "map-type",
						     &int_value);
		_dp_test_fail_unless(rc && int_value == map_type, file, line,
				     "%s failed to match map-type %d\n",
				     __func__, map_type);
	}

	struct dp_test_json_search_key key[] = {
		{ "map-list", NULL, -1 },
	};

	j_map_list_obj = dp_test_json_search(j_map_obj, key, 1);
	_dp_test_fail_unless(j_map_list_obj != NULL, file, line,
			     "%s failed to find map-list array\n", __func__);

	length = json_object_array_length(j_map_list_obj);

	uint8_t json_map[MAX_DSCP] = { 0 };

	for (i = 0; i < length; i++) {
		json_object *j_map_entry;
		const char *dscp_bitmap_str;
		uint64_t dscp_bitmap;
		int pcp;
		bool rc1;
		bool rc2;

		j_map_entry = json_object_array_get_idx(j_map_list_obj, i);

		rc1 = dp_test_json_string_field_from_obj(j_map_entry,
							 "dscp-bitmap",
							 &dscp_bitmap_str);
		rc2 = dp_test_json_int_field_from_obj(j_map_entry,
						      "pcp", &pcp);
		_dp_test_fail_unless(rc1 && rc2, file, line,
				     "%s failed to extract map from map-list\n",
				     __func__);

		dscp_bitmap = strtoul(dscp_bitmap_str, NULL, 10);

		for (cp = 0; cp < MAX_DSCP; cp++) {
			if (dscp_bitmap & (1ul << cp))
				json_map[cp] = pcp;
		}
	}

	for (cp = 0; cp < MAX_DSCP; cp++) {
		_dp_test_fail_unless(json_map[cp] == map_list[cp],
				     file, line,
				     "%s failed to match DSCP %u, %u vs %u\n",
				     __func__, cp, map_list[cp], json_map[cp]);
	}

	json_object_put(j_map_list_obj);
}

void
_dp_test_qos_hw_check_scheduler(json_object *j_obj, const char *type,
				const char *meter_type, int32_t weight,
				int64_t max_bandwidth, int32_t max_burst,
				int8_t overhead, bool debug,
				const char *file, const int line)
{
	const char *str_value;
	int32_t int_value;
	bool rc;

	_dp_test_fail_unless(j_obj != NULL, file, line, "null scheduler\n");

	if (type) {
		rc = dp_test_json_string_field_from_obj(j_obj, "type",
							&str_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && strncmp(str_value, type,
						   strlen(type)) == 0,
				     file, line,
				     "%s failed to match type %s\n",
				     __func__, type);
	}

	if (meter_type) {
		rc = dp_test_json_string_field_from_obj(j_obj, "meter-type",
							&str_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && strncmp(str_value, meter_type,
						   strlen(meter_type)) == 0,
				     file, line,
				     "%s failed to match meter-type %s\n",
				     __func__, meter_type);
	}

	if (weight >= 0) {
		rc = dp_test_json_int_field_from_obj(j_obj, "weight",
						     &int_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && weight == int_value, file, line,
				     "%s failed to match weight %d\n",
				     __func__, weight);
	}

	if (max_bandwidth >= 0) {
		rc = dp_test_json_int_field_from_obj(j_obj, "max-bandwidth",
						     &int_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && max_bandwidth == int_value, file,
				     line,
				     "%s failed to match max-bandwidth %ld\n",
				     __func__, max_bandwidth);
	}

	if (max_burst >= 0) {
		rc = dp_test_json_int_field_from_obj(j_obj, "max-burst",
						     &int_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && max_burst == int_value, file, line,
				     "%s failed to match max-burst %d\n",
				     __func__, max_burst);
	}

	if (overhead >= 0) {
		rc = dp_test_json_int_field_from_obj(j_obj, "overhead",
						     &int_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && overhead == int_value, file, line,
				     "%s failed to match overhead %d\n",
				     __func__, overhead);
	}
}

void
_dp_test_qos_hw_check_queue(json_object *j_obj, int32_t id,
			    int32_t queue_limit, int32_t queue_index,
			    uint8_t designation,
			    bool debug, const char *file, const int line)
{
	int32_t int_value;
	bool rc;

	_dp_test_fail_unless(j_obj != NULL, file, line, "null queue\n");

	if (id >= 0) {
		rc = dp_test_json_int_field_from_obj(j_obj, "id",
						     &int_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && id == int_value, file, line,
				     "%s failed to match id %d\n",
				     __func__, id);
	}

	if (queue_limit >= 0) {
		rc = dp_test_json_int_field_from_obj(j_obj, "queue-limit",
						     &int_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && queue_limit == int_value, file, line,
				     "%s failed to match queue-limit %d\n",
				     __func__, queue_limit);
	}

	if (queue_index >= 0) {
		rc = dp_test_json_int_field_from_obj(j_obj, "queue-index",
						     &int_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && queue_index == int_value, file, line,
				     "%s failed to match queue-index %d\n",
				     __func__, queue_index);
	}

	if (designation > 0) {
		rc = dp_test_json_int_field_from_obj(j_obj, "designation",
						     &int_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && (int)designation == int_value,
				     file, line,
				     "%s failed to match designation %d\n",
				     __func__, designation);
	}
}

void
_dp_test_qos_hw_check_wred_colour(json_object *j_obj, const char *colour,
				  int32_t enabled, int32_t min_threshold,
				  int32_t max_threshold,
				  int32_t drop_probability,
				  int32_t filter_weight,
				  bool debug, const char *file, const int line)
{
	char field_name[64];
	int32_t int_value;
	bool bool_value;
	bool rc;

	_dp_test_fail_unless(j_obj != NULL, file, line, "null wred\n");

	if (enabled >= 0) {
		sprintf(field_name, "%s-enabled", colour);
		rc = dp_test_json_boolean_field_from_obj(j_obj, field_name,
							 &bool_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && enabled == bool_value, file,
				     line,
				     "%s failed to match %s %d against %d\n",
				     __func__, field_name, enabled, bool_value);
	}

	if (min_threshold >= 0) {
		sprintf(field_name, "%s-min-threshold", colour);
		rc = dp_test_json_int_field_from_obj(j_obj, field_name,
						     &int_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && min_threshold == int_value, file,
				     line,
				     "%s failed to match %s %d against %d\n",
				     __func__, field_name, min_threshold,
				     int_value);
	}

	if (max_threshold >= 0) {
		sprintf(field_name, "%s-max-threshold", colour);
		rc = dp_test_json_int_field_from_obj(j_obj, field_name,
						     &int_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && max_threshold == int_value, file,
				     line,
				     "%s failed to match %s %d against %d\n",
				     __func__, field_name, max_threshold,
				     int_value);
	}

	if (drop_probability >= 0) {
		sprintf(field_name, "%s-drop-probability", colour);
		rc = dp_test_json_int_field_from_obj(j_obj, field_name,
						     &int_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && drop_probability == int_value, file,
				     line,
				     "%s failed to match %s %d against %d\n",
				     __func__, field_name, drop_probability,
				     int_value);
	}

	if (filter_weight >= 0) {
		rc = dp_test_json_int_field_from_obj(j_obj, "filter-weight",
						     &int_value);
		if (debug)
			dp_test_qos_json_dump(j_obj);

		_dp_test_fail_unless(rc && filter_weight == int_value, file,
				     line,
				     "%s failed to match filter-weight %d\n",
				     __func__, filter_weight);
	}
}

static json_object *
_dp_test_qos_get_json_mark_map(struct dp_test_json_search_key *key,
			       uint32_t key_size, const char *func,
			       bool debug, const char *file, const int line)
{
	json_object *j_show_obj;
	json_object *j_obj = NULL;
	struct dp_test_json_mismatches *mismatches = NULL;

	j_show_obj = dp_test_json_do_show_cmd("qos show mark-maps",
					      &mismatches, debug);
	if (j_show_obj) {
		if (debug)
			dp_test_qos_json_dump(j_obj);

		j_obj = dp_test_json_search(j_show_obj, key, key_size);
		if (!j_obj)
			_dp_test_qos_json_error(debug, file, line, j_show_obj,
						"%s failed to find json object",
						func);

		json_object_put(j_show_obj);
	}
	return j_obj;
}

static bool
_dp_test_qos_pcp_values(json_object *j_pcp_value, void *arg)
{
	struct dp_test_qos_json_array_iterate_argblk *argblk = arg;
	int value;
	uint32_t index;

	index = argblk->count++;

	_dp_test_fail_unless(json_object_get_type(j_pcp_value) == json_type_int,
			     argblk->file, argblk->line,
			     "%s failed to find integer pcp-value",
			     __func__);

	value = json_object_get_int(j_pcp_value);
	_dp_test_fail_unless(argblk->pcp_values[index] == value,
			     argblk->file, argblk->line,
			     "%s failed to match pcp-value %d against %d for "
			     "dscp-value %u",
			     __func__, value, argblk->pcp_values[index], index);

	return false;  /* Iterate to the end of the array */
}

void
_dp_test_qos_check_mark_map(const char *map_name, int8_t *pcp_values,
			    bool debug, const char *file, const int line)
{
	struct dp_test_qos_json_array_iterate_argblk argblk;
	json_object *j_obj;
	json_object *j_pcp_values;

	struct dp_test_json_search_key key[] = {
		{ "mark-maps", NULL, 0 },
		{ "map-name", map_name, 0 }
	};

	j_obj = _dp_test_qos_get_json_mark_map(key, ARRAY_SIZE(key), __func__,
					       debug, file, line);
	if (!j_obj)
		_dp_test_qos_json_error(debug, file, line, j_obj,
					"%s failed to find json object",
					__func__);

	struct dp_test_json_find_key pcp_key[] = {
		{ "pcp-values", NULL }
	};

	j_pcp_values = dp_test_json_find(j_obj, pcp_key, ARRAY_SIZE(pcp_key));
	_dp_test_fail_unless(j_pcp_values,
			     file, line, "%s failed to find pcp-values array",
			     __func__);

	argblk.debug = debug;
	argblk.file = (char *)file;
	argblk.line = (int)line;
	argblk.count = 0;
	argblk.pcp_values = pcp_values;

	dp_test_json_array_iterate(j_pcp_values,
				   _dp_test_qos_pcp_values,
				   &argblk);
	json_object_put(j_pcp_values);
	json_object_put(j_obj);
}

/*
 * QoS configuration functions
 */
void _dp_test_qos_delete_config_from_if(const char *if_name, bool debug,
					const char *file, const int line)
{
	char real[IFNAMSIZ];

	dp_test_send_config_src(dp_test_cont_src_get(), "qos %s disable",
				dp_test_intf_real(if_name, real));
}

void _dp_test_qos_verify_config(const char *expected_json_str,
		const char *verify_cmd,
		bool negate_match, bool debug)
{
	if (expected_json_str != NULL) {
		json_object *expected_json;
		expected_json = dp_test_json_create("%s", expected_json_str);
		dp_test_check_json_state(verify_cmd, expected_json,
				DP_TEST_JSON_CHECK_SUBSET,
				negate_match);
		json_object_put(expected_json);
	}

}
void _dp_test_qos_send_config(const char *cmd_list[],
		const char *expected_json_str,
		const char *verify_cmd,
		int num_cmds, bool debug,
		const char *file, const int line)

{
	int i = 0;

	for (i = 0; i < num_cmds; i++) {
		dp_test_send_config_src(dp_test_cont_src_get(),
				"qos global-object-cmd %s",
				cmd_list[i]);
	}

	_dp_test_qos_verify_config(expected_json_str,
			verify_cmd, false, debug);

}

void _dp_test_qos_send_cmd(const char *cmd,
		const char *expected_json_str,
		const char *verify_cmd,
		bool debug,
		const char *file, const int line)
{
	dp_test_send_config_src(dp_test_cont_src_get(),
			"qos global-object-cmd %s", cmd);

	_dp_test_qos_verify_config(expected_json_str,
			verify_cmd, false, debug);

}

void _dp_test_qos_send_if_cmd(const char *if_name,
		const char *cmd,
		const char *expected_json_str,
		const char *verify_cmd,
		bool debug,
		const char *file, const int line)

{
	char real[IFNAMSIZ];

	dp_test_send_config_src(dp_test_cont_src_get(), "qos %s %s",
				dp_test_intf_real(if_name, real), cmd);

	_dp_test_qos_verify_config(expected_json_str,
			verify_cmd, false, debug);

}

void _dp_test_qos_attach_config_to_if(const char *if_name,
				      const char *cmd_list[], bool debug,
				      const char *file, const int line)

{
	uint32_t i = 0;
	uint32_t subports = 0;
	int32_t items = -1;
	char real[IFNAMSIZ];

	while (!strstr(cmd_list[i], "enable")) {
		/*
		 * There should only be one "port subports" command that tells
		 * us how many subports are being configured.
		 */
		if (strstr(cmd_list[i], "port subports ")) {
			items = sscanf(cmd_list[i], "port subports %u",
				       &subports);
		}
		/*
		 * Update the numeric port-id with the required value
		 */
		dp_test_send_config_src(dp_test_cont_src_get(), "qos %s %s",
					dp_test_intf_real(if_name, real),
					cmd_list[i++]);
	}
	dp_test_send_config_src(dp_test_cont_src_get(), "qos %s %s",
				dp_test_intf_real(if_name, real),
				cmd_list[i++]);

	/*
	 * Now verify that the configuration has been completed by checking
	 * that each of the configured subports has four traffic-classes.
	 */
	i = 0;
	while (i++ < 100 && items != -1) {
		uint32_t sp;
		uint32_t tc;

		for (sp = 0; sp < subports; sp++) {
			for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE;
			     tc++) {
				if (!_dp_test_qos_get_json_subport_tc_no_fail
					(if_name, sp, tc, debug, file, line)) {
					if (debug)
						printf("%s no subport %u tc %u"
						       ", %s:%d\n", __func__,
						       sp, tc, file, line);
					usleep(10);
				}
			}
		}
	}
	if (i == 100)
		_dp_test_fail(file, line, "%s failed to configure\n", __func__);
}

/*
 * QoS packet test functions
 */
void
_dp_test_qos_pkt_forw_test(const char *ifname, uint vlan_id,
			   const char *l3_src, const char *l3_dst,
			   uint dscp, uint subport, uint pipe,
			   uint tc, uint queue, bool debug,
			   const char *file, const int line)
{
	struct dp_test_pkt_desc_t *pdesc;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;

	struct dp_test_pkt_desc_t v4_pkt_desc = {
		.text       = "TCP IPv4",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 1000,
				.dport = 1001,
				.flags = 0
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};
	pdesc = &v4_pkt_desc;

	v4_pkt_desc.l3_src = l3_src;
	v4_pkt_desc.l3_dst = l3_dst;
	/*
	 * Note that the DSCP value controls which TC and WRR queue the
	 * packet will pass through
	 */
	v4_pkt_desc.traf_class = dscp << 2;  /* Allow for 2 bits of ECN */

	/*
	 * Packet is forwarded
	 */
	test_pak = dp_test_v4_pkt_from_desc(&v4_pkt_desc);
	test_exp = dp_test_exp_from_desc(test_pak, pdesc);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);
	if (vlan_id != 0)
		dp_test_exp_set_vlan_tci(test_exp, vlan_id);

	/* Run the test */
	_dp_test_pak_receive(test_pak, pdesc->rx_intf, test_exp, file,
			     __func__, line);

	/* Verify */
	_dp_test_qos_check_subport_tc_counter(ifname, subport, tc, "packets", 1,
					      debug, file, line);
	_dp_test_qos_check_subport_tc_counter(ifname, subport, tc, "bytes", 74,
					      debug, file, line);
	_dp_test_qos_check_subport_tc_counter(ifname, subport, tc, "dropped", 0,
					      debug, file, line);

	_dp_test_qos_check_queue_counter(ifname, subport, pipe, tc, queue,
					 "packets", 1, debug, file, line);
	_dp_test_qos_check_queue_counter(ifname, subport, pipe, tc, queue,
					 "bytes", 74, debug, file, line);
	_dp_test_qos_check_queue_counter(ifname, subport, pipe, tc, queue,
					 "dropped", 0, debug, file, line);
}

void
_dp_test_qos_pkt_remark_test(const char *ifname, const uint vlan_id,
			     const char *l3_src, const char *l3_dst,
			     const uint dscp, const uint remark,
			     const uint subport, const uint pipe,
			     const uint tc, const uint queue, bool debug,
			     const char *file, const int line)
{
	struct dp_test_pkt_desc_t *pdesc;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;

	struct dp_test_pkt_desc_t v4_pkt_desc = {
		.text       = "TCP IPv4",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 1000,
				.dport = 1001,
				.flags = 0
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};
	pdesc = &v4_pkt_desc;

	v4_pkt_desc.l3_src = l3_src;
	v4_pkt_desc.l3_dst = l3_dst;
	/*
	 * Note that the DSCP value controls which TC and WRR queue the
	 * packet will pass through
	 */
	v4_pkt_desc.traf_class = dscp << 2;  /* Allow for 2 bits of ECN */

	/*
	 * Packet is forwarded
	 */
	test_pak = dp_test_v4_pkt_from_desc(&v4_pkt_desc);
	test_exp = dp_test_exp_from_desc(test_pak, pdesc);

	/*
	 * Update the DSCP value and recalculate the checksum
	 */
	dp_test_ipv4_remark_tos(dp_test_exp_get_pak(test_exp), remark << 2);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);
	if (vlan_id != 0)
		dp_test_exp_set_vlan_tci(test_exp, vlan_id);

	/* Run the test */
	_dp_test_pak_receive(test_pak, pdesc->rx_intf, test_exp, file,
			     __func__, line);

	/* Verify */
	_dp_test_qos_check_subport_tc_counter(ifname, subport, tc, "packets", 1,
					      debug, file, line);
	_dp_test_qos_check_subport_tc_counter(ifname, subport, tc, "bytes", 74,
					      debug, file, line);
	_dp_test_qos_check_subport_tc_counter(ifname, subport, tc, "dropped", 0,
					      debug, file, line);

	_dp_test_qos_check_queue_counter(ifname, subport, pipe, tc, queue,
					 "packets", 1, debug, file, line);
	_dp_test_qos_check_queue_counter(ifname, subport, pipe, tc, queue,
					 "bytes", 74, debug, file, line);
	_dp_test_qos_check_queue_counter(ifname, subport, pipe, tc, queue,
					 "dropped", 0, debug, file, line);
}

void
_dp_test_qos_pkt_force_drop(const char *ifname, const uint vlan_id,
			    const char *l3_src, const char *l3_dst,
			    const uint dscp, const uint queue_limit,
			    const uint subport, const uint pipe, const uint tc,
			    const uint queue, bool debug,
			    const char *file, const int line)
{
	struct dp_test_pkt_desc_t *pdesc;
	struct dp_test_expected *test_exp = NULL;
	struct rte_mbuf *test_pak[DP_TEST_MAX_EXPECTED_PAKS];
	uint i;

	struct dp_test_pkt_desc_t v4_pkt_desc = {
		.text       = "TCP IPv4",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 1000,
				.dport = 1001,
				.flags = 0
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};
	pdesc = &v4_pkt_desc;

	v4_pkt_desc.l3_src = l3_src;
	v4_pkt_desc.l3_dst = l3_dst;
	/*
	 * Note that the DSCP value controls which TC and WRR queue the
	 * packet will pass through
	 */
	v4_pkt_desc.traf_class = dscp << 2;  /* Allow for 2 bits of ECN */

	for (i = 0; i <= queue_limit; i++) {
		test_pak[i] = dp_test_v4_pkt_from_desc(&v4_pkt_desc);

		test_exp = dp_test_exp_from_desc_m(test_pak[i], pdesc,
						   test_exp, i);
		if (i != queue_limit)
			dp_test_exp_set_fwd_status_m(test_exp, i,
						     DP_TEST_FWD_FORWARDED);
		else
			dp_test_exp_set_fwd_status_m(test_exp, i,
						     DP_TEST_FWD_DROPPED);
	}

	if (vlan_id != 0)
		dp_test_exp_set_vlan_tci(test_exp, vlan_id);

	dp_test_pak_receive_n(test_pak, queue_limit + 1, pdesc->rx_intf,
			      test_exp);

	/* Verify */
	_dp_test_qos_check_subport_tc_counter(ifname, subport, tc, "packets",
					      queue_limit, debug, file, line);
	_dp_test_qos_check_subport_tc_counter(ifname, subport, tc, "dropped", 1,
					      debug, file, line);

	_dp_test_qos_check_queue_counter(ifname, subport, pipe, tc, queue,
					 "packets", queue_limit, debug, file,
					 line);
	_dp_test_qos_check_queue_counter(ifname, subport, pipe, tc, queue,
					 "dropped", 1, debug, file, line);
}

/*
 * Helper functions
 */
void
qos_lib_test_setup(void)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.11", "aa:bb:cc:dd:2:b1");
}

void
qos_lib_test_teardown(void)
{
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.11", "aa:bb:cc:dd:2:b1");
}
