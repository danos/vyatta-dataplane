/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane test npf portmap library
 */

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_portmap_lib.h"

/*
 * Get the json array containing the firewall portmap.  json_object_put should
 * be called once the caller has finished with the returned object.
 */
static json_object *
dp_test_npf_json_fw_portmap_array(void)
{
	json_object *jresp;
	json_object *jarray;
	struct dp_test_json_find_key key[] = { {"apm", NULL},
					       {"portmaps", NULL} };
	char cmd[TEST_MAX_CMD_LEN];
	char *response;
	bool err;

	spush(cmd, sizeof(cmd), "npf-op fw dump-portmap");

	response = dp_test_console_request_w_err(cmd, &err, false);
	if (!response || err)
		return NULL;

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);

	if (!jresp)
		return NULL;

	jarray = dp_test_json_find(jresp, key, ARRAY_SIZE(key));
	json_object_put(jresp);

	return jarray;
}

/*
 * Callback for the dp_test_json_array_iterate function that matches
 * a firewall portmap based on address and (optionally) state.
 */
struct dp_test_npf_json_portmap_match_t {
	const char  *addr;
	const char  *state;
};

static bool
dp_test_npf_json_portmap_match(json_object *jobj, void *arg)
{
	struct dp_test_npf_json_portmap_match_t *vals = arg;
	const char *str;

	if (!dp_test_json_string_field_from_obj(jobj, "address", &str))
		return false;

	if (strcmp(str, vals->addr) != 0)
		return false;

	if (vals->state) {
		if (!dp_test_json_string_field_from_obj(jobj, "state", &str))
			return false;
		if (strcmp(vals->state, str))
			return false;
	}

	return true;
}

/*
 * Return the json object for a specific firewall portmap
 *
 * The returned json object has its ref count incremented, so json_object_put
 * should be called once the caller has finished with the object.
 */
static json_object *
dp_test_npf_json_get_portmap(const char *addr, const char *state)
{
	struct dp_test_npf_json_portmap_match_t arg;
	json_object *jarray, *jobj, *jret = NULL;

	arg.addr = addr;
	arg.state = state;

	jarray = dp_test_npf_json_fw_portmap_array();
	if (!jarray)
		return NULL;

	jobj = dp_test_json_array_iterate(
		jarray,
		&dp_test_npf_json_portmap_match, &arg);

	if (jobj)
		jret = json_object_get(jobj);
	json_object_put(jarray);

	return jret;
}

/*
 * Returns true if the portmap "state" string is retrieved ok
 */
bool
dp_test_npf_json_get_portmap_state(const char *addr, char **state)
{
	json_object *jmap;
	bool rv;
	const char *str;

	jmap = dp_test_npf_json_get_portmap(addr, NULL);
	if (!jmap)
		return false;

	rv = dp_test_json_string_field_from_obj(jmap, "state", &str);
	if (rv)
		*state = strdup(str);

	json_object_put(jmap);
	return rv;
}

/*
 * Returns true if the portmap "used" count is retrieved ok
 */
bool
dp_test_npf_json_get_portmap_used(const char *addr, uint *used)
{
	json_object *jmap, *jprot;
	bool rv;
	const char *prot = "tcp";
	struct dp_test_json_find_key key[] = { {"protocols", NULL},
					       {"protocol", prot } };

	jmap = dp_test_npf_json_get_portmap(addr, NULL);
	if (!jmap)
		return false;

	jprot = dp_test_json_find(jmap, key, ARRAY_SIZE(key));

	if (!jprot) {
		json_object_put(jmap);
		return false;
	}

	rv = dp_test_json_int_field_from_obj(jprot, "ports_used", (int *)used);

	json_object_put(jmap);
	return rv;
}

/*
 * Returns true if the given port is in the portmap ports list.  Only
 * considers "ACTIVE" portmaps.
 */
static bool
dp_test_npf_json_get_portmap_port(const char *addr, uint16_t port)
{
	json_object *jmap, *jarray;
	const char *prot = "tcp";
	struct dp_test_json_find_key key[] = { {"protocols", NULL},
					       {"protocol", prot },
					       {"ports", NULL } };

	jmap = dp_test_npf_json_get_portmap(addr, "ACTIVE");
	if (!jmap)
		return false;

	jarray = dp_test_json_find(jmap, key, ARRAY_SIZE(key));

	if (!jarray) {
		json_object_put(jmap);
		return false;
	}

	if (json_object_get_type(jarray) != json_type_array) {
		json_object_put(jarray);
		json_object_put(jmap);
		return false;
	}

	uint arraylen, i;
	json_object *jvalue;

	arraylen = json_object_array_length(jarray);

	for (i = 0; i < arraylen; i++) {
		jvalue = json_object_array_get_idx(jarray, i);

		if (json_object_get_type(jvalue) != json_type_int)
			continue;

		if (json_object_get_int(jvalue) == (int)port) {
			json_object_put(jmap);
			return true;
		}
	}

	json_object_put(jmap);
	return false;
}

/*
 * Port-map is of the form:
 *
 * {
 *   "apm": {
 *     "section_size": 512,
 *     "hash_memory": 3304,
 *     "portmaps": [
 *       {
 *         "address": "172.0.2.1",
 *         "state": "ACTIVE",
 *         "protocols": [
 *           {
 *             "protocol": "tcp",
 *             "ports_used": 1,
 *             "ports": [
 *               80
 *             ]
 *           },
 *           {
 *             "protocol": "udp",
 *             "ports_used": 0
 *           },
 *           {
 *             "protocol": "other",
 *             "ports_used": 0
 *           }
 *         ]
 *       }
 *     ],
 *     "protocols": [
 *       {
 *         "protocol": "tcp",
 *         "mapping_count": 1
 *       },
 *       {
 *         "protocol": "udp",
 *         "mapping_count": 0
 *       },
 *       {
 *         "protocol": "other",
 *         "mapping_count": 0
 *       }
 *     ]
 *   }
 * }
 */

void
dp_test_npf_print_portmap(void)
{
	json_object *jresp;
	char *response;
	const char *str;
	bool err;

	response = dp_test_console_request_w_err("npf-op fw dump-portmap",
						 &err, true);
	if (!response || err)
		return;
	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));

	free(response);

	if (!jresp)
		return;
	str = json_object_to_json_string_ext(jresp, JSON_C_TO_STRING_PRETTY);
	if (str)
		printf("%s\n", str);
	json_object_put(jresp);
}

/*
 * Verify portmap state and/or used count
 */
void
_dp_test_npf_portmap_verify(const char *addr, const char *state, uint used,
			    const char *file, int line)
{
	json_object *jmap, *jprot;
	bool rv;
	uint ival = 0;
	const char *sval = NULL;
	const char *prot = "tcp";
	struct dp_test_json_find_key key[] = { {"protocols", NULL},
					       {"protocol", prot } };

	jmap = dp_test_npf_json_get_portmap(addr, NULL);
	if (!jmap)
		_dp_test_fail(file, line,
			      "\nFailed to get portmap for %s\n", addr);

	jprot = dp_test_json_find(jmap, key, ARRAY_SIZE(key));

	if (!jprot) {
		_dp_test_fail(file, line,
			      "\nFailed to get protocol info"
			      " for %s\n", addr);
		json_object_put(jmap);
		return;
	}

	rv = dp_test_json_int_field_from_obj(jprot, "ports_used", (int *)&ival);
	if (!rv)
		_dp_test_fail(file, line,
			      "\nFailed to get portmap \"ports_used\""
			      " field for %s\n", addr);

	rv = dp_test_json_string_field_from_obj(jmap, "state", &sval);
	if (!rv)
		_dp_test_fail(file, line,
			      "\nFailed to get portmap \"state\""
			      " field for %s\n", addr);

	if (state)
		_dp_test_fail_unless(!strcmp(sval, state), file, line,
				     "\nPortmap addr %s, exp state \"%s\""
				     " actual state \"%s\"\n",
				     addr, state, sval);

	if (used)
		_dp_test_fail_unless(used == ival, file, line,
				     "\nPortmap addr %s, exp used count %d"
				     " actual count %d\n",
				     addr, used, ival);

	json_object_put(jprot);
	json_object_put(jmap);
}

/*
 * Verify portmap port
 */
void
_dp_test_npf_portmap_port_verify(const char *addr, uint16_t port,
				 bool expected, const char *file, int line)
{
	bool rv;

	rv = dp_test_npf_json_get_portmap_port(addr, port);
	if (expected != rv)
		dp_test_npf_print_portmap();

	_dp_test_fail_unless(expected == rv,
			     file, line, "\n%s %d"
			     " for portmap %s\n",
			     expected ? "Failed to find" : "Found",
			     port, addr);
}
