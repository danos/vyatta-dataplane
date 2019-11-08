/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane test npf ALG library
 */

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_lib.h"
#include "dp_test_lib_intf.h"
#include "dp_test_pktmbuf_lib.h"
#include "dp_test_netlink_state.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_sess_lib.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_alg_lib.h"

/*
 * dp_test_npf_set_alg_port(1, "sip", 5090)
 */
void
_dp_test_npf_set_alg_port(uint iid, const char *name, uint16_t port,
			  const char *file, int line)
{
	char cmd[80];

	spush(cmd, sizeof(cmd), "npf-ut fw alg %u set %s port %u",
	      iid, name, port);
	_dp_test_npf_cmd(cmd, false, file, line);
}

/*
 * dp_test_npf_delete_alg_port(1, "sip", 5090)
 *
 * Deleting a non-default port will cause the default port to be added back
 * for that ALG.
 */
void
_dp_test_npf_delete_alg_port(uint iid, const char *name, uint16_t port,
			     const char *file, int line)
{
	char cmd[80];

	spush(cmd, sizeof(cmd), "npf-ut fw alg %u delete %s port %u",
	      iid, name, port);
	_dp_test_npf_cmd(cmd, false, file, line);
}

/*
 *
 *The output of "npf-op fw dump-alg" looks like:
 *
 *{
 *  "alg":{
 *    "instances":[
 *      {
 *        "vrfid":1,
 *        "tuples":[
 *          {
 *            "alg":"sip",
 *            "protocol":6,
 *            "alg_flags":1,
 *            "flags":5,
 *            "dport":5060
 *          },
 *          {
 *            "alg":"sip",
 *            "timestamp":15,
 *            "protocol":17,
 *            "session":true,
 *            "if_index":106,
 *            "alg_flags":2,
 *            "timeout":15,
 *            "flags":8,
 *            "sport":10000,
 *            "dport":20002,
 *            "srcip":"192.168.1.2",
 *            "dstip":"192.168.1.1",
 *            "alen":4,
 *            "tuple_data":true,
 *            "reap":true,
 *            "id":true
 *          }
 *        ]
 *      }
 *    ]
 *  }
 *}
 *
 */

void
dp_test_npf_print_alg_tuples(const char *desc)
{
	json_object *jresp;
	char *response;
	const char *str;
	bool err;

	if (desc)
		printf("%s\n", desc);

	response = dp_test_console_request_w_err("npf-op fw dump-alg",
						 &err, false);
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
 * Get the ALG tuple instances array
 */
static json_object *
dp_test_npf_json_alg_tuple_instance_array(void)
{
	json_object *jresp, *jarray;
	struct dp_test_json_find_key key[] = { {"alg", NULL},
					       {"instances", NULL} };
	char *response;
	bool err;

	response = dp_test_console_request_w_err("npf-op fw dump-alg",
						 &err, false);
	if (!response || err)
		return NULL;

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);

	if (!jresp)
		return NULL;

	jarray = dp_test_json_find(jresp, key, ARRAY_SIZE(key));
	json_object_put(jresp);

	if (jarray && json_object_get_type(jarray) != json_type_array) {
		json_object_put(jarray);
		return NULL;
	}
	return jarray;
}

/*
 * Get a specific ALG tuple instance
 */
static json_object *
dp_test_npf_json_alg_tuple_instance(uint npf_id)
{
	json_object *jarray, *jobj;

	jarray = dp_test_npf_json_alg_tuple_instance_array();

	if (!jarray) {
		printf("%s: instance array not found\n", __func__);
		return NULL;
	}

	jobj = dp_test_npf_json_array_get_instance(jarray, npf_id);

	return jobj;
}



/*
 * Parameters required to identify a tuple
 *
 * alg, proto and dport are mandatory.  The rest are optional.
 */
struct dp_test_npf_json_tuple_match_t {
	const char	*alg;
	uint		proto;
	uint16_t	dport;
	uint16_t	sport;
	const char	*dstip;
	const char	*srcip;
};

typedef bool (*dp_test_npf_json_tuple_cb)(json_object *jvalue, void *arg);

/*
 * Iterator callback.  Returns true if a tuple is matched.
 */
static bool
dp_test_npf_json_tuple_match(json_object *jobj, void *arg)
{
	struct dp_test_npf_json_tuple_match_t *m = arg;
	const char *str;
	int ival;
	bool rv;

	/*
	 * Mandatory fields
	 */
	rv = dp_test_json_string_field_from_obj(jobj, "alg", &str);
	if (!rv || strcmp(str, m->alg) != 0)
		return false;

	rv = dp_test_json_int_field_from_obj(jobj, "protocol", &ival);
	if (!rv || (uint)ival != m->proto)
		return false;

	rv = dp_test_json_int_field_from_obj(jobj, "dport", &ival);
	if (!rv || (uint16_t)ival != m->dport)
		return false;

	/*
	 * Optional fields
	 */
	if (m->sport) {
		rv = dp_test_json_int_field_from_obj(jobj,
						     "sport", &ival);
		if (rv && (uint16_t)ival != m->sport)
			return false;
	}

	if (m->srcip) {
		rv = dp_test_json_string_field_from_obj(jobj, "srcip", &str);
		if (rv && strcmp(str, m->srcip) != 0)
			return false;
	}

	if (m->dstip) {
		rv = dp_test_json_string_field_from_obj(jobj, "dstip", &str);
		if (rv && strcmp(str, m->dstip) != 0)
			return false;
	}

	return true;
}

static json_object *
dp_test_npf_json_alg_tuple_iterate(json_object *jarray,
				   dp_test_npf_json_tuple_cb cb, void *arg)
{

	json_object *jobj, *jret = NULL;

	if (!jarray)
		return NULL;

	jobj = dp_test_json_array_iterate(jarray, cb, arg);

	if (jobj)
		jret = json_object_get(jobj);

	return jret;
}

static json_object *
dp_test_npf_json_get_alg_tuple(uint npf_id, const char *alg, uint8_t proto,
			       uint16_t dport, uint16_t sport,
			       const char *dstip, const char *srcip)
{
	json_object *jinst, *jobj, *jarray;

	jinst = dp_test_npf_json_alg_tuple_instance(npf_id);
	if (!jinst)
		return NULL;

	/*
	 * The tuple instance contains two objects - "vrfid" and a "tuples"
	 * array
	 */
	struct dp_test_json_find_key key[] = { {"tuples", NULL} };

	jarray = dp_test_json_find(jinst, key, ARRAY_SIZE(key));
	json_object_put(jinst);

	if (!jarray)
		return NULL;

	if (json_object_get_type(jarray) != json_type_array) {
		json_object_put(jarray);
		return NULL;
	}

	struct dp_test_npf_json_tuple_match_t m = {
		.alg = alg,
		.proto = proto,
		.dport = dport,
		.sport = sport,
		.dstip = dstip,
		.srcip = srcip
	};

	jobj = dp_test_npf_json_alg_tuple_iterate(
		jarray, &dp_test_npf_json_tuple_match, &m);
	json_object_put(jarray);

	return jobj;
}

/*
 * Verify an ALG tuple exists
 */
void
_dp_test_npf_alg_tuple_verify(uint npf_id, const char *alg, uint8_t proto,
			      uint16_t dport, uint16_t sport,
			      const char *dstip, const char *srcip,
			      const char *file, int line)
{
	json_object *jobj;
	char str[256];
	int l = 0;

	l += spush(str + l, sizeof(str) - l,
		   "vrfid: %u, \"%s\", proto %u", npf_id, alg, proto);

	if (sport)
		l += spush(str + l, sizeof(str) - l, ", sport: %u", sport);
	if (dport)
		l += spush(str + l, sizeof(str) - l, ", dport: %u", dport);
	if (srcip)
		l += spush(str + l, sizeof(str) - l, ", srcip: %s", srcip);
	if (dstip)
		l += spush(str + l, sizeof(str) - l, ", dstip: %s", dstip);

	jobj = dp_test_npf_json_get_alg_tuple(npf_id, alg, proto, dport,
					      sport, dstip, srcip);

	if (!jobj) {
		dp_test_npf_print_alg_tuples(NULL);
		_dp_test_fail(file, line, "Failed to find tuple: %s", str);
	}
	if (jobj)
		json_object_put(jobj);
}

