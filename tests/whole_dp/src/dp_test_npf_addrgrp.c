/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Whole dataplane tests of npf address-groups
 */
#include <libmnl/libmnl.h>
#include <linux/random.h>
#include <netinet/in.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "npf/npf.h"
#include "npf/npf_if.h"
#include "npf/npf_cache.h"
#include "npf/npf_rule_gen.h"
#include "npf/npf_session.h"
#include "npf/npf_ruleset.h"
#include "npf/npf_ptree.h"
#include "npf/npf_cidr_util.h"
#include "npf/npf_addrgrp.h"
#include "npf/config/npf_config.h"

#include "dp_test.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_controller.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_npf_fw_lib.h"

static bool print_tbls;


/********************************************************************
 * Show
 *******************************************************************/

struct npf_addrgrp_show_ctl {
	char cmd[100];
	int  line;
	bool print;
	uint indent;
};

static void
npf_addrgrp_show_af_list(json_object *jouter, const char *list_name,
			 struct npf_addrgrp_show_ctl *ctl);

static bool
npf_addrgrp_show_af_list_cb(json_object *jobj, void *arg)
{
	int type, mask;
	bool rv;
	struct npf_addrgrp_show_ctl *ctl = arg;

	ctl->indent = ctl->indent + 4;

	if (0) {
		const char *const_str = json_object_to_json_string_ext(
			jobj, JSON_C_TO_STRING_PRETTY);

		if (const_str)
			printf("%s\n", const_str);
	}

	rv = dp_test_json_int_field_from_obj(jobj, "type", &type);
	if (!rv) {
		_dp_test_fail(__FILE__, ctl->line,
			      "type error \"%s\"", ctl->cmd);
		return true;
	}

	if (type == 0) {
		const char *prefix;

		rv = dp_test_json_string_field_from_obj(jobj, "prefix",
							&prefix);
		if (!rv) {
			_dp_test_fail(__FILE__, ctl->line,
				      "prefix error \"%s\"", ctl->cmd);
			return true;
		}

		rv = dp_test_json_int_field_from_obj(jobj, "mask", &mask);
		if (!rv) {
			if (ctl->print)
				printf("%*c%s\n", ctl->indent, ' ', prefix);
		} else {
			if (ctl->print)
				printf("%*c%s/%d\n", ctl->indent, ' ',
				       prefix, mask);
		}
	} else if (type == 1) {
		const char *start, *end;

		rv = dp_test_json_string_field_from_obj(jobj, "start", &start);
		if (!rv) {
			_dp_test_fail(__FILE__, ctl->line,
				      "start error \"%s\"", ctl->cmd);
			return true;
		}
		rv = dp_test_json_string_field_from_obj(jobj, "end", &end);
		if (!rv) {
			_dp_test_fail(__FILE__, ctl->line,
				      "end error \"%s\"", ctl->cmd);
			return true;
		}

		if (ctl->print)
			printf("%*c%s - %s\n", ctl->indent, ' ', start, end);

		npf_addrgrp_show_af_list(jobj, "range-prefixes", ctl);
	}

	ctl->indent = ctl->indent - 4;
	return false;
}

static void
npf_addrgrp_show_af_list(json_object *jouter, const char *list_name,
			 struct npf_addrgrp_show_ctl *ctl)
{
	json_object *jarray;

	if (!json_object_object_get_ex(jouter, list_name, &jarray))
		return;

	ctl->indent = ctl->indent + 4;

	if (ctl->print)
		printf("%*c%s\n", ctl->indent, ' ', list_name);

	_dp_test_fail_unless(json_object_get_type(jarray) == json_type_array,
			     __FILE__, ctl->line,
			     "Not json array (%s) \"%s\"", list_name, ctl->cmd);

	dp_test_json_array_iterate(jarray, npf_addrgrp_show_af_list_cb, ctl);

	ctl->indent = ctl->indent - 4;
}

static void npf_addrgrp_show_af(json_object *jouter, const char *af_name,
				struct npf_addrgrp_show_ctl *ctl)
{
	json_object *jobj;

	if (!json_object_object_get_ex(jouter, af_name, &jobj))
		return;

	ctl->indent = ctl->indent + 4;

	if (ctl->print)
		printf("%*c%s\n", ctl->indent, ' ', af_name);

	_dp_test_fail_unless(json_object_get_type(jobj) == json_type_object,
			     __FILE__, ctl->line,
			     "Not json object (%s) \"%s\"", af_name, ctl->cmd);

	npf_addrgrp_show_af_list(jobj, "list-entries", ctl);
	npf_addrgrp_show_af_list(jobj, "tree", ctl);

	ctl->indent = ctl->indent - 4;
}

/*
 * Show one address group.  'str' is the raw json from the dataplane.
 */
static int
npf_addrgrp_show_one(char *str, struct npf_addrgrp_show_ctl *ctl)
{
	json_object *jobj, *jobj2;
	const char *name;
	int tid;
	bool rv;

	/* Parse json string */
	jobj = parse_json(str, parse_err_str, sizeof(parse_err_str));
	if (!jobj) {
		_dp_test_fail(__FILE__, ctl->line,
			      "Parse json outer \"%s\"", ctl->cmd);
		return -1;
	}

	if (0) {
		const char *const_str = json_object_to_json_string_ext(
			jobj, JSON_C_TO_STRING_PRETTY);

		if (const_str)
			printf("%s\n", const_str);
	}

	/*
	 * If the address-group does not exist then no address-group obj will
	 * be returned.
	 */
	if (!json_object_object_get_ex(jobj, "address-group", &jobj2)) {
		json_object_put(jobj);
		return -1;
	}

	rv = dp_test_json_string_field_from_obj(jobj2, "name", &name);

	_dp_test_fail_unless(rv, __FILE__, ctl->line,
			     "Name json \"%s\"", ctl->cmd);

	/*
	 * Get address-group table ID.  This may be different than the one we
	 * asked for on the for loop.
	 */
	rv = dp_test_json_int_field_from_obj(jobj2, "id", &tid);

	_dp_test_fail_unless(rv, __FILE__, ctl->line,
			     "Table ID json \"%s\"", ctl->cmd);

	if (ctl->print)
		printf("%s\n", name);

	npf_addrgrp_show_af(jobj2, "ipv4", ctl);
	npf_addrgrp_show_af(jobj2, "ipv6", ctl);

	json_object_put(jobj);

	return tid;
}

/*
 * Show one or all address-groups.  Commands is:
 *
 * npf fw show address-group ...
 *
 * If an address-group name is specified then just that address-group is
 * returned.
 *
 * If the user want to fetch *all* groups, then multiple commands are
 * required. Table ID should initially set to 0, and then set it to the last
 * fetched ID plus 1 for subsequent calls.  So for example, the initial call
 * with id 0 might return 2 so the next call should use id 3.
 *
 * e.g.
 * npf_addrgrp_show("ipv4", "all", "all", "GRP1", true);
 */
#define npf_addrgrp_show(a, l, t, n, p)			\
	_npf_addrgrp_show(a, l, t, n, p, __LINE__)

static int
_npf_addrgrp_show(const char *af, const char *list, const char *tree,
		  const char *name, bool print, int line)
{
	char name_or_id[60];
	char *str;
	bool doall = true, err;
	int tid;
	struct npf_addrgrp_show_ctl ctl = {
		.line = line,
		.print = print,
		.indent = 0,
	};

	if (name != NULL && strcmp(name, "all") != 0) {
		/* Show named address-group */
		doall = false;
		spush(name_or_id, sizeof(name_or_id), "name=%s", name);
	} else {
		/* Show all address-groups */
		doall = true;
		spush(name_or_id, sizeof(name_or_id), "id=0");
	}

	do {
		spush(ctl.cmd, sizeof(ctl.cmd),
		      "npf-op fw show address-group af=%s list=%s tree=%s %s",
		      af ? af : "all",
		      list ? list : "all",
		      tree ? tree : "all",
		      name_or_id);

		str = dp_test_console_request_w_err(ctl.cmd, &err, false);

		if (!str || err) {
			if (str)
				free(str);
			_dp_test_fail(__FILE__, ctl.line,
				      "Console req \"%s\"", ctl.cmd);
			return -1;
		}

		tid = npf_addrgrp_show_one(str, &ctl);

		if (tid >= 0 && doall) {
			tid++;
			spush(name_or_id, sizeof(name_or_id), "id=%d", tid);
		}

		free(str);
	} while (tid >= 0 && doall);

	return 0;
}

/*
 * Display the optimal set of prefixes for an address-group
 */
#define npf_addrgrp_show_optimal(af, n, p)	\
	_npf_addrgrp_show_optimal(af, n, p, __LINE__)

static void
_npf_addrgrp_show_optimal(const char *af, const char *name, bool print,
			  int line)
{
	char *str;
	bool err;
	struct npf_addrgrp_show_ctl ctl = {
		.line = line,
		.print = print,
		.indent = 0,
	};

	if (ctl.print)
		printf("Optimal Address-Group Prefixes\n");

	spush(ctl.cmd, sizeof(ctl.cmd),
	      "npf-op fw show address-group optimal af=%s name=%s", af, name);

	str = dp_test_console_request_w_err(ctl.cmd, &err, false);

	if (!str || err) {
		if (str)
			free(str);
		_dp_test_fail(__FILE__, ctl.line,
			      "Console req \"%s\"", ctl.cmd);
		return;
	}

	npf_addrgrp_show_one(str, &ctl);

	free(str);
}


/*
 * Parse a string of format "10.0.0.1", "10.0.2.0/24", "2001::2", or
 * "2001::0/64", and write to a byte array 'key'.  Returns key length > 0 if
 * successful.
 */
static int
dp_test_string2key(const char *string, uint8_t *key, uint8_t *af,
		   uint8_t *mask)
{
	char s[80];
	uint8_t tmp[16];
	uint8_t alen;

	snprintf(s, sizeof(s), "%s", string);

	if (strchr(s, '.')) {
		*af = AF_INET;
		*mask = 32;
		alen = 4;
	} else if (strchr(s, ':')) {
		*af = AF_INET6;
		*mask = 128;
		alen = 16;
	} else {
		printf("Not IP or IPv6\n");
		return 0;
	}
	char *slash = strchr(s, '/');
	int rc;

	if (slash) {
		char *mask_str;
		char *endp;
		ulong len;

		*slash = '\0';
		mask_str = slash + 1;
		len = strtoul(mask_str, &endp, 10);
		if (endp == mask_str || len > *mask) {
			printf("strtoul failed\n");
			return 0;
		}
		*mask = len;
	}

	rc = inet_pton(*af, s, tmp);
	if (rc != 1)
		return 0;

	memcpy(key, tmp, alen);

	/* Restore slash */
	if (slash)
		*slash = '/';

	return alen;
}

/*
 * add 1 to address. Returns 0 if successful, else -1.  Addresses are in
 * network byte order.
 */
static int addr_incr(uint8_t *addr, int alen)
{
	int i;
	uint x, co = 0;

	/* start at least significant byte */
	x = addr[alen-1] + 1;
	addr[alen-1] = x & 0xFF;
	co = x >> 8;

	/* We are done if there is no carry over */
	if (co == 0)
		return 0;

	/* else add carry over to next byte */
	for (i = alen - 2; i >= 0; i--) {
		x = addr[i] + co;
		addr[i] = x & 0xFF;

		co = x >> 8;
		if (co == 0)
			return 0;
	}

	/* fail if there is any carry over */
	return co == 0 ? 0 : -1;
}

/*
 * Compare two addresses.
 *
 * Similar logic to memcmp.  Return -1 if a1 < a2, +1 id a1 > a2, 0 id a1 ==
 * a2.  Addresses are in network byte order.
 */
static int addr_cmp(uint8_t *a1, uint8_t *a2, int alen)
{
	int i;

	/* Start at most significant byte */
	for (i = 0; i < alen; i++) {
		if (a1[i] < a2[i])
			return -1;
		if (a1[i] > a2[i])
			return 1;
	}
	return 0;
}

/*
 * Address-group tree lookup.
 */
static bool
dp_test_addrgrp_tree_lookup(const char *group, const char *addr_str)
{
	uint8_t klen, af, mask;
	npf_addr_t addr;
	uint32_t tid;
	int rc;

	rc = npf_addrgrp_name2tid(group, &tid);
	if (rc < 0 || !npf_addrgrp_tid_valid(tid))
		return false;

	klen = dp_test_string2key(addr_str, addr.s6_addr, &af, &mask);
	dp_test_fail_unless(klen == 4 || klen == 16,
			     "Failed to parse addr %s", addr_str);

	/*
	 * This is the function called from the forwarding-threads.
	 * It does a shortest match lookup to verify address-group membership.
	 */
	rc = npf_addrgrp_lookup((klen == 4) ? AG_IPv4 : AG_IPv6, tid, &addr);
	return rc == 0;
}

/*
 * Add an address-group
 */
static void dp_test_addrgrp_create(const char *group)
{
	char cmd[100];

	spush(cmd, sizeof(cmd), "npf-ut fw table create %s", group);
	dp_test_npf_cmd(cmd, false);
}

/*
 * Delete an address-group
 */
static void dp_test_addrgrp_destroy(const char *group)
{
	char cmd[100];

	spush(cmd, sizeof(cmd), "npf-ut fw table delete %s", group);
	dp_test_npf_cmd(cmd, false);
}

/*
 * Add a prefix to an address-group
 */
static void _dp_test_addrgrp_prefix_add(const char *group,
					const char *pfxmask,
					bool exp,
					const char *file, int line)
{
	uint8_t klen, af, mask;
	npf_addr_t addr;
	char cmd[100];
	char *reply;
	bool err;

	klen = dp_test_string2key(pfxmask, addr.s6_addr, &af, &mask);
	_dp_test_fail_unless(klen == 4 || klen == 16,
			     file, line,
			     "Failed to parse prefix %s", pfxmask);

	spush(cmd, sizeof(cmd), "npf-ut fw table add %s %s", group, pfxmask);

	reply = dp_test_console_request_w_err(cmd, &err, false);

	/*
	 * Returned string for npf commands is just an empty string, which is
	 * of no interest
	 */
	free(reply);

	if (exp)
		_dp_test_fail_unless(!err, file, line,
				     "npf cmd failed: \"%s\"", cmd);
	else
		_dp_test_fail_unless(err, file, line,
				     "npf cmd passed: \"%s\"", cmd);

	/*
	 * If we expected the prefix to be added, then verify it is in the
	 * ptree.
	 */
	if (exp) {
		char addr_str[20];
		bool rv;

		inet_ntop(klen == 4 ? AF_INET : AF_INET6,
			  addr.s6_addr, addr_str, sizeof(addr_str));

		rv = dp_test_addrgrp_tree_lookup(group, addr_str);
		_dp_test_fail_unless(rv, file, line,
				     "Failed to find address %s "
				     "in address-group %s tree",
				     addr_str, group);
	}
}

#define dp_test_addrgrp_prefix_add(g, p, exp)			\
	_dp_test_addrgrp_prefix_add(g, p, exp, __FILE__, __LINE__)

/*
 * Remove a prefix and mask from an address-group.  Note that the prefix may
 * remain in the lists and tree if it has multiple masks.
 */
static void _dp_test_addrgrp_prefix_remove(const char *group,
					   const char *pfxmask,
					   bool exp, bool tree_exp,
					   const char *file, int line)
{
	uint8_t klen, af, mask;
	npf_addr_t addr;
	char cmd[100];
	char *reply;
	bool err;

	klen = dp_test_string2key(pfxmask, addr.s6_addr, &af, &mask);
	_dp_test_fail_unless(klen == 4 || klen == 16,
			     file, line,
			     "Failed to parse prefix %s", pfxmask);


	spush(cmd, sizeof(cmd), "npf-ut fw table remove %s %s", group, pfxmask);

	reply = dp_test_console_request_w_err(cmd, &err, false);

	/*
	 * Returned string for npf commands is just an empty string, which is
	 * of no interest
	 */
	free(reply);

	if (exp)
		_dp_test_fail_unless(!err, file, line,
				     "npf cmd failed: \"%s\"", cmd);
	else
		_dp_test_fail_unless(err, file, line,
				     "npf cmd passed: \"%s\"", cmd);

	/*
	 * If we successfully removed the prefix and mask, then check the
	 * ptree.
	 */
	if (exp) {
		char addr_str[20];
		bool rv;

		inet_ntop(klen == 4 ? AF_INET : AF_INET6,
			  addr.s6_addr, addr_str, sizeof(addr_str));

		rv = dp_test_addrgrp_tree_lookup(group, addr_str);

		/*
		 * Do we still expect this address to be covered by another
		 * entry?
		 */
		if (tree_exp)
			_dp_test_fail_unless(rv, file, line,
					     "Failed to find address %s "
					     "in address-group %s tree",
					     addr_str, group);
		else
			_dp_test_fail_unless(!rv, file, line,
					     "Found address %s "
					     "in address-group %s tree",
					     addr_str, group);
	}
}

#define dp_test_addrgrp_prefix_remove(g, p, exp, te)			\
	_dp_test_addrgrp_prefix_remove(g, p, exp, te, __FILE__, __LINE__)

/*
 * Add an address range to an address-group
 */
static void _dp_test_addrgrp_range_add(const char *group,
				       const char *start_str,
				       const char *end_str,
				       bool exp, bool verify,
				       const char *file, int line)
{
	uint8_t sklen, eklen, af, mask;
	npf_addr_t start, end;
	char cmd[100];
	char *reply;
	bool err;

	sklen = dp_test_string2key(start_str, start.s6_addr, &af, &mask);

	_dp_test_fail_unless(sklen == 4 || sklen == 16,
			     file, line,
			     "Failed to parse start address %s", start_str);

	_dp_test_fail_unless(mask == ((sklen == 4) ? 32 : 128),
			     file, line,
			     "Start addr mask is %u, expected %u",
			     mask, (sklen == 4) ? 32 : 128);

	eklen = dp_test_string2key(end_str, end.s6_addr, &af, &mask);

	_dp_test_fail_unless(eklen == 4 || eklen == 16,
			     file, line,
			     "Failed to parse end address %s", end_str);

	_dp_test_fail_unless(mask == ((eklen == 4) ? 32 : 128),
			     file, line,
			     "End addr mask is %u, expected %u",
			     mask, (eklen == 4) ? 32 : 128);

	_dp_test_fail_unless(eklen == sklen,
			     file, line,
			     "Start and end addresses must be same af");

	spush(cmd, sizeof(cmd), "npf-ut fw table add %s %s %s",
	      group, start_str, end_str);

	reply = dp_test_console_request_w_err(cmd, &err, false);

	/*
	 * Returned string for npf commands is just an empty string, which is
	 * of no interest
	 */
	free(reply);

	if (exp) {
		if (err)
			npf_addrgrp_show("all", "all", "all", group, true);

		_dp_test_fail_unless(!err, file, line,
				     "npf cmd failed: \"%s\"", cmd);
	} else {
		if (!err)
			npf_addrgrp_show("all", "all", "all", group, true);

		_dp_test_fail_unless(err, file, line,
				     "npf cmd passed: \"%s\"", cmd);
	}

	/*
	 * If we expected the address range to be added, then verify all
	 * addresses are in the ptree.
	 *
	 * Note, dont do this for more than 1000 or so addresses as it is very
	 * slow.
	 */
	if (exp && verify) {
		char addr_str[20];
		bool rv;
		npf_addr_t addr;

		/* For each address in range */
		for (memcpy(addr.s6_addr, start.s6_addr, sklen);
		     addr_cmp(addr.s6_addr, end.s6_addr, sklen) <= 0;
		     addr_incr(addr.s6_addr, sklen)) {

			inet_ntop(sklen == 4 ? AF_INET : AF_INET6,
				  addr.s6_addr, addr_str, sizeof(addr_str));

			rv = dp_test_addrgrp_tree_lookup(group, addr_str);
			_dp_test_fail_unless(rv, file, line,
					     "Failed to find address %s "
					     "in address-group %s tree, "
					     "range %s-%s",
					     addr_str, group,
					     start_str, end_str);
		}
	}
}

#define dp_test_addrgrp_range_add(g, s, e, exp, vfy)			\
	_dp_test_addrgrp_range_add(g, s, e, exp, vfy, __FILE__, __LINE__)


/*
 * tree_exp - true if we expect one or more addresses to remain in ptree after
 * removal of range.
 */
static void _dp_test_addrgrp_range_remove(const char *group,
					  const char *start_str,
					  const char *end_str,
					  bool exp, bool tree_exp,
					  const char *file, int line)
{
	uint8_t sklen, eklen, af, mask;
	npf_addr_t start, end;
	char cmd[100];
	char *reply;
	bool err;

	sklen = dp_test_string2key(start_str, start.s6_addr, &af, &mask);

	_dp_test_fail_unless(sklen == 4 || sklen == 16,
			     file, line,
			     "Failed to parse start address %s", start_str);

	_dp_test_fail_unless(mask == ((sklen == 4) ? 32 : 128),
			     file, line,
			     "Start addr mask is %u, expected %u",
			     mask, (sklen == 4) ? 32 : 128);

	eklen = dp_test_string2key(end_str, end.s6_addr, &af, &mask);

	_dp_test_fail_unless(eklen == 4 || eklen == 16,
			     file, line,
			     "Failed to parse end address %s", end_str);

	_dp_test_fail_unless(mask == ((eklen == 4) ? 32 : 128),
			     file, line,
			     "End addr mask is %u, expected %u",
			     mask, (eklen == 4) ? 32 : 128);

	_dp_test_fail_unless(eklen == sklen,
			     file, line,
			     "Start and end addresses must be same af");

	spush(cmd, sizeof(cmd), "npf-ut fw table remove %s %s %s",
	      group, start_str, end_str);

	reply = dp_test_console_request_w_err(cmd, &err, false);

	/*
	 * Returned string for npf commands is just an empty string, which is
	 * of no interest
	 */
	free(reply);

	if (exp) {
		if (err)
			npf_addrgrp_show("all", "all", "all", group, true);

		_dp_test_fail_unless(!err, file, line,
				     "npf cmd failed: \"%s\"", cmd);
	} else {
		if (!err)
			npf_addrgrp_show("all", "all", "all", group, true);

		_dp_test_fail_unless(err, file, line,
				     "npf cmd passed: \"%s\"", cmd);
	}

	/*
	 * If we expected the address range to be removed *and* one or more
	 * addresses in the range is *not* covered by another entry, then
	 * verify all addresses are removed from the ptree.
	 */
	if (exp && !tree_exp) {
		char addr_str[20];
		bool rv;
		npf_addr_t addr;

		/* For each address in range */
		for (memcpy(addr.s6_addr, start.s6_addr, sklen);
		     addr_cmp(addr.s6_addr, end.s6_addr, sklen) <= 0;
		     addr_incr(addr.s6_addr, sklen)) {

			inet_ntop(sklen == 4 ? AF_INET : AF_INET6,
				  addr.s6_addr, addr_str, sizeof(addr_str));

			rv = dp_test_addrgrp_tree_lookup(group, addr_str);

			_dp_test_fail_unless(!rv, file, line,
					     "Found address %s "
					     "in address-group %s tree, "
					     "range %s-%s",
					     addr_str, group,
					     start_str, end_str);
		}
	}
}

#define dp_test_addrgrp_range_remove(g, s, e, exp, te)			\
	_dp_test_addrgrp_range_remove(g, s, e, exp, te, __FILE__, __LINE__)


/********************************************************************
 * Tests
 *******************************************************************/

DP_DECL_TEST_SUITE(npf_addrgrp);


/*
 * Tests address-group creation, lookup and deletion
 */
DP_DECL_TEST_CASE(npf_addrgrp, npf_addrgrp1, NULL, NULL);
DP_START_TEST(npf_addrgrp1, test1)
{
	int rc;
	char name[20];
	uint i;
	struct npf_addrgrp *at[10] = {0};
	struct npf_addrgrp *tmp;

	for (i = 0; i < ARRAY_SIZE(at); i++) {
		snprintf(name, sizeof(name), "GRP%d", i);

		dp_test_addrgrp_create(name);

		at[i] = npf_addrgrp_lookup_name(name);
		dp_test_fail_unless(at[i] != NULL, "npf_addrgrp_lookup_name");

		dp_test_fail_unless(npf_addrgrp_ntables() == i + 1,
				    "npf_addrgrp_ntables %u",
				    npf_addrgrp_ntables());
	}


	dp_test_addrgrp_destroy("GRP2");

	tmp = npf_addrgrp_lookup_name("GRP2");
	dp_test_fail_unless(tmp == NULL, "npf_addrgrp_lookup_name");

	/* Destroy addr group tableset while it has entries */
	rc = npf_addrgrp_tbl_destroy();
	dp_test_fail_unless(rc == 0, "npf_addrgrp_tbl_destroy");

} DP_END_TEST;


/*
 * Tests adding and removing entries from an address-group.
 *
 * The show output should be as follows:
 *
 * ADDRGRP2
 *   IPv4 List
 *     10.0.0.0/16
 *     10.0.0.0/17
 *     10.0.0.0/20
 *     10.0.0.0/24
 *     10.0.0.0/25
 *     10.0.0.2 - 10.0.0.4
 *       10.0.0.2/31
 *       10.0.0.4/32
 *     10.0.0.10 - 10.0.0.15
 *       10.0.0.10/31
 *       10.0.0.12/30
 *     10.0.0.25/32
 *     10.0.0.100/30
 *     10.0.0.100/32
 *     10.0.0.101/32
 *     198.1.128.0/17
 *     198.192.0.0/10
 *   IPv4 Tree
 *     10.0.0.0/16
 *     10.0.0.2/31
 *     10.0.0.4/32
 *     10.0.0.10/31
 *     10.0.0.12/30
 *     10.0.0.25/32
 *     10.0.0.100/30
 *     10.0.0.101/32
 *     198.1.128.0/17
 *     198.192.0.0/10
 *
 * ADDRGRP2 optimal set of netblocks
 *   IPv4
 *     10.0.0.0/16
 *     198.1.128.0/17
 *     198.192.0.0/10
 *
 */
DP_DECL_TEST_CASE(npf_addrgrp, npf_addrgrp2, NULL, NULL);
DP_START_TEST(npf_addrgrp2, test1)
{
	uint64_t naddrs;
	int tid;
	bool rv;
	int rc;

	dp_test_addrgrp_create("ADDRGRP2");

	rc = npf_addrgrp_name2tid("ADDRGRP2", (uint32_t *)&tid);
	dp_test_fail_unless(rc == 0, "npf_addrgrp_name2tid");

	dp_test_addrgrp_prefix_add("ADDRGRP2", "10.0.0.25/32", true);

	naddrs = npf_addrgrp_naddrs(AG_IPv4, tid, false);
	dp_test_fail_unless(naddrs == 1,
			    "%s contains %lu addresses, expected 1",
			    "ADDRGRP2", naddrs);

	dp_test_addrgrp_range_add("ADDRGRP2", "10.0.0.10", "10.0.0.15",
				  true, true);

	naddrs = npf_addrgrp_naddrs(AG_IPv4, tid, false);
	dp_test_fail_unless(naddrs == 7,
			    "%s contains %lu addresses, expected 7",
			    "ADDRGRP2", naddrs);

	rv = dp_test_addrgrp_tree_lookup("ADDRGRP2", "10.0.0.9");
	dp_test_fail_unless(!rv, "Found 10.0.0.9 in ptree");

	rv = dp_test_addrgrp_tree_lookup("ADDRGRP2", "10.0.0.16");
	dp_test_fail_unless(!rv, "Found 10.0.0.16 in ptree");

	/*
	 * Insert, remove, then re-insert prefix 10.0.0.100/32
	 */
	dp_test_addrgrp_prefix_add("ADDRGRP2", "10.0.0.100/32", true);
	dp_test_addrgrp_prefix_remove("ADDRGRP2", "10.0.0.100/32",
				      true, false);
	dp_test_addrgrp_prefix_add("ADDRGRP2", "10.0.0.100/32", true);

	/*
	 * Insert, remove, then re-insert prefix 10.0.0.100/30
	 */
	dp_test_addrgrp_prefix_add("ADDRGRP2", "10.0.0.100/30", true);
	dp_test_addrgrp_prefix_remove("ADDRGRP2", "10.0.0.100/30", true, true);
	dp_test_addrgrp_prefix_add("ADDRGRP2", "10.0.0.100/30", true);

	/*
	 * Insert, remove, then re-insert range 10.0.0.2 - 10.0.0.4
	 */
	dp_test_addrgrp_range_add("ADDRGRP2", "10.0.0.2", "10.0.0.4",
				  true, true);
	dp_test_addrgrp_range_remove("ADDRGRP2", "10.0.0.2", "10.0.0.4",
				     true, false);
	dp_test_addrgrp_range_add("ADDRGRP2", "10.0.0.2", "10.0.0.4",
				  true, true);

	/*
	 * Insert 10.0.0.101/32
	 */
	dp_test_addrgrp_prefix_add("ADDRGRP2", "10.0.0.101/32", true);

	/*
	 * Insert 198.192.0.0/10
	 */
	dp_test_addrgrp_prefix_add("ADDRGRP2", "198.192.0.0/10", true);

	/*
	 * Insert 198.1.128.0/17
	 */
	dp_test_addrgrp_prefix_add("ADDRGRP2", "198.1.128.0/17", true);

	/*
	 *  Multiple masks for same prefix, 12.0.0.0
	 */
	dp_test_addrgrp_prefix_add("ADDRGRP2", "12.0.0.0/24", true);
	dp_test_addrgrp_prefix_add("ADDRGRP2", "12.0.0.0/16", true);
	dp_test_addrgrp_prefix_add("ADDRGRP2", "12.0.0.0/26", true);
	dp_test_addrgrp_prefix_add("ADDRGRP2", "12.0.0.0/18", true);
	dp_test_addrgrp_prefix_add("ADDRGRP2", "12.0.0.0/20", true);
	dp_test_addrgrp_prefix_add("ADDRGRP2", "12.0.0.0/12", true);
	dp_test_addrgrp_prefix_add("ADDRGRP2", "12.0.0.0/25", true);

	/* No more masks should be allowed for this prefix */
	dp_test_addrgrp_prefix_add("ADDRGRP2", "12.0.0.0/13", false);

	/* Remove shortest, longest, and in-between prefix */
	dp_test_addrgrp_prefix_remove("ADDRGRP2", "12.0.0.0/12", true, true);
	dp_test_addrgrp_prefix_remove("ADDRGRP2", "12.0.0.0/26", true, true);
	dp_test_addrgrp_prefix_remove("ADDRGRP2", "12.0.0.0/18", true, true);

	npf_addrgrp_show("all", "all", "all", "ADDRGRP2", print_tbls);
	npf_addrgrp_show_optimal("ipv4", "ADDRGRP2", print_tbls);

	/*
	 * Test insert failures
	 */

	/* host bits are set */
	dp_test_addrgrp_prefix_add("ADDRGRP2", "0.0.0.2/30", false);

	/* Duplicate of a multiple-mask entry */
	dp_test_addrgrp_prefix_add("ADDRGRP2", "10.0.0.0/20", false);

	/* Host prefix overlaps a range */
	dp_test_addrgrp_prefix_add("ADDRGRP2", "10.0.0.10/32", false);

	/* Range overlaps a host prefix */
	dp_test_addrgrp_range_add("ADDRGRP2", "10.0.0.24", "10.0.0.26",
				  false, false);

	npf_addrgrp_show("all", "all", "all", "ADDRGRP2", print_tbls);

	/*
	 * Be nice, and remove all entries
	 */
	dp_test_addrgrp_range_remove("ADDRGRP2", "10.0.0.2", "10.0.0.4",
				     true, true);
	dp_test_addrgrp_range_remove("ADDRGRP2", "10.0.0.10", "10.0.0.15",
				     true, true);
	dp_test_addrgrp_prefix_remove("ADDRGRP2", "12.0.0.0/16", true, true);
	dp_test_addrgrp_prefix_remove("ADDRGRP2", "12.0.0.0/20", true, true);
	dp_test_addrgrp_prefix_remove("ADDRGRP2", "12.0.0.0/24", true, true);
	dp_test_addrgrp_prefix_remove("ADDRGRP2", "12.0.0.0/25", true, false);
	dp_test_addrgrp_prefix_remove("ADDRGRP2", "10.0.0.25/32", true, false);
	dp_test_addrgrp_prefix_remove("ADDRGRP2", "10.0.0.100/30", true, true);
	dp_test_addrgrp_prefix_remove("ADDRGRP2", "10.0.0.100/32", true, false);
	dp_test_addrgrp_prefix_remove("ADDRGRP2", "10.0.0.101/32", true, false);
	dp_test_addrgrp_prefix_remove("ADDRGRP2", "198.1.128.0/17",
				      true, false);
	dp_test_addrgrp_prefix_remove("ADDRGRP2", "198.192.0.0/10",
				      true, false);

	dp_test_fail_unless(npf_addrgrp_nentries("ADDRGRP2") == 0,
			    "ADDRGRP2 not empty");

	dp_test_addrgrp_destroy("ADDRGRP2");

} DP_END_TEST;


/*
 * Tests adding and removing entries from an IPv6 address-group
 */
DP_DECL_TEST_CASE(npf_addrgrp, npf_addrgrp3, NULL, NULL);
DP_START_TEST(npf_addrgrp3, test1)
{
	dp_test_addrgrp_create("ADDRGRP3");

	dp_test_addrgrp_prefix_add("ADDRGRP3", "2002:2:2::1/128", true);
	dp_test_addrgrp_range_add("ADDRGRP3", "2002:2:3::1", "2002:2:3::20",
				  true, true);
	dp_test_addrgrp_prefix_add("ADDRGRP3", "2002:2:3::21/128", true);

	dp_test_addrgrp_range_add("ADDRGRP3",
				  "2002:2:3:1000:0:0:0:0",
				  "2002:2:4:2000:0:0:0:0",
				  true, false);

	/* display lists */
	npf_addrgrp_show("all", "all", "all", "ADDRGRP3", print_tbls);
	npf_addrgrp_show_optimal("ipv6", "ADDRGRP3", print_tbls);

	dp_test_addrgrp_destroy("ADDRGRP3");

} DP_END_TEST;


/*
 * Load up with multiple address groups, with multiple entries, then destroy
 * the address-group tableset
 */
DP_DECL_TEST_CASE(npf_addrgrp, npf_addrgrp4, NULL, NULL);
DP_START_TEST(npf_addrgrp4, test1)
{
	int rc;

	dp_test_addrgrp_create("ADDRGRP4");

	dp_test_addrgrp_prefix_add("ADDRGRP4", "10.0.0.25/32", true);
	dp_test_addrgrp_range_add("ADDRGRP4", "10.0.0.10", "10.0.0.15",
				  true, true);

	dp_test_addrgrp_create("ADDRGRP5");

	dp_test_addrgrp_prefix_add("ADDRGRP4", "15.0.0.25/32", true);
	dp_test_addrgrp_range_add("ADDRGRP4", "15.0.0.10", "15.0.0.15",
				  true, true);

	npf_addrgrp_show("ipv4", "all", "all", "ADDRGRP4", print_tbls);
	npf_addrgrp_show("ipv4", "all", "all", "ADDRGRP5", print_tbls);

	/*
	 * Destroy everything
	 */
	rc = npf_addrgrp_tbl_destroy();
	dp_test_fail_unless(rc == 0, "npf_addrgrp_tbl_destroy");

} DP_END_TEST;


/*
 * Tests address ranges
 */
DP_DECL_TEST_CASE(npf_addrgrp, npf_addrgrp5, NULL, NULL);
DP_START_TEST(npf_addrgrp5, test1)
{
	struct npf_if *nif;
	struct npf_config *npf_config;
	char real_ifname[IFNAMSIZ];
	const npf_ruleset_t *rlset;
	npf_decision_t decision;
	struct rte_mbuf  *pkt4;
	struct ifnet *ifp;
	int len = 22;

	struct dp_test_npf_rule_t ipv4_rules1[] = {
		{
			.rule = "10",
			.pass = PASS,
			.stateful = STATELESS,
			.npf = "proto-final=17 dst-addr-group=ADDR_GRP0"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t ipv4_rset1 = {
		.rstype = "fw-in",
		.name   = "IPV4_FW1",
		.enable = 1,
		.attach_point = "dp1T0",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = ipv4_rules1
	};

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "250.250.250.251/24");

	/* Get interface */
	dp_test_intf_real("dp1T0", real_ifname);
	ifp = dp_ifnet_byifname(real_ifname);
	dp_test_fail_unless(ifp, "ifp for %s", real_ifname);

	dp_test_npf_fw_addr_group_add("ADDR_GRP0");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP0", "1.0.0.0/24");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP0", "1.1.1.1");
	dp_test_npf_fw_addr_group_range_add("ADDR_GRP0", "1.1.1.3", "1.1.1.6");

	dp_test_npf_fw_addr_group_add("ADDR_GRP1");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP1", "4.0.0.0/24");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP1", "4.0.0.0/20");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP1", "5.0.0.0/24");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP1", "6.0.0.1/32");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP1", "6.0.0.2/32");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP1", "6.0.0.3/32");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP1", "6.0.0.4/32");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP1", "6.0.0.5/32");
	dp_test_npf_fw_addr_group_range_add("ADDR_GRP1", "7.1.1.3", "7.1.1.6");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP1", "2001:1:1::/64");

	npf_addrgrp_show("all", "all", "all", "all", print_tbls);
	npf_addrgrp_show_optimal("ipv4", "ADDR_GRP1", print_tbls);

	dp_test_npf_fw_addr_group_del("ADDR_GRP1");

	/* Add IPv4 ruleset 1 */
	dp_test_npf_fw_add(&ipv4_rset1, false);

	/* Get npf config pointer */
	nif = rcu_dereference(ifp->if_npf);
	npf_config = npf_if_conf(nif);
	dp_test_fail_unless(npf_config, "npf config for %s", real_ifname);

	/*  Get ruleset pointer */
	rlset = npf_get_ruleset(npf_config, NPF_RS_FW_IN);
	dp_test_fail_unless(rlset, "fw ruleset for %s", real_ifname);

	/* IPv4 packet */
	pkt4 = dp_test_create_udp_ipv4_pak("250.250.250.250", "1.0.0.1",
					   1, 1, 1, &len);
	dp_test_fail_unless(pkt4, "IPv4 packet create\n");

	dp_test_pktmbuf_eth_init(pkt4, "00:00:00:00:00:02", "00:00:00:00:00:01",
				 RTE_ETHER_TYPE_IPV4);

	uint16_t exp_npc4 = NPC_GROUPER | NPC_L4PORTS | NPC_IP4;
	uint i;

	/*
	 * Test data
	 */
	struct ag_prefix {
		const char *addr;
		npf_decision_t decsn;
	} test_arr1[] = {
		{ "1.0.0.1", NPF_DECISION_PASS },
		{ "1.0.0.255", NPF_DECISION_PASS },
		{ "1.0.1.0", NPF_DECISION_BLOCK },
		{ "1.1.1.1", NPF_DECISION_PASS },
		{ "1.1.1.2", NPF_DECISION_BLOCK },
		{ "1.1.1.3", NPF_DECISION_PASS },
		{ "1.1.1.4", NPF_DECISION_PASS },
		{ "1.1.1.5", NPF_DECISION_PASS },
		{ "1.1.1.6", NPF_DECISION_PASS },
		{ "1.1.1.7", NPF_DECISION_BLOCK },
	};
	struct iphdr *ip = dp_pktmbuf_mtol3(pkt4, struct iphdr *);

	/*
	 * Lookup addresses in test_arr1 and verify decision
	 */
	for (i = 0; i < ARRAY_SIZE(test_arr1); i++) {
		uint32_t addr;
		int rc;

		rc = inet_pton(AF_INET, test_arr1[i].addr, &addr);
		dp_test_fail_unless(rc == 1, "Couldn't create ip address");
		ip->daddr = addr;

		/* cache + ruleset inspect */
		decision = dp_test_npf_raw(0, pkt4, rlset, ifp,
					   PFIL_IN, exp_npc4);

		dp_test_fail_unless(decision == test_arr1[i].decsn,
				    "%s Expected %s, got %s",
				    test_arr1[i].addr,
				    npf_decision_str(test_arr1[i].decsn),
				    npf_decision_str(decision));
	}

	/*
	 * Delete all entries and check lookup fails
	 */
	dp_test_npf_fw_addr_group_addr_del("ADDR_GRP0", "1.0.0.0/24");
	dp_test_npf_fw_addr_group_addr_del("ADDR_GRP0", "1.1.1.1");
	dp_test_npf_fw_addr_group_range_del("ADDR_GRP0", "1.1.1.3", "1.1.1.6");

	for (i = 0; i < ARRAY_SIZE(test_arr1); i++) {
		uint32_t addr;
		int rc;

		rc = inet_pton(AF_INET, test_arr1[i].addr, &addr);
		dp_test_fail_unless(rc == 1, "Couldn't create ip address");
		ip->daddr = addr;

		/* cache + ruleset inspect */
		decision = dp_test_npf_raw(0, pkt4, rlset, ifp,
					   PFIL_IN, exp_npc4);

		dp_test_fail_unless(decision == NPF_DECISION_BLOCK,
				    "%s Expected %s, got %s",
				    test_arr1[i].addr,
				    npf_decision_str(NPF_DECISION_BLOCK),
				    npf_decision_str(decision));
	}

	/*
	 * Cleanup
	 */
	rte_pktmbuf_free(pkt4);
	dp_test_npf_fw_del(&ipv4_rset1, false);

	dp_test_npf_fw_addr_group_del("ADDR_GRP0");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "250.250.250.251/24");

} DP_END_TEST;


/*
 * Tests changing an address group range
 */
DP_DECL_TEST_CASE(npf_addrgrp, npf_addrgrp6, NULL, NULL);
DP_START_TEST(npf_addrgrp6, test1)
{
	dp_test_addrgrp_create("GRP1");

	dp_test_addrgrp_range_add("GRP1", "10.0.0.9", "10.0.0.16",
				  true, true);

	/*
	 * First three derived prefixes are identical.  Last prefix changes from
	 * 10.0.0.16/32 to 10.0.0.16/29, and 10.0.0.24/31 is added.
	 */
	dp_test_addrgrp_range_add("GRP1", "10.0.0.9", "10.0.0.25",
				  true, true);

	/*
	 * First three derived prefixes are identical.
	 */
	dp_test_addrgrp_range_add("GRP1", "10.0.0.9", "10.0.0.16",
				  true, true);

	dp_test_addrgrp_range_remove("GRP1", "10.0.0.9", "10.0.0.16",
				     true, false);

	dp_test_addrgrp_destroy("GRP1");
} DP_END_TEST;

/*
 * Tests prefix 0.0.0.0/0 in an address-group
 */
DP_DECL_TEST_CASE(npf_addrgrp, npf_addrgrp7, NULL, NULL);
DP_START_TEST(npf_addrgrp7, test1)
{
	struct npf_if *nif;
	struct npf_config *npf_config;
	char real_ifname[IFNAMSIZ];
	const npf_ruleset_t *rlset;
	npf_decision_t decision;
	struct rte_mbuf  *pkt4;
	struct ifnet *ifp;
	int len = 22;

	struct dp_test_npf_rule_t ipv4_rules1[] = {
		{
			.rule = "10",
			.pass = PASS,
			.stateful = STATELESS,
			.npf = "dst-addr-group=ADDR_GRP0"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t ipv4_rset1 = {
		.rstype = "fw-in",
		.name   = "IPV4_FW1",
		.enable = 1,
		.attach_point = "dp1T0",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = ipv4_rules1
	};

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "250.250.250.251/24");

	/* Get interface */
	dp_test_intf_real("dp1T0", real_ifname);
	ifp = dp_ifnet_byifname(real_ifname);
	dp_test_fail_unless(ifp, "ifp for %s", real_ifname);

	dp_test_npf_fw_addr_group_add("ADDR_GRP0");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP0", "0.0.0.0/0");

	npf_addrgrp_show("all", "all", "all", "all", print_tbls);

	/* Add IPv4 ruleset 1 */
	dp_test_npf_fw_add(&ipv4_rset1, false);

	/* Get npf config pointer */
	nif = rcu_dereference(ifp->if_npf);
	npf_config = npf_if_conf(nif);
	dp_test_fail_unless(npf_config, "npf config for %s", real_ifname);

	/*  Get ruleset pointer */
	rlset = npf_get_ruleset(npf_config, NPF_RS_FW_IN);
	dp_test_fail_unless(rlset, "fw ruleset for %s", real_ifname);

	/* IPv4 packet */
	pkt4 = dp_test_create_udp_ipv4_pak("250.250.250.250", "1.0.0.1",
					   1, 1, 1, &len);
	dp_test_fail_unless(pkt4, "IPv4 packet create\n");

	dp_test_pktmbuf_eth_init(pkt4, "00:00:00:00:00:02", "00:00:00:00:00:01",
				 RTE_ETHER_TYPE_IPV4);

	uint16_t exp_npc4 = NPC_GROUPER | NPC_L4PORTS | NPC_IP4;
	uint32_t addr;
	int rc;

	/*
	 * Lookup address and verify decision
	 */
	rc = inet_pton(AF_INET, "1.0.0.1", &addr);
	dp_test_fail_unless(rc == 1, "Couldn't create ip address");

	/* cache + ruleset inspect */
	decision = dp_test_npf_raw(0, pkt4, rlset, ifp, PFIL_IN, exp_npc4);

	dp_test_fail_unless(decision == NPF_DECISION_PASS,
			    "%s Expected %s, got %s",
			    "1.0.0.1",
			    npf_decision_str(NPF_DECISION_PASS),
			    npf_decision_str(decision));

	/*
	 * Delete all entries and check lookup fails
	 */
	dp_test_npf_fw_addr_group_addr_del("ADDR_GRP0", "0.0.0.0/0");

	/* cache + ruleset inspect */
	decision = dp_test_npf_raw(0, pkt4, rlset, ifp, PFIL_IN, exp_npc4);

	dp_test_fail_unless(decision == NPF_DECISION_BLOCK,
			    "%s Expected %s, got %s",
			    "1.0.0.1",
			    npf_decision_str(NPF_DECISION_BLOCK),
			    npf_decision_str(decision));

	/*
	 * Cleanup
	 */
	rte_pktmbuf_free(pkt4);
	dp_test_npf_fw_del(&ipv4_rset1, false);

	dp_test_npf_fw_addr_group_del("ADDR_GRP0");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "250.250.250.251/24");

} DP_END_TEST;

/*
 * Tests prefix ::/0 in an address-group
 */
DP_DECL_TEST_CASE(npf_addrgrp, npf_addrgrp8, NULL, NULL);
DP_START_TEST(npf_addrgrp8, test1)
{
	struct npf_if *nif;
	struct npf_config *npf_config;
	char real_ifname[IFNAMSIZ];
	const npf_ruleset_t *rlset;
	npf_decision_t decision;
	struct rte_mbuf  *pkt6;
	struct ifnet *ifp;
	int len = 22;

	struct dp_test_npf_rule_t ipv6_rules1[] = {
		{
			.rule = "10",
			.pass = PASS,
			.stateful = STATELESS,
			.npf = "dst-addr-group=ADDR_GRP0"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t ipv6_rset1 = {
		.rstype = "fw-in",
		.name   = "IPV6_FW1",
		.enable = 1,
		.attach_point = "dp1T0",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = ipv6_rules1
	};

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:2:2::3/96");

	/* Get interface */
	dp_test_intf_real("dp1T0", real_ifname);
	ifp = dp_ifnet_byifname(real_ifname);
	dp_test_fail_unless(ifp, "ifp for %s", real_ifname);

	dp_test_npf_fw_addr_group_add("ADDR_GRP0");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP0", "::/0");

	npf_addrgrp_show("all", "all", "all", "all", print_tbls);

	/* Add IPv6 ruleset 1 */
	dp_test_npf_fw_add(&ipv6_rset1, false);

	/* Get npf config pointer */
	nif = rcu_dereference(ifp->if_npf);
	npf_config = npf_if_conf(nif);
	dp_test_fail_unless(npf_config, "npf config for %s", real_ifname);

	/*  Get ruleset pointer */
	rlset = npf_get_ruleset(npf_config, NPF_RS_FW_IN);
	dp_test_fail_unless(rlset, "fw ruleset for %s", real_ifname);

	/* IPv6 packet */
	pkt6 = dp_test_create_udp_ipv6_pak("2002:2:2::2", "2001:2:2::1",
					   1, 1, 1, &len);
	dp_test_fail_unless(pkt6, "IPv6 packet create\n");

	dp_test_pktmbuf_eth_init(pkt6, "00:00:00:00:00:02", "00:00:00:00:00:01",
				 RTE_ETHER_TYPE_IPV6);

	uint16_t exp_npc6 = NPC_GROUPER | NPC_L4PORTS | NPC_IP6;
	npf_addr_t addr;
	int rc;

	/*
	 * Lookup address and verify decision
	 */
	rc = inet_pton(AF_INET6, "2001:2:2::1", &addr);
	dp_test_fail_unless(rc == 1, "Couldn't create ipv6 address");

	/* cache + ruleset inspect */
	decision = dp_test_npf_raw(0, pkt6, rlset, ifp, PFIL_IN, exp_npc6);

	dp_test_fail_unless(decision == NPF_DECISION_PASS,
			    "%s Expected %s, got %s",
			    "2001:2:2::1",
			    npf_decision_str(NPF_DECISION_PASS),
			    npf_decision_str(decision));

	/*
	 * Delete all entries and check lookup fails
	 */
	dp_test_npf_fw_addr_group_addr_del("ADDR_GRP0", "::/0");

	/* cache + ruleset inspect */
	decision = dp_test_npf_raw(0, pkt6, rlset, ifp, PFIL_IN, exp_npc6);

	dp_test_fail_unless(decision == NPF_DECISION_BLOCK,
			    "%s Expected %s, got %s",
			    "2001:2:2::1",
			    npf_decision_str(NPF_DECISION_BLOCK),
			    npf_decision_str(decision));

	/*
	 * Cleanup
	 */
	rte_pktmbuf_free(pkt6);
	dp_test_npf_fw_del(&ipv6_rset1, false);

	dp_test_npf_fw_addr_group_del("ADDR_GRP0");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:2:2::3/96");

} DP_END_TEST;


/*
 * npf_addrgrp9
 *
 * Tests that we allow both 10.0.0.1 and 10.0.0.1/32 entries in the same
 * address group, and when one is removed the other will remain in the ptree.
 */
DP_DECL_TEST_CASE(npf_addrgrp, npf_addrgrp9, NULL, NULL);
DP_START_TEST(npf_addrgrp9, test1)
{
	uint64_t naddrs;
	int tid;
	int rc;
	bool rv;

	/* Add address group */
	dp_test_addrgrp_create("ADDRGRP9");
	rc = npf_addrgrp_name2tid("ADDRGRP9", (uint32_t *)&tid);
	dp_test_fail_unless(rc == 0, "npf_addrgrp_name2tid");

	/* Add 10.0.0.25 */
	dp_test_addrgrp_prefix_add("ADDRGRP9", "10.0.0.25", true);

	/* Expect 1 entry */
	naddrs = npf_addrgrp_naddrs(AG_IPv4, tid, false);
	dp_test_fail_unless(naddrs == 1, "expected 1, got %lu", naddrs);

	/* Is 10.0.0.25 in ptree? */
	rv = dp_test_addrgrp_tree_lookup("ADDRGRP9", "10.0.0.25");
	dp_test_fail_unless(rv, "10.0.0.25 not found in ptree");

	/* Add 10.0.0.25/32 */
	dp_test_addrgrp_prefix_add("ADDRGRP9", "10.0.0.25/32", true);

	/* Still expect 1 entry */
	naddrs = npf_addrgrp_naddrs(AG_IPv4, tid, false);
	dp_test_fail_unless(naddrs == 1, "expected 1, got %lu", naddrs);

	/* Remove 10.0.0.25/32 */
	dp_test_addrgrp_prefix_remove("ADDRGRP9", "10.0.0.25/32", true, true);

	/* Still expect 1 entry */
	naddrs = npf_addrgrp_naddrs(AG_IPv4, tid, false);
	dp_test_fail_unless(naddrs == 1, "expected 1, got %lu", naddrs);

	/* Is 10.0.0.25 in ptree? */
	rv = dp_test_addrgrp_tree_lookup("ADDRGRP9", "10.0.0.25");
	dp_test_fail_unless(rv, "10.0.0.25 not found in ptree");

	/* Remove 10.0.0.25 */
	dp_test_addrgrp_prefix_remove("ADDRGRP9", "10.0.0.25", true, false);

	/* Expect 0 entries */
	naddrs = npf_addrgrp_naddrs(AG_IPv4, tid, false);
	dp_test_fail_unless(naddrs == 0, "expected 0, got %lu", naddrs);

	/* Is 10.0.0.25 in ptree? */
	rv = dp_test_addrgrp_tree_lookup("ADDRGRP9", "10.0.0.25");
	dp_test_fail_unless(!rv, "10.0.0.25 found in ptree");

	/*
	 * Repeat, but do add and delete in different order
	 */

	/* Add 10.0.0.25/32 */
	dp_test_addrgrp_prefix_add("ADDRGRP9", "10.0.0.25/32", true);

	/* Expect 1 entry */
	naddrs = npf_addrgrp_naddrs(AG_IPv4, tid, false);
	dp_test_fail_unless(naddrs == 1, "expected 1, got %lu", naddrs);

	/* Is 10.0.0.25 in ptree? */
	rv = dp_test_addrgrp_tree_lookup("ADDRGRP9", "10.0.0.25");
	dp_test_fail_unless(rv, "10.0.0.25 not found in ptree");

	/* Add 10.0.0.25 */
	dp_test_addrgrp_prefix_add("ADDRGRP9", "10.0.0.25", true);

	/* Still expect 1 entry */
	naddrs = npf_addrgrp_naddrs(AG_IPv4, tid, false);
	dp_test_fail_unless(naddrs == 1, "expected 1, got %lu", naddrs);

	/* Remove 10.0.0.25 */
	dp_test_addrgrp_prefix_remove("ADDRGRP9", "10.0.0.25", true, true);

	/* Still expect 1 entry */
	naddrs = npf_addrgrp_naddrs(AG_IPv4, tid, false);
	dp_test_fail_unless(naddrs == 1, "expected 1, got %lu", naddrs);

	/* Is 10.0.0.25 in ptree? */
	rv = dp_test_addrgrp_tree_lookup("ADDRGRP9", "10.0.0.25");
	dp_test_fail_unless(rv, "10.0.0.25 not found in ptree");

	/* Remove 10.0.0.25/32 */
	dp_test_addrgrp_prefix_remove("ADDRGRP9", "10.0.0.25/32", true, false);

	/* Expect 0 entries */
	naddrs = npf_addrgrp_naddrs(AG_IPv4, tid, false);
	dp_test_fail_unless(naddrs == 0, "expected 0, got %lu", naddrs);

	/* Is 10.0.0.25 in ptree? */
	rv = dp_test_addrgrp_tree_lookup("ADDRGRP9", "10.0.0.25");
	dp_test_fail_unless(!rv, "10.0.0.25 found in ptree");


	/* Delete address group */
	dp_test_fail_unless(npf_addrgrp_nentries("ADDRGRP9") == 0,
			    "ADDRGRP9 not empty");
	dp_test_addrgrp_destroy("ADDRGRP9");
} DP_END_TEST;


/*
 * npf_addrgrp10
 */
DP_DECL_TEST_CASE(npf_addrgrp, npf_addrgrp10, NULL, NULL);
DP_START_TEST(npf_addrgrp10, test1)
{
	struct npf_addrgrp *ag, *tmp;
	uint32_t tid;
	int rc;

	dp_test_addrgrp_create("ADDRGRP10");
	dp_test_addrgrp_prefix_add("ADDRGRP10", "10.0.0.0/24", true);

	rc = npf_addrgrp_name2tid("ADDRGRP10", &tid);
	dp_test_fail_unless(rc == 0, "npf_addrgrp_name2tid");

	ag = npf_addrgrp_tid2handle(tid);
	dp_test_fail_unless(ag, "npf_addrgrp_tid2handle");

	/* Take reference of address-group */
	npf_addrgrp_get(ag);

	/*
	 * Lookup using npf_addrgrp_lookup_v4_by_handle
	 */
	uint32_t ipaddr;
	inet_pton(AF_INET, "10.0.0.1", &ipaddr);

	rc = npf_addrgrp_lookup_v4_by_handle(ag, ipaddr);
	dp_test_fail_unless(rc == 0, "Lookup by handle failed");

	dp_test_addrgrp_prefix_remove("ADDRGRP10", "10.0.0.0/24", true, false);

	/* Unconfigure address-group */
	dp_test_addrgrp_destroy("ADDRGRP10");

	/*
	 * Addr-group should no longer be findable since we have deleted it
	 * from the tableset.
	 */
	tmp = npf_addrgrp_tid2handle(tid);
	dp_test_fail_unless(tmp == NULL, "Addr-group not found");

	/* Lookup of address should fail (but not crash) */
	rc = npf_addrgrp_lookup_v4_by_handle(ag, ipaddr);
	dp_test_fail_unless(rc != 0, "Lookup by handle succeeded");

	/* Release reference on address-group */
	npf_addrgrp_put(ag);

} DP_END_TEST;


/*
 * npf_addrgrp11 - Test that a host address and address range with contigous
 * addresses can be configured.
 */
DP_DECL_TEST_CASE(npf_addrgrp, npf_addrgrp11, NULL, NULL);
DP_START_TEST(npf_addrgrp11, test1)
{
	dp_test_addrgrp_create("ADDRGRP11");

	dp_test_addrgrp_prefix_add("ADDRGRP11", "10.136.166.206", true);
	dp_test_addrgrp_range_add("ADDRGRP11",
				  "10.136.166.207", "10.136.166.208",
				  true, true);
	dp_test_addrgrp_prefix_add("ADDRGRP11", "10.136.166.209", true);

	dp_test_addrgrp_prefix_remove("ADDRGRP11", "10.136.166.206",
				      true, false);
	dp_test_addrgrp_range_remove("ADDRGRP11",
				     "10.136.166.207", "10.136.166.208",
				  true, false);
	dp_test_addrgrp_prefix_remove("ADDRGRP11", "10.136.166.209",
				      true, false);

	/* Unconfigure address-group */
	dp_test_addrgrp_destroy("ADDRGRP11");

} DP_END_TEST;
