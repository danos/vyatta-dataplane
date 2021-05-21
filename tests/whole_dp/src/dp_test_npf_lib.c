/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane test npf library
 */

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "npf/npf_rc.h"
#include "npf/npf_state.h"
#include "npf/npf_timeouts.h"
#include "npf/alg/alg_npf.h"
#include "npf/alg/alg.h"
#include "npf/cgnat/cgn_sess2.h"
#include "npf/cgnat/cgn_test.h"

#include "dp_test.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_sess_lib.h"
#include "dp_test_npf_lib.h"

/*
 * Returns "action=accept" or "action=drop"
 */
const char *npf_action_string(bool accept)
{
	return accept ? "action=accept" : "action=drop";
}

/*
 * Predefined npf rule lists
 */
struct dp_test_npf_rule_t rule_def_block[] = {
	RULE_DEF_BLOCK,
	NULL_RULE };

struct dp_test_npf_rule_t rule_10_pass_tcp[] = {
	RULE_10_PASS_TCP,
	RULE_DEF_BLOCK,
	NULL_RULE };

struct dp_test_npf_rule_t rule_10_pass_tcp_sf[] = {
	RULE_10_PASS_TCP_SF,	/* Stateful */
	RULE_DEF_BLOCK,
	NULL_RULE };

struct dp_test_npf_rule_t rule_10_block_tcp[] = {
	RULE_10_BLOCK_TCP,
	RULE_DEF_PASS,
	NULL_RULE };

struct dp_test_npf_rule_t rule_10_pass_udp[] = {
	RULE_10_PASS_UDP,
	RULE_DEF_BLOCK,
	NULL_RULE };

struct dp_test_npf_rule_t rule_10_pass_udp_sf[] = {
	RULE_10_PASS_UDP_SF,	/* Stateful */
	RULE_DEF_BLOCK,
	NULL_RULE };

struct dp_test_npf_rule_t rule_10_block_udp[] = {
	RULE_10_BLOCK_UDP,
	RULE_DEF_PASS,
	NULL_RULE };

void
_dp_test_npf_commit(const char *file, int line)
{
	const char *cmd = "npf-ut commit";
	bool err;
	char *reply = dp_test_console_request_w_err(cmd, &err, false);

	free(reply);
	_dp_test_fail_unless(!err, file, line,
			     "npf cmd failed: \"%s\"", cmd);
}

/*
 * Issue npf command to dataplane
 */
void
_dp_test_npf_cmd(const char *cmd, bool print, const char *file, int line)
{
	char *reply;
	bool err;

	reply = dp_test_console_request_w_err(cmd, &err, print);

	/*
	 * Returned string for npf commands is just an empty string, which is
	 * of no interest
	 */
	free(reply);

	_dp_test_fail_unless(!err, file, line,
			     "npf cmd failed: \"%s\"", cmd);
}

void
_dp_test_npf_cmd_fmt(bool print, const char *file, int line,
		     const char *fmt_str, ...)
{
	char cmd[TEST_MAX_CMD_LEN];
	va_list ap;

	va_start(ap, fmt_str);
	vsnprintf(cmd, TEST_MAX_CMD_LEN, fmt_str, ap);
	_dp_test_npf_cmd(cmd, print, file, line);
	va_end(ap);
}

/*
 * Create an address group and (optionally) add one address or prefix
 */
void _dpt_addr_grp_create(const char *name, const char *addr,
			  const char *file, int line)
{
		_dp_test_npf_cmd_fmt(false, file, line,
				     "npf-ut fw table create %s", name);

		if (addr)
			_dp_test_npf_cmd_fmt(false, file, line,
					     "npf-ut fw table add %s %s",
					     name, addr);
}

/*
 * Destroy an address group
 */
void _dpt_addr_grp_destroy(const char *name, const char *addr,
			   const char *file, int line)
{
	if (addr)
		_dp_test_npf_cmd_fmt(false, file, line,
				     "npf-ut fw table remove %s %s",
				     name, addr);

	_dp_test_npf_cmd_fmt(false, file, line,
			     "npf-ut fw table delete %s", name);
}


/*
 * Create and attach a CGNAT policy. e.g.
 *
 * cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
 *                  "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);
 *
 * Note that this creates a match address-group, e.g. "POLICY1_AG"
 */
void
_cgnat_policy_add(const char *policy, uint pri, const char *src,
		  const char *pool, const char *intf,
		  enum cgn_map_type eim, enum cgn_fltr_type eif,
		  bool log_sess, bool check_feat,
		  bool add_or_change,
		  const char *file, const char *func, int line)
{
	char real_ifname[IFNAMSIZ];
	char addr_grp[60];

	dp_test_intf_real(intf, real_ifname);

	snprintf(addr_grp, sizeof(addr_grp), "%s_AG", policy);

	/* Add match address-group */
	if (add_or_change)
		_dpt_addr_grp_create(addr_grp, src, file, line);

	/* Add cgnat policy */
	_dp_test_npf_cmd_fmt(false, file, line,
			     "cgn-ut policy add %s priority=%u "
			     "match-ag=%s pool=%s log-sess-all=%s",
			     policy, pri, addr_grp, pool,
			     log_sess ? "yes" : "no");

	_dp_test_npf_cmd_fmt(false, file, line,
			     "cgn-ut policy attach name=%s intf=%s",
			     policy, real_ifname);

	/* Check cgnat feature is enabled */
	if (check_feat) {
		dp_test_wait_for_pl_feat(intf, "vyatta:ipv4-cgnat-in",
					 "ipv4-validate");
		dp_test_wait_for_pl_feat(intf, "vyatta:ipv4-cgnat-out",
					 "ipv4-out");
	}
}

void
_cgnat_policy_add2(const char *policy, uint pri, const char *src,
		   const char *pool, const char *intf,
		   const char *other,
		   const char *file, const char *func, int line)
{
	char real_ifname[IFNAMSIZ];
	char addr_grp[60];

	dp_test_intf_real(intf, real_ifname);

	snprintf(addr_grp, sizeof(addr_grp), "%s_AG", policy);

	/* Add match address-group */
	_dpt_addr_grp_create(addr_grp, src, file, line);

	/* Add cgnat policy */
	_dp_test_npf_cmd_fmt(false, file, line,
			     "cgn-ut policy add %s priority=%u "
			     "match-ag=%s pool=%s %s",
			     policy, pri, addr_grp, pool,
			     other ? other : "");

	_dp_test_npf_cmd_fmt(false, file, line,
			     "cgn-ut policy attach name=%s intf=%s",
			     policy, real_ifname);
}

void
_cgnat_policy_del(const char *policy, uint pri, const char *intf,
		 const char *file, const char *func, int line)
{
	char real_ifname[IFNAMSIZ];
	char addr_grp[60];

	dp_test_intf_real(intf, real_ifname);

	_dp_test_npf_cmd_fmt(false, file, line,
			     "cgn-ut policy detach name=%s intf=%s",
			    policy, real_ifname);

	/* Delete cgnat policy */
	_dp_test_npf_cmd_fmt(false, file, line,
			     "cgn-ut policy delete %s", policy);

	snprintf(addr_grp, sizeof(addr_grp), "%s_AG", policy);
	_dpt_addr_grp_destroy(addr_grp, NULL, file, line);
}


/*
 * Clear npf counters for one or more or all npf ruleset types/classes
 *
 * e.g. dp_test_npf_clear(NULL)
 *      dp_test_npf_clear("nat64");
 *      dp_test_npf_clear("fw-in fw-out");
 */
void dp_test_npf_clear(const char *class)
{
	char list[TEST_MAX_CMD_LEN];
	int l;
	uint rstype;

	if (class) {
		dp_test_npf_cmd_fmt(false, "npf-op clear all: %s", class);
		return;
	}

	for (rstype = 0, l = 0; rstype < NPF_RS_TYPE_COUNT; rstype++) {
		l += spush(list + l, sizeof(list) - l, " %s",
			   npf_get_ruleset_type_name(rstype));
	}
	dp_test_npf_cmd_fmt(false, "npf-op clear all: %s", list);
}

/*
 * Verify an npf ruleset presence/absence in the dataplane
 */
static void
_dp_test_npf_ruleset_verify(struct dp_test_npf_ruleset_t *rset,
			    bool state, bool debug,
			    const char *file, int line)
{
	if (!rset || !rset->name)
		return;

	json_object *jgrp;

	jgrp = _dp_test_npf_json_get_ruleset(rset->rstype, rset->attach_point,
					     rset->dir, rset->name,
					     debug, file, line);

	char rset_desc[80];
	spush(rset_desc, sizeof(rset_desc), "%s %s %s %s",
	      rset->rstype, rset->attach_point, rset->dir, rset->name);

	if (jgrp == NULL) {
		_dp_test_fail_unless(!state, file, line,
				     "\nRuleset [%s] not found\n",
				     rset_desc);
		return;
	}

	if (!rset->rules || !rset->rules->rule) {
		json_object_put(jgrp);
		/*
		 * No rules were specified so we were only testing for the
		 * presence/absence of the group.  Since the group was found,
		 * then we fail if state==false.
		 */
		_dp_test_fail_unless(state, file, line,
				     "\nRuleset [%s] found\n", rset_desc);
		return;
	}

	/*
	 * Group was found and a rules list was specified, so verify that
	 * all rules are present / not present.
	 */
	struct dp_test_npf_rule_t *rule;
	json_object *jrule;

	for (rule = rset->rules; rule && rule->rule != NULL; rule++) {
		jrule = dp_test_npf_json_get_rs_rule(jgrp, rule->rule);
		if (jrule) {
			json_object_put(jrule);
			if (!state) {
				json_object_put(jgrp);
				_dp_test_fail(file, line,
					      "\nnpf ruleset [%s], "
					      "rule %s present\n",
					      rset_desc, rule->rule);
				return;
			}
		} else {
			if (state) {
				json_object_put(jgrp);
				_dp_test_fail(file, line,
					      "\nnpf ruleset [%s], "
					      "missing rule %s\n",
					      rset_desc, rule->rule);
				return;
			}
		}
	}
	json_object_put(jgrp);
}

/*
 * Temporary buffers for storing real interface name
 */
#define DP_TEST_IFNAME_TMP_COUNT 4
#define DP_TEST_IFNAME_TMP_SIZE  (IFNAMSIZ+10)
static char *
dp_test_npf_ifname_buf(void)
{
	static uint cur = DP_TEST_IFNAME_TMP_COUNT;
	static char buf[DP_TEST_IFNAME_TMP_COUNT][DP_TEST_IFNAME_TMP_SIZE];

	if (cur >= DP_TEST_IFNAME_TMP_COUNT-1)
		cur = 0;
	else
		cur++;

	return buf[cur];
}

/*
 * Get the real interface name.  Return in a temporary buffer.
 */
char *
dp_test_intf_real_buf(const char *test_name)
{
	return dp_test_intf_real(test_name, dp_test_npf_ifname_buf());
}

/*
 * Determine ruleset attach type from ruleset feature name ("fw-in" etc)
 */
static const char *
dp_test_npf_ruleset_attach_type(const char *rstype)
{
	enum npf_ruleset_type t;
	int rc;

	rc = npf_get_ruleset_type(rstype, &t);
	if (rc != 0)
		return NULL;

	switch (t) {
	case NPF_RS_ACL_IN:
	case NPF_RS_ACL_OUT:
	case NPF_RS_FW_IN:
	case NPF_RS_FW_OUT:
	case NPF_RS_DNAT:
	case NPF_RS_SNAT:
	case NPF_RS_LOCAL:
	case NPF_RS_ORIGINATE:
	case NPF_RS_SESSION_RPROC:
	case NPF_RS_BRIDGE:
	case NPF_RS_PBR:
	case NPF_RS_NPTV6_IN:
	case NPF_RS_NPTV6_OUT:
	case NPF_RS_NAT64:
	case NPF_RS_NAT46:
		return "interface";
	case NPF_RS_ZONE:
		return "zone";
	case NPF_RS_IPSEC:
		/* TBD */
		break;
	case NPF_RS_CUSTOM_TIMEOUT:
		return "vrf";
	case NPF_RS_APPLICATION:
		return "global";
	case NPF_RS_QOS:
		return "qos";
	case NPF_RS_PORTMONITOR_IN:
		/* TBD */
		break;
	case NPF_RS_PORTMONITOR_OUT:
		/* TBD */
		break;
	case NPF_RS_TYPE_COUNT:
		break;
	}
	return NULL;
}

/*
 * Determine ruleset attach point string
 */
static const char *
dp_test_npf_ruleset_attach_point(struct dp_test_npf_ruleset_t *rset)
{
	char *buf;
	enum npf_ruleset_type t;
	int l, rc;

	rc = npf_get_ruleset_type(rset->rstype, &t);
	if (rc != 0)
		return NULL;

	switch (t) {
	case NPF_RS_ACL_IN:
	case NPF_RS_ACL_OUT:
	case NPF_RS_FW_IN:
	case NPF_RS_FW_OUT:
	case NPF_RS_DNAT:
	case NPF_RS_SNAT:
	case NPF_RS_LOCAL:
	case NPF_RS_ORIGINATE:
	case NPF_RS_SESSION_RPROC:
	case NPF_RS_BRIDGE:
	case NPF_RS_PBR:
	case NPF_RS_NPTV6_IN:
	case NPF_RS_NPTV6_OUT:
	case NPF_RS_NAT64:
	case NPF_RS_NAT46:
		/* Attach-point is interface name */
		return dp_test_intf_real_buf(rset->attach_point);
	case NPF_RS_ZONE:
		return rset->attach_point;
	case NPF_RS_IPSEC:
		/* TBD */
		return NULL;
	case NPF_RS_CUSTOM_TIMEOUT:
		/* TBD */
		return NULL;
	case NPF_RS_APPLICATION:
		return "";
	case NPF_RS_QOS:
		buf = dp_test_intf_real_buf(rset->attach_point);
		l = strlen(buf);
		spush(buf + l, DP_TEST_IFNAME_TMP_SIZE - l, "/0");
		return buf;
	case NPF_RS_PORTMONITOR_IN:
		/* TBD */
		return NULL;
	case NPF_RS_PORTMONITOR_OUT:
		/* TBD */
		return NULL;
	case NPF_RS_TYPE_COUNT:
		break;
	}
	return NULL;
}

/*
 * Attach a ruleset to an attach point
 */
static void
_dp_test_npf_ruleset_attach(struct dp_test_npf_ruleset_t *rset,
			    const char *class, bool debug, bool verify,
			    const char *file, int line)
{
	char cmd[TEST_MAX_CMD_LEN];
	const char *attach_type, *attach_point;

	attach_type = dp_test_npf_ruleset_attach_type(rset->rstype);
	_dp_test_fail_unless(attach_type, file, line,
			     "Failed to determine attach type for %s",
			     rset->rstype);

	attach_point = dp_test_npf_ruleset_attach_point(rset);
	_dp_test_fail_unless(attach_point, file, line,
			     "Failed to determine attach point");

	spush(cmd, sizeof(cmd),
	      "npf-ut attach %s:%s %s %s:%s",
	      attach_type, attach_point, rset->rstype, class, rset->name);

	_dp_test_npf_cmd(cmd, debug, file, line);

	dp_test_npf_commit();

	if (verify)
		_dp_test_npf_ruleset_verify(rset, true, debug, file, line);
}

static void
_dp_test_npf_ruleset_detach(struct dp_test_npf_ruleset_t *rset,
			    const char *class, bool debug, bool verify,
			    const char *file, int line)
{
	char cmd[TEST_MAX_CMD_LEN];
	const char *attach_type, *attach_point;

	attach_type = dp_test_npf_ruleset_attach_type(rset->rstype);
	_dp_test_fail_unless(attach_type, file, line,
			     "Failed to determine attach type for %s",
			     rset->rstype);

	attach_point = dp_test_npf_ruleset_attach_point(rset);
	_dp_test_fail_unless(attach_point, file, line,
			     "Failed to determine attach point");

	spush(cmd, sizeof(cmd),
	      "npf-ut detach %s:%s %s %s:%s",
	      attach_type, attach_point, rset->rstype, class, rset->name);

	_dp_test_npf_cmd(cmd, debug, file, line);

	dp_test_npf_commit();

	if (verify)
		_dp_test_npf_ruleset_verify(rset, false, debug, file, line);
}

/*
 * Add an npf ruleset.  Attach to attach_point if rset->attach_point is set
 * (not zones).
 *
 * Example useage:
 *
 *	struct dp_test_npf_rule_t rules[] = {
 *		{"10", PASS, STATELESS, "proto-final=6"},
 *		RULE_DEF_BLOCK,
 *		NULL_RULE };
 *
 *	struct dp_test_npf_ruleset_t rset = {
 *		.rstype = "fw-out",
 *		.name   = "FW1_OUT",
 *		.enable = 1,
 *		.attach_point = "dp1T0",
 *		.fwd    = FWD,
 *		.dir    = "out",
 *		.rules  = rules
 *	};
 *	dp_test_npf_fw_add(&rset, false);
 *
 * The ruleset class name is one of: fw, fw-internal (intra zone class), pbr,
 * qos, ipsec, custom-timeout, session-limiter, app-firewall.
 */
void
_dp_test_fw_ruleset_add(struct dp_test_fw_ruleset_t *rset,
			 const char *class, bool debug, bool verify,
			 const char *file, int line)
{
	struct dp_test_npf_rule_t *rule;

	if (!rset || !rset->name)
		return;

	/*
	 * Add ruleset rules
	 */
	for (rule = rset->rules; rule && rule->rule; rule++) {
		char *str = strstr(rule->npf, "proto-final=");

		/*
		 * If the npf rule has a protocol specified, it must be a
		 * number and not a string.
		 */
		if (str) {
			char *endp;
			ulong proto;

			str += 12;
			proto = strtoul(str, &endp, 10);
			if (endp == str || proto > 255)
				_dp_test_fail(
					file, line,
					"proto must be a protocol number");
		}
		/*
		 * Syntax is of the form:
		 *
		 * npf-ut add <class>:<name> <index> action=accept|drop
		 *            [stateful=y]
		 *	      [proto-final=<protocol>]
		 *            [src-addr=<addr>[/<mask>]]
		 *            [src-port=<port>]
		 *	      [dst-addr=<addr>[/<mask>]]
		 *            [dst-port=<port>]
		 *
		 * where "<port>" may be a single port or a port range.  Note,
		 * port numbers are only applicable for TCP and UDP.
		 */
		_dp_test_npf_cmd_fmt(debug, file, line,
				     "npf-ut add %s:%s %s %s %s%s",
				     class, rset->name, rule->rule,
				     npf_action_string(rule->pass),
				     rule->stateful ? "stateful=y ":"",
				     rule->npf);
	}

	/*
	 * Attach ruleset to attach point
	 */
	_dp_test_npf_ruleset_attach(rset, class, debug, verify, file, line);
}

/*
 * Detach npf ruleset from attach point if rset->attach_point set, and delete
 * ruleset
 */
void
_dp_test_fw_ruleset_del(struct dp_test_fw_ruleset_t *rset,
			 const char *class, bool debug, bool verify,
			 const char *file, int line)
{
	if (!rset || !rset->name)
		return;

	/*
	 * Detach ruleset from attach point
	 */
	_dp_test_npf_ruleset_detach(rset, class, debug, verify, file, line);

	/*
	 * Delete ruleset
	 */
	dp_test_npf_cmd_fmt(debug, "npf-ut delete %s:%s", class, rset->name);
	dp_test_npf_commit();
}

/*
 * Get the json array containing the npf groups for a particular ruleset type.
 * json_object_put should be called once the caller has finished with the
 * returned object.
 *
 * rstype - Ruleset type name
 */
static json_object *
dp_test_npf_json_get_rs_groups(const char *rstype,
			       struct dp_test_json_find_key *key,
			       int key_len)
{
	json_object *jresp;
	json_object *jarray;
	char cmd[TEST_MAX_CMD_LEN];
	char *response;
	bool err;

	snprintf(cmd, sizeof(cmd), "npf-op show all: %s", rstype);

	response = dp_test_console_request_w_err(cmd, &err, false);
	if (!response || err) {
		dp_test_fail("no response from dataplane");
		return NULL;
	}

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);

	if (!jresp) {
		dp_test_fail("failed to parse response");
		return NULL;
	}

	/* Optional debug */
#if 0
	const char *str = json_object_to_json_string_ext(
		jresp, JSON_C_TO_STRING_PRETTY);
	if (str)
		printf("%s\n", str);
#endif

	jarray = dp_test_json_find(jresp, key, key_len);
	json_object_put(jresp);

	if (!jarray)
		return NULL;

	return jarray;
}

/*
 * Get the inner "groups" json object for an npf ruleset.
 *
 * rstype   - Ruleset type.  See npf/config/npf_ruleset_type.c
 *            npf_ruleset_features array
 * ifname   - Interface name
 * dir      - "in" or "out" or NULL
 *
 * Returns a json array of the form:
 *
 *[
 *  {
 *    "class":"fw",
 *    "name":"FW1",
 *    "direction":"in",
 *    "rules":{
 *      "10":{
 *        "action":"pass ",
 *        "config":"action=accept (null)",
 *        "match":"all ",
 *        "bytes":0,
 *        "packets":0,
 *      },
 *      "10000":{
 *        "action":"block ",
 *        "config":"action=drop",
 *        "match":"all ",
 *        "bytes":0,
 *        "packets":0,
 *      }
 *    }
 *  }
 *]
 *
 * For zones, there is an attach point for each interface in the zone.  The
 * attach point is the receive interface.  The groups array in that ruleset
 * contains an "out" entry for every other interface in the zone.
 *
 * For custom-timeout, the attach_point is the VRF ID, i.e. "1" for default
 * VRF.
 */
json_object *
_dp_test_npf_json_get_rs(const char *rstype, const char *attach_point,
			 const char *dir, bool debug,
			 const char *file, int line)
{
	char real_ifname[IFNAMSIZ];
	enum npf_rs_flag dir_flag;
	enum npf_ruleset_type t;
	json_object *jarray;
	char tmp[40];
	uint flags;
	bool in;
	int rc;

	/*
	 * Verify the ruleset name with the dataplane
	 */
	rc = npf_get_ruleset_type(rstype, &t);
	dp_test_fail_unless(rc == 0,
			    "Unknown ruleset type \"%s\"", rstype);

	/*
	 * If specified, direction must be "in" or "out"
	 */
	if (dir) {
		dp_test_fail_unless(!strcmp(dir, "in") || !strcmp(dir, "out"),
				    "dir parameter must be \"in\" or \"out\"");
		in = !strcmp(dir, "in") ? true : false;
		dir_flag = in ? NPF_RS_FLAG_DIR_IN : NPF_RS_FLAG_DIR_OUT;
	} else
		dir_flag = NPF_RS_FLAG_DIR_IN | NPF_RS_FLAG_DIR_OUT;

	/*
	 * Verify direction is valid for this ruleset type
	 */
	flags = npf_get_ruleset_type_flags(t);
	dp_test_fail_unless((flags & dir_flag) == dir_flag,
			    "Mismatched ruleset direction \"%s\" "
			    "for ruleset \"%s\"",
			    dir ? dir : "NULL", rstype);

	/*
	 * The returned ruleset json is of the following form.  We want to
	 * pick out the "groups" array within this.
	 *
	 * "config": [{
	 *     "attach_type": "interface",
	 *     "attach_point": "dp0p1s1",
	 *     "rulesets": [{
	 *             "ruleset_type": "session-rproc",
	 *             "groups": [{
	 *
	 * Fetch the json array for this ruleset class
	 */
#define KEY_INDEX_ATTACH_TYPE 1
#define KEY_INDEX_ATTACH_POINT 2
	struct dp_test_json_find_key key[] = { {"config", NULL},
					       {"attach_type", NULL},
					       {"attach_point", NULL},
					       {"rulesets", NULL},
					       {"ruleset_type", rstype},
					       {"groups", NULL} };

	switch (t) {
	case NPF_RS_ACL_IN:
	case NPF_RS_ACL_OUT:
	case NPF_RS_FW_IN:
	case NPF_RS_FW_OUT:
	case NPF_RS_DNAT:
	case NPF_RS_SNAT:
	case NPF_RS_LOCAL:
	case NPF_RS_ORIGINATE:
	case NPF_RS_SESSION_RPROC:
	case NPF_RS_BRIDGE:
	case NPF_RS_PBR:
	case NPF_RS_NPTV6_IN:
	case NPF_RS_NPTV6_OUT:
	case NPF_RS_NAT64:
	case NPF_RS_NAT46:
		/* Attach-point is interface name */
		dp_test_intf_real(attach_point, real_ifname);

		key[KEY_INDEX_ATTACH_TYPE].val = "interface";
		key[KEY_INDEX_ATTACH_POINT].val = real_ifname;
		break;
	case NPF_RS_ZONE:
		key[KEY_INDEX_ATTACH_TYPE].val = "zone";
		key[KEY_INDEX_ATTACH_POINT].val = attach_point;
		break;
	case NPF_RS_IPSEC:
		/* TBD */
		break;
	case NPF_RS_CUSTOM_TIMEOUT:
		key[KEY_INDEX_ATTACH_TYPE].val = "vrf";
		key[KEY_INDEX_ATTACH_POINT].val = attach_point;
		break;
	case NPF_RS_APPLICATION:
		key[KEY_INDEX_ATTACH_TYPE].val = "global";
		key[KEY_INDEX_ATTACH_POINT].val = "";
		break;
	case NPF_RS_QOS:
		dp_test_intf_real(attach_point, real_ifname);
		snprintf(tmp, sizeof(tmp), "%s/0", real_ifname);
		key[KEY_INDEX_ATTACH_TYPE].val = "qos";
		key[KEY_INDEX_ATTACH_POINT].val = tmp;
		break;
	case NPF_RS_PORTMONITOR_IN:
		/* TBD */
		break;
	case NPF_RS_PORTMONITOR_OUT:
		/* TBD */
		break;
	case NPF_RS_TYPE_COUNT:
		dp_test_fail("Invalid ruleset type");
		break;
	}

	if (debug)
		printf("rstype=%s, attach_type=%s, attach_point=%s\n",
		       rstype,
		       key[KEY_INDEX_ATTACH_TYPE].val ?
		       key[KEY_INDEX_ATTACH_TYPE].val : "-",
		       key[KEY_INDEX_ATTACH_POINT].val ?
		       key[KEY_INDEX_ATTACH_POINT].val : "-");

	jarray = dp_test_npf_json_get_rs_groups(rstype, key, ARRAY_SIZE(key));

	if (debug) {
		if (jarray) {
			const char *str = json_object_to_json_string_ext(
				jarray, JSON_C_TO_STRING_PRETTY);
			if (str)
				printf("%s\n", str);
		} else
			printf("Not found\n");
	}

	return jarray;
}

static bool
json_match_name(json_object *jobj, void *arg)
{
	char *name = arg;
	const char *oname;

	if (!dp_test_json_string_field_from_obj(jobj, "name", &oname))
		return false;

	return strcmp(oname, name) == 0;
}

/*
 * Get a specific json object from an npf ruleset json array (as returned by
 * dp_test_npf_json_get_rs).
 *
 * Returns json object.  json_object_put should be called once the caller has
 * finished with the object.
 *
 * Example useage:
 *
 * jarray = dp_test_npf_json_get_rs("fw-in", "dp1T0", "in");
 * jobj = dp_test_npf_json_get_rs_name(jarray, "FW1");
 * ...
 * json_object_put(jarray);
 * json_object_put(jobj);
 */
json_object *
_dp_test_npf_json_get_rs_name(json_object *jarray, const char *name,
			      const char *file, int line)
{
	json_object *jobj;
	void *arg = (void *)name;

	if (!jarray || !name)
		_dp_test_fail(file, line, "%s bad params", __func__);

	jobj = dp_test_json_array_iterate(jarray, &json_match_name, arg);

	if (!jobj)
		return NULL;

	jobj = json_object_get(jobj);
	if (!jobj)
		_dp_test_fail(file, line,
			      "%s json_object_get failed", __func__);

#if 0
	const char *str = json_object_to_json_string_ext(
		jobj, JSON_C_TO_STRING_PRETTY);
	if (str)
		printf("%s\n", str);
#endif

	return jobj;
}

/*
 * Get a specific rule from a json ruleset.  The ruleset is typically what is
 * returned by dp_test_npf_json_get_rs_name.
 *
 * Returns json object.  json_object_put should be called once the caller has
 * finished with the object.
 *
 * Example useage:
 *
 * jarray = dp_test_npf_json_get_rs("fw-in", "dp1T0", "in");
 * jrset = dp_test_npf_json_get_rs_name(jarray, "FW1");
 * jrule = dp_test_npf_json_get_rs_rule(jrset, "10");
 * ...
 * json_object_put(jarray);
 * json_object_put(jrset);
 * json_object_put(jrule);
 */
json_object *
dp_test_npf_json_get_rs_rule(json_object *jrset, const char *rule)
{
	json_object *jrule;
	struct dp_test_json_find_key key[] = { {"rules", NULL},
					       {rule, NULL} };
	if (!jrset || !rule)
		return NULL;

	jrule = dp_test_json_find(jrset, key, ARRAY_SIZE(key));

	return jrule;
}

/*
 * Get the json object for a specific ruleset
 *
 * Returns json object.  json_object_put should be called once the caller has
 * finished with the object.
 *
 * Example useage:
 *
 * jrset = dp_test_npf_json_get_ruleset("fw-in", "dp1T0", "in",  "FW1");
 * jrset = dp_test_npf_json_get_ruleset("dnat",  "dp1T0", "in",  NULL);
 * jrset = dp_test_npf_json_get_ruleset("snat",  "dp1T0", "out", NULL);
 * jrset = dp_test_npf_json_get_ruleset("nat64",  "dp1T0", "in",  "NAT64_1");
 * jrset = dp_test_npf_json_get_ruleset("zone",  "dp1T0", "out", "dp2T1");
 */
json_object *
_dp_test_npf_json_get_ruleset(const char *rstype, const char *attach_point,
			      const char *dir, const char *rsname,
			      bool debug, const char *file, int line)
{
	json_object *jarray, *jrset;
	char real_ifname[IFNAMSIZ];
	enum npf_ruleset_type t;
	int rc;

	jarray = _dp_test_npf_json_get_rs(rstype, attach_point, dir,
					  false, file, line);
	if (!jarray)
		return NULL;

	rc = npf_get_ruleset_type(rstype, &t);
	_dp_test_fail_unless(rc == 0, file, line,
			     "Unknown ruleset type \"%s\"", rstype);

	/*
	 * The ruleset name for snat and dnat is the interface attach_point
	 */
	if (t == NPF_RS_DNAT || t == NPF_RS_SNAT) {
		dp_test_intf_real(attach_point, real_ifname);
		rsname = (const char *)real_ifname;
	}

	/*
	 * For nat64 and nat46, the attach point is an interface.
	 * For zone, the ruleset name is the 'to' interface.
	 */
	if (t == NPF_RS_NAT64 || t == NPF_RS_NAT46)
		dp_test_intf_real(attach_point, real_ifname);

	_dp_test_fail_unless(rsname, file, line, "NULL rsname");

	jrset = _dp_test_npf_json_get_rs_name(jarray, rsname, file, line);

	if (!jrset) {
		if (debug) {
			const char *str = json_object_to_json_string_ext(
				jarray, JSON_C_TO_STRING_PRETTY);
			if (str)
				printf("%s\n", str);
		}
		json_object_put(jarray);
		return NULL;
	}
	json_object_put(jarray);

	if (debug) {
		const char *str = json_object_to_json_string_ext(
			jrset, JSON_C_TO_STRING_PRETTY);
		if (str)
			printf("%s\n", str);
	}

	return jrset;
}


/*
 * Get the json object for a specific rule in a named ruleset
 *
 * Returns json object.  json_object_put should be called once the caller has
 * finished with the object.
 *
 * Example useage:
 *
 * jrule = dp_test_npf_json_get_rule("fw-in", "dp1T0", "in",  "FW1",   "10");
 * jrule = dp_test_npf_json_get_rule("dnat",  "dp1T0", "in",  NULL,    "10");
 * jrule = dp_test_npf_json_get_rule("snat",  "dp1T0", "out", NULL,    "10");
 * jrule = dp_test_npf_json_get_rule("nat64", NULL,    "in",  "dp1T0", "1");
 * jrule = dp_test_npf_json_get_rule("zone",  "dp1T0", "out", "dp2T1", "1");
 */
json_object *
_dp_test_npf_json_get_rule(const char *rstype, const char *attach_point,
			   const char *dir, const char *rsname,
			   const char *rule, bool debug,
			   const char *file, int line)
{
	json_object *jrset, *jrule;


	jrset = _dp_test_npf_json_get_ruleset(rstype, attach_point, dir, rsname,
					      debug, file, line);

	if (!jrset)
		return NULL;

	jrule = dp_test_npf_json_get_rs_rule(jrset, rule);
	json_object_put(jrset);

	if (debug) {
		const char *str = json_object_to_json_string_ext(
			jrule, JSON_C_TO_STRING_PRETTY);
		if (str)
			printf("%s\n", str);
	}

	return jrule;
}

/*
 * Verify the packet count of an npf rule.
 *
 * Example useage:
 *
 * _dp_test_npf_verify_pkt_count("Foo", "fw-in", "dp1T0", "in", "FW1", "10", 1);
 * _dp_test_npf_verify_pkt_count(NULL, "dnat", "dp1T0", "in", NULL, "10", 0);
 * _dp_test_npf_verify_pkt_count(NULL, "snat", "dp1T0", "out", NULL, "10", 2);
 * _dp_test_npf_verify_pkt_count(NULL, "nat64", NULL,  "in", "dp1T0", "1", 1);
 * _dp_test_npf_verify_pkt_count(NULL, "zone", "dp1T0", "out", "dp2T1", "1", 2);
 */
void
_dp_test_npf_verify_pkt_count(const char *desc,
			      const char *rstype, const char *attach_point,
			      const char *dir, const char *rsname,
			      const char *rule, uint exp_pkts,
			      const char *file, int line)
{
	char rule_desc[80];
	json_object *jrule;
	uint pkts = 0;
	bool rv;

	spush(rule_desc, sizeof(rule_desc), "%s %s %s %s %s",
	      rstype, attach_point, dir, rsname, rule);

	jrule = dp_test_npf_json_get_rule(rstype, attach_point, dir,
					  rsname, rule);
	_dp_test_fail_unless(jrule, file, line,
			     "Failed to find rule %s", rule_desc);

	rv = dp_test_json_int_field_from_obj(jrule, "packets", (int *)&pkts);
	_dp_test_fail_unless(rv, file, line,
			     "Failed to get packet count from rule %s",
			     rule_desc);

	json_object_put(jrule);

	_dp_test_fail_unless(pkts == exp_pkts, file, line,
			     "\n%s%snpf rule [%s] exp pkts %d, actual %d\n",
			     desc ? desc : "", desc ? "\n" : "",
			     rule_desc, exp_pkts, pkts);
}

void
dp_test_npf_print_sessions(const char *desc)
{
	json_object *jresp;
	const char *str;
	char *response;
	bool err;

	if (desc)
		printf("%s\n", desc);

	response = dp_test_console_request_w_err(
			"session-op show sessions full", &err, true);
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

void
dp_test_npf_print_nat_sessions(const char *desc)
{
	json_object *jresp;
	char *response;
	const char *str;
	bool err;

	if (desc)
		printf("%s\n", desc);

	response = dp_test_console_request_w_err(
			"session-op show sessions full", &err, false);
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

void
dp_test_npf_flush_portmap(void)
{
	dp_test_console_request_reply("npf-op fw portmap clear", false);
}

/*
 * Flush ruleset gc heap
 */
void
dp_test_npf_flush_rulesets(void)
{
	dp_test_console_request_reply("npf-op flush", false);
}

void
dp_test_npf_cleanup(void)
{
	/* reset timeouts state */
	npf_timeout_reset();

	/* flush alg tuples */
	npf_alg_flush_all();

	/* Clear sessions */
	dp_test_npf_clear_sessions();

	/* Reset session ID to 0 */
	dp_test_npf_reset_session_id();

	/* Clear portmaps */
	dp_test_npf_flush_portmap();

	dp_test_npf_clear_cgnat();

	/* Flush ruleset gc heap */
	dp_test_npf_flush_rulesets();

	/* Reset all algs. */
	npf_alg_reset();
}


const char *npf_decision_str(npf_decision_t decision)
{
	switch (decision) {
	case NPF_DECISION_UNKNOWN:
		return "UNKNOWN";
	case NPF_DECISION_BLOCK:
		return "BLOCK";
	case NPF_DECISION_BLOCK_UNACCOUNTED:
		return "BLOCK_UNACCOUNTED";
	case NPF_DECISION_PASS:
		return "PASS";
	case NPF_DECISION_UNMATCHED:
		return "UNMATCHED";
	};
	return "Unknown";
}

/*
 * Cache packet and optionally inspect it with an npf ruleset
 *
 * index   - Index, used to number any debug we print
 * pkt     - mbuf to cache and filter
 * rlset   - Ruleset.  If NULL, then cache pkt only
 * ifp     - Match on intf if non-NULL and rule has an intf
 * dir     - Direction.  PFIL_IN or PFIL_OUT.
 * exp_npc - Expected npc_info flags after caching the pkt, e.g.
 *           (NPC_GROUPER | NPC_L4PORTS | NPC_IP4)
 *
 * returns decision
 */
npf_decision_t
_dp_test_npf_raw(int index, struct rte_mbuf *pkt,
		 const struct npf_ruleset *rlset,
		 struct ifnet *ifp, int dir,
		 uint16_t exp_npc,
		 const char *file, int line)
{
	npf_cache_t npc_cache, *npc = &npc_cache;
	npf_decision_t decision = NPF_DECISION_PASS;
	uint16_t exp_etype;
	npf_rule_t *rule;
	int exp_alen;
	int rc;

	/*
	 * Use the expected cache info to determine IPv4 or IPv6
	 */
	if (exp_npc & NPC_IP6) {
		exp_alen = 16;
		exp_etype = RTE_ETHER_TYPE_IPV6;
	} else {
		exp_alen = 4;
		exp_etype = RTE_ETHER_TYPE_IPV4;
	}

	/*
	 * Cache packet and verify cache
	 */
	npf_cache_init(npc);
	rc = npf_cache_all(npc, pkt, htons(exp_etype));

	_dp_test_fail_unless(rc == 0, file, line,
			    "packet cache [%d]\n", index);

	_dp_test_fail_unless(npc->npc_alen, file, line,
			    "packet cache alen %d != %d [%d]\n",
			     npc->npc_alen, exp_alen, index);

	_dp_test_fail_unless(npc->npc_info == exp_npc,
			     file, line,
			    "packet cache info %x != %x [%d]\n",
			    npc->npc_info, exp_npc,  index);

	/*
	 * Inspect FW ruleset *only* if a ruleset is specified
	 */
	if (rlset) {
		rule = npf_ruleset_inspect(npc, pkt, rlset,
					   NULL, ifp, dir);
		_dp_test_fail_unless(rule, file, line,
				     "rule [%d]\n", index);

		/* Get the initial decision */
		decision = npf_rule_decision(rule);
	}

	return decision;
}

void cgn_alg_show_sessions(void)
{
	char *buf = NULL;
	size_t bufsz = 0;
	struct cgn_sess_fltr fltr;

	memset(&fltr, 0, sizeof(fltr));

	cgn_ut_show_sessions(&buf, &bufsz, &fltr);

	if (buf) {
		char err_str[1000];
		json_object *jobj;
		const char *str;

		jobj = parse_json(buf, err_str, sizeof(err_str));

		str = json_object_to_json_string_ext(jobj,
						     JSON_C_TO_STRING_PRETTY);
		if (str)
			printf("%s\n", str);

		json_object_put(jobj);
		free(buf);
	}
}
