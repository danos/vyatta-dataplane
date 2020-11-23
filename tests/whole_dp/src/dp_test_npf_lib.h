/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane test npf library
 */

#ifndef __DP_TEST_NPF_LIB_H__
#define __DP_TEST_NPF_LIB_H__

#include <stdint.h>
#include <stdbool.h>
#include "npf/npf.h"
#include "npf/npf_rc.h"
#include "npf/npf_ruleset.h"
#include "npf/config/npf_ruleset_type.h"

#include "dp_test/dp_test_firewall_lib.h"

/*
 * Defines for backward compatibility.
 */
#define dp_test_npf_rule_t	dp_test_fw_rule_t
#define dp_test_npf_ruleset_t	dp_test_fw_ruleset_t

#define NPF_PROTO_TCP		FW_PROTO_TCP
#define NPF_PROTO_UDP		FW_PROTO_UDP

#define RULE_1_PASS		{"1", PASS, STATELESS, ""}
#define RULE_10_PASS_TO_ANY	{"10", PASS, STATELESS, ""}
#define RULE_10_PASS_FM_ANY	{"10", PASS, STATELESS, ""}
#define RULE_10_PASS_TCP	{"10", PASS, STATELESS, NPF_PROTO_TCP}
#define RULE_10_PASS_TCP_SF	{"10", PASS, STATEFUL, NPF_PROTO_TCP}
#define RULE_10_BLOCK_TCP	{"10", BLOCK, STATELESS, NPF_PROTO_TCP}

#define RULE_10_PASS_UDP	{"10", PASS, STATELESS, NPF_PROTO_UDP}
#define RULE_10_PASS_UDP_SF	{"10", PASS, STATEFUL, NPF_PROTO_UDP}
#define RULE_10_BLOCK_UDP	{"10", BLOCK, STATELESS, NPF_PROTO_UDP}

/* Predefined firewall rule arrays */
extern struct dp_test_npf_rule_t rule_def_block[];
extern struct dp_test_npf_rule_t rule_10_pass_tcp[];
extern struct dp_test_npf_rule_t rule_10_pass_tcp_sf[];
extern struct dp_test_npf_rule_t rule_10_block_tcp[];

extern struct dp_test_npf_rule_t rule_10_pass_udp[];
extern struct dp_test_npf_rule_t rule_10_pass_udp_sf[];
extern struct dp_test_npf_rule_t rule_10_block_udp[];

/*
 * Returns "action=accept" or "action=drop"
 */
const char *npf_action_string(bool accept);

/*
 * Get the real interface name.  Return in a temporary buffer from a circular
 * array.
 */
char *dp_test_intf_real_buf(const char *test_name);

/*
 * Send npf request to the dataplane.  Will fail if the returned dataplane
 * status is "ERROR".  If 'print' is true, then print the command before it is
 * sent.
 */
void
_dp_test_npf_cmd(const char *cmd, bool print, const char *file, int line);

#define dp_test_npf_cmd(cmd, print)			     \
	_dp_test_npf_cmd(cmd, print, __FILE__, __LINE__)

void
_dp_test_npf_cmd_fmt(bool print, const char *file, int line,
		     const char *fmt_str, ...)
	__attribute__((__format__(printf, 4, 5)));

#define dp_test_npf_cmd_fmt(print, fmt_str, ...)	\
	_dp_test_npf_cmd_fmt(print, __FILE__, __LINE__, \
			     fmt_str, ##__VA_ARGS__)

/*
 * Simple config to create an address-group and (optionally) add one prefix or
 * address.
 */
void _dpt_addr_grp_create(const char *name, const char *addr,
			  const char *file, int line);

#define dpt_addr_grp_create(a, b)			\
	_dpt_addr_grp_create(a, b, __FILE__, __LINE__)

void _dpt_addr_grp_destroy(const char *name, const char *addr,
			   const char *file, int line);

#define dpt_addr_grp_destroy(a, b)			\
	_dpt_addr_grp_destroy(a, b, __FILE__, __LINE__)

/*
 * Create and attach a CGNAT policy, e.g.
 *
 * cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
 *                  "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);
 *
 * Note that this creates a match address-group, e.g. "POLICY1_AG"
 */
#include "npf/cgnat/cgn_policy.h"
#define CGN_3TUPLE false
#define CGN_5TUPLE true

void _cgnat_policy_add(const char *policy, uint pri, const char *src,
		       const char *pool, const char *intf,
		       enum cgn_map_type eim, enum cgn_fltr_type eif,
		       bool log_sess, bool check_feat,
		       bool add_or_change,
		       const char *file, const char *func, int line);

#define cgnat_policy_add(_a, _b, _c, _d, _e, _f, _g, _h, _i)		\
	_cgnat_policy_add(_a, _b, _c, _d, _e, _f, _g, _h, _i, true,	\
			  __FILE__, __func__, __LINE__)

#define cgnat_policy_change(_a, _b, _c, _d, _e, _f, _g, _h, _i)	\
	_cgnat_policy_add(_a, _b, _c, _d, _e, _f, _g, _h, _i,	\
			  false, __FILE__, __func__, __LINE__)

void _cgnat_policy_add2(const char *policy, uint pri, const char *src,
			const char *pool, const char *intf,
			const char *other,
			const char *file, const char *func, int line);
#define cgnat_policy_add2(_a, _b, _c, _d, _e, _f)		\
	_cgnat_policy_add2(_a, _b, _c, _d, _e, _f,		\
			   __FILE__, __func__, __LINE__)


/*
 * cgnat_policy_del("POLICY1", 10, "dp2T1");
 */
void _cgnat_policy_del(const char *policy, uint pri, const char *intf,
		       const char *file, const char *func, int line);

#define cgnat_policy_del(_a, _b, _c)					\
	_cgnat_policy_del(_a, _b, _c, __FILE__, __func__, __LINE__)


/*
 * Clear npf counters for one or more or all npf ruleset types/classes
 *
 * e.g. dp_test_npf_clear(NULL)
 *      dp_test_npf_clear("nat64");
 *      dp_test_npf_clear("fw-in fw-out");
 */
void dp_test_npf_clear(const char *class);

void
_dp_test_npf_commit(const char *file, int line);

#define dp_test_npf_commit()			     \
	_dp_test_npf_commit(__FILE__, __LINE__)

/* Pretty prints "npf fw list sessions" */
void
dp_test_npf_print_sessions(const char *desc);

/* Pretty prints "npf fw list sessions nat" */
void
dp_test_npf_print_nat_sessions(const char *desc);

/* Three gc passes are required to flush the addr-portmap */
void
dp_test_npf_flush_portmap(void);

/* Two gc passes are required to flush the rulesets gc heap */
void dp_test_npf_flush_rulesets(void);

/* Flush session table and addr-portmap table */
void
dp_test_npf_cleanup(void);


#define dp_test_npf_ruleset_add(rs, class, debug)			\
	_dp_test_fw_ruleset_add(rs, class, debug,			\
				 true, __FILE__, __LINE__)

#define dp_test_npf_fw_add(rs, debug)					\
	_dp_test_fw_ruleset_add(rs, "fw", debug,			\
				 true, __FILE__, __LINE__)

#define dp_test_npf_fw_intnl_add(rs, debug)		   \
	_dp_test_fw_ruleset_add(rs, "fw-internal", debug, \
				 true, __FILE__, __LINE__)

#define dp_test_npf_fw_del(fw, debug)				\
	_dp_test_fw_ruleset_del(fw, "fw", debug,		\
				 true, __FILE__, __LINE__)

#define dp_test_npf_fw_intnl_del(fw, debug)				\
	_dp_test_fw_ruleset_del(fw, "fw-internal", debug,		\
				 true, __FILE__, __LINE__)

/*
 * Get the inner "groups" json array for an npf ruleset.
 *
 * rstype       - Ruleset type.  See npf/config/npf_ruleset_type.c
 *                npf_ruleset_features array.
 * attach_point - Interface name
 * dir          - "in" or "out" or NULL
 *
 * Returns json object.  json_object_put should be called once the caller has
 * finished with the object.
 *
 * For most rulesets (fw-in, fw-out, dnat, snat, local, session-rproc, bridge,
 * pbr, zone), the attach_point is an interface.
 *
 * For zones, there is an attach point for each interface in the zone.  The
 * attach point is the receive interface.  The groups array in that ruleset
 * contains an "out" entry for every other interface in the zone.
 *
 * For custom-timeout, the attach_point is the VRF ID, i.e. "1" for default
 * VRF.
 */
json_object *_dp_test_npf_json_get_rs(const char *rstype,
				      const char *attach_point,
				      const char *dir, bool debug,
				      const char *file, int line);

#define dp_test_npf_json_get_rs(rsname, ifname, dir)		\
	_dp_test_npf_json_get_rs(rsname, ifname, dir, false,	\
				 __FILE__, __LINE__)

/*
 * Get json object in ruleset groups array with specific name
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
json_object *_dp_test_npf_json_get_rs_name(json_object *jarray,
					   const char *name,
					   const char *file, int line);

#define dp_test_npf_json_get_rs_name(jarray, name)			\
	_dp_test_npf_json_get_rs_name(jarray, name, __FILE__, __LINE__)

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
json_object *dp_test_npf_json_get_rs_rule(json_object *jrset,
					  const char *rule);


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
 * jrset = dp_test_npf_json_get_ruleset("nat64",  NULL,   "in",  "dp1T0");
 * jrset = dp_test_npf_json_get_ruleset("zone",  "dp1T0", "out", "dp2T1");
 */
json_object *
_dp_test_npf_json_get_ruleset(const char *rstype, const char *attach_point,
			      const char *dir, const char *rsname,
			      bool debug, const char *file, int line);

#define dp_test_npf_json_get_ruleset(rstype, ap, dir, rsname)  \
	_dp_test_npf_json_get_ruleset(rstype, ap, dir, rsname, \
				   false, __FILE__, __LINE__)

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
			   const char *file, int line);

#define dp_test_npf_json_get_rule(rstype, ap, dir, rsname, rule)  \
	_dp_test_npf_json_get_rule(rstype, ap, dir, rsname, rule, \
				   false, __FILE__, __LINE__)

/*
 * Verify the packet count of an npf rule.
 *
 * Example useage:
 *
 * _dp_test_npf_verify_pkt_count("Foo", "fw-in", "dp1T0", "in", "FW1", "10", 1);
 * _dp_test_npf_verify_pkt_count(NULL, "dnat", "dp1T0", "in", NULL, "10", 0);
 * _dp_test_npf_verify_pkt_count(NULL, "snat", "dp1T0", "out", NULL, "10", 2);
 * _dp_test_npf_verify_pkt_count(NULL, "nat64", NULL, "in", "dp1T0", "1", 1);
 * _dp_test_npf_verify_pkt_count(NULL, "zone", "dp1T0", "out", "dp2T1", "1", 2);
 */
void
_dp_test_npf_verify_pkt_count(const char *desc,
			      const char *rstype, const char *attach_point,
			      const char *dir, const char *rsname,
			      const char *rule, uint exp_pkts,
			      const char *file, int line);

static inline void
__dp_test_npf_verify_rule_pkt_count(const char *desc,
				    struct dp_test_npf_ruleset_t *rset,
				    const char *rule, uint exp_pkts,
				    const char *file, int line)
{
	_dp_test_npf_verify_pkt_count(desc, rset->rstype,
				      rset->attach_point,
				      rset->dir, rset->name,
				      rule, exp_pkts, file, line);
}

#define dp_test_npf_verify_rule_pkt_count(desc, rset, rule, pkts)	\
	__dp_test_npf_verify_rule_pkt_count(desc, rset, rule, pkts,	\
					    __FILE__, __LINE__)

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
 *
 * Example:
 *
 * struct npf_if *nif;
 * struct npf_config *npf_config;
 * const npf_ruleset_t *rlset;
 * char real_ifname[IFNAMSIZ];
 * npf_decision_t decision;
 * struct ifnet *ifp;
 * uint16_t exp_npc4;
 *
 * dp_test_intf_real("dp1T0", real_ifname);
 * ifp = dp_ifnet_byifname(real_ifname);
 * nif = rcu_dereference(ifp->if_npf);
 * npf_config = npf_if_conf(nif);
 * rlset = npf_get_ruleset(npf_config, NPF_RS_FW_IN);
 * exp_npc4 = NPC_GROUPER | NPC_L4PORTS | NPC_IP4;
 *
 * decision = dp_test_npf_raw(0, pkt4, rlset, ifp, PFIL_IN, exp_npc4);
 */
npf_decision_t _dp_test_npf_raw(int index, struct rte_mbuf *pkt,
					const struct npf_ruleset *rlset,
					struct ifnet *ifp, int dir,
					uint16_t exp_npc,
					const char *file, int line);

#define dp_test_npf_raw(idx, pkt, rlset, ifp, dir, exp)	 \
	_dp_test_npf_raw(idx, pkt, rlset, ifp, dir, exp, \
			 __FILE__, __LINE__)

const char *npf_decision_str(npf_decision_t decision);

#endif
