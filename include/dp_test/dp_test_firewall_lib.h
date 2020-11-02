/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane test firewall library
 */
#ifndef __DP_TEST_FIREWALL_LIB_H__
#define __DP_TEST_FIREWALL_LIB_H__

/*
 * A firewall comprises a single firewall group structure and one or
 * more firewall rule structures.
 *
 * First step is to create a firewall rules array, terminated with NULL_RULE:
 *
 *	struct dp_test_fw_rule_t rules[] = {
 *		{
 *			.rule     = "10",
 *			.pass     = PASS,
 *			.stateful = STATELESS,
 *			.npf      = "pass proto 6"},
 *		RULE_DEF_BLOCK,
 *		NULL_RULE };
 *
 * There are some predefined rules below, e.g. RULE_DEF_BLOCK is the same as
 * sonfiguring the default action to 'block'
 *
 * Second step is to create the firewall group:
 *
 *	struct dp_test_fw_ruleset_t fw = {
 *              .rstype = "fw-in",
 *		.name   = "FW1_IN",
 *		.enable = 1,
 *		.intf   = "dp2T1",
 *		.fwd    = FWD,
 *		.dir    = "in",
 *		.rules  = rules
 *	};
 *
 * The firewall group is added to the dataplane and assigned to an interface
 * by calling:
 *
 *      dp_test_npf_fw_add(&fw, false)
 */

/*
 * Simple, *short* definitions that make a firewall test matrix
 * more readable.
 */
#define STATELESS false
#define STATEFUL  true

#define BLOCK false
#define PASS true

#define ASSIGN true
#define REMOVE false

#define FORWARDS false
#define REVERSE true

#define FWD true
#define REV false



/*
 * Firewall rule
 */
struct dp_test_fw_rule_t {
	const char  *rule;	/* Rule number e.g. "10" */
	bool         pass;	/* BLOCK or PASS */
	bool         stateful;	/* STATELESS or STATEFUL */
	const char  *npf;	/* Actual rule e.g. "pass proto 6" */
};

/*
 * npf ruleset
 *
 * If 'attach_point' is non-NULL then the ruleset is attached to that
 * attach_point when dp_test_fw_ruleset_add is called.
 *
 * 'fwd' is a convenience variable to describe if the ruleset is used in the
 * forwards or reverse packet flow for a particular test.  It is not used by
 * any library code.  Currently it is only used by the test arrays in
 * dp_test_npf_fw.c.  Other users may ignore it.
 */
struct dp_test_fw_ruleset_t {
	const char   *rstype;	/* Feature name e.g. "fw-in" */
	const char   *name;	/* Ruleset name e.g. "FW1" */
	bool          enable;
	const char   *attach_point; /* Attach point e.g. interface name */
	bool          fwd;	/* true for forwards direction */
	const char    *dir;	/* "in" or "out" */
	/*
	 * Array of rules, terminated by a rule with NULL_RULE
	 */
	struct dp_test_fw_rule_t  *rules;
};

/*
 * Note, the dataplane has changed to only accept protocol numbers. and
 * not strings
 */
#define FW_PROTO_TCP		"proto-final=6"
#define FW_PROTO_UDP		"proto-final=17"

/*
 * firewall rule (struct dp_test_fw_rule_t) templates
 */
#define NULL_RULE		{NULL, BLOCK, STATELESS, NULL}
#define RULE_DEF_PASS		{"10000", PASS, STATELESS, ""}
#define RULE_DEF_BLOCK		{"10000", BLOCK, STATELESS, ""}

/* struct dp_test_fw_ruleset_t templates */
#define NULL_FW {NULL, NULL, 0, NULL, 0,  "-", NULL}
/*
 * Add a firewall ruleset.  Attach to attach_point if rset->attach_point is set.
 *
 * If 'verify' is set we check the ruleset has been added to the dataplane.
 */
void
_dp_test_fw_ruleset_add(struct dp_test_fw_ruleset_t *ruleset,
			 const char *class, bool debug, bool verify,
			 const char *file, int line);

#define dp_test_fw_ruleset_add(rs, class, debug)			\
	_dp_test_fw_ruleset_add(rs, class, debug,			\
				true, __FILE__, __LINE__)


/*
 * Remove a firewall ruleset from and interface and delete it
 *
 * If 'verify' is set we check the ruleset has been removed from the
 * dataplane.
 */
void
_dp_test_fw_ruleset_del(struct dp_test_fw_ruleset_t *ruleset,
			 const char *class, bool debug, bool verify,
			 const char *file, int line);

#define dp_test_fw_ruleset_del(fw, debug)				\
	_dp_test_fw_ruleset_del(fw, "fw", debug,		\
				 true, __FILE__, __LINE__)


#endif
