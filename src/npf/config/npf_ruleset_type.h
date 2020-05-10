/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_RULESET_TYPE_H
#define NPF_RULESET_TYPE_H

#include <stdint.h>

enum npf_ruleset_type {
	NPF_RS_ACL_IN,
	NPF_RS_ACL_OUT,
	NPF_RS_FW_IN,
	NPF_RS_FW_OUT,
	NPF_RS_DNAT,
	NPF_RS_SNAT,
	NPF_RS_ZONE,
	NPF_RS_LOCAL,
	NPF_RS_BRIDGE,
	NPF_RS_IPSEC,
	NPF_RS_PBR,
	NPF_RS_CUSTOM_TIMEOUT,
	NPF_RS_NAT64,
	NPF_RS_NAT46,
	NPF_RS_QOS,
	NPF_RS_SESSION_RPROC,
	NPF_RS_PORTMONITOR_IN,
	NPF_RS_PORTMONITOR_OUT,
	NPF_RS_APPLICATION,
	NPF_RS_NPTV6_IN,
	NPF_RS_NPTV6_OUT,
	NPF_RS_TYPE_COUNT /* Must be last */
};


/**
 * The following are flags associated with the different rule types to
 * give the capabilities of the rules.
 */
enum npf_rs_flag {
	NPF_RS_FLAG_NOTRACK =        1 << 0, /* not tracking state */
	NPF_RS_FLAG_NOTABLES =       1 << 1, /* not using resource tables */
	NPF_RS_FLAG_DIR_IN =         1 << 2, /* rules are for IN */
	NPF_RS_FLAG_DIR_OUT =        1 << 3, /* rules are for OUT */
	NPF_RS_FLAG_APP_FW =         1 << 4, /* rules may use app firewall */
	NPF_RS_FLAG_FEAT_INTF =      1 << 5, /* feats enabled per intf */
	NPF_RS_FLAG_FEAT_GBL =       1 << 6, /* feats enabled on all intfs */
	NPF_RS_FLAG_NO_STATS =       1 << 7, /* no stats allocated per rule */
};

/**
 * Get the flags associated with the given ruleset type
 *
 * @param type The type of the ruleset to get the flags
 * @return returns the flags for the type - 0 will be returned
 *         if an invalid type is passed in.
 */
unsigned int npf_get_ruleset_type_flags(enum npf_ruleset_type type);

/**
 * Get the feature flags associated with the given ruleset type
 *
 * @param type The type of the ruleset to get the flags
 * @return returns the flags for the type - 0 will be returned
 *         if an invalid type is passed in.
 */
unsigned int npf_get_ruleset_type_feat_flags(enum npf_ruleset_type type);

/**
 * Get the name associated with the given ruleset type
 *
 * @param type The type of the ruleset to get the name
 * @return returns the name of the type - NULL will be returned
 *         if an invalid type is passed in.
 */
const char *npf_get_ruleset_type_name(enum npf_ruleset_type type);

/**
 * Get the ruleset type associated with a given name
 *
 * @param name the name to look up
 * @param type a pointer to a type which will be filled in with
 *        the enum value on success.
 *
 * @return returns 0 on success and a negative errno on failure
 */

int npf_get_ruleset_type(const char *name, enum npf_ruleset_type *type);

/**
 * Get the ruleset log level associated with a given name
 *
 * @param type The type of the ruleset to get the log level
 *
 * @return returns log level on success and 0 on failure
 */

uint32_t npf_get_ruleset_type_log_level(enum npf_ruleset_type type);

/**
 * Get the log name associated with the given ruleset type
 *
 * @param type The type of the ruleset to get the log name
 * @return returns the log name of the type - NULL will be returned
 *         if an invalid type is passed in.
 */
const char *npf_get_ruleset_type_log_name(enum npf_ruleset_type type);

#endif /* _NPF_RULE_SET_TYPE_H_ */
