/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _PMF_PARSE_H_
#define _PMF_PARSE_H_

#include <stdint.h>

struct pmf_rule;

/*
 * The input format for some of the parsing, and output format for
 * unrecognised key/value pairs.
 */
struct pkp_keyval {
	char		*key;
	char		*value;
};

struct pkp_unused {
	uint32_t			num_pairs;
	uint32_t			num_unused;
	struct pkp_keyval		pairs[0];
};

int pkp_parse_rule_line(char const *rule_line, struct pmf_rule **prule,
			struct pkp_unused **remaining);
int pkp_parse_rproc_line(char const *rproc_line, struct pmf_rule **prule,
			struct pkp_unused **remaining);

#endif /* _PMF_PARSE_H_ */
