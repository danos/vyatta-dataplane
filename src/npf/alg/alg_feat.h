/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _ALG_FEAT_H_
#define _ALG_FEAT_H_

/*
 * The features that use ALGs.  This enum is used to differentiate npf and
 * cgnat alg and apt data structures and table entries.
 */
enum alg_feat {
	ALG_FEAT_NPF,
	ALG_FEAT_CGNAT,
};

#define ALG_FEAT_FIRST	ALG_FEAT_NPF
#define ALG_FEAT_LAST	ALG_FEAT_CGNAT
#define ALG_FEAT_MAX	(ALG_FEAT_LAST + 1)

#define ALG_FEAT_ALL	ALG_FEAT_MAX

/*
 * ALG feature names
 */
static inline const char *alg_feat_name(enum alg_feat feat)
{
	switch (feat) {
	case ALG_FEAT_NPF:
		return "npf";
	case ALG_FEAT_CGNAT:
		return "cgnat";
	};
	return "unknown";
}

#endif /* ALG_FEAT_H */
