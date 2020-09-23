#ifndef _IF_FEAT_H_
#define _IF_FEAT_H_
/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Pipeline feature reference counts and control.  Uses per-feature counters
 * in struct ifnet to control enabling and disabling of pipeline feature
 * nodes.
 */

#include "util.h"

struct ifnet;

/*
 * Feature enable ref count and flags.
 */
enum if_feat_enum {
	IF_FEAT_ACL_IN,
	IF_FEAT_ACL_OUT,
	IF_FEAT_DEFRAG,
	IF_FEAT_FW,
	IF_FEAT_FW_ORIG,
	IF_FEAT_PBR,
	IF_FEAT_NPTV6,
	IF_FEAT_DPI,
	IF_FEAT_CGNAT,
	IF_FEAT_NAT64,
};
#define IF_FEAT_FIRST IF_FEAT_ACL_IN
#define IF_FEAT_LAST  IF_FEAT_NAT64
#define IF_FEAT_COUNT (IF_FEAT_LAST+1)

#define IF_FEAT2FLAG(_f) (1 << (_f))

enum if_feat_flag {
	IF_FEAT_FLAG_ACL_IN =	IF_FEAT2FLAG(IF_FEAT_ACL_IN),
	IF_FEAT_FLAG_ACL_OUT =	IF_FEAT2FLAG(IF_FEAT_ACL_OUT),
	IF_FEAT_FLAG_DEFRAG =	IF_FEAT2FLAG(IF_FEAT_DEFRAG),
	IF_FEAT_FLAG_FW =	IF_FEAT2FLAG(IF_FEAT_FW),
	IF_FEAT_FLAG_FW_ORIG =	IF_FEAT2FLAG(IF_FEAT_FW_ORIG),
	IF_FEAT_FLAG_PBR =	IF_FEAT2FLAG(IF_FEAT_PBR),
	IF_FEAT_FLAG_NPTV6 =	IF_FEAT2FLAG(IF_FEAT_NPTV6),
	IF_FEAT_FLAG_DPI =	IF_FEAT2FLAG(IF_FEAT_DPI),
	IF_FEAT_FLAG_CGNAT =	IF_FEAT2FLAG(IF_FEAT_CGNAT),
	IF_FEAT_FLAG_NAT64 =	IF_FEAT2FLAG(IF_FEAT_NAT64),
};

#define IF_FEAT_IS_SET(_ft, _flags) ((IF_FEAT2FLAG(_ft) & (_flags)) != 0)
#define IF_FEAT_IS_CLR(_ft, _flags) ((IF_FEAT2FLAG(_ft) & (_flags)) == 0)

typedef void (*if_feat_enable_t)(struct ifnet *, bool);

/*
 * Initialize the function pointer for enabling and disabling a feature
 */
void if_feat_init(if_feat_enable_t fp, const char *name,
		  enum if_feat_enum feat);

/*
 * Increment feature ref count for an interface.  Feature is enabled when ref
 * count changes from 0 to 1.  Returns true when feature is enabled.
 */
bool if_feat_refcnt_incr(struct ifnet *ifp, enum if_feat_enum feat);

/*
 * Decrement feature ref count for an interface.  Feature is disabled when ref
 * count changes from 1 to 0.  Returns true when feature is disabled.
 */

bool if_feat_refcnt_decr(struct ifnet *ifp, enum if_feat_enum feat);

/*
 * Increment each feature set in feature-flag bitmask.
 */
void if_feat_intf_multi_refcnt_incr(struct ifnet *ifp, enum if_feat_flag ffl);

/*
 * Decrement each feature set in feature-flag bitmask.
 */
void if_feat_intf_multi_refcnt_decr(struct ifnet *ifp, enum if_feat_flag ffl);

/*
 * Increment each feature set in feature-flag bitmask for all interfaces.
 */
void if_feat_all_refcnt_incr(enum if_feat_flag ffl);

/*
 * Decrement each feature set in feature-flag bitmask for all interfaces.
 */
void if_feat_all_refcnt_decr(enum if_feat_flag ffl);

/*
 * Feature enum to name
 */
const char *if_feat_name(enum if_feat_enum feat);

#endif
