/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef ALG_DEFS_H
#define ALG_DEFS_H

/*
 * ALG Identifier
 */
enum cgn_alg_id {
	CGN_ALG_NONE,
	CGN_ALG_PPTP,
	CGN_ALG_SIP,
	CGN_ALG_FTP,
} __attribute__ ((__packed__));

#define CGN_ALG_FIRST	CGN_ALG_PPTP
#define CGN_ALG_LAST	CGN_ALG_FTP
#define CGN_ALG_MAX	(CGN_ALG_LAST + 1)

#define CGN_ALG_BIT(id)		(1 << ((id) - 1))
#define CGN_ALG_BIT_PPTP	CGN_ALG_BIT(CGN_ALG_PPTP)
#define CGN_ALG_BIT_SIP		CGN_ALG_BIT(CGN_ALG_SIP)
#define CGN_ALG_BIT_FTP		CGN_ALG_BIT(CGN_ALG_FTP)

/*
 * Assert as zero so we can simply test for zero or non-zero to determine if a
 * pkt or session is an ALG pkt/session.
 */
static_assert(CGN_ALG_NONE == 0, "CGN_ALG_NONE must be 0");

#endif /* ALG_DEFS_H */
