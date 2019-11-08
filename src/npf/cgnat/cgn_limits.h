/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _CGN_LIMITS_H_
#define _CGN_LIMITS_H_

#define FIVE_HUNDRED		(1<<9)
#define ONE_THOUSAND		(1<<10)
#define TWO_THOUSAND		(1<<11)
#define FOUR_THOUSAND		(1<<12)
#define EIGHT_THOUSAND		(1<<13)
#define ONE_MILLION		(1<<20)

#define ONE_SECOND		1
#define ONE_MINUTE		(60 * ONE_SECOND)
#define ONE_HOUR		(60 * ONE_MINUTE)


/**************************************************************************
 * CGNAT Session Table (private src addr, port, protocol, vrfid)
 **************************************************************************/

/*
 * Session timeout.  Default session timeout in seconds for established
 * sessions. Timeout for un-established sessions is half.
 *
 * rfc6888, REQ-8 "Once an external port is deallocated, it SHOULD NOT be
 * reallocated to a new mapping until at least 120 seconds have passed ..."
 */
#define CGN_SESSION_TIMEOUT_TCP    (1800)
#define CGN_SESSION_TIMEOUT_OTHER  (120)

/* Session garbage collection interval (seconds) */
#define CGN_SESS_GC_INTERVAL	10

/* Number of gc passes before session is deactivated */
#define CGN_SESS_GC_COUNT	2

/*
 * Session hash table (bucket sizes must be powers of 2).
 */
#define CGN_SESSION_HT_INIT	(8 * ONE_THOUSAND)
#define CGN_SESSION_HT_MIN	(8 * ONE_THOUSAND)
#define CGN_SESSION_HT_MAX	(32 * ONE_MILLION)

#define CGN_SESSIONS_MAX	CGN_SESSION_HT_MAX

/**************************************************************************
 * CGNAT Nested Session Table (public src addr and port)
 **************************************************************************/

#define CGN_SESS2_HT_INIT	4
#define CGN_SESS2_HT_MIN	4
#define CGN_SESS2_HT_MAX	64
#define CGN_SESS2_HT_FLAGS	(CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING)

/* MUST be less than USHRT_MAX */
#define CGN_DEST_SESSIONS_MAX	CGN_SESS2_HT_MAX

/**************************************************************************
 * CGNAT Source (private address, vrfid) Table
 **************************************************************************/

/* Session garbage collection interval (seconds) */
#define CGN_SRC_GC_INTERVAL	20

/* Number of gc passes before source is deactivated */
#define CGN_SRC_GC_COUNT	2

/*
 * Source hash table. (entry per inside address and vrfid)
 */
#define CGN_SOURCE_HT_INIT	256
#define CGN_SOURCE_HT_MIN	(8 * ONE_THOUSAND)
#define CGN_SOURCE_HT_MAX	(64 * ONE_THOUSAND)

#define CGN_SRC_TABLE_MAX	CGN_SOURCE_HT_MAX

#endif
