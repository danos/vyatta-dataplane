/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * alg_pinhole.c - ALG Pinhole table
 */

#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <rte_jhash.h>

#include "compiler.h"
#include "if_var.h"
#include "util.h"
#include "soft_ticks.h"
#include "vrf.h"

#include "npf/cgnat/cgn_rc.h"
#include "npf/cgnat/cgn_mbuf.h"
#include "npf/cgnat/cgn_session.h"
#include "npf/cgnat/cgn_map.h"
#include "npf/cgnat/cgn_policy.h"

#include "npf/cgnat/alg/alg_pinhole.h"

/*
 * The ALG pinhole table is used to match secondary (data) flows for ALG
 * protocols (SIP, FTP, and PPTP).
 *
 * The pinhole table entries are typically short-lived (10-120 secs).  These
 * are created as a result of inspecting the payloads of packets identified by
 * a well-known destination port and protocol.  These 'control' packets
 * typically contain information in the payload to identify data flow
 * addresses and/or ports.  This information is used to create pinhole table
 * entries.
 *
 * The pinhole table is typically looked-up whenever CGNAT fails to find a
 * session during its normal session lookup.  If a pinhole entry is found then
 * an ALG secondary (or 'child') session is created, and linked to the
 * 'parent' session that originally created the pinhole.
 *
 * The pinhole table entries contain 6-tuples (vrfid, protocol, source
 * address and port, destination address and port)
 *
 * However in some circumstances (e.g. ftp passive) we do not know the source
 * port of the data flow so a 5-tuple entry is created that will match any
 * source port.
 *
 * These entries are normally expired whenever a secondary flow is detected
 * (and session created), since they are no longer required.
 *
 * Some secondary flows may begin in either direction.  We need a pair of
 * pinhole entries for these.  They are both expired when one is matched.
 *
 * Some pinholes, when matched, will cause another pinhole to be created.  For
 * example, SIP RTP pinholes will, when matched, cause an RTCP pinhole to be
 * created.  In these instances we may have a parent -> child -> grandchild
 * session linkage.
 *
 * All ALGs will only create one pinhole at a time per parent session *except*
 * for SIP.  SIP may have multiple calls per parent session and each call may
 * cause multiple pinhole pairs to be created (All SIP pinholes are paired).
 *
 * Arbitrary limits have been placed on the number of open SIP calls (5) per
 * session and the number of secondary flows per call (4).  Therefore it is
 * theoretically possible for up to 40 pinholes to be created per SIP session.
 * However SIP calls within a session are contiguous.  At most, the end of one
 * call may overlap with the start of the next call.
 */

/*
 * CGNAT ALG pinhole hash table
 *
 * The table is created when first ALG is enabled and remains in existence
 * until the DP_EVT_UNINIT event occurs.
 *
 * tt_lock is used for paired pinholes to prevent simultaneous sessions being
 * created in both directions.
 *
 * tt_active is used to prevent new entries being added while the table is
 * being destroyed.
 */
static struct alg_pinhole_tbl {
	struct cds_lfht	*tt_ht;
	bool		tt_active;
	rte_atomic32_t	tt_count;
	rte_spinlock_t	tt_lock;
} alg_pinhole_table;

/*
 * Min and max sizes of the pinhole table.  Allow to grow to any size.  The
 * effective limit will be the number of CGNAT mappings available.
 */
#define ALG_PINHOLE_TBL_INIT	32
#define ALG_PINHOLE_TBL_MIN	256
#define ALG_PINHOLE_TBL_MAX	0


/*
 * Create CGNAT pinhole table.
 */
__attribute__((nonnull))
static int alg_pinhole_tbl_create(struct alg_pinhole_tbl *tt)
{
	struct cds_lfht *ht, *old;

	rte_atomic32_set(&tt->tt_count, 0);
	rte_spinlock_init(&tt->tt_lock);

	ht = cds_lfht_new(ALG_PINHOLE_TBL_INIT,
			  ALG_PINHOLE_TBL_MIN, ALG_PINHOLE_TBL_MAX,
			  CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING,
			  NULL);
	if (!ht)
		return -ENOMEM;

	old = rcu_cmpxchg_pointer(&tt->tt_ht, NULL, ht);
	if (old)
		/* Lost race to assign tt_ht. Thats ok. */
		dp_ht_destroy_deferred(ht);
	else
		tt->tt_active = true;

	return 0;
}

/*
 * Destroy pinhole table
 */
__attribute__((nonnull))
static void alg_pinhole_tbl_destroy(struct alg_pinhole_tbl *tt)
{
	struct cds_lfht *ht;

	assert(rte_atomic32_read(&tt->tt_count) == 0);

	ht = rcu_xchg_pointer(&tt->tt_ht, NULL);
	if (ht)
		dp_ht_destroy_deferred(ht);
}

/**************************************************************************
 * Initialisation and cleanup
 **************************************************************************/

/*
 * Called when first ALG is enabled.  The pinhole table remains in existence
 * until the dataplane is shutdown.
 */
int alg_pinhole_init(void)
{
	if (alg_pinhole_table.tt_ht)
		return 0;

	int rc = alg_pinhole_tbl_create(&alg_pinhole_table);
	if (rc < 0)
		return rc;

	return 0;
}

/*
 * Called indirectly via a DP_EVT_UNINIT event handler
 */
void alg_pinhole_uninit(void)
{
	if (!alg_pinhole_table.tt_ht)
		return;

	/* Prevent further entries being added */
	alg_pinhole_table.tt_active = false;

	alg_pinhole_tbl_destroy(&alg_pinhole_table);
}
