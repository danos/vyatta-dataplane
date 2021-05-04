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
#include "npf/cgnat/alg/alg_rc.h"

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
 * Pinhole table entry
 */
struct alg_pinhole {
	struct cds_lfht_node	ap_node;

	/* Pinhole key contains the 6-tuple plus the 'expired' flag */
	struct alg_pinhole_key	ap_key;

	/* Session from which the pinhole was created */
	struct cgn_session	*ap_cse;

	/*
	 * A simple monotonically increasing value.  It is used in show and
	 * log commands in order to identify specific pinhole entries.
	 */
	uint32_t		ap_id;

	/* ALG ID.  SIP, PPTP, or FTP */
	enum cgn_alg_id		ap_alg_id;

	/*
	 * A CGNAT port mapping is allocated when a pinhole is created.  It is
	 * subsequently used to create a session if and when the pinhole is
	 * matched.  This mapping is stored in ap_cmi between these events.
	 */
	struct cgn_map		ap_cmi;

	enum cgn_dir		ap_dir;

	/*
	 * Expiry time is a future value of soft_ticks.  Entry is expired once
	 * soft_ticks becomes greater than ap_expiry_time.  Timeout is the
	 * millisec value that is added to soft_ticks to determine the expiry
	 * time.
	 */
	uint64_t		ap_expiry_time;
	uint64_t		ap_timeout;

	rte_atomic16_t		ap_refcnt;

	/*
	 * Pinhole is activated only after is is added to the table and
	 * individual ALGs pinhole have initialised the pinhole.  An inactive
	 * pinhole will not be seen by packets.
	 */
	uint8_t			ap_active;

	uint8_t			ap_removing;
	struct rcu_head		ap_rcu;
};

/* Shortcuts to select items in the pinhole entry key */
#define ap_vrfid	ap_key.pk_vrfid
#define ap_expired	ap_key.pk_expired


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
 * Monotonically increasing ID. Each pinhole created is assigned the next
 * value.   Used for show and log purposes.
 */
static rte_atomic32_t alg_pinhole_id_resource;

/* Forward references */
static void alg_pinhole_set_expiry_time(struct alg_pinhole *ap,
					uint16_t timeout);


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

/*
 * Create a pinhole entry
 */
static struct alg_pinhole *alg_pinhole_create(void)
{
	return zmalloc_aligned(sizeof(struct alg_pinhole));
}

/*
 * Free a pinhole entry
 */
__attribute__((nonnull))
static void alg_pinhole_destroy(struct alg_pinhole *ap)
{
	free(ap);
}

/*
 * Called when last reference is removed from pinhole
 */
__attribute__((nonnull))
static void alg_pinhole_destroy_rcu(struct rcu_head *head)
{
	struct alg_pinhole *ap;

	ap = caa_container_of(head, struct alg_pinhole, ap_rcu);
	alg_pinhole_destroy(ap);
}

/*
 * Take reference on ALG pinhole.  This happens when:
 *
 *   1. pinhole is added to the pinhole table,
 *   2. pinhole is paired with another pinhole
 */
__attribute__((nonnull))
static struct alg_pinhole *alg_pinhole_get(struct alg_pinhole *ap)
{
	rte_atomic16_inc(&ap->ap_refcnt);
	return ap;
}

/*
 * Release reference on ALG pinhole
 */
__attribute__((nonnull))
static void alg_pinhole_put(struct alg_pinhole *ap)
{
	assert(rte_atomic16_read(&ap->ap_refcnt) != 0);

	if (rte_atomic16_dec_and_test(&ap->ap_refcnt))
		call_rcu(&ap->ap_rcu, alg_pinhole_destroy_rcu);
}

/*
 * Pinhole table hash function
 */
__attribute__((nonnull))
static ulong alg_pinhole_hash(const struct alg_pinhole_key *key)
{
	/*
	 * A special optimized version of jhash that handles 1 or more of
	 * uint32_ts.
	 */
	return rte_jhash_32b((const uint32_t *)key,
			     sizeof(*key) / sizeof(uint32_t), 0);
}

/*
 * Hash table match function.  Returns non-zero for a match.
 */
__attribute__((nonnull))
static int alg_pinhole_match(struct cds_lfht_node *node, const void *key)
{
	struct alg_pinhole *ap;

	ap = caa_container_of(node, struct alg_pinhole, ap_node);
	return !memcmp(&ap->ap_key, key, sizeof(struct alg_pinhole_key));
}

/*
 * Create and add a pinhole table entry.  Entry is not findable via the lookup
 * mechanism until it has been activated.
 */
__attribute__((nonnull))
struct alg_pinhole *
alg_pinhole_add(const struct alg_pinhole_key *key, struct cgn_session *cse,
		enum cgn_alg_id alg_id, enum cgn_dir dir, uint16_t timeout,
		int *error)
{
	struct alg_pinhole_tbl *tt = &alg_pinhole_table;
	struct alg_pinhole *ap;

	/* Does table exist, and is it active? */
	if (!tt->tt_ht || !tt->tt_active) {
		*error = -ALG_ERR_INT;
		return NULL;
	}

	/*
	 * All elements of the key/tuple must be initialised except for the
	 * source port (source port may be a wildcard).
	 */
	assert(key->pk_vrfid);
	assert(key->pk_ipproto);
	assert(key->pk_saddr);
	assert(key->pk_daddr);
	assert(key->pk_did);

	ap = alg_pinhole_create();
	if (!ap) {
		*error = -ALG_ERR_PHOLE_NOMEM;
		return NULL;
	}

	/* Direction in which the pinhole expects to match a pkt */
	ap->ap_dir = dir;

	/* Set expiry time */
	alg_pinhole_set_expiry_time(ap, timeout);

	/* Copy key to pinhole and initialise non-tuple params */
	memcpy(&ap->ap_key, key, sizeof(ap->ap_key));

	ap->ap_key.pk_expired = 0;
	ap->ap_key.pk_pad1 = 0;
	ap->ap_key.pk_pad2 = 0;

	/* Do the table add */
	struct cds_lfht_node *node;
	ulong hash = alg_pinhole_hash(&ap->ap_key);

	node = cds_lfht_add_unique(tt->tt_ht, hash, alg_pinhole_match,
				   &ap->ap_key, &ap->ap_node);

	/*
	 * Did we lose the race to insert the pinhole entry?  If we did, then
	 * that means another packet from the same data flow matched the
	 * pinhole at the same time as this pkt, but created the pinhole
	 * before us.  All we can do in this very unlikely scenario is drop
	 * this packet.
	 */
	if (unlikely(node != &ap->ap_node)) {
		alg_pinhole_destroy(ap);
		*error = -ALG_ERR_PHOLE_EXIST;
		return NULL;
	}

	rte_atomic32_inc(&tt->tt_count);
	ap->ap_alg_id = alg_id;

	/* The pinhole ID number is used for display purposes only */
	ap->ap_id = rte_atomic32_add_return(&alg_pinhole_id_resource, 1);

	/* Take reference on the pinhole while it is in the table */
	alg_pinhole_get(ap);

	/*
	 * The pinhole stores a pointer to the session that created it, so we
	 * take reference on the session
	 */
	ap->ap_cse = cgn_session_get(cse);

	return ap;
}

/*
 * Activate a new pinhole so that it is findable in the table.  This must be
 * done *after* any ALG specific initialisation has been done.
 *
 * _alg_pinhole_lookup only returns a pinhole if ap_active is true.  However
 * this field does not prevent a hash table match.  This ensures that a
 * duplicate pinhole is not added to the table between when the earlier
 * pinhole is added to the table and when it is activated.
 */
__attribute__((nonnull))
void cgn_alg_pinhole_activate(struct alg_pinhole *ap)
{
	ap->ap_active = true;
}

/*
 * Release any reservations held by the pinhole.
 *
 * This is required if a pinhole (or its owning session) is expired before the
 * pinhole was matched.
 */
__attribute__((nonnull))
static void alg_pinhole_release_reservation(struct alg_pinhole *ap)
{
	struct cgn_map *cmi;

	cmi = &ap->ap_cmi;

	if (cmi->cmi_reserved) {
		cgn_map_put(cmi, ap->ap_vrfid);
		assert(!cmi->cmi_reserved);
	}
}

/*
 * Delete pinhole table entry
 */
__attribute__((nonnull))
static int alg_pinhole_del(struct alg_pinhole_tbl *tt, struct alg_pinhole *ap)
{
	struct cgn_session *cse;
	int rc;

	assert(ap->ap_expired);

	/* Delete from pinhole table */
	rc = cds_lfht_del(tt->tt_ht, &ap->ap_node);
	if (rc < 0)
		return rc;

	assert(rte_atomic32_read(&tt->tt_count) > 0);
	rte_atomic32_dec(&tt->tt_count);

	/* Release any unused CGNAT port reservation */
	alg_pinhole_release_reservation(ap);

	/* Release hold on session */
	cse = rcu_dereference(ap->ap_cse);
	cse = rcu_cmpxchg_pointer(&ap->ap_cse, cse, NULL);
	if (cse)
		cgn_session_put(cse);

	/* Release 'table' reference on pinhole entry */
	alg_pinhole_put(ap);

	return 0;
}

/**************************************************************************
 * Pinhole Entry Accessors
 **************************************************************************/

enum cgn_alg_id alg_pinhole_alg_id(struct alg_pinhole *ap)
{
	return ap->ap_alg_id;
}

struct cgn_session *alg_pinhole_cse(struct alg_pinhole *ap)
{
	return ap->ap_cse;
}

struct cgn_map *alg_pinhole_map(struct alg_pinhole *ap)
{
	return &ap->ap_cmi;
}

bool alg_pinhole_has_mapping(struct alg_pinhole *ap)
{
	return ap->ap_cmi.cmi_reserved;
}

enum cgn_dir alg_pinhole_dir(struct alg_pinhole *ap)
{
	return ap->ap_dir;
}

/**************************************************************************
 * Pinhole Expiry and Garbage Collection
 **************************************************************************/

struct rte_timer alg_pinhole_gc_timer;

/* Seconds */
#define ALG_PINHOLE_GC_INTERVAL 5

/*
 * Default timeout if one is not specified by individual ALG
 */
#define ALG_PINHOLE_TIMEOUT	10
#define ALG_PINHOLE_TIMEOUT_MS	(ALG_PINHOLE_TIMEOUT * MSEC_PER_SEC)

/*
 * Set expiry time for new pinhole.  Expiry time is a future value of
 * soft_ticks in millisecs.
 */
__attribute__((nonnull))
static void alg_pinhole_set_expiry_time(struct alg_pinhole *ap,
					uint16_t timeout)
{
	if (timeout) {
		ap->ap_timeout = timeout * MSEC_PER_SEC;
		ap->ap_expiry_time = soft_ticks + ap->ap_timeout;
	} else {
		/* Default expiry time */
		ap->ap_timeout = 0;
		ap->ap_expiry_time = soft_ticks + ALG_PINHOLE_TIMEOUT_MS;
	}
}

/*
 * Expire a pinhole.  This means it is no longer findable in the hash table
 * lookup.  A pinhole will be deleted from the table 5-10 secs after being
 * expired (1-2 GC periods).
 */
__attribute__((nonnull)) void alg_pinhole_expire(struct alg_pinhole *ap)
{
	if (!ap->ap_expired)
		ap->ap_expired = true;
}

static int alg_pinhole_timer_start(void);

/*
 * Garbage collection.
 *
 * Pass #1: Expire pinhole
 * Pass #2: Mark pinhole as 'removing'
 * Pass #3: Delete pinhole
 */
static void alg_pinhole_gc(struct rte_timer *timer __unused, void *arg __unused)
{
	struct alg_pinhole_tbl *tt = &alg_pinhole_table;
	struct cds_lfht_iter iter;
	struct alg_pinhole *ap;

	if (!tt->tt_ht)
		return;

	cds_lfht_for_each_entry(tt->tt_ht, &iter, ap, ap_node) {
		if (soft_ticks <= ap->ap_expiry_time)
			continue;

		if (!ap->ap_expired) {
			alg_pinhole_expire(ap);
			continue;
		}
		if (!ap->ap_removing) {
			ap->ap_removing = true;
			continue;
		}
		alg_pinhole_del(tt, ap);
	}

	/* Restart timer if dataplane is still running. */
	if (running)
		(void)alg_pinhole_timer_start();
}

/* Start or restart pinhole GC timer */
static int alg_pinhole_timer_start(void)
{
	return rte_timer_reset(&alg_pinhole_gc_timer,
			       ALG_PINHOLE_GC_INTERVAL * rte_get_timer_hz(),
			       SINGLE, rte_get_master_lcore(), alg_pinhole_gc,
			       NULL);
}

static void alg_pinhole_timer_stop(void)
{
	(void)rte_timer_stop(&alg_pinhole_gc_timer);
}

static void alg_pinhole_timer_init(void)
{
	rte_timer_init(&alg_pinhole_gc_timer);
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

	alg_pinhole_timer_init();

	rc = alg_pinhole_timer_start();
	if (rc < 0)
		return rc;

	/* Allow entries to be added */
	alg_pinhole_table.tt_active = true;

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

	alg_pinhole_timer_stop();

	alg_pinhole_tbl_destroy(&alg_pinhole_table);
}
