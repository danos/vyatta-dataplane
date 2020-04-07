/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Address and port tuple database.  Used by ALGs to store 'interesting'
 * partial tuples.
 *
 * There are two hash tables per VRF instance - the 'dport' table and the
 * 'tuple' table.  These contain entries for multiple features (where one
 * feature is npf alg, and a second feature is cgnat alg).
 *
 * The dport table key comprises:
 *
 *   1. protocol,
 *   2. dest port, and
 *   3. feature ID (npf or cgnat).
 *
 * The tuple table key comprises:
 *
 *   1. interface index,
 *   2. protocol,
 *   3. source address and (optionally) port,
 *   4. destination address and port,
 *   5. feature ID (npf or cgnat).
 *
 * If src port is set to 0 then this indicates the entry should match any src
 * port.
 *
 *
 * dport Table
 *
 * The dport table entries are long-lived.  These are typically the well-known
 * ports for the respective ALG, e.g. port 21 for ftp, 5060 for SIP etc.
 *
 * Entries are created when an ALG is enabled.  The dport table is used to
 * identify ALG control flows.  The dport table is looked up just after a new
 * session has been created.  If an entry is found then the packet is passed
 * to the specific ALG for inspection.
 *
 *
 * tuple Table
 *
 * The tuple table entries are typically short-lived.  These are created as a
 * result of inspecting packets identified by a dport table entry.  These
 * 'control' packet typically contain information in the payload to identify
 * secondary flow addresses and/or ports.  This information is used to create
 * tuple table entries.
 *
 * The tuple table is typically looked-up whenever the feature (e.g. npf)
 * fails to find a session during its normal stateful lookup behaviour
 * (e.g. npf NAT or stateful firewall).  If an entry is found then an ALG
 * secondary (or 'child') session is created, and linked to the session that
 * originally created the tuple (i.e. the 'parent' session).
 *
 * These entries are normally expired whenever a secondary flow is detected
 * (and session created), since they are no longer required.
 *
 * Some tuple table entries may be long-lived, e.g. SIP adds a 'keep' tuple
 * with 'any src port' to detect a secondary flow.  It does this since it uses
 * its own mechanism to timeout SIP Requests, and hence timeout the tuple.
 *
 *
 * Separate counts are maintained per-feature for the number of entries each
 * feature has in the dport and tuple tables.
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
#include "dp_event.h"
#include "vrf.h"

#include "npf/alg/apt/apt_public.h"
#include "npf/alg/apt/apt_dport.h"
#include "npf/alg/apt/apt_tuple.h"
#include "npf/alg/apt/apt.h"


/* Forward references */
static void apt_vrf_create(struct vrf *vrf);
static void apt_instance_destroy(struct apt_instance *ai);


/*
 * Format an apt key into a string
 */
int apt_key_str(struct apt_key *key, char *dst, size_t sz)
{
	char saddr[INET6_ADDRSTRLEN];
	char daddr[INET6_ADDRSTRLEN];
	int l = 0;

	if (key->v4_key.k4_alen == 4) {
		inet_ntop(AF_INET, &key->v4_key.k4_saddr,
			  saddr, sizeof(saddr));
		inet_ntop(AF_INET, &key->v4_key.k4_daddr,
			  daddr, sizeof(daddr));
	} else {
		inet_ntop(AF_INET6, &key->v6_key.k6_saddr,
			  saddr, sizeof(saddr));
		inet_ntop(AF_INET6, &key->v6_key.k6_daddr,
			  daddr, sizeof(daddr));
	}

	l += snprintf(dst+l, sz-l, "intf=%u", key->v4_key.k4_ifindex);
	l += snprintf(dst+l, sz-l, " %s",
		      key->v4_key.k4_proto == IPPROTO_TCP ? "TCP" : "UDP");

	l += snprintf(dst+l, sz-l, " %s %u",
		      saddr, ntohs(key->v4_key.k4_sport));
	l += snprintf(dst+l, sz-l, " %s %u",
		      daddr, ntohs(key->v4_key.k4_dport));

	return l;
}

/**************************************************************************
 * APT VRF Instance
 **************************************************************************/

/*
 * Set the apt instance in a vrf
 */
static int apt_set_vrf_instance(struct vrf *vrf, struct apt_instance *ai)
{
	struct apt_instance *old;

	if (!vrf || !ai)
		return -EINVAL;

	old = rcu_cmpxchg_pointer(&vrf->v_apt, NULL, ai);
	if (old)
		return -EEXIST;

	return 0;
}

/*
 * Get apt instance from a vrf
 */
static struct apt_instance *apt_instance_from_vrf(struct vrf *vrf)
{
	if (vrf)
		return rcu_dereference(vrf->v_apt);
	return NULL;
}

/*
 * Get apt instance from an internal vrf_id
 */
struct apt_instance *apt_instance_from_vrfid(vrfid_t vrf_id)
{
	struct vrf *vrf = get_vrf(vrf_id);
	if (vrf)
		return rcu_dereference(vrf->v_apt);
	return NULL;
}

/*
 * Create apt vrf instance
 */
static struct apt_instance *apt_instance_create(struct vrf *vrf)
{
	struct apt_instance *ai;
	int rc;

	ai = zmalloc_aligned(sizeof(*ai));
	if (!ai)
		return NULL;

	rc = apt_dport_tbl_create(&ai->ai_dport);
	if (rc < 0)
		goto error;

	rc = apt_tuple_tbl_create(&ai->ai_tuple);
	if (rc < 0)
		goto error;

	ai->ai_vrfid = dp_vrf_get_external_id(vrf->v_id);
	rte_atomic32_set(&ai->ai_refcnt, 0);

	return ai;

error:
	apt_instance_destroy(ai);
	return NULL;
}

/*
 * Find or create an apt vrf instance.
 *
 * Called from alg_instance_create (which is called via DP_EVT_VRF_CREATE
 * event).  May also be called from unit-tests.
 *
 * ALGs are the only user of the APT instance.
 */
struct apt_instance *apt_instance_find_or_create(struct vrf *vrf)
{
	struct apt_instance *ai;

	assert(vrf);

	ai = apt_instance_from_vrf(vrf);
	if (!ai) {
		apt_vrf_create(vrf);
		ai = apt_instance_from_vrf(vrf);
	}

	return ai;
}

/*
 * Destroy an apt vrf instance immediately
 */
static void apt_instance_destroy(struct apt_instance *ai)
{
	if (!ai)
		return;

	apt_dport_tbl_destroy(&ai->ai_dport);
	apt_tuple_tbl_destroy(&ai->ai_tuple);

	free(ai);
}

static void apt_instance_destroy_rcu(struct rcu_head *head)
{
	struct apt_instance *ai;

	ai = caa_container_of(head, struct apt_instance, ai_rcu);
	apt_instance_destroy(ai);
}

struct apt_instance *apt_instance_get(struct apt_instance *ai)
{
	if (ai)
		rte_atomic32_inc(&ai->ai_refcnt);

	return ai;
}

/*
 * Asynchronously destroy ai when last reference is removed
 */
void apt_instance_put(struct apt_instance *ai)
{
	if (ai && rte_atomic32_dec_and_test(&ai->ai_refcnt))
		call_rcu(&ai->ai_rcu, apt_instance_destroy_rcu);
}

static void apt_instance_jsonw(json_writer_t *json, vrfid_t vrf_id)
{
	struct apt_instance *ai = apt_instance_from_vrfid(vrf_id);

	jsonw_start_object(json);
	jsonw_uint_field(json, "vrfid", dp_vrf_get_external_id(vrf_id));

	apt_dport_tbl_jsonw(json, &ai->ai_dport);
	apt_tuple_tbl_jsonw(json, &ai->ai_tuple);

	jsonw_end_object(json);
}

/*
 * Write apt json for one VRF or all VRFs.
 */
void apt_jsonw(FILE *f, vrfid_t vrf_id)
{
	json_writer_t *json = jsonw_new(f);
	struct vrf *vrf;

	jsonw_name(json, "apt");
	jsonw_start_object(json);

	jsonw_name(json, "instances");
	jsonw_start_array(json);

	if (vrf_id == VRF_INVALID_ID) {
		VRF_FOREACH(vrf, vrf_id) {
			apt_instance_jsonw(json, vrf_id);
		}
	} else
		apt_instance_jsonw(json, vrf_id);

	jsonw_end_array(json);
	jsonw_end_object(json);
	jsonw_destroy(&json);
}


/**************************************************************************
 * GC Timer
 **************************************************************************/

/* One-time timer initialization */
static bool apt_timer_running;

struct rte_timer apt_gc_timer;
#define APT_GC_INTERVAL 5

static void apt_start_timer(void);

static void apt_instance_gc(struct apt_instance *ai)
{
	/*
	 * dport entries must be manually expired elsewhere.  Expired entries
	 * are deleted after two passes of the garbage collector.
	 */
	apt_dport_tbl_gc(&ai->ai_dport);

	/*
	 * tuple entries are either manually expired elsewhere, or timed out
	 * and expired by the gc.  Expired entries are deleted after two
	 * passes of the garbage collector.
	 */
	apt_tuple_tbl_gc(&ai->ai_tuple, soft_ticks);
}

/*
 * Garbage collection.
 */
static void apt_gc(struct rte_timer *timer __rte_unused, void *arg __rte_unused)
{
	struct apt_instance *ai;
	struct vrf *vrf;
	vrfid_t vrfid;

	VRF_FOREACH(vrf, vrfid) {
		ai = apt_instance_from_vrf(vrf);
		if (ai)
			apt_instance_gc(ai);
	}

	/* Restart timer if dataplane still running. */
	if (running)
		apt_start_timer();
}

static void apt_start_timer(void)
{
	rte_timer_reset(&apt_gc_timer,
			APT_GC_INTERVAL * rte_get_timer_hz(),
			SINGLE, rte_get_master_lcore(), apt_gc, NULL);
}

static void apt_stop_timer(void)
{
	rte_timer_stop(&apt_gc_timer);
}

/*
 * Flush all table entries on an apt instance.
 *
 * Expired entries are deleted.  Unexpired entried are expired.
 *
 * If flush_all is *not* set true then only non-keep tuple entries are expired.
 * If flush_all *is* set true then all dport and tuple entries are expired.
 */
void apt_flush_instance(struct apt_instance *ai, int feat, bool flush_all)
{
	int f;

	if (!ai)
		return;

	if (feat <= ALG_FEAT_MAX) {
		apt_dport_tbl_flush(&ai->ai_dport, feat, flush_all,
				    NULL, NULL);
		apt_tuple_tbl_flush(&ai->ai_tuple, feat, flush_all,
				    NULL, NULL);
	} else {
		for (f = ALG_FEAT_FIRST; f <= ALG_FEAT_LAST; f++) {
			apt_dport_tbl_flush(&ai->ai_dport, f, flush_all,
					    NULL, NULL);
			apt_tuple_tbl_flush(&ai->ai_tuple, f, flush_all,
					    NULL, NULL);
		}
	}
}

/*
 * Flush matching tuple entries.
 *
 * Typically used when a feature session expires in order to expire tuples
 * created by that session.  Also used when the VRF instance is being
 * destroyed.
 */
void apt_flush_matching_tuples(struct apt_instance *ai, int feat,
			       bool flush_all, apt_match_func_t match_fn,
			       void *match_key)
{
	if (ai)
		apt_tuple_tbl_flush(&ai->ai_tuple, feat, flush_all,
				    match_fn, match_key);
}


/**************************************************************************
 * Dataplane Event Handlers
 **************************************************************************/

/*
 * DP_EVT_VRF_CREATE event handler
 *
 * This is called indirectly via the ALG DP_EVT_VRF_CREATE event handle as
 * that is currently the only user of the APT tables.  However it is written
 * such that it could be directly used as an DP_EVT_VRF_CREATE event handler
 * if required.
 */
static void apt_vrf_create(struct vrf *vrf)
{
	struct apt_instance *ai;
	int rc;

	if (!vrf || vrf->v_id == VRF_INVALID_ID)
		return;

	/* Ignore call if apt instance already exists */
	if (apt_instance_from_vrf(vrf))
		return;

	ai = apt_instance_create(vrf);
	if (!ai)
		return;

	rc = apt_set_vrf_instance(vrf, ai);

	if (rc < 0) {
		apt_instance_destroy(ai);
		return;
	}

	/* Take reference on instance */
	apt_instance_get(ai);

	/* Allow entries to be added to the tables */
	ai->ai_enabled = true;

	/* Only start timer when first instance is created */
	if (!apt_timer_running) {
		apt_start_timer();
		apt_timer_running = true;
	}
}

/*
 * DP_EVT_VRF_DELETE event handler
 */
static void apt_vrf_delete(struct vrf *vrf)
{
	struct apt_instance *ai;

	if (!vrf || vrf->v_id == VRF_INVALID_ID)
		return;

	ai = rcu_dereference(vrf->v_apt);

	ai = rcu_cmpxchg_pointer(&vrf->v_apt, ai, NULL);
	if (!ai)
		return;

	/* Disallow entries from being added to the tables */
	ai->ai_enabled = false;

	/*
	 * Call apt_flush_instance twice.  First time will delete any expired
	 * table entries and expire all non-expired entries.  Second time will
	 * delete all the entries expired by the first call.
	 */
	apt_flush_instance(ai, ALG_FEAT_ALL, true);
	apt_flush_instance(ai, ALG_FEAT_ALL, true);

	/* Release reference on apt instance */
	apt_instance_put(ai);
}

/* Unit-test only */
void dpt_apt_vrf_delete(vrfid_t vrf_id)
{
	struct vrf *vrf = get_vrf(vrf_id);

	apt_vrf_delete(vrf);
}

/*
 * DP_EVT_UNINIT event handler
 */
static void apt_uninit(void)
{
	apt_stop_timer();
	apt_timer_running = false;
}

/*
 * APT Dataplane Event Handler
 */
static const struct dp_event_ops apt_event_ops = {
	.uninit = apt_uninit,
	.vrf_delete = apt_vrf_delete,
};

/* Register event handler */
DP_STARTUP_EVENT_REGISTER(apt_event_ops);
