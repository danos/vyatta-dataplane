/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_timer.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <urcu/list.h>

#include "compiler.h"
#include "if_var.h"
#include "npf/config/npf_attach_point.h"
#include "npf/config/npf_config.h"
#include "npf/config/npf_ruleset_type.h"
#include "npf/npf_if.h"
#include "npf/npf_ruleset.h"
#include "npf/npf_session.h"
#include "npf/npf_vrf.h"
#include "npf/cgnat/cgn_if.h"
#include "util.h"
#include "vplane_log.h"

#ifdef REFCNTS_DEBUG
static const bool Refcnts_Debug = true;
#else /* REFCNTS_DEBUG */
static const bool Refcnts_Debug = false;
#endif /* REFCNTS_DEBUG */

enum /* nif_flags */ {
	NPF_IF_REMOVABLE	= (1 <<  0),
	NPF_IF_DEAD		= (1 <<  1),
};

/*
 * Internal npf interface structure
 */
struct npf_if_internal {
	struct npf_if		niif_if;

	uint32_t		niif_refcnt;
	uint32_t		niif_flags;
	struct cgn_intf		*niif_cgn;
	struct cds_list_head	niif_list;

	/*
	 * Per interface ruleset count.  Used for rulesets that attach to an
	 * interface.  This includes:
	 *
	 * fw-in, fw-out, dnat, snat, nat64, pbr, nptv6-in, nptv6-out
	 * bridge, session-rproc, portmonitor-in, portmonitor-out
	 *
	 * Note the attach point commit event callbacks mean we are only
	 * notified when a ruleset-type is first attached to an interface, and
	 * when the last ruleset of a given type has been removed from an
	 * interface.  As such, the 'counts' for these type of rulesets will
	 * only be 0 or 1.  However we maintain a count (instead of a boolean)
	 * so that rulesets can use the variable that way if they so choose.
	 */
	uint16_t		niif_rs_count[NPF_RS_TYPE_COUNT];
};

/* Forward reference */
static void npf_if_rs_count_decr_to_zero(struct ifnet *ifp, uint rulesets);

/*
 * npf interface structure garbage collection list and timer
 */
static CDS_LIST_HEAD(npf_if_gc_list);

#define NPF_IF_GC		5
static struct rte_timer npf_if_timer;

static rte_spinlock_t niif_lock = RTE_SPINLOCK_INITIALIZER;

/* Clean up an free the interface-specific npf state */
static void
npf_if_dealloc(struct npf_if_internal *niif)
{
	free(niif);	/* call_rcu not required */
}

/*
 * Periodic garbage collection
 *
 * NB: This is a callback function for rte_timer_reset(), so we use
 *     __rte_unused rather than __unused.
 */
static void
npf_if_gc(struct rte_timer *t __rte_unused, void *arg __rte_unused)
{
	struct npf_if_internal *niif, *n;

	cds_list_for_each_entry_safe(niif, n, &npf_if_gc_list, niif_list) {
		if (niif->niif_flags & NPF_IF_DEAD) {
			cds_list_del(&niif->niif_list);
			npf_if_dealloc(niif);
		} else if (niif->niif_flags & NPF_IF_REMOVABLE) {
			niif->niif_flags |= NPF_IF_DEAD;
		} else {
			niif->niif_flags |= NPF_IF_REMOVABLE;
		}
	}
}

/*
 * Take a reference on an NPF interface structure.  If it does not exist, then
 * create it.  May be called from either forwarding thread or master loop.
 * This is called when:
 *
 * 1. After DP_EVT_IF_INDEX_SET event if interface has interface attach points
 * 2. A session is activated on an interface
 * 3. npf config (e.g. nat64) on a different interface requires npf features
 *    to be enabled on all other interfaces
 *
 * initial_sess_count should be set to 1 for item #3, otherwise is should be
 * set to 0.
 */
static struct npf_if_internal *
npf_if_niif_create(struct ifnet *ifp, uint32_t initial_sess_count)
{
	struct npf_if_internal *niif;

	niif = (struct npf_if_internal *)ifp->if_npf;

	assert(rte_spinlock_is_locked(&niif_lock));

	if (!niif) {
		niif = zmalloc_aligned(sizeof(*niif));
		if (!niif) {
			RTE_LOG(ERR, FIREWALL, "i/f get: id=%u (%s)\n",
				ifp->if_index, ifp->if_name);
			return NULL;
		}
		niif->niif_if.nif_ifp = ifp;
		niif->niif_if.nif_sess = initial_sess_count;

		CDS_INIT_LIST_HEAD(&niif->niif_list);
		rcu_assign_pointer(ifp->if_npf, &niif->niif_if);
	}

	niif->niif_refcnt++;

	if (Refcnts_Debug)
		RTE_LOG(ERR, DATAPLANE, "%s: %s: refcnt now %u\n", __func__,
			ifp->if_name, niif->niif_refcnt);

	return niif;
}

/*
 * Remove reference from NPF interface structure.  If it is the last
 * reference, then NULL ifp->if_npf pointer and place niif onto the garbage
 * collection list.  May be called from either forwarding thread or master
 * loop.
 */
static void
npf_if_niif_delete(struct ifnet *ifp)
{
	struct npf_if_internal *niif = (struct npf_if_internal *)ifp->if_npf;

	assert(rte_spinlock_is_locked(&niif_lock));

	assert(niif != NULL);
	if (!niif)
		return;

	assert(niif->niif_refcnt >= 1);
	if (niif->niif_refcnt == 0)
		return;

	if (--niif->niif_refcnt == 0) {
		if (niif->niif_if.nif_sess)
			npf_session_disassoc_nif(ifp->if_index);

		rcu_assign_pointer(ifp->if_npf, NULL);
		cds_list_add_tail(&niif->niif_list, &npf_if_gc_list);
	}

	if (Refcnts_Debug)
		RTE_LOG(ERR, DATAPLANE, "%s: %s: refcnt now %u\n", __func__,
			ifp->if_name, niif->niif_refcnt);
}

/*
 * Take reference on interface niif
 */
void npf_if_reference_one(struct ifnet *ifp, void *arg __unused)
{
	npf_if_niif_create(ifp, 0);
}

/*
 * Take reference on niif for all interfaces.  Typically this happens when
 * nat64 is configured on one interface.
 */
void npf_if_reference_all(void)
{
	ifnet_walk(npf_if_reference_one, NULL);
}

/*
 * Release reference on interface niif
 */
void npf_if_release_one(struct ifnet *ifp, void *arg __unused)
{
	npf_if_niif_delete(ifp);
}

/*
 * Release reference on niif for all interfaces
 */
void npf_if_release_all(void)
{
	ifnet_walk(npf_if_release_one, NULL);
}

/*
 * npf_if_sessions_handling_enable
 *
 * Called when nif->nif_sess changes from 0 to 1.
 *
 * Note that "nif_exists" is set to false if the "nif" structure did
 * not exist. This also indicates that the session count has not been
 * incremented, and so should be initialised.
 */
void
npf_if_sessions_handling_enable(struct ifnet *ifp, bool nif_exists)
{
	struct npf_if_internal *niif;

	rte_spinlock_lock(&niif_lock);

	niif = (struct npf_if_internal *)ifp->if_npf;

	if (!nif_exists && niif) {
		/* Lost the race, as it was created by another thread. */
		uatomic_inc(&niif->niif_if.nif_sess);
		goto end;
	}

	/*
	 * Increment refcount for nif structure. It may not exist yet if
	 * sessions are only created due to DPI. Tell npf_if_niif_create() to
	 * initialise the session refcount to 1 (if it creates one), so a
	 * concurrent thread calling npf_if_session_inc() would increment it
	 * correctly.
	 */
	niif = npf_if_niif_create(ifp, 1);

	assert(niif != NULL);
	if (!niif)
		goto end;

	/* Enable defrag and fw features on interface */
	if_feat_refcnt_incr(ifp, IF_FEAT_DEFRAG);
	if_feat_refcnt_incr(ifp, IF_FEAT_FW);

end:
	rte_spinlock_unlock(&niif_lock);
}

/*
 * npf_if_sessions_handling_disable
 *
 * Called when nif->nif_sess changes from 1 to 0, which will occur when the
 * last session on an interface is destroyed.
 *
 * However the call to npf_if_session_dec, and hence
 * npf_if_sessions_handling_disable, will *only* happen if the interface
 * exists and is still active.  Hence we also call this from
 * npf_if_disable_with_name.
 */
void
npf_if_sessions_handling_disable(struct ifnet *ifp, bool lock)
{
	struct npf_if_internal *niif;

	if (lock)
		rte_spinlock_lock(&niif_lock);

	niif = (struct npf_if_internal *)ifp->if_npf;

	assert(niif != NULL);
	if (niif == NULL)
		goto end;

	/* Disable defrag and fw features on interface */
	if_feat_refcnt_decr(ifp, IF_FEAT_DEFRAG);
	if_feat_refcnt_decr(ifp, IF_FEAT_FW);

	/* Remove reference on npf interface structure. */
	npf_if_niif_delete(ifp);

end:
	if (lock)
		rte_spinlock_unlock(&niif_lock);
}

/*
 * npf_if_alloc_free
 *
 * npf_attpt_item_set_up callback for attach type NPF_ATTACH_TYPE_INTERFACE,
 * which in turn is driven by DP_EVT_IF_INDEX_SET and DP_EVT_IF_INDEX_UNSET
 * dataplane events.
 */
static int
npf_if_alloc_free(struct npf_config **npf_confp, bool alloc)
{
	struct ifnet *ifp = container_of((struct npf_if **) npf_confp,
					 struct ifnet, if_npf);
	struct npf_if_internal *niif;
	int err = 0;

	rte_spinlock_lock(&niif_lock);

	if (alloc) {
		niif = npf_if_niif_create(ifp, 0);

		assert(niif);
		if (niif == NULL) {
			err = -ENOMEM;
			goto end;
		}
	} else {
		assert(*npf_confp);
		if (*npf_confp == NULL) {
			err = -ENOENT;
			goto end;
		}
		npf_if_niif_delete(ifp);
	}

end:
	rte_spinlock_unlock(&niif_lock);

	return err;
}

/*
 * Callback for dataplane DP_EVT_IF_INDEX_SET event.  Also used for
 * DP_EVT_IF_RENAME event.
 */
void
npf_if_enable(struct ifnet *ifp, uint32_t ifindex __unused)
{
	int rc;

	/* Cause any NPF rulesets to be built */
	rc = npf_attpt_item_set_up(NPF_ATTACH_TYPE_INTERFACE, ifp->if_name,
				   (struct npf_config **)&ifp->if_npf,
				   npf_if_alloc_free);
	if (rc != 0) {
		RTE_LOG(ERR, DATAPLANE, "NPF attpt raise fail: if/%s\n",
			ifp->if_name);
	}

	rte_spinlock_lock(&niif_lock);

	/*
	 * Are there any feature counts for the vrf this new interface is in?
	 * If so, enable those features on the interface and create a niif
	 * structure.
	 */
	npf_vrf_if_index_set(ifp);

	/* Is this interface used for cgnat? */
	cgn_nif_index_set(ifp);

	rte_spinlock_unlock(&niif_lock);
}

/*
 * Callback for dataplane DP_EVT_IF_INDEX_UNSET event.  Also used for
 * DP_EVT_IF_RENAME event, in which case if_name is the old interface name.
 */
static void
npf_if_disable_with_name(struct ifnet *ifp, const char *if_name)
{
	/* Cause any NPF rulesets to be brought down */
	int rc = npf_attpt_item_set_down(NPF_ATTACH_TYPE_INTERFACE, if_name);

	if (rc != 0)
		RTE_LOG(ERR, DATAPLANE, "NPF attpt lower fail: if/%s\n",
			ifp->if_name);

	if (!ifp->if_npf)
		return;

	rte_spinlock_lock(&niif_lock);

	/*
	 * If a session took a reference on the interface, then release it.
	 * (This replaces the call to npf_if_session_dec by
	 * npf_session_destroy, which will not occur for an inactive
	 * interface)
	 */
	if (ifp->if_npf->nif_sess > 0)
		npf_if_sessions_handling_disable(ifp, false);

	/*
	 * Decrement per-interface ruleset counts to zero
	 */
	npf_if_rs_count_decr_to_zero(ifp, ~0);

	/* Is this interface used for cgnat? */
	cgn_nif_index_unset(ifp);

	/*
	 * Are there any feature counts for the vrf this interface?
	 * If so, disable those features on the interface.
	 */
	npf_vrf_if_index_unset(ifp);

	/*
	 * We used to force deleting the niif here.  This is no longer be
	 * necessary as the various ref counts should do the job for us.
	 */
	assert(ifp->if_npf == NULL);

	rte_spinlock_unlock(&niif_lock);
}

/*
 * Callback for DP_EVT_IF_INDEX_UNSET event
 */
void
npf_if_disable(struct ifnet *ifp, uint32_t ifindex __unused)
{
	npf_if_disable_with_name(ifp, ifp->if_name);
}

/*
 * Callback for DP_EVT_IF_RENAME event
 */
void
npf_if_rename(struct ifnet *ifp, const char *old_ifname)
{
	npf_if_disable_with_name(ifp, old_ifname);
	npf_if_enable(ifp, ifp->if_index);
}

/*
 * Increment interface ruleset count, and global ruleset count.
 */
void
npf_if_rs_count_incr(struct ifnet *ifp, enum npf_ruleset_type rs_type)
{
	if (!ifp || !ifp->if_npf || rs_type >= NPF_RS_TYPE_COUNT)
		return;

	struct npf_if_internal *niif = (struct npf_if_internal *)ifp->if_npf;

	assert(niif->niif_rs_count[rs_type] < USHRT_MAX);
	if (niif->niif_rs_count[rs_type] == USHRT_MAX) {
		RTE_LOG(ERR, DATAPLANE,
			"Cannot increment %s %s ruleset count above max\n",
			npf_get_ruleset_type_name(rs_type),
			ifp->if_name);
		return;
	}

	/*
	 * Increment interface feature ref counts for this ruleset type when
	 * the ruleset count changes from 0 to 1 if it is a 'per interface'
	 * type.
	 */
	if (niif->niif_rs_count[rs_type]++ == 0) {
		enum npf_rs_flag rfl;

		/* Are features enabled per-interface? */
		rfl = npf_get_ruleset_type_flags(rs_type);

		if ((rfl & NPF_RS_FLAG_FEAT_INTF) != 0) {
			enum if_feat_flag ffl;

			/* Enable relevant features for this interface */
			ffl = npf_get_ruleset_type_feat_flags(rs_type);
			if_feat_intf_multi_refcnt_incr(ifp, ffl);
		}
	}

	npf_gbl_rs_count_incr(rs_type);
}

/*
 * Decrement interface ruleset count, and global ruleset count.
 */
void
npf_if_rs_count_decr(struct ifnet *ifp, enum npf_ruleset_type rs_type)
{
	if (!ifp || !ifp->if_npf || rs_type >= NPF_RS_TYPE_COUNT)
		return;

	struct npf_if_internal *niif = (struct npf_if_internal *)ifp->if_npf;

	assert(niif->niif_rs_count[rs_type] > 0);
	if (niif->niif_rs_count[rs_type] == 0) {
		RTE_LOG(ERR, DATAPLANE,
			"Cannot decrement %s %s ruleset count below zero\n",
			npf_get_ruleset_type_name(rs_type),
			ifp->if_name);
		return;
	}

	/*
	 * Decrement interface feature ref counts for this ruleset type when
	 * the ruleset count changes from 1 to 0 if it is a 'per interface'
	 * type.
	 */
	if (--niif->niif_rs_count[rs_type] == 0) {
		enum npf_rs_flag rfl;

		/* Are features enabled per-interface? */
		rfl = npf_get_ruleset_type_flags(rs_type);

		if ((rfl & NPF_RS_FLAG_FEAT_INTF) != 0) {
			enum if_feat_flag ffl;

			/* Disable relevant features for this interface */
			ffl = npf_get_ruleset_type_feat_flags(rs_type);
			if_feat_intf_multi_refcnt_decr(ifp, ffl);
		}
	}

	npf_gbl_rs_count_decr(rs_type);
}

/*
 * Interface is going away.  Decrement all counts to zero.
 */
static void npf_if_rs_count_decr_to_zero(struct ifnet *ifp, uint rulesets)
{
	if (!ifp || !ifp->if_npf)
		return;

	struct npf_if_internal *niif = (struct npf_if_internal *)ifp->if_npf;
	enum npf_ruleset_type rs_type;

	for (rs_type = 0; rs_type < NPF_RS_TYPE_COUNT; rs_type++) {
		if ((BIT(rs_type) & rulesets) == 0)
			continue;
		while (niif->niif_rs_count[rs_type] > 0)
			npf_if_rs_count_decr(ifp, rs_type);
	}
}

/*
 * npf attach point NPF_ATTPT_EV_RLSET_ADD_COMMIT event.  Called when first
 * ruleset of a given type is added to an attach point.
 */
static npf_attpt_ev_cb npf_if_apev_if_add_rlset;
static void
npf_if_apev_if_add_rlset(enum npf_attpt_ev_type ev __unused,
		   struct npf_attpt_item *ap, void *data)
{
	enum npf_ruleset_type *ruleset_type = (enum npf_ruleset_type *) data;
	const struct npf_attpt_key *apk = npf_attpt_item_key(ap);

	struct ifnet *ifp = ifnet_byifname(apk->apk_point);
	if (!ifp || !ifp->if_index)
		return;

	rte_spinlock_lock(&niif_lock);
	npf_if_rs_count_incr(ifp, *ruleset_type);
	rte_spinlock_unlock(&niif_lock);
}

/*
 * npf attach point NPF_ATTPT_EV_RLSET_DEL_COMMIT event.  Called when the last
 * ruleset of a given type is removed from an attach point.
 */
static npf_attpt_ev_cb npf_if_apev_if_del_rlset;
static void
npf_if_apev_if_del_rlset(enum npf_attpt_ev_type ev __unused,
		   struct npf_attpt_item *ap, void *data)
{
	enum npf_ruleset_type *ruleset_type = (enum npf_ruleset_type *) data;
	const struct npf_attpt_key *apk = npf_attpt_item_key(ap);

	struct ifnet *ifp = ifnet_byifname(apk->apk_point);
	if (!ifp || !ifp->if_index)
		return;

	rte_spinlock_lock(&niif_lock);
	npf_if_rs_count_decr(ifp, *ruleset_type);
	rte_spinlock_unlock(&niif_lock);
}

/*
 * npf_if_init
 */
void npf_if_init(void)
{
	rte_timer_init(&npf_if_timer);
	rte_timer_reset(&npf_if_timer, NPF_IF_GC * rte_get_timer_hz(),
			PERIODICAL, rte_get_master_lcore(), npf_if_gc, NULL);

	npf_attpt_ev_listen(NPF_ATTACH_TYPE_INTERFACE,
			    (1 << NPF_ATTPT_EV_RLSET_ADD_COMMIT),
			    npf_if_apev_if_add_rlset);
	npf_attpt_ev_listen(NPF_ATTACH_TYPE_INTERFACE,
			    (1 << NPF_ATTPT_EV_RLSET_DEL_COMMIT),
			    npf_if_apev_if_del_rlset);
}

/*
 * npf_if_cleanup
 */
void npf_if_cleanup(void)
{
	npf_if_gc(NULL, NULL);
	npf_if_gc(NULL, NULL);
	npf_if_gc(NULL, NULL);
}

/*
 * Callback for DP_EVT_IF_ADDR_ADD DP_EVT_IF_ADDR_DEL events
 */
void npf_if_addr_change(enum cont_src_en cont_src, struct ifnet *ifp,
		uint32_t if_index __unused, int af, const void *addr __unused)
{
	if (cont_src != CONT_SRC_MAIN)
		return;

	/* Only for NPF nat masq, IPv6 unsupported */
	if (af == AF_INET6)
		return;

	if (!ifp)
		return;

	struct npf_if *nif = ifp->if_npf;
	if (!nif)
		return;

	/* Update if we have an SNAT ruleset */
	npf_ruleset_t *rs = nif->nif_conf.nc_rulesets[NPF_RS_SNAT];
	if (rs)
		npf_ruleset_update_masquerade(ifp, rs);
}

/*
 * Get cgnat interface structure.
 */
struct cgn_intf *npf_if_get_cgn(struct ifnet *ifp)
{
	struct npf_if_internal *niif;

	if (!ifp)
		return NULL;

	niif = (struct npf_if_internal *)ifp->if_npf;
	if (niif)
		return niif->niif_cgn;

	return NULL;
}

int npf_if_set_cgn(struct ifnet *ifp, struct cgn_intf *cgn)
{
	struct npf_if_internal *niif;
	int rc = 0;

	assert(!rte_spinlock_is_locked(&niif_lock));

	rte_spinlock_lock(&niif_lock);

	if (!ifp || !cgn) {
		rc = -1;
		goto end;
	}

	/* Take reference on niif.  Create, if necessary */
	niif = npf_if_niif_create(ifp, 0);
	if (!niif) {
		rc = -1;
		goto end;
	}

	rc = 0;
	rcu_assign_pointer(niif->niif_cgn, cgn);

end:
	rte_spinlock_unlock(&niif_lock);
	return rc;
}

int npf_if_clear_cgn(struct ifnet *ifp, bool lock)
{
	struct npf_if_internal *niif;
	struct cgn_intf *cgn;
	int rc = -1;

	if (lock) {
		assert(!rte_spinlock_is_locked(&niif_lock));
		rte_spinlock_lock(&niif_lock);
	} else {
		assert(rte_spinlock_is_locked(&niif_lock));
	}

	niif = (struct npf_if_internal *)ifp->if_npf;
	if (niif) {
		rc = 0;
		cgn = rcu_xchg_pointer(&niif->niif_cgn, NULL);

		/* Release reference on niif. */
		if (cgn)
			npf_if_niif_delete(ifp);
	}

	if (lock)
		rte_spinlock_unlock(&niif_lock);

	return rc;
}
