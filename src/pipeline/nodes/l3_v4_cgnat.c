/*
 * l3_v4_cgnat.c
 *
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * Carrier-grade NAT Feature Node
 */

#include <netinet/in.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_atomic.h>
#include <stdbool.h>

#include "compiler.h"
#include "ether.h"
#include "if_var.h"
#include "pktmbuf_internal.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "urcu.h"
#include "util.h"
#include "ip_funcs.h"
#include "ip_icmp.h"
#include "in_cksum.h"

#include "npf/npf.h"
#include "npf/npf_if.h"
#include "npf/npf_mbuf.h"
#include "npf/npf_addrgrp.h"
#include "npf/alg/alg_npf.h"

#include "npf/cgnat/alg/alg_public.h"
#include "npf/nat/nat_pool_public.h"
#include "npf/cgnat/cgn.h"
#include "npf/apm/apm.h"
#include "npf/cgnat/cgn_dir.h"
#include "npf/cgnat/cgn_rc.h"
#include "npf/cgnat/cgn_if.h"
#include "npf/cgnat/cgn_map.h"
#include "npf/cgnat/cgn_mbuf.h"
#include "npf/cgnat/cgn_policy.h"
#include "npf/cgnat/cgn_public.h"
#include "npf/cgnat/cgn_sess_state.h"
#include "npf/cgnat/cgn_session.h"
#include "npf/cgnat/cgn_source.h"
#include "npf/cgnat/cgn_test.h"


static bool
ipv4_cgnat_out_bypass(struct ifnet *ifp, struct rte_mbuf *mbuf)
{
	/* Check bypass enable/disable option */
	if (likely(!cgn_snat_alg_bypass_gbl))
		return false;

	/* Is SNAT configured on interface? */
	if (!npf_snat_active(ifp))
		return false;

	/* Does pkt match an ALG session or tuple? */
	if (!npf_alg_bypass_cgnat(ifp, mbuf))
		return false;

	return true;
}

/*
 * cgnat_try_initial
 *
 * If we matched an ALG pinhole earlier then the mapping info 'cmi' may
 * already be populated.
 *
 * Note that for inbound pkts matching an ALG tuple, cmi->cmi_oaddr will be
 * different from cpk->cpk_saddr. Some ALGs *may* elect not to attach a
 * mapping to an *outbound* pinhole.  Thats ok, as we will get a mapping here
 * for those cases.  Inbound pinholes MUST always contain a
 * mapping. (cmi_oaddr should *always* be a subscriber address.)
 */
static struct cgn_session *
cgnat_try_initial(struct cgn_map *cmi, struct ifnet *ifp,
		  struct cgn_packet *cpk, struct rte_mbuf *mbuf,
		  enum cgn_dir dir, int *error)
{
	struct cgn_session *cse;
	struct cgn_policy *cp;
	uint32_t oaddr;
	int rc = 0;
	vrfid_t vrfid = cpk->cpk_vrfid;

	/* Should SNAT-ALG pkts bypass CGNAT? */
	if (unlikely(ipv4_cgnat_out_bypass(ifp, mbuf))) {
		*error = -CGN_PCY_BYPASS;
		goto error;
	}

	/* cmi only has a reservation if an ALG pinhole was matched earlier */
	assert(!!cmi->cmi_reserved == (cpk->cpk_alg_id != CGN_ALG_NONE));

	/* Inbound pkts must have matched an ALG pinhole */
	assert(dir == CGN_DIR_OUT || cpk->cpk_alg_id != CGN_ALG_NONE);

	/*
	 * Get subscriber address.  This is found in the mapping info if we
	 * matched an ALG pinhole earlier, else it is found from the pkt
	 * cache.
	 */
	if (unlikely(cmi->cmi_reserved))
		/* Get subscriber addr from ALG pinhole */
		oaddr = cmi->cmi_oaddr;
	else
		/* Get subscriber addr from pkt */
		oaddr = cpk->cpk_saddr;

	assert(oaddr != 0);

	/*
	 * Lookup subscriber address in policy list on the interface.  This is
	 * how we determine that this is a CGNAT packet.  (Note, this is not
	 * strictly necessary for pkts that have matched an ALG, but we need
	 * the policy pointer regardless).
	 */
	cp = cgn_if_find_policy_by_addr(ifp, oaddr);
	if (!cp) {
		*error = -CGN_PCY_ENOENT;
		goto error;
	}

	/* Is this dest addr 'excluded' from translation? */
	if (unlikely(cp->cp_exclude_ag && dir == CGN_DIR_OUT)) {
		if (npf_addrgrp_lookup_v4_by_handle(
			    cp->cp_exclude_ag, cpk->cpk_daddr) == 0) {
			*error = -CGN_DST_EXCLUDED;
			goto error;
		}
	}

	/* If we find a policy then it must be a CGNAT packet */
	cpk->cpk_pkt_cgnat = true;

	/* Do not continue if session table is full */
	if (unlikely(cgn_session_table_full)) {
		*error = -CGN_S1_ENOSPC;
		goto error;
	}

	/* Get a mapping if we don't already have one from an ALG pinhole */
	if (!cmi->cmi_reserved) {
		cmi->cmi_proto = cpk->cpk_proto;
		cmi->cmi_oid = cpk->cpk_sid;
		cmi->cmi_oaddr = oaddr;

		/* Allocate public address and port */
		rc = cgn_map_get(cmi, cp, vrfid);

		if (rc) {
			*error = rc;
			goto error;
		}
	}

	/* Create a session. */
	cse = cgn_session_establish(cpk, cmi, dir, error);
	if (!cse)
		goto error;

	/* The mapping should have been consumed by the session */
	assert(!cmi->cmi_reserved);

	/* Check if we want to enable sub-sessions */
	cgn_session_try_enable_sub_sess(cse, cp, oaddr);

	return cse;

error:
	if (cmi->cmi_reserved)
		/* Release mapping */
		cgn_map_put(cmi, vrfid);

	return NULL;
}

/*
 * cgn_translate_at
 *
 * n_ptr should point to the start of the IP header.
 *
 * If 'embed' is true, then packet is an embedded packet whose 'direction'
 * (i.e. source and dest addrs) is opposite to that on the outer packet
 * 'direction'.
 *
 * If 'undo' is true, then we are undoing a translation in the same direction,
 * e.g. dir is OUT, and we are undoing the source translation.  This is the
 * case for packets that cause the router to generate an ICMP error *after*
 * the translation has taken place.
 */
static void
cgn_translate_at(struct cgn_packet *cpk, struct cgn_session *cse,
		 enum cgn_dir dir, void *n_ptr, bool embd, bool undo)
{
	uint32_t taddr;
	uint16_t tport;
	char *l3_ptr = (char *)n_ptr;
	char *l4_ptr = l3_ptr + cpk->cpk_l3_len;

	/*
	 * The 'forw' variable denotes if the translation is from orig to
	 * trans addr (forw=true), or the translation is from trans to orig
	 * addr (forw=false).
	 *
	 * For the normal case, forw=true when dir=CGN_DIR_OUT. However,
	 * forw=false when dir=CGN_DIR_OUT and undo=true since we are
	 * translating from the trans to the orig addr.
	 */
	bool forw;

	/*
	 * Pick the appropriate address and port.
	 *
	 * The session forwards entries have the original values,
	 * and the backwards entries have the translation values.
	 */
	if (likely(!undo)) {
		if (dir == CGN_DIR_IN) {
			/* Get orig addr from forw sentry */
			cgn_session_get_forw(cse, &taddr, &tport);
			forw = false;
		} else {
			/* Get trans addr from back sentry */
			cgn_session_get_back(cse, &taddr, &tport);
			forw = true;
		}
	} else {
		if (dir == CGN_DIR_OUT) {
			/* Get orig addr from forw sentry */
			cgn_session_get_forw(cse, &taddr, &tport);
			forw = false;
		} else {
			/* Get trans addr from back sentry */
			cgn_session_get_back(cse, &taddr, &tport);
			forw = true;
		}
	}

	/* Flip direction for embedded packets */
	if (unlikely(embd))
		dir = cgn_reverse_dir(dir);

	/* Re-write address */
	cgn_rwrip(l3_ptr, (dir == CGN_DIR_OUT), taddr);

	/*
	 * Re-write l4 port, ICMP ID or eGRE/GREv1
	 */
	if (likely(cpk->cpk_l4ports))
		/* TCP, UDP etc */
		cgn_rwrport(l4_ptr, (dir == CGN_DIR_OUT), tport);

	else if ((cpk->cpk_info & CPK_ICMP_ECHO) != 0)
		/* ICMP */
		cgn_rwricmpid(l4_ptr, tport);

	else if ((cpk->cpk_info & CPK_GRE) != 0) {
		/*
		 * GRE (PPTP)
		 * Only translate call ID in inbound pkts
		 */
		if (dir == CGN_DIR_IN) {
			tport = cgn_alg_pptp_orig_call_id(cse, cpk);
			assert(tport != 0);

			cgn_write_pptp_call_id(l4_ptr, tport);
		}
	}

	/* Rewrite IP checksum and (possibly) the transport checksums */
	uint16_t l3_chk_delta, l4_chk_delta;

	l3_chk_delta = cgn_session_get_l3_delta(cse, forw);
	l4_chk_delta = cgn_session_get_l4_delta(cse, forw);

	cgn_rwrcksums(cpk, l3_ptr, l3_chk_delta, l4_chk_delta);

	/* Update cache with translated addr and port */
	if (dir == CGN_DIR_OUT) {
		cpk->cpk_saddr = taddr;
		cpk->cpk_sid = tport;
	} else {
		cpk->cpk_daddr = taddr;
		cpk->cpk_did = tport;
	}
}

/*
 * cgn_untranslate_at
 */
static void
cgn_untranslate_at(struct cgn_packet *cpk, struct cgn_session *cse,
		   enum cgn_dir dir, void *n_ptr)
{
	cgn_translate_at(cpk, cse, dir, n_ptr, false, true);
}

/*
 * cgn_translate_l3_at
 *
 * Translate the outer IP header of an ICMP error message.
 */
static void
cgn_translate_l3_at(struct cgn_packet *cpk, enum cgn_dir dir, void *n_ptr,
		    uint32_t new_addr)
{
	uint32_t old_addr;
	uint16_t l3_delta;

	old_addr = (dir == CGN_DIR_OUT) ? cpk->cpk_saddr : cpk->cpk_daddr;
	l3_delta = ip_fixup32_cksum(0, old_addr, new_addr);

	/* Calculate and write l3 and l4 checksums */
	cgn_rwrcksums(cpk, (char *)n_ptr, ~l3_delta, 0);

	/* Write new address */
	cgn_rwrip(n_ptr, (dir == CGN_DIR_OUT), new_addr);
}

/*
 * Try to return a copied or cloned packet which has had its CGNAT translation
 * undone.
 *
 * This is called *after* a packt has been translated, but before it is turned
 * around and sent back to sender.
 */
struct rte_mbuf *cgn_copy_or_clone_and_undo(struct rte_mbuf *mbuf,
					    const struct ifnet *in_ifp,
					    const struct ifnet *out_ifp,
					    bool copy)
{
	bool did_cgnat_out = pktmbuf_mdata_exists(mbuf, PKT_MDATA_CGNAT_OUT);
	bool did_cgnat_in = pktmbuf_mdata_exists(mbuf, PKT_MDATA_CGNAT_IN);
	struct cgn_session *cse;
	int error = 0;

	/* Can not handle this yet */
	if (did_cgnat_out && did_cgnat_in)
		return NULL;

	/* Sanity */
	if (!did_cgnat_out && !did_cgnat_in)
		return NULL;

	if (did_cgnat_out && !out_ifp)
		return NULL;

	if (did_cgnat_in && !in_ifp)
		return NULL;

	cse = cgn_session_find_cached(mbuf);
	if (!cse)
		return NULL;

	enum cgn_dir dir = did_cgnat_out ? CGN_DIR_OUT : CGN_DIR_IN;

	/* Validate the session */
	struct ifnet *cse_ifp =
		(struct ifnet *)(did_cgnat_out ? out_ifp : in_ifp);

	if (cgn_session_ifindex(cse) != cse_ifp->if_index)
		return NULL;

	/* Make a clone or copy, and set up to untranslate */
	struct rte_mbuf *unnat;

	if (copy)
		unnat = pktmbuf_copy(mbuf, mbuf->pool);
	else
		unnat = pktmbuf_clone(mbuf, mbuf->pool);

	if (!unnat)
		return NULL;

	struct cgn_packet cpk;

	/* Inspect the packet. */
	error = cgn_cache_all(unnat, dp_pktmbuf_l2_len(unnat), cse_ifp, dir,
			      &cpk, false);
	if (error) {
		dp_pktmbuf_notify_and_free(unnat);
		return NULL;
	}

	void *n_ptr = dp_pktmbuf_mtol3(unnat, void *);

	cgn_untranslate_at(&cpk, cse, dir, n_ptr);

	return unnat;
}

/*
 * ICMP error message.  Look for a cgnat'd embedded packet, and translate if
 * found.
 *
 * If an error is encountered then we just return a single error number,
 * '-CGN_BUF_ICMP' regardless of the actual error.
 */
static int
ipv4_cgnat_icmp_err(struct cgn_packet *ocpk, struct ifnet *ifp,
		    struct rte_mbuf **mbufp, enum cgn_dir dir)
{
	struct rte_mbuf *mbuf = *mbufp;
	struct cgn_session *cse;
	struct cgn_packet ecpk;
	uint32_t offs;
	void *n_ptr;
	int error = 0;

	/* Find the start of the packet embedded in the ICMP error. */
	offs = dp_pktmbuf_l2_len(mbuf) + dp_pktmbuf_l3_len(mbuf) + ICMP_MINLEN;

	/* Inspect the embedded packet. */
	error = cgn_cache_all(mbuf, offs, ifp, dir, &ecpk, true);
	if (error)
		/* Not suitable for translation */
		return -CGN_BUF_ICMP;

	/* Lookup session table for embedded packet */
	cse = cgn_session_lookup_icmp_err(&ecpk, dir);
	if (!cse)
		return -CGN_BUF_ICMP;

	/*
	 * Ensure both the outer and inner headers are both in the first mbuf
	 * segment.
	 */
	error = pktmbuf_prepare_for_header_change(mbufp, offs +
						  ecpk.cpk_l3_len +
						  ecpk.cpk_l4_len);
	if (error)
		return -CGN_BUF_ICMP;

	/* mbuf might have changed above, so dereference again */
	mbuf = *mbufp;

	/* Find the start of the packet embedded in the ICMP error. */
	n_ptr = rte_pktmbuf_mtod(mbuf, char *) + offs;

	/*
	 * For payloads which use a pseudo header,  the final ICMP header
	 * checksum will be incorrect in that the the pseudo header has not
	 * been taken in to account as it is not present in the packet.
	 *
	 * So calculate the first half of its checksum delta - the inverse of
	 * the pre-translated source and destination address.
	 *
	 * Note that if the payload is UDP with checksum disabled, we have to
	 * use port deltas, not address deltas.
	 */
	const uint32_t embed_pre_s_a = ecpk.cpk_saddr;
	const uint32_t embed_pre_d_a = ecpk.cpk_daddr;
	const uint16_t embed_pre_s_p = ecpk.cpk_sid;
	const uint16_t embed_pre_d_p = ecpk.cpk_did;
	uint16_t icmp_cksum_delta = 0;
	bool fix_icmp_chksum32 = true;
	bool fix_icmp_chksum16 = false;

	switch (ecpk.cpk_ipproto) {
	default:
		fix_icmp_chksum32 = false;
		break;
	case IPPROTO_UDP:
		if (!ecpk.cpk_cksum) {
			fix_icmp_chksum32 = false;
			fix_icmp_chksum16 = true;
			icmp_cksum_delta =
				ip_partial_chksum_adjust(0,
					embed_pre_s_p, ~embed_pre_d_p);
			break;
		}
		/* FALLTHRU */
	case IPPROTO_TCP:
		/* FALLTHRU */
	case IPPROTO_UDPLITE:
		/* FALLTHRU */
	case IPPROTO_DCCP:
		icmp_cksum_delta =
			ip_fixup32_cksum(0, embed_pre_s_a, ~embed_pre_d_a);
		break;
	}

	/* Translate the embedded packet */
	cgn_translate_at(&ecpk, cse, dir, n_ptr, true, false);

	/*
	 * With the embedded packet having now been translated,  we adjust the
	 * outer packet accordingly.
	 */
	n_ptr = dp_pktmbuf_mtol3(mbuf, void *);
	cgn_translate_l3_at(ocpk, dir, n_ptr, (dir == CGN_DIR_OUT) ?
			    ecpk.cpk_daddr : ecpk.cpk_saddr);

	/*
	 * Cannot use deltas for the ICMP checksum for truncated
	 * ICMP error packets, so calculate it over all the data.
	 */
	if ((ecpk.cpk_info & CPK_ICMP_EMBD_SHORT) != 0) {
		struct icmp *icmp;

		icmp = dp_pktmbuf_mtol4(mbuf, struct icmp *);
		icmp->icmp_cksum = 0;
		icmp->icmp_cksum = dp_in4_cksum_mbuf(mbuf, NULL, icmp);
		return 0;
	}

	/*
	 * If needed, finish the calculation of the ICMP checksum delta
	 */
	if (fix_icmp_chksum32 || fix_icmp_chksum16) {
		struct icmp *ic;

		if (fix_icmp_chksum16)
			icmp_cksum_delta =
				ip_partial_chksum_adjust(icmp_cksum_delta,
							 ~ecpk.cpk_sid,
							 ecpk.cpk_did);
		else
			icmp_cksum_delta =
				ip_fixup32_cksum(icmp_cksum_delta,
						 ~ecpk.cpk_saddr,
						 ecpk.cpk_daddr);

		ic = (struct icmp *)((char *)n_ptr + dp_pktmbuf_l3_len(mbuf));

		ic->icmp_cksum = ip_fixup16_cksum(ic->icmp_cksum, 0,
						  icmp_cksum_delta);
	}

	return 0;
}

/*
 * ipv4_cgnat_common
 */
static int ipv4_cgnat_common(struct pl_packet *pkt, struct cgn_packet *cpk,
			     struct ifnet *ifp, struct rte_mbuf **mbufp, enum cgn_dir dir)
{
	struct rte_mbuf *mbuf = NULL;
	struct cgn_session *cse;
	void *n_ptr = NULL;
	bool new_inactive_session = false;
	int error = CGN_RC_OK;

	/* ICMP error message? */
	if (unlikely((cpk->cpk_info & CPK_ICMP_ERR) != 0)) {
		/* look for embedded packet to translate */
		error = ipv4_cgnat_icmp_err(cpk, ifp, mbufp, dir);
		return error;
	}

	/* Look for existing session */
	cse = cgn_session_inspect(cpk, dir, &error);

	/*
	 * The most likely reason the inspect might fail is if
	 * max-dest-per-session is reached.
	 */
	if (unlikely(error < 0))
		return error;

	if (unlikely(!cse)) {
		struct cgn_map cmi;

		memset(&cmi, 0, sizeof(cmi));

		/*
		 * Look for an ALG pinhole.  If the pinhole contains a mapping
		 * then that will be transferred to cmi.  The only error
		 * condition here is if we detect that inbound and outbound
		 * paired pinholes have been matched simultaneously.
		 */
		if (unlikely(cgn_alg_is_enabled())) {
			error = cgn_alg_pinhole_lookup(cpk, &cmi, dir);

			/* Lost race to match pinhole? */
			if (unlikely(error < 0))
				return error;
		}

		/*
		 * Only create sessions for outbound pkts, or inbound pkts
		 * that match an ALG pinhole.
		 */
		if (!cpk->cpk_keepalive)
			return -CGN_SESS_ENOENT;

		/*
		 * If the PPTP ALG is enabled then we will parse GRE pkts.  Do
		 * not allow GRE pkts to create a session unless they have
		 * matched an ALG pinhole.
		 */
		if (unlikely((cpk->cpk_info & CPK_GRE) &&
			     cpk->cpk_alg_id != CGN_ALG_PPTP))
			return -CGN_SESS_ENOENT;

		/*
		 * Get policy and mapping, and create a session.
		 *
		 * For ALGs the mapping will have already been added to cmi
		 * via the above call to cgn_alg_pinhole_lookup.
		 *
		 * For normal CGNAT, the mapping will be created during the
		 * call to cgnat_try_initial.
		 *
		 * In either case, cgnat_try_initial always consumes the
		 * mapping.  Either it is attached to the new session, or it
		 * is released.
		 */
		cse = cgnat_try_initial(&cmi, ifp, cpk, *mbufp, dir, &error);
		if (!cse)
			return error;

		/*
		 * If we fail after this point, and before the session is
		 * activated, then the new session needs to be destroyed.  We
		 * need this because of the jump backwards for hairpinned
		 * pkts.
		 */
		new_inactive_session = true;
	}

	/*
	 * Copy the l3 and l4 headers into a new segment if they are not all
	 * in the first segment, or if the mbuf is shared.
	 *
	 * For ALG parent/control we may need to ensure that *all* of the
	 * packet is in the first segment, so we leave min_len at 0.
	 */
	int min_len = 0;

	if (likely(!cgn_session_get_alg_inspect(cse)))
		min_len = dp_pktmbuf_l2_len(*mbufp) + cpk->cpk_l3_len +
			cpk->cpk_l4_len;

	error = pktmbuf_prepare_for_header_change(mbufp, min_len);
	if (unlikely(error)) {
		if (new_inactive_session)
			cgn_session_destroy(cse, false);
		return -CGN_BUF_ENOMEM;
	}

	/* We can jump back here for hairpinned packets */
translate:

	/* mbuf might have changed above, so dereference here */
	mbuf = *mbufp;
	n_ptr = dp_pktmbuf_mtol3(mbuf, void *);

	/* Translate */
	cgn_translate_at(cpk, cse, dir, n_ptr, false, false);

	/* Mark as CGNAT for the rest of the packet path */
	uint32_t pkt_flags;

	pkt_flags = (dir == CGN_DIR_IN) ?
		PKT_MDATA_CGNAT_IN : PKT_MDATA_CGNAT_OUT;

	pktmbuf_mdata_set(mbuf, pkt_flags);

	/*
	 * If pkt was cached on input to firewall etc. then the CGNAT
	 * translation will have invalidated that cache.  Mark as empty so any
	 * output firewall will re-cache it.
	 */
	pkt->npf_flags |= NPF_FLAG_CACHE_EMPTY;

	if (new_inactive_session) {
		/* Activate new session */
		error = cgn_session_activate(cse, cpk, dir);
		if (unlikely(error)) {
			/*
			 * Session activate can fail for three reasons:
			 * 1. Max cgnat sessions has been reached,
			 * 2. This thread lost the race to create a nested sess
			 * 3. No memory for nested session
			 */
			cgn_session_destroy(cse, false);
			return error;
		}

		/*
		 * Session is now activated and in hash tables, so clear
		 * new_inactive_session boolean.  If an error occurs after
		 * this point then the session will be cleaned-up by the
		 * garbage collector instead of being destroyed here.
		 */
		new_inactive_session = false;
	}

	/*
	 * Hairpinning.  Lookup destination addr and port.  If we get a match
	 * then that means one inside host is sending to the external addr of
	 * another inside host.  In these cases we want to map dest addr and
	 * port from the outside addr to the inside addr.
	 *
	 * The source address and port will already have been mapped to an
	 * external address and port.  These are left as-is.  This results in
	 * two inside hosts communicating with each other via their external
	 * mappings.
	 */
	if (unlikely(cgn_hairpinning_gbl && dir == CGN_DIR_OUT)) {
		struct cgn_session *hp_cse;

		/* Change pkt cache hash key to the dest addr and port */
		cpk->cpk_key.k_addr = cpk->cpk_daddr;
		cpk->cpk_key.k_port = cpk->cpk_did;

		hp_cse = cgn_session_lookup(&cpk->cpk_key, CGN_DIR_IN);
		if (hp_cse != NULL) {
			cse = hp_cse;
			error = cgn_cache_all(mbuf, dp_pktmbuf_l2_len(mbuf),
					      ifp, dir, cpk, false);
			if (error)
				return error;

			cgn_rc_inc(CGN_DIR_OUT, CGN_HAIRPINNED);
			cpk->cpk_pkt_hpinned = true;
			dir = CGN_DIR_IN;
			goto translate;
		}
	}

	/*
	 * Is this an ALG parent/control flow?
	 */
	if (unlikely(cgn_session_is_alg_parent(cse))) {
		error = cgn_alg_inspect(cse, cpk, mbuf, dir);
		if (error)
			return error;
	}

	/* Attach the session to the packet */
	struct pktmbuf_mdata *mdata = pktmbuf_mdata(mbuf);
	assert(cse);
	mdata->md_cgn_session = cse;
	pktmbuf_mdata_set(mbuf, PKT_MDATA_CGNAT_SESSION);

	return CGN_RC_OK;
}

/*
 * Unit-test wrapper around cgnat
 *
 * Only used by UTs.
 */
bool ipv4_cgnat_test(struct rte_mbuf **mbufp, struct ifnet *ifp,
		     enum cgn_dir dir, int *error)
{
	struct rte_mbuf *mbuf = *mbufp;
	struct pl_packet pkt;
	struct cgn_packet cpk;
	bool rv = true;

	/* Extract interesting fields from packet */
	*error = cgn_cache_all(mbuf, dp_pktmbuf_l2_len(mbuf), ifp, dir,
			      &cpk, false);

	if (likely(*error == 0)) {
		*error = ipv4_cgnat_common(&pkt, &cpk, ifp, &mbuf, dir);

		if (unlikely(mbuf != *mbufp))
			*mbufp = mbuf;
	}

	if (*error < 0) {
		rv = false;

		/*
		 * Allow packets that matched a firewall or nat session to
		 * bypass CGNAT drops
		 */
		if (pktmbuf_mdata_exists(mbuf, PKT_MDATA_SESSION)) {
			*error = 0;
			rv = true;
		}
	}

	if (unlikely(*error))
		cgn_rc_inc(dir, *error);

	return rv;
}

/*
 * Is the given address a CGNAT pool address?
 */
static bool cgn_is_pool_address(struct ifnet *ifp, uint32_t addr)
{
	struct cds_list_head *policy_list;
	struct cgn_policy *cp;

	/* Get cgnat policy list */
	policy_list = cgn_if_get_policy_list(ifp);
	if (!policy_list)
		return false;

	/* For each cgnat policy ... */
	cds_list_for_each_entry_rcu(cp, policy_list, cp_list_node) {

		/* Is addr in one of this pools address ranges? */
		if (nat_pool_is_pool_addr(cp->cp_pool, addr))
			return true;
	}
	return false;
}

/*
 * cgnat in
 */
ALWAYS_INLINE unsigned int
ipv4_cgnat_in_process(struct pl_packet *pkt, void *context __unused)
{
	struct ifnet *ifp = pkt->in_ifp;
	struct rte_mbuf *mbuf = pkt->mbuf;
	struct cgn_packet cpk;
	int error = 0;
	uint rc = IPV4_CGNAT_IN_ACCEPT;

	/* Extract interesting fields from packet */
	error = cgn_cache_all(mbuf, dp_pktmbuf_l2_len(mbuf), ifp, CGN_DIR_IN,
			      &cpk, false);

	if (likely(error == 0)) {
		error = ipv4_cgnat_common(pkt, &cpk, ifp, &mbuf, CGN_DIR_IN);

		if (unlikely(mbuf != pkt->mbuf)) {
			pkt->mbuf = mbuf;
			pkt->l3_hdr = dp_pktmbuf_mtol3(mbuf, void *);
		}
	}

	/*
	 * Drop pkt on error, subject to exceptions below
	 */
	if (unlikely(error < 0)) {
		rc = IPV4_CGNAT_IN_DROP;

		/*
		 * Allow packets that matched a firewall or nat session to
		 * bypass CGNAT drops
		 */
		if (pktmbuf_mdata_exists(mbuf, PKT_MDATA_SESSION)) {
			rc = IPV4_CGNAT_IN_ACCEPT;
			error = 0;
			goto end;

		}

		/*
		 * Did pkt match a CGNAT session or ALG pinhole?  If so, then
		 * we apply the 'drop' decision.
		 */
		if (cpk.cpk_pkt_cgnat)
			goto end;

		/*
		 * Allow packets through if the destination address is *not*
		 * in any NAT pool used by CGNAT policies on this interface.
		 */
		if (!cgn_is_pool_address(ifp, cpk.cpk_daddr)) {

			rc = IPV4_CGNAT_IN_ACCEPT;
			error = -CGN_POOL_ENOENT;
			goto end;
		}

		/*
		 * Pkt did *not* match a CGNAT session or ALG pinhole, but
		 * *is* addressed to a CGNAT public address.
		 */

		/*
		 * If pkt is an ICMP echo req sent to a CGNAT pool address
		 * then send an echo reply to the sender, and drop the
		 * original pkt.
		 */
		if ((cpk.cpk_info & CPK_ICMP_ECHO_REQ) != 0) {
			bool sent;
			sent = icmp_echo_reply_out(pkt->in_ifp, pkt->mbuf,
						   true);
			/*
			 * Set 'error' if reply was sent ok so that
			 * these are accounted for.  Orig pkt is
			 * dropped regardless.
			 */
			if (sent)
				error = -CGN_ICMP_ECHOREQ;
			goto end;
		}
	}

end:
	if (unlikely(error))
		cgn_rc_inc(CGN_DIR_IN, error);

	return rc;
}

/*
 * cgnat out
 */
ALWAYS_INLINE unsigned int ipv4_cgnat_out_process(struct pl_packet *pkt,
						  void *context __unused)
{
	struct ifnet *ifp = pkt->out_ifp;
	struct rte_mbuf *mbuf = pkt->mbuf;
	struct cgn_packet cpk;
	int error = 0;
	uint rc = IPV4_CGNAT_OUT_ACCEPT;

	/* Extract interesting fields from packet */
	error = cgn_cache_all(mbuf, dp_pktmbuf_l2_len(mbuf), ifp, CGN_DIR_OUT,
			      &cpk, false);

	if (likely(error == 0)) {
		/*
		 * Note that error code might be non-zero even when result is
		 * ACCEPT.  For example, if the packet does not match a CGNAT
		 * policy.
		 */
		error = ipv4_cgnat_common(pkt, &cpk, ifp, &mbuf, CGN_DIR_OUT);

		if (unlikely(mbuf != pkt->mbuf)) {
			pkt->mbuf = mbuf;
			pkt->l3_hdr = dp_pktmbuf_mtol3(mbuf, void *);
		}
	}

	/*
	 * Hairpinned packet?
	 */
	if (unlikely(error == 0 && cpk.cpk_pkt_hpinned)) {
		ip_lookup_and_forward(pkt->mbuf, pkt->in_ifp, true,
				      NPF_FLAG_CACHE_EMPTY);
		rc = IPV4_CGNAT_OUT_CONSUME;
		goto end;
	}

	/*
	 * Drop pkt on error, subject to exceptions below
	 */
	if (unlikely(error < 0)) {
		rc = IPV4_CGNAT_OUT_DROP;

		/*
		 * If a pkt failed to match a CGNAT policy, session or ALG
		 * pinhole then it is not a CGNAT pkt.  This also includes
		 * SNAT ALG pkts (CGN_PCY_BYPASS).
		 */
		if (!cpk.cpk_pkt_cgnat) {
			rc = IPV4_CGNAT_OUT_ACCEPT;
			goto end;
		}

		/*
		 * Send ICMP Unreachable?
		 */
		if (error == -CGN_BUF_PROTO || error == -CGN_BUF_ICMP) {
			/* Hard error.  Could not translate. */
			icmp_error(pkt->in_ifp, pkt->mbuf, ICMP_DEST_UNREACH,
				   ICMP_PROT_UNREACH, 0);
			goto end;
		}

		/*
		 * Initial CGNAT ALG release will *not* send ICMP Unreachable
		 * messages.  Counters will be used to monitor failures, and
		 * ICMP Unreachables may be enabled at a later time.
		 */
		if (cpk.cpk_pkt_cgnat && cpk.cpk_alg_id == CGN_ALG_NONE) {
			/* Soft error.  Should have been translated, but failed. */
			icmp_error(pkt->in_ifp, pkt->mbuf, ICMP_DEST_UNREACH,
				   ICMP_HOST_UNREACH, 0);
			goto end;
		}
	}

end:
	if (unlikely(error))
		cgn_rc_inc(CGN_DIR_OUT, error);

	return rc;
}

/* Register Input Node */
PL_REGISTER_NODE(ipv4_cgnat_in_node) = {
	.name = "vyatta:ipv4-cgnat-in",
	.type = PL_PROC,
	.handler = ipv4_cgnat_in_process,
	.num_next = IPV4_CGNAT_IN_NUM,
	.next = {
		[IPV4_CGNAT_IN_ACCEPT] = "term-noop",
		[IPV4_CGNAT_IN_DROP]   = "term-drop",
		[IPV4_CGNAT_IN_CONSUME] = "term-finish",
	}
};

/* Register Input Features */
PL_REGISTER_FEATURE(ipv4_cgnat_in_feat) = {
	.name = "vyatta:ipv4-cgnat-in",
	.node_name = "ipv4-cgnat-in",
	.feature_point = "ipv4-validate",
	.id = PL_L3_V4_IN_FUSED_FEAT_CGNAT,
	.visit_after = "vyatta:ipv4-fw-in",
};

/* Register Output Node */
PL_REGISTER_NODE(ipv4_cgnat_out_node) = {
	.name = "vyatta:ipv4-cgnat-out",
	.type = PL_PROC,
	.handler = ipv4_cgnat_out_process,
	.num_next = IPV4_CGNAT_OUT_NUM,
	.next = {
		[IPV4_CGNAT_OUT_ACCEPT] = "term-noop",
		[IPV4_CGNAT_OUT_DROP]   = "term-drop",
		[IPV4_CGNAT_OUT_CONSUME] = "term-finish",
	}
};

/* Register Output Features */
PL_REGISTER_FEATURE(ipv4_cgnat_out_feat) = {
	.name = "vyatta:ipv4-cgnat-out",
	.node_name = "ipv4-cgnat-out",
	.feature_point = "ipv4-out",
	.id = PL_L3_V4_OUT_FUSED_FEAT_CGNAT,
	.visit_after = "vyatta:ipv4-defrag-out",
};
