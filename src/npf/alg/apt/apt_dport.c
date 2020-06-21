/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * apt_dport.c - APT destination port table
 */

#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <rte_jhash.h>

#include "compiler.h"
#include "util.h"
#include "soft_ticks.h"
#include "vrf.h"

#include "npf/alg/apt/apt_public.h"
#include "npf/alg/apt/apt.h"
#include "npf/alg/apt/apt_dport.h"

/*
 * The destination port table.
 *
 * Typical default destination ports used to identify ALG flows are:
 *
 * Port			TCP	UDP
 * ------------		-----	-----
 *  21	FTP		Yes	-
 *  69	TFTP		-	Yes
 * 111	ONC RPC		Yes	Yes
 * 5060	SIP		Yes	Yes
 */

#define APT_DPORT_NAMESZ 16

/*
 * Destination port entry.  Key is: protocol, dest port, and feature (npf or
 * cgnat).
 *
 * de_dport is in network-byte order.
 */
struct apt_dport {
	struct cds_lfht_node	de_node;
	struct apt_dport_key	de_key;
	void			*de_ctx;	/* Feature context */
	struct apt_instance	*de_ai;		/* apt instance */
	rte_atomic32_t		de_count;
	rte_atomic16_t		de_refcnt;
	uint8_t			de_removing;
	char			de_name[APT_DPORT_NAMESZ];
	struct rcu_head		de_rcu;
};

#define de_dport	de_key.k_dport
#define de_proto	de_key.k_proto
#define de_feat		de_key.k_feat
#define de_expired	de_key.k_expired

/*
 * Min and max sizes of the destination port table
 */
#define APT_DPORT_TBL_INIT	16
#define APT_DPORT_TBL_MIN	16
#define APT_DPORT_TBL_MAX	65536

/*
 * Get count of entries for the given feature
 */
uint32_t apt_dport_tbl_count(struct apt_instance *ai, enum alg_feat feat)
{
	uint32_t count = 0;
	int f;

	if (!ai)
		return 0;

	if (feat < ALG_FEAT_MAX)
		return rte_atomic32_read(&ai->ai_dport.dt_count[feat]);

	for (f = ALG_FEAT_FIRST; f <= ALG_FEAT_LAST; f++)
		count += rte_atomic32_read(&ai->ai_dport.dt_count[f]);

	return count;
}

/*
 * Create a dest port table
 */
int apt_dport_tbl_create(struct apt_dport_tbl *dt)
{
	struct cds_lfht *ht, *old;
	uint feat;

	for (feat = ALG_FEAT_FIRST; feat <= ALG_FEAT_LAST; feat++)
		rte_atomic32_set(&dt->dt_count[feat], 0);

	ht = cds_lfht_new(APT_DPORT_TBL_INIT,
			  APT_DPORT_TBL_MIN, APT_DPORT_TBL_MAX,
			  CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING,
			  NULL);
	if (!ht)
		return -ENOMEM;

	old = rcu_cmpxchg_pointer(&dt->dt_ht, NULL, ht);
	if (old) {
		/* Lost race to assign dt_ht. Thats ok. */
		dp_ht_destroy_deferred(ht);
		return 0;
	}
	return 0;
}

/*
 * Destroy a dest port table
 */
void apt_dport_tbl_destroy(struct apt_dport_tbl *dt)
{
	struct cds_lfht *ht;

	/* Table should already be empty */
	assert(rte_atomic32_read(&dt->dt_count[ALG_FEAT_NPF]) == 0);
	assert(rte_atomic32_read(&dt->dt_count[ALG_FEAT_CGNAT]) == 0);

	ht = rcu_xchg_pointer(&dt->dt_ht, NULL);
	if (ht)
		dp_ht_destroy_deferred(ht);
}

/*
 * Create a dest port table entry
 */
static struct apt_dport *apt_dport_create(uint16_t dport, const char *name)
{
	struct apt_dport *de;

	de = zmalloc_aligned(sizeof(*de));
	if (!de)
		return NULL;

	de->de_dport = dport;

	if (name) {
		strncpy(de->de_name, name, sizeof(de->de_name));
		de->de_name[APT_DPORT_NAMESZ-1] = '\0';
	}

	return de;
}

/*
 * Destroy a dest port table entry
 */
static void apt_dport_destroy(struct apt_dport *de)
{
	if (de)
		free(de);
}

static void apt_dport_destroy_rcu(struct rcu_head *head)
{
	struct apt_dport *de;

	de = caa_container_of(head, struct apt_dport, de_rcu);
	apt_dport_destroy(de);
}

/* Take reference on dport entry */
static struct apt_dport *apt_dport_get(struct apt_dport *de)
{
	if (de)
		rte_atomic16_inc(&de->de_refcnt);
	return de;
}

/* Release reference on dport entry */
static void apt_dport_put(struct apt_dport *de)
{
	if (de && rte_atomic16_dec_and_test(&de->de_refcnt))
		call_rcu(&de->de_rcu, apt_dport_destroy_rcu);
}

/*
 * Expire a dest port entry.  Expired entries are not findable in the table.
 */
static void apt_dport_expire(struct apt_dport *de)
{
	if (!de || de->de_expired)
		return;

	de->de_expired = true;
}

/* Set ALG private data handle in dport entry */
void apt_dport_set_feat_ctx(struct apt_dport *de, void *ctx)
{
	if (de)
		de->de_ctx = ctx;
}

/* Hash function */
static ulong apt_dport_hash(struct apt_dport_key *key)
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
static int apt_dport_match(struct cds_lfht_node *node, const void *k)
{
	const struct apt_dport_key *key = k;
	struct apt_dport *de;
	int rc;

	de = caa_container_of(node, struct apt_dport, de_node);

	assert((sizeof(struct apt_dport_key) & 0x3) == 0);
	assert(de->de_key.k_pad1 == 0);
	assert(de->de_key.k_pad2 == 0);
	assert(key->k_pad1 == 0);
	assert(key->k_pad2 == 0);

	rc = !memcmp(&de->de_key, key, sizeof(struct apt_dport_key));
	return rc;
}

/*
 * Add a dest port table entry.  This is done from the main thread via
 * configuration.
 */
int apt_dport_add(struct apt_instance *ai, enum alg_feat feat, void *ctx,
		  uint8_t proto, uint16_t dport, const char *name)
{
	struct cds_lfht_node *node;
	struct apt_dport_tbl *dt;
	struct apt_dport *de;

	if (!ai || !ai->ai_enabled || feat > ALG_FEAT_LAST)
		return -EINVAL;

	dt = &ai->ai_dport;
	if (!dt->dt_ht)
		return -EINVAL;

	if (apt_dport_tbl_count(ai, ALG_FEAT_ALL) >= APT_DPORT_TBL_MAX)
		return -ENOSPC;

	de = apt_dport_create(dport, name);
	if (!de)
		return -ENOMEM;

	/* Store back pointer to instance */
	de->de_ai = apt_instance_get(ai);

	/* Store feature context */
	de->de_ctx = ctx;

	/* key is dport, proto, and feat */
	de->de_dport = dport;
	de->de_proto = proto;
	de->de_feat = feat;
	de->de_expired = false;

	node = cds_lfht_add_unique(dt->dt_ht,
				   apt_dport_hash(&de->de_key),
				   apt_dport_match,
				   &de->de_key,
				   &de->de_node);

	/*
	 * Either we lost the race to add an entry (should never happen), or
	 * the caller did not check if the entry already existed.
	 */
	if (node != &de->de_node) {
		apt_instance_put(ai);
		free(de);
		return -EEXIST;
	}

	/* Take reference on entry while it is in table */
	apt_dport_get(de);

	rte_atomic32_inc(&dt->dt_count[feat]);
	return 0;
}

/*
 * Delete a dest port
 */
static int _apt_dport_del(struct apt_dport_tbl *dt, struct apt_dport *de)
{
	int rc;

	rc = cds_lfht_del(dt->dt_ht, &de->de_node);
	if (rc < 0)
		return rc;

	/* Notify alg of delete */
	alg_apt_dport_delete(de, de->de_ctx);

	rte_atomic32_dec(&dt->dt_count[de->de_feat]);

	/* Release reference on apt instance */
	apt_instance_put(de->de_ai);
	de->de_ai = NULL;

	/* Release reference on entry */
	apt_dport_put(de);

	return 0;
}

static struct apt_dport *
apt_dport_lookup_key(struct apt_dport_tbl *dt, struct apt_dport_key *key)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	cds_lfht_lookup(dt->dt_ht, apt_dport_hash(key),
			apt_dport_match, key, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (!node)
		return NULL;

	return caa_container_of(node, struct apt_dport, de_node);
}

/*
 * Lookup destination port.  dport is in network-byte order.
 */
static struct apt_dport *
_apt_dport_lookup(struct apt_instance *ai, enum alg_feat feat, uint8_t proto,
		  uint16_t dport, bool inc_count)
{
	struct apt_dport_tbl *dt = ai ? &ai->ai_dport : NULL;
	struct apt_dport *de;
	struct apt_dport_key key;

	if (!dt || !dt->dt_ht)
		return NULL;

	key.k_dport = dport;
	key.k_proto = proto;
	key.k_feat = feat;
	key.k_expired = false;
	key.k_pad1 = 0;
	key.k_pad2 = 0;

	de = apt_dport_lookup_key(dt, &key);
	if (!de)
		return NULL;

	if (inc_count)
		rte_atomic32_inc(&de->de_count);

	return de;
}

/*
 * Lookup a dport entry
 */
void *apt_dport_lookup(struct apt_instance *ai, enum alg_feat feat,
		       uint8_t proto, uint16_t dport, bool inc_count)
{
	struct apt_dport *de;

	de = _apt_dport_lookup(ai, feat, proto, dport, inc_count);

	return de ? de->de_ctx : NULL;
}

/*
 * Lookup and expire a dport entry
 */
int apt_dport_lookup_and_expire(struct apt_instance *ai, enum alg_feat feat,
				uint8_t proto, uint16_t dport)
{
	struct apt_dport *de;
	int rc = -ENOENT;

	de = _apt_dport_lookup(ai, feat, proto, dport, false);
	if (de) {
		apt_dport_expire(de);
		rc = 0;
	}
	return rc;
}

/*
 * Format a string from a dest port entry
 */
char *apt_dport_str(struct apt_dport *de, char *dst, size_t sz)
{
	uint32_t vrfid = 0;

	if (de->de_ai)
		vrfid = de->de_ai->ai_vrfid;

	snprintf(dst, sz, "[%u] \"%s\" %s %u \"%s\"",
		 vrfid, alg_feat_name(de->de_feat),
		 de->de_proto == IPPROTO_TCP ? "TCP" : "UDP",
		 ntohs(de->de_dport), de->de_name);

	return dst;
}

/*
 * Write json for a dest port table entry
 */
static void apt_dport_jsonw(json_writer_t *json, struct apt_dport *de)
{
	jsonw_start_object(json);
	jsonw_string_field(json, "feature", alg_feat_name(de->de_feat));

	jsonw_uint_field(json, "dport", ntohs(de->de_dport));
	jsonw_uint_field(json, "proto", de->de_proto);
	jsonw_uint_field(json, "count", rte_atomic32_read(&de->de_count));
	jsonw_uint_field(json, "refcnt", rte_atomic16_read(&de->de_refcnt));
	jsonw_bool_field(json, "expired", de->de_expired);

	jsonw_end_object(json);
}

/*
 * Write json for the dest port table of an instance
 */
void apt_dport_tbl_jsonw(json_writer_t *json, struct apt_dport_tbl *dt)
{
	struct cds_lfht_iter iter;
	struct apt_dport *de;

	jsonw_name(json, "dport");
	jsonw_start_array(json);

	if (dt->dt_ht) {
		cds_lfht_for_each_entry(dt->dt_ht, &iter, de, de_node) {
			apt_dport_jsonw(json, de);
		}
	}

	jsonw_end_array(json);
}

/*
 * Write json for select dest port table entries
 */
void
apt_dport_jsonw_matching(json_writer_t *json, struct apt_instance *ai,
			 int feat, apt_match_func_t match_fn, void *match_key)
{
	struct apt_dport_tbl *dt = ai ? &ai->ai_dport : NULL;
	struct cds_lfht_iter iter;
	struct apt_dport *de;

	jsonw_name(json, "dport");
	jsonw_start_array(json);

	if (!dt || !dt->dt_ht)
		goto end;

	cds_lfht_for_each_entry(dt->dt_ht, &iter, de, de_node) {
		if (feat != de->de_feat && feat != ALG_FEAT_ALL)
			continue;

		if (match_fn && !(*match_fn)(de->de_ctx, match_key))
			continue;

		apt_dport_jsonw(json, de);
	}

end:
	jsonw_end_array(json);
}

/*
 * For all entries matching the match key:
 *   1. delete any expired entries, and
 *   2. expire entries if flush_all is true
 *
 * Called when an apt instance is being destroyed, typically as a result of a
 * DP_EVT_VRF_DELETE event.
 */
void apt_dport_tbl_flush(struct apt_dport_tbl *dt, int feat, bool flush_all,
			 apt_match_func_t match_fn, void *match_key)
{
	struct cds_lfht_iter iter;
	struct apt_dport *de;

	if (!dt->dt_ht)
		return;

	/*
	 * Currently all dest port entries are 'keep' entries, so only expire
	 * if flush_all is set.
	 */
	cds_lfht_for_each_entry(dt->dt_ht, &iter, de, de_node) {
		if (feat != de->de_feat && feat != ALG_FEAT_ALL)
			continue;

		if (match_fn && !(*match_fn)(de->de_ctx, match_key))
			continue;

		if (de->de_expired)
			_apt_dport_del(dt, de);

		if (flush_all)
			apt_dport_expire(de);
	}
}

/*
 * dport table garbage collection.  Entries change as follows:
 *   expired -> removing -> deleted
 *
 * Note that there is no timeout for dport table entries.  They are added and
 * expired as a result of alg config.
 */
void apt_dport_tbl_gc(struct apt_dport_tbl *dt)
{
	struct cds_lfht_iter iter;
	struct apt_dport *de;

	if (!dt->dt_ht)
		return;

	cds_lfht_for_each_entry(dt->dt_ht, &iter, de, de_node) {
		if (de->de_expired) {
			if (de->de_removing)
				_apt_dport_del(dt, de);
			else
				de->de_removing = true;
		}
	}
}
