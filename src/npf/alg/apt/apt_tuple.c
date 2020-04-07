/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * apt_tuple.c - APT tuple table
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

#include "npf/alg/apt/apt_public.h"
#include "npf/alg/apt/apt.h"
#include "npf/alg/apt/apt_tuple.h"


/*
 * Tuple table entry.
 *
 * Default timeout is 10 secs.
 *
 * te_expiry_time is a future value of soft_ticks.  Entry is expired once
 * soft_ticks becomes greater than te_expiry_time.
 *
 * te_keep is set true for tuples where the ALG itself controls when to
 * timeout the tuple (only the SIP ALT_CNTL tuple is a 'keep' tuple).
 *
 * te_paired is used to pair two tuples together.  This is used when the
 * expected flow can start in either direction.
 */
struct apt_tuple {
	struct cds_lfht_node	te_node;
	struct apt_key		te_key;
	void			*te_ctx;	/* Feature context */
	uint64_t		te_expiry_time;	/* Millisecs */
	uint64_t		te_timeout;	/* Millisecs */
	struct apt_tuple	*te_paired;
	uint32_t		te_id;		/* Monotonically increasing */
	rte_atomic16_t		te_refcnt;
	uint8_t			te_keep;	/* Do not timeout */
	uint8_t			te_removing;
	struct rcu_head		te_rcu;
};

/* Common keys in both v4 and v6 keys */
#define te_ifindex	te_key.v4_key.k4_ifindex
#define te_expired	te_key.v4_key.k4_expired
#define te_proto	te_key.v4_key.k4_proto
#define te_alen		te_key.v4_key.k4_alen
#define te_feat		te_key.v4_key.k4_feat
#define te_dport	te_key.v4_key.k4_dport
#define te_sport	te_key.v4_key.k4_sport

/*
 * Min and max sizes of the tuple table
 */
#define APT_TUPLE_TBL_INIT	32
#define APT_TUPLE_TBL_MIN	256
#define APT_TUPLE_TBL_MAX	32768

/* Retry count for tuple insertions. */
#define APT_RETRY_COUNT	10

#define APT_TUPLE_TIMEOUT	10
#define APT_TUPLE_TIMEOUT_MS	(APT_TUPLE_TIMEOUT * 1000)

/* Monotonically increasing ID */
static rte_atomic32_t apt_tuple_id_resource;


/*
 * Get count of tuple entries for the given feature
 */
uint32_t apt_tuple_tbl_count(struct apt_instance *ai, enum alg_feat feat)
{
	uint32_t count = 0;
	int f;

	if (!ai)
		return 0;

	if (feat < ALG_FEAT_MAX)
		return rte_atomic32_read(&ai->ai_tuple.tt_count[feat]);

	for (f = ALG_FEAT_FIRST; f <= ALG_FEAT_LAST; f++)
		count += rte_atomic32_read(&ai->ai_tuple.tt_count[f]);

	return count;
}

/*
 * The tuple table contains both 5 and 6-tuple entries:
 *
 * 5-tuple (intf, proto, saddr, daddr, dport).  Aka 'any source port' table.
 * 6-tuple (intf, proto, saddr, daddr, dport, sport). Aka 'all' table.
 */

int apt_tuple_tbl_create(struct apt_tuple_tbl *tt)
{
	/* Check tuple key sizes are multiples of 4 */
	assert((sizeof(struct apt_v4_key) & 0x3) == 0);
	assert((sizeof(struct apt_v6_key) & 0x3) == 0);

	/* Check the common key objects are at same offsets */
	assert(offsetof(struct apt_v4_key, k4_ifindex) ==
	       offsetof(struct apt_v6_key, k6_ifindex));
	assert(offsetof(struct apt_v4_key, k4_expired) ==
	       offsetof(struct apt_v6_key, k6_expired));
	assert(offsetof(struct apt_v4_key, k4_proto) ==
	       offsetof(struct apt_v6_key, k6_proto));
	assert(offsetof(struct apt_v4_key, k4_feat) ==
	       offsetof(struct apt_v6_key, k6_feat));
	assert(offsetof(struct apt_v4_key, k4_dport) ==
	       offsetof(struct apt_v6_key, k6_dport));
	assert(offsetof(struct apt_v4_key, k4_sport) ==
	       offsetof(struct apt_v6_key, k6_sport));
	assert(offsetof(struct apt_v4_key, k4_alen) ==
	       offsetof(struct apt_v6_key, k6_alen));

	struct cds_lfht *ht, *old;
	uint feat;

	for (feat = ALG_FEAT_FIRST; feat <= ALG_FEAT_LAST; feat++) {
		rte_atomic32_set(&tt->tt_count[feat], 0);
		rte_spinlock_init(&tt->tt_lock[feat]);
	}

	ht = cds_lfht_new(APT_TUPLE_TBL_INIT,
			  APT_TUPLE_TBL_MIN, APT_TUPLE_TBL_MAX,
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

void apt_tuple_tbl_destroy(struct apt_tuple_tbl *tt)
{
	struct cds_lfht *ht;

	assert(rte_atomic32_read(&tt->tt_count[ALG_FEAT_NPF]) == 0);
	assert(rte_atomic32_read(&tt->tt_count[ALG_FEAT_CGNAT]) == 0);

	ht = rcu_xchg_pointer(&tt->tt_ht, NULL);
	if (ht)
		dp_ht_destroy_deferred(ht);
}

/*
 * Create a tuple entry
 */
static struct apt_tuple *apt_tuple_create(void)
{
	struct apt_tuple *te;

	te = zmalloc_aligned(sizeof(*te));
	if (!te)
		return NULL;

	rte_atomic16_set(&te->te_refcnt, 0);

	return te;
}

static void apt_tuple_destroy(struct apt_tuple *te)
{
	free(te);
}

static void apt_tuple_destroy_rcu(struct rcu_head *head)
{
	struct apt_tuple *te;

	te = caa_container_of(head, struct apt_tuple, te_rcu);
	apt_tuple_destroy(te);
}

static struct apt_tuple *apt_tuple_get(struct apt_tuple *te)
{
	if (te)
		rte_atomic16_inc(&te->te_refcnt);
	return te;
}

static void apt_tuple_put(struct apt_tuple *te)
{
	if (te && rte_atomic16_dec_and_test(&te->te_refcnt))
		call_rcu(&te->te_rcu, apt_tuple_destroy_rcu);
}

/*
 * Get tuple entry feat context
 */
void *apt_tuple_get_feat_ctx(struct apt_tuple *te)
{
	return te ? te->te_ctx : NULL;
}

void apt_tuple_clear_feat_ctx(struct apt_tuple *te)
{
	if (te)
		te->te_ctx = NULL;
}

/* Hash function */
static ulong apt_tuple_v4_hash(struct apt_v4_key *key)
{
	/*
	 * A special optimized version of jhash that handles 1 or more of
	 * uint32_ts.
	 */
	return rte_jhash_32b((const uint32_t *)key,
			     sizeof(*key) / sizeof(uint32_t), 0);
}

static ulong apt_tuple_v6_hash(struct apt_v6_key *key)
{
	/*
	 * A special optimized version of jhash that handles 1 or more of
	 * uint32_ts.
	 */
	return rte_jhash_32b((const uint32_t *)key,
			     sizeof(*key) / sizeof(uint32_t), 0);
}

/*
 * Hash table match functions.  Returns non-zero for a match.
 */
static int apt_tuple_v4_match(struct cds_lfht_node *node, const void *key)
{
	struct apt_tuple *te;

	te = caa_container_of(node, struct apt_tuple, te_node);

	return !memcmp(&te->te_key.v4_key, key, sizeof(struct apt_v4_key));
}

static int apt_tuple_v6_match(struct cds_lfht_node *node, const void *key)
{
	struct apt_tuple *te;

	te = caa_container_of(node, struct apt_tuple, te_node);

	return !memcmp(&te->te_key.v6_key, key, sizeof(struct apt_v6_key));
}

/*
 * Add v4 or v6 tuple table entry
 *
 * The following MUST be initialized in the key: k4_ifindex, k4_proto,
 * k4_dport, k4_sport, k4_daddr and k4_saddr (or v6 equivalent).
 *
 * The following are assumed to *not* be setup in the key: k4_feat,
 * k4_expired, k4_pad2.
 */
struct apt_tuple *
apt_tuple_add(struct apt_instance *ai, enum alg_feat feat, void *ctx,
	      const struct apt_key *key, uint16_t timeout,
	      bool replace, bool keep, int *error)
{
	struct apt_tuple_tbl *tt = ai ? &ai->ai_tuple : NULL;
	cds_lfht_match_fct match_fn;
	const void *match_key;
	struct apt_tuple *te;
	uint32_t hash;
	uint retry;
	bool is_v4;
	int rc;

	if (!tt || feat > ALG_FEAT_LAST) {
		*error = -EINVAL;
		return NULL;
	}

	if (apt_tuple_tbl_count(ai, ALG_FEAT_ALL) >= APT_TUPLE_TBL_MAX) {
		*error = -ENOSPC;
		return NULL;
	}

	te = apt_tuple_create();
	if (!te) {
		*error = -ENOMEM;
		return NULL;
	}

	/* Store feature context */
	te->te_ctx = ctx;

	te->te_keep = keep;

	/* v4 or v6? */
	assert(key->v4_key.k4_alen == 4 || key->v4_key.k4_alen == 16);
	is_v4 = (key->v4_key.k4_alen == 4);

	/* ifindex, proto, ports and addresses should be set in key */
	if (likely(is_v4)) {
		memcpy(&te->te_key.v4_key, &key->v4_key,
		       sizeof(struct apt_v4_key));

		/* These are not setup by the above memcpy */
		te->te_key.v4_key.k4_pad2 = 0;
		te->te_key.v4_key.k4_feat = feat;
		te->te_key.v4_key.k4_expired = false;

		match_fn = apt_tuple_v4_match;
		match_key = &te->te_key.v4_key;

		hash = apt_tuple_v4_hash(&te->te_key.v4_key);
	} else {
		memcpy(&te->te_key.v6_key, &key->v6_key,
		       sizeof(struct apt_v6_key));

		/* These are not setup by the above memcpy */
		te->te_key.v6_key.k6_pad2 = 0;
		te->te_key.v6_key.k6_feat = feat;
		te->te_key.v6_key.k6_expired = false;

		match_fn = apt_tuple_v6_match;
		match_key = &te->te_key.v6_key;

		hash = apt_tuple_v6_hash(&te->te_key.v6_key);
	}

	/*
	 * If 'replace' is true, then the caller attempting to replace an
	 * existing tuple.  Do this by expiring the existing tuple and
	 * retrying for a limited number of times.
	 */
	rc = -EEXIST;
	retry = APT_RETRY_COUNT;

	while (retry--) {
		struct cds_lfht_node *node;
		struct apt_tuple *old;

		node = cds_lfht_add_unique(tt->tt_ht, hash, match_fn,
					   match_key, &te->te_node);

		if (likely(node == &te->te_node)) {
			/* Success */
			rc = 0;
			break;
		}

		if (!replace)
			break;

		/* Expire existing entry and try again */
		old = caa_container_of(node, struct apt_tuple, te_node);
		apt_tuple_expire(old);
	}

	/* Did we loose the race to insert tuple entry? */
	if (rc < 0) {
		free(te);
		*error = -EEXIST;
		return NULL;
	}

	te->te_id = rte_atomic32_add_return(&apt_tuple_id_resource, 1);

	/* Take reference on tuple entry */
	apt_tuple_get(te);

	/* Set expiry time */
	if (timeout) {
		te->te_timeout = timeout * 1000;
		te->te_expiry_time = soft_ticks + te->te_timeout;
	} else {
		te->te_timeout = 0;
		te->te_expiry_time = soft_ticks + APT_TUPLE_TIMEOUT_MS;
	}

	rte_atomic32_inc(&tt->tt_count[feat]);
	return te;
}

/*
 * Delete tuple table entry
 */
static int apt_tuple_del(struct apt_tuple_tbl *tt, struct apt_tuple *te)
{
	int rc;

	assert(te->te_expired);

	rc = cds_lfht_del(tt->tt_ht, &te->te_node);
	if (rc < 0)
		return rc;

	/* Notify alg that tuple is being deleted */
	alg_apt_tuple_delete(te, te->te_ctx);

	rte_atomic32_dec(&tt->tt_count[te->te_feat]);

	/* Release reference on tuple entry */
	apt_tuple_put(te);

	return 0;
}

/*
 * Lookup a v4 key in the tuple hash table
 */
static struct apt_tuple *
_apt_tuple_v4_lookup(struct apt_instance *ai, enum alg_feat feat,
		     struct apt_v4_key *key)
{
	struct apt_tuple_tbl *tt = ai ? &ai->ai_tuple : NULL;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct apt_tuple *te = NULL;

	if (!tt || !tt->tt_ht)
		return NULL;

	key->k4_feat = feat;
	key->k4_alen = 4;
	key->k4_pad2 = 0;
	key->k4_expired = false;

	cds_lfht_lookup(tt->tt_ht, apt_tuple_v4_hash(key),
			apt_tuple_v4_match, key, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (node)
		te = caa_container_of(node, struct apt_tuple, te_node);

	return te;
}

/*
 * Lookup a v6 key in the tuple hash table
 */
static struct apt_tuple *
_apt_tuple_v6_lookup(struct apt_instance *ai, enum alg_feat feat,
		     struct apt_v6_key *key)
{
	struct apt_tuple_tbl *tt = ai ? &ai->ai_tuple : NULL;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct apt_tuple *te = NULL;

	if (!tt || !tt->tt_ht)
		return NULL;

	key->k6_feat = feat;
	key->k6_alen = 16;
	key->k6_pad2 = 0;
	key->k6_expired = false;

	cds_lfht_lookup(tt->tt_ht, apt_tuple_v6_hash(key),
			apt_tuple_v6_match, key, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (node)
		te = caa_container_of(node, struct apt_tuple, te_node);

	return te;
}

/*
 * Lookup tuple.  If tuple found, expire it if it is a non 'keep' tuple.
 * Check for race with paired tuple, if one exists.
 */
struct apt_tuple *
apt_tuple_lookup_and_expire(struct apt_instance *ai, enum alg_feat feat,
			    struct apt_key *key, bool *drop)
{
	struct apt_tuple *te;
	bool is_v4 = (key->v4_key.k4_alen == 4);

	/*
	 * First try and match an entry with the packets source port.
	 */
	if (likely(is_v4))
		te = _apt_tuple_v4_lookup(ai, feat, &key->v4_key);
	else
		te = _apt_tuple_v6_lookup(ai, feat, &key->v6_key);

	/*
	 * If no match, then we try and match an 'any src port' entry.  To do
	 * this we set the keys src port to 0 as this allows the same
	 * optimised match function to be used.
	 */
	if (!te && key->v4_key.k4_sport) {
		uint16_t tmp = key->v4_key.k4_sport;

		key->v4_key.k4_sport = 0;

		if (likely(is_v4))
			te = _apt_tuple_v4_lookup(ai, feat, &key->v4_key);
		else
			te = _apt_tuple_v6_lookup(ai, feat, &key->v6_key);

		key->v4_key.k4_sport = tmp;
	}

	if (!te)
		return NULL;

	/* A 'keep' tuple is never paired */
	if (te->te_keep)
		return te;

	if (likely(!te->te_paired)) {
		apt_tuple_expire(te);
		return te;
	}

	/*
	 * Paired tuple.  There is one race we are concerned with - possible
	 * receipt of both a forward and reverse packet.
	 */
	rte_spinlock_lock(&ai->ai_tuple.tt_lock[feat]);

	if (te->te_expired) {
		if (drop)
			*drop = true;
	} else {
		/* The first expire will unpair the tuples */
		apt_tuple_expire(te->te_paired);
		apt_tuple_expire(te);
	}

	rte_spinlock_unlock(&ai->ai_tuple.tt_lock[feat]);

	return te;
}

/*
 * Lookup an IPv4 tuple.  Used by cgnat.
 */
struct apt_tuple *
apt_tuple_v4_lookup(struct apt_instance *ai, enum alg_feat feat,
		    struct apt_v4_key *key)
{
	struct apt_tuple *te;

	/* First try and match an entry with the packets source port */
	te = _apt_tuple_v4_lookup(ai, feat, key);

	/*
	 * If no match, then we try and match an 'any src port' entry.  To do
	 * this we set the keys src port to 0 as this allows the same
	 * optimised match function to be used.
	 */
	if (!te && key->k4_sport) {
		uint16_t tmp = key->k4_sport;

		key->k4_sport = 0;

		te = _apt_tuple_v4_lookup(ai, feat, key);

		key->k4_sport = tmp;
	}

	return te;
}

/*
 * Link two tuples together
 */
int apt_tuple_pair(struct apt_tuple *te1, struct apt_tuple *te2)
{
	if (te1->te_paired || te2->te_paired)
		return -EINVAL;

	te1->te_paired = apt_tuple_get(te2);
	te2->te_paired = apt_tuple_get(te1);

	return 0;
}

/*
 * Unlink two tuples
 */
static void apt_tuple_unpair(struct apt_tuple *te)
{
	struct apt_tuple *te2;

	if (!te || !te->te_paired)
		return;

	te2 = te->te_paired;
	assert(te2->te_paired == te);

	apt_tuple_put(te2);
	te->te_paired = NULL;

	apt_tuple_put(te2->te_paired);
	te2->te_paired = NULL;
}

/*
 * Format a string from a tuple entry
 */
char *apt_tuple_str(struct apt_tuple *te, char *dst, size_t sz)
{
	int l = 0;

	l += snprintf(dst+l, sz-l, "[%u] ", te->te_id);
	l += apt_key_str(&te->te_key, dst+l, sz-l);
	l += snprintf(dst+l, sz-l, " %s", alg_feat_name(te->te_feat));
	l += snprintf(dst+l, sz-l, " [");
	l += snprintf(dst+l, sz-l, "%s", te->te_keep ? "K":"-");
	l += snprintf(dst+l, sz-l, "%s", te->te_expired ? "E":"-");
	l += snprintf(dst+l, sz-l, "]");

	return dst;
}

static void apt_tuple_jsonw(struct json_writer *json, struct apt_tuple *te)
{
	char saddr[INET6_ADDRSTRLEN];
	char daddr[INET6_ADDRSTRLEN];
	uint64_t etime = 0, timeout = APT_TUPLE_TIMEOUT;

	if (te->te_timeout)
		timeout = te->te_timeout / 1000;

	if (te->te_expiry_time > soft_ticks)
		etime = (te->te_expiry_time - soft_ticks) / 1000;

	jsonw_start_object(json);

	jsonw_uint_field(json, "id", te->te_id);
	jsonw_string_field(json, "feature",
			   alg_feat_name(te->te_key.v4_key.k4_feat));
	jsonw_uint_field(json, "timeout", timeout);
	jsonw_uint_field(json, "expiry_time", etime);
	jsonw_bool_field(json, "expired", te->te_expired);
	jsonw_bool_field(json, "keep", te->te_keep);
	jsonw_uint_field(json, "alen", te->te_alen);
	if (te->te_paired)
		jsonw_uint_field(json, "pair", te->te_paired->te_id);

	if (te->te_alen == 4) {
		inet_ntop(AF_INET, &te->te_key.v4_key.k4_saddr,
			  saddr, sizeof(saddr));
		inet_ntop(AF_INET, &te->te_key.v4_key.k4_daddr,
			  daddr, sizeof(daddr));
	} else {
		inet_ntop(AF_INET6, &te->te_key.v6_key.k6_saddr,
			  saddr, sizeof(saddr));
		inet_ntop(AF_INET6, &te->te_key.v6_key.k6_daddr,
			  daddr, sizeof(daddr));
	}

	jsonw_uint_field(json, "proto", te->te_proto);
	jsonw_uint_field(json, "ifindex", te->te_ifindex);
	jsonw_string_field(json, "saddr", saddr);
	jsonw_uint_field(json, "sport", ntohs(te->te_sport));
	jsonw_string_field(json, "daddr", daddr);
	jsonw_uint_field(json, "dport", ntohs(te->te_dport));

	/* Allow feature to write json for tuple context */
	alg_apt_tuple_jsonw(json, te->te_feat, te->te_ctx, te->te_expired);

	jsonw_end_object(json);
}

void apt_tuple_tbl_jsonw(struct json_writer *json, struct apt_tuple_tbl *tt)
{
	struct cds_lfht_iter iter;
	struct apt_tuple *te;

	jsonw_name(json, "tuple");
	jsonw_start_array(json);

	if (tt->tt_ht) {
		cds_lfht_for_each_entry(tt->tt_ht, &iter, te, te_node) {
			apt_tuple_jsonw(json, te);
		}
	}

	jsonw_end_array(json);
}

void apt_tuple_jsonw_matching(json_writer_t *json, struct apt_instance *ai,
			      int feat, apt_match_func_t match_fn,
			      void *match_key)
{
	struct apt_tuple_tbl *tt = ai ? &ai->ai_tuple : NULL;
	struct cds_lfht_iter iter;
	struct apt_tuple *te;

	jsonw_name(json, "tuple");
	jsonw_start_array(json);

	if (!tt || !tt->tt_ht)
		goto end;

	cds_lfht_for_each_entry(tt->tt_ht, &iter, te, te_node) {
		if (feat != te->te_feat && feat != ALG_FEAT_ALL)
			continue;

		if (match_fn && !(*match_fn)(te->te_ctx, match_key))
			continue;

		apt_tuple_jsonw(json, te);
	}

end:
	jsonw_end_array(json);
}

/*
 * Tuple table walk
 */
int apt_tuple_walk(struct apt_instance *ai, int feat,
		   apt_match_func_t match_fn, void *match_key,
		   apt_walk_cb_func_t walk_cb, void *ctx)
{
	struct apt_tuple_tbl *tt = ai ? &ai->ai_tuple : NULL;
	struct cds_lfht_iter iter;
	struct apt_tuple *te;

	if (!tt || !tt->tt_ht)
		return 0;

	cds_lfht_for_each_entry(tt->tt_ht, &iter, te, te_node) {
		if (feat != te->te_feat && feat != ALG_FEAT_ALL)
			continue;

		if (match_fn && !(*match_fn)(te->te_ctx, match_key))
			continue;

		if ((*walk_cb)(te, ctx))
			return 1;
	}

	return 0;
}

/*
 * Expire a tuple
 */
void apt_tuple_expire(struct apt_tuple *te)
{
	if (!te || te->te_expired)
		return;

	te->te_expired = true;
	apt_tuple_unpair(te);
}

static bool apt_tuple_is_expired(struct apt_tuple *te, uint64_t current)
{
	if (te->te_expired)
		return true;

	/*
	 * 'keep' entries never timeout.  They must be explicitly expired
	 * and/or deleted.
	 */
	if (te->te_keep)
		return false;

	if (current > te->te_expiry_time) {
		apt_tuple_expire(te);
		return true;
	}
	return false;
}

/*
 * Flush entries my expiring them.  They will no longer be found by a lookup
 * or add.  The gc will delete the expired entries after two passes.
 */
void apt_tuple_tbl_flush(struct apt_tuple_tbl *tt, int feat, bool flush_all,
			 apt_match_func_t match_fn, void *match_key)
{
	struct cds_lfht_iter iter;
	struct apt_tuple *te;

	if (!tt->tt_ht)
		return;

	cds_lfht_for_each_entry(tt->tt_ht, &iter, te, te_node) {
		if (feat != te->te_feat && feat != ALG_FEAT_ALL)
			continue;

		if (match_fn && !(*match_fn)(te->te_ctx, match_key))
			continue;

		if (te->te_expired)
			apt_tuple_del(tt, te);

		if (flush_all || !te->te_keep)
			apt_tuple_expire(te);

	}
}

/*
 * Garbage collection
 */
void apt_tuple_tbl_gc(struct apt_tuple_tbl *tt, uint64_t current)
{
	struct cds_lfht_iter iter;
	struct apt_tuple *te;

	if (!tt->tt_ht)
		return;

	cds_lfht_for_each_entry(tt->tt_ht, &iter, te, te_node) {

		if (apt_tuple_is_expired(te, current)) {
			if (te->te_removing)
				apt_tuple_del(tt, te);
			else
				te->te_removing = true;
		}
	}
}
