/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <rte_acl.h>
#include <rte_mempool.h>
#include <rte_jhash.h>

#include "npf_rte_acl.h"
#include "npf_rule_gen.h"

#include "main.h"
#include "urcu.h"
#include "util.h"
#include "vplane_log.h"

#include "rldb.h"

#define RLDB_ERR(args...) RTE_LOG(ERR, DATAPLANE, args)

#define RLDB_MAX_RULES    (1 << 17)
#define RLDB_MAX_ELEMENTS (2 * RLDB_MAX_RULES)

#define GLOBAL_MIN_BUCKETS (2 << 6)
#define GLOBAL_MAX_BUCKETS (2 << 10)

#define RLDB_MIN_BUCKETS (1 << 16)
#define RLDB_MAX_BUCKETS (1 << 17)

struct rldb_db_handle {
	npf_match_ctx_t *match_ctx;
	uint32_t flags;
	uint16_t af;
	struct rte_acl_rule *acl_rules;
	struct cds_lfht *ht;
	struct cds_lfht_node ht_node;
	struct rldb_stats stats;
	/* --- cacheline 1 boundary (64 bytes) was 40 bytes ago --- */
	char name[RLDB_NAME_MAX];
};

struct rldb_rule_handle {
	uint32_t rule_no;
	struct cds_lfht_node ht_node;
	struct rldb_rule_spec rule;
};

static struct rte_mempool *rldb_rh_mempool;
static struct cds_lfht *rldb_global_ht;

static bool rldb_disabled;

static rte_atomic32_t rldb_counter;

/*
 * initialize infrastructure for rule database
 */
int rldb_init(void)
{
	int rc;
	rldb_rh_mempool = rte_mempool_create("rldb_rh_pool", RLDB_MAX_ELEMENTS,
					  sizeof(struct rldb_rule_handle),
					  0, 0, NULL, NULL, NULL, NULL,
					  rte_socket_id(), 0);

	if (!rldb_rh_mempool) {
		RLDB_ERR("Could not allocate rldb rule-handle pool\n");
		return -ENOMEM;
	}

	rldb_global_ht = cds_lfht_new(GLOBAL_MIN_BUCKETS,
				      GLOBAL_MIN_BUCKETS,
				      GLOBAL_MAX_BUCKETS,
				      CDS_LFHT_AUTO_RESIZE, NULL);

	if (!rldb_global_ht) {
		RLDB_ERR("Could not allocate rldb id hashtable\n");
		rc = -ENOMEM;
		goto error;
	}

	rldb_disabled = false;

	rc = npf_rte_acl_setup();
	if (rc)
		goto error;

	return 0;

error:
	rldb_cleanup();
	return rc;
}

static int rldb_name_match(struct cds_lfht_node *node, const void *key)
{
	const char *key_name = key;

	struct rldb_db_handle *db = caa_container_of(node,
						     struct rldb_db_handle,
						     ht_node);

	if (strcmp(key_name, db->name) == 0)
		return 1;

	return 0;
}

static void rldb_db_handle_destroy(struct rldb_db_handle *db)
{
	if (!db)
		return;

	cds_lfht_destroy(db->ht, NULL);

	if (db->match_ctx)
		npf_rte_acl_destroy(db->af, &db->match_ctx);

	free(db);
}

/*
 * Borrowed from nat_pool.c:
 * ----8<----
 * rte_jhash reads from memory in 4-byte chunks.  If the length of 'name' is
 * not a multiple of 4 bytes then it may try and read memory that is not
 * mapped.  Issue was detected by valgrind.
 * ---->8-----
 *
 * Also spotted by AddressSanitizer: global-buffer-overflow
 */
static uint32_t rldb_name_hash(const char *name, size_t name_len)
{
	char buf[name_len+3];

	memcpy(buf, name, name_len);
	return rte_jhash(buf, name_len, 0);
}

/*
 * create rule database of specified name
 */
int rldb_create(const char *name, uint32_t flags, struct rldb_db_handle **_db)
{
	uint32_t hash;
	struct rldb_db_handle *db = NULL;
	size_t name_len;
	struct cds_lfht_node *node;
	int id, rc = 0;

	if (!name)
		return -EINVAL;

	if (rldb_disabled) {
		RLDB_ERR("RLDB is not initialized\n");
		return -ENODEV;
	}

	name_len = strnlen(name, RLDB_NAME_MAX);
	if (name_len == RLDB_NAME_MAX || name_len == 0)
		return -EINVAL;

	db = zmalloc_aligned(sizeof(*db));
	if (!db) {
		RLDB_ERR("Could not allocate memory for rldb: \"%s\".\n", name);
		rc = -ENOMEM;
		goto error;
	}

	id = rte_atomic32_add_return(&rldb_counter, 1);
	snprintf(db->name, RLDB_NAME_MAX, "%s-%d", name, id);

	if (flags & NPFRL_FLAG_V4_PFX)
		db->af = AF_INET;
	else if (flags & NPFRL_FLAG_V6_PFX)
		db->af = AF_INET6;
	else {
		rc = -EAFNOSUPPORT;
		goto error;
	}

	db->flags = flags;

	db->ht = cds_lfht_new(RLDB_MIN_BUCKETS,
			      RLDB_MIN_BUCKETS,
			      RLDB_MAX_BUCKETS, CDS_LFHT_AUTO_RESIZE, NULL);

	if (!db->ht) {
		RLDB_ERR("Could not allocate rldb hashtable\n");
		rc = -ENOMEM;
		goto error;
	}

	cds_lfht_node_init(&db->ht_node);

	hash = rldb_name_hash(name, name_len);
	node = cds_lfht_add_unique(rldb_global_ht, hash, rldb_name_match,
				   &db->name, &db->ht_node);
	if (node != &db->ht_node) {
		RLDB_ERR("Could not add rldb: database with the name \"%s\" "
			 "already exists.\n", name);
		rc = -EEXIST;
		goto error;
	}

	rc = npf_rte_acl_init(db->af, db->name, RLDB_MAX_RULES, &db->match_ctx);
	if (rc < 0) {
		RLDB_ERR
		    ("Could not add rldb (%s): NPF rte_acl could not be "
		     "initialized\n", name);
		goto error;
	}

	*_db = db;

	return 0;

error:
	if (db) {
		cds_lfht_del(rldb_global_ht, &db->ht_node);
		rldb_db_handle_destroy(db);
	}

	return rc;
}

static void rldb_prepare_rule_v4(struct rldb_rule_spec *rule,
				 uint8_t *match_addr, uint8_t *mask)
{
	uint8_t proto = 0;
	uint16_t loport = 0, hiport = 0;
	struct rldb_v4_prefix *pfx;

	/* protocol */
	if (rule->rldb_flags & NPFRL_FLAG_PROTO)
		proto = rule->rldb_proto.npfrl_proto;

	match_addr[NPC_GPR_PROTO_OFF_v4] = proto;
	mask[NPC_GPR_PROTO_OFF_v4] = proto ? 0 : ~0;

	/* src addr */
	if (rule->rldb_flags & NPFRL_FLAG_SRC_PFX) {
		pfx = &rule->rldb_src_addr.v4_pfx;
		*(uint32_t *) &match_addr[NPC_GPR_SADDR_OFF_v4] =
		    *(uint32_t *) &pfx->npfrl_bytes;
		*(uint32_t *) &mask[NPC_GPR_SADDR_OFF_v4] =
		    htonl(npf_prefix_to_host_mask4(pfx->npfrl_plen));
	}

	/* dst addr */
	if (rule->rldb_flags & NPFRL_FLAG_DST_PFX) {
		pfx = &rule->rldb_dst_addr.v4_pfx;
		*(uint32_t *) &match_addr[NPC_GPR_DADDR_OFF_v4] =
		    *(uint32_t *) &pfx->npfrl_bytes;
		*(uint32_t *) &mask[NPC_GPR_DADDR_OFF_v4] =
		    htonl(npf_prefix_to_host_mask4(pfx->npfrl_plen));
	}

	/* src port */
	if (rule->rldb_flags & NPFRL_FLAG_SRC_PORT_RANGE) {
		loport = rule->rldb_src_port_range.npfrl_loport;
		hiport = rule->rldb_src_port_range.npfrl_hiport;
	} else {
		loport = 0;
		hiport = 0xFFFF;
	}

	match_addr[NPC_GPR_SPORT_OFF_v4] = loport >> 8;
	match_addr[NPC_GPR_SPORT_OFF_v4 + 1] = loport & 0xFF;

	mask[NPC_GPR_SPORT_OFF_v4] = hiport >> 8;
	mask[NPC_GPR_SPORT_OFF_v4 + 1] = hiport & 0xFF;

	/* dst port */
	if (rule->rldb_flags & NPFRL_FLAG_DST_PORT_RANGE) {
		loport = rule->rldb_dst_port_range.npfrl_loport;
		hiport = rule->rldb_dst_port_range.npfrl_hiport;
	} else {
		loport = 0;
		hiport = 0xFFFF;
	}

	match_addr[NPC_GPR_DPORT_OFF_v4] = loport >> 8;
	match_addr[NPC_GPR_DPORT_OFF_v4 + 1] = loport & 0xFF;

	mask[NPC_GPR_DPORT_OFF_v4] = hiport >> 8;
	mask[NPC_GPR_DPORT_OFF_v4 + 1] = hiport & 0xFF;
}

static void rldb_prepare_rule_v6(struct rldb_rule_spec *rule,
				 uint8_t *match_addr, uint8_t *mask)
{
	uint8_t proto = 0;
	uint16_t loport = 0, hiport = 0;
	unsigned int i;
	struct in6_addr addr_mask;
	uint8_t *addr_mask_ptr;
	struct rldb_v6_prefix *pfx;

	/* protocol */
	if (rule->rldb_flags & NPFRL_FLAG_PROTO)
		proto = rule->rldb_proto.npfrl_proto;

	match_addr[NPC_GPR_PROTO_OFF_v6] = proto;
	mask[NPC_GPR_PROTO_OFF_v6] = proto ? 0 : ~0;

	/* src addr */
	if (rule->rldb_flags & NPFRL_FLAG_SRC_PFX) {
		pfx = &rule->rldb_src_addr.v6_pfx;
		npf_masklen_to_grouper_mask(AF_INET6, pfx->npfrl_plen,
					    &addr_mask);
		addr_mask_ptr = (uint8_t *) &addr_mask.s6_addr;
		for (i = 0; i < NPC_GPR_SADDR_LEN_v6; i++) {
			match_addr[NPC_GPR_SADDR_OFF_v6 + i] =
			    pfx->npfrl_bytes[i];
			mask[NPC_GPR_SADDR_OFF_v6 + i] = addr_mask_ptr[i];
		}
	}

	/* dst addr */
	if (rule->rldb_flags & NPFRL_FLAG_DST_PFX) {
		pfx = &rule->rldb_dst_addr.v6_pfx;
		npf_masklen_to_grouper_mask(AF_INET6, pfx->npfrl_plen,
					    &addr_mask);
		addr_mask_ptr = (uint8_t *) &addr_mask.s6_addr;
		for (i = 0; i < NPC_GPR_DADDR_LEN_v6; i++) {
			match_addr[NPC_GPR_DADDR_OFF_v6 + i] =
			    pfx->npfrl_bytes[i];
			mask[NPC_GPR_DADDR_OFF_v6 + i] = addr_mask_ptr[i];
		}
	}

	/* src port */
	if (rule->rldb_flags & NPFRL_FLAG_SRC_PORT_RANGE) {
		loport = rule->rldb_src_port_range.npfrl_loport;
		hiport = rule->rldb_src_port_range.npfrl_hiport;
	} else {
		loport = 0;
		hiport = 0xFFFF;
	}

	match_addr[NPC_GPR_SPORT_OFF_v6] = loport >> 8;
	match_addr[NPC_GPR_SPORT_OFF_v6 + 1] = loport & 0xFF;

	mask[NPC_GPR_SPORT_OFF_v6] = hiport >> 8;
	mask[NPC_GPR_SPORT_OFF_v6 + 1] = hiport & 0xFF;

	/* dst port */
	if (rule->rldb_flags & NPFRL_FLAG_DST_PORT_RANGE) {
		loport = rule->rldb_dst_port_range.npfrl_loport;
		hiport = rule->rldb_dst_port_range.npfrl_hiport;
	} else {
		loport = 0;
		hiport = 0xFFFF;
	}

	match_addr[NPC_GPR_DPORT_OFF_v6] = loport >> 8;
	match_addr[NPC_GPR_DPORT_OFF_v6 + 1] = loport & 0xFF;

	mask[NPC_GPR_DPORT_OFF_v6] = hiport >> 8;
	mask[NPC_GPR_DPORT_OFF_v6 + 1] = hiport & 0xFF;
}

/*
 * start a sequence of operations
 */
int rldb_start_transaction(struct rldb_db_handle *db)
{
	if (!db)
		return -EINVAL;

	if (rldb_disabled) {
		RLDB_ERR("RLDB is not initialized\n");
		return -ENODEV;
	}

	return npf_rte_acl_start_transaction(db->af, db->match_ctx);
}

/*
 * commit a sequence of operations
 */
int rldb_commit_transaction(struct rldb_db_handle *db)
{
	int rc;

	if (!db)
		return -EINVAL;

	if (rldb_disabled) {
		RLDB_ERR("RLDB is not initialized\n");
		return -ENODEV;
	}

	rc = npf_rte_acl_commit_transaction(db->af, db->match_ctx);
	if (rc < 0)
		goto error;

	db->stats.rldb_transaction_cnt++;

	return 0;
error:
	db->stats.rldb_err.transaction_failed++;
	return rc;
}

static int rldb_rule_match(struct cds_lfht_node *node, const void *key)
{
	const uint32_t *key_rule_no = key;

	struct rldb_rule_handle *rh = caa_container_of(node,
						       struct rldb_rule_handle,
						       ht_node);

	return rh->rule_no == *key_rule_no;
}

static int rldb_rule_handle_create(uint32_t rule_no,
				   struct rldb_rule_spec const *in_spec,
				   struct rldb_rule_handle **out_rh)
{
	int rc;
	struct rldb_rule_handle *rh;
	struct rte_mempool_cache *cache;

	cache = rte_mempool_default_cache(rldb_rh_mempool, rte_lcore_id());
	if (unlikely(rte_mempool_generic_get(rldb_rh_mempool, (void *)&rh,
					     1, cache) != 0)) {
		RLDB_ERR
		    ("Could not allocate memory from rldb memory pool for "
		     "rule %u.\n", rule_no);
		rc = -ENOMEM;
		goto error;
	}

	memset(rh, 0, sizeof(*rh));

	rh->rule_no = rule_no;
	memcpy(&rh->rule, in_spec, sizeof(rh->rule));

	if (out_rh)
		*out_rh = rh;

	return 0;

error:
	return rc;
}

static void rldb_rule_handle_destroy(struct rldb_rule_handle *rh)
{
	struct rte_mempool_cache *cache;

	cache = rte_mempool_default_cache(rldb_rh_mempool, rte_lcore_id());
	rte_mempool_generic_put(rldb_rh_mempool, (void *)&rh, 1, cache);
}

/*
 * add rule to the specified database
 *
 * rule_no MUST NOT be 0.
 */
int rldb_add_rule(struct rldb_db_handle *db, uint32_t rule_no,
		  struct rldb_rule_spec const *in_spec,
		  struct rldb_rule_handle **out_rh)
{
	int rc;
	struct rldb_rule_handle *rh = NULL;
	struct cds_lfht_node *node;
	uint8_t match_addr[NPC_GPR_SIZE_v6] = { 0 };
	uint8_t mask[NPC_GPR_SIZE_v6] = { 0 };

	if (!db || !rule_no || !in_spec || !out_rh)
		return -EINVAL;

	if (rldb_disabled)
		return -ENODEV;

	rc = rldb_rule_handle_create(rule_no, in_spec, &rh);
	if (rc < 0) {
		RLDB_ERR("Could not create rule handle for rule %u\n", rule_no);
		goto error;
	}

	switch (db->af) {
	case AF_INET:
		rldb_prepare_rule_v4(&rh->rule, match_addr, mask);
		break;
	case AF_INET6:
		rldb_prepare_rule_v6(&rh->rule, match_addr, mask);
		break;
	default:
		rc = -EAFNOSUPPORT;
		goto error;
	}

	node = cds_lfht_add_unique(db->ht, rule_no,
				   rldb_rule_match, &rh, &rh->ht_node);
	if (node != &rh->ht_node) {
		RLDB_ERR("Could not add rule %u to rldb \"%s\".\n",
			 rule_no, db->name);
		rc = -EEXIST;
		goto error;
	}

	rc = npf_rte_acl_add_rule(db->af, db->match_ctx, rh->rule_no,
				  rh->rule.rldb_priority, match_addr, mask,
				  NULL);
	if (rc < 0) {
		RLDB_ERR("Failed to add ACL rule: %u\n", rh->rule_no);
		goto delete_and_error;
	}

	*out_rh = rh;

	db->stats.rldb_rules_added++;
	db->stats.rldb_rule_cnt++;

	return 0;

delete_and_error:
	cds_lfht_del(db->ht, &rh->ht_node);

error:
	if (rh)
		rldb_rule_handle_destroy(rh);

	db->stats.rldb_err.rule_add_failed++;
	return rc;
}

/*
 * delete rule from the specified database
 */
int rldb_del_rule(struct rldb_db_handle *db, struct rldb_rule_handle *rh)
{
	int rc;
	uint32_t rule_no;
	uint8_t match_addr[NPC_GPR_SIZE_v6];
	uint8_t mask[NPC_GPR_SIZE_v6];

	if (!db || !rh)
		return -EINVAL;

	if (rldb_disabled)
		return -ENODEV;

	switch (db->af) {
	case AF_INET:
		rldb_prepare_rule_v4(&rh->rule, match_addr, mask);
		break;
	case AF_INET6:
		rldb_prepare_rule_v6(&rh->rule, match_addr, mask);
		break;
	default:
		rc = -EAFNOSUPPORT;
		goto error;
	}

	rule_no = rh->rule_no;

	rc = npf_rte_acl_del_rule(db->af, db->match_ctx, rule_no,
				  rh->rule.rldb_priority, match_addr, mask);
	if (rc < 0) {
		RLDB_ERR("Failed to remove ACL rule %u from ACL trie\n",
			 rule_no);
		goto error;

	}

	cds_lfht_del(db->ht, &rh->ht_node);
	rldb_rule_handle_destroy(rh);

	db->stats.rldb_rules_deleted++;
	db->stats.rldb_rule_cnt--;

	return 0;

error:
	db->stats.rldb_err.rule_del_failed++;
	return rc;
}

/*
 * find rule by rule number
 */
int rldb_find_rule(struct rldb_db_handle *db, uint32_t rule_no,
		   struct rldb_rule_handle **out_rh)
{
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;

	if (!out_rh || !db || !rule_no)
		return -EINVAL;

	if (rldb_disabled)
		return -ENODEV;

	cds_lfht_lookup(db->ht, rule_no, rldb_rule_match, &rule_no, &iter);

	node = cds_lfht_iter_get_node(&iter);

	/* no match */
	if (!node) {
		*out_rh = NULL;
		return -ENOENT;
	}

	*out_rh = caa_container_of(node, struct rldb_rule_handle, ht_node);

	return 0;
}

static int rldb_rule_no_to_priority(void *userdata,
				    uint32_t rule_no,
				    uint32_t *priority)
{
	int err;
	struct rldb_rule_handle *rh;
	struct rldb_db_handle *db = (struct rldb_db_handle *) userdata;

	err = rldb_find_rule(db, rule_no, &rh);
	if (err)
		return err;

	*priority = rh->rule.rldb_priority;
	return 0;
}

/*
 * match packets against rules in the specified database
 */
int rldb_match(struct rldb_db_handle *db,
	       /* array of packets to be matched */
	       struct rte_mbuf *m[],
	       /* number of packets */
	       uint32_t num_packets, struct rldb_result *result)
{
	uint32_t rule_no = 0;
	struct rldb_rule_handle *rh;
	struct npf_match_cb_data data = { 0 };
	int rc = 0;

	if (!db || !m || num_packets != 1)
		return -EINVAL;

	if (rldb_disabled)
		return -ENODEV;

	/* non-npc variant. Supports only standard 5-tuple packets */
	data.mbuf = m[0];
	rc = npf_rte_acl_match(db->af, db->match_ctx, NULL, &data,
			       rldb_rule_no_to_priority, (void *)db, &rule_no);
	if (rc == -ENOENT)
		goto error;

	if (rc != 0 && rc != -ENOENT)
		goto error;

	if (result) {
		rc = rldb_find_rule(db, rule_no, &rh);
		if (rc < 0)
			goto error;

		result->rldb_rule_no = rule_no;
		result->rldb_user_data = rh->rule.rldb_user_data;
	}

error:
	db->stats.rldb_err.rule_match_failed++;
	return rc;
}

/*
 * get statistics at database level
 */
int rldb_get_stats(struct rldb_db_handle *db, struct rldb_stats *stats)
{
	if (!db)
		return -EINVAL;

	if (rldb_disabled) {
		RLDB_ERR("RLDB is not initialized\n");
		return -ENODEV;
	}

	memcpy(stats, &db->stats, sizeof(*stats));

	return 0;
}

/*
 * clear statistics at database level
 */
int rldb_clear_stats(struct rldb_db_handle *db)
{
	if (!db)
		return -EINVAL;

	if (rldb_disabled) {
		RLDB_ERR("RLDB is not initialized\n");
		return -ENODEV;
	}

	memset(&db->stats, 0, sizeof(db->stats));

	return 0;
}

/*
 * walk rule database
 */
void rldb_walk(struct rldb_db_handle *db, rldb_walker_t walker, void *userdata)
{
	struct cds_lfht_iter iter;
	struct rldb_rule_handle *rh;

	if (!db || !walker)
		return;

	if (rldb_disabled) {
		RLDB_ERR("RLDB is not initialized\n");
		return;
	}

	cds_lfht_for_each_entry(db->ht, &iter, rh, ht_node) {
		if (walker(rh, userdata) < 0)
			return;
	}
}

#define PREFIX_STRLEN (INET6_ADDRSTRLEN + sizeof("/128"))

static const char *rldb_prefix_str(uint16_t family, union rldb_pfx *rldb_pfx,
				   char *buf, size_t blen)
{
	char addrbuf[INET6_ADDRSTRLEN];
	const char *addrstr;
	uint32_t count;
	int16_t prefix_len = -1;

	switch (family) {
	case AF_INET:
		addrstr =
		    inet_ntop(family, (void *)&rldb_pfx->v4_pfx.npfrl_bytes[0],
			      addrbuf, sizeof(addrbuf));
		prefix_len = rldb_pfx->v4_pfx.npfrl_plen;
		break;
	case AF_INET6:
		addrstr =
		    inet_ntop(family, (void *)&rldb_pfx->v6_pfx.npfrl_bytes[0],
			      addrbuf, sizeof(addrbuf));
		prefix_len = rldb_pfx->v6_pfx.npfrl_plen;
		break;
	default:
		addrstr = NULL;
	}

	count = snprintf(buf, blen, "%s", addrstr ? : "[bad address]");
	if (prefix_len >= 0)
		snprintf(buf + count, blen - count, "/%d", prefix_len);

	return buf;
}

static const char *rldb_port_range(struct rldb_l4port_range *pr, char *buf,
				   size_t blen)
{
	int rc;

	if (pr->npfrl_loport == pr->npfrl_hiport)
		rc = snprintf(buf, blen, "%u", pr->npfrl_loport);
	else
		rc = snprintf(buf, blen, "%u-%u", pr->npfrl_loport,
			      pr->npfrl_hiport);

	if (rc < 0)
		snprintf(buf, blen, "[bad port-range]");

	return buf;
}

static void rldb_dump_rule_spec(struct rldb_rule_spec *rule, json_writer_t *wr)
{
	char prefix_buf[PREFIX_STRLEN];
	uint16_t af = 0;

	if (rule->rldb_flags & NPFRL_FLAG_V4_PFX)
		af = AF_INET;
	else if (rule->rldb_flags & NPFRL_FLAG_V6_PFX)
		af = AF_INET6;

	jsonw_uint_field(wr, "priority", rule->rldb_priority);
	jsonw_uint_field(wr, "flags", rule->rldb_flags);

	jsonw_string_field(wr, "src_addr",
			   rldb_prefix_str(af, &rule->rldb_src_addr, prefix_buf,
					   sizeof(prefix_buf)));

	jsonw_string_field(wr, "dst_addr",
			   rldb_prefix_str(af, &rule->rldb_dst_addr, prefix_buf,
					   sizeof(prefix_buf)));

	jsonw_uint_field(wr, "proto", rule->rldb_proto.npfrl_proto);

	jsonw_string_field(wr, "sport",
			   rldb_port_range(&rule->rldb_src_port_range,
					   prefix_buf, sizeof(prefix_buf)));
	jsonw_string_field(wr, "dport",
			   rldb_port_range(&rule->rldb_dst_port_range,
					   prefix_buf, sizeof(prefix_buf)));
}

/*
 * dump rule database in json form
 */
void rldb_dump(struct rldb_db_handle *db, json_writer_t *wr)
{
	struct cds_lfht_iter iter;
	struct rldb_rule_handle *rh;
	struct rldb_stats *stats;

	if (!db || !wr)
		return;

	if (rldb_disabled) {
		RLDB_ERR("RLDB is not initialized\n");
		return;
	}

	jsonw_string_field(wr, "name", db->name);
	jsonw_uint_field(wr, "flags", db->flags);

	/* stats */
	stats = &db->stats;

	jsonw_name(wr, "stats");
	jsonw_start_object(wr);
	jsonw_uint_field(wr, "rules_added", stats->rldb_rules_added);
	jsonw_uint_field(wr, "rules_deleted", stats->rldb_rules_deleted);
	jsonw_uint_field(wr, "rule_cnt", stats->rldb_rule_cnt);
	jsonw_uint_field(wr, "transaction_cnt", stats->rldb_transaction_cnt);

	jsonw_name(wr, "error-counters");
	jsonw_start_object(wr);
	jsonw_uint_field(wr, "rule_add_failed",
			 db->stats.rldb_err.rule_add_failed);
	jsonw_uint_field(wr, "rule_del_failed",
			 db->stats.rldb_err.rule_del_failed);
	jsonw_uint_field(wr, "rule_match_failed",
			 db->stats.rldb_err.rule_match_failed);
	jsonw_uint_field(wr, "transaction_failed",
			 db->stats.rldb_err.transaction_failed);
	jsonw_end_object(wr);

	jsonw_end_object(wr);

	/* rules */

	jsonw_name(wr, "rules");

	jsonw_start_array(wr);
	cds_lfht_for_each_entry(db->ht, &iter, rh, ht_node) {
		jsonw_start_object(wr);
		jsonw_uint_field(wr, "rule_no", rh->rule_no);
		rldb_dump_rule_spec(&rh->rule, wr);
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);

	npf_rte_acl_dump(db->match_ctx, wr);
}

/*
 * destroy specified rule database
 */
int rldb_destroy(struct rldb_db_handle *db)
{
	struct cds_lfht_iter iter;
	struct rldb_rule_handle *rh;

	if (!db)
		return -EINVAL;

	if (rldb_disabled) {
		RLDB_ERR("RLDB is not initialized\n");
		return -ENODEV;
	}

	if (db->ht) {
		cds_lfht_for_each_entry(db->ht, &iter, rh, ht_node) {
			if (!cds_lfht_del(db->ht, &rh->ht_node))
				rldb_rule_handle_destroy(rh);
		}
	}

	cds_lfht_del(rldb_global_ht, &db->ht_node);
	rldb_db_handle_destroy(db);

	return 0;
}

/*
 * clean up infrastructure set up for rule database
 */
int rldb_cleanup(void)
{
	int rc = 0;
	struct cds_lfht_iter iter;
	struct rldb_db_handle *db;

	if (rldb_global_ht) {
		cds_lfht_for_each_entry(rldb_global_ht, &iter, db, ht_node) {
			rldb_destroy(db);
		}

		cds_lfht_destroy(rldb_global_ht, NULL);
	}

	if (rldb_rh_mempool)
		rte_mempool_free(rldb_rh_mempool);

	rldb_rh_mempool = NULL;
	rldb_global_ht = NULL;

	rldb_disabled = true;

	npf_rte_acl_teardown();

	return rc;
}
