/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <pthread.h>
#include <rte_acl.h>
#include <rte_atomic.h>
#include <rte_rcu_qsbr.h>
#include <rte_ip.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include "vplane_log.h"
#include "vplane_debug.h"
#include "npf_rte_acl.h"
#include <rte_log.h>
#include "../ip_funcs.h"
#include "../netinet6/ip6_funcs.h"

static uint32_t npf_match_ctx_cnt;
static pthread_t acl_merge_tid;
static void *npf_rte_acl_optimize(void *args);

static struct rte_mempool *npr_mtrie_pool;
static struct rte_mempool *npr_acl4_mempool;
static struct rte_mempool *npr_acl6_mempool;
static struct rte_mempool *npr_pdel_pool;

#define NPR_RULE_MAX_ELEMENTS (1 << 14)

#define NPR_ACL_RING_SZ 512

struct rte_ring *npr_acl4_ring, *npr_acl6_ring;

/*
 * Trie state contexts:
 *
 * - writable: trie is open to accept new rules, not yet build
 *             nor used for matching/classification of traffic.
 * - frozen: trie is closed and does no longer accept new rules.
 *           Those tries usually are already in use for matching
 *           classification. Or about to get staged for matching.
 * - merging: trie is about to get merged into a consolidated trie.
 *            It's closed and does not longer accept new rules,
 *            but is used for matching.
 *
 *
 * The usual state transitions of tries are:
 *
 * writable -> frozen -> merging (-> trie gets released)
 *
 * Note: those states are independent of higher-level APIs
 * transaction logic/state.
 */

enum trie_state {
	TRIE_STATE_WRITABLE = 0,
	TRIE_STATE_FROZEN,
	TRIE_STATE_MERGING,
	TRIE_STATE_MAX
};

const char *trie_state_strs[TRIE_STATE_MAX] = {
	[TRIE_STATE_WRITABLE] = "writable",
	[TRIE_STATE_FROZEN]   = "frozen",
	[TRIE_STATE_MERGING]  = "merging",
};

/*
 * A trie containing a subset of entries for a particular context.
 * Used to optimize update operations
 */

#define NPF_M_TRIE_FLAG_POOL   0x8000   /* trie allocated from pool */

struct npf_match_ctx_trie {
	struct cds_list_head  trie_link;
	char                 *trie_name;
	uint16_t              num_rules;
	uint16_t              flags;
	enum trie_state       trie_state;
	struct rte_acl_ctx   *acl_ctx;
	bool                  rules_deleted;
	struct rcu_head       npr_rcu;
};

#define MAX_TRANSACTION_ENTRIES 512

static struct cds_list_head ctx_list;

struct npf_match_ctx {
	struct cds_list_head  ctx_link;   /* linkage for all ctx structures */
	struct cds_list_head  trie_list;  /* linkage for tries in this ctx */
	char                 *ctx_name;   /* name of match context. Needs to be
					   * globally unique
					   */
	rte_atomic16_t        num_tries;  /* number of tries associated with
					   * this context
					   */
	uint32_t              ctx_id;     /* counter used to generate a unique
					   * id
					   */
	int                   af;
	uint32_t              max_rules;
	uint32_t              num_rules;
	struct trans_entry   *tr;
	uint32_t              tr_num_entries;
	bool                  tr_in_progress;
	rte_spinlock_t        merge_lock;
};

struct pending_delete {
	struct cds_list_head       pending_link; /* linkage pendling_delete list */
	struct rte_acl_rule       *rule;         /* copied rule to be deleted */
};

enum rule_op {
	RULE_OP_ADD,
	RULE_OP_DELETE
};

struct trans_entry {
	enum rule_op               rule_op;
	struct npf_match_ctx_trie *trie;
	const struct rte_acl_rule *rule;
};

/* rte acl stuff */
/*
 * Rule and trace formats definitions.
 */
enum {
	PROTO_FIELD_IPV4,
	SRC_FIELD_IPV4,
	DST_FIELD_IPV4,
	SRCP_FIELD_IPV4,
	DSTP_FIELD_IPV4,
	NUM_FIELDS_IPV4
};

/*
 * That effectively defines order of IPV4 classifications:
 *  - PROTO
 *  - SRC IP ADDRESS
 *  - DST IP ADDRESS
 *  - PORTS (SRC and DST)
 */
enum {
	RTE_ACL_IPV4_PROTO,
	RTE_ACL_IPV4_SRC,
	RTE_ACL_IPV4_DST,
	RTE_ACL_IPV4_PORTS,
	RTE_ACL_IPV4_NUM
};

/*
 * rte-acl requires the first field in the rule to be 1 byte long.
 * That is the reason for starting with the IP protocol number.
 * The other fields are defined as offsets relative to the protocol
 * field.
 */
static struct rte_acl_field_def ipv4_defs[NUM_FIELDS_IPV4] = {
	[PROTO_FIELD_IPV4] = {
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint8_t),
		.field_index = PROTO_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4_PROTO,
		.offset = 0,
	},
	[SRC_FIELD_IPV4] = {
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4_SRC,
		.offset = (offsetof(struct rte_ipv4_hdr, src_addr) -
			   offsetof(struct rte_ipv4_hdr, next_proto_id)),
	},
	[DST_FIELD_IPV4] = {
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4_DST,
		.offset = (offsetof(struct rte_ipv4_hdr, dst_addr) -
			   offsetof(struct rte_ipv4_hdr, next_proto_id)),
	},
	[SRCP_FIELD_IPV4] = {
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = SRCP_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4_PORTS,
		.offset = (sizeof(struct rte_ipv4_hdr) -
			   offsetof(struct rte_ipv4_hdr, next_proto_id)),
	},
	[DSTP_FIELD_IPV4] = {
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = DSTP_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4_PORTS,
		.offset = (sizeof(struct rte_ipv4_hdr) -
			   offsetof(struct rte_ipv4_hdr, next_proto_id) +
			   sizeof(uint16_t)),
	},
};

#define	IPV6_ADDR_LEN	16
#define	IPV6_ADDR_U16	(IPV6_ADDR_LEN / sizeof(uint16_t))
#define	IPV6_ADDR_U32	(IPV6_ADDR_LEN / sizeof(uint32_t))

enum {
	PROTO_FIELD_IPV6,
	SRC1_FIELD_IPV6,
	SRC2_FIELD_IPV6,
	SRC3_FIELD_IPV6,
	SRC4_FIELD_IPV6,
	DST1_FIELD_IPV6,
	DST2_FIELD_IPV6,
	DST3_FIELD_IPV6,
	DST4_FIELD_IPV6,
	SRCP_FIELD_IPV6,
	DSTP_FIELD_IPV6,
	NUM_FIELDS_IPV6
};

/*
 * rte-acl requires the first field in the rule to be 1 byte long.
 * That is the reason for starting with the IP protocol number.
 * The other fields are defined as offsets relative to the protocol
 * field.
 */
static struct rte_acl_field_def ipv6_defs[NUM_FIELDS_IPV6] = {
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint8_t),
		.field_index = PROTO_FIELD_IPV6,
		.input_index = PROTO_FIELD_IPV6,
		.offset = 0,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC1_FIELD_IPV6,
		.input_index = SRC1_FIELD_IPV6,
		.offset = (offsetof(struct rte_ipv6_hdr, src_addr) -
			   offsetof(struct rte_ipv6_hdr, proto)),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC2_FIELD_IPV6,
		.input_index = SRC2_FIELD_IPV6,
		.offset = (offsetof(struct rte_ipv6_hdr, src_addr) -
			   offsetof(struct rte_ipv6_hdr, proto) +
			   sizeof(uint32_t)),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC3_FIELD_IPV6,
		.input_index = SRC3_FIELD_IPV6,
		.offset = (offsetof(struct rte_ipv6_hdr, src_addr) -
			   offsetof(struct rte_ipv6_hdr, proto) +
			   2 * sizeof(uint32_t)),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC4_FIELD_IPV6,
		.input_index = SRC4_FIELD_IPV6,
		.offset = (offsetof(struct rte_ipv6_hdr, src_addr) -
			   offsetof(struct rte_ipv6_hdr, proto) +
			   3 * sizeof(uint32_t)),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST1_FIELD_IPV6,
		.input_index = DST1_FIELD_IPV6,
		.offset = (offsetof(struct rte_ipv6_hdr, dst_addr)
			   - offsetof(struct rte_ipv6_hdr, proto)),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST2_FIELD_IPV6,
		.input_index = DST2_FIELD_IPV6,
		.offset = (offsetof(struct rte_ipv6_hdr, dst_addr) -
			   offsetof(struct rte_ipv6_hdr, proto) +
			   sizeof(uint32_t)),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST3_FIELD_IPV6,
		.input_index = DST3_FIELD_IPV6,
		.offset = (offsetof(struct rte_ipv6_hdr, dst_addr) -
			   offsetof(struct rte_ipv6_hdr, proto) +
			   2 * sizeof(uint32_t)),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST4_FIELD_IPV6,
		.input_index = DST4_FIELD_IPV6,
		.offset = (offsetof(struct rte_ipv6_hdr, dst_addr) -
			   offsetof(struct rte_ipv6_hdr, proto) +
			   3 * sizeof(uint32_t)),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = SRCP_FIELD_IPV6,
		.input_index = SRCP_FIELD_IPV6,
		.offset = (sizeof(struct rte_ipv6_hdr) -
			   offsetof(struct rte_ipv6_hdr, proto)),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = DSTP_FIELD_IPV6,
		.input_index = SRCP_FIELD_IPV6,
		.offset = (sizeof(struct rte_ipv6_hdr) -
			   offsetof(struct rte_ipv6_hdr, proto) +
			   sizeof(uint16_t)),
	},
};

enum {
	CB_FLD_SRC_ADDR,
	CB_FLD_DST_ADDR,
	CB_FLD_SRC_PORT_LOW,
	CB_FLD_SRC_PORT_DLM,
	CB_FLD_SRC_PORT_HIGH,
	CB_FLD_DST_PORT_LOW,
	CB_FLD_DST_PORT_DLM,
	CB_FLD_DST_PORT_HIGH,
	CB_FLD_PROTO,
	CB_FLD_USERDATA,
	CB_FLD_NUM,
};

RTE_ACL_RULE_DEF(acl4_rules, RTE_DIM(ipv4_defs));
RTE_ACL_RULE_DEF(acl6_rules, RTE_DIM(ipv6_defs));

static uint32_t
acl_rule_hash(const void *data, uint32_t data_len, uint32_t init_val)
{
	const struct rte_acl_rule *rule = (const struct rte_acl_rule *) data;

	return rte_jhash(&rule->data.userdata, data_len, init_val);
}

#define NPR_MTRIE_MAX_RULES    MAX_TRANSACTION_ENTRIES
#define NPR_POOL_DEF_MAX_TRIES 128

static int npf_rte_acl_trie_destroy(int af, struct npf_match_ctx_trie *m_trie);

static int npf_rte_acl_destroy_mtrie_pool(int af);

static inline int npf_rte_acl_get_ring(int af, struct rte_ring **ring)
{
	if (af == AF_INET)
		*ring = npr_acl4_ring;
	else if (af == AF_INET6)
		*ring = npr_acl6_ring;
	else
		return -EINVAL;

	return 0;
}

static int npf_rte_acl_create_trie(int af, int max_rules,
				   struct npf_match_ctx_trie **m_trie)
{
	int err;
	size_t key_len = sizeof(((struct rte_acl_rule *) 0)->data.userdata);

	/* rte_acl in hashtable mode can only generate
	 * rules with at least 8 entries.
	 */
	if (max_rules < 8)
		max_rules = 8;

	struct rte_acl_param acl_param = {
		.socket_id = SOCKET_ID_ANY,
		.max_rule_num = max_rules,
		.flags = ACL_F_USE_HASHTABLE,
		.hash_func = acl_rule_hash,
		.hash_key_len = key_len,
	};
	struct rte_acl_rcu_config rcu_conf = {
		.mode = RTE_ACL_QSBR_MODE_DQ,
		.dq_size = max_rules,
		.dq_trigger_reclaim_limit = 0,
		.dq_max_reclaim_size = ~0,
		.thread_id = dp_lcore_id(),
		.v = dp_rcu_qsbr_get(),
	};
	struct npf_match_ctx_trie *tmp_trie;
	const char *pfx1, *pfx2;
	char acl_name[RTE_ACL_NAMESIZE];
	static uint16_t v4_cnt, v6_cnt;

	if (af == AF_INET) {
		acl_param.rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv4_defs));
		acl_param.rule_pool = npr_acl4_mempool;
		pfx1 = "ipv4";
	} else if (af == AF_INET6) {
		acl_param.rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv6_defs));
		acl_param.rule_pool = npr_acl6_mempool;
		pfx1 = "ipv6";
	} else
		return -EINVAL;

	if (max_rules <= NPR_MTRIE_MAX_RULES) {
		err = rte_mempool_get(npr_mtrie_pool, (void **)&tmp_trie);
		if (err) {
			RTE_LOG(ERR, DATAPLANE,
				"Could not allocate %s mtrie for pool\n", pfx1);
			return -ENOMEM;
		}
		memset(tmp_trie, 0, sizeof(*tmp_trie));
		tmp_trie->flags = NPF_M_TRIE_FLAG_POOL;
		pfx2 = "pool";
	} else {
		tmp_trie = calloc(1, sizeof(*tmp_trie));
		if (!tmp_trie)
			return -ENOMEM;
		pfx2 = "merge";
	}

	snprintf(acl_name, RTE_ACL_NAMESIZE, "%s-%s-%d", pfx1, pfx2,
		 af == AF_INET ? v4_cnt++ : v6_cnt++);

	tmp_trie->trie_name = strdup(acl_name);
	if (!tmp_trie->trie_name) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not allocate name %s for ACL ctx\n",
			acl_name);
		err = -ENOMEM;
		goto error;
	}

	acl_param.name = acl_name;
	tmp_trie->acl_ctx = rte_acl_create(&acl_param);
	if (tmp_trie->acl_ctx == NULL) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not allocate ACL context for %s: %s\n", acl_name,
			rte_strerror(rte_errno));
		err = -rte_errno;
		goto error;
	}

	err = rte_acl_rcu_qsbr_add(tmp_trie->acl_ctx, &rcu_conf);
	if (err) {
		RTE_LOG(ERR, DATAPLANE, "Failed to enable RCU for ACL ctx %s\n",
			tmp_trie->trie_name);
		goto error;
	}

	*m_trie = tmp_trie;
	return 0;

error:
	if (tmp_trie->acl_ctx)
		rte_acl_free(tmp_trie->acl_ctx);

	if (tmp_trie->trie_name)
		free(tmp_trie->trie_name);

	if (tmp_trie->flags == NPF_M_TRIE_FLAG_POOL)
		rte_mempool_put(npr_mtrie_pool, tmp_trie);
	else
		free(tmp_trie);
	return err;
}

static inline int
npf_rte_acl_get_trie(int af, struct npf_match_ctx_trie **m_trie)
{
	int err;
	struct rte_ring *ring;

	if (!m_trie)
		return -EINVAL;

	err = npf_rte_acl_get_ring(af, &ring);
	if (err)
		return err;

	err = rte_ring_dequeue(ring, (void **)m_trie);
	if (err) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not dequeue new trie for af %d ring: %s\n",
			af, strerror(-err));
		return err;
	}

	return 0;
}

static int
npf_rte_acl_put_trie(int af, struct npf_match_ctx_trie *m_trie)
{
	int err;
	struct rte_ring *ring;

	err = npf_rte_acl_get_ring(af, &ring);
	if (err)
		return err;

	err = rte_ring_enqueue(ring, (void **)m_trie);
	if (err) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not enqueue new trie for af %d ring: %s\n",
			af, strerror(-err));
		return err;
	}

	return 0;
}

static int
npf_rte_acl_create_mtrie_pool(int af, int max_tries)
{
	int i, err;
	struct npf_match_ctx_trie *m_trie;
	struct rte_ring *ring;

	err = npf_rte_acl_get_ring(af, &ring);
	if (err)
		return err;

	for (i = 0; i < max_tries; i++) {
		err = npf_rte_acl_create_trie(af, NPR_MTRIE_MAX_RULES, &m_trie);
		if (err) {
			RTE_LOG(ERR, DATAPLANE,
				"Could not allocate mtrie for pool\n");
			goto error;
		}

		m_trie->trie_state = TRIE_STATE_WRITABLE;

		err = rte_ring_enqueue(ring, m_trie);
		if (err) {
			RTE_LOG(ERR, DATAPLANE, "Could not enqueue trie %s to ring\n",
				m_trie->trie_name);
			goto error;
		}
	}

	return 0;

error:
	npf_rte_acl_destroy_mtrie_pool(af);
	return -ENOMEM;
}

static int npf_rte_acl_destroy_mtrie_pool(int af)
{
	struct rte_ring *ring;
	int err;
	struct npf_match_ctx_trie *m_trie;

	err = npf_rte_acl_get_ring(af, &ring);
	if (err)
		return err;

	while ((err = rte_ring_dequeue(ring, (void **)&m_trie)) == 0) {
		free(m_trie->trie_name);
		rte_acl_free(m_trie->acl_ctx);
		rte_mempool_put(npr_mtrie_pool, m_trie);
	}

	return 0;
}

/*
 * Packet matching callback functions which use the rte_acl API
 */

static int
npf_rte_acl_add_trie(npf_match_ctx_t *m_ctx)
{
	int err;
	struct npf_match_ctx_trie *m_trie;

	err = npf_rte_acl_get_trie(m_ctx->af, &m_trie);
	if (err)
		return err;

	cds_list_add(&m_trie->trie_link, &m_ctx->trie_list);
	rte_atomic16_inc(&m_ctx->num_tries);
	DP_DEBUG(RLDB_ACL, DEBUG, DATAPLANE,
		 "Added trie %s to ctx %s (Trie count = %d)\n",
		 m_trie->trie_name, m_ctx->ctx_name,
		 rte_atomic16_read(&m_ctx->num_tries));

	return err;
}

static void
npf_rte_acl_delete_trie(npf_match_ctx_t *ctx, struct npf_match_ctx_trie *m_trie)
{
	cds_list_del(&m_trie->trie_link);
	npf_rte_acl_trie_destroy(ctx->af, m_trie);
	rte_atomic16_dec(&ctx->num_tries);
	DP_DEBUG(RLDB_ACL, DEBUG, DATAPLANE,
		 "Delete trie %s from ctx %s (Trie count = %d)\n",
		 m_trie->trie_name, ctx->ctx_name,
		 rte_atomic16_read(&ctx->num_tries));
}

static int npf_rte_acl_get_writable_trie(npf_match_ctx_t *m_ctx,
					 struct npf_match_ctx_trie **m_trie)
{
	int err;
	struct npf_match_ctx_trie *tmp_trie;

	if (rte_atomic16_read(&m_ctx->num_tries)) {
		tmp_trie = cds_list_first_entry(&m_ctx->trie_list,
						struct npf_match_ctx_trie,
						trie_link);

		if (tmp_trie->trie_state == TRIE_STATE_WRITABLE &&
		    tmp_trie->num_rules < NPR_MTRIE_MAX_RULES) {
			*m_trie = tmp_trie;
			return 0;
		}
	}

	err = npf_rte_acl_add_trie(m_ctx);
	if (err)
		return err;

	tmp_trie = cds_list_first_entry(&m_ctx->trie_list,
					struct npf_match_ctx_trie,
					trie_link);

	*m_trie = tmp_trie;
	return 0;
}

int npf_rte_acl_init(int af, const char *name, uint32_t max_rules,
		     npf_match_ctx_t **m_ctx)
{
	char ctx_name[RTE_ACL_NAMESIZE];
	npf_match_ctx_t *tmp_ctx;
	uint16_t rule_size;
	size_t tr_sz;
	int err;

	if (!npf_match_ctx_cnt) {
		err = pthread_create(&acl_merge_tid, NULL, npf_rte_acl_optimize,
				     NULL);
		if (err) {
			RTE_LOG(ERR, DATAPLANE,
				"Could not create thread for ACL optimization");
			return err;
		}
	}

	if (af == AF_INET)
		rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv4_defs));
	else if (af == AF_INET6)
		rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv6_defs));
	else
		return -EINVAL;

	tmp_ctx = calloc(1, sizeof(npf_match_ctx_t));
	if (!tmp_ctx) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not allocate match context for %s\n", name);
		return -ENOMEM;
	}

	snprintf(ctx_name, RTE_ACL_NAMESIZE, "%s-%s", name,
		 af == AF_INET ? "ipv4" : "ipv6");

	tmp_ctx->ctx_name = strdup(ctx_name);
	if (!tmp_ctx->ctx_name) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not allocate name %s for ACL ctx\n",
			ctx_name);
		err = -ENOMEM;
		goto error;
	}
	tmp_ctx->max_rules = max_rules;

	tr_sz = (sizeof(struct trans_entry) + rule_size)
		* MAX_TRANSACTION_ENTRIES;
	tmp_ctx->tr = rte_zmalloc("trie_transaction_records", tr_sz,
				  RTE_CACHE_LINE_SIZE);
	if (!tmp_ctx->tr) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not allocate transaction record memory pool for trie %s\n",
			tmp_ctx->ctx_name);
		err = -ENOMEM;
		goto error;
	}

	tmp_ctx->af = af;
	CDS_INIT_LIST_HEAD(&tmp_ctx->trie_list);

	err = npf_rte_acl_add_trie(tmp_ctx);
	if (err)
		goto error;

	*m_ctx = tmp_ctx;

	cds_list_add(&tmp_ctx->ctx_link, &ctx_list);
	npf_match_ctx_cnt++;

	return 0;

error:
	if (tmp_ctx->tr)
		rte_free(tmp_ctx->tr);
	if (tmp_ctx->ctx_name)
		free(tmp_ctx->ctx_name);
	free(tmp_ctx);

	return err;
}

/*
 * convert big-endian wildcard mask to mask
 */
static inline uint8_t wc_mask_to_mask(const uint8_t *wc_mask, uint8_t len)
{
	uint8_t mask = 0, tmp;
	int8_t i, j;

	for (i = len - 1; i >= 0; i--) {
		tmp = wc_mask[i];

		for (j = 0; j < 8; j++) {
			if (!(tmp & 0x1))
				break;
			mask++;
			tmp >>= 1;
		}
		if (j != 8)
			break;
	}
	return ((len * 8) - mask);
}

static int
npf_rte_acl_record_transaction_entry(npf_match_ctx_t *m_ctx,
				     struct npf_match_ctx_trie *m_trie,
				     enum rule_op rule_op,
				     const struct rte_acl_rule *acl_rule,
				     size_t rule_sz __rte_unused)
{
	struct trans_entry *t_entry = NULL;

	if (m_ctx->tr_num_entries >= MAX_TRANSACTION_ENTRIES) {
		RTE_LOG(ERR, DATAPLANE,
			"Number of transaction entries for trie %s exceeded (%u).\n",
			m_ctx->ctx_name, MAX_TRANSACTION_ENTRIES);
		return -ENOMEM;
	}

	t_entry = &m_ctx->tr[m_ctx->tr_num_entries++];
	t_entry->rule_op = rule_op;
	t_entry->trie = m_trie;
	t_entry->rule = acl_rule;

	return 0;
}

/*
 * convert IPv4 5 tuple and mask to ACL rule
 * The rules are stored in NPF in network byte order.
 * However rte_acl expects the rules to be in host byte order.
 */
static void npf_rte_acl_add_v4_rule(const uint8_t *match_addr, uint8_t *mask,
				    uint32_t rule_no, uint32_t priority,
				    struct acl4_rules *v4_rules)
{
	uint16_t val, val_mask;

	memset(v4_rules, 0, sizeof(*v4_rules));
	v4_rules->data.category_mask = 1;
	v4_rules->data.priority = priority;
	v4_rules->data.userdata = rule_no;

	/*
	 * Protocol id may either be unspecified or a specific value
	 */
	val = match_addr[NPC_GPR_PROTO_OFF_v4];
	val_mask = mask[NPC_GPR_PROTO_OFF_v4];
	if (val_mask == 0)
		val_mask = val;

	v4_rules->field[PROTO_FIELD_IPV4].value.u8 = val;
	v4_rules->field[PROTO_FIELD_IPV4].mask_range.u8 = val_mask;

	v4_rules->field[SRC_FIELD_IPV4].value.u32 =
		rte_bswap32(*(uint32_t *)&match_addr[NPC_GPR_SADDR_OFF_v4]);
	v4_rules->field[SRC_FIELD_IPV4].mask_range.u32 =
		wc_mask_to_mask((const uint8_t *)&mask[NPC_GPR_SADDR_OFF_v4],
				4);

	v4_rules->field[DST_FIELD_IPV4].value.u32 =
		rte_bswap32(*(uint32_t *)&match_addr[NPC_GPR_DADDR_OFF_v4]);
	v4_rules->field[DST_FIELD_IPV4].mask_range.u32 =
		wc_mask_to_mask((const uint8_t *)&mask[NPC_GPR_DADDR_OFF_v4],
				4);

	v4_rules->field[SRCP_FIELD_IPV4].value.u16 =
		*(uint16_t *)&match_addr[NPC_GPR_SPORT_OFF_v4];
	v4_rules->field[SRCP_FIELD_IPV4].mask_range.u16 =
		*(uint16_t *)&mask[NPC_GPR_SPORT_OFF_v4];

	v4_rules->field[DSTP_FIELD_IPV4].value.u16 =
		*(uint16_t *)&match_addr[NPC_GPR_DPORT_OFF_v4];
	v4_rules->field[DSTP_FIELD_IPV4].mask_range.u16 =
		*(uint16_t *)&mask[NPC_GPR_DPORT_OFF_v4];
}

/*
 * convert IPv6 5 tuple and mask to ACL rule
 * The rules are stored in NPF in network byte order.
 * However rte_acl expects the rules to be in host byte order.
 */
static void npf_rte_acl_add_v6_rule(uint8_t *match_addr, uint8_t *mask,
				    uint32_t rule_no, uint32_t priority,
				    struct acl6_rules *v6_rules)
{
	uint16_t val, val_mask;
	uint8_t *v6_addr, *v6_mask;

	memset(v6_rules, 0, sizeof(*v6_rules));
	v6_rules->data.category_mask = 1;
	v6_rules->data.priority = priority;
	v6_rules->data.userdata = rule_no;

	/*
	 * Protocol id may either be unspecified or a specific value
	 */
	val = match_addr[NPC_GPR_PROTO_OFF_v6];
	val_mask = mask[NPC_GPR_PROTO_OFF_v6];
	if (val_mask == 0)
		val_mask = val;

	v6_rules->field[PROTO_FIELD_IPV6].value.u8 = val;
	v6_rules->field[PROTO_FIELD_IPV6].mask_range.u8 = val_mask;

	v6_addr = &match_addr[NPC_GPR_SADDR_OFF_v6];
	v6_mask = &mask[NPC_GPR_SADDR_OFF_v6];
	v6_rules->field[SRC1_FIELD_IPV6].value.u32 =
		rte_bswap32(*(uint32_t *)v6_addr);
	v6_rules->field[SRC1_FIELD_IPV6].mask_range.u32 =
		wc_mask_to_mask(v6_mask, 4);
	v6_addr += sizeof(uint32_t);
	v6_mask += sizeof(uint32_t);

	v6_rules->field[SRC2_FIELD_IPV6].value.u32 =
		rte_bswap32(*(uint32_t *)v6_addr);
	v6_rules->field[SRC2_FIELD_IPV6].mask_range.u32 =
		wc_mask_to_mask(v6_mask, 4);
	v6_addr += sizeof(uint32_t);
	v6_mask += sizeof(uint32_t);

	v6_rules->field[SRC3_FIELD_IPV6].value.u32 =
		rte_bswap32(*(uint32_t *)v6_addr);
	v6_rules->field[SRC3_FIELD_IPV6].mask_range.u32 =
		wc_mask_to_mask(v6_mask, 4);
	v6_addr += sizeof(uint32_t);
	v6_mask += sizeof(uint32_t);

	v6_rules->field[SRC4_FIELD_IPV6].value.u32 =
		rte_bswap32(*(uint32_t *)v6_addr);
	v6_rules->field[SRC4_FIELD_IPV6].mask_range.u32 =
		wc_mask_to_mask(v6_mask, 4);

	v6_addr = &match_addr[NPC_GPR_DADDR_OFF_v6];
	v6_mask = &mask[NPC_GPR_DADDR_OFF_v6];

	v6_rules->field[DST1_FIELD_IPV6].value.u32 =
		rte_bswap32(*(uint32_t *)v6_addr);
	v6_rules->field[DST1_FIELD_IPV6].mask_range.u32 =
		wc_mask_to_mask(v6_mask, 4);
	v6_addr += sizeof(uint32_t);
	v6_mask += sizeof(uint32_t);

	v6_rules->field[DST2_FIELD_IPV6].value.u32 =
		rte_bswap32(*(uint32_t *)v6_addr);
	v6_rules->field[DST2_FIELD_IPV6].mask_range.u32 =
		wc_mask_to_mask(v6_mask, 4);
	v6_addr += sizeof(uint32_t);
	v6_mask += sizeof(uint32_t);

	v6_rules->field[DST3_FIELD_IPV6].value.u32 =
		rte_bswap32(*(uint32_t *)v6_addr);
	v6_rules->field[DST3_FIELD_IPV6].mask_range.u32 =
		wc_mask_to_mask(v6_mask, 4);
	v6_addr += sizeof(uint32_t);
	v6_mask += sizeof(uint32_t);

	v6_rules->field[DST4_FIELD_IPV6].value.u32 =
		rte_bswap32(*(uint32_t *)v6_addr);
	v6_rules->field[DST4_FIELD_IPV6].mask_range.u32 =
		wc_mask_to_mask(v6_mask, 4);

	v6_rules->field[SRCP_FIELD_IPV6].value.u16 =
		*(uint16_t *)&match_addr[NPC_GPR_SPORT_OFF_v6];
	v6_rules->field[SRCP_FIELD_IPV6].mask_range.u16 =
		*(uint16_t *)&mask[NPC_GPR_SPORT_OFF_v6];

	v6_rules->field[DSTP_FIELD_IPV6].value.u16 =
		*(uint16_t *)&match_addr[NPC_GPR_DPORT_OFF_v6];
	v6_rules->field[DSTP_FIELD_IPV6].mask_range.u16 =
		*(uint16_t *)&mask[NPC_GPR_DPORT_OFF_v6];
}

static int
npf_rte_acl_trie_add_rule(int af, struct npf_match_ctx_trie *m_trie,
			  const struct rte_acl_rule *acl_rule)
{
	int err;

	err = rte_acl_add_rules(m_trie->acl_ctx, acl_rule, 1);
	if (err) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not add rule for af %d to trie %s (%s), max_rules %d, num_rules %d : %d\n",
			af, m_trie->trie_name,
			trie_state_strs[m_trie->trie_state],
			NPR_MTRIE_MAX_RULES, m_trie->num_rules, err);
		return err;
	}
	m_trie->num_rules++;

	return 0;
}

int npf_rte_acl_add_rule(int af, npf_match_ctx_t *m_ctx, uint32_t rule_no,
			 uint32_t priority, uint8_t *match_addr, uint8_t *mask,
			 void *match_ctx __rte_unused)
{
	struct acl4_rules v4_rules;
	struct acl6_rules v6_rules;
	const struct rte_acl_rule *acl_rule;
	int err = 0;
	size_t rule_sz;
	struct npf_match_ctx_trie *m_trie;

	if (!m_ctx->tr_in_progress) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not add rule %u for trie %s: no transaction in progress\n",
			rule_no, m_ctx->ctx_name);
		return -EINVAL;
	}

	err = npf_rte_acl_get_writable_trie(m_ctx, &m_trie);
	if (err)
		return err;

	if (af == AF_INET) {
		npf_rte_acl_add_v4_rule(match_addr, mask, rule_no, priority,
					&v4_rules);
		acl_rule = (const struct rte_acl_rule *)&v4_rules;
		rule_sz = sizeof(struct acl4_rules);
	} else {
		npf_rte_acl_add_v6_rule(match_addr, mask, rule_no, priority,
					&v6_rules);
		acl_rule = (const struct rte_acl_rule *)&v6_rules;
		rule_sz = sizeof(struct acl6_rules);
	}

	err = npf_rte_acl_trie_add_rule(af, m_trie, acl_rule);
	if (err < 0)
		return err;

	m_ctx->num_rules++;

	DP_DEBUG(RLDB_ACL, DEBUG, DATAPLANE,
		 "Added rule %d to ctx %s\n", rule_no, m_ctx->ctx_name);

	err = npf_rte_acl_record_transaction_entry(m_ctx, m_trie, RULE_OP_ADD,
						   acl_rule, rule_sz);
	if (err)
		return err;

	return 0;
}

static int npf_rte_acl_trie_build(int af, struct npf_match_ctx_trie *m_trie)
{
	struct rte_acl_config cfg = { 0 };
	int err;

	if (!m_trie->num_rules)
		return 0;

	cfg.num_categories = 1;
	if (af == AF_INET) {
		cfg.num_fields = RTE_DIM(ipv4_defs);
		memcpy(cfg.defs, ipv4_defs, sizeof(ipv4_defs));
	} else {
		cfg.num_fields = RTE_DIM(ipv6_defs);
		memcpy(cfg.defs, ipv6_defs, sizeof(ipv6_defs));
	}

	/* build the runtime structures for added rules, with 2 categories. */
	err = rte_acl_build(m_trie->acl_ctx, &cfg);
	if (err != 0) {
		/* handle error at build runtime structures for ACL context. */
		RTE_LOG(ERR, DATAPLANE,
			"Could not build ACL rules for %s : %s\n",
			m_trie->trie_name, strerror(-err));
		return err;
	}
	m_trie->trie_state = TRIE_STATE_FROZEN;
	return 0;
}

int npf_rte_acl_build(int af, npf_match_ctx_t **m_ctx)
{
	int err = 0;
	npf_match_ctx_t *ctx = *m_ctx;
	struct npf_match_ctx_trie *m_trie;
	struct cds_list_head *list_entry, *next;

	if (!rte_atomic16_read(&ctx->num_tries))
		return 0;

	cds_list_for_each_safe(list_entry, next, &ctx->trie_list) {
		m_trie = cds_list_entry(list_entry, struct npf_match_ctx_trie,
					trie_link);

		if (m_trie->trie_state != TRIE_STATE_WRITABLE)
			break;

		err = npf_rte_acl_trie_build(af, m_trie);
		if (err)
			return err;
	}

	return err;
}

static int
npf_rte_acl_trie_del_rule(int af, struct npf_match_ctx_trie *m_trie,
			  const struct rte_acl_rule *acl_rule)
{
	int err = 0;

	err = rte_acl_del_rule(m_trie->acl_ctx, acl_rule);
	if (err && err != -ENOENT) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not remove rule for af %d : %d\n", af, err);
		return err;
	}

	/* Only reduce counter if there was a matching delete */
	if (err != -ENOENT)
		m_trie->num_rules--;

	return err;
}

int npf_rte_acl_del_rule(int af, npf_match_ctx_t *m_ctx, uint32_t rule_no,
			 uint32_t priority, uint8_t *match_addr, uint8_t *mask)
{
	struct npf_match_ctx_trie *m_trie;
	struct acl4_rules v4_rules;
	struct acl6_rules v6_rules;
	const struct rte_acl_rule *acl_rule;
	int err = 0;
	struct cds_list_head *list_entry, *next;
	size_t rule_sz;

	if (!m_ctx->tr_in_progress) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not delete rule %d from trie %s: no transaction in progress\n",
			rule_no, m_ctx->ctx_name);
		return -EINVAL;
	}

	if (af == AF_INET) {
		npf_rte_acl_add_v4_rule(match_addr, mask, rule_no, priority,
					&v4_rules);
		acl_rule = (const struct rte_acl_rule *)&v4_rules;
		rule_sz = sizeof(struct acl4_rules);
	} else {
		npf_rte_acl_add_v6_rule(match_addr, mask, rule_no, priority,
					&v6_rules);
		acl_rule = (const struct rte_acl_rule *)&v6_rules;
		rule_sz = sizeof(struct acl6_rules);
	}

	err = -ENOENT;

	rte_spinlock_lock(&m_ctx->merge_lock);

	cds_list_for_each_safe(list_entry, next, &m_ctx->trie_list) {
		m_trie = cds_list_entry(list_entry, struct npf_match_ctx_trie,
					trie_link);

		/*
		 * deletes are only permitted on entries that have been
		 * successfully added and committed. So only frozen tries
		 * are consulted
		 */
		if (m_trie->trie_state != TRIE_STATE_FROZEN)
			break;

		err = npf_rte_acl_trie_del_rule(af, m_trie, acl_rule);
		if (!err) {
			DP_DEBUG(RLDB_ACL, DEBUG, DATAPLANE,
				 "Deleted rule %d from ctx %s\n", rule_no,
				 m_ctx->ctx_name);
			if (!m_trie->num_rules) {
				npf_rte_acl_delete_trie(m_ctx, m_trie);
			}
			break;
		}
	}

	rte_spinlock_unlock(&m_ctx->merge_lock);

	/* record a transaction entry only upon successful deletion */
	if (!err)
		err = npf_rte_acl_record_transaction_entry(m_ctx, m_trie,
							   RULE_OP_DELETE,
							   acl_rule, rule_sz);

	return err;
}

static int
npf_rte_acl_trie_match(int af, struct npf_match_ctx_trie *m_trie,
		       npf_cache_t *npc __rte_unused,
		       struct npf_match_cb_data *data,
		       uint32_t *rule_no)
{
	int ret;
	uint32_t results = 0;
	const uint8_t *pkt_data[1];
	struct rte_mbuf *m = data->mbuf;
	uint8_t *nlp;

	if (!m_trie->num_rules)
		return -ENOENT;

	if (af == AF_INET) {
		nlp = (uint8_t *)iphdr(m);
		nlp = RTE_PTR_ADD(nlp, offsetof(struct ip, ip_p));
	} else {
		nlp = (uint8_t *)ip6hdr(m);
		nlp = RTE_PTR_ADD(nlp, offsetof(struct rte_ipv6_hdr, proto));
	}
	pkt_data[0] = nlp;

	ret = rte_acl_classify(m_trie->acl_ctx, pkt_data, &results, 1, 1);
	if (ret)
		return -EINVAL;

	*rule_no = results;
	return results ? 0 : -ENOENT;
}

int npf_rte_acl_match(int af, npf_match_ctx_t *m_ctx,
		      npf_cache_t *npc __rte_unused,
		      struct npf_match_cb_data *data,
		      npf_rte_acl_prio_map_cb_t prio_map_cb,
		      void *prio_map_userdata,
		      uint32_t *rule_no)
{
	int err;
	struct cds_list_head *list_entry, *next;
	struct npf_match_ctx_trie *m_trie;
	uint32_t result, priority = 0, tmp_priority = 0;

	if (!m_ctx->num_rules || !rte_atomic16_read(&m_ctx->num_tries))
		return -ENOENT;

	DP_DEBUG(RLDB_ACL, DEBUG, DATAPLANE, "Starting match on %s\n", m_ctx->ctx_name);

	cds_list_for_each_safe(list_entry, next, &m_ctx->trie_list) {
		m_trie = cds_list_entry(list_entry, struct npf_match_ctx_trie,
					trie_link);

		if (m_trie->trie_state == TRIE_STATE_WRITABLE) {
			DP_DEBUG(RLDB_ACL, DEBUG, DATAPLANE, "Skipping trie %s\n",
				 m_trie->trie_name);
			continue;
		}

		err = npf_rte_acl_trie_match(af, m_trie, npc, data, rule_no);
		if (!err) {
			DP_DEBUG(RLDB_ACL, DEBUG, DATAPLANE,
				 "Matched rule %d in trie %s\n", *rule_no,
				 m_trie->trie_name);
			err = prio_map_cb(prio_map_userdata, *rule_no, &tmp_priority);
			if (err)
				break;

			DP_DEBUG(RLDB_ACL, DEBUG, DATAPLANE,
				 "Priority of rule %d = %d\n",
				 *rule_no, tmp_priority);

			if (tmp_priority > priority) {
				priority = tmp_priority;
				result = *rule_no;
			}
		}
	}

	if (!priority)
		err = -ENOENT;
	else {
		*rule_no = result;
		err = 0;
	}

	return err;
}

int npf_rte_acl_start_transaction(int af __unused, npf_match_ctx_t *m_ctx)
{
	if (m_ctx->tr_in_progress) {
		RTE_LOG(ERR, DATAPLANE,
			"Transaction already in progress for trie %s\n",
			m_ctx->ctx_name);
		return -EINPROGRESS;
	}

	m_ctx->tr_in_progress = true;
	return 0;
}

/* Rollsback all operations of the current transaction.
 * In the unexpected case that an individual rollback operation
 * failed, this method will continue rolling back all other rules.
 *
 * Return code is smaller zero if at least one rollback action did
 * not succeed.
 */
static int npf_rte_acl_rollback_transaction(int af, npf_match_ctx_t *m_ctx)
{
	uint32_t i;
	int rc = 0;

	/* Rollbacks are not yet ready for prime-time.
	 *
	 * Transaction failures are considered fatal since then.
	 */
	rte_panic("Fatal error: NPF RTE ACL transaction failed.\n.");

	for (i = 0; i < m_ctx->tr_num_entries; i++) {
		struct trans_entry *te = &m_ctx->tr[i];

		switch (te->rule_op) {
		case RULE_OP_ADD:
			if (npf_rte_acl_trie_del_rule(af, te->trie, te->rule)
			    < 0)
				rc = -1;
			break;
		case RULE_OP_DELETE:
			if (npf_rte_acl_trie_add_rule(af, te->trie, te->rule)
			    < 0)
				rc = -1;
			break;
		default:
			RTE_LOG(ERR, DATAPLANE,
				"Unexpected transaction rule operation (%d) for trie %s\n",
				te->rule_op, m_ctx->ctx_name);
			rc = -1;
			break;
		}

		if (rc < 0) {
			RTE_LOG(ERR, DATAPLANE,
				"Failed to rollback rule on trie %s\n",
				m_ctx->ctx_name);
		}
	}

	return rc;
}

int npf_rte_acl_commit_transaction(int af, npf_match_ctx_t *m_ctx)
{
	int rc = 0;

	rc = npf_rte_acl_build(af, &m_ctx);

	/* build failed -> rollback transaction */
	if (rc < 0) {
		if (npf_rte_acl_rollback_transaction(af, m_ctx) < 0) {
			RTE_LOG(ERR, DATAPLANE,
				"FATAL: Transaction rollback of trie failed %s\n",
				m_ctx->ctx_name);
		}
	}

	m_ctx->tr_num_entries = 0;
	m_ctx->tr_in_progress = false;
	return rc;
}

static int
npf_rte_acl_trie_destroy(int af, struct npf_match_ctx_trie *m_trie)
{
	if (m_trie->flags & NPF_M_TRIE_FLAG_POOL)
		npf_rte_acl_put_trie(af, m_trie);
	else {
		rte_acl_reset(m_trie->acl_ctx);
		rte_acl_free(m_trie->acl_ctx);
		free(m_trie->trie_name);
	}
	return 0;
}

int npf_rte_acl_destroy(int af __rte_unused, npf_match_ctx_t **m_ctx)
{
	npf_match_ctx_t *ctx = *m_ctx;
	struct cds_list_head *list_entry, *next;
	struct npf_match_ctx_trie *m_trie;

	if (!rte_atomic16_read(&ctx->num_tries))
		return 0;

	cds_list_for_each_safe(list_entry, next, &ctx->trie_list) {
		m_trie = cds_list_entry(list_entry, struct npf_match_ctx_trie,
					trie_link);
		npf_rte_acl_delete_trie(ctx, m_trie);
	}

	cds_list_del(&ctx->ctx_link);
	free(ctx->ctx_name);
	free(ctx);
	*m_ctx = NULL;

	npf_match_ctx_cnt--;

	if (!npf_match_ctx_cnt) {
		pthread_cancel(acl_merge_tid);
		acl_merge_tid = 0;
	}
	return 0;
}

size_t npf_rte_acl_rule_size(int af)
{
	if (af == AF_INET)
		return RTE_ACL_RULE_SZ(RTE_DIM(ipv4_defs));

	return RTE_ACL_RULE_SZ(RTE_DIM(ipv6_defs));
}

#define M_TRIE_POOL_SIZE 512
#define PENDING_DELETE_POOL_SIZE 512

int npf_rte_acl_setup(void)
{
	int err;

	CDS_INIT_LIST_HEAD(&ctx_list);

	npr_pdel_pool = rte_mempool_create("npr_pdel_pool",
					   PENDING_DELETE_POOL_SIZE,
					   sizeof(struct pending_delete),
					   0, 0, NULL, NULL, NULL, NULL,
					   SOCKET_ID_ANY, 0);
	if (!npr_pdel_pool) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not create memory pool for pending deletes\n");
		goto error;
	}

	npr_mtrie_pool = rte_mempool_create("npr_mtrie_pool", M_TRIE_POOL_SIZE,
					    sizeof(struct npf_match_ctx_trie),
					    0, 0, NULL, NULL, NULL, NULL,
					    SOCKET_ID_ANY, 0);
	if (!npr_mtrie_pool) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not create memory pool for ACL m-tries\n");
		goto error;
	}

	npr_acl4_mempool = rte_mempool_create("npr_acl4_pool",
					      NPR_RULE_MAX_ELEMENTS,
					      npf_rte_acl_rule_size(AF_INET),
					      0, 0, NULL, NULL, NULL, NULL,
					      rte_socket_id(), 0);

	if (!npr_acl4_mempool) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not allocate acl rule pool for IPv4\n");
		goto error;
	}

	npr_acl6_mempool = rte_mempool_create("npr_acl6_pool",
					      NPR_RULE_MAX_ELEMENTS,
					      npf_rte_acl_rule_size(AF_INET6),
					      0, 0, NULL, NULL, NULL, NULL,
					      rte_socket_id(), 0);

	if (!npr_acl6_mempool) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not allocate acl rule pool for IPv6\n");
		goto error;
	}

	npr_acl4_ring = rte_ring_create("npr_acl4_ring", NPR_ACL_RING_SZ,
					0, 0);
	if (!npr_acl4_ring) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not create ring for IPv4 ACL m-tries\n");
		goto error;
	}

	npr_acl6_ring = rte_ring_create("npr_acl6_ring", NPR_ACL_RING_SZ,
					0, 0);
	if (!npr_acl6_ring) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not create ring for IPv6 ACL m-tries\n");
		goto error;
	}

	err = npf_rte_acl_create_mtrie_pool(AF_INET,
					    NPR_POOL_DEF_MAX_TRIES);
	if (err)
		goto error;

	err = npf_rte_acl_create_mtrie_pool(AF_INET6,
					    NPR_POOL_DEF_MAX_TRIES);
	if (err)
		goto error;

	return 0;

error:
	npf_rte_acl_teardown();
	return -ENOMEM;
}

int npf_rte_acl_teardown(void)
{
	if (npr_acl4_ring) {
		npf_rte_acl_destroy_mtrie_pool(AF_INET);
		rte_ring_free(npr_acl4_ring);
		npr_acl4_ring = NULL;
	}

	if (npr_acl6_ring) {
		npf_rte_acl_destroy_mtrie_pool(AF_INET6);
		rte_ring_free(npr_acl6_ring);
		npr_acl6_ring = NULL;
	}

	if (npr_acl4_mempool) {
		rte_mempool_free(npr_acl4_mempool);
		npr_acl4_mempool = NULL;
	}

	if (npr_acl6_mempool) {
		rte_mempool_free(npr_acl6_mempool);
		npr_acl6_mempool = NULL;
	}

	if (npr_mtrie_pool) {
		rte_mempool_free(npr_mtrie_pool);
		npr_mtrie_pool = NULL;
	}

	if (npr_pdel_pool) {
		rte_mempool_free(npr_pdel_pool);
		npr_pdel_pool = NULL;
	}

	return 0;
}

void npf_rte_acl_dump(npf_match_ctx_t *ctx, json_writer_t *wr)
{
	struct cds_list_head *list_entry, *next;
	struct npf_match_ctx_trie *m_trie;
	uint16_t num_tries = rte_atomic16_read(&ctx->num_tries);

	if (!num_tries)
		return;

	jsonw_name(wr, ctx->ctx_name);
	jsonw_start_object(wr);
	jsonw_uint_field(wr, "num_tries", num_tries);
	jsonw_name(wr, "tries");
	jsonw_start_array(wr);
	cds_list_for_each_safe(list_entry, next, &ctx->trie_list) {
		m_trie = cds_list_entry(list_entry, struct npf_match_ctx_trie,
					trie_link);
		jsonw_start_object(wr);
		jsonw_string_field(wr, "trie-name", m_trie->trie_name);
		jsonw_uint_field(wr, "num_rules", m_trie->num_rules);
		jsonw_string_field(wr, "state",
				   trie_state_strs[m_trie->trie_state]);
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
	jsonw_end_object(wr);
}


/*
 * Small tries are created in the main thread in order to enable a high tunnel
 * setup rate. However, keeping a long list of tries permanently can harm
 * forwarding performance. So they are examined and consolidated in a background
 * merge thread.

 * In order to minimize contention between the merge thread and the main thread,
 * and to ensure that the main thread does not stay locked for any extended
 * period, the following technique is used. The main thread acquires a lock only
 * during deletion of an entry from a trie. The merge thread acquires the same
 * lock only to cache the rule counts in the tries being merged and finally at
 * the time of replacing the tries being merged with the consolidated trie. If
 * rules have been deleted from any of the tries being merged while the
 * consolidated trie is being built, the consolidation is restarted
 */

/* limit number of rules in consolidated tries to 32K for optimal build time */
#define NPR_TRIE_MAX_RULES (1 << 15)

static void
npf_rte_acl_select_candidate_tries(struct npf_match_ctx_trie *merge_start __rte_unused,
				   uint16_t *num_tries __rte_unused,
				   uint16_t *num_rules __rte_unused)
{
	/* merge_start - first trie to be merged
	 * num_tries - number of tries to be merged
	 * num_rules - total number of rules in new merged trie
	 */
}

__rte_unused
static int
npf_rte_acl_delete_pending_rules(int af, struct npf_match_ctx_trie *new_trie,
				 struct cds_list_head *delete_list)
{
	int rc;
	struct pending_delete *pd, *next;
	struct rte_mempool *rule_pool;

	if (af == AF_INET)
		rule_pool = npr_acl4_mempool;
	else if (af == AF_INET6)
		rule_pool = npr_acl6_mempool;
	else
		return -EINVAL;

	if (cds_list_empty(delete_list))
		return 0;

	cds_list_for_each_entry_safe(pd, next, delete_list, pending_link) {

		rc = npf_rte_acl_trie_del_rule(af, new_trie, pd->rule);
		if (rc < 0) {
			RTE_LOG(ERR, DATAPLANE,
				"Failed to delete pending rule from merged trie %s: %s\n",
				new_trie->trie_name, rte_strerror(-rc));
			return rc;
		}

		cds_list_del_rcu(&pd->pending_link);

		rte_mempool_put(rule_pool, pd->rule);
		rte_mempool_put(npr_pdel_pool, pd);
	}

	return 0;
}

static int
npf_rte_acl_copy_rules(npf_match_ctx_t *ctx,
		       struct npf_match_ctx_trie *merge_start,
		       uint16_t num_tries,
		       struct npf_match_ctx_trie *dst_trie)
{
	int rc;
	struct npf_match_ctx_trie *next, *m_trie = merge_start;
	uint16_t i = 0;

	cds_list_for_each_entry_safe_from(m_trie, next, &ctx->trie_list, trie_link) {

		DP_DEBUG(RLDB_ACL, DEBUG, DATAPLANE, "Updating trie-state %s from %s to %s (%s)\n",
				m_trie->trie_name, trie_state_strs[m_trie->trie_state],
				trie_state_strs[TRIE_STATE_MERGING], __func__);
		m_trie->trie_state = TRIE_STATE_MERGING;

		DP_DEBUG(RLDB_ACL, DEBUG, DATAPLANE, "Merging %s (%u rules) into %s (%s)\n",
				m_trie->trie_name, m_trie->num_rules, dst_trie->trie_name,
				__func__);

		rc = rte_acl_copy_rules(dst_trie->acl_ctx, m_trie->acl_ctx);
		if (rc < 0) {
			RTE_LOG(ERR, DATAPLANE,
				"Could not copy rules into new trie %s: %s\n",
				dst_trie->trie_name, rte_strerror(-rc));
			return rc;
		}

		dst_trie->num_rules += m_trie->num_rules;

		if (++i == num_tries)
			break;
	}

	return 0;
}

static void
npf_rte_acl_delete_merged_tries(struct npf_match_ctx_trie *merge_start,
				uint16_t num_tries)
{
	struct cds_list_head *list_entry, *next;
	uint16_t i = 0;

	cds_list_for_each_safe(list_entry, next, &merge_start->trie_link) {
		cds_list_del(list_entry);
		if (++i == num_tries)
			break;
	}
}

static void npf_rte_acl_optimize_ctx(npf_match_ctx_t *ctx)
{
	int rc;
	struct cds_list_head *list_entry, *next;
	struct npf_match_ctx_trie *m_trie, *merge_start = NULL,
				  *new_trie = NULL;
	uint16_t merge_trie_cnt = 0, merge_rule_cnt;

	/* complete one full iteration over the list */
	/* find first frozen trie */
	cds_list_for_each_safe(list_entry, next, &ctx->trie_list) {
		m_trie = cds_list_entry(list_entry, struct npf_match_ctx_trie,
					trie_link);

		if (m_trie->trie_state == TRIE_STATE_FROZEN) {
			merge_start = m_trie;
			break;
		}
	}

	/* acquire merge lock */
	rte_spinlock_lock(&ctx->merge_lock);

	npf_rte_acl_select_candidate_tries(merge_start, &merge_trie_cnt,
					   &merge_rule_cnt);
	if (merge_trie_cnt <= 1) {
		rte_spinlock_unlock(&ctx->merge_lock);
		return;
	}

	/* allocate new trie */
	npf_rte_acl_create_trie(ctx->af, merge_rule_cnt, &new_trie);

	/* copy rules to new trie */
	rc = npf_rte_acl_copy_rules(ctx, merge_start, merge_trie_cnt, new_trie);
	if (rc < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"Trie-Optimization: Failed to copy rules into new trie: %s\n",
			strerror(-rc));
		return;
	}

	/* release merge lock */
	rte_spinlock_unlock(&ctx->merge_lock);

	/* build new trie */

	/* acquire merge lock */
	rte_spinlock_lock(&ctx->merge_lock);

	/* delete rules in pending list */

	/* rebuild trie */

	/* insert new trie */

	/* delete candidate tries */
	npf_rte_acl_delete_merged_tries(merge_start, merge_trie_cnt);

	/* release merge lock */
	rte_spinlock_unlock(&ctx->merge_lock);
}

#define NPF_RTE_ACL_MERGE_INTERVAL 5

static void *npf_rte_acl_optimize(void *args __rte_unused)
{
	npf_match_ctx_t *ctx;
	struct cds_list_head *list_entry, *next;

	pthread_setname_np(pthread_self(), "dp/acl-opt");
	dp_rcu_register_thread();
	while (1) {
		dp_rcu_thread_online();

		cds_list_for_each_safe(list_entry, next, &ctx_list) {
			ctx = cds_list_entry(list_entry, struct npf_match_ctx,
					     ctx_link);

			if (rte_atomic16_read(&ctx->num_tries) <= 2)
				continue;

			npf_rte_acl_optimize_ctx(ctx);
		}

		dp_rcu_thread_offline();
		sleep(NPF_RTE_ACL_MERGE_INTERVAL);
	}

	return NULL;
}
