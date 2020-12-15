/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <rte_acl.h>
#include <rte_ip.h>
#include "vplane_log.h"
#include "npf_rte_acl.h"
#include <rte_log.h>
#include "../ip_funcs.h"
#include "../netinet6/ip6_funcs.h"

#define MAX_TRANSACTION_ENTRIES 512

struct npf_match_ctx {
	struct rte_acl_ctx *acl_ctx;
	char *name;
	uint16_t num_rules;
	struct trans_entry   *tr;
	uint32_t              tr_num_entries;
	bool                  tr_in_progress;
};

enum rule_op {
	RULE_OP_ADD,
	RULE_OP_DELETE
};

struct trans_entry {
	enum rule_op               rule_op;
	struct npf_match_ctx      *trie;
	struct rte_acl_rule       *rule;
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

/*
 * Packet matching callback functions which use the rte_acl API
 */

int npf_rte_acl_init(int af, const char *name, uint32_t max_rules,
		     npf_match_ctx_t **m_ctx)
{
	struct rte_acl_param acl_param = {
		.socket_id = SOCKET_ID_ANY,
		.max_rule_num = max_rules,
	};
	char acl_name[RTE_ACL_NAMESIZE];
	npf_match_ctx_t *tmp_ctx;
	static uint32_t ctx_id;
	size_t tr_sz;
	int err;

	tmp_ctx = calloc(1, sizeof(npf_match_ctx_t));
	if (!tmp_ctx) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not allocate match context for %s\n", name);
		return -ENOMEM;
	}

	/*
	 * rte_acl_create returns a pointer to an existing context if
	 * there is one of the same name. The NPF call flow involves
	 * re-creating an entire ruleset when there are changes to the
	 * configuration. In order to ensure that a new context is created
	 * each time, a unique number is suffixed to the name
	 */
	snprintf(acl_name, RTE_ACL_NAMESIZE, "%s-%s-%d", name,
		 af == AF_INET ? "ipv4" : "ipv6", ctx_id++);
	acl_param.name = acl_name;

	tmp_ctx->name = strdup(acl_name);
	if (!tmp_ctx->name) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not allocate name %s for ACL ctx\n",
			acl_name);
		free(tmp_ctx);
		return -ENOMEM;
	}
	if (af == AF_INET)
		acl_param.rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv4_defs));
	else
		acl_param.rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv6_defs));

	tmp_ctx->acl_ctx = rte_acl_create(&acl_param);
	if (tmp_ctx->acl_ctx == NULL) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not allocate ACL context for %s\n",
			(af == AF_INET ? "ipv4" : "ipv6"));
		free(tmp_ctx->name);
		free(tmp_ctx);
		return -ENOMEM;
	}

	tr_sz = (sizeof(struct trans_entry) + rule_size)
		* MAX_TRANSACTION_ENTRIES;
	tmp_ctx->tr = rte_zmalloc("trie_transaction_records", tr_sz,
				  RTE_CACHE_LINE_SIZE);
	if (!tmp_ctx->tr) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not allocate transaction record memory pool for trie %s\n",
			tmp_ctx->name);
		err = -ENOMEM;
		goto error;
	}

	*m_ctx = tmp_ctx;

	return 0;

error:
	if (tmp_ctx->acl_ctx)
		rte_acl_free(tmp_ctx->acl_ctx);

	if (tmp_ctx->name)
		free(tmp_ctx->name);

	if (tmp_ctx)
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

static int npf_rte_acl_record_transaction_entry(npf_match_ctx_t *m_ctx,
						enum rule_op rule_op,
						const struct rte_acl_rule
						*acl_rule, size_t rule_sz)
{
	struct trans_entry *t_entry = NULL;
	uintptr_t ptr;

	if (m_ctx->tr_num_entries >= MAX_TRANSACTION_ENTRIES) {
		RTE_LOG(ERR, DATAPLANE,
			"Number of transaction entries for trie %s exceeded (%u).\n",
			m_ctx->name, MAX_TRANSACTION_ENTRIES);
		return -ENOMEM;
	}

	t_entry = &m_ctx->tr[m_ctx->tr_num_entries++];
	t_entry->rule_op = rule_op;
	t_entry->trie = m_ctx;

	ptr = (uintptr_t) t_entry + sizeof(struct trans_entry);

	t_entry->rule = (struct rte_acl_rule *)ptr;

	memcpy(t_entry->rule, acl_rule, rule_sz);
	return 0;
}

/*
 * convert IPv4 5 tuple and mask to ACL rule
 * The rules are stored in NPF in network byte order.
 * However rte_acl expects the rules to be in host byte order.
 */
static void npf_rte_acl_add_v4_rule(const uint8_t *match_addr, uint8_t *mask,
				    uint32_t rule_no,
				    struct acl4_rules *v4_rules)
{
	uint16_t val, val_mask;

	memset(v4_rules, 0, sizeof(*v4_rules));
	v4_rules->data.category_mask = 1;
	v4_rules->data.priority = rule_no;
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
				    uint32_t rule_no,
				    struct acl6_rules *v6_rules)
{
	uint16_t val, val_mask;
	uint8_t *v6_addr, *v6_mask;

	memset(v6_rules, 0, sizeof(*v6_rules));
	v6_rules->data.category_mask = 1;
	v6_rules->data.priority = rule_no;
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

static int _npf_rte_acl_add_rule(int af, npf_match_ctx_t *m_ctx,
				 const struct rte_acl_rule *acl_rule)
{
	int err;

	err = rte_acl_add_rules(m_ctx->acl_ctx, acl_rule, 1);
	if (err) {
		RTE_LOG(ERR, DATAPLANE, "Could not add rule for af %d : %d\n",
			af, err);
		return err;
	}

	return 0;
}

int npf_rte_acl_add_rule(int af, npf_match_ctx_t *m_ctx, uint32_t rule_no,
			 uint8_t *match_addr, uint8_t *mask,
			 void *match_ctx __rte_unused)
{
	struct acl4_rules v4_rules;
	struct acl6_rules v6_rules;
	const struct rte_acl_rule *acl_rule;
	int err = 0;
	size_t rule_sz;

	if (!m_ctx->tr_in_progress) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not add rule %u for trie %s: no transaction in progress\n",
			rule_no, m_ctx->name);
		return -EINVAL;
	}

	if (af == AF_INET) {
		npf_rte_acl_add_v4_rule(match_addr, mask, rule_no, &v4_rules);
		acl_rule = (const struct rte_acl_rule *)&v4_rules;
		rule_sz = sizeof(struct acl4_rules);
	} else {
		npf_rte_acl_add_v6_rule(match_addr, mask, rule_no, &v6_rules);
		acl_rule = (const struct rte_acl_rule *)&v6_rules;
		rule_sz = sizeof(struct acl6_rules);
	}

	err = npf_rte_acl_record_transaction_entry(m_ctx, RULE_OP_ADD,
						   acl_rule, rule_sz);
	if (err)
		return err;

	err = _npf_rte_acl_add_rule(af, m_ctx, acl_rule);
	if (err < 0)
		return err;

	m_ctx->num_rules++;

	return 0;
}

static int npf_rte_acl_build(int af, npf_match_ctx_t **m_ctx)
{
	struct rte_acl_config cfg = { 0 };
	int err;
	npf_match_ctx_t *ctx = *m_ctx;

	if (!ctx)
		return -EINVAL;

	if (!ctx->num_rules)
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
	err = rte_acl_build(ctx->acl_ctx, &cfg);
	if (err != 0) {
		/* handle error at build runtime structures for ACL context. */
		RTE_LOG(ERR, DATAPLANE,
			"Could not build ACL rules for %s : %s\n",
			(af == AF_INET ? "ipv4" : "ipv6"), strerror(-err));
		return err;
	}

	return 0;
}

static int
_npf_rte_acl_del_rule(int af, struct npf_match_ctx *m_ctx,
			   const struct rte_acl_rule *acl_rule)
{
	int err = 0;

	err = rte_acl_del_rule(m_ctx->acl_ctx, acl_rule);
	if (err && err != -ENOENT) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not remove rule for af %d : %d\n", af, err);
		return err;
	}

	/* Only reduce counter if there was a matching delete */
	if (err != -ENOENT)
		m_ctx->num_rules--;

	return err;
}

int npf_rte_acl_del_rule(int af, npf_match_ctx_t *m_ctx, uint32_t rule_no,
			 uint8_t *match_addr, uint8_t *mask)
{
	struct acl4_rules v4_rules;
	struct acl6_rules v6_rules;
	const struct rte_acl_rule *acl_rule;
	int err = 0;
	size_t rule_sz;


	if (af == AF_INET) {
		npf_rte_acl_add_v4_rule(match_addr, mask, rule_no, &v4_rules);
		acl_rule = (const struct rte_acl_rule *)&v4_rules;
		rule_sz = sizeof(struct acl4_rules);
	} else {
		npf_rte_acl_add_v6_rule(match_addr, mask, rule_no, &v6_rules);
		acl_rule = (const struct rte_acl_rule *)&v6_rules;
		rule_sz = sizeof(struct acl6_rules);
	}

	if (!m_ctx->tr_in_progress) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not delete rule %d from trie %s: no transaction in progress\n",
			rule_no, m_ctx->name);
		return -EINVAL;
	}

	err = npf_rte_acl_record_transaction_entry(m_ctx, RULE_OP_DELETE,
						   acl_rule, rule_sz);
	if (err)
		return err;

	return _npf_rte_acl_del_rule(af, m_ctx, acl_rule);
}

int npf_rte_acl_match(int af, npf_match_ctx_t *m_ctx,
		      npf_cache_t *npc __rte_unused,
		      struct npf_match_cb_data *data,
		      uint32_t *rule_no)
{
	int ret;
	uint32_t results = UINT32_MAX;
	const uint8_t *pkt_data[1];
	struct rte_mbuf *m = data->mbuf;
	uint8_t *nlp;

	if (!m_ctx->num_rules)
		return 0;

	if (af == AF_INET) {
		nlp = (uint8_t *)iphdr(m);
		nlp = RTE_PTR_ADD(nlp, offsetof(struct ip, ip_p));
	} else {
		nlp = (uint8_t *)ip6hdr(m);
		nlp = RTE_PTR_ADD(nlp, offsetof(struct rte_ipv6_hdr, proto));
	}
	pkt_data[0] = nlp;

	ret = rte_acl_classify(m_ctx->acl_ctx, pkt_data, &results, 1, 1);
	if (ret)
		return 0;

	*rule_no = results;
	return 1;
}

int npf_rte_acl_start_transaction(int af __unused, npf_match_ctx_t *m_ctx)
{
	if (m_ctx->tr_in_progress) {
		RTE_LOG(ERR, DATAPLANE,
			"Transaction already in progress for trie %s\n",
			m_ctx->name);
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
			if (_npf_rte_acl_del_rule(af, te->trie, te->rule) < 0)
				rc = -1;
			break;
		case RULE_OP_DELETE:
			if (_npf_rte_acl_add_rule(af, te->trie, te->rule) < 0)
				rc = -1;
			break;
		default:
			RTE_LOG(ERR, DATAPLANE,
				"Unexpected transaction rule operation (%d) for trie %s\n",
				te->rule_op, m_ctx->name);
			rc = -1;
			break;
		}

		if (rc < 0) {
			RTE_LOG(ERR, DATAPLANE,
				"Failed to rollback rule on trie %s\n",
				m_ctx->name);
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
				m_ctx->name);
		}
	}

	m_ctx->tr_num_entries = 0;
	m_ctx->tr_in_progress = false;
	return rc;
}

int npf_rte_acl_destroy(int af __rte_unused, npf_match_ctx_t **m_ctx)
{
	npf_match_ctx_t *ctx = *m_ctx;

	if (ctx) {
		rte_acl_reset(ctx->acl_ctx);
		rte_acl_free(ctx->acl_ctx);
		free(ctx->name);
		rte_free(ctx->tr);
		free(ctx);
		*m_ctx = NULL;
	}

	return 0;
}
