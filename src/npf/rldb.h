/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef NPF_RULE_DB_H

#define NPF_RULE_DB_H

#include <rte_mbuf.h>
#include <stdint.h>
#include <json_writer.h>

#define RLDB_NAME_MAX 64

enum rldb_l3_field {
	RLDB_L3F_SRC	= 1,
	RLDB_L3F_DST,
	RLDB_L3F_PROTO,
	RLDB_L3F__LEN
};

struct rldb_v4_prefix {
	uint8_t		npfrl_plen;
	uint8_t		npfrl_bytes[4];
};

struct rldb_v6_prefix {
	uint8_t		npfrl_plen;
	uint8_t		npfrl_bytes[16];
};

struct rldb_proto {
	uint8_t		npfrl_proto;
	uint8_t		npfrl_unknown : 1;
};

struct rldb_l4port_range {
	uint16_t	npfrl_loport;
	uint16_t	npfrl_hiport;
};

enum rldb_npfrl_flags {
	NPFRL_FLAG_V4_PFX         = 0x00000001,
	NPFRL_FLAG_V6_PFX         = 0x00000002,
	NPFRL_FLAG_SRC_PFX        = 0x00000004,
	NPFRL_FLAG_DST_PFX        = 0x00000008,
	NPFRL_FLAG_PROTO          = 0x00000010,
	NPFRL_FLAG_SRC_PORT_RANGE = 0x00000020,
	NPFRL_FLAG_DST_PORT_RANGE = 0x00000040,
};

union rldb_pfx {
	struct rldb_v4_prefix v4_pfx;
	struct rldb_v6_prefix v6_pfx;
};

struct rldb_rule_spec {
	uintptr_t                rldb_user_data;
	uint32_t                 rldb_priority;
	uint32_t                 rldb_flags;     /* NPFRL_FLAG_* */
	union rldb_pfx           rldb_src_addr;
	union rldb_pfx           rldb_dst_addr;
	struct rldb_proto        rldb_proto;
	struct rldb_l4port_range rldb_src_port_range;
	struct rldb_l4port_range rldb_dst_port_range;
};

struct rldb_result {
	uint32_t rldb_rule_no;
	uintptr_t rldb_user_data;
};

struct rldb_stats {
	uint64_t rldb_rules_added;
	uint64_t rldb_rules_deleted;
	uint64_t rldb_rule_cnt;
	uint64_t rldb_transaction_cnt;
	struct err_cntrs {
		uint64_t rule_add_failed;
		uint64_t rule_del_failed;
		uint64_t rule_match_failed;
		uint64_t transaction_failed;
	} rldb_err;
};

struct rldb_db_handle;
struct rldb_rule_handle;

/*
 * initialize infrastructure for rule database
 */
int rldb_init(void);

/*
 * create rule database of specified name
 */
int rldb_create(const char *name, uint32_t flags, struct rldb_db_handle **db);

/*
 * start a sequence of operations
 */
int rldb_start_transaction(struct rldb_db_handle *db);

/*
 * commit a sequence of operations
 */
int rldb_commit_transaction(struct rldb_db_handle *db);

/*
 * add rule to the specified database
 */
int rldb_add_rule(struct rldb_db_handle *db, uint32_t rule_no,
		  struct rldb_rule_spec const *in_spec,
		  struct rldb_rule_handle **out_rh);

/*
 * delete a rule from the specified database
 */
int rldb_del_rule(struct rldb_db_handle *db, struct rldb_rule_handle *rh);

/*
 * find rules by rule number
 */
int rldb_find_rule(struct rldb_db_handle *db, uint32_t rule_no,
		   struct rldb_rule_handle **out_rh);

/*
 * match packets against rules in the specified database
 */
int rldb_match(struct rldb_db_handle *db, struct rte_mbuf *m[],
	       uint32_t num_packets, struct rldb_result *result);

/*
 * get statistics at database level
 */
int rldb_get_stats(struct rldb_db_handle *db, struct rldb_stats *stats);

/*
 * clear statistics at database level
 */
int rldb_clear_stats(struct rldb_db_handle *db);

/*
 * callback prototype for walker
 */
typedef int (*rldb_walker_t)(const struct rldb_rule_handle *rh, void *userdata);

/*
 * walk rule database
 */
void rldb_walk(struct rldb_db_handle *db, rldb_walker_t walker, void *userdata);

/*
 * dump rule database in json form
 */
void rldb_dump(struct rldb_db_handle *db, json_writer_t *wr);

/*
 * destroy specified rule database
 */
int rldb_destroy(struct rldb_db_handle *db);

/*
 * clean up infrastructure set up for rule database
 */
int rldb_cleanup(void);

#endif /* RLDB_H */
