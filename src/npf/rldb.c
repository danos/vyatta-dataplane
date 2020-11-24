/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "rldb.h"

/*
 * initialize infrastructure for rule database
 */
int rldb_init(void)
{
	return 0;
}

/*
 * create rule database of specified name
 */
int rldb_create(const char *name __rte_unused, uint32_t flags __rte_unused,
		struct rldb_db_handle **db __rte_unused)
{
	return 0;
}

/*
 * start a sequence of operations
 */
int rldb_start_transaction(struct rldb_db_handle *db __rte_unused)
{
	return 0;
}

/*
 * commit a sequence of operations
 */
int rldb_commit_transaction(struct rldb_db_handle *db __rte_unused)
{
	return 0;
}

/*
 * add rule to the specified database
 */
int rldb_add_rule(struct rldb_db_handle *db __rte_unused,
		  uint32_t rule_no __rte_unused,
		  struct rldb_rule_spec const *in_spec __rte_unused,
		  struct rldb_rule_handle **out_rule __rte_unused)
{
	return 0;
}

/*
 * delete rule from the specified database
 */
int rldb_del_rule(struct rldb_db_handle *db __rte_unused,
		  struct rldb_rule_handle *rule __rte_unused)
{
	return 0;
}

/*
 * find rule by rule number
 */
int rldb_find_rule(struct rldb_db_handle *db __rte_unused,
		   uint32_t rule_no __rte_unused,
		   struct rldb_rule_handle **out_rule __rte_unused)
{
	return 0;
}

/*
 * match packets against rules in the specified database
 */
int rldb_match(struct rldb_db_handle *db __rte_unused,
	       /* array of packets to be matched */
	       struct rte_mbuf *m[] __rte_unused,
	       /* number of packets */
	       uint32_t num_packets __rte_unused,
	       struct rldb_result *results __rte_unused)
{
	return 0;
}

/*
 * get statistics at database level
 */
int rldb_get_stats(struct rldb_db_handle *db __rte_unused,
		   struct rldb_stats *stats __rte_unused)
{
	return 0;
}

/*
 * clear statistics at database level
 */
int rldb_clear_stats(struct rldb_db_handle *db __rte_unused)
{
	return 0;
}

/*
 * walk rule database
 */
void rldb_walk(struct rldb_db_handle *db __rte_unused,
	       rldb_walker_t walker __rte_unused, void *userdata __rte_unused)
{

}

/*
 * dump rule database in json form
 */
void rldb_dump(struct rldb_db_handle *db __rte_unused,
	       json_writer_t *wr __rte_unused)
{

}

/*
 * destroy specified rule database
 */
int rldb_destroy(struct rldb_db_handle *db __rte_unused)
{
	return 0;
}

/*
 * clean up infrastructure set up for rule database
 */
int rldb_cleanup(void)
{
	return 0;
}
