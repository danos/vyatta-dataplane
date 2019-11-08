/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <rte_branch_prediction.h>
#include <rte_log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <util.h>

#include "npf/grouper2.h"
#include "npf/npf_ruleset.h"
#include "vplane_log.h"

/*
 * The goal of this module is to provide a quick match of the basic
 * address/port addresses against an arbritrary sized ruleset with near
 * constant time performance.  Since this match cannot fully represent all of
 * the available matching options available in the current product the
 * expected behavior is to drop out of the matching 13 tuple (for ipv4), and
 * then proceed to the NPF processor to complete the remaining matching.
 *
 * Data structures maintained here are only written to during a configuration
 * event. After the configuration event has completed, tables used during
 * processing are read-only.
 *
 * Modeled on the following paper:
 * "Grouper: A Packet Classification Algorithm Allowing Time-Space Tradeoffs"
 * Modeled on the paper: http://www.cse.usf.edu/~ligatti/papers/grouper-conf.pdf
 *
 * This is designed to fit in the Vyatta NPF-derived ecosystem (and was written
 * from scratch--with no source borrowed from the open sourced grouper project,
 * hence grouper2).
 *
 */

/*
 * todo items (impvmts to memory, perf, extensibility):
 *
 * 1.  possible 2 byte comparison on smaller rulesets
 * 2.  extend matching to support additional types?
 * 3.  support dynamic updates
 * 4.  single global table per table name (reduce footprint)
 * 5.  support arbritrary rule number insertion
 *
 * The following conditions are not supported by the grouper, and result in a
 * "match all" for the relevant tables:
 *
 * 1. More than one source or destination address is specified by an
 *    individual rule (i.e. subrule).  This includes:
 *
 *    a. Address negation, i.e. match all addresses except the one specified
 *    b. Address groups
 *
 * 2. More than one source or destination port is specified by an individual
 *    rule (i.e. subrule).  This includes:
 *
 *    a. Port ranges (but only when the range specifies more than one port)
 */


/* rule set size steps */
static const uint32_t g_size_alloc[] = {
	64,
	256,
	1024,
	4096,
	8192,
	16384 /* max size means roughly 200mbytes per ruleset applied */
};
#define MAX_RULESET_IDX		5
#define MAX_RULESET_SIZE	g_size_alloc[MAX_RULESET_IDX]

#define STRIDE_BITS		64
#define BYTES_PER_TABLE		1
#define PATTERN_PER_TABLE	(1u << (BYTES_PER_TABLE * 8))


#define  RULE_MATCH(x) {						\
		rule_match &= conf->_match_table[x][packet[x]][j];      \
		if (!rule_match)					\
			continue;					\
	}



typedef bool (*g2_fp_eval_rule)(const uint8_t *, uint32_t, const void *);

/*
 * Grouper config
 *
 * The _mask field is allocated as a _num_tables byte array.  During grouper
 * rule insertion, we use this to maintain a cumulative mask for each table.
 * Once all rules have been added, a 0xFF value for any byte in _mask means
 * that that the grouper is a "match all" for that table.  When this occurs,
 * we replace this table with the _match_all table, thus saving memory.
 *
 * Further, if *all* bytes of _mask are "match all", then there is no
 * need to run the grouper at all, so remove it.
 */
struct g2_config {
	/* overall number of tables used for the match */
	unsigned int _num_tables;

	/* number of rules inserted */
	unsigned int _num_rules;

	/* number of 64 bit comparison is performed, i.e. rules / 64 */
	unsigned int _num_chunks;

	/* rule set size index */
	unsigned int _rs_size_idx;

	/* rule no index */
	rule_no_t *_rule_no;

	/* datum returned on a match */
	void **_md;

	/* Cumulative per-table mask */
	uint8_t *_mask;

	/* Shared "match all" table */
	uint64_t **_match_all;

	/* match table -- MUST be last */
	uint64_t **_match_table[];
};

/*
 * Allocate or reallocate match_table
 *
 * Each match table is allocated in a single chunk, laid out as follows:
 *
 *     Pointer array                   Bit patterns
 *  /                 \ /   0         1                  255   \
 *  +------------------+----------------------------------------+
 *  |   |   |      |   |         |         |          |         |
 *  |   |   |      |   |---------+---------+----------+---------|
 *  |   |   |      |   |    |    |    |    |     |    |         |
 *  +------------------+----------------------------------------+
 *    0   1         255           \       /
 *                               64-bit words
 *                               in bit pattern
 *
 *  The pointer array is set to point to the relevant bit pattern.
 *
 * _match_table[0]        - Points to the first match table
 * _match_table[0][0]     - Pointer to first bit pattern in first table
 * _match_table[0][0][0]  - First 64-bit chunk in first bit pattern
 *
 * A table starts of with one 64-bit word per bit pattern.  When the 65th rule
 * is added, this is increased to four 64-bit words per bit pattern etc.
 */
static bool
g2_alloc_match_table(g2_config_t *conf, uint table)
{
	size_t array_bytes, bitp_bytes_tot;
	uint bitp_bytes;
	uint8_t *old_table;
	uint8_t *new_table;
	uint j;

	/* Bytes for pointer array */
	array_bytes = PATTERN_PER_TABLE * sizeof(uint64_t *);

	/* Bytes for 1 bit pattern */
	bitp_bytes = g_size_alloc[conf->_rs_size_idx] / NBITS(uint8_t);

	/* bytes for all bit patterns */
	bitp_bytes_tot = bitp_bytes * PATTERN_PER_TABLE;

	old_table = (uint8_t *)conf->_match_table[table];
	new_table = malloc_aligned(array_bytes + bitp_bytes_tot);

	if (!new_table)
		return false;

	/* Zero bit patterns */
	memset(new_table + array_bytes, 0, bitp_bytes_tot);

	conf->_match_table[table] = (uint64_t **)new_table;

	/*
	 * Set array elements to point into bit patterns.
	 *
	 * First bit pattern is at "new_table + array_bytes".
	 * jth bit pattern offset is "j * bitp_bytes".
	 */
	for (j = 0; j < PATTERN_PER_TABLE; j++)
		conf->_match_table[table][j] =
			(uint64_t *)(new_table + array_bytes +
				     (j * bitp_bytes));

	/*
	 * If there is an old table, then copy bitmaps from it to the new table.
	 * This will only occur when we have increased the bit pattern size.
	 */
	if (old_table && conf->_rs_size_idx > 0) {
		uint old_bitp_bytes =
			g_size_alloc[conf->_rs_size_idx-1] / NBITS(uint8_t);

		for (j = 0; j < PATTERN_PER_TABLE; ++j) {
			memcpy(new_table + array_bytes + (j * bitp_bytes),
			       old_table + array_bytes + (j * old_bitp_bytes),
			       old_bitp_bytes);
		}
		free(old_table);
	}
	return true;
}


/*
 * Grouper initialization.
 *
 * num_tables is the number of tables required for the grouper.  _match_table
 * pointer array is contiguous to the conf structure. For example, for 12
 * match tables we have:
 *
 *        conf                        _match_table[]
 *  /                 \ /                                      \
 *  +------------------+----------------------------------------+
 *  |  g2_config_t     |    |    |                         |    |
 *  +------------------+----------------------------------------+
 *                       0    1                              11
 */
g2_config_t *g2_init(uint num_tables)
{
	unsigned int i;
	g2_config_t *conf;

	if (num_tables < 1)
		return NULL;

	/*
	 * Alloc conf structure and table pointer array
	 */
	conf = zmalloc_aligned(sizeof(g2_config_t) +
			       num_tables * sizeof(uint64_t *));
	if (!conf)
		goto error;

	conf->_num_rules = 0;
	conf->_num_tables = num_tables;
	conf->_rs_size_idx = 0;

	for (i = 0; i < num_tables; ++i) {
		if (!g2_alloc_match_table(conf, i))
			goto error;
	}

	/* Cumulative mask starts of as "dont care" / "match all" */
	conf->_mask = malloc(num_tables);
	if (!conf->_mask)
		goto error;

	memset(conf->_mask, 0xFF, num_tables);

	return conf;

error:
	RTE_LOG(ERR, FIREWALL, "Error in grouper allocation\n");
	g2_destroy(&conf);
	return NULL;
}

/*
 * Reallocate memory for each bit pattern for each table
 */
static bool
g2_realloc_bit_pattern(g2_config_t *conf)
{
	uint i;

	for (i = 0; i < conf->_num_tables; ++i)
		if (!g2_alloc_match_table(conf, i))
			return false;
	return true;
}

/*
 * Clear a specific rule bit in each bit pattern in each table
 */
static void
g2_clear_rule_bit(g2_config_t *conf, uint rule_index)
{
	uint i, j;
	uint word = rule_index / NBITS(uint64_t);
	uint shift =  rule_index % NBITS(uint64_t);
	uint64_t mask = ~(1ul << shift);

	for (i = 0; i < conf->_num_tables; ++i)
		for (j = 0; j < PATTERN_PER_TABLE; ++j)
			conf->_match_table[i][j][word] &= mask;
}

/*
 * Set the bit for every rule in a table
 */
static void
g2_set_all_bits(const g2_config_t *conf, uint64_t **table)
{
	if (conf->_num_rules == 0)
		return;

	uint nwords = conf->_num_rules / STRIDE_BITS;
	uint rbits = conf->_num_rules % STRIDE_BITS;
	uint j;

	for (j = 0; j < PATTERN_PER_TABLE; ++j) {
		uint word;

		/* Set complete words */
		for (word = 0; word < nwords; word++)
			table[j][word] = 0xFFFFFFFFFFFFFFFFull;

		/* Set remaining incomplete word */
		table[j][word] |= (1ul << rbits) - 1;
	}
}

/*
 * Create a new grouper rule.  Returns true if successful.
 *
 * match_data is the data to be passed to the callback function in the event
 * of a match.  Rules are inserted in order they are evaluated.
 */
bool
g2_create_rule(g2_config_t *conf, rule_no_t rule_no, void *match_data)
{
	uint i;

	if (!conf)
		return false;

	/*
	 * Check for duplicates first.
	 *
	 * This check below was added to suppress multiple rules since we are
	 * now counting table references. multiple entries are being inserted
	 * into the table due to callback from netlink messages on commit--the
	 * source of the bug. this needs to be fixed.
	 */
	for (i = 0; i < conf->_num_rules; ++i) {
		if (rule_no == conf->_rule_no[i])
			return false; /* already inserted */
	}

	/*
	 * Have we exceeded the allocated space for this new rule?
	 */
	if (conf->_num_rules >= g_size_alloc[conf->_rs_size_idx]) {
		if (conf->_rs_size_idx >= MAX_RULESET_IDX)
			return false;

		/*
		 * bump up to next size step, and realloc bit map
		 */
		conf->_rs_size_idx++;

		if (!g2_realloc_bit_pattern(conf)) {
			RTE_LOG(ERR, FIREWALL,
				"grouper rule bit pattern "
				"reallocation failed\n");
			return false;
		}
	}

	/*
	 * Add new entry to tail of _rule_no array
	 */
	conf->_rule_no = realloc(conf->_rule_no,
				(conf->_num_rules + 1) * sizeof(rule_no_t));
	if (!conf->_rule_no) {
		RTE_LOG(ERR, FIREWALL, "grouper rule reallocation failed\n");
		return false;
	}

	uint rule_index = conf->_num_rules;

	/* Set rule number */
	conf->_rule_no[rule_index] = rule_no;

	/*
	 * We maintain a count of the number of 64 (stride) bit chunks
	 * (_num_chunks)
	 */
	conf->_num_chunks = 1 + rule_index / STRIDE_BITS;

	/*
	 * Zero the new bit in each bit pattern in each table
	 */
	g2_clear_rule_bit(conf, rule_index);

	/*
	 * Realloc the match data pointer array, and add the match data for
	 * the new rule
	 */
	conf->_md = realloc(conf->_md, (conf->_num_rules + 1) * sizeof(void *));
	if (!conf->_md) {
		RTE_LOG(ERR, FIREWALL,
			"grouper rule match data reallocation failed\n");
		return false;
	}

	conf->_md[rule_index] = match_data;

	/* Only increment _num_rules if all reallocs' succeeded */
	conf->_num_rules++;

	return true;
}

/*
 * Grouper mask/match evaluation
 *
 * conf:    ptr to conf structure returned via g2_init()
 * table:   Table number to start evaluation
 * ntables: Number of tables to evaluate
 * func:    ptr to function to evaluate matches
 * arg:     ptr to pass to func
 *
 * Takes in the rule bit array and run a comparison against all bit patterns
 * then update the tables accordingly.
 *
 * Stores each rule as a bit column of matches (00-FF) across the equivalent
 * number of tables.
 */
static bool
g2_add_eval(g2_config_t *conf, uint table, uint ntables,
	    g2_fp_eval_rule func, const void *arg)
{
	if (table + ntables > conf->_num_tables)
		return false;

	/* Rule number was the last one added */
	uint rule_index = conf->_num_rules - 1;

	uint word = rule_index / NBITS(uint64_t);
	uint shift =  rule_index % NBITS(uint64_t);
	uint64_t bit = 1ul << shift;
	unsigned int i;

	/*
	 * Conditionally set the new bit for each matching bit pattern in each
	 * table
	 */
	for (i = table; i < table + ntables; ++i) {
		uint j;

		for (j = 0; j < PATTERN_PER_TABLE; ++j) {
			bool match_flag;
			uint k;

			match_flag = true;
			for (k = 0; k < BYTES_PER_TABLE; ++k) {
				const uint8_t j2 = *((uint8_t *)&j + k);

				/*
				 * The mask/match bytes may have started at a
				 * table other than 0, so subtract the start
				 * table.
				 */
				if (func(&j2, i - table, arg)) {
					match_flag = false;
					break;
				}
			}
			if (match_flag)
				conf->_match_table[i][j][word] |= bit;
		}
	}
	return true;
}

struct match_mask {
	const uint8_t *_match;
	const uint8_t *_mask;
};

/*
 *  Currently fixed to one byte table size. Else need equivalent
 * of this:
 *	uint8_t mask2 = *(mask + BYTES_PER_TABLE * i + k);
 *	uint8_t match2 = *(match + BYTES_PER_TABLE * i + k);
 */
static bool
match_mask_eval(const uint8_t *val, uint32_t seg, const void *arg)
{
	const struct match_mask *mm = (const struct match_mask *)arg;
	uint8_t match = mm->_match[seg];
	uint8_t mask  = mm->_mask[seg];
	/*
	 * MASK == 1 MEANS DON'T CARE
	 * means xor the number and match, then mask out anything we don't
	 * care about
	 */
	return ((match ^ *val) & ~mask);
}

/*
 * Initialize one or more grouper tables from a match/mask pattern.
 */
bool
g2_add(g2_config_t *conf, uint table, uint ntables,
	const uint8_t *match, const uint8_t *mask)
{
	uint i;

	if (!match)
		return false;

	if (!mask)
		return false;

	const struct match_mask mm = {
		._match = match,
		._mask = mask,
	};

	/*
	 * Cumulative mask.  Remember which bits are "dont care" for all rules
	 * in the ruleset.
	 */
	for (i = 0; i <  ntables; i++)
		conf->_mask[i + table] &= mask[i];

	return g2_add_eval(conf, table, ntables, match_mask_eval, &mm);
}

/*
 * Optimize the grouper after all rules have been evaluated.
 */
void
g2_optimize(g2_config_t **confp)
{
	if (!confp || !*confp)
		return;

	uint j;
	g2_config_t *conf = *confp;

	if (!conf->_mask)
		return;

	/*
	 * Memory optimization for "match all" tables.
	 *
	 * _mask is the cumulative mask for all rules in the ruleset.  Any
	 * table with a cumulative mask of 0xFF means none of the rules in
	 * this ruleset care what value this byte of the packet is, and there
	 * can be replaced with the _match_all table.
	 */
	for (j = 0; j < conf->_num_tables; j++) {
		if (conf->_mask[j] != 0xFF)
			continue;

		if (conf->_match_all == NULL) {
			/*
			 * The _match_all table does not exist yet.  Simply
			 * reuse this table as the _match_all table
			 */
			conf->_match_all = conf->_match_table[j];

			/* Set bit for every rule in all bit patterns */
			g2_set_all_bits(conf, conf->_match_all);
		} else {
			/*
			 * The _match_all table aready exists.	Replace the
			 * table with the match_all table.
			 */
			if (conf->_match_table[j] != conf->_match_all) {
				free(conf->_match_table[j]);
				conf->_match_table[j] = conf->_match_all;
			}
		}
	}
}

/*
 * g2_eval4()
 * conf:     ptr to configuration structure
 * packet:   n byte packet to compare
 *
 * returns:  first rule matched.
 */
inline
void *g2_eval4(const g2_config_t *conf, const uint8_t *packet,
	       const void *data)
{
	uint32_t j;

	/*
	 * for each chunk of rules, i.e. 64 at a time
	 */
	for (j = 0; j < conf->_num_chunks; ++j) {
		uint64_t rule_match = UINT64_MAX;

		/* For each table */
		RULE_MATCH(0);
		RULE_MATCH(1);
		RULE_MATCH(2);
		RULE_MATCH(3);
		RULE_MATCH(4);
		RULE_MATCH(5);
		RULE_MATCH(6);
		RULE_MATCH(7);
		RULE_MATCH(8);
		RULE_MATCH(9);
		RULE_MATCH(10);
		RULE_MATCH(11);
		RULE_MATCH(12);

		/* iterate over all possible matches in 64 rules */

		while (rule_match) {
			uint32_t loc;
			uint32_t idx_match;

			/* find next match in chunk */
			loc = ffsl(rule_match);
			idx_match = loc + (j * STRIDE_BITS);

			if (unlikely(idx_match > conf->_num_rules))
				return NULL;

			void *r = conf->_md[idx_match - 1];

			/* Process the bytecode to verify the match */
			if (npf_rule_proc(data, r))
				return r;

			/* exclusive OR w/ loc to allow further search */
			rule_match ^= (1ull << (loc - 1ull));
		}
	}
	/* 0 is no match */
	return NULL;
}

void *g2_eval6(const g2_config_t *conf, const uint8_t *packet,
	       const void *data)
{
	uint32_t j;

	/*
	 * for each chunk of rules, i.e. 64 at a time
	 */
	for (j = 0; j < conf->_num_chunks; ++j) {
		uint64_t rule_match = UINT64_MAX;

		/* For each table */
		RULE_MATCH(0);
		RULE_MATCH(1);
		RULE_MATCH(2);
		RULE_MATCH(3);
		RULE_MATCH(4);
		RULE_MATCH(5);
		RULE_MATCH(6);
		RULE_MATCH(7);
		RULE_MATCH(8);
		RULE_MATCH(9);
		RULE_MATCH(10);
		RULE_MATCH(11);
		RULE_MATCH(12);
		RULE_MATCH(13);
		RULE_MATCH(14);
		RULE_MATCH(15);
		RULE_MATCH(16);
		RULE_MATCH(17);
		RULE_MATCH(18);
		RULE_MATCH(19);
		RULE_MATCH(20);
		RULE_MATCH(21);
		RULE_MATCH(22);
		RULE_MATCH(23);
		RULE_MATCH(24);
		RULE_MATCH(25);
		RULE_MATCH(26);
		RULE_MATCH(27);
		RULE_MATCH(28);
		RULE_MATCH(29);
		RULE_MATCH(30);
		RULE_MATCH(31);
		RULE_MATCH(32);
		RULE_MATCH(33);
		RULE_MATCH(34);
		RULE_MATCH(35);
		RULE_MATCH(36);

		/* iterate over all possible matches in 64 rules */

		while (rule_match) {
			uint32_t loc;
			uint32_t idx_match;

			/* find next match in chunk */
			loc = ffsl(rule_match);
			idx_match = loc + (j * STRIDE_BITS);

			if (unlikely(idx_match > conf->_num_rules))
				return NULL;

			void *r = conf->_md[idx_match - 1];

			/* Process the bytecode to verify the match */
			if (npf_rule_proc(data, r))
				return r;

			/* exclusive OR w/ loc to allow further search */
			rule_match ^= (1ull << (loc - 1ull));
		}
	}
	/* 0 is no match */
	return NULL;
}

/*
 * g2_destroy()
 * conf: ptr to conf structure.
 *
 * Release memory on match_table
 *
 */
void
g2_destroy(g2_config_t **confp)
{
	unsigned int i;
	g2_config_t *conf;

	if (!confp || !*confp)
		return;

	conf = *confp;

	for (i = 0; i < conf->_num_tables; ++i) {
		if (!conf->_match_table[i])
			continue;

		if (conf->_match_table[i] != conf->_match_all)
			free(conf->_match_table[i]);
	}

	free(conf->_rule_no);
	free(conf->_md);
	free(conf->_mask);
	free(conf->_match_all);
	free(conf);
	*confp = NULL;
}
