/*
 * pl_common.h
 *
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef PL_COMMON_H
#define PL_COMMON_H

#include <stdbool.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <inttypes.h>
#include <stdio.h>

struct rte_mbuf;
struct ifnet;
struct pl_node;
struct json_writer;
struct pl_feature_registration;

#define PL_NODE_INPUT_MAX 16
#define PL_NODE_COLL_MAX 128
#define PL_NODE_STORE_MAX 4

enum pl_mode {
	/*
	 * Regular mode is where the graph is walked node-by-node and
	 * process functions invoked for each. Dynamic-mode features
	 * are invoked in this mode. This mode is roughly 30% slower
	 * than fused-mode.
	 */
	PL_MODE_REGULAR,
	/*
	 * Fused mode with all the same functionality as regular mode,
	 * but the entire graph is turned into one function at build
	 * time and so provides better performance than regular mode.
	 */
	PL_MODE_FUSED,
	/*
	 * Fused mode, but without support for dynamic features. This
	 * provides the best performance and can be used when no
	 * dynamic features are enabled.
	 */
	PL_MODE_FUSED_NO_DYN_FEATS,
};

/* callback for storage removal */
typedef void
(pl_storage_delete) (void *s);

/*
 * These are carry over from existing
 * pipeline functionality but should be
 * refactored out of existence if possible.
 */
enum validation_flags {
	NEEDS_EMPTY     = 0x0,
	NEEDS_SLOWPATH  = 0x1,
};

struct pl_packet {
	struct rte_mbuf      *mbuf;
	void                 *l3_hdr;
	int                   l2_pkt_type;
	enum validation_flags val_flags;
	union {
		struct next_hop *v4;
		struct next_hop_v6 *v6;
	} nxt;
	struct ifnet         *in_ifp;
	struct ifnet         *out_ifp;
	uint32_t              tblid;
	uint16_t              npf_flags;
	uint16_t              l2_proto;
	int                   max_data_used;
	void                 *data[PL_NODE_STORE_MAX];
} __rte_cache_aligned;

enum pl_node_feat_action {
	PL_NODE_FEAT_ADD,
	PL_NODE_FEAT_REM,
};

/* main node processing entry point */
typedef unsigned int
(pl_proc) (struct pl_packet *p);

/* node initialization function */
typedef void
(pl_init_node) (const struct pl_node *);

/* command structure */
struct pl_command {
	/* input */
	int argc;
	char **argv;

	/* output */
	FILE *fp;            /* to be deprecated */
	struct json_writer *json; /* preferred */
};

/* callback for commands */
typedef int
(pl_cmd_proc)(struct pl_command *cmd);

typedef int
(pl_node_feat_change) (struct pl_node *node,
		       struct pl_feature_registration *feat,
		       enum pl_node_feat_action action);

typedef bool
(pl_node_feat_iterate) (struct pl_node *node, bool first,
			unsigned int *feature_id, void **context);

typedef struct pl_node *
(pl_node_lookup_by_name_fn) (const char *name);

/*
 * Types of nodes
 */
enum pl_node_type {
	PL_PROC = 0,
	PL_OUTPUT,
	PL_CONTINUE,
};


/* registration */
struct pl_node_registration {
	const char        *name;
	pl_init_node      *init;
	pl_proc           *handler;
	pl_node_feat_change *feat_change;
	pl_node_feat_iterate *feat_iterate;
	pl_node_lookup_by_name_fn *lookup_by_name;
	enum pl_node_type  type;
	bool               disable;
	uint16_t           num_next;

	/* internal state */
	void              *data;
	int                node_decl_id;
	TAILQ_ENTRY(pl_node_registration) links;
	uint16_t           max_feature_reg_idx;
	struct pl_feature_registration **feature_regs;
	struct pl_node_registration **next_nodes;
	/* end internal state */

	const char        *next[];
};

struct pl_feature_registration {
	const char        *name;
	const char        *feature_point;
	const char        *node_name;
	const char        *visit_before;
	const char        *visit_after;
	uint8_t            id;

	/* internal state */
	bool               dynamic;
	struct pl_node_registration *node;
	struct pl_node_registration *feature_point_node;
	TAILQ_ENTRY(pl_feature_registration) links;
	TAILQ_ENTRY(pl_feature_registration) feature_point_links;
	/* end internal state */
};

/* Node registration */
void
pl_add_node_registration(struct pl_node_registration *node);

#define PL_REGISTER_NODE(x)			          \
	static struct pl_node_registration x;		  \
	static void __pl_add_node_registration_##x(void)  \
		__attribute__((__constructor__));         \
	static void __pl_add_node_registration_##x(void)  \
	{						  \
		pl_add_node_registration(&x);		  \
	}						  \
	static struct pl_node_registration x

void
pl_add_feature_registration(struct pl_feature_registration *feat);

#define PL_REGISTER_FEATURE(x)			          \
	struct pl_feature_registration x;			  \
	static void __pl_add_feature_registration_##x(void)  \
		__attribute__((__constructor__));         \
	static void __pl_add_feature_registration_##x(void)  \
	{						  \
		pl_add_feature_registration(&x);		  \
	}						  \
	struct pl_feature_registration x

#define PL_DECLARE_FEATURE(x)			          \
	extern struct pl_feature_registration x


struct pl_node_storage {
	uint8_t            id;
	bool               disable;
	pl_storage_delete *release;
};

#define PL_STORAGE_ID(x) ((x).id)

void
pl_register_storage(struct pl_node_storage *storage);

#define PL_REGISTER_STORAGE(x)						 \
	struct pl_node_storage x;					 \
	static void __pl_add_node_storage_##x(void)                      \
				  __attribute__((__constructor__));      \
	static void __pl_add_node_storage_##x(void)                      \
	{                                                                \
		pl_register_storage(&x);                                 \
	}                                                                \
	struct pl_node_storage x

/*
 *  operational commands
 */
struct pl_node_command {
	uint32_t version;
	const char  *cmd;
	pl_cmd_proc *handler;
};

void
pl_add_node_command(struct pl_node_command *cmd);

void
pl_add_node_op_command(struct pl_node_command *cmd);


#define PL_REGISTER_OPCMD(x, ...)                                 \
	__VA_ARGS__ struct pl_node_command x;                     \
	static void __pl_add_node_command_##x(void)               \
		__attribute__((__constructor__));                 \
	static void __pl_add_node_command_##x(void)               \
	{ pl_add_node_command(&x); }				  \
	__VA_ARGS__ struct pl_node_command x

/*
 * Use pl_cmd_err instead of fprintf(cmd->fp, "").  cmd->fp may be NULL if a
 * command is deferred and then replayed, for example after an interface
 * event.
 */
void pl_cmd_err(struct pl_command *cmd, const char *fmt, ...);

#endif /* PL_COMMON_H */
