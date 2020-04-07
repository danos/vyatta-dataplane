/*
 * pl_common.h
 *
 * Copyright (c) 2017,2019-2020, AT&T Intellectual Property.  All rights reserved.
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
#include "urcu.h"

#include "pipeline.h"

struct rte_mbuf;
struct ifnet;
struct pl_node;
struct json_writer;
struct pl_feature_registration;
struct pl_node_registration;

#define PL_NODE_INPUT_MAX 16
#define PL_NODE_COLL_MAX 128

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


enum pl_node_feat_action {
	PL_NODE_FEAT_ADD,
	PL_NODE_FEAT_REM,
};

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

typedef int
(pl_node_feat_change_all) (struct pl_feature_registration *feat,
			    enum pl_node_feat_action action);

typedef int
(pl_node_feat_type_insert) (struct pl_node_registration *node,
			    struct pl_feature_registration *feat,
			    uint32_t type);

typedef int
(pl_node_feat_type_remove) (struct pl_node_registration *node,
			    struct pl_feature_registration *feat,
			    uint32_t type);

typedef int
(pl_node_feat_type_find) (uint32_t type);

typedef bool
(pl_node_feat_iterate) (struct pl_node *node, bool first,
			unsigned int *feature_id, void **context,
			void **storage_context);

typedef struct pl_node *
(pl_node_lookup_by_name_fn) (const char *name);

typedef int
(pl_node_register_context) (struct pl_node *node,
			    struct pl_feature_registration *feat,
			    void *context);

typedef int
(pl_node_unregister_context) (struct pl_node *node,
			      struct pl_feature_registration *feat);

typedef void *
(pl_node_get_context) (struct pl_node *node,
		       struct pl_feature_registration *feat);

typedef int
(pl_node_setup_cleanup_cb) (struct pl_feature_registration *feat);

typedef void *
(pl_node_get_context) (struct pl_node *node,
		       struct pl_feature_registration *feat);

/* registration */
struct pl_node_registration {
	const char        *name;
	pl_proc           *handler;
	pl_node_feat_change *feat_change;
	pl_node_feat_change_all *feat_change_all;
	pl_node_feat_iterate *feat_iterate;
	pl_node_lookup_by_name_fn *lookup_by_name;
	pl_node_feat_type_insert *feat_type_insert;
	pl_node_feat_type_remove *feat_type_remove;
	pl_node_feat_type_find *feat_type_find;
	pl_node_register_context *feat_reg_context;
	pl_node_unregister_context *feat_unreg_context;
	pl_node_get_context *feat_get_context;
	pl_node_setup_cleanup_cb *feat_setup_cleanup_cb;
	enum pl_node_type  type;
	uint16_t           num_next;

	/* internal state */
	struct cds_lfht   *pl_feat_node_ht;
	int                node_decl_id;
	int                feature_point_id;
	TAILQ_ENTRY(pl_node_registration) links;
	uint16_t           max_feature_reg_idx;
	struct pl_feature_registration **feature_regs;
	struct pl_node_registration **next_nodes;
	/* end internal state */

	const char        *next[];
};

enum pl_feat_type {
	PL_FEAT_LIST,
	PL_FEAT_CASE,
};

struct pl_feature_registration {
	const char        *plugin_name;
	const char        *name;
	const char        *feature_point;
	const char        *node_name;
	const char        *visit_before;
	const char        *visit_after;
	bool              always_on;
	uint8_t            id;
	uint32_t          feat_type;
	enum pl_feat_type feature_type;

	/* internal state */
	bool               dynamic;
	struct cds_lfht_node feat_node;
	struct rcu_head      feat_rcu;
	struct pl_node_registration *node;
	struct pl_node_registration *feature_point_node;
	TAILQ_ENTRY(pl_feature_registration) links;
	TAILQ_ENTRY(pl_feature_registration) feature_point_links;
	dp_pipeline_inst_cleanup_cb *cleanup_cb;
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

int pl_get_max_node_count(void);

#endif /* PL_COMMON_H */
