/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <arpa/inet.h>
#include <czmq.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <rte_log.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "compiler.h"
#include "json_writer.h"
#include "npf_shim.h"
#include "urcu.h"
#include "util.h"
#include "vplane_log.h"
#include "npf/dpi/app_cmds.h"
#include "npf/dpi/npf_appdb.h"

static zhash_t *cmd_op_hash;

typedef int (*cmd_handler)(FILE *, int, char **);

struct app_command {
	cmd_handler handler;
	const char *tokens;
};

struct cmd_entry {
	zhash_t *_next;
	cmd_handler _hndlr;
};

/*
 * Common error strings
 */
static const char err_str_unknown[] = "unknown command";
static const char err_str_missing[] = "missing command";

/* Error handler */
static void __attribute__((format(printf, 2, 3)))
cmd_err(FILE *f, const char *format, ...)
{
	char str[100];
	va_list ap;

	va_start(ap, format);
	vsnprintf(str, sizeof(str), format, ap);
	va_end(ap);

#ifdef DEBUG
	printf("%s: %s\n", __func__, str);
#endif

	RTE_LOG(DEBUG, DATAPLANE, "%s\n", str);

	if (f)
		fprintf(f, "%s", str);
}

/*
 * This function reads in the initialized fw_commands data
 * defined in this file to build up a nested hash of hashes
 * n-level tree. Each node in the hash is a unique keyword
 * with an optional function ptr or handler.
 *
 * The intent here is that any user issued command matches
 * against deepest matching node with a command handler.
 */
static void
recurse_cmds(zhash_t *cmds, const struct app_command *f, char *toks)
{
	const char *tok;

	tok = strsep(&toks, " ");

	if (tok) {
		if (!zhash_lookup(cmds, tok)) {
			struct cmd_entry *c_entry = calloc(sizeof(*c_entry), 1);

			c_entry->_next = zhash_new();
			zhash_insert(cmds, tok, c_entry);
		}
		struct cmd_entry *c_entry = zhash_lookup(cmds, tok);

		if (toks == NULL)
			c_entry->_hndlr = f->handler;
		recurse_cmds(c_entry->_next, f, toks);
	}
}

/* Init */
static zhash_t *
cmd_hash_init(struct app_command const cmd_table[], unsigned int num)
{
	unsigned int i;

	zhash_t *cmds = zhash_new();

	for (i = 0; i < num; ++i) {
		char *toks = strdupa(cmd_table[i].tokens);

		recurse_cmds(cmds, &cmd_table[i], toks);
	}

	return cmds;
}

/*
 * Using the hash of hashes tree built by recurse_cmds, this function
 * finds a match with a space tokenized command against the cmd
 * tree and returns the most specific matched handler function ptr.
 */
static cmd_handler
cmd_find(zhash_t *cmds, char **c, int *depth, cmd_handler h)
{
	struct cmd_entry *c_entry;

	c_entry = zhash_lookup(cmds, c[*depth]);
	if (c_entry) {
		if (c_entry->_hndlr)
			h = c_entry->_hndlr;

		if (c[*depth+1] && c_entry->_next != NULL) {
			++(*depth);
			return cmd_find(c_entry->_next, c, depth, h);
		}

		++(*depth);
		return c_entry->_hndlr;
	}
	return h;
}

/* Dumper */
static void cmd_dump(zhash_t *cmds __unused, int depth __unused)
{
#ifdef DEBUG_DUMP_CMDS
	struct cmd_entry *c;

	++depth;

	for (c = zhash_first(cmds);
	     c != NULL;
	     c = zhash_next(cmds)) {
		printf("%*s", depth * 2, "");

		puts(zhash_cursor(cmds));
		if (c->_hndlr)
			printf(": %p", c->_hndlr);
		putc('\n', stdout);
		cmd_dump(c->_next, depth);
	}
#endif /* DEBUG_DUMP_CMDS */
}

/* Error handler */
static void
cmd_error(char const *prefix, int argc, char **argv, int depth)
{
	char cmd[200];
	int i, l = 0;

	/* Re-constitute the original command string */
	argc += depth;
	argv -= depth;

	l += snprintf(cmd+l, sizeof(cmd)-l, "%s ", prefix);
	for (i = 0; i < argc && l < (int)sizeof(cmd); i++) {
		if (i == depth)
			l += snprintf(cmd+l, sizeof(cmd)-l, "/ ");
		l += snprintf(cmd+l, sizeof(cmd)-l, "%s ", argv[i]);
	}
	/* remove trailing space if we didn't fill the buffer */
	if (l > 0 && l < (int)sizeof(cmd))
		cmd[l-1] = '\0';

#ifdef DEBUG
	printf("Cmd failed \"%s\"\n", cmd);
#endif

	RTE_LOG(ERR, DATAPLANE, "Error \"%s\"\n", cmd);
}

/* Command handler */
static int
cmd_handle(FILE *f, int argc, char **argv, zhash_t *cmds)
{
#ifdef DEBUG
	int ii;

	for (ii = 0; ii < argc; ++ii)
		printf("%s ", argv[ii]);
	putc('\n', stdout);
#endif
	if (argc < 2) {
		cmd_err(f, "%s", err_str_missing);
		return -1;
	}

	/* Save and skip the prefix */
	char const *prefix = argv[0];
	--argc, ++argv;

	int depth = 0;

	cmd_dump(cmds, 0);

	cmd_handler h = cmd_find(cmds, argv, &depth, NULL);
	int rc = -1;

	if (h) {
		argc -= depth;
		argv += depth;
		rc = h(f, argc, argv);
	} else
		cmd_err(f, "%s: %s", err_str_unknown, argv[0]);

	if (rc < 0)
		cmd_error(prefix, argc, argv, depth);

	return rc;
}

/* Show the application name hash table. */
static int
cmd_op_show_app_db_byname(FILE *f, int argc __unused, char **argv __unused)
{
	json_writer_t *json = jsonw_new(f);
	if (!json)
		return 1;

	jsonw_pretty(json, true);
	jsonw_name(json, "appdb");
	jsonw_start_object(json);

	appdb_name_walk(json, appdb_name_entry_to_json);

	jsonw_end_object(json);
	jsonw_destroy(&json);

	return 0;
}

/* Show the application ID hash table. */
static int
cmd_op_show_app_db_byid(FILE *f, int argc __unused, char **argv __unused)
{
	json_writer_t *json = jsonw_new(f);
	if (!json)
		return 1;

	jsonw_pretty(json, true);
	jsonw_name(json, "appdb");
	jsonw_start_object(json);

	appdb_id_walk(json, appdb_id_entry_to_json);

	jsonw_end_object(json);
	jsonw_destroy(&json);

	return 0;
}

enum cmd_op {
	OP_SHOW_APP_DB_NAME,
	OP_SHOW_APP_DB_ID,
};

static const struct app_command app_cmd_op[] = {
	[OP_SHOW_APP_DB_NAME] = {
		.tokens = "show app db name",
		.handler = cmd_op_show_app_db_byname,
	},
	[OP_SHOW_APP_DB_ID] = {
		.tokens = "show app db id",
		.handler = cmd_op_show_app_db_byid,
	},
};

/* Initialisation */
static __attribute__((constructor)) void
app_cmd_op_initialize(void)
{
	cmd_op_hash = cmd_hash_init(app_cmd_op,
			ARRAY_SIZE(app_cmd_op));
}

/* Public API */
int
cmd_app_op(FILE *f, int argc, char **argv)
{
	return cmd_handle(f, argc, argv, cmd_op_hash);
}
