/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Common support for NPF commands (Firewall/NAT/PBR)
 */

#include <errno.h>
#include <rte_log.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compiler.h"
#include "npf/config/npf_attach_point.h"
#include "npf/npf_cmd.h"
#include "vplane_log.h"

struct cmd_entry {
	zhash_t *_next;
	npf_cmd_handler _hndlr;
};

/*
 * Common error strings
 */
const char npf_cmd_str_unknown[] = "unknown command";
const char npf_cmd_str_missing[] = "missing command";
const char npf_cmd_str_missing_arg[] = "missing argument";
const char npf_cmd_str_too_many_chars[] = "too many characters";

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
recurse_cmds(zhash_t *cmds, const struct npf_command *f, char *toks)
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

zhash_t *npf_cmd_hash_init(struct npf_command const cmd_table[],
			   unsigned int num)
{
	unsigned int i;

	zhash_t *npf_cmds = zhash_new();

	for (i = 0; i < num; ++i) {
		char *toks = strdupa(cmd_table[i].tokens);
		recurse_cmds(npf_cmds, &cmd_table[i], toks);
	}

	return npf_cmds;
}

/*
 * Using the hash of hashes tree built by recurse_cmds, this function
 * finds a match with a space tokenized command against the cmd
 * tree and returns the most specific matched handler function ptr.
 */
npf_cmd_handler
npf_cmd_find(zhash_t *cmds, char **c, int *depth, npf_cmd_handler h)
{
	struct cmd_entry *c_entry;

	c_entry = zhash_lookup(cmds, c[*depth]);
	if (c_entry) {
		if (c_entry->_hndlr)
			h = c_entry->_hndlr;

		if (c[*depth+1] && c_entry->_next != NULL) {
			++(*depth);
			return npf_cmd_find(c_entry->_next, c, depth, h);
		}

		++(*depth);
		return c_entry->_hndlr;
	}
	return h;
}

/*
 * Args are maked as unused for when this is compiled out.
 */
void
npf_cmd_dump(zhash_t *cmds __unused, int depth __unused)
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
		npf_cmd_dump(c->_next, depth);
	}
#endif /* DEBUG_DUMP_CMDS */
}

void __attribute__((format(printf, 2, 3)))
npf_cmd_err(FILE *f, const char *format, ...)
{
	char str[100];
	va_list ap;

	va_start(ap, format);
	vsnprintf(str, sizeof(str), format, ap);
	va_end(ap);

#ifdef DEBUG
	printf("npf_cmd_err: %s\n", str);
#endif

	RTE_LOG(DEBUG, DATAPLANE, "%s\n", str);

	if (f)
		fprintf(f, "%s", str);
}

static void npf_cmd_err_dump(char const *prefix, int argc, char **argv,
			     int depth)
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

int npf_cmd_handle(FILE *f, int argc, char **argv, zhash_t *npf_cmds)
{
#ifdef DEBUG
	int ii;

	for (ii = 0; ii < argc; ++ii)
		printf("%s ", argv[ii]);
	putc('\n', stdout);
#endif
	if (argc < 2) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}

	/* Save and skip the prefix (npf-cfg/npf-ut/npf-op) */
	char const *prefix = argv[0];
	--argc, ++argv;

	int depth = 0;

	npf_cmd_dump(npf_cmds, 0);

	npf_cmd_handler h = npf_cmd_find(npf_cmds, argv, &depth, NULL);
	int rc = -1;

	if (h) {
		argc -= depth;
		argv += depth;
		rc = h(f, argc, argv);
	} else {
		npf_cmd_err(f, "%s: %s", npf_cmd_str_unknown, argv[0]);
		depth = 0;
	}

	if (rc < 0)
		npf_cmd_err_dump(prefix, argc, argv, depth);

	return rc;
}

int
npf_str2ap_type_and_point(char *word, enum npf_attach_type *attach_type,
			  const char **attach_point)
{
	char *colon_p;
	int ret;

	for (colon_p = word; *colon_p != '\0'; colon_p++) {
		if (*colon_p == ':') {
			*colon_p = '\0';
			ret = npf_get_attach_type(word, attach_type);
			*colon_p = ':';
			if (ret < 0)
				return ret;
			*attach_point = colon_p + 1;
			return 0;
		}
	}
	return -EINVAL;
}

int
npf_extract_class_and_group(char *word, enum npf_rule_class *group_class,
			    char **group)
{
	char *colon_p;
	int ret;

	for (colon_p = word; *colon_p != '\0'; colon_p++) {
		if (*colon_p == ':') {
			*colon_p = '\0';
			ret = npf_get_rule_class(word, group_class);
			*colon_p = ':';
			if (ret < 0)
				return ret;
			*group = colon_p + 1;
			return 0;
		}
	}
	return -EINVAL;
}
