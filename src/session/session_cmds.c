/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
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
#include "session.h"
#include "session_cmds.h"
#include "session_feature.h"
#include "session_op.h"
#include "session_private.h"
#include "urcu.h"
#include "util.h"
#include "vplane_log.h"

/* Max number of sessions to return as json */
#define MAX_JSON_SESSIONS       16384

static zhash_t *cmd_op_hash;
static zhash_t *cmd_cfg_hash;

typedef int (*cmd_handler)(FILE *, int, char **);

struct session_command {
	cmd_handler handler;
	const char *tokens;
};

struct cmd_entry {
	zhash_t *_next;
	cmd_handler _hndlr;
};

#define SD_FILTER_NONE		0x00
#define SD_FILTER_NAT		0x01
#define SD_FILTER_NAT64		0x02
#define SD_FILTER_NAT46		0x04
#define SD_FILTER_ALG		0x08
#define SD_FILTER_CONN_ID	0x10

struct session_dump {
	FILE	*sd_fp;
	int	sd_start;
	int	sd_count;
	void	*sd_data;
	bool	sd_features;
	uint8_t sd_filter;
	ulong	sd_conn_id;
};

/* Parameters for session expiration by filtering */
#define FILTER_BY_ANY_SRCIP	0x01
#define FILTER_BY_ANY_DSTIP	0x02
#define FILTER_BY_ANY_SRC_ID	0x04
#define FILTER_BY_ANY_DST_ID	0x08
#define FILTER_BY_ID		0x10
#define FILTER_BY_ANY_PROTO	0x20

struct session_filter_params {
	uint32_t	sf_srcip[4];
	uint32_t	sf_dstip[4];
	uint16_t	sf_src_id;
	uint16_t	sf_dst_id;
	uint8_t		sf_s_af;
	uint8_t		sf_d_af;
	uint16_t	sf_flags;
	uint64_t	sf_id;
	uint16_t	sf_proto;
};

/*
 * Common error strings
 */
const char err_str_unknown[] = "unknown command";
const char err_str_missing[] = "missing command";
const char err_str_missing_arg[] = "missing argument";
const char err_str_too_many_chars[] = "too many characters";

static void __attribute__((format(printf, 2, 3))) cmd_err(FILE *f,
		const char *format, ...)
{
	char str[100];
	va_list ap;

	va_start(ap, format);
	vsnprintf(str, sizeof(str), format, ap);
	va_end(ap);

#ifdef DEBUG
	printf("cmd_err: %s\n", str);
#endif

	RTE_LOG(DEBUG, DATAPLANE, "%s\n", str);

	if (f)
		fprintf(f, "%s", str);
}

static int arg_to_int(const char *arg)
{
	char *p;
	unsigned long val = strtoul(arg, &p, 10);

	if (p == arg || val > INT_MAX)
		return -1;

	return (uint32_t) val;
}

static long arg_to_long(const char *arg)
{
	char *p;
	unsigned long val = strtoul(arg, &p, 10);

	if (p == arg || val > LONG_MAX)
		return -1;

	return (long) val;
}

static int cmd_feature_json(struct session *s __unused,
		struct session_feature *sf, void *data)
{
	json_writer_t *json = data;
	const struct session_feature_ops *ops = feature_operations[sf->sf_type];

	/* Only if the feature has a json op */
	if (!ops->json)
		return 0;

	jsonw_start_object(json);
	jsonw_int_field(json, "type", sf->sf_type);
	ops->json(json, sf);
	jsonw_end_object(json);

	return 0;
}

void
cmd_session_json(struct session *s, json_writer_t *json, bool add_feat,
		 bool is_json_array)
{
	char buf[INET6_ADDRSTRLEN];
	uint32_t if_index;
	const void *saddr;
	const void *daddr;
	uint16_t sid;
	uint16_t did;
	struct sentry *init_sen = rcu_dereference(s->se_sen);
	int tmp;

	/* No sentry?  (racing with expiration) */
	if (!init_sen)
		return;

	if (is_json_array) {
		/* New array element */
		jsonw_start_object(json);
		jsonw_uint_field(json, "id", s->se_id);
	} else {
		/* New named object (session ID is the name) */
		sprintf(buf, "%lu", s->se_id);
		jsonw_name(json, buf);
		jsonw_start_object(json);
	}

	/* Extract addrs/ids from the sentry */
	session_sentry_extract(init_sen, &if_index, &tmp, &saddr, &sid, &daddr,
			&did);

	jsonw_uint_field(json, "vrf_id", s->se_vrfid);
	jsonw_string_field(json, "src_addr",
			inet_ntop(tmp, saddr, buf, sizeof(buf)));
	jsonw_uint_field(json, "src_port", ntohs(sid));
	jsonw_string_field(json, "dst_addr",
			inet_ntop(tmp, daddr, buf, sizeof(buf)));
	jsonw_uint_field(json, "dst_port", ntohs(did));

	jsonw_uint_field(json, "proto", s->se_protocol);
	jsonw_string_field(json, "interface", ifnet_indextoname_safe(if_index));

	jsonw_int_field(json, "time_to_expire", sess_time_to_expire(s));
	jsonw_int_field(json, "state_expire_window", s->se_timeout);
	jsonw_int_field(json, "state", s->se_protocol_state);
	jsonw_int_field(json, "gen_state", s->se_gen_state);

	if (s->se_link && s->se_link->sl_parent)
		jsonw_uint_field(json, "parent", s->se_link->sl_parent->se_id);
	else
		jsonw_uint_field(json, "parent", 0);

	uint64_t ts = rte_get_timer_cycles();
	if (ts > s->se_create_time)
		jsonw_uint_field(json, "duration",
				 (ts - s->se_create_time) / rte_get_timer_hz());

	/* Bitmap of features enabled on this session */
	jsonw_uint_field(json, "feature_type", sess_feature_type_bm(s));

	/* Add feature json if desired */
	if (add_feat) {
		jsonw_int_field(json, "features_count",
				rte_atomic16_read(&s->se_feature_count));
		jsonw_name(json, "features");
		jsonw_start_array(json);
		session_feature_walk_session(s, SESSION_FEATURE_ALL,
				cmd_feature_json, json);
		jsonw_end_array(json);
	}

	/* Session counters */
	jsonw_name(json, "counters");
	jsonw_start_object(json);
	jsonw_uint_field(json, "packets_in",
			 rte_atomic64_read(&s->se_pkts_in));
	jsonw_uint_field(json, "bytes_in",
			 rte_atomic64_read(&s->se_bytes_in));
	jsonw_uint_field(json, "packets_out",
			 rte_atomic64_read(&s->se_pkts_out));
	jsonw_uint_field(json, "bytes_out",
			 rte_atomic64_read(&s->se_bytes_out));
	jsonw_end_object(json); /* End of counters */

	jsonw_end_object(json);
}

static int cmd_session_json_cb(struct session *s, void *data)
{
	struct session_dump *sd = data;
	json_writer_t *json = sd->sd_data;

	if (sd->sd_filter) {
		if ((sd->sd_filter & SD_FILTER_NAT) &&
		    !session_is_nat(s))
			return 0;
		if ((sd->sd_filter & SD_FILTER_NAT64) &&
		    !session_is_nat64(s))
			return 0;
		if ((sd->sd_filter & SD_FILTER_NAT46) &&
		    !session_is_nat46(s))
			return 0;
		if ((sd->sd_filter & SD_FILTER_ALG) &&
		    !session_is_alg(s))
			return 0;
		if ((sd->sd_filter & SD_FILTER_CONN_ID) &&
		    (s->se_id != sd->sd_conn_id))
			return 0;
	}

	/* Skip? */
	if (sd->sd_start-- > 0)
		return 0;

	/* Filled? */
	if (sd->sd_count-- <= 0)
		return -1;  /* Stop walk we are full */

	/* Add the session json */
	cmd_session_json(s, json, sd->sd_features, false);

	return 0;
}

static int cmd_sentry_json(struct sentry *sen, void *data)
{
	struct session_dump *sd = data;
	char buf[INET6_ADDRSTRLEN];
	uint32_t if_index;
	const void *saddr;
	const void *daddr;
	uint16_t sid;
	uint16_t did;
	json_writer_t *json = sd->sd_data;
	struct session *s = sen->sen_session;
	int af;

	/* Skip? */
	if (sd->sd_start-- > 0)
		return 0;

	/* Filled? */
	if (sd->sd_count-- <= 0)
		return -1;  /* Stop walk, we are full */

	/* Extract addrs/ids from the sentry */
	session_sentry_extract(sen, &if_index, &af, &saddr, &sid, &daddr, &did);

	jsonw_uint_field(json, "session_id", s->se_id);
	jsonw_string_field(json, "src_addr",
			inet_ntop(af, saddr, buf, sizeof(buf)));
	jsonw_uint_field(json, "src_port", ntohs(sid));
	jsonw_string_field(json, "dst_addr",
			inet_ntop(af, daddr, buf, sizeof(buf)));
	jsonw_uint_field(json, "dst_port", ntohs(did));

	jsonw_uint_field(json, "proto", s->se_protocol);
	jsonw_uint_field(json, "vrfid", s->se_vrfid);

	return 0;
}

static void cmd_session_show_summary(FILE *fp)
{
	json_writer_t *json;
	uint32_t sessions_used;
	uint32_t sessions_max;
	struct session_counts sc = { 0 };

	json = jsonw_new(fp);
	if (!json)
		return;
	jsonw_pretty(json, true);
	jsonw_name(json, "config");
	jsonw_start_object(json);
	jsonw_name(json, "sessions");
	jsonw_start_object(json);
	jsonw_name(json, "statistics");
	jsonw_start_object(json);

	session_counts(&sessions_used, &sessions_max, &sc);
	jsonw_uint_field(json, "used", sessions_used);
	jsonw_uint_field(json, "max", sessions_max);
	jsonw_uint_field(json, "nat", sc.sc_nat);
	jsonw_uint_field(json, "nat64", sc.sc_nat64);
	jsonw_uint_field(json, "nat46", sc.sc_nat46);

	npf_print_state_stats(json);

	jsonw_end_object(json);
	jsonw_end_object(json);
	jsonw_end_object(json);
	jsonw_destroy(&json);
}

static void cmd_session_show(struct session_dump *sd)
{
	json_writer_t *json = jsonw_new(sd->sd_fp);
	sd->sd_data = json;

	if (sd->sd_count <= 0 || sd->sd_count >= MAX_JSON_SESSIONS)
		sd->sd_count = MAX_JSON_SESSIONS;

	jsonw_name(json, "config");
	jsonw_start_object(json);
	jsonw_name(json, "sessions");
	jsonw_start_object(json);

	session_table_walk(cmd_session_json_cb, sd);

	jsonw_end_object(json);
	jsonw_end_object(json);
	jsonw_destroy(&json);
}

static void cmd_sentries_show(FILE *fp, int start, int count)
{
	struct session_dump sd;
	json_writer_t *json;

	sd.sd_fp = fp;
	sd.sd_start = start;
	sd.sd_count = count;
	sd.sd_filter = 0;

	json = jsonw_new(fp);
	sd.sd_data = json;

	if (count <= 0 || count >= MAX_JSON_SESSIONS)
		sd.sd_count = MAX_JSON_SESSIONS;

	jsonw_name(json, "sentries");
	jsonw_start_object(json);
	jsonw_start_array(json);

	sentry_table_walk(cmd_sentry_json, &sd);

	jsonw_end_array(json);
	jsonw_end_object(json);
	jsonw_destroy(&json);
}

/* Expire all sessions */
static int cmd_session_expire_all(struct session *s, void *data __unused)
{
	session_expire(s, NULL);
	return 0;
}

/* Expire all nat64 sessions */
static int cmd_session_expire_nat64(struct session *s, void *data __unused)
{
	if (session_is_nat64(s))
		session_expire(s, NULL);
	return 0;
}

/* Expire all nat46 sessions */
static int cmd_session_expire_nat46(struct session *s, void *data __unused)
{
	if (session_is_nat46(s))
		session_expire(s, NULL);
	return 0;
}

/* Expire all sessions by filter */
static int cmd_session_expire_id(struct session *s, void *data)
{
	struct session_filter_params *sf = data;

	if (s->se_id == sf->sf_id)
		session_expire(s, NULL);
	return 0;
}

/* Init session filter params */
static int cmd_init_sf(FILE *f, struct session_filter_params *sf,
		const char *saddr, const char *sid, const char *daddr,
		const char *did, const char *proto)
{
	int tmp;

	/* Source address */
	if (strncmp(saddr, "any", 3) != 0) {
		if (inet_pton(AF_INET, saddr, sf->sf_srcip) == 1)
			sf->sf_s_af = AF_INET;
		else if (inet_pton(AF_INET6, saddr, sf->sf_srcip) == 1)
			sf->sf_s_af = AF_INET6;
		else {
			cmd_err(f, "invalid filter source address");
			return -1; /* invalid addr */
		}
	} else
		sf->sf_flags |= FILTER_BY_ANY_SRCIP;

	/* Destination address */
	if (strncmp(daddr, "any", 3) != 0) {
		if (inet_pton(AF_INET, daddr, sf->sf_dstip) == 1)
			sf->sf_d_af = AF_INET;
		else if (inet_pton(AF_INET6, daddr, sf->sf_dstip) == 1)
			sf->sf_d_af = AF_INET6;
		else {
			cmd_err(f, "invalid filter destination address");
			return -1; /* invalid addr */
		}
	} else
		sf->sf_flags |= FILTER_BY_ANY_DSTIP;

	/* Source port/id */
	if (strncmp(sid, "any", 3) != 0) {
		tmp = arg_to_int(sid);
		if (tmp < 0 || tmp > USHRT_MAX) {
			cmd_err(f, "invalid filter source id: %s\n", sid);
			return -1;
		}
		sf->sf_src_id = tmp;
	} else
		sf->sf_flags |= FILTER_BY_ANY_SRC_ID;

	/* Destination port/id */
	if (strncmp(did, "any", 3) != 0) {
		tmp = arg_to_int(did);
		if (tmp < 0 || tmp > USHRT_MAX) {
			cmd_err(f, "invalid filter destination id: %s\n", did);
			return -1;
		}
		sf->sf_dst_id = tmp;
	} else
		sf->sf_flags |= FILTER_BY_ANY_DST_ID;

	/* protocol */
	if (strncmp(proto, "any", 3) != 0) {
		tmp = arg_to_int(proto);
		if (tmp < 0 || tmp > USHRT_MAX) {
			cmd_err(f, "invalid filter protocol: %s\n", proto);
			return -1;
		}
		sf->sf_proto = tmp;
	} else
		sf->sf_flags |= FILTER_BY_ANY_PROTO;

	return 0;
}

static int cmd_filter_cmp_addr(int af, const uint32_t *addr1,
		const uint32_t *addr2)
{
	int len = (af == AF_INET) ? 1 : 4;
	int i;

	for (i = 0; i < len; i++)
		if (addr1[i] != addr2[i])
			return 0;

	return 1;
}

static bool cmd_filter_match(struct sentry *sen,
		struct session_filter_params *sf)
{
	uint32_t if_index;
	uint16_t sid;
	uint16_t did;
	uint16_t proto;
	const void *daddr;
	const void *saddr;
	int af;

	session_sentry_extract(sen, &if_index, &af, &saddr, &sid, &daddr, &did);
	proto = sen->sen_protocol;

	/* protocol */
	if (!(sf->sf_flags & FILTER_BY_ANY_PROTO) &&
		proto != sf->sf_proto)
		return false;

	/* Source port/id */
	if (!(sf->sf_flags & FILTER_BY_ANY_SRC_ID) &&
		ntohs(sid) != sf->sf_src_id)
		return false;

	/* Destination port/id */
	if (!(sf->sf_flags & FILTER_BY_ANY_DST_ID) &&
		ntohs(did) != sf->sf_dst_id)
		return false;

	/* Source addr */
	if (!(sf->sf_flags & FILTER_BY_ANY_SRCIP)) {
		if (af != sf->sf_s_af)
			return false;

		if (!cmd_filter_cmp_addr(af, saddr, sf->sf_srcip))
			return false;
	}

	/* Destination addr */
	if (!(sf->sf_flags & FILTER_BY_ANY_DSTIP)) {
		if (af != sf->sf_d_af)
			return false;

		if (!cmd_filter_cmp_addr(af, daddr, sf->sf_dstip))
			return false;
	}

	return true;
}

/* Callback for filtering on sentries */
static int cmd_sentry_expire_filter(struct sentry *sen, void *data)
{
	struct session_filter_params *sf = data;

	/* Already expired? */
	if (sen->sen_session->se_flags & SESSION_EXPIRED)
		return 0;

	if (cmd_filter_match(sen, sf))
		session_expire(sen->sen_session, NULL);

	return 0;
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
recurse_cmds(zhash_t *cmds, const struct session_command *f, char *toks)
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

static zhash_t *cmd_hash_init(struct session_command const cmd_table[],
			   unsigned int num)
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
static cmd_handler cmd_find(zhash_t *cmds, char **c, int *depth, cmd_handler h)
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

/*
 * Args are marked as unused for when this is compiled out.
 */
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


static void cmd_error(char const *prefix, int argc, char **argv, int depth)
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

static int cmd_handle(FILE *f, int argc, char **argv, zhash_t *cmds)
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

static int cmd_op_walk_sessions_summary(FILE *f, int argc __unused,
		char **argv __unused)
{
	cmd_session_show_summary(f);
	return 0;
}

static int
cmd_op_delete_sessions(FILE *f, int argc, char **argv)
{
	/*
	 * argv:   [1  ] [2] [3  ] [4] [5  ] [6] [7  ] [8] [9  ] [10]
	 * cli ex: saddr any sport 300 daddr any dport any proto any
	 */
	enum {
		FT_SRC_ADDR_NAME = 1,
		FT_SRC_ADDR_VALUE = 2,
		FT_SRC_PORT_NAME = 3,
		FT_SRC_PORT_VALUE = 4,
		FT_DST_ADDR_NAME = 5,
		FT_DST_ADDR_VALUE = 6,
		FT_DST_PORT_NAME = 7,
		FT_DST_PORT_VALUE = 8,
		FT_PROTO_NAME = 9,
		FT_PROTO_VALUE = 10,
		NUM_FLT_PARAMS = 11
	};

	struct session_filter_params sf = { {0} };
	int rc;

	if (argc < 1) {
		cmd_err(f, "%s", err_str_missing);
		return -1;
	}

	if (strcmp(argv[0], "all") == 0) {
		session_table_walk(cmd_session_expire_all, NULL);
		return 0;
	}
	if (strcmp(argv[0], "id") == 0) {
		if (argc < 2) {
			cmd_err(f, "%s", err_str_missing_arg);
			return -1;
		}
		sf.sf_id = arg_to_long(argv[1]);
		sf.sf_flags = FILTER_BY_ID;
		session_table_walk(cmd_session_expire_id, &sf);
		return 0;
	}
	if (strcmp(argv[0], "filter") == 0) {
		if (argc < NUM_FLT_PARAMS) {
			cmd_err(f, "%s", err_str_missing_arg);
			return -1;
		}

		rc = cmd_init_sf(f, &sf,
				argv[FT_SRC_ADDR_VALUE],
				argv[FT_SRC_PORT_VALUE],
				argv[FT_DST_ADDR_VALUE],
				argv[FT_DST_PORT_VALUE],
				argv[FT_PROTO_VALUE]);
		if (rc)
			return rc;
		sentry_table_walk(cmd_sentry_expire_filter, &sf);
		return 0;
	}
	if (strcmp(argv[0], "dpi") == 0) {
		/* TODO: npf_clear_session_dpi(); */
		return 0;
	}
	if (strcmp(argv[0], "nat64") == 0) {
		session_table_walk(cmd_session_expire_nat64, NULL);
		return 0;
	}
	if (strcmp(argv[0], "nat46") == 0) {
		session_table_walk(cmd_session_expire_nat46, NULL);
		return 0;
	}

	cmd_err(f, "%s: %s", err_str_unknown, argv[0]);
	return -1;
}

/* Parse optional start/count walk limits */
static int cmd_parse_limits(FILE *f, int argc, char **argv,
		int *start, int *count)
{
	if (argc > 0) {
		*start = arg_to_int(argv[0]);
		if (*start < 0) {
			cmd_err(f, "invalid start limit: %s", argv[0]);
			return -EINVAL;
		}

		if (argc > 1) {
			*count = arg_to_int(argv[1]);
			if (*count <= 0) {
				cmd_err(f, "invalid count limit: %s",
						argv[1]);
				return -EINVAL;
			}
		}
	}
	return 0;
}

static int cmd_op_walk_sessions(FILE *f, int argc, char **argv)
{
	int start = 0;
	int count = 0;
	int rc;
	ulong conn_id = 0;
	bool have_conn_id = false;

	/* Parse an initial "id N" connection ID, if any */
	if (argc >= 1 && !strcmp(argv[0], "id")) {
		conn_id = arg_to_long(argv[1]);
		have_conn_id = true;
		argc -= 2;
		argv += 2;
	}

	/* Now parse the "start" and "count" limits, if any */
	rc = cmd_parse_limits(f, argc, argv, &start, &count);
	if (rc)
		return rc;

	struct session_dump sd = {
		.sd_fp = f,
		.sd_features = false,	/* No feature json */
		.sd_filter = have_conn_id ? SD_FILTER_CONN_ID : SD_FILTER_NONE,
		.sd_conn_id = conn_id,
		.sd_start = start,
		.sd_count = count,
	};
	cmd_session_show(&sd);
	return 0;
}

static int cmd_op_walk_sessions_full(FILE *f, int argc, char **argv)
{
	int start = 0;
	int count = 0;
	int rc;

	rc = cmd_parse_limits(f, argc, argv, &start, &count);
	if (rc)
		return rc;

	struct session_dump sd = {
		.sd_fp = f,
		.sd_features = true,	/* Include feature json */
		.sd_filter = 0,
		.sd_conn_id = 0,
		.sd_start = start,
		.sd_count = count,
	};
	cmd_session_show(&sd);
	return 0;
}

/*
 * Return nat64 sessions
 */
static int cmd_op_walk_sessions_nat64(FILE *f, int argc, char **argv)
{
	int start = 0;
	int count = 0;
	int rc;

	rc = cmd_parse_limits(f, argc, argv, &start, &count);
	if (rc)
		return rc;

	struct session_dump sd = {
		.sd_fp = f,
		.sd_features = true,	/* Include feature json */
		.sd_filter = SD_FILTER_NAT64,
		.sd_conn_id = 0,
		.sd_start = start,
		.sd_count = count,
	};
	cmd_session_show(&sd);
	return 0;
}

/*
 * Return nat46 sessions
 */
static int cmd_op_walk_sessions_nat46(FILE *f, int argc, char **argv)
{
	int start = 0;
	int count = 0;
	int rc;

	rc = cmd_parse_limits(f, argc, argv, &start, &count);
	if (rc)
		return rc;

	struct session_dump sd = {
		.sd_fp = f,
		.sd_features = true,	/* Include feature json */
		.sd_filter = SD_FILTER_NAT46,
		.sd_conn_id = 0,
		.sd_start = start,
		.sd_count = count,
	};
	cmd_session_show(&sd);
	return 0;
}

static int cmd_op_walk_sentries(FILE *f, int argc, char **argv)
{
	int start = 0;
	int count = 0;
	int rc;

	rc = cmd_parse_limits(f, argc, argv, &start, &count);
	if (rc)
		return rc;

	cmd_sentries_show(f, start, count);
	return 0;
}

static int cmd_cfg_max_sessions(FILE *f, int argc, char **argv)
{
	long count;

	if (!argc) {
		cmd_err(f, "missing max_session count");
		return -EINVAL;
	}

	count = arg_to_long(argv[0]);
	if (count < 0 || count > UINT_MAX) {
		cmd_err(f, "invalid max session count: %s", argv[0]);
		return -EINVAL;
	}
	session_set_max_sessions(count);
	return 0;
}

/*
 * Parse a session log item with optional value. Currently supported are:
 * "creation=on|off", "deletion=on|off", "periodic=<time-in-seconds>".
 * For periodic if <time-in-seconds> is 0, it means disable periodic logging.
 */

static int session_log_parse_param(FILE *f, struct session_log_cfg *scfg,
				   char *item, char *value)
{
	if (!strcmp(item, "creation")) {
		if (!strcmp(value, "on")) {
			scfg->slc_log_creation = 1;
		} else if (!strcmp(value, "off")) {
			scfg->slc_log_creation = 0;
		} else {
			cmd_err(f, "session: invalid log %s value: %s", item,
				value);
			return -EINVAL;
		}
	} else if (!strcmp(item, "deletion")) {
		if (!strcmp(value, "on")) {
			scfg->slc_log_deletion = 1;
		} else if (!strcmp(value, "off")) {
			scfg->slc_log_deletion = 0;
		} else {
			cmd_err(f, "session: invalid log %s value: %s", item,
				value);
			return -EINVAL;
		}
	} else if (!strcmp(item, "periodic")) {
		char *endp;

		scfg->slc_log_interval = strtoul(value, &endp, 10);

		if (*endp) {
			cmd_err(f, "session: invalid log %s value: %s", item,
				value);
			return -EINVAL;
		}
		if (scfg->slc_log_interval == 0)
			scfg->slc_log_periodic = 0;
		else
			scfg->slc_log_periodic = 1;
	} else {
		cmd_err(f, "session: unknown session log parameter %s", item);
		return -EINVAL;
	}

	return 0;
}


/*
 * This is for configuring the session logging. The format of parameters
 * are: <name>=<value>, and a number of values can be configured in a
 * single line.
 */
static int cmd_cfg_session_logging(FILE *f, int argc, char **argv)
{
	int i;
	int rc;
	char *c;
	struct session_log_cfg scfg = {0};

	for (i = 0; i < argc; i++) {
		char *arg = strdupa(argv[i]);
		c = strchr(arg, '=');
		if (!c) {
			cmd_err(f, "session: missing equal in log parameter:"
				" %s", arg);
			return -EINVAL;
		}

		*c = '\0';
		c += 1;

		rc = session_log_parse_param(f, &scfg, arg, c);

		if (rc)
			return rc;
	}

	session_set_global_logging_cfg(&scfg);

	return 0;
}

enum cmd_op {
	OP_SHOW_SESSIONS_SUMMARY,
	OP_SHOW_SESSIONS_NAT,
	OP_SHOW_SESSIONS_NAT64,
	OP_SHOW_SESSIONS_NAT46,
	OP_SHOW_SESSIONS,
	OP_SHOW_SENTRIES,
	OP_DELETE,
	OP_LIST,
	OP_SHOW_DP_SESSIONS,
	OP_CLEAR_DP_SESSIONS,
};

enum cmd_cfg {
	CFG_MAX_SESSIONS,
	CFG_LOGGING,
};

static const struct session_command session_cmd_op[] = {
	[OP_SHOW_SESSIONS_SUMMARY] = {
		.tokens = "show sessions summary",
		.handler = cmd_op_walk_sessions_summary,
	},
	[OP_SHOW_SESSIONS_NAT] = {
		.tokens = "show sessions full",
		.handler = cmd_op_walk_sessions_full,
	},
	[OP_SHOW_SESSIONS_NAT64] = {
		.tokens = "show sessions nat64",
		.handler = cmd_op_walk_sessions_nat64,
	},
	[OP_SHOW_SESSIONS_NAT46] = {
		.tokens = "show sessions nat46",
		.handler = cmd_op_walk_sessions_nat46,
	},
	[OP_SHOW_SESSIONS] = {
		.tokens = "show sessions",
		.handler = cmd_op_walk_sessions,
	},
	[OP_SHOW_SENTRIES] = {
		.tokens = "show sentries",
		.handler = cmd_op_walk_sentries,
	},
	[OP_DELETE] = {
		.tokens = "clear session",
		.handler = cmd_op_delete_sessions,
	},
	[OP_LIST] = {
		.tokens = "list",
		.handler = cmd_op_list,
	},
	[OP_SHOW_DP_SESSIONS] = {
		.tokens = "show dataplane sessions",
		.handler = cmd_op_show_dp_sessions,
	},
	[OP_CLEAR_DP_SESSIONS] = {
		.tokens = "clear dataplane sessions",
		.handler = cmd_op_clear_dp_sessions,
	},
};

static const struct session_command session_cmd_cfg[] = {
	[CFG_MAX_SESSIONS] = {
		.tokens = "sessions-max",
		.handler = cmd_cfg_max_sessions,
	},
	[CFG_LOGGING] = {
		.tokens = "logging",
		.handler = cmd_cfg_session_logging,
	}
};

static __attribute__((constructor)) void
session_cmd_op_initialize(void)
{

	cmd_op_hash = cmd_hash_init(session_cmd_op,
			ARRAY_SIZE(session_cmd_op));
	cmd_cfg_hash = cmd_hash_init(session_cmd_cfg,
			ARRAY_SIZE(session_cmd_cfg));
}

int cmd_session_op(FILE *f, int argc, char **argv)
{
	return cmd_handle(f, argc, argv, cmd_op_hash);
}

int cmd_session_cfg(FILE *f, int argc, char **argv)
{
	return cmd_handle(f, argc, argv, cmd_cfg_hash);
}

int cmd_session_ut(FILE *f, int argc, char **argv)
{
	return cmd_session_cfg(f, argc, argv);
}
