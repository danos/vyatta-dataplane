/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <arpa/inet.h>
#include <czmq.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <rte_log.h>
#include <rte_branch_prediction.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "if_var.h"
#include "in6_var.h"
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

enum sd_orderby {
	SD_ORDERBY_NONE,
	SD_ORDERBY_SADDR,
	SD_ORDERBY_DADDR,
	SD_ORDERBY_ID,
	SD_ORDERBY_TO,
};

/*
 * Session dump for show command
 */
struct session_dump {
	FILE			*sd_fp;
	json_writer_t		*sd_json;

	/* For ordered retrieval */
	enum sd_orderby	sd_orderby;
};

static void __attribute__((format(printf, 2, 3))) cmd_err(FILE *f,
		const char *format, ...)
{
	char str[100];
	va_list ap;

	va_start(ap, format);
	vsnprintf(str, sizeof(str), format, ap);
	va_end(ap);

	RTE_LOG(DEBUG, DATAPLANE, "%s\n", str);

	if (f) {
		json_writer_t *json = jsonw_new(f);
		if (json) {
			jsonw_string_field(json, "__error", str);
			jsonw_destroy(&json);
		}
	}
}

/* Pop next argument from list */
static char *next_arg(int *argcp, char ***argvp)
{
	char *arg = NULL;

	if (*argcp > 0) {
		arg = *argvp[0];
		*argcp -= 1;
		*argvp += 1;
	}

	return arg;
}

static int cmd_op_parse_orderby(FILE *f, int *argcp, char ***argvp,
				struct session_dump *sd)
{
	char *val;

	val = next_arg(argcp, argvp);
	if (!val)
		return -EINVAL;

	if (!sd)
		return 0;

	if (!strcmp(val, "dst_addr"))
		sd->sd_orderby = SD_ORDERBY_DADDR;
	else if (!strcmp(val, "src_addr"))
		sd->sd_orderby = SD_ORDERBY_SADDR;
	else if (!strcmp(val, "id"))
		sd->sd_orderby = SD_ORDERBY_ID;
	else if (!strcmp(val, "time_to_expire"))
		sd->sd_orderby = SD_ORDERBY_TO;
	else {
		cmd_err(f, "Invalid option to orderby \"%s\"\n", val);
		return -EINVAL;
	}

	return 0;
}

/*
 * Parse arguments.
 */
static int
cmd_op_parse(FILE *f, int argc, char **argv, struct session_dump *sd)
{
	char *cmd;
	int error = 0;

	while (argc > 0) {
		cmd = next_arg(&argc, &argv);

		if (!strcmp(cmd, "orderby")) {

			error = cmd_op_parse_orderby(f, &argc, &argv, sd);
			if (error < 0)
				return error;
		}
	}
	return 0;
}

/*
 * Session walker callback function for returning a list of items from the
 * sessions.
 */
static int cmd_session_json_list(struct session *s, void *data)
{
	struct sentry *sen = rcu_dereference(s->se_sen);
	struct session_dump *sd = data;

	switch (sd->sd_orderby) {
	case SD_ORDERBY_SADDR:
	case SD_ORDERBY_DADDR: {
		const struct in6_addr *addr;
		const void *saddr;
		const void *daddr;
		int af;

		/* Extract addrs from the sentry */
		session_sentry_extract_addrs(sen, &af, &saddr, &daddr);
		addr = (sd->sd_orderby == SD_ORDERBY_SADDR) ? saddr : daddr;

		/*
		 * IP addresses are returned as uints.  IPv6 addrs are
		 * returned as strings.
		 */
		if (af == AF_INET)
			jsonw_uint(sd->sd_json, ntohl(addr->s6_addr32[0]));
		else {
			char addr_str[INET6_ADDRSTRLEN];

			inet_ntop(AF_INET6, addr, addr_str, sizeof(addr_str));
			jsonw_string(sd->sd_json, addr_str);
		}
		break;
	}
	case SD_ORDERBY_ID:
		jsonw_uint(sd->sd_json, s->se_id);
		break;

	case SD_ORDERBY_TO:
		jsonw_uint(sd->sd_json, sess_time_to_expire(s));
		break;

	case SD_ORDERBY_NONE:
		break;
	};

	return 0;
}

/*
 * cmd_op_list
 */
int cmd_op_list(FILE *f, int argc, char **argv)
{
	struct session_dump sd = {0};
	int rc;

	sd.sd_fp = f;

	/* Default to return list of source addresses */
	sd.sd_orderby = SD_ORDERBY_SADDR;

	rc = cmd_op_parse(f, argc, argv, &sd);
	if (rc < 0)
		return rc;

	json_writer_t *json;

	json = jsonw_new(sd.sd_fp);
	if (!json)
		return -EINVAL;
	sd.sd_json = json;

	jsonw_name(json, "list");
	jsonw_start_array(json);

	session_table_walk(cmd_session_json_list, &sd);

	jsonw_end_array(json);
	jsonw_destroy(&json);

	return 0;
}
