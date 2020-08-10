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

enum sf_dir {
	SF_DIR_NONE,
	SF_DIR_IN,
	SF_DIR_OUT,
};

/*
 * Session filter for list, show and clear commands
 */
struct session_filter {
	bool		sf_ip;
	bool		sf_ip6;
	enum sf_dir	sf_dir;
	uint16_t	sf_proto;
	uint32_t	sf_ifindex;
	uint64_t	sf_id;
};

/*
 * Session dump for show command
 */
struct session_dump {
	FILE			*sd_fp;
	json_writer_t		*sd_json;
	struct session_filter	*sd_sf;		/* Session filter */

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

/* Extract an uint from a string */
static uint arg_to_uint(const char *arg, int *error)
{
	char *p;
	unsigned long val;

	if (!arg) {
		*error = -EINVAL;
		return 0;
	}

	val = strtoul(arg, &p, 10);
	if (p == arg || val > UINT_MAX) {
		*error = -EINVAL;
		return 0;
	}
	return (uint32_t) val;
}

/* Extract an ulong from a string */
static ulong arg_to_ulong(const char *arg, int *error)
{
	char *p;
	unsigned long val;

	if (!arg) {
		*error = -EINVAL;
		return 0;
	}

	val = strtoul(arg, &p, 10);
	if (p == arg) {
		*error = -EINVAL;
		return 0ul;
	}
	return val;
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
	if (!val) {
		cmd_err(f, "Missing parameter to orderby command\n");
		return -EINVAL;
	}

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
		cmd_err(f, "Invalid option \"%s\" to orderby command\n", val);
		return -EINVAL;
	}

	return 0;
}

/*
 * Parse arguments.
 */
static int
cmd_op_parse(FILE *f, int argc, char **argv, struct session_filter *sf,
	     struct session_dump *sd)
{
	char *cmd, *val;
	int error = 0;

	while (argc > 0) {
		cmd = next_arg(&argc, &argv);

		if (!strcmp(cmd, "ip"))
			/* IP sessions */
			sf->sf_ip = true;

		else if (!strcmp(cmd, "ip6"))
			/* IPv6 sessions */
			sf->sf_ip6 = true;

		else if (!strcmp(cmd, "id")) {
			/*
			 * Session ID filter
			 */
			ulong tmp;
			val = next_arg(&argc, &argv);
			if (!val)
				goto error_missing_param;

			tmp = arg_to_ulong(val, &error);
			if (error < 0)
				goto error_param_value;

			sf->sf_id = tmp;

		} else if (!strcmp(cmd, "dir")) {
			val = next_arg(&argc, &argv);
			if (!val)
				goto error_missing_param;

			if (!strcmp(val, "in"))
				sf->sf_dir = SF_DIR_IN;
			else if (!strcmp(val, "out"))
				sf->sf_dir = SF_DIR_OUT;

		} else if (!strcmp(cmd, "intf")) {
			/*
			 * Interface filter
			 */
			struct ifnet *ifp;
			val = next_arg(&argc, &argv);
			if (!val)
				goto error_missing_param;

			ifp = dp_ifnet_byifname(val);
			if (!ifp)
				goto error_param_value;

			sf->sf_ifindex = ifp->if_index;

		} else if (!strcmp(cmd, "proto")) {
			/*
			 * Protocol filter
			 */
			uint tmp;
			val = next_arg(&argc, &argv);
			if (!val)
				goto error_missing_param;

			tmp = arg_to_uint(val, &error);
			if (error < 0 || tmp > UCHAR_MAX)
				goto error_param_value;

			sf->sf_proto = tmp;

		} else if (!strcmp(cmd, "orderby")) {

			error = cmd_op_parse_orderby(f, &argc, &argv, sd);
			if (error < 0)
				return error;
		}
	}

	/* Default to both IP and IPv6 if neither is specified */
	if (!sf->sf_ip && !sf->sf_ip6) {
		sf->sf_ip = true;
		sf->sf_ip6 = true;
	}

	return 0;

error_missing_param:
	cmd_err(f, "Missing parameter to \"%s\" command\n", cmd);
	return -EINVAL;

error_param_value:
	cmd_err(f, "Error with parameter to \"%s\" command\n", cmd);
	return -EINVAL;
}

/*
 * Filter.  Returns false if pkt is to be blocked by the filter.
 */
static bool
cmd_session_filter(const struct session *s, const struct session_filter *sf)
{
	const struct sentry *sen = rcu_dereference(s->se_sen);

	/* Session ID */
	if (sf->sf_id && sf->sf_id != s->se_id)
		return false;

	/* Address family */
	if ((sen->sen_flags & SENTRY_IPv4) != 0) {
		if (!sf->sf_ip)
			return false;
	} else if ((sen->sen_flags & SENTRY_IPv6) != 0) {
		if (!sf->sf_ip6)
			return false;
	}

	/* Direction */
	if (sf->sf_dir) {
		if (sf->sf_dir == SF_DIR_IN && !session_is_in(s))
			return false;

		if (sf->sf_dir == SF_DIR_OUT && !session_is_out(s))
			return false;
	}

	/* Interface */
	if (sf->sf_ifindex && sf->sf_ifindex != sen->sen_ifindex)
		return false;

	/* Protocol */
	if (sf->sf_proto && sf->sf_proto != sen->sen_protocol)
		return false;

	return true;
}

/*
 * Session walker callback function for returning a list of items from the
 * sessions.
 */
static int cmd_session_json_list(struct session *s, void *data)
{
	struct sentry *sen = rcu_dereference(s->se_sen);
	struct session_dump *sd = data;
	struct session_filter *sf = sd->sd_sf;

	if (!cmd_session_filter(s, sf))
		return 0;

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
	struct session_filter sf = {0};
	struct session_dump sd = {0};
	int rc;

	sd.sd_fp = f;
	sd.sd_sf = &sf;

	/* Default to return list of source addresses */
	sd.sd_orderby = SD_ORDERBY_SADDR;

	rc = cmd_op_parse(f, argc, argv, &sf, &sd);
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
