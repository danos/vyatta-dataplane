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
#include "ip_addr.h"
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
 * 'other' is any session for which the feature is none or unknown, i.e. *not*
 * nat, nat64, alg, or dpi.
 */
#define SF_FEATURE_ANY		0x00
#define SF_FEATURE_OTHER	0x01
#define SF_FEATURE_SNAT		0x02
#define SF_FEATURE_DNAT		0x04
#define SF_FEATURE_NAT64	0x08
#define SF_FEATURE_NAT46	0x10
#define SF_FEATURE_ALG		0x20
#define SF_FEATURE_APP		0x40
#define SF_FEATURE_CONN_ID	0x80

/*
 * Session filter for list, show and clear commands
 */
struct session_filter {
	uint32_t	sf_addrids[SENTRY_LEN_IPV6];
	uint32_t	sf_mask[SENTRY_LEN_IPV6];
	uint		sf_addrids_depth;	/* Number of words to cmp */

	bool		sf_ip;
	bool		sf_ip6;
	enum sf_dir	sf_dir;
	uint8_t		sf_s_af;
	uint8_t		sf_d_af;
	uint8_t		sf_features;	/* Session feature fltr */
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

/* Word offset into sf_addrids */
static inline uint sess_addrids_offs(uint8_t af, bool src)
{
	if (src)
		return 1;
	return (af == AF_INET) ? 2 : 5;
}

static inline struct in6_addr *sess_addrids_saddr(uint8_t af, uint32_t *addrids)
{
	uint offs = sess_addrids_offs(af, true);
	return (struct in6_addr *)&addrids[offs];
}

static inline struct in6_addr *sess_addrids_daddr(uint8_t af, uint32_t *addrids)
{
	uint offs = sess_addrids_offs(af, false);
	return (struct in6_addr *)&addrids[offs];
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

/*
 * Parse address or prefix and mask.  Returns < 0 for failure.
 */
static int
cmd_op_parse_addr_mask(const char *addr_str, struct in6_addr *addr,
		       struct in6_addr *mask, uint8_t *af)
{
	char *p, *pp = NULL;
	uint pfx_len = 0;
	int rc = 0;

	/* Separate address from prefix length (if present) */
	p = strchr(addr_str, '/');
	if (p) {
		pp = p + 1;
		*p = '\0';

		pfx_len = arg_to_uint(pp, &rc);
		if (rc < 0)
			return rc;
	}

	/* IPv4 or IPv6? */
	if (inet_pton(AF_INET, addr_str, addr) == 1) {
		*af = AF_INET;

		if (pfx_len == 0 || pfx_len > 32)
			pfx_len = 32;

		mask->s6_addr32[0] = prefixlen_to_mask(pfx_len);

	} else if (inet_pton(AF_INET6, addr_str, addr) == 1) {
		*af = AF_INET6;

		if (pfx_len == 0 || pfx_len > 128)
			pfx_len = 128;

		in6_prefixlen2mask(mask, pfx_len);

	} else
		return -EINVAL;

	return 0;
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

/*
 * Finish setting up the addrids filter
 */
static int
cmd_op_finalize_addrids_fltr(FILE *f, struct session_filter *sf,
			     uint16_t sport, uint16_t dport)
{
	uint offs, len;

	if (sf->sf_s_af && sf->sf_d_af &&
	    (sf->sf_s_af != sf->sf_d_af)) {
		cmd_err(f,
			"Mismatch between src-addr and dest-addr filters\n");
		return -EINVAL;
	}

	/* Setup port filters */
	if (sport || dport) {
		sf->sf_addrids[0] = htons(sport) << 16 | htons(dport);

		if (dport)
			sf->sf_mask[0] = 0x0000FFFF;
		if (sport)
			sf->sf_mask[0] |= 0xFFFF0000;

		/* Depth is the number of words to compare */
		sf->sf_addrids_depth = 1;
	}

	/* Overwrite depth if src-addr specified */
	if (sf->sf_s_af) {
		offs = sess_addrids_offs(sf->sf_s_af, true);
		len = (sf->sf_s_af == AF_INET) ? 1 : 4;

		sf->sf_addrids_depth = offs + len;
	}

	/* Overwrite depth if dst-addr specified */
	if (sf->sf_d_af) {
		offs = sess_addrids_offs(sf->sf_d_af, false);
		len = (sf->sf_d_af == AF_INET) ? 1 : 4;

		sf->sf_addrids_depth = offs + len;
	}
	return 0;
}

static int
cmd_op_parse_src_addr(FILE *f, int *argcp, char ***argvp,
		      struct session_filter *sf)
{
	struct in6_addr addr, mask;
	struct in6_addr *sf_addr, *sf_mask;
	char *val;
	int error;
	uint8_t af;

	val = next_arg(argcp, argvp);
	if (!val)
		goto error;

	error = cmd_op_parse_addr_mask(val, &addr, &mask, &af);
	if (error < 0)
		goto error;

	sf_addr = sess_addrids_saddr(af, sf->sf_addrids);
	*sf_addr = addr;
	sf->sf_s_af = af;

	sf_mask = sess_addrids_saddr(af, sf->sf_mask);
	*sf_mask = mask;

	return 0;

error:
	cmd_err(f, "Error with src-addr filter params\n");
	return -EINVAL;
}

static int
cmd_op_parse_dst_addr(FILE *f, int *argcp, char ***argvp,
		      struct session_filter *sf)
{
	struct in6_addr addr, mask;
	struct in6_addr *sf_addr, *sf_mask;
	char *val;
	int error;
	uint8_t af;

	val = next_arg(argcp, argvp);
	if (!val)
		goto error;

	error = cmd_op_parse_addr_mask(val, &addr, &mask, &af);
	if (error < 0)
		goto error;

	sf_addr = sess_addrids_daddr(af, sf->sf_addrids);
	*sf_addr = addr;
	sf->sf_s_af = af;

	sf_mask = sess_addrids_daddr(af, sf->sf_mask);
	*sf_mask = mask;

	return 0;

error:
	cmd_err(f, "Error with dest-addr filter params\n");
	return -EINVAL;
}

static int cmd_op_parse_feat(FILE *f, int *argcp, char ***argvp,
			     struct session_filter *sf)
{
	char *val;

	val = next_arg(argcp, argvp);
	if (!val) {
		cmd_err(f, "Missing parameter to feat command\n");
		return -EINVAL;
	}

	if (!strcmp(val, "other"))
		sf->sf_features |= SF_FEATURE_OTHER;
	else if (!strcmp(val, "snat"))
		sf->sf_features |= SF_FEATURE_SNAT;
	else if (!strcmp(val, "dnat"))
		sf->sf_features |= SF_FEATURE_DNAT;
	else if (!strcmp(val, "nat64"))
		sf->sf_features |= SF_FEATURE_NAT64;
	else if (!strcmp(val, "nat46"))
		sf->sf_features |= SF_FEATURE_NAT46;
	else if (!strcmp(val, "alg"))
		sf->sf_features |= SF_FEATURE_ALG;
	else if (!strcmp(val, "application"))
		sf->sf_features |= SF_FEATURE_APP;
	else {
		cmd_err(f, "Invalid parameter \"%s\" to feat command\n", val);
		return -EINVAL;
	}

	return 0;
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
	uint16_t sport = 0, dport = 0;
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

		} else if (!strcmp(cmd, "src-addr")) {
			/*
			 * Source address filter
			 */
			error = cmd_op_parse_src_addr(f, &argc, &argv, sf);
			if (error < 0)
				return error;

		} else if (!strcmp(cmd, "dst-addr")) {
			/*
			 * Destination address filter
			 */
			error = cmd_op_parse_dst_addr(f, &argc, &argv, sf);
			if (error < 0)
				return error;

		} else if (!strcmp(cmd, "src-port")) {
			/*
			 * Source port filter
			 */
			uint tmp;
			val = next_arg(&argc, &argv);
			if (!val)
				goto error_missing_param;

			tmp = arg_to_uint(val, &error);
			if (error < 0 || tmp > USHRT_MAX)
				goto error_param_value;

			sport = tmp;

		} else if (!strcmp(cmd, "dst-port")) {
			/*
			 * Destination port filter
			 */
			uint tmp;
			val = next_arg(&argc, &argv);
			if (!val)
				goto error_missing_param;

			tmp = arg_to_uint(val, &error);
			if (error < 0 || tmp > USHRT_MAX)
				goto error_param_value;

			dport = tmp;

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

		} else if (!strcmp(cmd, "feat")) {
			/*
			 * Session feature filter
			 */
			error = cmd_op_parse_feat(f, &argc, &argv, sf);
			if (error < 0)
				return error;

		} else if (!strcmp(cmd, "orderby")) {

			error = cmd_op_parse_orderby(f, &argc, &argv, sd);
			if (error < 0)
				return error;
		}
	}
	cmd = NULL;

	error = cmd_op_finalize_addrids_fltr(f, sf, sport, dport);
	if (error < 0)
		return error;

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
	uint i;

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

	/* Port numbers, Source address, Dest address */
	for (i = 0; i < sf->sf_addrids_depth; i++) {
		uint32_t mask = sf->sf_mask[i];

		if ((sf->sf_addrids[i] & mask) != (sen->sen_addrids[i] & mask))
			return false;
	}

	/* Session features */
	if (sf->sf_features) {
		uint8_t sess_feat = 0;

		if (session_is_snat(s))
			sess_feat |= SF_FEATURE_SNAT;

		if (session_is_dnat(s))
			sess_feat |= SF_FEATURE_DNAT;

		if (session_is_nat64(s))
			sess_feat |= SF_FEATURE_NAT64;

		if (session_is_nat46(s))
			sess_feat |= SF_FEATURE_NAT46;

		if (session_is_alg(s))
			sess_feat |= SF_FEATURE_ALG;

		if (session_is_app(s))
			sess_feat |= SF_FEATURE_APP;

		if (sess_feat == 0)
			sess_feat |= SF_FEATURE_OTHER;

		if ((sf->sf_features & sess_feat) == 0)
			return false;
	}

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
