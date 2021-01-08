/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @file cgn_log_rte.c - cgnat logging using rte_log()
 */

#include <errno.h>
#include <netinet/in.h>
#include <linux/if.h>

#include "compiler.h"
#include "if_var.h"
#include "util.h"
#include "soft_ticks.h"
#include "vplane_log.h"

#include "npf/cgnat/cgn.h"
#include "npf/cgnat/cgn_log.h"
#include "npf/cgnat/cgn_source.h"
#include "npf/cgnat/cgn_sess_state.h"
#include "npf/cgnat/cgn_session.h"
#include "npf/cgnat/cgn_sess2.h"
#include "npf/nat/nat_pool.h"

#define ADDR_CHARS 16

#define CGNAT_RTE_LOG(level, ...) \
	rte_log(level, RTE_LOGTYPE_CGNAT, "CGNAT: " __VA_ARGS__)

/*
 * Log subscriber session start - SUBSCRIBER_START
 */
static void cl_rte_log_subscriber_start(uint32_t addr)
{
	char str1[ADDR_CHARS];

	RTE_LOG(NOTICE, CGNAT,
		"SUBSCRIBER_START subs-addr=%s start-time=%lu\n",
		cgn_addrstr(addr, str1, ADDR_CHARS), unix_epoch_us);
}

/*
 * Log subscriber session end - SUBSCRIBER_END
 */
static void cl_rte_log_subscriber_end(uint32_t addr, uint64_t start_time,
				      uint64_t end_time, uint64_t pkts_out,
				      uint64_t bytes_out, uint64_t pkts_in,
				      uint64_t bytes_in, uint64_t sessions)
{
	char str1[ADDR_CHARS];

	RTE_LOG(NOTICE, CGNAT,
		"SUBSCRIBER_END subs-addr=%s start-time=%lu "
		"end-time=%lu sessions=%lu forw=%lu/%lu back=%lu/%lu\n",
		cgn_addrstr(addr, str1, ADDR_CHARS), start_time, end_time,
		sessions, pkts_out, bytes_out, pkts_in, bytes_in);
}

static const char *cgn_log_name_or_unknown(const char *name)
{
	return name ? name : "(unknown)";
}

/*
 * Log port block allocation - PB_ALLOCATED
 */
static void cl_rte_log_pb_alloc(uint32_t pvt_addr, uint32_t pub_addr,
				uint16_t port_start, uint16_t port_end,
				uint64_t start_time, const char *policy_name,
				const char *pool_name)
{
	char str1[ADDR_CHARS];
	char str2[ADDR_CHARS];

	RTE_LOG(NOTICE, CGNAT,
		"PB_ALLOCATED subs-addr=%s policy=%s pub-addr=%s pool=%s "
		"port=%u-%u start-time=%lu\n",
		cgn_addrstr(pvt_addr, str1, ADDR_CHARS),
		cgn_log_name_or_unknown(policy_name),
		cgn_addrstr(pub_addr, str2, ADDR_CHARS),
		cgn_log_name_or_unknown(pool_name),
		port_start, port_end, start_time);
}

/*
 * Log port block release - PB_RELEASED
 */
static void cl_rte_log_pb_release(uint32_t pvt_addr, uint32_t pub_addr,
				  uint16_t port_start, uint16_t port_end,
				  uint64_t start_time, uint64_t end_time,
				  const char *policy_name,
				  const char *pool_name)
{
	char str1[ADDR_CHARS];
	char str2[ADDR_CHARS];

	RTE_LOG(NOTICE, CGNAT,
		"PB_RELEASED subs-addr=%s policy=%s pub-addr=%s pool=%s "
		"port=%u-%u start-time=%lu end-time=%lu\n",
		cgn_addrstr(pvt_addr, str1, ADDR_CHARS),
		cgn_log_name_or_unknown(policy_name),
		cgn_addrstr(pub_addr, str2, ADDR_CHARS),
		cgn_log_name_or_unknown(pool_name),
		port_start, port_end, start_time, end_time);
}

/*
 * Log 5-tuple session
 */
static uint
cl_rte_log_sess_common(struct cgn_sess2 *s2, char *log_str, uint log_str_sz)
{
#define ADDR_CHARS 16
	char str1[ADDR_CHARS];
	char str2[ADDR_CHARS];
	char str3[ADDR_CHARS];
	char state_str[12];
	struct ifnet *ifp;
	struct cgn_session *cse = cgn_sess2_session(s2);
	uint32_t pid = cgn_session_id(cse);
	uint32_t int_src = cgn_session_forw_addr(cse);
	uint16_t int_port = cgn_session_forw_id(cse);
	uint32_t ext_src = cgn_session_back_addr(cse);
	uint16_t ext_port = cgn_session_back_id(cse);
	struct cgn_state *state = cgn_sess2_state(s2);
	uint len;

	ifp = dp_ifnet_byifindex(cgn_session_ifindex(cse));

	if (state->st_proto == NAT_PROTO_TCP)
		snprintf(state_str, sizeof(state_str), "%s[%u/0x%02X]",
			 cgn_sess_state_str_short(state),
			 state->st_state, state->st_hist);
	else
		snprintf(state_str, sizeof(state_str), "%s[%u]",
			 cgn_sess_state_str_short(state),
			 state->st_state);

	len = snprintf(log_str, log_str_sz,
		       "ifname=%s session-id=%u.%u proto=%u dir=%s "
		       "addr=%s->%s port=%u->%u cgn-addr=%s cgn-port=%u "
		       "state=%s start-time=%lu",
		       ifp ? ifp->if_name : "-", pid,
		       cgn_sess2_id(s2), cgn_sess2_ipproto(s2),
		       cgn_sess2_dir(s2) == CGN_DIR_IN ? "in" : "out",
		       cgn_addrstr(ntohl(int_src), str1, ADDR_CHARS),
		       cgn_addrstr(ntohl(cgn_sess2_addr(s2)), str2, ADDR_CHARS),
		       ntohs(int_port), ntohs(cgn_sess2_port(s2)),
		       cgn_addrstr(ntohl(ext_src), str3, ADDR_CHARS),
		       ntohs(ext_port), state_str,
		       cgn_sess2_start_time(s2));

	return len;
}

/*
 * Log SESSION_CREATE
 */
static void cl_rte_log_sess_start(struct cgn_sess2 *s2)
{
#define LOG_STR_SZ 400
	char log_str[LOG_STR_SZ];

	cl_rte_log_sess_common(s2, log_str, sizeof(log_str));
	RTE_LOG(NOTICE, CGNAT, "SESSION_CREATE %s\n", log_str);
}

/*
 * Periodic logging - SESSION_ACTIVE
 */
static void cl_rte_log_sess_active(struct cgn_sess2 *s2)
{
#define LOG_STR_SZ 400
	char log_str[LOG_STR_SZ];
	uint len;
	struct cgn_state *state = cgn_sess2_state(s2);

	len = cl_rte_log_sess_common(s2, log_str, sizeof(log_str));

	len += snprintf(log_str + len, sizeof(log_str) - len,
			" cur-time=%lu", cgn_time_usecs());

	len += snprintf(log_str + len, sizeof(log_str) - len,
			" out=%u/%lu in=%lu/%lu",
			cgn_sess2_pkts_out_tot(s2), cgn_sess2_bytes_out_tot(s2),
			cgn_sess2_pkts_in_tot(s2), cgn_sess2_bytes_in_tot(s2));

	if (state->st_proto == NAT_PROTO_TCP)
		/* TCP round-trip time in microsecs */
		snprintf(log_str + len, sizeof(log_str) - len,
			 " int-rtt=%lu ext-rtt=%lu",
			 state->st_int_rtt, state->st_ext_rtt);

	RTE_LOG(NOTICE, CGNAT, "SESSION_ACTIVE %s\n", log_str);
}

/*
 * Log 5-tuple session end - SESSION_DELETE
 */
static void cl_rte_log_sess_end(struct cgn_sess2 *s2, uint64_t end_time)
{
#define LOG_STR_SZ 400
	char log_str[LOG_STR_SZ];
	uint len;
	struct cgn_state *state = cgn_sess2_state(s2);

	len = cl_rte_log_sess_common(s2, log_str, sizeof(log_str));

	len += snprintf(log_str + len, sizeof(log_str) - len,
			" end-time=%lu", end_time);

	len += snprintf(log_str + len, sizeof(log_str) - len,
			" out=%u/%lu in=%lu/%lu",
			cgn_sess2_pkts_out_tot(s2), cgn_sess2_bytes_out_tot(s2),
			cgn_sess2_pkts_in_tot(s2), cgn_sess2_bytes_in_tot(s2));

	if (state->st_proto == NAT_PROTO_TCP)
		/* TCP round-trip time in microsecs */
		snprintf(log_str + len, sizeof(log_str) - len,
			 " int-rtt=%lu ext-rtt=%lu",
			 state->st_int_rtt, state->st_ext_rtt);

	RTE_LOG(NOTICE, CGNAT, "SESSION_DELETE %s\n", log_str);
}

/*
 * Log SUBSCRIBER_TABLE_FULL, SUBSCRIBER_TABLE_AVAILABLE, and
 * SUBSCRIBER_TABLE_THRESHOLD
 */
static void cl_rte_log_resource_subscriber_table(enum cgn_resource_type type,
						 int32_t count,
						 int32_t max_count)
{
	const char *event_name;
	uint32_t level;

	switch(type) {
	case CGN_RESOURCE_FULL:
		event_name = "SUBSCRIBER_TABLE_FULL";
		level = RTE_LOG_ERR;
		break;
	case CGN_RESOURCE_AVAILABLE:
		event_name = "SUBSCRIBER_TABLE_AVAILABLE";
		level = RTE_LOG_ERR;
		break;
	case CGN_RESOURCE_THRESHOLD:
		event_name = "SUBSCRIBER_TABLE_THRESHOLD";
		level = RTE_LOG_WARNING;
		break;
	default:
		return;
	}

	CGNAT_RTE_LOG(level, "%s count=%d/%d\n", event_name, count, max_count);
}

/*
 * Log SESSION_TABLE_FULL, SESSION_TABLE_AVAILABLE, and
 * SESSION_TABLE_THRESHOLD
 */
static void cl_rte_log_resource_session_table(enum cgn_resource_type type,
					      int32_t count, int32_t max_count)
{
	const char *event_name;
	uint32_t level;

	switch(type) {
	case CGN_RESOURCE_FULL:
		event_name = "SESSION_TABLE_FULL";
		level = RTE_LOG_ERR;
		break;
	case CGN_RESOURCE_AVAILABLE:
		event_name = "SESSION_TABLE_AVAILABLE";
		level = RTE_LOG_ERR;
		break;
	case CGN_RESOURCE_THRESHOLD:
		event_name = "SESSION_TABLE_THRESHOLD";
		level = RTE_LOG_WARNING;
		break;
	default:
		return;
	}

	CGNAT_RTE_LOG(level, "%s count=%d/%d\n", event_name, count, max_count);
}

/*
 * Logs APM_TABLE_ABOVE_LIMIT, APM_TABLE_BELOW_LIMIT, and APM_TABLE_THRESHOLD
 *
 * The apm table has no maximum size.  However the user may specify a limit
 * for which warnings will be logged when the table size goes above/below that
 * limit.   A threshold may also be specified as a percentage of the limit.
 */
static void cl_rte_log_resource_apm_table(enum cgn_resource_type type,
					  int32_t count, int32_t limit_count)
{
	const char *event_name;
	uint32_t level;

	switch(type) {
	case CGN_RESOURCE_FULL:
		event_name = "APM_TABLE_ABOVE_LIMIT";
		level = RTE_LOG_WARNING;
		break;
	case CGN_RESOURCE_AVAILABLE:
		event_name = "APM_TABLE_BELOW_LIMIT";
		level = RTE_LOG_WARNING;
		break;
	case CGN_RESOURCE_THRESHOLD:
		event_name = "APM_TABLE_THRESHOLD";
		level = RTE_LOG_WARNING;
		break;
	default:
		return;
	}

	CGNAT_RTE_LOG(level, "%s count=%d/%d\n",
		      event_name, count, limit_count);
}

/*
 * Basic log string for a 3-tuple session
 */
static int cgn_session_log_str(struct cgn_session *cse, bool incl_trans,
			       char *log_str, uint log_str_sz)
{
#define ADDR_CHARS 16
	char str1[ADDR_CHARS];
	struct ifnet *ifp;
	uint32_t pid = cgn_session_id(cse);
	uint32_t int_src = cgn_session_forw_addr(cse);
	uint16_t int_port = cgn_session_forw_id(cse);
	uint len;

	ifp = dp_ifnet_byifindex(cgn_session_ifindex(cse));

	len = snprintf(log_str, log_str_sz,
		       "ifname=%s session-id=%u proto=%u "
		       "addr=%s port=%u",
		       ifp ? ifp->if_name : "-", pid,
		       cgn_session_ipproto(cse),
		       cgn_addrstr(ntohl(int_src), str1, ADDR_CHARS),
		       ntohs(int_port));

	if (incl_trans) {
		uint32_t ext_src = cgn_session_back_addr(cse);
		uint16_t ext_port = cgn_session_back_id(cse);

		len += snprintf(log_str + len, log_str_sz - len,
				" cgn-addr=%s cgn-port=%u",
				cgn_addrstr(ntohl(ext_src), str1, ADDR_CHARS),
				ntohs(ext_port));
	}

	return len;
}

/*
 * Log DEST_SESSIONS_FULL, DEST_SESSIONS_AVAILABLE, and
 * DEST_SESSIONS_THRESHOLD
*/
static void cl_rte_log_resource_dest_session_table(enum cgn_resource_type type,
						   struct cgn_session *cse,
						   int16_t count,
						   int16_t max_count)
{
	const char *event_name;
	uint32_t level;
	char log_str[140];

	switch(type) {
	case CGN_RESOURCE_FULL:
		event_name = "DEST_SESSIONS_FULL";
		level = RTE_LOG_ERR;
		break;
	case CGN_RESOURCE_AVAILABLE:
		event_name = "DEST_SESSIONS_AVAILABLE";
		level = RTE_LOG_ERR;
		break;
	case CGN_RESOURCE_THRESHOLD:
		event_name = "DEST_SESSIONS_THRESHOLD";
		level = RTE_LOG_WARNING;
		break;
	default:
		return;
	}

	cgn_session_log_str(cse, true, log_str, sizeof(log_str));

	CGNAT_RTE_LOG(level, "%s count=%d/%d %s\n",
		event_name, count, max_count, log_str);
}

/*
 * Logs for subscriber resource limits - MBPU_FULL, MBPU_AVAILABLE,
 * and MBPU_THRESHOLD
 */
static void
cl_rte_log_resource_subscriber_mbpu(enum cgn_resource_type type,
				    uint32_t addr, uint8_t ipproto,
				    uint16_t count, uint16_t max_count)
{
	char str1[ADDR_CHARS];
	const char *event_name;
	uint32_t level;

	switch(type) {
	case CGN_RESOURCE_FULL:
		event_name = "MBPU_FULL";
		level = RTE_LOG_ERR;
		break;
	case CGN_RESOURCE_AVAILABLE:
		event_name = "MBPU_AVAILABLE";
		level = RTE_LOG_ERR;
		break;
	case CGN_RESOURCE_THRESHOLD:
		event_name = "MBPU_THRESHOLD";
		level = RTE_LOG_WARNING;
		break;
	default:
		return;
	}

	/* ipproto will be 0 for 'other' (i.e. non-TCP and non-UDP) */
	CGNAT_RTE_LOG(level, "%s proto=%u subs-addr=%s blocks=%u/%u\n",
		      event_name, ipproto,
		      cgn_addrstr(addr, str1, ADDR_CHARS),
		      count, max_count);
}

/*
 * Logs for public address blocks resource limits - PB_FULL,
 * PB_AVAILABLE, and PB_THRESHOLD
 */
static void cl_rte_log_resource_public_pb(enum cgn_resource_type type,
					  uint32_t addr, uint16_t blocks_used,
					  uint16_t nblocks)
{
	char str1[ADDR_CHARS];
	const char *event_name;
	uint32_t level;

	switch(type) {
	case CGN_RESOURCE_FULL:
		event_name = "PB_FULL";
		level = RTE_LOG_ERR;
		break;
	case CGN_RESOURCE_AVAILABLE:
		event_name = "PB_AVAILABLE";
		level = RTE_LOG_ERR;
		break;
	case CGN_RESOURCE_THRESHOLD:
		event_name = "PB_THRESHOLD";
		level = RTE_LOG_WARNING;
		break;
	default:
		return;
	}

	CGNAT_RTE_LOG(level, "%s pub-addr=%s blocks=%u/%u\n", event_name,
		      cgn_addrstr(addr, str1, ADDR_CHARS), blocks_used,
		      nblocks);
}

/*
 * Logs NP_FULL, NP_AVAILABLE, and NP_THRESHOLD
 */
static void cl_rte_log_resource_pool(enum cgn_resource_type type,
				     struct nat_pool *np,
				     int32_t count, int32_t max_count)
{
	const char *pool_name = nat_pool_name(np);
	const char *event_name;
	uint32_t level;

	switch(type) {
	case CGN_RESOURCE_FULL:
		event_name = "NP_FULL";
		level = RTE_LOG_ERR;
		break;
	case CGN_RESOURCE_AVAILABLE:
		event_name = "NP_AVAILABLE";
		level = RTE_LOG_ERR;
		break;
	case CGN_RESOURCE_THRESHOLD:
		event_name = "NP_THRESHOLD";
		level = RTE_LOG_WARNING;
		break;
	default:
		return;
	}

	CGNAT_RTE_LOG(level, "%s pool=%s count=%d/%d\n",
		      event_name, cgn_log_name_or_unknown(pool_name),
		      count, max_count);
}

/*
 * Log a session clear event (SESSION_CLEAR).  This is done when one or more
 * 2-tuple sessions are cleared manually, either from a clear command or a
 * change in config (e.g. nat pool block size changes).  This log message
 * replaces the multiple SESSION_END log messages in order to avoid scale
 * issues.
 */
static void
cl_rte_log_sess_clear(const char *desc, uint count, uint64_t clear_time)
{
#define LOG_STR_CL_SZ 300
	char log_str[LOG_STR_CL_SZ];

	snprintf(log_str, sizeof(log_str),
			"desc=\"%s\" count=%u time=%lu", desc, count,
			cgn_ticks2timestamp(clear_time));

	RTE_LOG(NOTICE, CGNAT, "SESSION_CLEAR %s\n", log_str);
}

const struct cgn_session_log_fns cgn_session_rte_log_fns = {
	.cl_sess_start = cl_rte_log_sess_start,
	.cl_sess_active = cl_rte_log_sess_active,
	.cl_sess_end = cl_rte_log_sess_end,
};

const struct cgn_port_block_alloc_log_fns cgn_port_block_alloc_rte_log_fns = {
	.cl_pb_alloc = cl_rte_log_pb_alloc,
	.cl_pb_release = cl_rte_log_pb_release,
};

const struct cgn_subscriber_log_fns cgn_subscriber_rte_log_fns = {
	.cl_subscriber_start = cl_rte_log_subscriber_start,
	.cl_subscriber_end = cl_rte_log_subscriber_end,
};

const struct cgn_res_constraint_log_fns cgn_res_constraint_rte_log_fns = {
	.cl_resource_subscriber_mbpu = cl_rte_log_resource_subscriber_mbpu,
	.cl_resource_public_pb = cl_rte_log_resource_public_pb,
	.cl_sess_clear = cl_rte_log_sess_clear,
	.cl_resource_subscriber_table = cl_rte_log_resource_subscriber_table,
	.cl_resource_session_table = cl_rte_log_resource_session_table,
	.cl_resource_dest_session_table =
		cl_rte_log_resource_dest_session_table,
	.cl_resource_apm_table = cl_rte_log_resource_apm_table,
	.cl_resource_pool = cl_rte_log_resource_pool,
};

const struct cgn_log_fns cgn_rte_log_fns = {
	.cl_name = "rte_log",
	.logfn[CGN_LOG_TYPE_SESSION].session = &cgn_session_rte_log_fns,
	.logfn[CGN_LOG_TYPE_PORT_BLOCK_ALLOCATION].port_block_alloc =
		&cgn_port_block_alloc_rte_log_fns,
	.logfn[CGN_LOG_TYPE_SUBSCRIBER].subscriber =
		&cgn_subscriber_rte_log_fns,
	.logfn[CGN_LOG_TYPE_RES_CONSTRAINT].res_constraint =
		&cgn_res_constraint_rte_log_fns,
};
