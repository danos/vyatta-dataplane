/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <values.h>
#include <rte_jhash.h>
#include <rte_mbuf.h>
#include <rte_timer.h>
#include "util.h"
#include "json_writer.h"
#include "soft_ticks.h"

#include "npf/cgnat/cgn_dir.h"
#include "npf/cgnat/cgn_rc.h"
#include "npf/cgnat/cgn_mbuf.h"
#include "npf/cgnat/cgn_session.h"

#include "npf/cgnat/alg/alg_public.h"
#include "npf/cgnat/alg/alg_session.h"
#include "npf/cgnat/alg/alg_pinhole.h"
#include "npf/cgnat/alg/alg_pptp.h"
#include "npf/cgnat/alg/alg_rc.h"
#include "npf/cgnat/alg/alg.h"

/*
 * Bitmap of enabled ALGs (CGN_ALG_BIT_PPTP etc.)
 */
static uint8_t cgn_alg_enabled;

/*
 * Well-known TCP/UDP ports
 */
#define PPTP_PORT	1723	/* PPTP VPN */
#define SIP_PORT	5060


/*
 * ALG control flows are identified by protocol and well-known port.
 *
 * A port is only added to the table if and when an ALG is enabled via config.
 *
 * When a new CGNAT session is created, and if any ALGs are enabled, then the
 * cgn_alg_dport table is looked up to determine if the session is an ALG
 * control (or 'parent') session.
 */
static uint16_t cgn_alg_dport[NAT_PROTO_COUNT][CGN_ALG_MAX];

/* Simple global counters for non-packet inspection items */
struct cgn_alg_stats_alg {
	uint64_t	count[CGN_ALG_STATS_MAX];
};

struct cgn_alg_stats {
	struct cgn_alg_stats_alg alg[CGN_ALG_MAX];
};

static struct cgn_alg_stats *cgn_alg_stats;

enum cgn_alg_id cgn_alg_get_id(struct cgn_alg_sess_ctx *as)
{
	return as ? as->as_alg_id : CGN_ALG_NONE;
}

static const char *_cgn_alg_id_name[CGN_ALG_MAX] = {
	[CGN_ALG_NONE] = "-",
	[CGN_ALG_PPTP] = "pptp",
	[CGN_ALG_SIP]  = "sip",
};

const char *cgn_alg_id_name(enum cgn_alg_id id)
{
	if (id <= CGN_ALG_LAST)
		return _cgn_alg_id_name[id];
	return "-";
};

enum cgn_alg_id cgn_alg_name2id(const char *name)
{
	enum cgn_alg_id id;

	for (id = CGN_ALG_FIRST; id <= CGN_ALG_LAST; id++)
		if (strcmp(name, _cgn_alg_id_name[id]) == 0)
			return id;
	return CGN_ALG_NONE;
}

/**
 * Is any CGNAT ALG enabled?
 *
 * This is used in two places to determine if a packet should be examined by
 * the CGNAT ALG.
 *
 * 1. If a packet does not match a CGNAT session then we check
 * cgn_alg_is_enabled before looking up the ALG pinhole table
 *
 * 2. When a new CGNAT session is created, we check cgn_alg_is_enabled before
 * determining if the destination port belongs to a CGNAT ALG protocol
 *
 * If either of the above is true then we will set the CGNAT cache object,
 * cpk_alg_id.  The setting of cpk_alg_id determines if the ALG inspection
 * routine is called at the end of the CGNAT packet pipeline node.
 *
 * We also set cpk_alg_id when we find an ALG CGNAT session in the lookup
 * mentioned in point 1 above.
 */
bool cgn_alg_is_enabled(void)
{
	return cgn_alg_enabled != 0;
}

/**
 * Is any CGNAT PPTP ALG enabled?
 */
bool cgn_alg_pptp_is_enabled(void)
{
	return cgn_alg_enabled & CGN_ALG_BIT_PPTP;
}

/*
 * Called by cgn_session_establish in order to identify ALG control, or
 * parent, flows.  'port' is in network byte order.
 */
enum cgn_alg_id cgn_alg_dest_port_lookup(enum nat_proto proto, uint16_t port)
{
	enum cgn_alg_id alg_id;

	for (alg_id = CGN_ALG_FIRST; alg_id <= CGN_ALG_LAST; alg_id++)
		if (port == cgn_alg_dport[proto][alg_id])
			return alg_id;

	return CGN_ALG_NONE;
}

/*
 * ALGs work when CGNAT is in either 3-tuple (main sessions only) or 5-tuple
 * mode (main sessions and sub-sessions).
 *
 * We record the (outbound) destination address and port/ID of the packet that
 * caused the ALG session to be created, and use that here to verify that this
 * packet belongs to that flow.
 *
 * The important check here is to match the address.  We will already have
 * matched a main session (3-tuple), so also matching the address gives us a
 * 4-tuple match.  That in itself should be sufficient to ensure that we do
 * not inspect other packets that also match these 4 tuples.  However we do
 * make a best effort to also check the port/ID ...
 *
 * The destination port/ID we initially save is treated somewhat differently
 * depending on ALG type.
 *
 * PPTP control/parent sessions are the simple 'well known' cases as they use
 * TCP.  Outbound we verify the destination address and port, and inbound we
 * verify the source address and port.
 *
 * For SIP UDP sessions, the initial outbound INVITE Request is sent to port
 * 5060.  However the initial inbound Response may use a different port than
 * 5060 (this is one reason for the source port/ID wildcard in pinhole
 * entries).
 */
static int cgn_alg_verify_remote_client(struct cgn_alg_sess_ctx *as,
					struct cgn_packet *cpk,
					enum cgn_dir dir)
{
	uint32_t remote_addr;	/* Remote client address */
	uint16_t remote_id;	/* Remote client port/ID */

	if (dir == CGN_DIR_IN) {
		remote_addr = cpk->cpk_saddr;
		remote_id = cpk->cpk_sid;
	} else {
		remote_addr = cpk->cpk_daddr;
		remote_id = cpk->cpk_did;
	}

	switch (as->as_alg_id) {
	case CGN_ALG_PPTP:
		if (remote_addr != as->as_dst_addr ||
		    remote_id != as->as_dst_port)
			return -1;

		break;

	case CGN_ALG_SIP:
		if (remote_addr != as->as_dst_addr)
			return -1;

		if (as->as_proto == NAT_PROTO_UDP &&
		    remote_id != as->as_dst_port)
			/*
			 * Note, if 5-tuple sessions are enabled then this
			 * change in port will cause a second sub-session
			 * (dest record) to be created
			 */
			as->as_dst_port = remote_id;

		if (remote_id != as->as_dst_port)
			return -1;

		break;

	case CGN_ALG_NONE:
		break;
	}

	return 0;
}

/*
 * Inspect and/or translate ALG packet payload for a parent/control flow.
 * Last thing to be called in CGNAT path.
 *
 * If an error occurs we just count that error and return 0.  It is possible
 * that we may later want to change that.
 */
int cgn_alg_inspect(struct cgn_session *cse, struct cgn_packet *cpk,
		    struct rte_mbuf *mbuf, enum cgn_dir dir)
{
	struct cgn_alg_sess_ctx *as;
	int rc = ALG_OK;

	assert(cgn_session_is_alg_parent(cse));
	assert(cgn_session_alg_get(cse));

	as = cgn_session_alg_get(cse);
	if (!as) {
		rc = -ALG_ERR_INT;
		goto end;
	}

	/* Do not inspect inbound pkts that are not part of the ALG flow */
	if (cgn_alg_verify_remote_client(as, cpk, dir) < 0)
		return 0;

	/*
	 * Is the ALG still interested in seeing pkts on this flow?  This will
	 * also do any required payload translation.
	 */
	if (as->as_inspect) {

		/*
		 * Is the payload length a min length?  ALGs are not
		 * interested in TCP handshake, for example.
		 */
		if (cgn_payload_len(cpk) < as->as_min_payload)
			goto end;

		/* SIP has a max payload size that it can parse */
		if (as->as_max_payload != 0 &&
		    cgn_payload_len(cpk) > as->as_max_payload) {
			rc = -ALG_ERR_PLOAD_MAX;
			goto end;
		}

		switch (as->as_alg_id) {
		case CGN_ALG_PPTP:
			rc = cgn_alg_pptp_inspect(cpk, mbuf, dir, as);
			if (rc == 0)
				rc = -ALG_OK_PPTP;
			break;

		case CGN_ALG_SIP:
			break;

		case CGN_ALG_NONE:
			rc = -ALG_ERR_INT;
			break;
		}
	}

end:
	alg_rc_inc(dir, rc);

	/* Condense to a single CGNAT return code */
	return rc <= -ALG_RC_ERR_FIRST ? -CGN_ALG_ERR_INSP : 0;
}

uint64_t cgn_alg_stats_read(enum cgn_alg_id id, enum cgn_alg_stat_e stat)
{
	uint64_t sum;
	uint i;

	assert(id <= CGN_ALG_LAST);
	assert(stat <= CGN_ALG_STATS_LAST);

	if (!cgn_alg_stats)
		return 0UL;

	sum = 0UL;
	FOREACH_DP_LCORE(i)
		sum += cgn_alg_stats[i].alg[id].count[stat];

	return sum;
}

/*
 * These are ever increasing counts, so to 'clear' them we subtract the same
 * 'destroyed' count value from both the 'destroyed' and 'created' counts.
 */
void cgn_alg_stats_clear(enum cgn_alg_id id)
{
	uint i;

	assert(id <= CGN_ALG_LAST);

	if (!cgn_alg_stats)
		return;

	FOREACH_DP_LCORE(i) {
		uint64_t tmp;

		tmp = cgn_alg_stats[i].alg[id].count[CAS_CTRL_SESS_DSTD];
		if (tmp) {
			cgn_alg_stats[i].alg[id].count[CAS_CTRL_SESS_DSTD] -= tmp;
			cgn_alg_stats[i].alg[id].count[CAS_CTRL_SESS_CRTD] -= tmp;
		}

		tmp = cgn_alg_stats[i].alg[id].count[CAS_DATA_SESS_DSTD];
		if (tmp) {
			cgn_alg_stats[i].alg[id].count[CAS_DATA_SESS_DSTD] -= tmp;
			cgn_alg_stats[i].alg[id].count[CAS_DATA_SESS_CRTD] -= tmp;
		}
	}
}

void cgn_alg_stats_inc(enum cgn_alg_id id, enum cgn_alg_stat_e stat)
{
	assert(id <= CGN_ALG_LAST);
	assert(stat <= CGN_ALG_STATS_LAST);

	if (likely(cgn_alg_stats != NULL))
		cgn_alg_stats[dp_lcore_id()].alg[id].count[stat]++;
}

static void cgn_alg_stats_init(void)
{
	if (cgn_alg_stats)
		return;

	cgn_alg_stats = zmalloc_aligned((get_lcore_max() + 1) *
					sizeof(*cgn_alg_stats));
}

static void cgn_alg_stats_uninit(void)
{
	free(cgn_alg_stats);
	cgn_alg_stats = NULL;
}

/**************************************************************************
 * Configuration
 **************************************************************************/

/*
 * 'port' is in host byte order.  Enable an ALG for a protocol and port.
 */
static void apt_dport_add(enum cgn_alg_id alg_id, enum nat_proto proto,
			  uint16_t port)
{
	if (proto < NAT_PROTO_COUNT && alg_id < CGN_ALG_MAX)
		cgn_alg_dport[proto][alg_id] = htons(port);
}

static void apt_dport_del(enum cgn_alg_id alg_id, enum nat_proto proto)
{
	if (proto < NAT_PROTO_COUNT && alg_id < CGN_ALG_MAX)
		cgn_alg_dport[proto][alg_id] = 0;
}

/*
 * Enable a CGNAT ALG
 */
int cgn_alg_enable(const char *name)
{
	enum cgn_alg_id id = cgn_alg_name2id(name);
	uint8_t id_bit;

	if (id == CGN_ALG_NONE)
		return -EINVAL;

	id_bit = CGN_ALG_BIT(id);

	/* Already enabled? */
	if ((cgn_alg_enabled & id_bit) != 0)
		return 0;

	switch (id) {
	case CGN_ALG_NONE:
		break;
	case CGN_ALG_PPTP:
		apt_dport_add(CGN_ALG_PPTP, NAT_PROTO_TCP, PPTP_PORT);
		break;
	case CGN_ALG_SIP:
		apt_dport_add(CGN_ALG_SIP, NAT_PROTO_UDP, SIP_PORT);
		apt_dport_add(CGN_ALG_SIP, NAT_PROTO_TCP, SIP_PORT);
		break;
	};

	/*
	 * Create the pinhole table if this the first ALG to be enabled. (The
	 * pinhole table remains in existence until the dataplane UNINIT event
	 * occurs)
	 */
	if (cgn_alg_enabled == 0) {
		int rc = alg_pinhole_init();
		if (rc < 0)
			return rc;
	}

	/* Setting cgn_alg_enabled will expose the ALG to packets */
	cgn_alg_enabled |= id_bit;

	return 0;
}

/*
 * Disable a CGNAT ALG
 */
int cgn_alg_disable(const char *name)
{
	enum cgn_alg_id id = cgn_alg_name2id(name);
	uint8_t id_bit;

	if (id == CGN_ALG_NONE)
		return -EINVAL;

	id_bit = CGN_ALG_BIT(id);

	/* Already disabled? */
	if ((cgn_alg_enabled & id_bit) == 0)
		return 0;

	cgn_alg_enabled &= ~id_bit;

	switch (id) {
	case CGN_ALG_NONE:
		break;
	case CGN_ALG_PPTP:
		apt_dport_del(CGN_ALG_PPTP, NAT_PROTO_TCP);
		break;
	case CGN_ALG_SIP:
		apt_dport_del(CGN_ALG_SIP, NAT_PROTO_UDP);
		apt_dport_del(CGN_ALG_SIP, NAT_PROTO_TCP);
		break;
	};

	return 0;
}

/*
 * Show ALG status
 */
static void cgn_alg_show_status(json_writer_t *json)
{
	enum cgn_alg_id id;
	uint8_t id_bit;

	jsonw_name(json, "status");
	jsonw_start_array(json);

	for (id = CGN_ALG_FIRST; id <= CGN_ALG_LAST; id++) {
		id_bit = CGN_ALG_BIT(id);

		/* Temporary while PPTP is only alg available in Yang */
		if (id != CGN_ALG_PPTP && (cgn_alg_enabled & id_bit) == 0)
			continue;

		jsonw_start_object(json);
		jsonw_string_field(json, "name", _cgn_alg_id_name[id]);
		jsonw_uint_field(json, "enabled",
				 (cgn_alg_enabled & id_bit) != 0);

		if (cgn_alg_dport[NAT_PROTO_TCP][id])
			jsonw_uint_field(json, "tcp",
					 ntohs(cgn_alg_dport[NAT_PROTO_TCP][id]));

		if (cgn_alg_dport[NAT_PROTO_UDP][id])
			jsonw_uint_field(json, "udp",
					 ntohs(cgn_alg_dport[NAT_PROTO_UDP][id]));

		jsonw_end_object(json);
	}
	jsonw_end_array(json);
}

/*
 * Show stats for ALG inspection of CGNAT control packets for one direcion
 */
static void
cgn_alg_show_inspect_stats_dir(json_writer_t *json, enum cgn_dir dir,
			       const char *name)
{
	uint64_t count;
	int rc;

	jsonw_name(json, name);
	jsonw_start_array(json);

	for (rc = ALG_RC_FIRST; rc <= ALG_RC_LAST; rc++) {
		/*
		 * Do not include SIP OK return code if SIP ALG is disabled.
		 * This is a temporary measure that allows the SIP stats to
		 * not show unless enabled in a dev dataplane image.
		 */
		if (rc == ALG_OK_SIP &&
		    (cgn_alg_enabled & CGN_ALG_BIT_SIP) == 0)
			continue;

		jsonw_start_object(json);

		count = alg_rc_read(dir, rc);
		jsonw_string_field(json, "name", alg_rc_str(rc));
		jsonw_string_field(json, "desc", alg_rc_detail_str(rc));
		jsonw_uint_field(json, "rc", rc);
		jsonw_uint_field(json, "count", count);

		jsonw_end_object(json);
	}

	jsonw_end_array(json);
}

/*
 * Show stats for ALG inspection of CGNAT control packets
 */
static void cgn_alg_show_inspect_stats(json_writer_t *json)
{
	jsonw_name(json, "inspect");
	jsonw_start_object(json);

	cgn_alg_show_inspect_stats_dir(json, CGN_DIR_OUT, "out");
	cgn_alg_show_inspect_stats_dir(json, CGN_DIR_IN, "in");

	jsonw_end_object(json);
}

/*
 * Show stats for ALG sessions
 */
static void cgn_alg_show_session_stats(json_writer_t *json)
{
	enum cgn_alg_id id;

	jsonw_name(json, "sessions");
	jsonw_start_object(json);

	for (id = CGN_ALG_FIRST; id <= CGN_ALG_LAST; id++) {
		uint8_t id_bit = CGN_ALG_BIT(id);

		/* Temporary while PPTP is only alg available in Yang */
		if (id != CGN_ALG_PPTP && (cgn_alg_enabled & id_bit) == 0)
			continue;

		jsonw_name(json, cgn_alg_id_name(id));
		jsonw_start_object(json);

		jsonw_uint_field(
			json, "ctrl_sessions_crtd",
			cgn_alg_stats_read(id, CAS_CTRL_SESS_CRTD));
		jsonw_uint_field(
			json, "data_sessions_crtd",
			cgn_alg_stats_read(id, CAS_DATA_SESS_CRTD));
		jsonw_uint_field(
			json, "ctrl_sessions_dstd",
			cgn_alg_stats_read(id, CAS_CTRL_SESS_DSTD));
		jsonw_uint_field(
			json, "data_sessions_dstd",
			cgn_alg_stats_read(id, CAS_DATA_SESS_DSTD));

		jsonw_end_object(json);
	}

	jsonw_end_object(json);
}

static void cgn_alg_show_summary(json_writer_t *json)
{
	jsonw_name(json, "summary");
	jsonw_start_object(json);

	cgn_alg_show_status(json);

	jsonw_name(json, "stats");
	jsonw_start_object(json);

	cgn_alg_show_inspect_stats(json);
	cgn_alg_show_session_stats(json);

	jsonw_end_object(json);
	jsonw_end_object(json);
}

/*
 * Show ALG
 */
void cgn_alg_show(FILE *f, int argc, char **argv)
{
	json_writer_t *json;

	/* Remove "cgn-op show alg" */
	argc -= 3;
	argv += 3;

	json = jsonw_new(f);
	if (!json)
		return;

	jsonw_name(json, "alg");
	jsonw_start_object(json);

	/* Default to show status */
	if (argc == 0 || !strcmp(argv[0], "status"))
		cgn_alg_show_status(json);

	if (argc >= 1 && !strcmp(argv[0], "summary"))
		cgn_alg_show_summary(json);

	if (argc >= 1 && !strcmp(argv[0], "pinholes")) {
		enum cgn_alg_id id = CGN_ALG_NONE;

		if (argc >= 2)
			id = cgn_alg_name2id(argv[1]);

		cgn_alg_show_pinholes(json, id);
	}

	jsonw_end_object(json);
	jsonw_destroy(&json);
}

/*
 * Add select ALG counts to the CGNAT summary json
 */
void cgn_alg_cgnat_summary(struct json_writer *json)
{
	uint64_t count;

	count = alg_rc_read(CGN_DIR_OUT, ALG_OK_PPTP);
	jsonw_uint_field(json, "alg_pptp_out", count);

	count = alg_rc_read(CGN_DIR_IN, ALG_OK_PPTP);
	jsonw_uint_field(json, "alg_pptp_in", count);

}

static void cgn_alg_clear_inspect_stats(void)
{
	int rc;

	for (rc = ALG_RC_FIRST; rc <= ALG_RC_LAST; rc++) {
		alg_rc_clear(CGN_DIR_OUT, rc);
		alg_rc_clear(CGN_DIR_IN, rc);
	}
}

static void cgn_alg_clear_session_stats(void)
{
	enum cgn_alg_id id;

	for (id = CGN_ALG_FIRST; id <= CGN_ALG_LAST; id++)
		cgn_alg_stats_clear(id);
}

/*
 * Clear ALG
 */
void cgn_alg_clear(int argc, char **argv)
{
	/* Remove "cgn-op clear alg" */
	argc -= 3;
	argv += 3;

	if (argc == 0 || !strcmp(argv[0], "stats")) {
		if (argc < 2 || !strcmp(argv[1], "inspect"))
			cgn_alg_clear_inspect_stats();

		if (argc < 2 || !strcmp(argv[1], "session"))
			cgn_alg_clear_session_stats();
	}
}

/**************************************************************************
 * Initialisation
 **************************************************************************/

/*
 * Called via DP_EVT_INIT event handler
 */
void cgn_alg_init(void)
{
	alg_rc_init();
	cgn_alg_stats_init();
}

/*
 * Called via DP_EVT_UNINIT event handler
 */
void cgn_alg_uninit(void)
{
	alg_pinhole_uninit();
	alg_rc_uninit();
	cgn_alg_stats_uninit();
}
