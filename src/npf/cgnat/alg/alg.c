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

/*
 * Bitmap of enabled ALGs (CGN_ALG_BIT_FTP etc.)
 */
static uint8_t cgn_alg_enabled;

/*
 * Well-known TCP/UDP ports
 */
#define FTP_PORT	21
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

static const char *_cgn_alg_id_name[CGN_ALG_MAX] = {
	[CGN_ALG_NONE] = "-",
	[CGN_ALG_FTP]  = "ftp",
	[CGN_ALG_PPTP] = "pptp",
	[CGN_ALG_SIP]  = "sip",
};

static enum cgn_alg_id cgn_alg_name2id(const char *name)
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
	case CGN_ALG_FTP:
		apt_dport_add(CGN_ALG_FTP, NAT_PROTO_TCP, FTP_PORT);
		break;
	case CGN_ALG_PPTP:
		apt_dport_add(CGN_ALG_PPTP, NAT_PROTO_TCP, PPTP_PORT);
		break;
	case CGN_ALG_SIP:
		apt_dport_add(CGN_ALG_SIP, NAT_PROTO_UDP, SIP_PORT);
		apt_dport_add(CGN_ALG_SIP, NAT_PROTO_TCP, SIP_PORT);
		break;
	};

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
	case CGN_ALG_FTP:
		apt_dport_del(CGN_ALG_FTP, NAT_PROTO_TCP);
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
