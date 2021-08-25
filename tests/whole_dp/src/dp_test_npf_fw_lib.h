/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane test npf firewall library
 */

#ifndef __DP_TEST_NPF_FW_LIB_H__
#define __DP_TEST_NPF_FW_LIB_H__

#include <stdint.h>
#include <stdbool.h>
#include <json-c/json.h>

#include "dp_test_lib_pkt.h"
#include "dp_test_npf_lib.h"

/*
 * Zone test config structure
 *
 * Simple zone config for two interface zones and a local zone.  Example:
 *
 *	struct dpt_zone_cfg cfg = {
 *		.private = {
 *			.name = "PRIVATE",
 *			.intf = { "dp1T0", "dp1T1", NULL },
 *			.local = false,
 *		},
 *		.public = {
 *			.name = "PUBLIC",
 *			.intf = { "dp1T2", "dp1T3", NULL },
 *			.local = false,
 *		},
 *		.pub_to_priv = {
 *			.name		= "PUB_TO_PRIV",
 *			.pass		= BLOCK,
 *			.stateful	= STATELESS,
 *			.npf		= "",
 *		},
 *		.local = { 0 },
 *		.priv_to_pub = {
 *			.name		= "PRIV_TO_PUB",
 *			.pass		= PASS,
 *			.stateful	= STATELESS,
 *			.npf		= "",
 *		},
 *		.local_to_priv = { 0 },
 *		.priv_to_local = { 0 },
 *		.local_to_pub = { 0 },
 *		.pub_to_local = { 0 },
 *	};
 *
 *	dpt_zone_cfg(&cfg, true, false); // enable
 *	dpt_zone_cfg(&cfg, false, false); // disable
 *
 */
#define INTF_PER_ZONE 3

struct dpt_zone {
	/* Zone name */
	const char *name;

	/* Zone member interfaces */
	const char *intf[INTF_PER_ZONE];

	/* Local zone if true */
	bool        local;
};

/* Zone ruleset and rule variables */
struct dpt_zone_rule {
	const char  *name;	/* No rule added if NULL */
	bool         pass;	/* BLOCK or PASS */
	bool         stateful;	/* STATELESS or STATEFUL */
	const char  *npf;	/* npf rule */
};

struct dpt_zone_cfg {
	struct dpt_zone		private;
	struct dpt_zone		public;
	struct dpt_zone		local;
	struct dpt_zone_rule	pub_to_priv;
	struct dpt_zone_rule	priv_to_pub;
	struct dpt_zone_rule	local_to_priv;
	struct dpt_zone_rule	priv_to_local;
	struct dpt_zone_rule	local_to_pub;
	struct dpt_zone_rule	pub_to_local;
};

void dpt_zone_cfg(struct dpt_zone_cfg *cfg, bool add, bool debug);

void _dp_test_zone_add(const char *zname, const char *file, int line);

#define dp_test_zone_add(name) \
	_dp_test_zone_add(name, __FILE__, __LINE__)


void _dp_test_zone_remove(const char *zname, const char *file, int line);

#define dp_test_zone_remove(name)			\
	_dp_test_zone_remove(name, __FILE__, __LINE__)

void _dp_test_zone_local(const char *zname, bool set,
			 const char *file, int line);

#define dp_test_zone_local(name, set)				\
	_dp_test_zone_local(name, set, __FILE__, __LINE__)


void _dp_test_zone_policy_add(const char *zone, const char *policy,
			      const char *file, int line);

#define dp_test_zone_policy_add(zn, pl)				\
	_dp_test_zone_policy_add(zn, pl, __FILE__, __LINE__)


void _dp_test_zone_policy_del(const char *zone, const char *policy,
			      const char *file, int line);

#define dp_test_zone_policy_del(zn, pl)				\
	_dp_test_zone_policy_del(zn, pl, __FILE__, __LINE__)

/*
 * Add a zone
 */
void _dp_test_zone_intf_add(const char *zname, const char *ifname,
			    const char *file, int line);

#define dp_test_zone_intf_add(zn, ifn)				\
	_dp_test_zone_intf_add(zn, ifn, __FILE__, __LINE__)


void _dp_test_zone_intf_del(const char *zname, const char *ifname,
			    const char *file, int line);

#define dp_test_zone_intf_del(zn, ifn)				\
	_dp_test_zone_intf_del(zn, ifn, __FILE__, __LINE__)


/*
 * Address group
 */
void
_dp_test_npf_fw_addr_group_add(const char *table, const char *file, int line);

#define dp_test_npf_fw_addr_group_add(table)				\
	_dp_test_npf_fw_addr_group_add(table, __FILE__, __LINE__)

void
_dp_test_npf_fw_addr_group_del(const char *table, const char *file, int line);

#define dp_test_npf_fw_addr_group_del(table)				\
	_dp_test_npf_fw_addr_group_del(table, __FILE__, __LINE__)

void
_dp_test_npf_fw_addr_group_addr_add(const char *table, const char *addr,
				    const char *file, int line);

#define dp_test_npf_fw_addr_group_addr_add(table, addr)			\
	_dp_test_npf_fw_addr_group_addr_add(table, addr, __FILE__, __LINE__)

void
_dp_test_npf_fw_addr_group_range_add(const char *table, const char *start,
				     const char *end, const char *file,
				     int line);

#define dp_test_npf_fw_addr_group_range_add(table, start, end)		\
	_dp_test_npf_fw_addr_group_range_add(table, start, end,		\
					     __FILE__, __LINE__)

void
_dp_test_npf_fw_addr_group_range_del(const char *table, const char *start,
				     const char *end, const char *file,
				     int line);

#define dp_test_npf_fw_addr_group_range_del(table, start, end)		\
	_dp_test_npf_fw_addr_group_range_del(table, start, end,		\
					     __FILE__, __LINE__)

void
_dp_test_npf_fw_addr_group_addr_del(const char *table, const char *addr,
				    const char *file, int line);

#define dp_test_npf_fw_addr_group_addr_del(table, addr)			\
	_dp_test_npf_fw_addr_group_addr_del(table, addr, __FILE__, __LINE__)

#define NPF_ZONES_SHOW_INTFS 0x01
#define NPF_ZONES_SHOW_POLS  0x02
#define NPF_ZONES_SHOW_RSETS 0x04
#define NPF_ZONES_SHOW_ALL   (NPF_ZONES_SHOW_INTFS | NPF_ZONES_SHOW_POLS | \
			      NPF_ZONES_SHOW_RSETS)

/*
 * Add a port group
 *
 * name - Port group name.  Must start with "$p", e.g. "$pPG1"
 * port - Numbered port, port range, or service name e.g. "http"
 *
 * Adding a port group overwrites any previous command.  i.e.
 * if you want to change port group from port 10 to port 10 and 20
 * you would set port string to "10,20".
 */
void
_dp_test_npf_fw_port_group_add(const char *name, const char *port,
			       const char *file, int line);

#define dp_test_npf_fw_port_group_add(name, port)			\
	_dp_test_npf_fw_port_group_add(name, port, __FILE__, __LINE__)

void
_dp_test_npf_fw_port_group_del(const char *name,
			       const char *file, int line);

#define dp_test_npf_fw_port_group_del(name)				\
	_dp_test_npf_fw_port_group_del(name, __FILE__, __LINE__)

/*
 * Utilities for parsing the json output of "npf fw list"
 */

/*
 * Return the json object for a specific firewall zone group
 *
 * The returned json object has its ref count incremented, so json_object_put
 * should be called once the caller has finished with the object.
 */
json_object *
dp_test_npf_json_get_fw_zone(const char *name, const char *from_intf,
			     const char *to_intf);

/*
 * Wrapper around UDP test packet
 */
void
_dpt_udp(const char *rx_intf, const char *pre_smac,
	 const char *pre_saddr, uint16_t pre_sport,
	 const char *pre_daddr, uint16_t pre_dport,
	 const char *post_saddr, uint16_t post_sport,
	 const char *post_daddr, uint16_t post_dport,
	 const char *post_dmac, const char *tx_intf,
	 int status, int pre_vlan, int post_vlan,
	 const char *pre_pl, int pre_len,
	 const char *post_pl, int post_len,
	 const char *file, const char *func, int line);

#define dpt_udp(_a, _b, _c, _d, _e, _f, _g, _h,				\
		_i, _j, _k, _l, _m)					\
	_dpt_udp(_a, _b, _c, _d, _e, _f, _g, _h,			\
		 _i, _j, _k, _l, _m, 0, 0,				\
		 NULL, 0, NULL, 0,					\
		 __FILE__, __func__, __LINE__)

#define dpt_vlan_udp(_a, _b, _c, _d, _e, _f, _g, _h,			\
		     _i, _j, _k, _l, _m, _n, _o)			\
	_dpt_udp(_a, _b, _c, _d, _e, _f, _g, _h,			\
		 _i, _j, _k, _l, _m, _n, _o,				\
		 NULL, 0, NULL, 0,					\
		 __FILE__, __func__, __LINE__)

#define dpt_udp_pl(_a, _b, _c, _d, _e, _f, _g, _h,			\
		   _i, _j, _k, _l, _m, _n, _o, _p, _q, _r)		\
	_dpt_udp(_a, _b, _c, _d, _e, _f, _g, _h,			\
		 _i, _j, _k, _l, _m, 0, 0,				\
		 _n, _o, _p, _q,					\
		 __FILE__, _r ? _r : __func__, __LINE__)


void
_dpt_tcp(uint8_t flags,
	 const char *rx_intf, const char *pre_smac,
	 const char *pre_saddr, uint16_t pre_sport,
	 const char *pre_daddr, uint16_t pre_dport,
	 const char *post_saddr, uint16_t post_sport,
	 const char *post_daddr, uint16_t post_dport,
	 const char *post_dmac, const char *tx_intf,
	 int status, int pre_vlan, int post_vlan,
	 const char *file, const char *func, int line);

#define dpt_tcp(_a, _b, _c, _d, _e, _f, _g, _h,				\
		_i, _j, _k, _l, _m, _n)					\
	_dpt_tcp(_a, _b, _c, _d, _e, _f, _g, _h,			\
		 _i, _j, _k, _l, _m, _n, 0, 0,				\
		 __FILE__, __func__, __LINE__)

void
_dpt_icmp(uint8_t icmp_type,
	  const char *rx_intf, const char *pre_smac,
	  const char *pre_saddr, uint16_t pre_icmp_id,
	  const char *pre_daddr,
	  const char *post_saddr, uint16_t post_icmp_id,
	  const char *post_daddr,
	  const char *post_dmac, const char *tx_intf,
	  int status, int pre_vlan, int post_vlan,
	  const char *file, const char *func, int line);

#define dpt_icmp(_a, _b, _c, _d, _e, _f, _g, _h,			\
		 _i, _j, _k, _l)					\
	_dpt_icmp(_a, _b, _c, _d, _e, _f, _g,				\
		  _h, _i, _j, _k, _l, 0, 0,				\
		  __FILE__, __func__, __LINE__)

/*
 * Enhanced GRE packet (eth:ip:gre:?).   Used for PPTP.
 *
 * payload is the optional payload to add after the enhanced GRE header
 */
void
_dpt_gre(const char *rx_intf, const char *pre_smac,
	 const char *pre_saddr, uint16_t pre_call_id,
	 const char *pre_daddr,
	 const char *post_saddr, uint16_t post_call_id,
	 const char *post_daddr,
	 const char *post_dmac, const char *tx_intf,
	 int status, char *payload, uint plen,
	 const char *file, const char *func, int line);

#define dpt_gre(_a, _b, _c, _d, _e, _f, _g, _h,				\
		_i, _j, _k, _l, _m)					\
	_dpt_gre(_a, _b, _c, _d, _e, _f, _g,				\
		 _h, _i, _j, _k, _l, _m,				\
		 __FILE__, __func__, __LINE__)

#endif /* DP_TEST_NPF_FW_LIB_H */
