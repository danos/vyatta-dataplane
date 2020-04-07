/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane test npf firewall library
 */

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_fw_lib.h"


/*
 * npf Zones
 */
static void dpt_zone_cfg_zone(struct dpt_zone *zn,
			      bool add, bool debug)
{
	char rname[IFNAMSIZ];
	uint i;

	if (!zn || !zn->name)
		return;

	if (add) {
		dp_test_npf_cmd_fmt(debug, "npf-ut zone add %s", zn->name);
		if (zn->local)
			dp_test_npf_cmd_fmt(debug, "npf-ut zone local %s set",
					    zn->name);

		/* Add interfaces to zone */
		for (i = 0; i < ARRAY_SIZE(zn->intf); i++) {
			if (!zn->intf[i])
				continue;

			dp_test_npf_cmd_fmt(debug,
					    "npf-ut zone intf add %s %s",
					    zn->name,
					    dp_test_intf_real(zn->intf[i],
							      rname));
		}
	} else {
		for (i = 0; i < ARRAY_SIZE(zn->intf); i++) {
			if (!zn->intf[i])
				continue;

			dp_test_npf_cmd_fmt(debug,
					    "npf-ut zone intf remove %s %s",
					    zn->name,
					    dp_test_intf_real(zn->intf[i],
							      rname));
		}

		if (zn->local)
			dp_test_npf_cmd_fmt(debug, "npf-ut zone local %s clear",
					    zn->name);
		dp_test_npf_cmd_fmt(debug, "npf-ut zone remove %s", zn->name);
	}
}

static void
dpt_zone_cfg_rule(struct dpt_zone *from, struct dpt_zone *to,
		  struct dpt_zone_rule *rl, bool add, bool debug)
{
	char attach_point[100];

	if (!rl || !rl->name)
		return;

	snprintf(attach_point, sizeof(attach_point),
		 "%s>%s", from->name, to->name);

	struct dp_test_npf_rule_t  rule[] = {
		{
			.rule	= "1",
			.pass	= rl->pass,
			.stateful = rl->stateful,
			.npf	= rl->npf,
		},
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t rlset = {
		.rstype		= "zone",
		.name		= rl->name,
		.enable		= 1,
		.attach_point	= attach_point,
		.fwd		= 0,
		.dir		= "out",
		.rules		= rule
	};

	if (add) {
		dp_test_npf_cmd_fmt(debug, "npf-ut zone policy add %s %s",
				    from->name, to->name);

		dp_test_npf_fw_add(&rlset, debug);
	} else {
		dp_test_npf_fw_del(&rlset, debug);

		dp_test_npf_cmd_fmt(debug, "npf-ut zone policy remove %s %s",
				    from->name, to->name);
	}
}

static void dpt_zone_cfg_rules(struct dpt_zone_cfg *cfg, bool add, bool debug)
{
	dpt_zone_cfg_rule(&cfg->public, &cfg->private,
			  &cfg->pub_to_priv, add, debug);

	dpt_zone_cfg_rule(&cfg->private, &cfg->public,
			  &cfg->priv_to_pub, add, debug);

	dpt_zone_cfg_rule(&cfg->local, &cfg->private,
			  &cfg->local_to_priv, add, debug);

	dpt_zone_cfg_rule(&cfg->private, &cfg->local,
			  &cfg->priv_to_local, add, debug);

	dpt_zone_cfg_rule(&cfg->local, &cfg->public,
			  &cfg->local_to_pub, add, debug);

	dpt_zone_cfg_rule(&cfg->public, &cfg->local,
			  &cfg->pub_to_local, add, debug);
}

void dpt_zone_cfg(struct dpt_zone_cfg *cfg, bool add, bool debug)
{
	if (add) {
		dpt_zone_cfg_zone(&cfg->private, add, debug);
		dpt_zone_cfg_zone(&cfg->public, add, debug);
		dpt_zone_cfg_zone(&cfg->local, add, debug);

		dpt_zone_cfg_rules(cfg, add, debug);
	} else {
		dpt_zone_cfg_rules(cfg, add, debug);

		dpt_zone_cfg_zone(&cfg->private, add, debug);
		dpt_zone_cfg_zone(&cfg->public, add, debug);
		dpt_zone_cfg_zone(&cfg->local, add, debug);
	}
}


const char *
dp_test_zone_attach_point_name(const char *from_zone, const char *to_zone)
{
	static char name[100];

	spush(name, sizeof(name), "%s>%s", from_zone, to_zone);
	return name;
}

void
_dp_test_zone_add(const char *zname, const char *file, int line)
{
	char cmd[TEST_MAX_CMD_LEN];

	spush(cmd, sizeof(cmd), "npf-ut zone add %s", zname);

	_dp_test_npf_cmd(cmd, false, file, line);
}

void
_dp_test_zone_remove(const char *zname, const char *file, int line)
{
	char cmd[TEST_MAX_CMD_LEN];

	spush(cmd, sizeof(cmd), "npf-ut zone remove %s", zname);

	_dp_test_npf_cmd(cmd, false, file, line);
}

void
_dp_test_zone_local(const char *zname, bool set, const char *file, int line)
{
	char cmd[TEST_MAX_CMD_LEN];

	spush(cmd, sizeof(cmd), "npf-ut zone local %s %s",
	      zname, set ? "set" : "clear");

	_dp_test_npf_cmd(cmd, false, file, line);
}

void
_dp_test_zone_policy_add(const char *zone, const char *policy,
			 const char *file, int line)
{
	char cmd[TEST_MAX_CMD_LEN];

	spush(cmd, sizeof(cmd), "npf-ut zone policy add %s %s",
	      zone, policy);

	_dp_test_npf_cmd(cmd, false, file, line);
}

void
_dp_test_zone_policy_del(const char *zone, const char *policy,
			 const char *file, int line)
{
	char cmd[TEST_MAX_CMD_LEN];

	spush(cmd, sizeof(cmd), "npf-ut zone policy remove %s %s",
	      zone, policy);

	_dp_test_npf_cmd(cmd, false, file, line);
}

void
_dp_test_zone_intf_add(const char *zname, const char *ifname,
		       const char *file, int line)
{
	char cmd[TEST_MAX_CMD_LEN];
	char rname[IFNAMSIZ];

	spush(cmd, sizeof(cmd), "npf-ut zone intf add %s %s",
	      zname, dp_test_intf_real(ifname, rname));

	_dp_test_npf_cmd(cmd, false, file, line);
}

void
_dp_test_zone_intf_del(const char *zname, const char *ifname,
		       const char *file, int line)
{
	char cmd[TEST_MAX_CMD_LEN];
	char rname[IFNAMSIZ];

	spush(cmd, sizeof(cmd), "npf-ut zone intf remove %s %s",
	      zname, dp_test_intf_real(ifname, rname));

	_dp_test_npf_cmd(cmd, false, file, line);
}

static json_object *
dp_test_zone_json_get_zones(const char *zone, const char *policy,
			    uint8_t flags)
{
	json_object *jresp;
	char *response;
	bool err;
	char cmd[TEST_MAX_CMD_LEN];

	spush(cmd, sizeof(cmd),
	      "npf-op show zones %s %s %u",
	      zone ? zone : "all",
	      policy ? policy : "all", flags);

	response = dp_test_console_request_w_err(cmd, &err, false);
	if (!response || err) {
		printf("  no response\n");
		return NULL;
	}

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));

	if (!jresp) {
		printf("  failed to parse json\n");
		printf("%s\n", response);
		free(response);
		return NULL;
	}
	free(response);

	return jresp;
}

void
dp_test_zone_print_zones(const char *zone, const char *policy,
			 uint8_t flags)
{
	json_object *jobj;
	const char *str;

	jobj = dp_test_zone_json_get_zones(zone, policy, flags);
	if (!jobj) {
		printf("Zones not found\n");
		return;
	}

	str = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PRETTY);
	if (str)
		printf("%s\n", str);
	json_object_put(jobj);
}



/*
 * Create an address-group.  Table is a number string, e.g. "0" or "1".
 */
void
_dp_test_npf_fw_addr_group_add(const char *table,
			       const char *file, int line)
{
	_dp_test_npf_cmd_fmt(false, file, line,
			     "npf-ut fw table create %s", table);
}

/*
 * Delete an address-group
 */
void
_dp_test_npf_fw_addr_group_del(const char *table,
			       const char *file, int line)
{
	_dp_test_npf_cmd_fmt(false, file, line,
			    "npf-ut fw table delete %s", table);
}

/*
 * Add address to address-group.  Address may be an IPv4 or IPv6 address or
 * subnet/mask.
 */
void
_dp_test_npf_fw_addr_group_addr_add(const char *table, const char *addr,
				    const char *file, int line)
{
	_dp_test_npf_cmd_fmt(false, file, line,
			     "npf-ut fw table add %s %s", table, addr);
}

/*
 * Add address range to address-group.  Address may be an IPv4 or IPv6
 * addresses.
 */
void
_dp_test_npf_fw_addr_group_range_add(const char *table, const char *start,
				     const char *end,
				     const char *file, int line)
{
	_dp_test_npf_cmd_fmt(false, file, line,
			     "npf-ut fw table add %s %s %s",
			     table, start, end);
}

void
_dp_test_npf_fw_addr_group_range_del(const char *table, const char *start,
				     const char *end,
				     const char *file, int line)
{
	_dp_test_npf_cmd_fmt(false, file, line,
			     "npf-ut fw table remove %s %s %s",
			     table, start, end);
}

/*
 * Remove an address from an address-group
 */
void
_dp_test_npf_fw_addr_group_addr_del(const char *table, const char *addr,
				    const char *file, int line)
{
	_dp_test_npf_cmd_fmt(false, file, line,
			     "npf-ut fw table remove %s %s", table, addr);
}

/*
 * Add a port group
 *
 * name - Port group name
 * port - Numbered port, or port range
 *
 * Adding a port group overwrites any previous command.  i.e.
 * if you want to change port group from port 10 to port 10 and 20
 * you would set port string to "10,20".
 */
void
_dp_test_npf_fw_port_group_add(const char *name, const char *port,
			       const char *file, int line)
{
	_dp_test_npf_cmd_fmt(false, file, line,
			     "npf-ut add port-group:%s 0 %s",
				     name, port);
}

void
_dp_test_npf_fw_port_group_del(const char *name,
			       const char *file, int line)
{
	_dp_test_npf_cmd_fmt(false, file, line,
			     "npf-ut delete port-group:%s", name);
}


/*
 * Simple wrapper around receiving a UDP packet.
 *
 * 'post' params are optional (use if NATing etc.).
 *
 * e.g.
 *	dpt_udp("dp1T2", "aa:bb:cc:dd:3:a1", 0,
 *		 "3.3.3.11", 41003, "4.4.4.11", 1004,
 *		 NULL, 0, NULL, 0,
 *		 "aa:bb:cc:dd:4:a1", 0, "dp1T3",
 *		 DP_TEST_FWD_FORWARDED);
 *
 */
void
_dpt_udp(const char *rx_intf, const char *pre_smac,
	 const char *pre_saddr, uint16_t pre_sport,
	 const char *pre_daddr, uint16_t pre_dport,
	 const char *post_saddr, uint16_t post_sport,
	 const char *post_daddr, uint16_t post_dport,
	 const char *post_dmac, const char *tx_intf,
	 int status, int pre_vlan, int post_vlan,
	 const char *file, const char *func, int line)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak, *exp_pak;
	int len = 20;

	/*
	 * If tx_intf is NULL then assume pkt is intf to local.
	 * If rx_intf is NULL then assume pkt is local to intf.
	 */
	if (!rx_intf && !tx_intf)
		_dp_test_fail(file, line,
			      "Both rx_intf and tx_intf can be NULL");

	/* Pre IPv4 UDP packet */
	struct dp_test_pkt_desc_t pre_pkt_UDP = {
		.text       = "IPv4 UDP",
		.len        = len,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = pre_saddr,
		.l2_src     = pre_smac,
		.l3_dst     = pre_daddr,
		.l2_dst     = post_dmac,
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = pre_sport,
				.dport = pre_dport
			}
		},
		.rx_intf    = rx_intf ? rx_intf : tx_intf,
		.tx_intf    = tx_intf ? tx_intf : rx_intf,
	};

	/* If 'post' values NULL then use 'pre' values */
	bool use_pre = (post_saddr == NULL);

	/* Post IPv4 UDP packet */
	struct dp_test_pkt_desc_t post_pkt_UDP = {
		.text       = "IPv4 UDP",
		.len        = len,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = use_pre ? pre_saddr : post_saddr,
		.l2_src     = pre_smac,
		.l3_dst     = use_pre ? pre_daddr : post_daddr,
		.l2_dst     = post_dmac,
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = use_pre ? pre_sport : post_sport,
				.dport = use_pre ? pre_dport : post_dport
			}
		},
		.rx_intf    = pre_pkt_UDP.rx_intf,
		.tx_intf    = pre_pkt_UDP.tx_intf
	};

	/*
	 * If rx_intf is NULL then its local -> tx_intf
	 */
	if (rx_intf)
		test_pak = dp_test_v4_pkt_from_desc(&pre_pkt_UDP);
	else
		test_pak = dp_test_from_spath_v4_pkt_from_desc(&pre_pkt_UDP);

	exp_pak = dp_test_v4_pkt_from_desc(&post_pkt_UDP);
	test_exp = dp_test_exp_create(exp_pak);

	rte_pktmbuf_free(exp_pak);
	exp_pak = dp_test_exp_get_pak(test_exp);

	if (rx_intf && tx_intf) {
		/* intf -> intf */
		dp_test_exp_set_oif_name(test_exp, tx_intf);

		dp_test_pktmbuf_eth_init(exp_pak, post_dmac,
					 dp_test_intf_name2mac_str(tx_intf),
					 ETHER_TYPE_IPv4);
		dp_test_ipv4_decrement_ttl(exp_pak);

	} else if (!rx_intf && tx_intf) {
		/* local -> intf */
		dp_test_exp_set_oif_name(test_exp, tx_intf);

		dp_test_pktmbuf_eth_init(test_pak, post_dmac,
					 dp_test_intf_name2mac_str(tx_intf),
					 ETHER_TYPE_IPv4);

		dp_test_pktmbuf_eth_init(exp_pak, post_dmac,
					 dp_test_intf_name2mac_str(tx_intf),
					 ETHER_TYPE_IPv4);

	} else if (rx_intf && !tx_intf) {
		/* intf -> local */
		dp_test_pktmbuf_eth_init(exp_pak,
					 dp_test_intf_name2mac_str(rx_intf),
					 pre_smac,
					 ETHER_TYPE_IPv4);

		if (status == DP_TEST_FWD_FORWARDED)
			status = DP_TEST_FWD_LOCAL;
	}

	/* vlan */
	if (pre_vlan > 0)
		dp_test_pktmbuf_vlan_init(test_pak, pre_vlan);

	if (post_vlan > 0) {
		dp_test_exp_set_vlan_tci(test_exp, post_vlan);

		(void)dp_test_pktmbuf_eth_init(
			dp_test_exp_get_pak(test_exp),
			post_dmac,
			dp_test_intf_name2mac_str(tx_intf),
			ETHER_TYPE_IPv4);
	}

	dp_test_exp_set_fwd_status(test_exp, status);

	/* Run the test */
	if (rx_intf)
		/* intf -> intf or local */
		_dp_test_pak_receive(test_pak, rx_intf, test_exp,
				     file, func, line);
	else
		/* local -> intf */
		_dp_test_send_slowpath_pkt(test_pak, test_exp,
					   file, func, line);
}

/*
 * dpt_tcp
 */
void
_dpt_tcp(uint8_t flags, const char *rx_intf, const char *pre_smac,
	 const char *pre_saddr, uint16_t pre_sport,
	 const char *pre_daddr, uint16_t pre_dport,
	 const char *post_saddr, uint16_t post_sport,
	 const char *post_daddr, uint16_t post_dport,
	 const char *post_dmac, const char *tx_intf,
	 int status, int pre_vlan, int post_vlan,
	 const char *file, const char *func, int line)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak, *exp_pak;

	/* Pre IPv4 TCP packet */
	struct dp_test_pkt_desc_t pre_pkt_TCP = {
		.text       = "IPv4 TCP",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = pre_saddr,
		.l2_src     = pre_smac,
		.l3_dst     = pre_daddr,
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = pre_sport,
				.dport = pre_dport,
				.flags = flags,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = rx_intf,
		.tx_intf    = tx_intf
	};

	/* Post IPv4 TCP packet */
	struct dp_test_pkt_desc_t post_pkt_TCP = {
		.text       = "IPv4 TCP",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = post_saddr,
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = post_daddr,
		.l2_dst     = post_dmac,
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = post_sport,
				.dport = post_dport,
				.flags = flags,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = rx_intf,
		.tx_intf    = tx_intf
	};

	test_pak = dp_test_v4_pkt_from_desc(&pre_pkt_TCP);

	exp_pak = dp_test_v4_pkt_from_desc(&post_pkt_TCP);
	test_exp = dp_test_exp_from_desc(exp_pak, &post_pkt_TCP);
	rte_pktmbuf_free(exp_pak);

	/* vlan */
	if (pre_vlan > 0)
		dp_test_pktmbuf_vlan_init(test_pak, pre_vlan);

	if (post_vlan > 0) {
		dp_test_exp_set_vlan_tci(test_exp, post_vlan);

		(void)dp_test_pktmbuf_eth_init(
			dp_test_exp_get_pak(test_exp),
			post_dmac,
			dp_test_intf_name2mac_str(tx_intf),
			ETHER_TYPE_IPv4);
	}

	dp_test_exp_set_fwd_status(test_exp, status);

	_dp_test_pak_receive(test_pak, rx_intf, test_exp,
			     file, func, line);
}


/*
 * dpt_icmp
 */
void
_dpt_icmp(uint8_t icmp_type,
	  const char *rx_intf, const char *pre_smac,
	  const char *pre_saddr, uint16_t pre_icmp_id,
	  const char *pre_daddr,
	  const char *post_saddr, uint16_t post_icmp_id,
	  const char *post_daddr,
	  const char *post_dmac, const char *tx_intf,
	  int status, int pre_vlan, int post_vlan,
	  const char *file, const char *func, int line)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak, *exp_pak;

	/* Pre IPv4 ICMP packet */
	struct dp_test_pkt_desc_t pre_pkt_ICMP = {
		.text       = "IPv4 ICMP",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = pre_saddr,
		.l2_src     = pre_smac,
		.l3_dst     = pre_daddr,
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMP,
		.l4         = {
			.icmp = {
				.type = icmp_type,
				.code = 0,
				{
					.dpt_icmp_id = pre_icmp_id,
					.dpt_icmp_seq = 0,
				},
			}
		},
		.rx_intf    = rx_intf,
		.tx_intf    = tx_intf
	};

	/* Post IPv4 ICMP packet */
	struct dp_test_pkt_desc_t post_pkt_ICMP = {
		.text       = "Packet A, IPv4 ICMP",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = post_saddr,
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = post_daddr,
		.l2_dst     = post_dmac,
		.proto      = IPPROTO_ICMP,
		.l4         = {
			.icmp = {
				.type = icmp_type,
				.code = 0,
				{
					.dpt_icmp_id = post_icmp_id,
					.dpt_icmp_seq = 0,
				},
			}
		},
		.rx_intf    = rx_intf,
		.tx_intf    = tx_intf
	};

	test_pak = dp_test_v4_pkt_from_desc(&pre_pkt_ICMP);

	exp_pak = dp_test_v4_pkt_from_desc(&post_pkt_ICMP);
	test_exp = dp_test_exp_from_desc(exp_pak, &post_pkt_ICMP);
	rte_pktmbuf_free(exp_pak);

	/* vlan */
	if (pre_vlan > 0)
		dp_test_pktmbuf_vlan_init(test_pak, pre_vlan);

	if (post_vlan > 0) {
		dp_test_exp_set_vlan_tci(test_exp, post_vlan);

		(void)dp_test_pktmbuf_eth_init(
			dp_test_exp_get_pak(test_exp),
			post_dmac,
			dp_test_intf_name2mac_str(tx_intf),
			ETHER_TYPE_IPv4);
	}

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	_dp_test_pak_receive(test_pak, rx_intf, test_exp,
			     file, func, line);
}
