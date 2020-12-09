/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Program the dataplane by sending console commands
 */
#ifndef _DP_TEST_CMD_STATE_H_
#define _DP_TEST_CMD_STATE_H_

#include <stdint.h>

struct dp_test_port_range {
	uint16_t start;
	uint16_t end;
};

void
dp_test_cmd_replace_dnat(int rule_num, const char *ifname, const char *orig_ip,
			 const char *dnat_ip, uint8_t proto,
			 uint16_t dnat_port);
void
dp_test_cmd_delete_dnat(int rule_num, const char *ifname,
			const char *orig_ip, uint8_t proto);
void
dp_test_cmd_replace_snat(int rule_num, const char *ifname, const char *orig_ip,
			 const char *snat_ip, struct dp_test_port_range *ports);
void
dp_test_cmd_delete_snat(int rule_num, const char *ifname, const char *orig_ip);

void
_dp_test_neigh_clear_entry(const char *ifname, const char *ipaddr,
			   const char *file, const char *func,
			   int line);
#define dp_test_neigh_clear_entry(ifname, ipaddr) \
	_dp_test_neigh_clear_entry(ifname, ipaddr, __FILE__, __func__, __LINE__)

#endif /* _DP_TEST_CMD_STATE_H_ */
