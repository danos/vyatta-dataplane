/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
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

#include "dp_test_npf_lib.h"

const char *
dp_test_npf_fw_str(struct dp_test_npf_ruleset_t *fw);

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

#endif
