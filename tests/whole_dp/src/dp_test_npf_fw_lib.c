/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
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
#include "dp_test_lib.h"
#include "dp_test_lib_intf.h"
#include "dp_test_pktmbuf_lib.h"
#include "dp_test_netlink_state.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_fw_lib.h"


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
