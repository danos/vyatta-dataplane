/*
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane test npf firewall library
 */

#ifndef __DP_TEST_NPF_PORTMAP_LIB_H__
#define __DP_TEST_NPF_PORTMAP_LIB_H__

#include <stdint.h>
#include <stdbool.h>
#include <json-c/json.h>

#include "dp_test_npf_lib.h"

/*
 * Returns true successfully if the portmap "state" string is retrieved ok
 */
bool
dp_test_npf_json_get_portmap_state(const char *addr, char **state);

/*
 * Returns true if the portmap "used" count as retrieved ok
 */
bool
dp_test_npf_json_get_portmap_used(const char *addr, uint *used);

void
dp_test_npf_print_portmap(void);

/*
 * Verify portmap state and/or used count
 */
void
_dp_test_npf_portmap_verify(const char *addr, const char *state, uint used,
			    const char *file, int line);

#define dp_test_npf_portmap_verify(addr, state, used)			\
	_dp_test_npf_portmap_verify(addr, state, used, __FILE__, __LINE__)

/*
 * Verify portmap port
 */
void
_dp_test_npf_portmap_port_verify(const char *addr, uint16_t port,
				 bool expected,
				 const char *file, int line);

#define dp_test_npf_portmap_port_verify(addr, port)			\
	_dp_test_npf_portmap_port_verify(addr, port, true, __FILE__, __LINE__)

#define dp_test_npf_portmap_port_free_verify(addr, port)		\
	_dp_test_npf_portmap_port_verify(addr, port, false, __FILE__, __LINE__)

#endif /* __DP_TEST_NPF_PORTMAP_LIB_H__ */
