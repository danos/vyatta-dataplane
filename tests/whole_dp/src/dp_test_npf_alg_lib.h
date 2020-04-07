/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane test npf library
 */

#ifndef __DP_TEST_NPF_ALG_LIB_H__
#define __DP_TEST_NPF_ALG_LIB_H__

#include <stdint.h>
#include <stdbool.h>

#include "dp_test_json_utils.h"

/*
 * Add or delete an ALG port
 */
void
_dp_test_npf_set_alg_port(uint iid, const char *name, uint16_t port,
			  const char *file, int line);

#define dp_test_npf_set_alg_port(iid, name, port)			\
	_dp_test_npf_set_alg_port(iid, name, port, __FILE__, __LINE__)

void
_dp_test_npf_delete_alg_port(uint iid, const char *name, uint16_t port,
			  const char *file, int line);

#define dp_test_npf_delete_alg_port(iid, name, port)			\
	_dp_test_npf_delete_alg_port(iid, name, port, __FILE__, __LINE__)

/*
 * Verify that an ALF tuple exists
 *
 * Optional fields: sport, srcip, dstip
 */
void
_dp_test_npf_alg_tuple_verify(uint npf_id, const char *alg, uint8_t proto,
			      uint16_t dport, uint16_t sport,
			      const char *dstip, const char *srcip,
			      const char *file, int line);

#define dp_test_npf_alg_tuple_verify(npf_id, alg, proto, dport, sport,	\
				     dstip, srcip)			\
	_dp_test_npf_alg_tuple_verify(npf_id, alg, proto, dport, sport, \
				      dstip, srcip,			\
				      __FILE__, __LINE__)

void
dp_test_npf_print_alg_tuples(const char *desc);

#endif
