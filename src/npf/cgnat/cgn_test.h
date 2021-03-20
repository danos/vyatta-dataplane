/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _CGN_TEST_H_
#define _CGN_TEST_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "npf/cgnat/cgn_dir.h"

/*
 * Used by CGNAT unit-tests only
 */

struct ifnet;
struct rte_mbuf;

void dp_test_npf_clear_cgnat(void);
bool ipv4_cgnat_test(struct rte_mbuf **mbufp, struct ifnet *ifp,
		     enum cgn_dir dir, int *error);
size_t cgn_session_size(void);
size_t cgn_sess2_size(void);

#endif
