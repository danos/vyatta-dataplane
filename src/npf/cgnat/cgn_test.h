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

/*
 * The following fetch json strings directly without going through opd
 */
struct cgn_sess_fltr;

void cgn_ut_show_sessions(char **buf, size_t *bufsz, struct cgn_sess_fltr *fltr);

#endif /* CGN_TEST_H */
