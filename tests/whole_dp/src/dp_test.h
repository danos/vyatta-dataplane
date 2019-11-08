/*-
 * Copyright (c) 2017, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _DP_TEST_H_
#define _DP_TEST_H_

/*
 * These test build on the Check package.
 * If, for some reason this hasn't been pulled in automatically try
 * 'sudo apt-get install check' or better download and build the
 * tarball because then you get a more up to date version.  The
 * debian7 package lacks support for selecting specific tests and has
 * less good error handling.
 */
#include <check.h>
#include <stdio.h>
#include "dp_test_cmd_check.h"
#include "dp_test_macros.h"


#include "if_var.h"

#define DP_TEST_TMP_BUF 2048
#define DP_TEST_TMP_BUF_SMALL 100
#define DP_TEST_INTF_BUF IFNAMSIZ

char *dp_test_pname; /* Program name for logging */
extern struct rte_mempool *dp_test_pool;

/*
 * Base names for the rings used to rx/tx packets to/from the
 * null pmd drivers.  2 digits are added to the base name to
 * define a ring per device.
 */
#define DP_TEST_RX_RING_BASE_NAME "nullrx_"
#define DP_TEST_TX_RING_BASE_NAME "nulltx_"

int dp_test_debug_get(void);

/* The entry point into the dataplane test process */
int dataplane_test_main(int argc, char **argv);
int dp_test_run_tests(void *ctx);
Suite *dp_test_get_suite(const char *filename);

int __wrap_main(int argc, char **argv);
int __real_main(int argc, char **argv);
int __wrap_RAND_bytes(unsigned char *buf, int num);
struct rte_mempool *__wrap_rte_pktmbuf_pool_create(
	const char *name, unsigned int n, unsigned int cache_size,
	uint16_t priv_size, uint16_t data_room_size, int socket_id);
struct rte_mempool *__wrap_rte_mempool_create(
	const char *name, unsigned int n, unsigned int elt_size,
	unsigned int cache_size, unsigned int private_data_size,
	rte_mempool_ctor_t *mp_init, void *mp_init_arg,
	rte_mempool_obj_cb_t *obj_init, void *obj_init_arg,
	int socket_id, unsigned int flags);
struct rte_mempool *__real_rte_mempool_create(
	const char *name, unsigned int n, unsigned int elt_size,
	unsigned int cache_size, unsigned int private_data_size,
	rte_mempool_ctor_t *mp_init, void *mp_init_arg,
	rte_mempool_obj_cb_t *obj_init, void *obj_init_arg,
	int socket_id, unsigned int flags);
int __wrap_rte_eal_init(int argc, char **argv);
int __real_rte_eal_init(int argc, char **argv);
FILE *__wrap_popen(const char *command, const char *type);
int __wrap_pclose(FILE *stream);

#endif /* _DP_TEST_H_ */
