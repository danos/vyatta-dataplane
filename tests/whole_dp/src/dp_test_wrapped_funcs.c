/*-
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * The DPDK functions that we wrap to allow us to provide our
 * own test versions. Also includes some of the required functions
 * that we do not link in, but that do need implementations.
 */

#include <time.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include "netlink.h"
#include <linux/rtnetlink.h>
#include <libmnl/libmnl.h>
#include <czmq.h>
#include <syslog.h>
#include <rte_branch_prediction.h>
#include "rte_log.h"
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_launch.h>
#include <rte_mempool.h>

#include "vplane_debug.h"
#include "ip_funcs.h"
#include "in_cksum.h"

#include "if_var.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"

unsigned int proc_pagemap_readable;

int __wrap_RAND_bytes(unsigned char *buf, int num)
{
	static unsigned char iv[] = {
		0x64, 0xc8, 0x6e, 0x89, 0x53, 0x45, 0x54, 0xd6,
		0xb1, 0x0c, 0x8c, 0xca, 0xc4, 0x44, 0xbf, 0xd3};
	dp_test_assert_internal((unsigned int)num <= sizeof(iv));
	int i;

	for (i = 0; i < num; i++)
		*(buf + i) = iv[i];
	return 1;
}

struct rte_mempool *__wrap_rte_pktmbuf_pool_create(
	const char *name, unsigned int n, unsigned int cache_size,
	uint16_t priv_size, uint16_t data_room_size, int socket_id)
{
	struct rte_pktmbuf_pool_private mbp_priv;
	unsigned int elt_size;

	if (RTE_ALIGN(priv_size, RTE_MBUF_PRIV_ALIGN) != priv_size) {
		RTE_LOG(ERR, MBUF, "mbuf priv_size=%u is not aligned\n",
			priv_size);
		rte_errno = EINVAL;
		return NULL;
	}
	elt_size = sizeof(struct rte_mbuf) + (unsigned int)priv_size +
		(unsigned int)data_room_size;
	mbp_priv.mbuf_data_room_size = data_room_size;
	mbp_priv.mbuf_priv_size = priv_size;

	return rte_mempool_create(name, n, elt_size, cache_size,
				  sizeof(struct rte_pktmbuf_pool_private),
				  rte_pktmbuf_pool_init, &mbp_priv,
				  rte_pktmbuf_init, NULL,
				  socket_id, MEMPOOL_F_NO_IOVA_CONTIG);
}

struct rte_mempool *__wrap_rte_mempool_create(
	const char *name, unsigned int n, unsigned int elt_size,
	unsigned int cache_size, unsigned int private_data_size,
	rte_mempool_ctor_t *mp_init, void *mp_init_arg,
	rte_mempool_obj_cb_t *obj_init, void *obj_init_arg,
	int socket_id, unsigned int flags)
{
	return __real_rte_mempool_create(name, n, elt_size, cache_size,
					 private_data_size, mp_init,
					 mp_init_arg, obj_init, obj_init_arg,
					 socket_id,
					 flags | MEMPOOL_F_NO_IOVA_CONTIG);
}

int __wrap_rte_eal_init(int argc, char **argv)
{
	int ret = __real_rte_eal_init(argc, argv);
	dp_test_intf_dpdk_init();
	return ret;
}

FILE *__wrap_popen(const char *command, const char *type)
{
	return NULL;
}

int __wrap_pclose(FILE *stream)
{
	return 0;
}

uint32_t dp_test_sys_update;

uint32_t __wrap_sysinfo(struct sysinfo *s_info)
{
	s_info->uptime = dp_test_sys_update;
	return 0;
}

void dp_test_sys_uptime_inc(uint32_t inc)
{
	dp_test_sys_update += inc;
}
