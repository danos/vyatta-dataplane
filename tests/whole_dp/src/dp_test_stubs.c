/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.
 * All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Stubs for the parts of the dataplane that we don't link in
 * to the test image.
 */

#include <stdbool.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <rte_mbuf.h>
#include <sys/types.h>

#include "json_writer.h"
#include "main.h"
#include "if_var.h"
#include "ip_funcs.h"
#include "shadow.h"
#include "netlink.h"
#include "npf_shim.h"
#include "commands.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "capture.h"

#include "dp_test.h"

int spath_pipefd[2] = {0};
int shadow_pipefd[DATAPLANE_MAX_PORTS] = {0};

void capture_hardware(const struct ifnet *ifp, struct rte_mbuf *mbuf)
{
}

void
capture_burst(const struct ifnet *ifp, struct rte_mbuf *pkts[], unsigned int n)
{
	/* nothing to do */
}

void capture_cancel(struct ifnet *ifp)
{
	/* nothing to do */
}

int cmd_capture(FILE *f, int argc, char **argv)
{
	return 0;
}

int slowpath_init(void)
{
	if (pipe(spath_pipefd) == -1)
		return 101;

	shadow_init_spath_ring(spath_pipefd[0]);
	return spath_pipefd[0];
}

void capture_init(uint16_t mbuf_sz)
{
	/* nothing to do */
}

void capture_destroy(void)
{
}

int
rtnl_process_team(const struct nlmsghdr *nlh, void *data __unused)
{
	return 0;
}

void ip_id_init(void)
{
}

uint16_t dp_ip_randomid(uint16_t salt)
{
	return 0;
}

/* Packet entrypoint for packets coming from kernel on to shadow tun devices */
int tap_receive(zloop_t *loop, zmq_pollitem_t *item,
		       struct shadow_if_info *sii, struct rte_mbuf **pkt)
{
	char buf[1];

	read(sii->fd, buf, 1);
	if (dp_test_read_pkt_available()) {
		*pkt = dp_test_get_read_pkt();
		return 1;
	}

	return 0;
}

/* Packet entry point for .spath in VR */
int spath_receive(zmq_pollitem_t *item, struct tun_pi *pi,
		  struct tun_meta *meta, struct shadow_if_info *sii,
		  struct rte_mbuf **mbuf)
{
	char buf[1];

	read(spath_pipefd[0], buf, 1);
	if (dp_test_read_pkt_available()) {

		*mbuf = dp_test_get_read_pkt();
		pi->proto = dp_test_get_read_proto();

		meta->flags = dp_test_get_read_meta_flags();
		meta->iif = dp_test_get_read_meta_iif();

		return 1;
	}

	return 0;
}

/* VR case: Packet coming for dpdk interfaces.
 * Send the packet directly for validation.
 */
int tuntap_write(int fd, struct rte_mbuf *m, struct ifnet *ifp)
{
	struct shadow_if_info *sii = get_fd2shadowif(fd);
	struct ifnet *ifp_phys;

	if (!sii)
		return -1;

	for (ifp_phys = ifp;
	     ifp_phys->if_type == IFT_L2VLAN;
	     ifp_phys = ifp_phys->if_parent)
		;
	/* we could get bridge interface packets being passed up here as well */
	assert(ifp->if_type != IFT_ETHER || ifp->if_port == sii->port);

	dp_test_pak_verify(m, ifp, dp_test_global_expected,
			   DP_TEST_FWD_LOCAL);
	return 0;
}

/* TODO: This can be removed in future to use the actual function in the source
 * code. For now returning true to make sure the packet is not dropped. However
 * the side effect is in some cases packet metadata is not set.
 */
bool local_packet_filter(const struct ifnet *ifp, struct rte_mbuf *m)
{
	return true;
}

int tap_attach(const char *ifname)
{
	int pipefd[2];
	portid_t portid = dp_test_intf_name2port(ifname);

	/* Create pipe as a signaliing mechanism between UT and the source code
	 * zloop for shadow interface packets
	 */
	if (pipe(pipefd) == -1)
		return 0;

	/* Store the write side. Read fd will come back to us through sii */
	shadow_pipefd[portid] = pipefd[1];

	return pipefd[0];
}

/* There is no syslog running in the whole_dp UT environment */
/* NOLINTNEXTLINE(readability-inconsistent-declaration-parameter-name) */
void syslog(int priority, const char *format, ...)
{
	char log_buf[DP_TEST_TMP_BUF];
	va_list ap;

	va_start(ap, format);
	vsnprintf(log_buf, sizeof(log_buf), format, ap);
	va_end(ap);

	printf("%s\n", log_buf);

}
