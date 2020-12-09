/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * dataplane UT Interface helpers
 */

#include <rte_eth_ring.h>
#include <rte_errno.h>

#include "dp_test_lib_intf_internal.h"

#include "dp_test.h"
#include "dp_test_console.h"
#include "dp_test_controller.h"
#include "dp_test_json_utils.h"
#include "dp_test_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_str.h"

/*
 * A note about interface names
 *
 * Tests are written using this interface format i.e. dp2T3
 * We call these the test interface names.
 *
 * The dataplane proper runs with
 *   VR format names when in VR mode i.e dpT23
 * We call these the real interface names.
 */

enum dp_test_intf_type_e
dp_test_intf_type(const char *if_name)
{
	dp_test_assert_internal(if_name != NULL);
	if (strncmp(if_name, "dp", 2) == 0) {
		if (strlen(if_name) > 4 && !strncmp(if_name + 3, "vrrp", 4))
			return DP_TEST_INTF_TYPE_MACVLAN;
		if (strlen(if_name) > 4 && !strncmp(if_name + 3, "sw_port", 7))
			return DP_TEST_INTF_TYPE_SWITCH_PORT;
		return DP_TEST_INTF_TYPE_DP;
	}

	if (strncmp(if_name, "vtun", 4) == 0)
		return DP_TEST_INTF_TYPE_NON_DP;

	if (strncmp(if_name, "br", 2) == 0)
		return DP_TEST_INTF_TYPE_BRIDGE;
	if (strncmp(if_name, "sw", 2) == 0)
		return DP_TEST_INTF_TYPE_BRIDGE;
	if (strncmp(if_name, "vxl", 3) == 0)
		return DP_TEST_INTF_TYPE_VXLAN;
	if (strncmp(if_name, "vti", 3) == 0)
		return DP_TEST_INTF_TYPE_VTI;
	if (strncmp(if_name, "tun", 3) == 0)
		return DP_TEST_INTF_TYPE_GRE;
	if (strncmp(if_name, "vfp", 3) == 0)
		return DP_TEST_INTF_TYPE_VFP;
	if (strncmp(if_name, "erspan", 6) == 0)
		return DP_TEST_INTF_TYPE_ERSPAN;
	if (strncmp(if_name, DP_TEST_INTF_NON_DP_PREAMBLE,
		    strlen(DP_TEST_INTF_NON_DP_PREAMBLE)) == 0)
		return DP_TEST_INTF_TYPE_NON_DP;
	if (strncmp(if_name, "lo", 2) == 0 || strncmp(if_name, "vrf", 3) == 0)
		return DP_TEST_INTF_TYPE_LO;
	if (strncmp(if_name, "ppp", 2) == 0)
		return DP_TEST_INTF_TYPE_PPP;

	dp_test_assert_internal(false);
	return DP_TEST_INTF_TYPE_ERROR; /* Definitely something wrong */
}

/*
 * Sanity check that name is in real name format.
 */
static bool
dp_test_intf_is_real_format(const char *real_name)
{
	if (dp_test_intf_type(real_name) != DP_TEST_INTF_TYPE_DP)
		return true;

	/* dpT<n><m> */
	dp_test_assert_internal(real_name[2] == 'T');
	dp_test_assert_internal(isdigit(real_name[3]));
	dp_test_assert_internal(isdigit(real_name[4]));
	return true;
}

static uint16_t
dp_test_intf2default_dpid_check_valid(const char *if_name)
{
	dp_test_assert_internal(if_name);
	dp_test_assert_internal(isdigit(if_name[2]));

	uint16_t id = atoi(&if_name[2]); /* ie dp<n>T1 */

	dp_test_assert_internal(id > 0);

	return id;
}

uint16_t
dp_test_intf2default_dpid(const char *if_name)
{
	return 0;
}

/*
 * Convert the test interface name to the real VR interface name.
 *
 * i.e. dp<n>T<m> -> VR dpT<n><m>
 *      dp2T1     -> VR dpT21
 */
char *
dp_test_intf_real(const char *test_name, char *real_name)
{
	int m;

	dp_test_assert_internal(test_name);
	dp_test_assert_internal(real_name);

	if (dp_test_intf_type(test_name) != DP_TEST_INTF_TYPE_DP)
		/* Don't change virtual intf: br, tun etc */
		goto no_change;
	if (isalpha(test_name[2]))
		/* This is already in real format */
		goto no_change;

	/* check dataplane id is valid */
	m = dp_test_intf2default_dpid_check_valid(test_name);

	/* there should be a 'T' followed by another number */
	const char *cp = strchr(test_name, 'T');

	dp_test_assert_internal(cp && isdigit(*(cp + 1)));

	snprintf(real_name, IFNAMSIZ, "dpT%i%s", m, (cp + 1));

	dp_test_intf_is_real_format(real_name);
	return real_name;

no_change:
	if (test_name == real_name)
		return real_name;
	snprintf(real_name, IFNAMSIZ, "%s", test_name);
	dp_test_intf_is_real_format(real_name);
	return real_name;
}

#define DP_TEST_INTF_ADDR_MAX 4 /* For secondary IP addresses */
/*
 * Keep track of the interface information the test controller has sent to the
 * dataplane.
 */
struct dp_test_intf {
	portid_t port_id;        /* pci device_id */
	uint dpid;              /* vplane ID */
	int ifindex;            /* Interface index allocated by 'kernel' */
	uint8_t state;          /* Track interface programmed state */
	char if_name[IFNAMSIZ];
	struct rte_ether_addr mac;  /* Interface mac address */
	in_addr_t ip4[DP_TEST_INTF_ADDR_MAX];
	struct in6_addr ip6[DP_TEST_INTF_ADDR_MAX];
	uint8_t active;    /* are there switch_port interface active */
	uint8_t bkp_interconnect; /* switch_port over a dpdk bp port */
};

static struct dp_test_intf dp_test_intf_default[] = {
	/*
	 * Test interfaces
	 *
	 * To help debugging LSB of mac is ifindex value.
	 */
	{  0, 1, 100, 0, "dp1T0", /* VR dpT10 */
		{ .addr_bytes = { 0x00, 0x00, 0xa4, 0x00, 0x00, 0x64 } },
		{ 0, 0, 0, 0 },
		{ IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT,
			IN6ADDR_ANY_INIT },
	},
	{  1, 1, 101, 0, "dp1T1", /* VR dpT11 */
		{ .addr_bytes = { 0x00, 0x00, 0xa4, 0x00, 0x00, 0x65 } },
		{ 0, 0, 0, 0 },
		{ IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT,
			IN6ADDR_ANY_INIT },
	},
	{  2, 1, 102, 0, "dp1T2",
		{ .addr_bytes = { 0x00, 0x00, 0xa4, 0x00, 0x00, 0x66 } },
		{ 0, 0, 0, 0 },
		{ IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT,
			IN6ADDR_ANY_INIT },
	},
	{  3, 1, 103, 0, "dp1T3",
		{ .addr_bytes = { 0x00, 0x00, 0xa4, 0x00, 0x00, 0x67 } },
		{ 0, 0, 0, 0 },
		{ IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT,
			IN6ADDR_ANY_INIT },
	},
	{  4, 1, 104, 0, "dp1T4",
		{ .addr_bytes = { 0x00, 0x00, 0xa4, 0x00, 0x00, 0x68 } },
		{ 0, 0, 0, 0 },
		{ IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT,
			IN6ADDR_ANY_INIT },
	},
	{  5, 2, 105, 0, "dp2T0", /* VR dpT20 */
		{ .addr_bytes = { 0x00, 0x00, 0xa4, 0x00, 0x00, 0x69 } },
		{ 0, 0, 0, 0 },
		{ IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT,
			IN6ADDR_ANY_INIT },
	},
	{  6, 2, 106, 0, "dp2T1",
		{ .addr_bytes = { 0x00, 0x00, 0xa4, 0x00, 0x00, 0x6a } },
		{ 0, 0, 0, 0 },
		{ IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT,
			IN6ADDR_ANY_INIT },
	},
	{  7, 2, 107, 0, "dp2T2",
		{ .addr_bytes = { 0x00, 0x00, 0xa4, 0x00, 0x00, 0x6b } },
		{ 0, 0, 0, 0 },
		{ IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT,
			IN6ADDR_ANY_INIT },
	},
	{  8, 2, 108, 0, "dp2T3",
		{ .addr_bytes = { 0x00, 0x00, 0xa4, 0x00, 0x00, 0x6c } },
		{ 0, 0, 0, 0 },
		{ IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT,
			IN6ADDR_ANY_INIT },
	},
	{  9, 2, 109, 0, "dp2T4",
		{ .addr_bytes = { 0x00, 0x00, 0xa4, 0x00, 0x00, 0x6d } },
		{ 0, 0, 0, 0 },
		{ IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT,
			IN6ADDR_ANY_INIT },
	},
	{ 10, 3, 110, 0, "dp3T0", /* VR dpT30 */
		{ .addr_bytes = { 0x00, 0x00, 0xa4, 0x00, 0x00, 0x6e } },
		{ 0, 0, 0, 0 },
		{ IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT,
			IN6ADDR_ANY_INIT },
	},
	{ 11, 3, 111, 0, "dp3T1",
		{ .addr_bytes = { 0x00, 0x00, 0xa4, 0x00, 0x00, 0x6f } },
		{ 0, 0, 0, 0 },
		{ IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT,
			IN6ADDR_ANY_INIT },
	},
	{ 12, 3, 112, 0, "dp3T2",
		{ .addr_bytes = { 0x00, 0x00, 0xa4, 0x00, 0x00, 0x70 } },
		{ 0, 0, 0, 0 },
		{ IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT,
			IN6ADDR_ANY_INIT },
	},
	{ 13, 3, 113, 0, "dp3T3",
		{ .addr_bytes = { 0x00, 0x00, 0xa4, 0x00, 0x00, 0x71 } },
		{ 0, 0, 0, 0 },
		{ IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT,
			IN6ADDR_ANY_INIT },
	},
	{ 14, 3, 114, 0, "dp3T4",
		{ .addr_bytes = { 0x00, 0x00, 0xa4, 0x00, 0x00, 0x72 } },
		{ 0, 0, 0, 0 },
		{ IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT,
			IN6ADDR_ANY_INIT },
	},
	{ 15, 4, 115, 0, "dp4T0", /* VR dpT40 */
		{ .addr_bytes = { 0x00, 0x00, 0xa4, 0x00, 0x00, 0x73 } },
		{ 0, 0, 0, 0 },
		{ IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT,
			IN6ADDR_ANY_INIT },
	},
	{ 16, 4, 116, 0, "dp4T1",
		{ .addr_bytes = { 0x00, 0x00, 0xa4, 0x00, 0x00, 0x74 } },
		{ 0, 0, 0, 0 },
		{ IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT,
			IN6ADDR_ANY_INIT },
	},
	{ 17, 4, 117, 0, "dp4T2",
		{ .addr_bytes = { 0x00, 0x00, 0xa4, 0x00, 0x00, 0x75 } },
		{ 0, 0, 0, 0 },
		{ IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT,
			IN6ADDR_ANY_INIT },
	},
	{ 18, 4, 118, 0, "dp4T3",
		{ .addr_bytes = { 0x00, 0x00, 0xa4, 0x00, 0x00, 0x76 } },
		{ 0, 0, 0, 0 },
		{ IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT,
			IN6ADDR_ANY_INIT },
	},
	{ 19, 4, 119, 0, "dp4T4",
		{ .addr_bytes = { 0x00, 0x00, 0xa4, 0x00, 0x00, 0x77 } },
		{ 0, 0, 0, 0 },
		{ IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT,
			IN6ADDR_ANY_INIT },
	},
};

static struct dp_test_intf dp_test_intf_switch_port[] = {
	{ 20, 1, 120, 0, "dp1sw_port_0_0", /* switch port interface */
		{ .addr_bytes = { 0x00, 0x00, 0xa4, 0xbe, 0xef, 0x88 } },
		{ 0, 0, 0, 0 },
		{ IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT,
		  IN6ADDR_ANY_INIT}, false, true,
	},
	{ 21, 1, 121, 0, "dp1sw_port_0_7", /* switch port interface */
		{ .addr_bytes = { 0x00, 0x00, 0xa4, 0xbe, 0xef, 0x01 } },
		{ 0, 0, 0, 0 },
		{ IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT, IN6ADDR_ANY_INIT,
		  IN6ADDR_ANY_INIT}, false, false,
	},
};

void dp_test_intf_dpdk_init(void)
{
	struct dp_test_intf *intf;
	unsigned int i;
	char intf_name[32];
	char rx_ring_name[32];
	char tx_ring_name[32];
	struct rte_ring *rx_ring;
	struct rte_ring *tx_ring;
	char loc = 0;
	int port;
	int ret;

	for (i = 0; i < dp_test_intf_count_local(); i++) {
		intf = &dp_test_intf_default[i];
		loc = intf->if_name[3];

		snprintf(intf_name, sizeof(intf_name),
			 "eth_ring%c%c",
			 loc, intf->if_name[4]);
		snprintf(rx_ring_name, sizeof(rx_ring_name),
			 DP_TEST_RX_RING_BASE_NAME "%c%c",
			 loc, intf->if_name[4]);
		snprintf(tx_ring_name, sizeof(tx_ring_name),
			 DP_TEST_TX_RING_BASE_NAME "%c%c",
			 loc, intf->if_name[4]);
		rx_ring = rte_ring_create(rx_ring_name, 512,
					  SOCKET_ID_ANY,
					  RING_F_SC_DEQ);
		tx_ring = rte_ring_create(tx_ring_name, 512,
					  SOCKET_ID_ANY,
					  RING_F_SP_ENQ);
		if (!rx_ring || !tx_ring)
			rte_panic(
				"unable to allocate rings for interface %s\n",
				intf->if_name);

		if (dp_test_intf_type(intf->if_name) ==
		    DP_TEST_INTF_TYPE_SWITCH_PORT)
			rte_panic("switch ports %s in local interface list\n",
				  intf->if_name);

		port = rte_eth_from_rings(intf_name, &rx_ring, 1, &tx_ring,
					  1, SOCKET_ID_ANY);
		if (port < 0)
			rte_panic("pmd create fail intf %s - %s\n",
				  intf->if_name, rte_strerror(rte_errno));

		ret = rte_eth_dev_mac_addr_add(port, &intf->mac, 0);
		if (ret < 0)
			rte_panic("set mac addr fail on intf %s - %s\n",
				  intf->if_name, rte_strerror(rte_errno));
	}
}

#define DP_TEST_INTF_VIRT_MAX 100
#define DP_TEST_INTF_VIRT_IF_BASE 1000
#define DP_TEST_INTF_NON_DP 10000
struct dp_test_intf dp_test_intf_virt[DP_TEST_INTF_VIRT_MAX];

static struct dp_test_intf *
dp_test_intf_find_virt(const char *real_if_name)
{
	int i;

	/* virtual interfaces */
	for (i = 0; i < DP_TEST_INTF_VIRT_MAX; i++)
		if (strncmp(real_if_name, dp_test_intf_virt[i].if_name,
			    IFNAMSIZ) == 0)
			return &dp_test_intf_virt[i];
	return NULL;
}

static struct dp_test_intf *
dp_test_intf_find_hw(const char *real_if_name)
{
	int i;

	/* h/w interfaces */
	for (i = 0; i < dp_test_intf_count(); i++)
		if (strncmp(real_if_name, dp_test_intf_default[i].if_name,
			    IFNAMSIZ) == 0)
			return &dp_test_intf_default[i];
	return NULL;
}

static struct dp_test_intf *
dp_test_intf_find_switch_port(const char *real_if_name)
{
	int i;

	/* h/w interfaces */
	for (i = 0; i < dp_test_intf_switch_port_count(); i++)
		if (strncmp(real_if_name,
				dp_test_intf_switch_port[i].if_name,
				IFNAMSIZ) == 0)
			return &dp_test_intf_switch_port[i];
	return NULL;
}

void
dp_test_intf_switch_port_activate(const char *real_if_name)
{
	struct dp_test_intf *intf;

	intf = dp_test_intf_find_switch_port(real_if_name);

	if (!intf || intf->active)
		return;

	intf->active = true;

	json_object *intf_set;

	intf_set = dp_test_json_intf_set_create();
	dp_test_intf_create_default_set(intf_set);

}

void
dp_test_intf_switch_port_deactivate(const char *real_if_name)
{
	struct dp_test_intf *intf;

	intf = dp_test_intf_find_switch_port(real_if_name);

	if (!intf || !intf->active)
		return;

	intf->active = false;

	json_object *intf_set;

	intf_set = dp_test_json_intf_set_create();
	dp_test_intf_create_default_set(intf_set);

}

bool dp_test_intf_switch_port_over_bkp(const char *real_if_name)
{
	struct dp_test_intf *intf;

	intf = dp_test_intf_find_switch_port(real_if_name);

	if (!intf)
		return false;

	return intf->bkp_interconnect ? true : false;
}

/*
 * Return count all h/w (non virtual) interfaces.
 */
uint8_t
dp_test_intf_count(void)
{
	return ARRAY_SIZE(dp_test_intf_default);
}

/*
 * Return count of all switch_port (non default/virtual)
 * interfaces.
 */
uint8_t
dp_test_intf_switch_port_count(void)
{
	return ARRAY_SIZE(dp_test_intf_switch_port);
}

#define DP_TEST_INTF_ERROR_IFINDEX 0 /* Hopefully an invalid ifindex/count */

uint8_t
dp_test_intf_count_local(void)
{
	return dp_test_intf_count();
}

/*
 * Return count of all virtual and non-virtual interfaces expected in
 * the test clean state.
 */
uint8_t
dp_test_intf_clean_count(void)
{
	/* add one for loopback interface */
	return dp_test_intf_count() + 1;
}

/* Generate real interfaces.
 * We need to do this early as dataplane wrapped functions need early access.
 */
void dp_test_intf_init(void)
{
	int i;

	for (i = 0; i < dp_test_intf_count(); i++)
		dp_test_intf_real(dp_test_intf_default[i].if_name,
				  dp_test_intf_default[i].if_name);
}

/*
 * Create a new ifindex and store it index by if_name
 * To aid debugging the last 2 LSB of the mac are set to the ifindex.
 * Virtual interfaces do not have a port id, so set it to invalid.
 *
 * Return the new ifindex stored.
 */
int
dp_test_intf_virt_add(const char *if_name)
{
	struct rte_ether_addr mac = {
		.addr_bytes = { 0x00, 0x00, 0xa5, 0x00, 0x00, 0x00 }
	};
	char real_if_name[IFNAMSIZ];
	struct dp_test_intf *intf;
	int i, ifindex;

	dp_test_intf_real(if_name, real_if_name);
	for (i = 0; i < DP_TEST_INTF_VIRT_MAX; i++) {
		intf = &dp_test_intf_virt[i];
		if (intf->ifindex == 0) {
			snprintf(intf->if_name, IFNAMSIZ, "%s", real_if_name);
			ifindex = i + DP_TEST_INTF_VIRT_IF_BASE;
			intf->ifindex = ifindex;
			intf->mac = mac;
			intf->dpid = dp_test_intf2default_dpid(if_name);
			intf->mac.addr_bytes[5] = (uint8_t)ifindex;
			intf->mac.addr_bytes[4] = (uint8_t)(ifindex >> 8);
			intf->port_id = DP_TEST_INTF_INVALID_PORT_ID;
			return intf->ifindex;
		}
	}
	dp_test_assert_internal(false);
	return DP_TEST_INTF_ERROR_IFINDEX;
}

void
dp_test_intf_virt_del(const char *if_name)
{
	char real_if_name[IFNAMSIZ];
	int i;

	dp_test_intf_real(if_name, real_if_name);
	for (i = 0; i < DP_TEST_INTF_VIRT_MAX; i++)
		if (strncmp(real_if_name, dp_test_intf_virt[i].if_name,
			    IFNAMSIZ) == 0) {
			dp_test_intf_virt[i].ifindex = 0;
			return;
		}
	dp_test_assert_internal(false);
}

static struct dp_test_intf *
dp_test_intf_name2intf(const char *if_name)
{
	char real_if_name[IFNAMSIZ];
	struct dp_test_intf *target_intf;

	dp_test_intf_real(if_name, real_if_name);

	target_intf = dp_test_intf_find_hw(real_if_name);
	if (!target_intf)
		target_intf = dp_test_intf_find_switch_port(real_if_name);
	if (!target_intf)
		target_intf = dp_test_intf_find_virt(real_if_name);

	dp_test_assert_internal(target_intf);
	return target_intf;
}

/*
 * Set op_state flags on if_name intf
 */
void
dp_test_intf_name_add_state(const char *if_name, uint8_t state)
{
	struct dp_test_intf *intf;

	intf = dp_test_intf_name2intf(if_name);
	dp_test_assert_internal(intf);

	intf->state |= state;
}

/*
 * clear op_state flags on if_name intf
 */
void
dp_test_intf_name_del_state(const char *if_name, uint8_t state)
{
	struct dp_test_intf *intf;

	intf = dp_test_intf_name2intf(if_name);
	dp_test_assert_internal(intf);

	intf->state &= ~state;
}

/* Convert to Uplink local vplaned ifindex format */
unsigned int
dp_test_cont_src_ifindex(unsigned int ifindex)
{
	if (dp_test_cont_src_get() == CONT_SRC_UPLINK)
		ifindex |= (1U << 31);
	return ifindex;
}

/*
 * Convert if_name to ifindex
 */
int
dp_test_intf_name2index(const char *if_name)
{
	struct dp_test_intf *intf;

	/*
	 * Special case for ifindex so that we can send NL messages
	 * for routes out of interfaces that do not exist on the
	 * dataplane.
	 */
	if (dp_test_intf_type(if_name) == DP_TEST_INTF_TYPE_NON_DP)
		return DP_TEST_INTF_NON_DP;

	intf = dp_test_intf_name2intf(if_name);
	dp_test_assert_internal(intf);

	return intf->ifindex;
}

struct rte_ether_addr *
dp_test_intf_name2mac(const char *if_name)
{
	struct dp_test_intf *intf;

	intf = dp_test_intf_name2intf(if_name);
	dp_test_assert_internal(intf);

	return &intf->mac;
}

/*
 * Return a string holding the interface's ether address.
 * Note: This function returns one of 4 static buffers, i.e. it should
 * be safe to call this up to 4 times and then make use of the results
 * in subsequent calls elsewhere (for example, in setting up a pak, which
 * can use two macs) before the function starts overwriting its earlier
 * results.
 */
char *
dp_test_intf_name2mac_str(const char *if_name)
{
	static char ebuf[4][32];
	static int next;

	return ether_ntoa_r(dp_test_intf_name2mac(if_name), ebuf[next++ % 4]);
}

/*
 * Convert if_name to port_id
 */
uint8_t
dp_test_intf_name2port(const char *if_name)
{
	struct dp_test_intf *intf;

	intf = dp_test_intf_name2intf(if_name);
	dp_test_assert_internal(intf);

	return intf->port_id;
}

static struct dp_test_intf *
dp_test_intf_port2intf(portid_t port_id)
{
	int i;

	dp_test_assert_internal(port_id < dp_test_intf_count() +
				dp_test_intf_switch_port_count());
	dp_test_assert_internal(port_id != DP_TEST_INTF_INVALID_PORT_ID);

	for (i = 0; i < dp_test_intf_count(); i++)
		if (port_id == dp_test_intf_default[i].port_id)
			return &dp_test_intf_default[i];
	for (i = 0; i < dp_test_intf_switch_port_count(); i++)
		if (port_id == dp_test_intf_switch_port[i].port_id)
			return &dp_test_intf_switch_port[i];

	dp_test_assert_internal(false);
	return NULL;
}

/*
 * Convert port_id to real if_name.
 */
void
dp_test_intf_port2name(portid_t port_id, char *if_name)
{
	struct dp_test_intf *intf;

	intf = dp_test_intf_port2intf(port_id);
	dp_test_assert_internal(intf);

	snprintf(if_name, IFNAMSIZ, "%s", intf->if_name);
}

/*
 *
 * Convert port_id to if_index.
 */
int
dp_test_intf_port2index(portid_t port_id)
{
	struct dp_test_intf *intf;

	intf = dp_test_intf_port2intf(port_id);
	dp_test_assert_internal(intf);

	return intf->ifindex;
}

static int
dp_test_intf_ip4_find(in_addr_t ip4, struct dp_test_intf *intf)
{
	int i;

	for (i = 0; i < DP_TEST_INTF_ADDR_MAX; i++)
		if (intf->ip4[i] == ip4)
			return i;

	return DP_TEST_INTF_ERROR_IFINDEX;
}

static void
dp_test_intf_ip4(const char *if_name, const in_addr_t *ip4, bool add)
{
	struct dp_test_intf *intf;
	int i;

	intf = dp_test_intf_name2intf(if_name);
	dp_test_assert_internal(intf);

	if (add) {
		i = dp_test_intf_ip4_find(*ip4, intf);
		if (i == DP_TEST_INTF_ERROR_IFINDEX) {
			/* Add it if there is space */
			i = dp_test_intf_ip4_find(0, intf);
			intf->ip4[i] = *ip4;
		}
	} else {
		i = dp_test_intf_ip4_find(*ip4, intf);
		intf->ip4[i] = 0;
	}
}

static int
dp_test_intf_ip6_find(struct in6_addr *ip6, struct dp_test_intf *intf)
{
	int i;

	for (i = 0; i < DP_TEST_INTF_ADDR_MAX; i++)
		if (IN6_ARE_ADDR_EQUAL(&intf->ip6[i], ip6))
			return i;

	/* If we do not find the address, we should not have looked for it */
	dp_test_assert_internal(false);
	return DP_TEST_INTF_ERROR_IFINDEX;
}

static void
dp_test_intf_ip6(const char *if_name, struct in6_addr *ip6, bool add)
{
	struct in6_addr ip6_zero = IN6ADDR_ANY_INIT;
	struct dp_test_intf *intf;
	int i;

	intf = dp_test_intf_name2intf(if_name);
	dp_test_assert_internal(intf);

	if (add) {
		i = dp_test_intf_ip6_find(&ip6_zero, intf);
		intf->ip6[i] = *ip6;
	} else {
		i = dp_test_intf_ip6_find(ip6, intf);
		intf->ip6[i] = ip6_zero;
	}
}

static void
dp_test_intf_addr(const char *if_name, struct dp_test_addr *addr, bool add)
{
	switch (addr->family) {
	case AF_INET:
		return dp_test_intf_ip4(if_name, &addr->addr.ipv4, add);
	case AF_INET6:
		return dp_test_intf_ip6(if_name, &addr->addr.ipv6, add);
	default:
		dp_test_assert_internal(false);
	}
}

void
dp_test_intf_add_addr(const char *if_name, struct dp_test_addr *addr)
{
	dp_test_intf_addr(if_name, addr, true);
}

void
dp_test_intf_del_addr(const char *if_name, struct dp_test_addr *addr)
{
	dp_test_intf_addr(if_name, addr, false);
}

static void
dp_test_intf_primary_ip4(const char *if_name, in_addr_t *primary)
{
	struct dp_test_intf *intf;
	int i;

	intf = dp_test_intf_name2intf(if_name);
	dp_test_assert_internal(intf);

	for (i = 0; i < DP_TEST_INTF_ADDR_MAX; i++)
		if (intf->ip4[i] != 0) {
			*primary = intf->ip4[i];
			return;
		}

	dp_test_assert_internal(false);
}

static void
dp_test_intf_primary_ip6(const char *if_name, struct in6_addr *primary)
{
	struct dp_test_intf *intf;
	struct in6_addr ip6_zero = IN6ADDR_ANY_INIT;
	int i;

	intf = dp_test_intf_name2intf(if_name);
	dp_test_assert_internal(intf);

	for (i = 0; i < DP_TEST_INTF_ADDR_MAX; i++)
		if (!IN6_ARE_ADDR_EQUAL(&intf->ip6[i], &ip6_zero)) {
			*primary = intf->ip6[i];
			return;
		}

	dp_test_assert_internal(false);
}

/*
 * return primary address (of type family), of an interface
 * This will be the first configured addr on the interface
 * address->family [IN]
 * address->addr [OUT]
 */
void
dp_test_intf_name2addr(const char *if_name, struct dp_test_addr *addr)
{
	switch (addr->family) {
	case AF_INET:
		dp_test_intf_primary_ip4(if_name, &addr->addr.ipv4);
		break;
	case AF_INET6:
		dp_test_intf_primary_ip6(if_name, &addr->addr.ipv6);
		break;
	default:
		dp_test_assert_internal(false);
	}
}

/*
 * Convert if_name to IPv4 address str
 */
void
dp_test_intf_name2addr_str(const char *if_name, int family, char *addr_str,
			   int buf_len)
{
	struct dp_test_addr addr;

	addr.family = family;
	dp_test_intf_name2addr(if_name, &addr);
	switch (family) {
	case AF_INET:
		inet_ntop(AF_INET, &addr.addr.ipv4, addr_str, buf_len);
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, &addr.addr.ipv6, addr_str, buf_len);
		break;
	default:
		dp_test_assert_internal(false);
		break;
	}
}

/*
 * Create default set of interfaces, available to all tests.
 *
 * intf_set: set of expected interfaces in 'clean' state.
 */
void dp_test_intf_create_default_set(json_object *intf_set)
{
	const char *if_name;
	int i;

	dp_test_intf_virt_add("lo");
	dp_test_netlink_create_lo("lo", false);
	if (intf_set)
		dp_test_json_intf_add_lo(intf_set, "lo");

	/*
	 * Setup the interfaces - all tests will run
	 * with a default set of interfaces.
	 */
	for (i = 0; i < dp_test_intf_count(); i++) {
		if_name = dp_test_intf_default[i].if_name;
		dp_test_netlink_set_interface_l2(if_name);
		if (intf_set)
			dp_test_json_intf_add(intf_set, if_name, NULL, false);
	}

	for (i = 0; i < dp_test_intf_switch_port_count(); i++)
		if (dp_test_intf_switch_port[i].active && intf_set) {
			if_name =
				dp_test_intf_switch_port[i].if_name;
			dp_test_json_intf_add(intf_set, if_name,
							NULL, false);
		}

	if (intf_set) {
		dp_test_set_expected_ifconfig(intf_set);
		dp_test_set_expected_npf_fw_portmap();
		dp_test_set_expected_vrf();
		dp_test_set_expected_route_stats();
		json_object_put(intf_set);
	}
}

/*
 * Regenerate the expected ifconfig json
 */
void dp_test_reset_expected_ifconfig(void)
{
	const char *if_name;
	int i;
	json_object *intf_set;
	enum cont_src_en old_cont_src = dp_test_cont_src_get();

	intf_set = dp_test_json_intf_set_create();

	dp_test_cont_src_set(CONT_SRC_MAIN);

	dp_test_json_intf_add_lo(intf_set, "lo");

	for (i = 0; i < dp_test_intf_count(); i++) {
		if_name = dp_test_intf_default[i].if_name;
		dp_test_json_intf_add(intf_set, if_name, NULL, false);
	}

	for (i = 0; i < dp_test_intf_switch_port_count(); i++)
		if (dp_test_intf_switch_port[i].active && intf_set) {
			if_name =
				dp_test_intf_switch_port[i].if_name;
			dp_test_json_intf_add(intf_set, if_name,
							NULL, false);
		}

	dp_test_set_expected_ifconfig(intf_set);
	json_object_put(intf_set);

	dp_test_cont_src_set(old_cont_src);
}

static void dp_test_intf_get_stats_for_if(const char *ifname,
					  struct if_data *stats)
{
	char real_ifname[IFNAMSIZ];
	dp_test_intf_real(ifname, real_ifname);
	struct ifnet *ifp = dp_ifnet_byifname(real_ifname);
	if_stats(ifp, stats);
}

void dp_test_intf_initial_stats_for_if(const char *ifname,
				       struct if_data *stats)
{
	dp_test_intf_get_stats_for_if(ifname, stats);
}

void dp_test_intf_delta_stats_for_if(const char *ifname,
				     const struct if_data *initial_stats,
				     struct if_data *stats)
{
	struct if_data total_stats;
	dp_test_intf_get_stats_for_if(ifname, &total_stats);
	stats->ifi_ipackets = total_stats.ifi_ipackets -
		initial_stats->ifi_ipackets;
	stats->ifi_ierrors = total_stats.ifi_ierrors -
		initial_stats->ifi_ierrors;
	stats->ifi_opackets = total_stats.ifi_opackets -
		initial_stats->ifi_opackets;
	stats->ifi_oerrors = total_stats.ifi_oerrors -
		initial_stats->ifi_oerrors;
	stats->ifi_ibytes = total_stats.ifi_ibytes - initial_stats->ifi_ibytes;
	stats->ifi_obytes = total_stats.ifi_obytes - initial_stats->ifi_obytes;
	stats->ifi_idropped = total_stats.ifi_idropped -
		initial_stats->ifi_idropped;
	stats->ifi_odropped_txring = total_stats.ifi_odropped_txring -
		initial_stats->ifi_odropped_txring;
	stats->ifi_odropped_hwq = total_stats.ifi_odropped_hwq -
		initial_stats->ifi_odropped_hwq;
	stats->ifi_odropped_proto = total_stats.ifi_odropped_proto -
		initial_stats->ifi_odropped_proto;
	stats->ifi_ibridged = total_stats.ifi_ibridged -
		initial_stats->ifi_ibridged;
	stats->ifi_imulticast = total_stats.ifi_imulticast -
		initial_stats->ifi_imulticast;
	stats->ifi_ivlan = total_stats.ifi_ivlan - initial_stats->ifi_ivlan;
	stats->ifi_no_address = total_stats.ifi_no_address -
		initial_stats->ifi_no_address;
	stats->ifi_no_vlan = total_stats.ifi_no_vlan -
		initial_stats->ifi_no_vlan;
	stats->ifi_unknown = total_stats.ifi_unknown -
		initial_stats->ifi_unknown;
}

/*
 * Create a Bridge Group interface.
 */
void _dp_test_intf_bridge_create(const char *br_name,
				 const char *file, const char *func,
				 int line)
{
	dp_test_assert_internal(dp_test_intf_type(br_name) ==
			DP_TEST_INTF_TYPE_BRIDGE);
	dp_test_intf_virt_add(br_name);
	_dp_test_netlink_create_bridge(br_name, true, file, func, line);
	_dp_test_netlink_set_interface_l2(br_name, true, file, func, line);
}

/*
 * Enable VLAN filtering on a Bridge Group interface.
 */
void _dp_test_intf_bridge_enable_vlan_filter(const char *br_name,
					     const char *file, const char *func,
					     int line)
{
	dp_test_assert_internal(dp_test_intf_type(br_name) ==
				DP_TEST_INTF_TYPE_BRIDGE);
	_dp_test_netlink_set_bridge_vlan_filter(br_name, true,
						file, func, line);
}

/*
 * Delete a Bridge Group interface.
 */
void _dp_test_intf_bridge_del(const char *br_name,
			      const char *file, const char *func,
			      int line)
{
	dp_test_assert_internal(dp_test_intf_type(br_name) ==
				DP_TEST_INTF_TYPE_BRIDGE);
	_dp_test_netlink_del_bridge(br_name, true, file, func, line);
	dp_test_intf_virt_del(br_name);
}

/*
 * Add L2 interface(port) to Bridge Group.
 */
void _dp_test_intf_bridge_add_port(const char *br_name, const char *if_name,
				   const char *file, const char *func,
				   int line)
{
	dp_test_assert_internal(dp_test_intf_type(br_name) ==
				DP_TEST_INTF_TYPE_BRIDGE);
	_dp_test_netlink_add_bridge_port(br_name, if_name, true,
					 file, func, line);
	dp_test_intf_name_add_state(if_name, DP_TEST_INTF_STATE_BRIDGE);
}

/*
 * Set state and allowed vlans of a bridge port
 */
void _dp_test_intf_bridge_port_set(const char *br_name,
	const char *if_name, uint16_t pvid, struct bridge_vlan_set *vlans,
	struct bridge_vlan_set *untag_vlans, uint8_t state,
	const char *file, const char *func,
	int line)
{
	dp_test_assert_internal(dp_test_intf_type(br_name) ==
				DP_TEST_INTF_TYPE_BRIDGE);
	_dp_test_netlink_bridge_port_set(br_name, if_name, pvid,
		vlans, untag_vlans, state, true, file, func, line);
}

/*
 * Remove L2 interface(port) from Bridge Group.
 */
void _dp_test_intf_bridge_remove_port(const char *br_name, const char *if_name,
				      const char *file, const char *func,
				      int line)
{
	dp_test_assert_internal(dp_test_intf_type(br_name) ==
				DP_TEST_INTF_TYPE_BRIDGE);
	dp_test_intf_name_del_state(if_name, DP_TEST_INTF_STATE_BRIDGE);
	_dp_test_netlink_remove_bridge_port(br_name, if_name, true,
					    file, func, line);
}

/*
 * Create a VXLAN interface.
 */
void _dp_test_intf_vxlan_create(const char *vxlan_name, uint32_t vni,
				const char *parent_name,
				const char *file, const char *func,
				int line)
{
	dp_test_intf_virt_add(vxlan_name);
	_dp_test_netlink_create_vxlan(vxlan_name, vni, parent_name, true,
				      file, func, line);
	_dp_test_netlink_set_interface_mtu(vxlan_name, 1430, true,
					   file, func, line);
}

/*
 * Delete a VXLAN interface.
 */
void _dp_test_intf_vxlan_del(const char *vxlan_name, uint32_t vni,
			     const char *file, const char *func,
			     int line)
{
	_dp_test_netlink_del_vxlan(vxlan_name, vni, true,
				   file, func, line);
	dp_test_intf_virt_del(vxlan_name);
}

/*
 * Create a VLAN interface.
 */
void _dp_test_intf_vif_create(const char *vif_name, const char *parent_name,
			      uint16_t vlan, uint16_t vlan_proto,
			      const char *file, const char *func,
			      int line)
{
	dp_test_intf_virt_add(vif_name);
	_dp_test_netlink_create_vif(vif_name, parent_name, vlan, vlan_proto,
				    true, file, func, line);
}

/*
 * Create an incomplete VLAN interface. Store the state in the table, but do
 * not send the netlink message. Incomplete routes can then be generated that
 * use this interface.
 */
void dp_test_intf_vif_create_incmpl(const char *vif_name,
				    const char *parent_name,
				    uint16_t vlan)
{
	dp_test_intf_virt_add(vif_name);
}

/*
 * Finish the generation of an incomplete interface.
 */
void dp_test_intf_vif_create_incmpl_fin(const char *vif_name,
					const char *parent_name, uint16_t vlan)
{
	dp_test_netlink_create_vif(vif_name, parent_name, vlan);
}


/*
 * Delete a VLAN interface.
 */
void _dp_test_intf_vif_del(const char *vif_name, uint16_t vlan,
			   uint16_t vlan_proto, const char *file,
			   const char *func, int line)
{
	_dp_test_netlink_del_vif(vif_name, vlan, vlan_proto, true,
				 file, func, line);
	dp_test_intf_virt_del(vif_name);
}

void _dp_test_intf_macvlan_create(const char *if_name,
				  const char *parent_name,
				  const char *mac_str, const char *file,
				  const char *func, int line)
{
	dp_test_intf_virt_add(if_name);
	_dp_test_netlink_create_macvlan(if_name, parent_name, mac_str,
					true, file, func, line);
}

void _dp_test_intf_macvlan_del(const char *if_name,
			       const char *file, const char *func,
			       int line)
{
	_dp_test_netlink_del_macvlan(if_name, true,
				     file, func, line);
	dp_test_intf_virt_del(if_name);
}

/*
 * Create a GRE tunnel interface.
 */
void dp_test_intf_gre_create(const char *gre_name,
			     const char *gre_local,
			     const char *gre_remote,
			     uint32_t gre_key,
			     uint32_t vrf_id)
{
	dp_test_assert_internal(dp_test_intf_type(gre_name) ==
				DP_TEST_INTF_TYPE_GRE);
	dp_test_intf_virt_add(gre_name);
	dp_test_netlink_create_tunnel(gre_name, gre_local,
				      gre_remote, gre_key, false, vrf_id,
				      DP_TEST_TUN_ENCAP_TYPE_IP);
}

/*
 * Create a GRE bridge-tunnel interface.
 */
void dp_test_intf_gre_l2_create(const char *gre_name,
				const char *gre_local,
				const char *gre_remote,
				uint32_t gre_key)
{
	dp_test_assert_internal(dp_test_intf_type(gre_name) ==
				DP_TEST_INTF_TYPE_GRE);
	dp_test_intf_virt_add(gre_name);
	dp_test_netlink_create_tunnel(gre_name, gre_local,
				      gre_remote, gre_key, false,
				      VRF_DEFAULT_ID,
				      DP_TEST_TUN_ENCAP_TYPE_BRIDGE);
}

/*
 * Delete a GRE tunnel interface.
 */
void dp_test_intf_gre_delete(const char *gre_name,
			     const char *gre_local,
			     const char *gre_remote,
			     uint32_t gre_key,
			     uint32_t vrf_id)
{
	dp_test_assert_internal(dp_test_intf_type(gre_name) ==
				DP_TEST_INTF_TYPE_GRE);
	dp_test_netlink_delete_tunnel(gre_name, gre_local,
				      gre_remote, gre_key, false, vrf_id,
				      DP_TEST_TUN_ENCAP_TYPE_IP);
	dp_test_intf_virt_del(gre_name);
}

/*
 * Delete a GRE bridge-tunnel interface.
 */
void dp_test_intf_gre_l2_delete(const char *gre_name,
				const char *gre_local,
				const char *gre_remote,
				uint32_t gre_key)
{
	dp_test_assert_internal(dp_test_intf_type(gre_name) ==
				DP_TEST_INTF_TYPE_GRE);
	dp_test_netlink_delete_tunnel(gre_name, gre_local,
				      gre_remote, gre_key, false,
				      VRF_DEFAULT_ID,
				      DP_TEST_TUN_ENCAP_TYPE_BRIDGE);
	dp_test_intf_virt_del(gre_name);
}

/*
 * Create a ERSPAN tunnel interface.
 */
void dp_test_intf_erspan_create(const char *erspan_name,
			     const char *erspan_local,
			     const char *erspan_remote,
			     uint32_t gre_key,
			     bool gre_seq,
			     uint32_t vrf_id)
{
	dp_test_assert_internal(dp_test_intf_type(erspan_name) ==
				DP_TEST_INTF_TYPE_ERSPAN);
	dp_test_intf_virt_add(erspan_name);
	dp_test_netlink_create_tunnel(erspan_name, erspan_local,
				      erspan_remote, gre_key, gre_seq, vrf_id,
				      DP_TEST_TUN_ENCAP_TYPE_ERSPAN);
}

/*
 * Delete a ERSPAN tunnel interface.
 */
void dp_test_intf_erspan_delete(const char *erspan_name,
			     const char *erspan_local,
			     const char *erspan_remote,
			     uint32_t gre_key,
			     bool gre_seq,
			     uint32_t vrf_id)
{
	dp_test_assert_internal(dp_test_intf_type(erspan_name) ==
				DP_TEST_INTF_TYPE_ERSPAN);
	dp_test_netlink_delete_tunnel(erspan_name, erspan_local,
				      erspan_remote, gre_key, gre_seq, vrf_id,
				      DP_TEST_TUN_ENCAP_TYPE_ERSPAN);
	dp_test_intf_virt_del(erspan_name);
}

void dp_test_intf_vti_create(const char *vti_name,
			     const char *vti_local,
			     const char *vti_remote,
			     uint16_t mark,
			     vrfid_t vrf_id)
{
	dp_test_assert_internal(dp_test_intf_type(vti_name) ==
				DP_TEST_INTF_TYPE_VTI);
	dp_test_intf_virt_add(vti_name);
	dp_test_netlink_create_vti(vti_name, vti_local,
				   vti_remote, mark, vrf_id);
}

void dp_test_intf_vti_delete(const char *vti_name,
			     const char *vti_local,
			     const char *vti_remote,
			     uint16_t mark,
			     vrfid_t vrf_id)
{
	dp_test_assert_internal(dp_test_intf_type(vti_name) ==
				DP_TEST_INTF_TYPE_VTI);
	dp_test_netlink_delete_vti(vti_name, vti_local,
				   vti_remote, mark, vrf_id);
	dp_test_intf_virt_del(vti_name);
}

void dp_test_intf_nondp_create(const char *name)
{
	dp_test_intf_virt_add(name);
	dp_test_netlink_create_nondp(name);
}

void dp_test_intf_nondp_create_incmpl(const char *name)
{
	dp_test_intf_virt_add(name);
}

void dp_test_intf_nondp_create_incmpl_fin(const char *name)
{
	dp_test_netlink_create_nondp(name);
}

void dp_test_intf_nondp_delete(const char *name)
{
	dp_test_netlink_del_nondp(name);
	dp_test_intf_virt_del(name);
}

/*
 * Create a PPP interface.
 */
void dp_test_intf_ppp_create(const char *intf_name, uint32_t vrf_id)
{
	dp_test_intf_virt_add(intf_name);
	_dp_test_netlink_create_ppp(intf_name, vrf_id, true, __FILE__,
				    __func__, __LINE__);
}

/*
 * Delete a PPP interface.
 */
void dp_test_intf_ppp_delete(const char *intf_name, uint32_t vrf_id)
{
	_dp_test_netlink_delete_ppp(intf_name, vrf_id, true, __FILE__,
				    __func__, __LINE__);
	dp_test_intf_virt_del(intf_name);
}

void
_dp_test_intf_loopback_create(const char *name,
			      const char *file, const char *func, int line)
{
	dp_test_intf_virt_add(name);
	_dp_test_netlink_create_lo(name, true, file, func, line);
}

void
_dp_test_intf_loopback_delete(const char *name,
			      const char *file, const char *func, int line)
{
	_dp_test_netlink_del_lo(name, true, file, func, line);
	dp_test_intf_virt_del(name);
}

void _dp_test_intf_vfp_create(const char *name, vrfid_t vrf_id, bool verify,
			      const char *file, const char *func, int line)
{
	dp_test_intf_virt_add(name);
	_dp_test_netlink_create_vfp(name, vrf_id, verify, file, func, line);
}

void _dp_test_intf_vfp_delete(const char *name, vrfid_t vrf_id,
			      const char *file, const char *func, int line)
{
	_dp_test_netlink_del_vfp(name, vrf_id, false, file, func, line);
	dp_test_intf_virt_del(name);
}

void _dp_test_intf_vrf_if_create(const char *name, vrfid_t vrf_id,
				     uint32_t tableid, const char *file,
				     int line)
{
	dp_test_intf_virt_add(name);
	_dp_test_netlink_create_vrf_if(name, vrf_id, tableid, true,
					   file, NULL, line);
}

void _dp_test_intf_vrf_if_delete(const char *name, vrfid_t vrf_id,
				     uint32_t tableid, const char *file,
				     int line)
{
	_dp_test_netlink_del_vrf_if(name, vrf_id, tableid, true,
					file, NULL, line);
	dp_test_intf_virt_del(name);
}
