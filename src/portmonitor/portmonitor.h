/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef PORTMONITOR_H
#define PORTMONITOR_H

#include <netinet/in.h>
#include <linux/if.h>
#include <fal_plugin.h>

#define MAX_PORTMONITOR_SESSIONS		8
#define MAX_PORTMONITOR_SRC_INTF		8

#define PORTMONITOR_DIRECTION_RX		0x01
#define PORTMONITOR_DIRECTION_TX		0x02

#define ERSPAN_ORIG_FRAME_NO_VLAN		0x0
#define ERSPAN_ORIG_FRAME_ISL_ENCAP		0x01
#define ERSPAN_ORIG_FRAME_802_1Q_ENCAP		0x02
#define ERSPAN_ORIG_FRAME_VLAN_PRESERVED	0x03

#define ERSPAN_ORIG_FRAME_NO_ERR		0x0
#define ERSPAN_ORIG_FRAME_SHORT			0x01
#define ERSPAN_ORIG_FRAME_OVERSIZED		0x02
#define ERSPAN_ORIG_FRAME_CRC_OR_ALIGN_ERR	0x03

#define ERSPAN_ORIG_FRAME_TYPE_ETH		0x0
#define ERSPAN_ORIG_FRAME_TYPE_IP		0x02

#define ERSPAN_TIMESTAMP_GRA_100MS		0x0
#define ERSPAN_TIMESTAMP_GRA_100NS		0x01
#define ERSPAN_TIMESTAMP_GRA_IEEE_1588		0x02

#define ERSPAN_SUBHDR_PLATFORM_ID		0x03

#define ERSPAN_TYPE_II_GRE_PROTOCOL_TYPE	0x88BE
#define ERSPAN_TYPE_III_GRE_PROTOCOL_TYPE	0x22EB

#define ERSPAN_HARDWARE_ID	0x33	/* unique ID */

#define ERSPAN_VERSION(ver_vlan)	((ver_vlan) >> 12)
#define ERSPAN_VLAN(ver_vlan)		((ver_vlan) & 0xFFF)
#define ERSPAN_ID(cos_en_t_id)		((cos_en_t_id) & 0x03FF)
#define ERSPAN_EN(cos_en_t_id)		(((cos_en_t_id) >> 11) & 0x3)

enum {
	PORTMONITOR_NONE = 0,
	PORTMONITOR_SPAN,
	PORTMONITOR_RSPAN_SOURCE,
	PORTMONITOR_RSPAN_DESTINATION,
	PORTMONITOR_ERSPAN_SOURCE,
	PORTMONITOR_ERSPAN_DESTINATION,
};

enum {
	ERSPAN_TYPE_II = 1,
	ERSPAN_TYPE_III,
};

enum {
	PORTMONITOR_IN_FILTER = 1,
	PORTMONITOR_OUT_FILTER,
};

enum {
	PORTMONITOR_FILTER_SET = 1,
	PORTMONITOR_FILTER_DELETE,
};

enum {
	PM_SRC_SESSION_SRC_IF = 1,
	PM_DST_SESSION_SRC_IF,
	PM_SESSION_DST_IF,
};

struct portmonitor_filter {
	char		*name;		/* filtr name */
	uint8_t		type;		/* filter type: in or out */
};

struct portmonitor_srcif {
	struct ifnet			*ifp;		/* source ifp */
	char				ifname[IFNAMSIZ]; /* source ifname */
	struct portmonitor_session	*pm_session;	/* srcif session */
	struct cds_list_head		srcif_list;	/* Linked list chain */
	struct rcu_head			srcif_rcu;	/* Chain for rcu free */
};

struct erspan_v2_hdr {
	uint16_t	version_vlan;	/* ERSPAN version and orignal VLAN */
	uint16_t	cos_en_t_id;	/* CoS,encap type,truncated,ERSPAN ID */
	uint32_t	index;		/* port ID and traffic direction */
} __attribute__((__packed__));

struct erspan_v3_subhdr {
	uint32_t	platid_portid;	/* platform specific sub-header type */
	uint32_t	timestamp;	/* timestamp seconds value */
} __attribute__((__packed__));

struct erspan_v3_hdr {
	uint16_t version_vlan;		/* ERSPAN version and orignal VLAN */
	uint16_t cos_bso_t_id;		/* CoS,bso,truncated,ERSPAN ID */
	uint32_t timestamp;		/* timestamp nanoseconds value */
	uint16_t sgt;			/* security group tag */
	uint16_t p_ft_hwid_d_gra_o;	/*prot,frametype,HWID,dir,gran,subhdr*/
	struct erspan_v3_subhdr subhdr3;	/* sub-header type 0x3 */
} __attribute__((__packed__));

struct portmonitor_session {
	struct cds_list_head	session_list;		/* Linked list chain */
	uint8_t			session_id;		/* session ID */
	uint8_t			session_type;		/* session type */
	bool			disabled;		/* session disabled */
	uint8_t			srcif_cnt;		/* source intf cnt */
	uint16_t		erspan_id;		/* erspan id */
	uint8_t			erspan_hdr_type;	/* erspan hdr type */
	uint16_t		gre_proto;		/* GRE protocol */
	struct ifnet		*dest_ifp;		/* destination ifp */
	char			dest_ifname[IFNAMSIZ];	/* destination ifname */
	zlist_t			*filter_list;		/* in and out filters */
	struct rcu_head		session_rcu;		/* Chain for rcu free */
	fal_object_t		fal_obj;		/* Fal object */
};

struct portmonitor_info {
	uint8_t				pm_iftype;	/* src/dst interface */
	uint8_t				direction;	/* Both/RX/TX */
	struct portmonitor_session	*pm_session;	/* srcif session */
	struct rcu_head			pminfo_rcu;	/* Chain for RCU free */
	bool				hw_mirroring;   /* hw mirroring */
};

void portmonitor_src_vif_rx_output(struct ifnet *ifp, struct rte_mbuf **m)
					__attribute__((cold));
void portmonitor_src_vif_tx_output(struct ifnet *ifp, struct rte_mbuf **m)
					__attribute__((cold));
void portmonitor_src_phy_rx_output(struct ifnet *ifp, struct rte_mbuf *mbi[],
					unsigned int n) __attribute__((cold));
void portmonitor_src_phy_tx_output(struct ifnet *ifp, struct rte_mbuf *mbi[],
					unsigned int n) __attribute__((cold));
int portmonitor_dest_output(struct ifnet *ifp, struct rte_mbuf *m)
	__attribute__((cold));
void portmonitor_cleanup(struct ifnet *ifp);

#endif /* PORTMONITOR_H */
