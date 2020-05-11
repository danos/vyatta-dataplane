/* pppoe.h
 *
 * Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef PPPOE_H
#define PPPOE_H

#include <rte_ether.h>
#include <rte_malloc.h>
#include <inttypes.h>
#include <linux/if_ether.h>
#include <linux/ppp_defs.h>
#include <urcu.h>

#include "pl_common.h"
#include "if_var.h"

#define PPPOE_VER_TYPE(v, t)(((v) << 4) | (t))

/* A PPPoE Packet, including Ethernet headers */
struct pppoe_packet {
	struct rte_ether_hdr eth_hdr;   /* Ethernet header */
	uint8_t vertype; /* PPPoE Version and Type (must both be 1) */
	uint8_t code;	/* PPPoE code */
	uint16_t session;	/* PPPoE session */
	uint16_t length; /* Payload length */
	uint16_t protocol; /* Inner proto type (differs from ether types) */
};

/* PPPoE Tag */
struct pppoe_tag {
	uint16_t type;   /* tag type */
	uint16_t length; /* Length of payload */
};
 /* Header size of a PPPoE tag */
 #define TAG_HDR_SIZE 4

struct pppoe_connection {
	struct rcu_head scpppoe_rcu;
	struct rte_ether_addr my_eth; /* My MAC address */
	struct rte_ether_addr peer_eth; /* Peer's MAC address */
	uint16_t session;		/* Session ID */
	char *service_name;		/* Desired service name, if any */
	char *ac_name;		/* Desired AC name, if any */
	struct pppoe_tag host_uniq;		/* Use Host-Uniq tag */
	struct pppoe_tag cookie;	/* We have to send this if we get it */
	struct pppoe_tag relay_id;	/* Ditto */
	int mtu;			/* Stored MTU */
	int mru;			/* Stored MRU */
	int valid;
	struct ifnet *underlying_interface;
	uint32_t underlying_ifindex;
	char underlying_name[IFNAMSIZ];
	struct cds_list_head list_node;
	struct ifnet *ifp; /* pointer back to containing ifp */
};

/* cds_lfht_hash helpers follow */
#define PPPOE_HASH_MIN_BUCKETS 4
#define PPPOE_HASH_MAX_BUCKETS 16

struct pppoe_session_key {
	uint16_t session;
	uint32_t underlying_ifindex;
};

struct pppoe_map_tbl {
	struct rcu_head rcu_head;
	struct cds_lfht *ht;
};

struct pppoe_map_tbl *pppoe_map_tbl;

struct pppoe_map_node {
	uint16_t session;
	struct rcu_head pppoe_rcu;
	struct ifnet *ppp;
	struct cds_lfht_node pnode;
};

bool ppp_do_encap(struct rte_mbuf *m,
		struct pppoe_connection *conn, uint16_t proto, bool output);
void ppp_tunnel_output(struct ifnet *ifp, struct rte_mbuf *m,
		       struct ifnet *input_ifp, uint16_t proto);
int cmd_pppoe(FILE *f, int argc, char **argv);
struct ifnet *ppp_lookup_ses(struct ifnet *underlying_interface,
	uint16_t session);
void ppp_remove_ses(uint32_t ifindex, uint16_t session);
bool pppoe_init_session(struct ifnet *ppp_dev, uint16_t session);
struct cds_list_head *pppoe_get_conn_list(void);
void pppoe_track_underlying_interfaces(void);
#endif /* PPPOE_H */
