/*-
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2013-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef QOS_H
#define QOS_H


#include <rte_sched.h>

#include "if_var.h"
#include "npf/npf_ruleset.h"
#include "fal_plugin.h"
#include "json_writer.h"

struct rte_sched_port;

#define DEFAULT_QSIZE	64	/* 64 packets */
#define MAX_QSIZE	8192	/* 8192 packets */
#define DEFAULT_TBSIZE	10000	/* 10000 bytes or credits (1 byte/credit) */
#define DEFAULT_PERIOD	10000	/* 10000 microseconds */
#define DEFAULT_Q	3	/* class 3: queue 0 */
#define MAX_PIPES       256

#define MAX_RED_QUEUE_LENGTH 8192   /* 8192 packets */

#define	QOS_DPDK_ID	0
#define	QOS_HW_ID	1
#define	NUM_DEVS	2

#define QOS_MAX_DROP_PRECEDENCE 2

/*
 * We support 2 queues with up to 4 WRED profiles configured per queue
 * so allow a maximum of 8 per profile.
 */
#define QOS_NUM_DSCP_MAPS 8
#define QOS_MAX_DSCP_MAPS (QOS_NUM_DSCP_MAPS - 1)

/*
 * Maximum burst size in bytes supported by DPDK. This value must match the
 * burst-size maximum range given in vyatta-npf-v1.yang.
 */
#define QOS_MAX_BURST_SIZE_DPDK    (312500000) // 100ms at 25Gbit/sec
#define QOS_MAX_BURST_SIZE_DEFAULT QOS_MAX_BURST_SIZE_DPDK

struct npf_act_grp;

enum qos_queue_size_type {
	QOS_QUEUE_SIZE_PACKETS,
	QOS_QUEUE_SIZE_BYTES,
	QOS_QUEUE_SIZE_USEC
};

enum qos_state {
	QOS_INSTALL,
	QOS_NPF_READY,
	QOS_NPF_COMMIT
};

struct qos_red_params {
	uint32_t	min_th;
	uint32_t	max_th;
	enum qos_queue_size_type qsize_type;
	uint16_t	maxp_inv;
	/* Negated log2 of queue weight
	 * (wq = 1 / (2 ^ wq_log2))
	 */
	uint16_t	wq_log2;
};

/*
 * This holds the names of the dscp groups and the masks.
 * We need to save this incase a resource group is changed
 * and we need to reset the classification indices.
 */
struct qos_dscp_map {
	unsigned int num_maps;
	uint8_t qmap[QOS_NUM_DSCP_MAPS];
	char *dscp_grp_names[QOS_NUM_DSCP_MAPS];
	uint64_t dscp_mask[QOS_NUM_DSCP_MAPS];
};

enum egress_map_type {
	EGRESS_UNDEF = 0,
	EGRESS_DSCP = 1,
	EGRESS_DESIGNATION = 2,
	EGRESS_DSCPGRP_DSCP = 3,
	EGRESS_DESIGNATION_PCP = 4
};

struct qos_mark_map_entry {
	uint8_t des;
	enum fal_packet_colour color;
	uint8_t pcp_value;
};

struct dscp_grp_list {
	SLIST_ENTRY(dscp_grp_list) list;
	uint8_t pcp_val;
	char name[0];
};

struct qos_mark_map {
	struct rcu_head obj_rcu;
	struct cds_list_head list;
	enum egress_map_type type;
	union {
		uint8_t des_used;
		uint64_t dscp_used;
	};
	union {
		struct qos_mark_map_entry entries[FAL_QOS_MAP_DES_DP_VALUES];
		uint8_t pcp_value[MAX_DSCP];
	};
	fal_object_t mark_obj;
	SLIST_HEAD(dscp_grps, dscp_grp_list) dscp_grps;
	char map_name[0];
};

struct qos_rate_info {
	bool bw_is_percent;
	union _bw_info {
		float bw_percent;
		uint64_t bandwidth;
	} rate;

	bool burst_is_time;
	union _burst_info {
		uint32_t size;
		uint32_t time_ms;
	} burst;

	uint32_t period;
};

struct qos_tc_rate_info {
	struct qos_rate_info tc_rate[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
};

struct qos_shaper_conf {
	uint64_t	tb_rate;	/* bytes/sec */
	uint64_t	tc_rate[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	uint32_t	tc_period;
	uint32_t	tb_size;
#ifdef RTE_SCHED_SUBPORT_TC_OV
	uint8_t		tc_ov_weight;	/* Weight TC 3 oversubscription */
#endif
};

static_assert(sizeof(struct qos_shaper_conf) ==
	      sizeof(struct rte_sched_subport_params),
	      "qos and dpdk structures are not of same size");

/* Qos Scheduler sub port (one per vlan) */
struct subport_info {
	char attach_name[IFNAMSIZ + sizeof("/4294967295")];
		/* Big enough to hold: "<if-name>/<unsigned-int>" */
	struct npf_config *npf_config;
	struct npf_act_grp *act_grp_list;
	struct mark_reqs *marks;
	uint8_t *profile_map;		/* pipe to profile */
	struct qos_shaper_conf params;
	struct qos_rate_info subport_rate;
	struct qos_tc_rate_info sp_tc_rates;

	uint32_t match_id;		/* Used as index for npf matches */
	uint32_t vlan_id;
	struct rte_sched_subport_stats64 queue_stats; /* Non-zeroing counts */
	struct rte_sched_subport_stats64 clear_stats; /* Counts at last clear */
	uint32_t qsize[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	enum qos_queue_size_type qsize_type;
	struct qos_red_params red_params[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE]
					[RTE_COLORS];
	bool pipe_configured[MAX_PIPES];
	struct qos_mark_map *mark_map;
	bool auto_speed;
};

/* DSCP and PCP maps (per profile) */
struct queue_map {
	uint8_t pcp2q[MAX_PCP];	/* Priority Code Point -> queue */
	uint8_t dscp2q[MAX_DSCP];/* DSCP -> queue */
	uint8_t local_priority_queue; /* Queue for hi-prio from-us packets */
	uint8_t pcp_enabled:1,	/* Flag to track user-defined PCP map */
		dscp_enabled:1, /* Flag to track user-defined DSCP map */
		local_priority:1, /* Local priority queue enabled */
		designation:1,
		unused:4;
	uint8_t conf_ids[RTE_SCHED_QUEUES_PER_PIPE]; /* The configured Q ids */
	struct qos_dscp_map *dscp_maps;
	uint64_t reset_mask;
};

/* Egress map sub-port/VIF information */
struct egress_map_subport_info {
	SLIST_ENTRY(egress_map_subport_info) egr_map_list;
	int vlan_id;
	fal_object_t egr_map_obj;
};

/* Egress map infprmation per Physical port */
struct egress_map_info {
	SLIST_HEAD(egr_map_head, egress_map_subport_info) egr_map_head;
};

#define CONF_ID_Q_CONFIG  0x80
#define CONF_ID_Q_DEFAULT 0x40
#define CONF_ID_Q_IN_USE (CONF_ID_Q_CONFIG | CONF_ID_Q_DEFAULT)

enum ingress_map_type {
	INGRESS_UNDEF = 0,
	INGRESS_DSCP,
	INGRESS_PCP
};

#define	INGRESS_DESIGNATORS	8
#define	MAX_DESIGNATOR		7
/* We currently support 3 levels of drop precedence; green, yellow and red */
#define	NUM_DPS			3
#define	MAX_DP			2

/* Qos queue counters (one per queue) */
struct queue_stats {
	/* The ever-increasing counts */
	uint64_t n_bytes;
	uint64_t n_bytes_dropped;
	uint64_t n_pkts;
	uint64_t n_pkts_dropped;
	uint64_t n_pkts_red_dropped;
	uint64_t n_pkts_red_dscp_dropped[RTE_NUM_DSCP_MAPS];
	/* The values of the ever-increasing counts at the last clear */
	uint64_t n_bytes_lc;
	uint64_t n_bytes_dropped_lc;
	uint64_t n_pkts_lc;
	uint64_t n_pkts_dropped_lc;
	uint64_t n_pkts_red_dropped_lc;
	uint64_t n_pkts_red_dscp_dropped_lc[RTE_NUM_DSCP_MAPS];
};

struct qos_red_q_params {
	uint64_t	dscp_set[RTE_NUM_DSCP_MAPS];
	struct qos_red_params qparams[RTE_NUM_DSCP_MAPS];
	char		*grp_names[RTE_NUM_DSCP_MAPS];
	uint8_t		num_maps;
	uint8_t		filter_weight;
	uint8_t         dps_in_use;
};

struct qos_red_pipe_params {
	SLIST_ENTRY(qos_red_pipe_params) list;
	struct qos_red_q_params red_q_params;
	uint32_t	qindex;
	bool		alloced;
};

struct qos_pipe_params {
	struct qos_shaper_conf	shaper;
	uint8_t		wrr_weights[RTE_SCHED_QUEUES_PER_PIPE];
	uint8_t		designation[INGRESS_DESIGNATORS];
	uint8_t		des_set;
	SLIST_HEAD(red_head, qos_red_pipe_params) red_head;
};

struct qos_port_params {
	struct qos_pipe_params	*pipe_profiles;
	uint32_t	n_pipe_profiles;
	uint32_t	mtu;
	uint64_t	rate;	/* Port rate in bytes/sec */
	int32_t		frame_overhead;
	uint32_t	n_subports_per_port;
	uint32_t	n_pipes_per_subport;
	uint32_t	qsize[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	enum qos_queue_size_type qsize_type;
};

/* Qos Scheduler handles (one per physical port) */
struct sched_info {
	int dev_id;			/* Device ID - DPDK or FAL */
	struct ifnet *ifp;
	union _dev_info {
		struct _dpdk {
			struct rte_sched_port *port;	/* DPDK object */
		} dpdk;
		struct _fal {
			fal_object_t hw_port_sched_group; /* FAL object */
			uint32_t hw_port_id;              /* FAL id */
		} fal;
	} dev_info;
	struct subport_info *subport;	/* Subport's */
	struct qos_port_params port_params;
	struct qos_rate_info *profile_rates;
	struct qos_tc_rate_info *profile_tc_rates;
	struct qos_rate_info port_rate;
	bool    enabled;
	enum qos_state	reset_port;
	struct rcu_head rcu;

	/* subports and pipes as configured, actual size is in port_params */
	uint32_t n_subports;		/* Original values */
	uint32_t n_pipes;

	uint16_t vlan_map[VLAN_N_VID];	/* Vlan vid to sub-port policy */
	struct queue_map *queue_map;
	struct queue_stats *queue_stats;
	rte_spinlock_t stats_lock;      /* To control access to queue-stats */
	SLIST_ENTRY(sched_info) list;
};

struct mark_reqs {
	struct mark_reqs *next;
	void             **handle;
	int		refs;
	enum qos_mark_type {
		MARK,
		POLICE
	} type;
};

struct qos_show_context {
	json_writer_t *wr;
	bool optimised_json;
	bool is_platform;
	bool sent_sysdef_map;
};

/*
 * This structure is used as the device plug in structure.
 * There will always be one for the DPDK, we may need a second
 * one if there's also a hardware forwarding path.
 */
struct qos_dev {
	int (*qos_init)(void);
	int (*qos_disable)(struct ifnet *ifp, struct sched_info *q);
	int (*qos_enable)(struct ifnet *ifp, struct sched_info *q);
	int (*qos_start)(struct ifnet *ifp, struct sched_info *q,
			 uint64_t bps, uint16_t min_len);
	int (*qos_stop)(struct ifnet *ifp, struct sched_info *q);
	void (*qos_free)(struct sched_info *q);
	int (*qos_subport_read_stats)(struct sched_info *q, uint32_t sub,
				      struct rte_sched_subport_stats64 *st);
	int (*qos_subport_clear_stats)(struct sched_info *q, uint32_t sub);
	int (*qos_queue_read_stats)(struct sched_info *q, uint32_t subport,
				    uint32_t pipe, uint32_t tc, uint32_t queue,
				    struct queue_stats *st, uint64_t *qlen,
				    bool *qlen_in_pkts);
	int (*qos_queue_clear_stats)(struct sched_info *q, uint32_t subport,
				     uint32_t pipe, uint32_t tc,
				     uint32_t queue);
	void (*qos_dscp_resgrp_json)(struct sched_info *qinfo, uint32_t subport,
				     uint32_t pipe, uint32_t tc, uint32_t q,
				     uint64_t *random_dscp_drop,
				     json_writer_t *wr);
	uint64_t (*qos_check_rate)(uint64_t rate, uint64_t parent_bw);
};

extern struct qos_dev qos_devices[];

extern fal_object_t qos_global_map_obj;

/* Encode DPDK Traffic-Class and Queue */
#define QMAP(tc, wrr)	(wrr << RTE_SCHED_TC_BITS | (tc))

#define	QOS_FREE(qinfo)		qos_devices[qinfo->dev_id].qos_free
#define	QOS_START(qinfo)	qos_devices[qinfo->dev_id].qos_start
#define	QOS_STOP(qinfo)		qos_devices[qinfo->dev_id].qos_stop
#define	QOS_SUBPORT_RD_STATS(qinfo) \
			qos_devices[qinfo->dev_id].qos_subport_read_stats
#define	QOS_SUBPORT_CLR_STATS(qinfo) \
			qos_devices[qinfo->dev_id].qos_subport_clear_stats
#define	QOS_QUEUE_RD_STATS(qinfo) \
			qos_devices[qinfo->dev_id].qos_queue_read_stats
#define	QOS_QUEUE_CLR_STATS(qinfo) \
			qos_devices[qinfo->dev_id].qos_queue_clear_stats
#define	QOS_DISABLE(qinfo)	qos_devices[qinfo->dev_id].qos_disable
#define	QOS_ENABLE(qinfo)	qos_devices[qinfo->dev_id].qos_enable
#define QOS_DSCP_RESGRP_JSON(qinfo) \
			qos_devices[qinfo->dev_id].qos_dscp_resgrp_json
#define QOS_CHECK_RATE(qinfo) qos_devices[qinfo->dev_id].qos_check_rate
#define QOS_CONFIGURED(qinfo) \
	(qinfo->dev_info.dpdk.port || qinfo->dev_info.fal.hw_port_id)

/*
 * Given an interface walk back to the parent device (if a vlan)
 * to find the QoS handle (if any)
 */
static inline struct sched_info *qos_handle(const struct ifnet *ifp)
{
	if (likely(!ifp->qos_software_fwd))
		return NULL;

	return rcu_dereference(ifp->if_qos);
}

/*
 * The bottom RTE_SCHED_TC_BITS bits is the TC.
 * The next RTE_SCHED_WRR_BITS is the q index.
 * The next two bits are the drop precedence
 */
static inline unsigned int q_from_mask(unsigned int value)
{
	return ((value & RTE_SCHED_TC_MASK) *
		RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS) +
		((value >> RTE_SCHED_TC_BITS) & RTE_SCHED_WRR_MASK);
}

/*
 * Functions to insert/extract { traffic-class, queue, drop-precedence } from
 * the map
 */
static inline uint8_t qmap_to_tc(uint8_t m)
{
	return m & RTE_SCHED_TC_MASK;
}

static inline uint8_t qmap_to_wrr(uint8_t m)
{
	return (m >> RTE_SCHED_TC_BITS) & RTE_SCHED_WRR_MASK;
}

static inline uint8_t qmap_to_dp(uint8_t m)
{
	return m >> RTE_SCHED_TC_WRR_BITS;
}

#define DES_IN_USE 0x80

/*
 * Search for the designation value for this queue.
 * If there isn't one allocate the next free one.
 */
static inline bool qos_qmap_to_des(uint8_t q, uint8_t *des2q, int *ind)
{
	int i;

	for (i = 0; i < INGRESS_DESIGNATORS; i++) {
		if (des2q[i] == (DES_IN_USE | q_from_mask(q))) {
			*ind = i;
			return true;
		}
	}
	for (i = 0; i < INGRESS_DESIGNATORS; i++) {
		if (des2q[i] & DES_IN_USE)
			continue;
		des2q[i] = DES_IN_USE | q_from_mask(q);
		*ind = i;
		return true;
	}
	return false;
}

_Static_assert(sizeof(struct rte_sched_subport_params) !=
	       sizeof(struct rte_sched_pipe_params),
	       "Structures should be the same size.");

void qos_sched_subport_params_check(struct qos_shaper_conf *params,
				struct qos_rate_info *config_rate,
				struct qos_rate_info *config_tc_rate,
				uint16_t max_pkt_len, uint32_t max_burst_size,
				uint64_t bps,
				struct sched_info *qinfo);


static inline void qos_sched_pipe_check(struct sched_info *qinfo,
					uint16_t max_pkt_len,
					uint32_t max_burst_size, uint64_t bps)
{
	unsigned int profile;

	for (profile = 0;
	     profile < qinfo->port_params.n_pipe_profiles;
	     profile++) {
		unsigned int subport;
		uint64_t parent_rate = bps;
		struct qos_pipe_params *p
			= qinfo->port_params.pipe_profiles + profile;

		/*
		 * Find the subport each pipe profile is associated with.
		 * This will allow the pipe rate (and its TCs) to be restored
		 * based on its parent subport rate.
		 */
		for (subport = 0;
		     subport < qinfo->port_params.n_subports_per_port;
		     subport++) {
			unsigned int pipe;
			struct subport_info *sinfo = qinfo->subport + subport;

			for (pipe = 0; pipe < MAX_PIPES; pipe++) {
				if (sinfo->pipe_configured[pipe] &&
				    sinfo->profile_map[pipe] == profile) {
					parent_rate = sinfo->params.tb_rate;
					break;
				}
			}
			if (pipe != MAX_PIPES)
				break;
		}

		/*
		 * Make sure no pipe is faster than actual line or subport rate.
		 * We're casting the pipe params to the subport params, which
		 * will work as long as they share the first 4 fields. If this
		 * breaks, check if these structures have changed.
		 */
		qos_sched_subport_params_check(
			&p->shaper,
			&qinfo->profile_rates[profile],
			qinfo->profile_tc_rates[profile].tc_rate,
			max_pkt_len, max_burst_size, parent_rate, qinfo);
	}
}

struct ingress_designator {
	uint8_t		dps_in_use;
	uint64_t	mask[NUM_DPS];
};

struct qos_ingress_map {
	struct rcu_head			obj_rcu;
	struct cds_list_head		list;
	enum ingress_map_type		type;
	struct ingress_designator	designation[INGRESS_DESIGNATORS];
	bool				sysdef;
	fal_object_t			map_obj;
	char				name[0];
};

/*
 * The ingress map plugin structure.
 */
struct qos_ingressm {
	int (*qos_ingressm_attach)(unsigned int ifindex, unsigned int vlan,
				   struct qos_ingress_map *map);
	int (*qos_ingressm_detach)(unsigned int ifindex, unsigned int vlan);
	int (*qos_ingressm_config)(struct qos_ingress_map *map, bool create);
};

extern struct qos_ingressm qos_ingressm;

/*
 * The egress map plugin structure.
 */
struct qos_egressm {
	int (*qos_egressm_attach)(unsigned int ifindex, unsigned int vlan,
				   struct qos_mark_map *map);
	int (*qos_egressm_detach)(unsigned int ifindex, unsigned int vlan,
				   struct qos_mark_map *map);
	int (*qos_egressm_config)(struct qos_mark_map *map, bool create);
};

extern struct qos_egressm qos_egressm;

void qos_init(void);
int qos_sched_start(struct ifnet *ifp, uint64_t link_speed);
void qos_sched_stop(struct ifnet *ifp);
uint32_t qos_sched_calc_qindex(struct sched_info *qinfo, unsigned int subport,
			       unsigned int pipe, unsigned int tc,
			       unsigned int q);
bool qos_wred_threshold_get(struct qos_red_params *wred_params,
		uint64_t rate, uint32_t *wred_min_th, uint32_t *wred_max_th);
uint32_t qos_queue_size_get(uint32_t qsize,
		enum qos_queue_size_type qsize_type,
		uint64_t rate);
uint32_t qos_sp_qsize_get(struct qos_port_params *pp,
			  struct subport_info *sinfo, int tc);
struct sched_info;
int qos_sched(struct ifnet *ifp, struct sched_info *qinfo,
	      struct rte_mbuf *enq_pkts[], uint32_t n_pkts,
	      struct rte_mbuf *deq_pkts[], uint32_t space);
struct subport_info *qos_get_subport(const char *name, struct ifnet **ifp);
struct npf_act_grp *qos_ag_get_head(struct subport_info *subport);
struct npf_act_grp *qos_ag_set_or_get_head(struct subport_info *subport,
					   struct npf_act_grp *act_grp);
int16_t qos_get_overhead(const char *name);
int16_t qos_get_overhead_from_ifnet(struct ifnet *ifp);
bool qos_sched_subport_get_stats(struct sched_info *qinfo, uint16_t vlan_id,
				 struct rte_sched_subport_stats64 *stats);
struct ifnet *qos_get_vlan_ifp(const char *att_pnt, uint16_t *vlan_id);
void qos_save_mark_req(const char *att_pnt, enum qos_mark_type type,
		       uint16_t refs, void **handle);
void qos_save_mark_v_pol(npf_rule_t *rl, void *po);
void qos_enable_inner_marking(struct ifnet *ifp, uint16_t vlan_id);
void qos_disable_inner_marking(struct ifnet *ifp, uint16_t vlan_id);
void qos_subport_npf_free(struct sched_info *qinfo);
struct sched_info *qos_sched_new(struct ifnet *ifp, unsigned int subports,
				 unsigned int pipes, unsigned int profiles,
				 int32_t overhead);
void qos_sched_free(struct sched_info *qinfo);
void qos_sched_free_rcu(struct rcu_head *head);
uint8_t qos_get_prio_lp_des(void);
int qos_sched_disable(struct ifnet *ifp, struct sched_info *qinfo);

int qos_hw_show_port(struct ifnet *ifp, void *arg);
void qos_hw_dump_map(json_writer_t *wr, const struct sched_info *qinfo,
		     uint32_t subport, uint32_t pipe);
void qos_hw_dump_subport(json_writer_t *wr, const struct sched_info *qinfo,
			 uint32_t subport);
void qos_hw_dump_buf_errors(json_writer_t *wr);
struct qos_red_pipe_params *
qos_red_find_q_params(struct qos_pipe_params *pipe, unsigned int qindex);
struct qos_red_pipe_params *
qos_red_alloc_q_params(struct qos_pipe_params *pipe, unsigned int qindex);

/* The DPDK plugin functions */
void qos_dpdk_dscp_resgrp_json(struct sched_info *qinfo, uint32_t subport,
			       uint32_t pipe, uint32_t tc, uint32_t q,
			       uint64_t *random_dscp_drop,
			       json_writer_t *wr);
int qos_dpdk_subport_read_stats(struct sched_info *qinfo, uint32_t subport,
				struct rte_sched_subport_stats64 *stats);
int qos_dpdk_subport_clear_stats(struct sched_info *qinfo, uint32_t subport);
int qos_dpdk_queue_read_stats(struct sched_info *qinfo, uint32_t subport,
			      uint32_t pipe, uint32_t tc, uint32_t q,
			      struct queue_stats *queue_stats, uint64_t *qlen,
			      bool *qlen_in_pkts);
int qos_dpdk_queue_clear_stats(struct sched_info *qinfo,
			       uint32_t subport, uint32_t pipe,
			       uint32_t tc, uint32_t q);
void qos_dpdk_free(struct sched_info *qinfo);
int qos_dpdk_port(struct ifnet *ifp,
		  unsigned int subports, unsigned int pipes,
		  unsigned int profiles, unsigned int overhead);
int qos_dpdk_disable(struct ifnet *ifp, struct sched_info *qinfo);
int qos_dpdk_enable(struct ifnet *ifp,
		    struct sched_info *qinfo);
int qos_dpdk_stop(__unused struct ifnet *ifp, struct sched_info *qinfo);
int qos_dpdk_start(struct ifnet *ifp, struct sched_info *qinfo,
		   uint64_t bps, uint16_t max_pkt_len);
uint64_t qos_dpdk_check_rate(uint64_t rate, uint64_t parent_bw);

/* The HW forwarding plugin functions */
fal_object_t
qos_hw_get_ingress_map(uint32_t port_obj_id, uint32_t subport_id,
		       uint32_t pipe_id);
fal_object_t
qos_hw_get_egress_map(uint32_t port_obj_id, uint32_t subport_id,
		      uint32_t pipe_id);
fal_object_t
qos_hw_get_subport_sg(uint32_t port_obj_id, uint32_t subport_id);
void qos_hw_dscp_resgrp_json(struct sched_info *qinfo, uint32_t subport,
			     uint32_t pipe, uint32_t tc, uint32_t q,
			     uint64_t *random_dscp_drop,
			     json_writer_t *wr);
int qos_hw_subport_read_stats(struct sched_info *qinfo, uint32_t subport,
			      struct rte_sched_subport_stats64 *stats);
int qos_hw_subport_clear_stats(struct sched_info *qinfo, uint32_t subport);
int qos_hw_queue_read_stats(struct sched_info *qinfo, uint32_t subport,
			    uint32_t pipe, uint32_t tc, uint32_t queue,
			    struct queue_stats *stats, uint64_t *qlen,
			    bool *qlen_in_pkts);
int qos_hw_queue_clear_stats(struct sched_info *qinfo, uint32_t subport,
			     uint32_t pipe, uint32_t tc, uint32_t q);
void qos_hw_free(__unused struct sched_info *qinfo);
int qos_hw_port(struct ifnet *ifp,
		unsigned int subports, unsigned int pipes,
		unsigned int profiles, unsigned int overhead);
int qos_hw_disable(__unused struct ifnet *ifp, struct sched_info *qinfo);
int qos_hw_enable(struct ifnet *ifp, struct sched_info *qinfo);
int qos_hw_stop(__unused struct ifnet *ifp,
		__unused struct sched_info *qinfo);
int qos_hw_start(__unused struct ifnet *ifp, struct sched_info *qinfo,
		 uint64_t bps, uint16_t max_pkt_len);
uint64_t qos_hw_check_rate(uint64_t rate, uint64_t parent_bw);
int qos_hw_init(void);
void qos_hw_del_map(fal_object_t mark_obj);
void qos_hw_show_legacy_map(struct queue_map *qmap, json_writer_t *wr);
fal_object_t qos_hw_get_att_ingress_map(struct ifnet *ifp, unsigned int vlan);
fal_object_t qos_hw_get_att_egress_map(struct ifnet *ifp, unsigned int vlan);
struct qos_mark_map *qos_egress_map_find(char const *name);
void qos_abs_rate_save(struct qos_rate_info *bw_info, uint64_t abs_bw);
struct egress_map_subport_info *qos_egress_map_subport_get(
		struct ifnet *parent_ifp, int vlan_id);
struct egress_map_subport_info *qos_egress_map_subport_new(struct ifnet *ifp,
				 struct ifnet *parent_ifp, bool is_sub_if);
uint32_t *qos_interface_hw_stats_get(void);
uint32_t *qos_vlan_hw_stats_get(void);

#endif /* QOS_H */
