/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef SESSION_H
#define SESSION_H

#include <arpa/inet.h>
#include <rte_atomic.h>
#include <rte_spinlock.h>
#include <stdbool.h>
#include <stdint.h>
#include <urcu/list.h>

#include "if_var.h"
#include "urcu.h"
#include "util.h"

struct ifnet;
struct rte_mbuf;

/*
 * For polling during UT cleanup.
 */
extern rte_atomic32_t session_rcu_counter;

/* Sentry Match Lengths in 32bit words */
#define SENTRY_LEN_IPV4		3
#define SENTRY_LEN_IPV6		9

/* Sentry flags */
enum {
	SENTRY_INIT	= 0x01,
	SENTRY_FORW	= 0x02,
	SENTRY_BACK	= 0x04,
	SENTRY_IPv4	= 0x08,
	SENTRY_IPv6	= 0x10,
};

/* Feature definitions */
enum session_feature_type {
	SESSION_FEATURE_ALL = 0,
	SESSION_FEATURE_TEST_INTERFACE,	/* For UTs, never delete */
	SESSION_FEATURE_TEST,		/* For UTs, never delete */
	SESSION_FEATURE_NPF,
	SESSION_FEATURE_END,		/* Must be last */
};

/* Session flags */
#define SESSION_EXPIRED		0x01
#define SESSION_NAT		0x02	/* This session was natted */
#define SESSION_INSERTED	0x04	/* Inserted in session ht */

enum session_log_event {
	SESSION_LOG_CREATION,
	SESSION_LOG_DELETION,
	SESSION_LOG_PERIODIC
};

struct session_log_cfg {
	uint8_t slc_log_creation:1;
	uint8_t	slc_log_deletion:1;
	uint8_t	slc_log_periodic:1;
	uint32_t slc_log_interval;
};

struct session;
struct session_feature;

/*
 * Feature operations.
 *
 * Note that if destroy is NULL, then free() is called.
 *
 * The 'pack' and 'unpack' ops require some detail. These routines are
 * called (if defined) during session syncing (aka: Connsync) on the
 * master node (pack) and peer node (unpack).
 *
 * The pack routine must write whatever data, in whatever format is desired.
 * It should only write data that is required to restore (unpack) the
 * feature datum on the peer node.
 *
 * If the pack routine returns non-zero, the feature will not be restored
 * on the remote node.
 *
 * The 'unpack' routine must resolve the data contained in the fp, and
 * if appropriate, do a session_feature_add() to restore the feature
 * on the peer.
 *
 * The 'json' op is called to enable the feature to jsonify any feature data.
 */
struct session_feature_ops {
	void	(*expired)(struct session *, uint32_t if_index,
			enum session_feature_type, void *);
	void	(*destroy)(struct session *, uint32_t if_index,
			enum session_feature_type, void *);
	void	(*json)(json_writer_t *json, struct session_feature *sf);
	void	(*log)(enum session_log_event event, struct session *s,
		       struct session_feature *sf);
};

#define SESS_FEAT_REQ_EXPIRY	0x01		/* feature marked for expiry */

/* session feature struct. */
struct session_feature {
	struct cds_lfht_node			sf_node;
	struct cds_lfht_node			sf_session_node;
	struct session				*sf_session;
	void					*sf_data;
	uint32_t				sf_idx;
	enum session_feature_type		sf_type;
	const struct session_feature_ops	*sf_ops;
	struct rcu_head				sf_rcu_head;
	uint64_t				sf_expire_time;
	uint16_t				sf_flags;
};

/* Session sentry structs. */
struct sentry {
	struct cds_lfht_node	sen_node;
	struct rcu_head		sen_rcu_head;
	struct session		*sen_session;
	uint32_t		sen_ifindex;
	uint16_t		sen_flags;
	uint8_t			sen_len;
	uint8_t			sen_protocol;
	uint32_t		sen_addrids[];	/* ids/addrs, must be last */
};

/* sentry_packet - decomposition of the packet */
struct sentry_packet {
	vrfid_t		sp_vrfid;			/* VRF id */
	uint32_t	sp_ifindex;			/* Interface index */
	uint16_t	sp_sentry_flags;		/* flags */
	uint8_t		sp_protocol;			/* ip protocol */
	uint8_t		sp_len;				/* match len */
	uint32_t	sp_addrids[SENTRY_LEN_IPV6];	/* ids and addrs */
};

/* Session link - Used by algs to link sessions */
struct session_link {
	struct cds_list_head	sl_children;
	struct session		*sl_parent;
	struct session		*sl_self;
	struct cds_list_head	sl_link;
	rte_spinlock_t		sl_lock;
	rte_atomic16_t		sl_refcnt;
};

/*
 * Session structure.
 *
 * N.B.  Layout is such that session lookup params are in the
 *       first cacheline.
 *
 * WARNING: If you add fields here, you must add them
 *          to session_pack.h if you need them on the
 *          session sync peer node.
 */
struct session {
	struct cds_lfht_node	se_node;
	vrfid_t			se_vrfid;
	rte_atomic16_t		se_feature_count; /* # feature data */
	rte_atomic16_t		se_feature_exp_count; /* # requesting expiry */
	rte_atomic16_t		se_link_cnt;	/* Child count */
	rte_atomic16_t		se_sen_cnt;	/* Sentry count */
	uint16_t		se_flags;
	uint8_t			se_protocol;
	uint8_t			pad[1];
	struct session_link	*se_link;	/* For linking of sessions */
	struct sentry		*se_sen;	/* Cached INIT sentry */
	uint64_t		se_id;		/* id of this session */
	uint32_t		se_custom_timeout;
	uint32_t		se_timeout;
	/* --- cacheline 1 boundary (64 bytes) --- */
	struct rcu_head		se_rcu_head;
	uint64_t		se_etime;	/* Expiration timeout */
	uint8_t			se_protocol_state; /* For display */
	uint8_t			se_idle:1;
	uint8_t			se_nat:1;	/* nat? */
	uint8_t			se_nat64:1;	/* nat64? */
	uint8_t			se_nat46:1;	/* nat46? */
	uint8_t			se_alg:1;	/* alg? */
	uint8_t			se_log_creation:1;
	uint8_t			se_log_deletion:1;
	uint8_t			se_log_periodic:1;
	uint32_t		se_log_interval;
	uint64_t		se_ltime;	/* time of next periodic log */
	uint64_t		se_create_time;	/* time session was created */
};

/* For UTs, counts of various sessions */
struct session_counts {
	uint32_t	sc_nat;		/* Num of NPF features with NAT */
	uint32_t	sc_nat64;	/* Num of NPF features with NAT64 */
	uint32_t	sc_nat46;	/* Num of NPF features with NAT46 */
	uint32_t	sc_tcp;		/* tcp sessions */
	uint32_t	sc_udp;		/* udp sessions */
	uint32_t	sc_icmp;	/* icmp sessions */
	uint32_t	sc_icmp6;	/* icmp-v6 sessions */
	uint32_t	sc_other;	/* All else */
	/* Counts of various feature types */
	uint32_t	sc_feature_counts[SESSION_FEATURE_END+1];
};

/* Session protos */

/**
 * Mark an ALG session.
 *
 * This state remains until the session is deleted.
 *
 * @param s  The session
 */
static inline void session_set_alg(struct session *s)
{
	s->se_alg = 1;
}

/**
 * Mark a session as being natted.
 *
 * This state remains until the session is deleted.
 *
 * @param s
 * The session
 */
static inline void session_set_nat(struct session *s)
{
	s->se_nat = 1;
}

/**
 * Mark a session as being nat64.
 *
 * This state remains until the session is deleted.
 *
 * @param s
 * The session
 */
static inline void session_set_nat64(struct session *s)
{
	s->se_nat64 = 1;
}

/**
 * Mark a session as being nat46.
 *
 * This state remains until the session is deleted.
 *
 * @param s
 * The session
 */
static inline void session_set_nat46(struct session *s)
{
	s->se_nat46 = 1;
}

/**
 * Test an ALG session.
 *
 * Test if this is an alg session
 *
 * @param s  The session
 */
static inline bool session_is_alg(struct session *s)
{
	return s->se_alg == 1;
}

/**
 * Test a session as being natted.
 *
 * Test if this is a nat session
 *
 * @param s
 * The session
 */
static inline bool session_is_nat(struct session *s)
{
	return s->se_nat == 1;
}

/**
 * Test if this is a nat64 session
 *
 * @param s
 * The session
 */
static inline bool session_is_nat64(struct session *s)
{
	return s->se_nat64 == 1;
}

/**
 * Test if this is a nat46 session
 *
 * @param s
 * The session
 */
static inline bool session_is_nat46(struct session *s)
{
	return s->se_nat46 == 1;
}

/**
 * Establish a session from a packet.
 *
 * This will atomically create a new session, or return an existing
 * session.  If it creates a new session, forward and reverse sentries are
 * added to the sentry table.
 *
 * This routine handles a possible race condition where packets for the
 * dame flow are handled on separate forwarding threads.
 *
 * 0 (zero) returned for success.
 *
 * @param m
 * The packet.
 *
 * @param ifp
 * The current interface.  Used to obtain the interface name.
 *
 * @param timeout
 * The initial timeout.  Note that if NPF references this session, NPF
 * will adjust the timeout according to protocol.
 *
 * @param se
 * The session handle.
 *
 * @param created
 * If true, then this invocation created the session.  If false,
 * then the session was already established.
 *
 */
int session_establish(struct rte_mbuf *m, const struct ifnet *ifp,
		uint32_t timeout, struct session **s, bool *created);

/**
 * Lookup a session based on a packet.
 *
 * @param m
 * The packet to match.
 * @param if_index
 * The index associated with the interface that is being looked up.
 * @param s
 * The session.
 * @param forw
 * Direction of lookup match
 *
 * 0 (zero) returned on success.
 */
int session_lookup(struct rte_mbuf *m, uint32_t if_index, struct session **s,
		bool *forw);

/**
 * Expire a session.
 *
 * Expire a session and call all feature 'expire' operations.  Note
 * that the session may be inflight at the time of expiration.  Future
 * lookups for the session will fail with -ENOENT.
 *
 * Also unlinks and expires all children of this session.
 *
 * @param s
 * The session to expire.
 *
 * @param m (optional)
 * If non-NULL, removes the session from the packet's meta data cache.
 *
 * 0 (zero) returned on success.
 */
void session_expire(struct session *s, struct rte_mbuf *m);

/**
 * Add sentries to a session based on a packet.
 *
 * Add additional sentries to a session, both a FORW and BACK sentry
 * are added.  Features that decap and/or transform the src/dst sides of
 * a packet should call this to ensure that other features can locate
 * this session.
 *
 * @param s
 * The session.
 *
 * @param if_index
 * The index of the interface that the packet is being processed on.
 *
 * @param m
 * The packet to parse.
 */
int session_sentry_insert_pkt(struct session *s, uint32_t if_index,
			      struct rte_mbuf *m);

/**
 * Sentry insert
 *
 * Create and insert an additional sentry for this session.
 *
 * @param s
 * The session.
 *
 * @param if_index
 * The index of the interface to be associated with the sentry.
 *
 * @param flags
 * Flags for this sentry, must contain the IPv4/6 flag, and
 * one of the FORW/BACK sentry flags.
 *
 * @param sid
 * The source id for matching.
 *
 * @param saddr
 * The source address (IPv4 or 6)
 *
 * @param did
 * The destination id.
 *
 * @param daddr
 * The destination address.
 */
int session_sentry_insert(struct session *m, uint32_t if_index, uint16_t flags,
		uint16_t sid, const void *saddr,
		uint16_t did, const void *daddr);

/**
 * Max sessions
 *
 * Called by CLI only.  Sets the max session limit.
 *
 * @param max
 * Max number of sessions.
 */
void session_set_max_sessions(uint32_t max);

/**
 * Set global logging configuration
 *
 * Called by CLI only.  Sets the global session logging configuration.
 *
 * @param scfg
 * Structure holding session logging configuration information.
 */
void session_set_global_logging_cfg(struct session_log_cfg *scfg);

/**
 * Hash table counts.
 *
 * Used by CLI for determining session counts
 *
 * @param  used
 * Number of existing sessions.
 *
 * @param
 * Max number of sessions allowed.
 *
 * @param
 * counts struct, must be zero'ed prior.
 */
void session_counts(uint32_t *used, uint32_t *max, struct session_counts *sc);

/**
 * hash table counts.
 *
 * Used by UTs only.  Various counts of internal hash tables.
 *
 * @param sen_cnt
 * Number of sentries in the sentry hash table.
 *
 * @param se_cnt
 * Number of entries in the session hash table.
 */
void session_table_counts(unsigned long *sen_cnt, unsigned long *sess_cnt);

/**
 * Base parent
 *
 * Returns the grandparent of a nested stack of linked sessions.  Used
 * by ALGs.
 *
 * @param s
 * The current session.
 */
struct session *session_base_parent(struct session *s);

/**
 * Protocol/State and timeout
 *
 * The timeout is referenced once GC determines the session is idle. A session
 * becomes idle when no additional packets are seen by the session.  At
 * this point the session will remain for 'timeout' seconds, then the GC will
 * change the session state to expired, and perform session cleanup.
 *
 * The 'state' field is intended for use by NPF assuming it is configured
 * to handle protocol state checking, this field within the session is
 * only referenced for display purposes.
 *
 * Specify 0 (zero) for the state field if you merely want to reset a timeout.
 *
 * @param s
 * The session.
 *
 * @param state
 * The current protocol state.
 *
 * @param timeout
 * The protocol state timeout.
 */
void session_set_protocol_state_timeout(struct session *s, uint8_t state,
		uint32_t timeout);

/**
 * Init
 *
 * Initialize the session subsystem
 */
void session_init(void);

/**
 * Init sentry packet.
 *
 * Initialize a sentry_packet struct for the purposes of creating a
 * session.  Can be used to
 *
 * @param sp
 * The sentry packet struct, all fields will be defined.
 *
 * @param if_index
 * The index associated with the interface that the sentry should be
 * associated with.
 *
 * @param flags
 * Flags indicating whether IPv4 or 6, and whether a FORW or BACK
 * sentry.
 *
 * @param proto
 * The IP protocol.
 *
 * @param vrfid
 * The VRF id.
 *
 * @param sid
 * Source Id.
 *
 * @param saddr
 * Source IP address.
 *
 * @param did
 * Destination Id.
 *
 * @param daddr
 * Destination IP address.
 */
int session_init_sentry_packet(struct sentry_packet *sp, uint32_t if_index,
		uint16_t flags, uint8_t proto, vrfid_t vrfid,
		uint16_t sid, const void *saddr,
		uint16_t did, const void *daddr);

/**
 *
 * Create a sentry packet based on a packet.
 *
 * Create a sentry packet, which can be used to create a sentry which will
 * lookup the addresses of the packet in the forward direction.
 *
 * @param m
 * Current packet.
 *
 * @param if_index
 * The index of the interface associated with the packet.
 *
 * @param sp
 * Place to store the packet sentry.
 *
 * @return 0 on success, -errno on failure.
 */
int sentry_packet_from_mbuf(struct rte_mbuf *m, uint32_t if_index,
			    struct sentry_packet *sp);

/**
 * Reverse a sentry packet
 *
 * This creates the reverse of a sentry packet, which is useful to pass
 * into session_create_from_sentry_packets() for sessions that are
 * not NATed (i.e. matching for the backward direction is just a swap
 * of addresses compared to the forward direction).
 *
 * @param sp
 * A pointer to the sentry_packet to be reversed.
 *
 * @param rsp
 * A pointer to the sentry_packet to be filled in with the reversed.
 * sentry_packet.
 */
void sentry_packet_reverse(struct sentry_packet *sp, struct sentry_packet *rsp);

/**
 * Autonomous Session creation
 *
 * Create a session from a sentry packet.
 * This allows features to create sessions without a packet.
 *
 * References the packet cache
 *
 * References the packet cache
 *
 * @param m
 * Current packet.
 *
 * @param sp_forw
 * The forward sentry packet
 *
 * @param sp_back
 * The backward sentry packet
 *
 * @param ifp
 * Current interface, the interface name is referenced and the interface
 * is associated with the sentry.
 *
 * @param timeout
 * Initial session timeout.
 *
 * @param se
 * The newly created session.
 *
 * @param created
 * If true, then this invocation created the session.  If false,
 * then the session was already established.
 */
int session_create_from_sentry_packets(struct rte_mbuf *m,
		struct sentry_packet *sp_forw,
		struct sentry_packet *sp_back,
		const struct ifnet *ifp, uint32_t timeout,
		struct session **se, bool *created);

/**
 * Session lookup by sentry packet.
 *
 * Lookup a session based on a provided sentry packet.  Used
 * for obtaining sessions from embedded packets (eg: icmp errors)
 *
 * @param  sp
 * A sentry packet.
 *
 * @params se
 * The matching session.
 *
 * @params forw
 * Direction of lookup match
 */
int session_lookup_by_sentry_packet(const struct sentry_packet *sp,
		struct session **se, bool *forw);

/**
 * Session link
 *
 * Link a child session to a parent.  Used by ALGs.
 *
 * Parent sessions can contain a number of child sessions, but a
 * child session can only have one parent.
 *
 * @param parent
 * Parent session
 *
 * @param child
 * The child.
 */
int session_link(struct session *parent, struct session *child);

/**
 * Unlink a session from its parent.
 *
 * @param s
 * The session to unlink.
 */
void session_unlink(struct session *s);

/**
 * Unlink all sessions from its parent.
 *
 * @param s
 * The session to unlink.
 */
void session_unlink_all(struct session *s);

/**
 * Session/Sentry table walk
 *
 * Walk the sentry or session tables and pass the element to
 * the given walk function.
 *
 * @param sen/s
 * The sentry or session
 *
 * @param data
 * pointer to supplied data or NULL.
 */
typedef int (*sentry_walk_t)(struct sentry *sen, void *data);
typedef int (*session_walk_t)(struct session *s, void *data);

int sentry_table_walk(sentry_walk_t func, void *data);
int session_table_walk(session_walk_t func, void *data);


/**
 * Walk linked sessions.
 *
 * This routine walks a linked list of child sessions from the
 * given parent session and execute 'func' on each session.
 *
 * Optionally, will safely unlink the sessions as it traverses them.
 *
 * The routine traverses to the bottom of the (possibly) nested
 * list of sessions recursively, then executes the callback function
 * for each found session on the way back up the stack, *including*
 * the specified session.
 *
 * @param s
 * The starting session.
 *
 * @param do_unlink
 * If TRUE, unlink the sessions.
 *
 * @param func
 * The callback to execute.
 *
 * @param data
 * pointer to supplied data or NULL.
 */
typedef void (session_link_walk_t)(struct session *s, void *data);

void session_link_walk(struct session *s, bool do_unlink,
		session_link_walk_t *func, void *data);

/**
 * Destroy all sentries/sessions.
 *
 * Used by UTs to force a cleanup between tests.
 */
int session_table_destroy_all(void);

/**
 * Extract elements of a sentry.
 *
 * @param sen
 * The sentry
 *
 * @param if_index
 * return of interface index the sentry is associated with
 *
 * @param af
 * return of AF_INET or AF_INET6 based on sentry addresses.
 *
 * @param saddr
 * return pointer to source address
 *
 * @param sid
 * return of the source id
 *
 * @param daddr
 * return pointer to destination address.
 *
 * @param did
 * return of the destination id.
 */
void session_sentry_extract(struct sentry *sen, uint32_t *if_index, int *af,
		const void **saddr, uint16_t *sid, const void **daddr,
		uint16_t *did);

/**
 * Execute the session GC path.
 *
 * This routine artbitrarily executes the GC path for the sentry
 * hash table.  It is only used by the Unit tests to simulate the
 * GC running over time.
 *
 */
void session_gc(void);

/**
 * Session alloc
 *
 * Allocate a session struct, for use by session syncing.
 */
struct session *session_alloc(void);

static inline uint64_t session_get_id(struct session *s)
{
	if (s)
		return s->se_id;
	return 0;
}

#endif /* _SESSION_H_ */
