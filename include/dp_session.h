/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef VYATTA_DATAPLANE_DP_SESSION_H
#define VYATTA_DATAPLANE_DP_SESSION_H

/**
 * This file provides declarations for accessing firewall sessions.
 *
 * The dataplane firewall creates and maintains states for flows matching
 * stateful firewall NAT rules in the session structure (struct session).
 * A session changes as the packets matching the session is processed by
 * the dataplane firewall.
 *
 * These functions provides a way to register a callback function to be
 * called when a passing packet affect a session's state. It also provides
 * a set of utility function that allows retrieval of sessions data.
 */

#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

/**
 * Session types
 * Bit masks for sessions.
 */
enum dp_session_type {
	SESSION_TYPE_NONE = 0,
	SESSION_TYPE_FW = 1,		/**< A stateful firewall session */
	SESSION_TYPE_NAT = (1 << 1),	/**< The session is natted */
	SESSION_TYPE_NAT64 = (1 << 2),	/**< IPv6 to IPv4 nat session */
	SESSION_TYPE_NAT46 = (1 << 3),	/**< IPv4 to IPv6 nat */
	SESSION_TYPE_ALG = (1 << 4),	/**< Session is for an ALG */
};

#define dp_is_session_type(flag, t) ((flag) & SESSION_TYPE_ ## t)

/**
 * Session event Hooks.
 *
 * A session_watch callback function is called on occurrence of one of
 * the following session events.
 */
enum dp_session_hook {
	SESSION_ACTIVATE,	/**< A session is being activated */
	SESSION_STATE_CHANGE,	/**< Session state has changed */
	SESSION_STATS_UPDATE,	/**< Session stats are updated */
	SESSION_EXPIRE,		/**< Session has expired - may be deleted */
	SESSION_MAX,
};

/**
 * Sessions protocol states.
 */
enum dp_session_state {
	SESSION_STATE_NONE = 0,
	SESSION_STATE_NEW,
	SESSION_STATE_ESTABLISHED,
	SESSION_STATE_TERMINATING,
	SESSION_STATE_CLOSED,
} __attribute__ ((__packed__));

/**
 * Session attribute.
 */
enum dp_session_attr {
	SESSION_ATTR_BYTES_IN		= 1,
	SESSION_ATTR_PKTS_IN		= (1 << 1),
	SESSION_ATTR_PROTOCOL		= (1 << 2),
	SESSION_ATTR_TCP_FLAGS		= (1 << 3),
	SESSION_ATTR_L4_SRC_PORT	= (1 << 4),
	SESSION_ATTR_IPV4_SRC_ADDR	= (1 << 5),
	SESSION_ATTR_L4_DST_PORT	= (1 << 6),
	SESSION_ATTR_IPV4_DST_ADDR	= (1 << 7),
	SESSION_ATTR_CREATE_TIME	= (1 << 8),
	SESSION_ATTR_BYTES_OUT		= (1 << 9),
	SESSION_ATTR_PKTS_OUT		= (1 << 10),
	SESSION_ATTR_IF_NAME		= (1 << 11),
	SESSION_ATTR_DPI		= (1 << 12),
};

#define SESSION_ATTR_ALL	0xffffffff
#define SESSION_ATTR_SENTRY	(SESSION_ATTR_L4_SRC_PORT \
				| SESSION_ATTR_IPV4_SRC_ADDR \
				| SESSION_ATTR_L4_DST_PORT \
				| SESSION_ATTR_IPV4_DST_ADDR \
				| SESSION_ATTR_IF_NAME)

struct dp_session_info {
	enum dp_session_attr query;
	uint64_t	se_id;
	uint16_t	se_flags;
	uint8_t		se_protocol;
	uint8_t		se_protocol_state;
	uint64_t	se_pkts_in;
	uint64_t	se_bytes_in;
	uint64_t	se_create_time;	/* time session was created */
	uint64_t	se_pkts_out;
	uint64_t	se_bytes_out;

	// address
	int             se_af;
	uint16_t        se_src_port;
	uint32_t        se_src_addr;
	uint16_t        se_dst_port;
	uint32_t        se_dst_addr;
	const char      *se_ifname;
	const char      *se_app_name;
	const char      *se_app_proto;
	const char      *se_app_type;

	// firewall
	const char      *se_fwd_status;

	// misc
	time_t          timestamp;
	uint64_t	duration; /* seconds */
};

#define SESSION_STATE_FIRST	SESSION_STATE_NONE
#define SESSION_STATE_LAST	SESSION_STATE_CLOSED
#define SESSION_STATE_SIZE	(SESSION_STATE_LAST + 1)

static inline bool
dp_session_state_is_valid(enum dp_session_state state)
{
	static_assert(SESSION_STATE_FIRST == 0,
		      "SESSION_STATE_FIRST != 0");
	return state <= SESSION_STATE_LAST;
}

static inline const char *
dp_session_state_name(enum dp_session_state state, bool upper)
{
	switch (state) {
	case SESSION_STATE_NEW:
		return upper ? "OPENING" : "opening";
	case SESSION_STATE_ESTABLISHED:
		return upper ? "ESTABLISHED" : "established";
	case SESSION_STATE_TERMINATING:
		return upper ? "CLOSING" : "closing";
	case SESSION_STATE_CLOSED:
		return upper ? "CLOSED" : "closed";
	case SESSION_STATE_NONE:
		break;
	};
	return upper ? "NONE" : "none";
}

static inline enum dp_session_state dp_session_name2state(const char *name)
{
	if (!strcmp(name, "new") || !strcmp(name, "opening"))
		return SESSION_STATE_NEW;
	else if (!strcmp(name, "established"))
		return SESSION_STATE_ESTABLISHED;
	else if (!strcmp(name, "terminating") || !strcmp(name, "closing"))
		return SESSION_STATE_TERMINATING;
	else if (!strcmp(name, "closed"))
		return SESSION_STATE_CLOSED;
	else
		return SESSION_STATE_NONE;
}

/**
 * Session packing type.
 *
 * Used in dp_session_pack to indicate type of packing needed.
 */
enum session_pack_type {
	SESSION_PACK_NONE = 0,  /**< packing type not set */
	SESSION_PACK_FULL,	/**< pack full session for later restoration */
	SESSION_PACK_UPDATE,	/**< pack only session states and stats */
} __attribute__ ((__packed__));

/** Forward declaration for session handle */
struct session;

/**
 * Typedef for session watch callback function.
 *
 * Session watch function called by the dataplane session
 * management code as packets causes changes to the session.
 * This function call is dp_rcu_read_lock() protected.
 *
 * @param[in] session - pointer to the affected session.
 * The existence of the session pointer is guaranteed only
 * @param [in] hook - reason for which the call back is called.
 * @param [in] data - pointer to the context passed at the time of
 * registration.
 *
 * session watch callback should never block as this function is
 * called from dataplane forwarding path and can affect forwarding
 * performance.
 */
typedef void (session_watch_fn_t) (struct session *session,
				   enum dp_session_hook hook, void *data);

/**
 * typedef for session walk callback.
 */
typedef int (dp_session_walk_t)(struct session *session, void *data);

/**
 * A structure used for registering a session watcher callback.
 */
struct session_watch {
	session_watch_fn_t *fn;	/**< callback function */
	unsigned int types;	/**< bitwise or of SESSION_TYPE_* to watch */
	void *data;		/**< callback data */
	const char *name;	/**< Session watcher name used for logging */
};

/**
 * Register a session watcher. Only one session watcher may be
 * registered at a time.
 *
 * @param [in] se_watch - a filled up struct session_watch.
 *
 * @return - non-negative watcher id on success,
 *     -EBUSY if another watcher is already registered.
 *     -errno other errors.
 */
int dp_session_watch_register(struct session_watch *se_watch);

/**
 * unregister a previously registered watcher.
 *
 * @param [in] watcher_id - session watcher to unregister.
 *
 * @return - 0 on success
 *   - ENOENT - No such watch registered.
 */
int dp_session_watch_unregister(int watcher_id);

/**
 * get an id for use with set/get private data.
 *
 * @return - non-negative integer id on success.
 *	- EBUSY if other user data is already registered.
 */
int dp_session_user_data_register(void);

/**
 * indicate that private data is no longer used.
 *
 * @return - non-negative integer id on success.
 *	- ENOENT for for invalid id
 */
int dp_session_user_data_unregister(int id);

/**
 * attach private data to a session.
 *
 * if data pointer is non NULL it is set by atomic compare and exchange
 * with NULL.
 * If the data pointer is NULL, the old data pointer is cleared.
 *
 * @param [in] session - the affected session
 * @param [in] data - pointer to private data.
 *
 * @return - 1 if the data can be set correctly.
 *   - 0 if the data can't be set
 */
bool dp_session_set_private(int id, struct session *session, void *data);

/**
 * get a session's attached private data
 *
 * @param [in] session - session with the private data attached
 *
 * @return - the pointer to attached private data.
 */
void *dp_session_get_private(int id, const struct session *session);

/**
 * Run a function over all sessions.
 * Session walk gets terminated if the callback returns nonzero.
 *
 * @param fn - callback function.
 * @param data - pointer to data or NULL
 * @param types - bit mask of dp_session_types to walk
 *
 * @return - return of callback function.
 */
int dp_session_table_walk(dp_session_walk_t *fn, void *data,
			  unsigned int types);

/**
 * Query a session's info.
 */
int dp_session_query(struct session *s, enum dp_session_attr query,
		     struct dp_session_info *info);

/**
 * Get a session's unique id.
 *
 * @param [in] session
 */
uint64_t dp_session_unique_id(const struct session *session);

/**
 * Get a sessions generic protocol state
 *
 * @param [in] session
 */
enum dp_session_state dp_session_get_state(const struct session *session);

/**
 * Get a sessions generic protocol state name
 *
 * @param [in] session
 * @param [in] upper
 */
const char *dp_session_get_state_name(const struct session *session,
				      bool upper);

/**
 * is session in an expired state?
 *
 * @param [in] session
 */
bool dp_session_is_expired(const struct session *session);

/**
 * is session in establised state?
 *
 * @param [in] session
 */
bool dp_session_is_established(const struct session *session);

/**
 * Get maximum buffer size required to pack a session.
 *
 * @return - maximum session buffer size required to pack a session.
 */
uint32_t dp_session_buf_size_max(void);

/**
 * Serialize a session into the buffer.
 *
 * This packed sessions are used to restore the session on a different router.
 * Two different packing functions are provided, the first packs complete
 * session information that can be used to fully recreate a session later using
 * dp_session_restore(). dp_session_pack() may also be used
 * to pack only stats and states of sessions and later the packed data may be
 * used to update an already restored session.
 *
 * @param [in] session - session to be packed
 * @param [in, out] buf - session buffer pointer.
 * @param [in] size - size of buffer,
 * @param [in] spt - SESSION_PACK_FULL, SESSION_PACK_UPDATE
 *
 * @return - packed length on success
 *   -errno on error.
 */
int dp_session_pack(struct session *session, void *buf, uint32_t size,
		 enum session_pack_type spt, struct session **session_peer);

/*
 * restore a session from the packed data or update its state.
 * If the buf contains a SESSION_PACK_FULL payload any old session
 * with same session key will be deleted.
 *
 * @param [in] buf - buffer to be restored
 * @param [in] size_t size - length of buffer
 * @param [out] spt - pack type.
 */
int dp_session_restore(void *buf, uint32_t size, enum session_pack_type *spt);

#endif
