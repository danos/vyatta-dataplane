/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _CGN_SESS_STATE_H_
#define _CGN_SESS_STATE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "json_writer.h"

#include "npf/nat/nat_proto.h"
#include "npf/cgnat/cgn.h"
#include "npf/cgnat/cgn_mbuf.h"


/* Canned record of TCP session states */
enum cgn_state_history {
	CGN_SESS_HIST_ESTD = 0x01,	/* Reached Established state */
	CGN_SESS_HIST_FFIN = 0x02,	/* Forw FIN flag seen */
	CGN_SESS_HIST_BFIN = 0x04,	/* Back FIN flag seen */
	CGN_SESS_HIST_FRST = 0x08,	/* Forw RST flag seen */
	CGN_SESS_HIST_BRST = 0x10,	/* Back RST flag seen */
	CGN_SESS_HIST_FACK = 0x20,	/* Forw ACK flag seen */
	CGN_SESS_HIST_BACK = 0x40,	/* Back ACK flag seen */
	CGN_SESS_HIST_DIR  = 0x80,	/* forw == in */
};

/*
 * CGN session state tracking.  Applies to nested 2-tuple sessions.
 */
struct cgn_state {
	uint8_t		st_state;
	enum nat_proto	st_proto;
	uint8_t		st_hist;
	uint8_t		st_pad1[1];
	uint16_t	st_dst_port; /* Outbound dest port */
	rte_atomic16_t	st_idle;     /* keeps an estbd session alive */

	/*
	 * st_ext_rtt - round-trip time from cgnat device to destination.
	 *              (Time from client SYN to server SYN/ACK)
	 * st_int_rtt - round-trip time from cgnat device to subscriber.
	 *              (Time from server SYN/ACK to subscriber ACK)
	 *
	 * microseconds.
	 */
	uint64_t	st_ext_rtt;
	uint64_t	st_int_rtt;

	rte_spinlock_t	st_lock;
};

/*
 * CGN session state for non-TCP 5-tuple sessions
 */
enum cgn_sess_state {
	CGN_SESS_STATE_NONE = 0,
	CGN_SESS_STATE_CLOSED,
	CGN_SESS_STATE_INIT,
	CGN_SESS_STATE_ESTABLISHED,
};

#define CGN_SESS_STATE_FIRST	CGN_SESS_STATE_CLOSED
#define CGN_SESS_STATE_LAST	CGN_SESS_STATE_ESTABLISHED
#define CGN_SESS_STATE_COUNT	(CGN_SESS_STATE_LAST + 1)

enum cgn_sess_event {
	CGN_SESS_EVENT_NONE = 0,
	CGN_SESS_EVENT_PKT,
	CGN_SESS_EVENT_TO,
};

#define CGN_SESS_EVENT_FIRST	CGN_SESS_EVENT_PKT
#define CGN_SESS_EVENT_LAST	CGN_SESS_EVENT_TO
#define CGN_SESS_EVENT_COUNT	(CGN_SESS_EVENT_LAST + 1)

/*
 * CGN session state for TCP 5-tuple sessions
 *
 * The first 4 states MUST match the corresponding cgn_sess_state states
 */
enum cgn_tcp_state {
	CGN_TCP_STATE_NONE = 0,
	CGN_TCP_STATE_CLOSED,
	CGN_TCP_STATE_INIT,
	CGN_TCP_STATE_ESTABLISHED,
	CGN_TCP_STATE_TRANS,
	CGN_TCP_STATE_C_FIN_RCV,
	CGN_TCP_STATE_S_FIN_RCV,
	CGN_TCP_STATE_CS_FIN_RCV,
};

#define CGN_TCP_STATE_FIRST	CGN_TCP_STATE_CLOSED
#define CGN_TCP_STATE_LAST	CGN_TCP_STATE_CS_FIN_RCV
#define CGN_TCP_STATE_COUNT	(CGN_TCP_STATE_LAST + 1)

enum cgn_tcp_event {
	CGN_TCP_EVENT_NONE = 0,
	CGN_TCP_EVENT_SYN,
	CGN_TCP_EVENT_RST,
	CGN_TCP_EVENT_ACK,
	CGN_TCP_EVENT_FIN,
	CGN_TCP_EVENT_TO,
};

#define CGN_TCP_EVENT_FIRST	CGN_TCP_EVENT_SYN
#define CGN_TCP_EVENT_LAST	CGN_TCP_EVENT_TO
#define CGN_TCP_EVENT_COUNT	(CGN_TCP_EVENT_LAST + 1)

/*
 * Non-TCP session expiry time enums
 */
enum cgn_state_etime_other {
	CGN_ETIME_OPENING,
	CGN_ETIME_ESTBD,
};

#define CGN_ETIME_FIRST		CGN_ETIME_OPENING
#define CGN_ETIME_LAST		CGN_ETIME_ESTBD
#define CGN_ETIME_COUNT		(CGN_ETIME_LAST + 1)

/*
 * UDP:
 * Opening: 10s, 30s, 4m
 * Established: 30s, 300s, 1800s
 */
#define CGN_DEF_ETIME_UDP_OPENING	(30 * ONE_SECOND)
#define CGN_DEF_ETIME_UDP_ESTBD		(300 * ONE_SECOND)

extern uint32_t cgn_sess_udp_etime[];

/*
 * Other:
 * Opening: 10s, 30s, 4m
 * Established: 30s, 240s, 1800s
 */
#define CGN_DEF_ETIME_OTHER_OPENING	(30 * ONE_SECOND)
#define CGN_DEF_ETIME_OTHER_ESTBD	(240 * ONE_SECOND)

extern uint32_t cgn_sess_other_etime[];

/*
 * TCP session expiry time enums
 */
enum cgn_state_etime_tcp {
	CGN_ETIME_TCP_OPENING,
	CGN_ETIME_TCP_ESTBD,
	CGN_ETIME_TCP_CLOSING,
};

#define CGN_ETIME_TCP_FIRST	CGN_ETIME_TCP_OPENING
#define CGN_ETIME_TCP_LAST	CGN_ETIME_TCP_CLOSING
#define CGN_ETIME_TCP_COUNT	(CGN_ETIME_TCP_LAST + 1)

/*
 * Opening: 10s, 4m, 4m
 * Established: 30s, 2h 4m, 4h
 * Clsing: 10s, 4m, 4m
 */
#define CGN_DEF_ETIME_TCP_OPENING	(4 * ONE_MINUTE)
#define CGN_DEF_ETIME_TCP_ESTBD		((4 * ONE_MINUTE) + (2 * ONE_HOUR))
#define CGN_DEF_ETIME_TCP_CLOSING	(4 * ONE_MINUTE)

extern uint32_t cgn_sess_tcp_etime[];

/*
 * Get or set TCP or UDP per-port Established expiry times
 */
void cgn_cgn_port_tcp_etime_set(uint16_t port, uint32_t timeout);
void cgn_cgn_port_udp_etime_set(uint16_t port, uint32_t timeout);

static inline const char *cgn_tcp_state_str(enum cgn_tcp_state state)
{
	switch (state) {
	case CGN_TCP_STATE_NONE:
		return "none";
	case CGN_TCP_STATE_CLOSED:
		return "closed";
	case CGN_TCP_STATE_INIT:
		return "opening";
	case CGN_TCP_STATE_ESTABLISHED:
		return "established";
	case CGN_TCP_STATE_TRANS:
		return "transitory";
	case CGN_TCP_STATE_C_FIN_RCV:
		return "closing";
	case CGN_TCP_STATE_S_FIN_RCV:
		return "closing";
	case CGN_TCP_STATE_CS_FIN_RCV:
		return "closing";
	};
	return "???";
}

static inline const char *
cgn_tcp_state_str_short(enum cgn_tcp_state state)
{
	switch (state) {
	case CGN_TCP_STATE_NONE:
		return "NO";
	case CGN_TCP_STATE_CLOSED:
		return "CL";
	case CGN_TCP_STATE_INIT:
		return "OP";
	case CGN_TCP_STATE_ESTABLISHED:
		return "ES";
	case CGN_TCP_STATE_TRANS:
		return "TR";
	case CGN_TCP_STATE_C_FIN_RCV:
		return "CG";
	case CGN_TCP_STATE_S_FIN_RCV:
		return "CG";
	case CGN_TCP_STATE_CS_FIN_RCV:
		return "CG";
	};
	return "??";
}

static inline const char *cgn_tcp_event_str(enum cgn_tcp_event event)
{
	switch (event) {
	case CGN_TCP_EVENT_NONE:
		return "NONE";
	case CGN_TCP_EVENT_SYN:
		return "SYN";
	case CGN_TCP_EVENT_RST:
		return "RST";
	case CGN_TCP_EVENT_ACK:
		return "ACK";
	case CGN_TCP_EVENT_FIN:
		return "FIN";
	case CGN_TCP_EVENT_TO:
		return "TIMEOUT";
	};
	return "???";
}

static inline const char *cgn_sess_event_str(enum cgn_sess_event event)
{
	switch (event) {
	case CGN_SESS_EVENT_NONE:
		return "NONE";
	case CGN_SESS_EVENT_PKT:
		return "PKT";
	case CGN_SESS_EVENT_TO:
		return "TIMEOUT";
	};
	return "???";
}

static inline const char *cgn_dir_str(enum cgn_dir dir)
{
	switch (dir) {
	case CGN_DIR_OUT:
		return "OUT";
	case CGN_DIR_IN:
		return "IN";
	};
	return "???";
}

/* Initialize session state */
void cgn_sess_state_init(struct cgn_state *st, enum nat_proto proto,
			 uint16_t port);

/*
 * Evaluate session state for packet
 *
 * st           Pointer to state variable in 3-tuple or 5-tuple session
 * cpk		Packet decomposition
 * dir		Forwards or backwards
 * start_time	Session start time, unix epoch microseconds
 */
void cgn_sess_state_inspect(struct cgn_state *st, struct cgn_packet *cpk,
			    enum cgn_dir dir, uint64_t start_time);

/*
 * Get state-dependent expiry time
 */
uint32_t cgn_sess_state_expiry_time(enum nat_proto proto, uint16_t port,
				    uint8_t state);

/*
 * Timeout event.  Returns true if session is closed.
 */
bool cgn_sess_state_timeout(struct cgn_state *st);

/*
 * Force a session to closed state
 */
void cgn_sess_state_close(struct cgn_state *st);

const char *cgn_sess_state_str(struct cgn_state *st);
const char *cgn_sess_state_str_short(struct cgn_state *st);

void cgn_sess_state_jsonw(json_writer_t *json, struct cgn_state *st);

#endif /* _CGN_SESS_STATE_H_ */
