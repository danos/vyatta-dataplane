/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @file cgn_sess_state.c - cgnat session state
 *
 */

#include <errno.h>
#include <values.h>

#include "util.h"
#include "soft_ticks.h"

#include "npf/cgnat/cgn_limits.h"
#include "npf/cgnat/cgn_mbuf.h"
#include "npf/cgnat/cgn_sess2.h"
#include "npf/cgnat/cgn_sess_state.h"

/*
 * NAT TCP State Machine for 5-tuple TCP sessions (rfc7857)
 */
static uint8_t
cgn_tcp_fsm[CGN_TCP_STATE_COUNT][CGN_DIR_SZ][CGN_TCP_EVENT_COUNT] = {
	[CGN_TCP_STATE_NONE] = {
		[CGN_DIR_FORW] = { 0 },
		[CGN_DIR_BACK] = { 0 },
	},
	[CGN_TCP_STATE_CLOSED] = {
		[CGN_DIR_FORW] = {
			[CGN_TCP_EVENT_NONE]     = 0,
			[CGN_TCP_EVENT_SYN]      = CGN_TCP_STATE_INIT,
			[CGN_TCP_EVENT_RST]      = 0,
			[CGN_TCP_EVENT_ACK]      = 0,
			[CGN_TCP_EVENT_FIN]      = 0,
			[CGN_TCP_EVENT_TO]       = 0,
		},
		[CGN_DIR_BACK] = {
			[CGN_TCP_EVENT_NONE]     = 0,
			[CGN_TCP_EVENT_SYN]      = 0,
			[CGN_TCP_EVENT_RST]      = 0,
			[CGN_TCP_EVENT_ACK]      = 0,
			[CGN_TCP_EVENT_FIN]      = 0,
			[CGN_TCP_EVENT_TO]       = 0,
		},
	},
	[CGN_TCP_STATE_INIT] = {
		[CGN_DIR_FORW] = {
			[CGN_TCP_EVENT_NONE]     = 0,
			[CGN_TCP_EVENT_SYN]      = 0,
			[CGN_TCP_EVENT_RST]      = 0,
			[CGN_TCP_EVENT_ACK]      = 0,
			[CGN_TCP_EVENT_FIN]      = 0,
			[CGN_TCP_EVENT_TO]       = CGN_TCP_STATE_CLOSED,
		},
		[CGN_DIR_BACK] = {
			[CGN_TCP_EVENT_NONE]     = 0,
			[CGN_TCP_EVENT_SYN]      = CGN_TCP_STATE_ESTABLISHED,
			[CGN_TCP_EVENT_RST]      = 0,
			[CGN_TCP_EVENT_ACK]      = 0,
			[CGN_TCP_EVENT_FIN]      = 0,
			[CGN_TCP_EVENT_TO]       = CGN_TCP_STATE_CLOSED,
		},
	},
	[CGN_TCP_STATE_ESTABLISHED] = {
		[CGN_DIR_FORW] = {
			[CGN_TCP_EVENT_NONE]     = 0,
			[CGN_TCP_EVENT_SYN]      = 0,
			[CGN_TCP_EVENT_RST]      = CGN_TCP_STATE_TRANS,
			[CGN_TCP_EVENT_ACK]      = 0,
			[CGN_TCP_EVENT_FIN]      = CGN_TCP_STATE_C_FIN_RCV,
			[CGN_TCP_EVENT_TO]       = CGN_TCP_STATE_TRANS,
		},
		[CGN_DIR_BACK] = {
			[CGN_TCP_EVENT_NONE]     = 0,
			[CGN_TCP_EVENT_SYN]      = 0,
			[CGN_TCP_EVENT_RST]      = CGN_TCP_STATE_TRANS,
			[CGN_TCP_EVENT_ACK]      = 0,
			[CGN_TCP_EVENT_FIN]      = CGN_TCP_STATE_S_FIN_RCV,
			[CGN_TCP_EVENT_TO]       = CGN_TCP_STATE_TRANS,
		},
	},
	[CGN_TCP_STATE_TRANS] = {
		[CGN_DIR_FORW] = {
			[CGN_TCP_EVENT_NONE]     = 0,
			[CGN_TCP_EVENT_SYN]      = 0,
			[CGN_TCP_EVENT_RST]      = 0,
			[CGN_TCP_EVENT_ACK]      = CGN_TCP_STATE_ESTABLISHED,
			[CGN_TCP_EVENT_FIN]      = 0,
			[CGN_TCP_EVENT_TO]       = CGN_TCP_STATE_CLOSED,
		},
		[CGN_DIR_BACK] = {
			[CGN_TCP_EVENT_NONE]     = 0,
			[CGN_TCP_EVENT_SYN]      = 0,
			[CGN_TCP_EVENT_RST]      = 0,
			[CGN_TCP_EVENT_ACK]      = CGN_TCP_STATE_ESTABLISHED,
			[CGN_TCP_EVENT_FIN]      = 0,
			[CGN_TCP_EVENT_TO]       = CGN_TCP_STATE_CLOSED,
		},
	},
	[CGN_TCP_STATE_C_FIN_RCV] = {
		[CGN_DIR_FORW] = {
			[CGN_TCP_EVENT_NONE]     = 0,
			[CGN_TCP_EVENT_SYN]      = 0,
			[CGN_TCP_EVENT_RST]      = 0,
			[CGN_TCP_EVENT_ACK]      = 0,
			[CGN_TCP_EVENT_FIN]      = 0,
			[CGN_TCP_EVENT_TO]       = CGN_TCP_STATE_CLOSED,
		},
		[CGN_DIR_BACK] = {
			[CGN_TCP_EVENT_NONE]     = 0,
			[CGN_TCP_EVENT_SYN]      = 0,
			[CGN_TCP_EVENT_RST]      = 0,
			[CGN_TCP_EVENT_ACK]      = 0,
			[CGN_TCP_EVENT_FIN]      = CGN_TCP_STATE_CS_FIN_RCV,
			[CGN_TCP_EVENT_TO]       = CGN_TCP_STATE_CLOSED,
		},
	},
	[CGN_TCP_STATE_S_FIN_RCV] = {
		[CGN_DIR_FORW] = {
			[CGN_TCP_EVENT_NONE]     = 0,
			[CGN_TCP_EVENT_SYN]      = 0,
			[CGN_TCP_EVENT_RST]      = 0,
			[CGN_TCP_EVENT_ACK]      = 0,
			[CGN_TCP_EVENT_FIN]      = CGN_TCP_STATE_CS_FIN_RCV,
			[CGN_TCP_EVENT_TO]       = CGN_TCP_STATE_CLOSED,
		},
		[CGN_DIR_BACK] = {
			[CGN_TCP_EVENT_NONE]     = 0,
			[CGN_TCP_EVENT_SYN]      = 0,
			[CGN_TCP_EVENT_RST]      = 0,
			[CGN_TCP_EVENT_ACK]      = 0,
			[CGN_TCP_EVENT_FIN]      = 0,
			[CGN_TCP_EVENT_TO]       = CGN_TCP_STATE_CLOSED,
		},
	},
	[CGN_TCP_STATE_CS_FIN_RCV] = {
		[CGN_DIR_FORW] = {
			[CGN_TCP_EVENT_NONE]     = 0,
			[CGN_TCP_EVENT_SYN]      = 0,
			[CGN_TCP_EVENT_RST]      = 0,
			[CGN_TCP_EVENT_ACK]      = 0,
			[CGN_TCP_EVENT_FIN]      = 0,
			[CGN_TCP_EVENT_TO]       = CGN_TCP_STATE_CLOSED,
		},
		[CGN_DIR_BACK] = {
			[CGN_TCP_EVENT_NONE]     = 0,
			[CGN_TCP_EVENT_SYN]      = 0,
			[CGN_TCP_EVENT_RST]      = 0,
			[CGN_TCP_EVENT_ACK]      = 0,
			[CGN_TCP_EVENT_FIN]      = 0,
			[CGN_TCP_EVENT_TO]       = CGN_TCP_STATE_CLOSED,
		},
	},
};

/*
 * NAT Session State Machine for non-TCP 5-tuple sessions
 */
static uint8_t
cgn_sess_fsm[CGN_SESS_STATE_COUNT][CGN_DIR_SZ][CGN_SESS_EVENT_COUNT] = {
	[CGN_SESS_STATE_NONE] = {
		[CGN_DIR_FORW] = { 0 },
		[CGN_DIR_BACK] = { 0 },
	},
	[CGN_SESS_STATE_CLOSED] = {
		[CGN_DIR_FORW] = {
			[CGN_SESS_EVENT_NONE]     = 0,
			[CGN_SESS_EVENT_PKT]      = CGN_SESS_STATE_INIT,
			[CGN_SESS_EVENT_TO]       = 0,
		},
		[CGN_DIR_BACK] = { 0 },
	},
	[CGN_SESS_STATE_INIT] = {
		[CGN_DIR_FORW] = {
			[CGN_SESS_EVENT_NONE]     = 0,
			[CGN_SESS_EVENT_PKT]      = 0,
			[CGN_SESS_EVENT_TO]       = CGN_SESS_STATE_CLOSED,
		},
		[CGN_DIR_BACK] = {
			[CGN_SESS_EVENT_NONE]     = 0,
			[CGN_SESS_EVENT_PKT]      = CGN_SESS_STATE_ESTABLISHED,
			[CGN_SESS_EVENT_TO]       = CGN_SESS_STATE_CLOSED,
		},
	},
	[CGN_SESS_STATE_ESTABLISHED] = {
		[CGN_DIR_FORW] = {
			[CGN_SESS_EVENT_NONE]     = 0,
			[CGN_SESS_EVENT_PKT]      = 0,
			[CGN_SESS_EVENT_TO]       = CGN_SESS_STATE_CLOSED,
		},
		[CGN_DIR_BACK] = {
			[CGN_SESS_EVENT_NONE]     = 0,
			[CGN_SESS_EVENT_PKT]      = 0,
			[CGN_SESS_EVENT_TO]       = CGN_SESS_STATE_CLOSED,
		},
	},
};


/*
 * Other session expiry times
 */
uint32_t cgn_sess_other_etime[CGN_ETIME_COUNT] = {
	[CGN_ETIME_OPENING]	= CGN_DEF_ETIME_OTHER_OPENING,
	[CGN_ETIME_ESTBD]	= CGN_DEF_ETIME_OTHER_ESTBD,
};

uint32_t cgn_sess_udp_etime[CGN_ETIME_COUNT] = {
	[CGN_ETIME_OPENING]	= CGN_DEF_ETIME_UDP_OPENING,
	[CGN_ETIME_ESTBD]	= CGN_DEF_ETIME_UDP_ESTBD,
};

/*
 * Non-TCP session expiry times
 */
uint32_t cgn_sess_tcp_etime[CGN_ETIME_TCP_COUNT] = {
	[CGN_ETIME_TCP_OPENING]	= CGN_DEF_ETIME_TCP_OPENING,
	[CGN_ETIME_TCP_ESTBD]	= CGN_DEF_ETIME_TCP_ESTBD,
	[CGN_ETIME_TCP_CLOSING]	= CGN_DEF_ETIME_TCP_CLOSING,
};


void
cgn_sess_state_init(struct cgn_state *st, uint8_t proto)
{
	st->st_state = CGN_SESS_STATE_CLOSED;
	st->st_proto = proto;
	rte_atomic16_clear(&st->st_idle);
	rte_spinlock_init(&st->st_lock);
}

/*
 * Evaluate session state
 */
void
cgn_sess_state_inspect(struct cgn_state *st, struct cgn_packet *cpk, int dir,
		       uint64_t start_time)
{
	uint8_t new;

	rte_spinlock_lock(&st->st_lock);

	if (st->st_proto == NAT_PROTO_TCP) {
		bool forw = (dir == CGN_DIR_FORW);
		enum cgn_tcp_event event;
		uint64_t rtt;

		/*
		 * Inspect TCP flags in order to determine event type, rtt
		 * times, and to record TCP flow history.
		 */

		/* hist_bit relies on these asserts */
		assert(CGN_SESS_HIST_FFIN == 0x02);
		assert(CGN_SESS_HIST_BFIN == 0x04);
		assert(CGN_SESS_HIST_FRST == 0x08);
		assert(CGN_SESS_HIST_BRST == 0x10);
		assert(CGN_SESS_HIST_FACK == 0x20);
		assert(CGN_SESS_HIST_BACK == 0x40);

		uint8_t hist_bit = 0x02;
		if (!forw)
			hist_bit <<= 1;

		if (cpk->cpk_tcp_flags & TH_RST) {
			/* RST event */
			event = CGN_TCP_EVENT_RST;
			hist_bit <<= 2;

			/* Record forw or back RST seen */
			if ((st->st_hist & hist_bit) == 0)
				st->st_hist |= hist_bit;

		} else if (cpk->cpk_tcp_flags & TH_SYN) {
			/* SYN event */
			event = CGN_TCP_EVENT_SYN;

			/* External rtt.  Look for incoming SYN-ACK. */
			if (!forw && (cpk->cpk_tcp_flags & TH_ACK)) {
				rtt = soft_ticks - start_time;
				st->st_ext_rtt = MIN(rtt, USHRT_MAX);
			}

		} else if (cpk->cpk_tcp_flags & TH_FIN) {
			/* FIN event */
			event = CGN_TCP_EVENT_FIN;

			/* Record forw or back FIN seen */
			if ((st->st_hist & hist_bit) == 0)
				st->st_hist |= hist_bit;

		} else if (cpk->cpk_tcp_flags & TH_ACK) {
			event = CGN_TCP_EVENT_ACK;
			hist_bit <<= 4;

			/* Record forw or back ACK seen */
			if ((st->st_hist & hist_bit) == 0) {
				st->st_hist |= hist_bit;

				/* Int rtt. Look for first forw ACK */
				if (forw) {
					rtt = soft_ticks - start_time -
						st->st_ext_rtt;
					st->st_int_rtt = MIN(rtt, USHRT_MAX);
				}
			}

		} else
			event = CGN_TCP_EVENT_NONE;

		/* Crank TCP state machine */
		new = cgn_tcp_fsm[st->st_state][dir][event];

		if (new != CGN_TCP_STATE_NONE && new != st->st_state) {
			st->st_state = new;
			if (new == CGN_TCP_STATE_ESTABLISHED)
				st->st_hist |= CGN_SESS_HIST_ESTD;
		}
	} else {
		/* Crank non-TCP state machine */
		new = cgn_sess_fsm[st->st_state][dir][CGN_SESS_EVENT_PKT];

		if (new != CGN_SESS_STATE_NONE && new != st->st_state)
			st->st_state = new;
	}

	/* Clear idle flag, if packet is eligible */
	if (cpk->cpk_keepalive && rte_atomic16_read(&st->st_idle) != 0)
		rte_atomic16_clear(&st->st_idle);

	rte_spinlock_unlock(&st->st_lock);
}

/*
 * Get state-dependent expiry time
 */
uint32_t cgn_sess_state_expiry_time(uint8_t proto, uint8_t state)
{
	uint32_t etime;

	if (state <= CGN_SESS_STATE_CLOSED)
		return 0;

	if (proto == NAT_PROTO_TCP) {
		if (state == CGN_TCP_STATE_ESTABLISHED)
			etime = cgn_sess_tcp_etime[CGN_ETIME_TCP_ESTBD];
		else if (state == CGN_TCP_STATE_INIT)
			etime = cgn_sess_tcp_etime[CGN_ETIME_TCP_OPENING];
		else
			etime = cgn_sess_tcp_etime[CGN_ETIME_TCP_CLOSING];
	} else if (proto == NAT_PROTO_UDP) {
		if (state == CGN_SESS_STATE_ESTABLISHED)
			etime = cgn_sess_udp_etime[CGN_ETIME_ESTBD];
		else
			etime = cgn_sess_udp_etime[CGN_ETIME_OPENING];
	} else {
		if (state == CGN_SESS_STATE_ESTABLISHED)
			etime = cgn_sess_other_etime[CGN_ETIME_ESTBD];
		else
			etime = cgn_sess_other_etime[CGN_ETIME_OPENING];
	}
	return etime;
}

/*
 * Timeout event for 2-tuple session.  Returns timeout value for state
 * (regardless of if it changed or not).
 */
uint32_t cgn_sess_state_timeout(struct cgn_state *st)
{
	uint8_t new;
	uint32_t etime;

	rte_spinlock_lock(&st->st_lock);

	if (st->st_proto == NAT_PROTO_TCP) {

		new = cgn_tcp_fsm[st->st_state][CGN_DIR_FORW][CGN_TCP_EVENT_TO];

		if (new != CGN_TCP_STATE_NONE && new != st->st_state)
			st->st_state = new;
	} else {
		new = cgn_sess_fsm[st->st_state][CGN_DIR_FORW]
			[CGN_SESS_EVENT_TO];

		if (new != CGN_SESS_STATE_NONE && new != st->st_state)
			st->st_state = new;
	}

	etime = cgn_sess_state_expiry_time(st->st_proto, new);

	rte_spinlock_unlock(&st->st_lock);
	return etime;
}

/*
 * Force a session to closed state
 */
void cgn_sess_state_close(struct cgn_state *st)
{
	uint8_t new;

	rte_spinlock_lock(&st->st_lock);

	if (st->st_proto == NAT_PROTO_TCP) {
		new = CGN_TCP_STATE_CLOSED;

		if (new != st->st_state)
			st->st_state = new;
	} else {
		new = CGN_SESS_STATE_CLOSED;

		if (new != st->st_state)
			st->st_state = new;
	}

	rte_spinlock_unlock(&st->st_lock);
}

const char *cgn_sess_state_str(struct cgn_state *st)
{
	/* TCP string covers TCP and non TCP */
	return cgn_tcp_state_str(st->st_state);
}

const char *cgn_sess_state_str_short(struct cgn_state *st)
{
	/* TCP string covers TCP and non TCP */
	return cgn_tcp_state_str_short(st->st_state);
}

void cgn_sess_state_jsonw(json_writer_t *json, struct cgn_state *st)
{
	jsonw_uint_field(json, "state", st->st_state);

	if (st->st_proto == NAT_PROTO_TCP) {
		uint32_t rtt_ext, rtt_int;

		/* millisecs to microsecs */
		rtt_ext = st->st_ext_rtt * 1000;
		rtt_int = st->st_int_rtt * 1000;

		jsonw_uint_field(json, "rtt_ext", rtt_ext);
		jsonw_uint_field(json, "rtt_int", rtt_int);
		jsonw_uint_field(json, "hist", st->st_hist);
	}
}
