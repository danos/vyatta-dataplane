/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */

/*	$NetBSD: npf_state_tcp.c,v 1.11 2012/10/06 23:50:17 rmind Exp $	*/

/*-
 * Copyright (c) 2010-2012 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-2-Clause-NETBSD)
 *
 * This material is based upon work partially supported by The
 * NetBSD Foundation under a contract with Mindaugas Rasiukevicius.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <netinet/tcp.h>
#include <rte_branch_prediction.h>
#include <stdbool.h>
#include <stdint.h>
/*
 * NPF TCP state engine for connection tracking.
 */
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "npf/npf_cache.h"
#include "npf/npf_rc.h"
#include "npf/npf_state.h"

struct rte_mbuf;

#define	SEQ_LEQ(a, b)	((int)((a)-(b)) <= 0)
#define	SEQ_GT(a, b)	((int)((a)-(b)) > 0)
#define	SEQ_GEQ(a, b)	((int)((a)-(b)) >= 0)

static bool npf_strict_order_rst;
static bool npf_state_tcp_strict;

#define	NPF_TCP_MAXACKWIN	66000

/*
 * List of TCP flag cases and conversion of flags to a case (index).
 */
enum npf_tcpfc {
	TCPFC_INVALID = 0,
	TCPFC_SYN,
	TCPFC_SYNACK,
	TCPFC_ACK,
	TCPFC_FIN,
	TCPFC_RST
};

#define TCPFC_FIRST	TCPFC_INVALID
#define TCPFC_LAST	TCPFC_RST
#define TCPFC_COUNT	(TCPFC_LAST + 1)

#define CORE_TCP_FLAGS	(TH_FIN|TH_SYN|TH_RST|TH_ACK)

static inline enum npf_tcpfc npf_tcpfl2case(const uint8_t tcpfl)
{
	enum npf_tcpfc c;
	u_int i;

	assert(TH_FIN == 0x01);
	assert(TH_SYN == 0x02);
	assert(TH_ACK == 0x10);
	assert(TH_RST == 0x04);

	/*
	 * Flags are shifted to use four least significant bits, thus each
	 * flag combination has a unique number ranging from 0 to 15, e.g.
	 * TH_SYN | TH_ACK has number 10, since (0x02 | (0x10 >> 1)) == 10.
	 * However, the requirement is to have number 0 for invalid cases,
	 * such as TH_SYN | TH_FIN, and to have the same number for TH_FIN
	 * and TH_FIN|TH_ACK cases.  Thus, we generate a mask assigning 4
	 * bits for each number, which contains the actual case numbers:
	 *
	 * TCPFC_SYNACK	<< (10 << 2) == 0x20000000000 (10 - SYN,ACK)
	 * TCPFC_FIN	<<  (9 << 2) == 0x04000000000 (9  - FIN,ACK)
	 * ...
	 *
	 * Hence, OR'ed mask value is 0x0005024300050140.
	 */
	i = (tcpfl & (TH_SYN | TH_FIN | TH_RST)) | ((tcpfl & TH_ACK) >> 1);
	c = (0x0005024300050140ull >> (i << 2)) & 7;

	assert(c < TCPFC_COUNT);
	return c;
}


/* Match with NPF defined states */

#define sNO NPF_TCPS_NONE         /*TCP_CONNTRACK_NONE*/
#define sSS NPF_TCPS_SYN_SENT     /*TCP_CONNTRACK_SYN_SENT*/
#define sSR NPF_TCPS_SYN_RECEIVED /*TCP_CONNTRACK_SYN_RECV*/
#define sES NPF_TCPS_ESTABLISHED  /*TCP_CONNTRACK_ESTABLISHED*/
#define sFW NPF_TCPS_FIN_WAIT     /*TCP_CONNTRACK_FIN_WAIT*/
#define sCW NPF_TCPS_CLOSE_WAIT   /*TCP_CONNTRACK_CLOSE_WAIT*/
#define sLA NPF_TCPS_LAST_ACK     /*TCP_CONNTRACK_LAST_ACK*/
#define sTW NPF_TCPS_TIME_WAIT    /*TCP_CONNTRACK_TIME_WAIT*/
#define sCL NPF_TCPS_CLOSING      /*TCP_CONNTRACK_CLOSE*/
#define sS2 NPF_TCPS_SIMSYN_SENT  /*TCP_CONNTRACK_SYN_SENT2*/

/*
 * sIV and sIG are only used as the values stored in npf_tcp_strict_fsm
 */
#define sIG 0			/* Ignore */
#define sIV NPF_TCP_NSTATES	/* Invalid */



static uint8_t npf_tcp_strict_fsm[NPF_FLOW_SZ][TCPFC_COUNT][NPF_TCP_NSTATES];

/*
 * NPF transition table of a tracked TCP connection.
 *
 * There is a single state, which is changed in the following way:
 *
 * new_state = npf_tcp_fsm[old_state][direction][npf_tcpfl2case(tcp_flags)];
 *
 * Note that this state is different from the state in each end (host).
 */
static uint8_t npf_tcp_fsm[NPF_TCP_NSTATES][NPF_FLOW_SZ][TCPFC_COUNT] = {
	[NPF_TCPS_NONE] = {
		[NPF_FLOW_FORW] = {
			/* Handshake (1): initial SYN. */
			[TCPFC_SYN]	= NPF_TCPS_SYN_SENT,
			/* We have missed some of all of the the handshake */
			[TCPFC_ACK]	= NPF_TCPS_ESTABLISHED,
			[TCPFC_SYNACK]	= NPF_TCPS_SYN_RECEIVED,
			[TCPFC_INVALID]	= NPF_TCPS_ERR,
			[TCPFC_FIN]	= NPF_TCPS_FIN_SENT,
			[TCPFC_RST]	= NPF_TCPS_CLOSED,
		},
	},
	[NPF_TCPS_SYN_SENT] = {
		[NPF_FLOW_FORW] = {
			/* SYN may be retransmitted. */
			[TCPFC_SYN]	= NPF_TCPS_OK,
			[TCPFC_RST]	= NPF_TCPS_RST_RECEIVED,
		},
		[NPF_FLOW_BACK] = {
			/* Handshake (2): SYN-ACK is expected. */
			[TCPFC_SYNACK]	= NPF_TCPS_SYN_RECEIVED,
			/* Simultaneous initiation - SYN. */
			[TCPFC_SYN]	= NPF_TCPS_SIMSYN_SENT,
			[TCPFC_RST]	= NPF_TCPS_RST_RECEIVED,
		},
	},
	[NPF_TCPS_SIMSYN_SENT] = {
		[NPF_FLOW_FORW] = {
			/* Original SYN re-transmission. */
			[TCPFC_SYN]	= NPF_TCPS_OK,
			/* SYN-ACK response to simultaneous SYN. */
			[TCPFC_SYNACK]	= NPF_TCPS_SYN_RECEIVED,
			[TCPFC_RST]	= NPF_TCPS_RST_RECEIVED,
		},
		[NPF_FLOW_BACK] = {
			/* Simultaneous SYN re-transmission.*/
			[TCPFC_SYN]	= NPF_TCPS_OK,
			/* SYN-ACK response to original SYN. */
			[TCPFC_SYNACK]	= NPF_TCPS_SYN_RECEIVED,
			/* FIN may occur early. */
			[TCPFC_FIN]	= NPF_TCPS_FIN_RECEIVED,
			[TCPFC_RST]	= NPF_TCPS_RST_RECEIVED,
		},
	},
	[NPF_TCPS_SYN_RECEIVED] = {
		[NPF_FLOW_FORW] = {
			/* Handshake (3): ACK is expected. */
			[TCPFC_ACK]	= NPF_TCPS_ESTABLISHED,
			/* FIN may be sent early. */
			[TCPFC_FIN]	= NPF_TCPS_FIN_SENT,
			[TCPFC_RST]	= NPF_TCPS_RST_RECEIVED,
		},
		[NPF_FLOW_BACK] = {
			/* SYN-ACK may be retransmitted. */
			[TCPFC_SYNACK]	= NPF_TCPS_OK,
			/* XXX: ACK of late SYN in simultaneous case? */
			[TCPFC_ACK]	= NPF_TCPS_OK,
			/* FIN may occur early. */
			[TCPFC_FIN]	= NPF_TCPS_FIN_RECEIVED,
			[TCPFC_RST]	= NPF_TCPS_RST_RECEIVED,
		},
	},
	[NPF_TCPS_ESTABLISHED] = {
		/*
		 * Regular ACKs (data exchange) or FIN.
		 * FIN packets may have ACK set.
		 */
		[NPF_FLOW_FORW] = {
			[TCPFC_ACK]	= NPF_TCPS_OK,
			/* FIN by the sender. */
			[TCPFC_FIN]	= NPF_TCPS_FIN_SENT,
			[TCPFC_RST]	= NPF_TCPS_RST_RECEIVED,
		},
		[NPF_FLOW_BACK] = {
			[TCPFC_ACK]	= NPF_TCPS_OK,
			/* FIN by the receiver. */
			[TCPFC_FIN]	= NPF_TCPS_FIN_RECEIVED,
			[TCPFC_RST]	= NPF_TCPS_RST_RECEIVED,
		},
	},
	[NPF_TCPS_FIN_SENT] = {
		[NPF_FLOW_FORW] = {
			/* FIN may be re-transmitted.  Late ACK as well. */
			[TCPFC_ACK]	= NPF_TCPS_OK,
			[TCPFC_FIN]	= NPF_TCPS_OK,
			[TCPFC_RST]	= NPF_TCPS_RST_RECEIVED,
		},
		[NPF_FLOW_BACK] = {
			/* If ACK, connection is half-closed now. */
			[TCPFC_ACK]	= NPF_TCPS_FIN_WAIT,
			/* FIN or FIN-ACK race - immediate closing. */
			[TCPFC_FIN]	= NPF_TCPS_CLOSING,
			[TCPFC_RST]	= NPF_TCPS_RST_RECEIVED,
		},
	},
	[NPF_TCPS_FIN_RECEIVED] = {
		/*
		 * FIN was received.  Equivalent scenario to sent FIN.
		 */
		[NPF_FLOW_FORW] = {
			[TCPFC_ACK]	= NPF_TCPS_CLOSE_WAIT,
			[TCPFC_FIN]	= NPF_TCPS_CLOSING,
			[TCPFC_RST]	= NPF_TCPS_RST_RECEIVED,
		},
		[NPF_FLOW_BACK] = {
			[TCPFC_ACK]	= NPF_TCPS_OK,
			[TCPFC_FIN]	= NPF_TCPS_OK,
			[TCPFC_RST]	= NPF_TCPS_RST_RECEIVED,
		},
	},
	[NPF_TCPS_CLOSE_WAIT] = {
		/* Sender has sent the FIN and closed its end. */
		[NPF_FLOW_FORW] = {
			[TCPFC_ACK]	= NPF_TCPS_OK,
			[TCPFC_FIN]	= NPF_TCPS_LAST_ACK,
			[TCPFC_RST]	= NPF_TCPS_RST_RECEIVED,
		},
		[NPF_FLOW_BACK] = {
			[TCPFC_ACK]	= NPF_TCPS_OK,
			[TCPFC_FIN]	= NPF_TCPS_LAST_ACK,
			[TCPFC_RST]	= NPF_TCPS_RST_RECEIVED,
		},
	},
	[NPF_TCPS_FIN_WAIT] = {
		/* Receiver has closed its end. */
		[NPF_FLOW_FORW] = {
			[TCPFC_ACK]	= NPF_TCPS_OK,
			[TCPFC_FIN]	= NPF_TCPS_LAST_ACK,
			[TCPFC_RST]	= NPF_TCPS_RST_RECEIVED,
		},
		[NPF_FLOW_BACK] = {
			[TCPFC_ACK]	= NPF_TCPS_OK,
			[TCPFC_FIN]	= NPF_TCPS_LAST_ACK,
			[TCPFC_RST]	= NPF_TCPS_RST_RECEIVED,
		},
	},
	[NPF_TCPS_CLOSING] = {
		/* Race of FINs - expecting ACK. */
		[NPF_FLOW_FORW] = {
			[TCPFC_ACK]	= NPF_TCPS_LAST_ACK,
			[TCPFC_RST]	= NPF_TCPS_RST_RECEIVED,
		},
		[NPF_FLOW_BACK] = {
			[TCPFC_ACK]	= NPF_TCPS_LAST_ACK,
			[TCPFC_RST]	= NPF_TCPS_RST_RECEIVED,
		},
	},
	[NPF_TCPS_LAST_ACK] = {
		/* FINs exchanged - expecting last ACK. */
		[NPF_FLOW_FORW] = {
			[TCPFC_ACK]	= NPF_TCPS_TIME_WAIT,
			[TCPFC_RST]	= NPF_TCPS_RST_RECEIVED,
		},
		[NPF_FLOW_BACK] = {
			[TCPFC_ACK]	= NPF_TCPS_TIME_WAIT,
			[TCPFC_RST]	= NPF_TCPS_RST_RECEIVED,
		},
	},
	[NPF_TCPS_TIME_WAIT] = {
		/* May re-open the connection as per RFC 1122. */
		[NPF_FLOW_FORW] = {
			[TCPFC_SYN]	= NPF_TCPS_SYN_SENT,
			/*  Prevent TIME-WAIT assassination (RFC 1337).*/
			[TCPFC_RST]	= NPF_TCPS_OK,
		},
		[NPF_FLOW_BACK] = {
			/*  Prevent TIME-WAIT assassination (RFC 1337).*/
			[TCPFC_RST]	= NPF_TCPS_OK,
		},
	},
};

/*
 * Change the uninitialized state machine values from 0 (NPF_TCPS_NONE) to
 * NPF_TCPS_OK, which is effectively a NOP, i.e. no state transition will
 * occur.  The prevents unexpected flags and state combinations from forcing
 * the session to CLOSED state.
 */
static void npf_state_tcp_fsm_init(void)
{
	uint8_t state;
	uint di, fc;

	assert(NPF_TCPS_NONE == 0);

	for (state = NPF_TCPS_FIRST; state <= NPF_TCPS_LAST; state++) {
		/* Forwards */
		di = NPF_FLOW_FORW;

		for (fc = 0; fc < TCPFC_COUNT; fc++)
			if (npf_tcp_fsm[state][di][fc] == NPF_TCPS_NONE)
				npf_tcp_fsm[state][di][fc] = NPF_TCPS_OK;

		/* Back */
		di = NPF_FLOW_BACK;

		for (fc = 0; fc < TCPFC_COUNT; fc++)
			if (npf_tcp_fsm[state][di][fc] == NPF_TCPS_NONE)
				npf_tcp_fsm[state][di][fc] = NPF_TCPS_OK;
	}
}

void
npf_state_tcp_init(void)
{
	uint8_t state;

	/*compared to: nf_conntrack_proto_tcp.c */

	/* sIG is 0 */
	memset(npf_tcp_strict_fsm, 0, sizeof(npf_tcp_strict_fsm));
	/* for receiving initial tcp syn packet */

	/* for receiving initial tcp syn ack packet */
	npf_tcp_strict_fsm[NPF_FLOW_FORW][TCPFC_SYNACK][sNO] = sIV;
	npf_tcp_strict_fsm[NPF_FLOW_FORW][TCPFC_SYNACK][sSS] = sIV;
	npf_tcp_strict_fsm[NPF_FLOW_FORW][TCPFC_SYNACK][sES] = sIV;
	npf_tcp_strict_fsm[NPF_FLOW_FORW][TCPFC_SYNACK][sFW] = sIV;
	npf_tcp_strict_fsm[NPF_FLOW_FORW][TCPFC_SYNACK][sCW] = sIV;
	npf_tcp_strict_fsm[NPF_FLOW_FORW][TCPFC_SYNACK][sLA] = sIV;
	npf_tcp_strict_fsm[NPF_FLOW_FORW][TCPFC_SYNACK][sTW] = sIV;
	npf_tcp_strict_fsm[NPF_FLOW_FORW][TCPFC_SYNACK][sCL] = sIV;

	/* for receiving initial tcp FIN packet */
	npf_tcp_strict_fsm[NPF_FLOW_FORW][TCPFC_FIN][sNO] = sIV;
	npf_tcp_strict_fsm[NPF_FLOW_FORW][TCPFC_FIN][sSS] = sIV;
	npf_tcp_strict_fsm[NPF_FLOW_FORW][TCPFC_FIN][sS2] = sIV;

	/* ack */
	npf_tcp_strict_fsm[NPF_FLOW_FORW][TCPFC_ACK][sNO] = sIV;
	npf_tcp_strict_fsm[NPF_FLOW_FORW][TCPFC_ACK][sSS] = sIV;
	npf_tcp_strict_fsm[NPF_FLOW_FORW][TCPFC_ACK][sS2] = sIV;

	/* rst */
	/* invalid flag combinations */
	for (state = NPF_TCPS_FIRST; state <= NPF_TCPS_LAST; state++)
		npf_tcp_strict_fsm[NPF_FLOW_FORW][TCPFC_INVALID][state] = sIV;

	/*reply*/

	/*syn*/
	npf_tcp_strict_fsm[NPF_FLOW_BACK][TCPFC_SYN][sNO] = sIV;
	npf_tcp_strict_fsm[NPF_FLOW_BACK][TCPFC_SYN][sSR] = sIV;
	npf_tcp_strict_fsm[NPF_FLOW_BACK][TCPFC_SYN][sES] = sIV;
	npf_tcp_strict_fsm[NPF_FLOW_BACK][TCPFC_SYN][sFW] = sIV;
	npf_tcp_strict_fsm[NPF_FLOW_BACK][TCPFC_SYN][sCW] = sIV;
	npf_tcp_strict_fsm[NPF_FLOW_BACK][TCPFC_SYN][sLA] = sIV;
	npf_tcp_strict_fsm[NPF_FLOW_BACK][TCPFC_SYN][sTW] = sIV;
	npf_tcp_strict_fsm[NPF_FLOW_BACK][TCPFC_SYN][sCL] = sIV;

	/*synack*/
	npf_tcp_strict_fsm[NPF_FLOW_BACK][TCPFC_SYNACK][sNO] = sIV;

	/*fin*/
	npf_tcp_strict_fsm[NPF_FLOW_BACK][TCPFC_FIN][sNO] = sIV;
	npf_tcp_strict_fsm[NPF_FLOW_BACK][TCPFC_FIN][sSS] = sIV;
	npf_tcp_strict_fsm[NPF_FLOW_BACK][TCPFC_FIN][sS2] = sIV;

	/* ack */
	npf_tcp_strict_fsm[NPF_FLOW_BACK][TCPFC_ACK][sNO] = sIV;

	/* rst */
	/* invalid flag combinations */
	for (state = NPF_TCPS_FIRST; state <= NPF_TCPS_LAST; state++)
		npf_tcp_strict_fsm[NPF_FLOW_BACK][TCPFC_INVALID][state] = sIV;

	npf_state_tcp_fsm_init();
}


/*
 * npf_tcp_inwindow: determine whether the packet is in the TCP window
 * and thus part of the connection we are tracking.
 */
static bool
npf_tcp_inwindow(const npf_cache_t *npc, struct rte_mbuf *nbuf,
		 npf_state_t *nst, const enum npf_flow_dir di)
{
	const struct tcphdr * const th = &npc->npc_l4.tcp;
	const uint8_t tcpfl = th->th_flags;
	struct npf_tcp_window *fstate, *tstate;
	int tcpdlen, ackskew;
	tcp_seq seq, ack, end;
	uint32_t win;

	assert(npf_cache_ipproto(npc) == IPPROTO_TCP);

	/*
	 * Perform SEQ/ACK numbers check against boundaries.  Reference:
	 *
	 *	Rooij G., "Real stateful TCP packet filtering in IP Filter",
	 *	10th USENIX Security Symposium invited talk, Aug. 2001.
	 *
	 * There are four boundaries defined as following:
	 *	I)   SEQ + LEN	<= MAX { SND.ACK + MAX(SND.WIN, 1) }
	 *	II)  SEQ	>= MAX { SND.SEQ + SND.LEN - MAX(RCV.WIN, 1) }
	 *	III) ACK	<= MAX { RCV.SEQ + RCV.LEN }
	 *	IV)  ACK	>= MAX { RCV.SEQ + RCV.LEN } - MAXACKWIN
	 *
	 * Let these members of struct npf_tcp_window be the maximum seen
	 * values of:
	 *	nst_end		- SEQ + LEN
	 *	nst_maxend	- ACK + MAX(WIN, 1)
	 *	nst_maxwin	- MAX(WIN, 1)
	 */

	tcpdlen = npf_tcpsaw(npc, &seq, &ack, &win);
	end = seq + tcpdlen;
	if (tcpfl & TH_SYN) {
		end++;
	}
	if (tcpfl & TH_FIN) {
		end++;
	}

	fstate = &nst->nst_tcpst[di];
	tstate = &nst->nst_tcpst[!di];
	win = win ? (win << fstate->nst_wscale) : 1;

	/*
	 * Initialise if the first packet.
	 * Note: only case when nst_maxwin is zero.
	 */
	if (unlikely(((tcpfl & CORE_TCP_FLAGS) == TH_SYN))) {
		/*
		 * Normally, it should be the first SYN or a re-transmission
		 * of SYN.  The state of the other side will get set with a
		 * SYN-ACK reply (see below).
		 */
		fstate->nst_end = end;
		fstate->nst_maxend = end;
		fstate->nst_maxwin = win;
		tstate->nst_end = 0;
		tstate->nst_maxend = 0;
		tstate->nst_maxwin = 1;

		/*
		 * Handle TCP Window Scaling (RFC 1323).  Both sides may
		 * send this option in their SYN packets.
		 */
		fstate->nst_wscale = 0;
		(void)npf_fetch_tcpopts(npc, nbuf, NULL, &fstate->nst_wscale);

		tstate->nst_wscale = 0;

		/* Done. */
		return true;
	}
	if (unlikely(((tcpfl & CORE_TCP_FLAGS) == (TH_SYN | TH_ACK)))) {
		/*
		 * Should be a SYN-ACK reply to SYN.  If SYN is not set,
		 * then we cannot track, so abort here,
		 */
		if (!tstate->nst_end)
			return true;

		fstate->nst_end = end;
		fstate->nst_maxend = end + 1;
		fstate->nst_maxwin = win;
		fstate->nst_wscale = 0;

		/* Handle TCP Window Scaling */
		(void)npf_fetch_tcpopts(npc, nbuf, NULL,
					&fstate->nst_wscale);
	}

	/*
	 * If either side is not initialized, ignore
	 * window bounds checking.
	 */
	if (!fstate->nst_end || !tstate->nst_end)
		return true;

	if ((tcpfl & TH_ACK) == 0) {
		/* Pretend that an ACK was sent. */
		ack = tstate->nst_end;
	} else if ((tcpfl & (TH_ACK|TH_RST)) == (TH_ACK|TH_RST) && ack == 0) {
		/* Workaround for some TCP stacks. */
		ack = tstate->nst_end;
	}

	if (unlikely(tcpfl & TH_RST)) {
		/* RST to the initial SYN may have zero SEQ - fix it up. */
		if (seq == 0 && nst->nst_state == NPF_TCPS_SYN_SENT) {
			end = fstate->nst_end;
			seq = end;
		}

		/* Strict in-order sequence for RST packets. */
		if (npf_strict_order_rst && (fstate->nst_end - seq) > 1) {
			return false;
		}
	}

	/*
	 * Determine whether the data is within previously noted window,
	 * that is, upper boundary for valid data (I).
	 */
	if (!SEQ_LEQ(end, fstate->nst_maxend)) {
		return false;
	}

	/* Lower boundary (II), which is no more than one window back. */
	if (!SEQ_GEQ(seq, fstate->nst_end - tstate->nst_maxwin)) {
		return false;
	}

	/*
	 * Boundaries for valid acknowledgments (III, IV) - one predicted
	 * window up or down, since packets may be fragmented.
	 */
	ackskew = tstate->nst_end - ack;
	if (ackskew < -NPF_TCP_MAXACKWIN ||
	    ackskew > (NPF_TCP_MAXACKWIN << fstate->nst_wscale)) {
		return false;
	}

	/*
	 * Packet has been passed.
	 *
	 * Negative ackskew might be due to fragmented packets.  Since the
	 * total length of the packet is unknown - bump the boundary.
	 */

	if (ackskew < 0) {
		tstate->nst_end = ack;
	}
	/* Keep track of the maximum window seen. */
	if (fstate->nst_maxwin < win) {
		fstate->nst_maxwin = win;
	}
	if (SEQ_GT(end, fstate->nst_end)) {
		fstate->nst_end = end;
	}
	/* Note the window for upper boundary. */
	if (SEQ_GEQ(ack + win, tstate->nst_maxend)) {
		tstate->nst_maxend = ack + win;
	}
	return true;
}

/*
 * npf_state_tcp: inspect TCP segment, determine whether it belongs to
 * the connection and track its state.  Returns either:
 *  1. the new TCP state,
 *  2. NPF_TCPS_OK, if no state change is required, or
 *  3. A negative return code if the packet should be discarded
 */
uint8_t
npf_state_tcp(const npf_cache_t *npc, struct rte_mbuf *nbuf, npf_state_t *nst,
	      const enum npf_flow_dir di, int *error)
{
	const struct tcphdr * const th = &npc->npc_l4.tcp;
	const uint8_t tcpfl = th->th_flags;
	const uint8_t state = nst->nst_state;
	uint8_t nstate;
	const enum npf_tcpfc flagcase = npf_tcpfl2case(tcpfl);

	assert(di <= NPF_FLOW_LAST);

	/* Look for a transition to a new state. */
	nstate = npf_tcp_fsm[state][di][flagcase];

	/* only filter on invalid state transitions */
	/* let npf actually handle the state transitions */
	if (npf_state_tcp_strict) {
		/* Only a SYN or RST can create a session. */
		if (state == NPF_TCPS_NONE &&
		    (tcpfl & CORE_TCP_FLAGS) != TH_SYN &&
		    (tcpfl & TH_RST) == 0) {
			*error = -NPF_RC_TCP_SYN;
			return NPF_TCPS_ERR;
		}

		if (npf_tcp_strict_fsm[di][flagcase][state] == sIV) {
			*error = -NPF_RC_TCP_STATE;
			return NPF_TCPS_ERR;
		}
	}

	/* Determine whether TCP packet really belongs to this connection. */
	if (!npf_tcp_inwindow(npc, nbuf, nst, di)) {
		*error = -NPF_RC_TCP_WIN;
		return NPF_TCPS_ERR;
	}

	return nstate;
}

void npf_state_set_tcp_strict(bool value)
{
	npf_state_tcp_strict = value;
}
