/*	$NetBSD: ip_id.c,v 1.15 2011/11/19 22:51:25 tls Exp $	*/

/*-
 * Copyright (c) 2008 The NetBSD Foundation, Inc.
 * All rights reserved.
 * Copyright (c) 2017,2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-2-Clause-NETBSD)
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by the 3am Software Foundry ("3am").  It was developed by Matt Thomas.
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

#include <netinet/in.h>
#include <rte_debug.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <stdint.h>
#include <stdlib.h>

#include "ip_funcs.h"

#define	IPID_MAXID	65535
#define	IPID_NUMIDS	32768

struct ipid_state {
	uint16_t	ids_start_slot;
	uint16_t	ids_slots[IPID_MAXID];
};

/*
 * Store the IDs on a per core basis so that we can access from
 * multiple cores concurrently without having to lock.
 */
static RTE_DEFINE_PER_LCORE(struct ipid_state *, ip_ids);

static inline uint32_t
ipid_random(void)
{
	return random();
}

void ip_id_init(void)
{
	size_t i;

	RTE_PER_LCORE(ip_ids) = malloc(sizeof(struct ipid_state));
	if (!RTE_PER_LCORE(ip_ids))
		rte_panic("no memory for lcore %u ip ids\n", rte_lcore_id());

	RTE_PER_LCORE(ip_ids)->ids_start_slot = ipid_random();
	for (i = 0; i < IPID_MAXID; i++)
		RTE_PER_LCORE(ip_ids)->ids_slots[i] = i;

	/*
	 * Shuffle the array.
	 */
	for (i = IPID_MAXID; --i > 0;) {
		size_t k = ipid_random() % (i + 1);
		uint16_t t = RTE_PER_LCORE(ip_ids)->ids_slots[i];

		RTE_PER_LCORE(ip_ids)->ids_slots[i] =
			RTE_PER_LCORE(ip_ids)->ids_slots[k];
		RTE_PER_LCORE(ip_ids)->ids_slots[k] = t;
	}
}

uint16_t dp_ip_randomid(uint16_t salt)
{
	uint32_t r, k, id;

	if (!RTE_PER_LCORE(ip_ids))
		ip_id_init();

	/* A random number. */
	r = ipid_random();

	/*
	 * We do a modified Fisher-Yates shuffle but only one position at a
	 * time. Instead of the last entry, we swap with the first entry and
	 * then advance the start of the window by 1.  The next time that
	 * swapped-out entry can be used is at least 32768 iterations in the
	 * future.
	 *
	 * The easiest way to visual this is to imagine a card deck with 52
	 * cards.  First thing we do is split that into two sets, each with
	 * half of the cards; call them deck A and deck B.  Pick a card
	 * randomly from deck A and remember it, then place it at the
	 * bottom of deck B.  Then take the top card from deck B and add it
	 * to deck A.  Pick another card randomly from deck A and ...
	 */
	k = (r & (IPID_NUMIDS - 1)) + RTE_PER_LCORE(ip_ids)->ids_start_slot;
	if (k >= IPID_MAXID)
		k -= IPID_MAXID;

	id = RTE_PER_LCORE(ip_ids)->ids_slots[k];
	if (k != RTE_PER_LCORE(ip_ids)->ids_start_slot) {
		RTE_PER_LCORE(ip_ids)->ids_slots[k] =
			RTE_PER_LCORE(ip_ids)->ids_slots[
				RTE_PER_LCORE(ip_ids)->ids_start_slot];
		RTE_PER_LCORE(ip_ids)->ids_slots[
			RTE_PER_LCORE(ip_ids)->ids_start_slot] = id;
	}
	if (++RTE_PER_LCORE(ip_ids)->ids_start_slot == IPID_MAXID)
		RTE_PER_LCORE(ip_ids)->ids_start_slot = 0;

	/*
	 * Add an optional salt to the id to further obscure it.
	 */
	id += salt;
	if (id >= IPID_MAXID)
		id -= IPID_MAXID;

	return htons(id + 1);
}
