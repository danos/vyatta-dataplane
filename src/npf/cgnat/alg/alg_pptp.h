/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef ALG_PPTP_H
#define ALG_PPTP_H

#include <stdint.h>
#include "npf/cgnat/cgn_dir.h"

struct cgn_alg_sess_ctx;
struct alg_pinhole;
struct cgn_session;
struct cgn_packet;
struct rte_mbuf;

struct cgn_alg_sess_ctx *cgn_alg_pptp_sess_init(struct cgn_session *cse,
						struct alg_pinhole *ap);
void cgn_alg_pptp_sess_uninit(struct cgn_alg_sess_ctx *as);

int cgn_alg_pptp_child_sess2_init(struct cgn_alg_sess_ctx *as,
				  struct cgn_sess2 *s2);

int cgn_alg_pptp_inspect(struct cgn_packet *cpk, struct rte_mbuf *mbuf,
			 enum cgn_dir dir, struct cgn_alg_sess_ctx *as);

void cgn_alg_show_pptp_session(struct json_writer *json,
			       struct cgn_alg_sess_ctx *as);

#endif /* ALG_PPTP_H */
