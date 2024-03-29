/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef SESSION_PACK_PB_H
#define SESSION_PACK_PB_H
#include "protobuf/SessionPack.pb-c.h"

struct session;

int session_restore_sentry_packet_pb(struct sentry_packet *sp,
				     const struct ifnet *ifp,
				     DPSessionKeyMsg *sk);
int session_pack_pb(struct session *s, DPSessionMsg *dpsm, bool full_copy);
int session_restore_counters_pb(struct session *s, DPSessionCounterMsg *scm);
struct session *session_restore_pb(DPSessionMsg *dpsm, struct ifnet *ifp,
				   uint8_t protocol);

#endif /* SESSION_PACK_PB_H */
