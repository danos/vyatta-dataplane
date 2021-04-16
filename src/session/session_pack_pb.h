/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef SESSION_PACK_PB_H
#define SESSION_PACK_PB_H
#include "protobuf/SessionPack.pb-c.h"

struct session;

int session_pack_sentry_pb(struct session *s, DPSessionKeyMsg *sk);
int session_pack_pb(struct session *s, DPSessionMsg *dpsm);
struct session *session_restore_pb(DPSessionMsg *dpsm, struct ifnet *ifp);

#endif
