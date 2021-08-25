/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef SESSION_WATCH_H
#define SESSION_WATCH_H

#include <stdbool.h>
#include "dp_session.h"

bool is_watch_on(void);

/*
 * call notfication function for established sessions.
 * skip closed/closing sessions if the sessions were never
 *
 * Skip session with pending acks.
 */
void session_do_watch(struct session *session, enum dp_session_hook hook);

#endif /* SESSION_WATCH_H */
