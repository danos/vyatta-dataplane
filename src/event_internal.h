/*-
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef EVENT_INTERNAL_H
#define EVENT_INTERNAL_H

#include <stdbool.h>

#include "control.h"
#include "event.h"

typedef int (*ev_callback_t)(void *arg);

void register_event_fd(int fd, ev_callback_t rdfunc, void *arg);
void unregister_event_fd(int fd);
void register_event_socket_src(void *socket, ev_callback_t rdfunc, void *arg,
			       enum cont_src_en cont_src);

int get_next_event(enum cont_src_en cont_src, long ms, bool cont_src_all);

#endif /* EVENT_INTERNAL_H */
