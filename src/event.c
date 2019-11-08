/*-
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <bsd/sys/queue.h>
#include <czmq.h>
#include <errno.h>
#include <rte_debug.h>
#include <rte_log.h>
#include <rte_spinlock.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <zmq.h>

#include "event.h"
#include "urcu.h"
#include "vplane_log.h"

struct event {
	LIST_ENTRY(event) next;
	int		  refcnt;
	enum cont_src_en  cont_src;
	void		  *socket;
	int		  fd;
	ev_callback_t	  rdfunc;
	void		  *arg;
};

static struct {
	LIST_HEAD(, event) list;
	unsigned int list_size;
	int		   dirty;
	zmq_pollitem_t	   *items;
	struct event       **events;
} todo;

static rte_spinlock_t event_list_lock = RTE_SPINLOCK_INITIALIZER;

static void release_event(struct event *ev)
{
	if (--ev->refcnt == 0)
		free(ev);
}

/* Rebuild list for poll */
static void rebuild_poll_list(void)
{
	struct event *ev, *tev;
	unsigned int i;

	rte_spinlock_lock(&event_list_lock);
	if (!todo.dirty) {
		rte_spinlock_unlock(&event_list_lock);
		return;
	}

	for (i = 0; i < todo.list_size; i++) {
		ev = todo.events[i];
		release_event(ev);
	}

	/* Evaluate list size */
	todo.list_size = 0;

	LIST_FOREACH_SAFE(ev, &todo.list, next, tev)
		todo.list_size++;

	/*
	 * The list should never be completely empty, we would always
	 * have the sockets to the co-located vplaned.
	 */
	if (!todo.list_size)
		rte_panic("event list is empty");

	todo.items = realloc(todo.items,
			      todo.list_size * sizeof(zmq_pollitem_t));
	todo.events = realloc(todo.events,
			       todo.list_size * sizeof(struct event *));

	if ((!todo.items || !todo.events) && todo.list_size)
		rte_panic("realloc of poll lists failed\n");

	memset(todo.items, 0, todo.list_size * sizeof(zmq_pollitem_t));

	i = 0;
	LIST_FOREACH(ev, &todo.list, next) {
		zmq_pollitem_t *p = &todo.items[i];

		if (ev->socket)
			p->socket = ev->socket;
		else
			p->fd = ev->fd;

		p->events = ZMQ_POLLIN;
		ev->refcnt++;
		todo.events[i++] = ev;
	}

	todo.dirty = 0;
	rte_spinlock_unlock(&event_list_lock);
}

/*
 * Register a function to be called by get_next_event
 * when file descriptor has data available.
 */
static void register_event(int fd, void *socket, ev_callback_t rdfunc,
			   void *arg, enum cont_src_en cont_src)
{
	struct event *ev = malloc(sizeof(*ev));

	if (ev == NULL)
		rte_panic("%s(): out of memory\n", __func__);

	ev->arg = arg;
	ev->cont_src = cont_src;
	ev->fd = fd;
	ev->socket = socket;
	ev->rdfunc = rdfunc;

	rte_spinlock_lock(&event_list_lock);
	ev->refcnt = 1;
	LIST_INSERT_HEAD(&todo.list, ev, next);
	todo.dirty = 1;
	rte_spinlock_unlock(&event_list_lock);
}

void register_event_fd(int fd, ev_callback_t rdfunc, void *arg)
{
	register_event(fd, NULL, rdfunc, arg, CONT_SRC_MAIN);
}

void register_event_socket(void *socket, ev_callback_t rdfunc, void *arg)
{
	register_event(-1, socket, rdfunc, arg, CONT_SRC_MAIN);
}

void register_event_socket_src(void *socket, ev_callback_t rdfunc, void *arg,
			       enum cont_src_en cont_src)
{
	register_event(-1, socket, rdfunc, arg, cont_src);
}

static void __delete_event(struct event *ev)
{
	LIST_REMOVE(ev, next);
	todo.dirty = 1;
	release_event(ev);
}

static void delete_event(struct event *ev)
{
	rte_spinlock_lock(&event_list_lock);
	__delete_event(ev);
	rte_spinlock_unlock(&event_list_lock);
}

void unregister_event_socket(void *socket)
{
	struct event *ev, *ev2;

	rte_spinlock_lock(&event_list_lock);
	LIST_FOREACH_SAFE(ev, &todo.list, next, ev2) {
		if (ev->socket != socket)
			continue;
		__delete_event(ev);
	}
	rte_spinlock_unlock(&event_list_lock);
}

/*
 * Do a poll and wait for something to happen
 *
 * ms is timeout in microseconds.
 * cont_src_all is an optimisation.  It allows the passed in cont_src to handle
 * events aimed at another cont_src, as long as that other cont_src is ready.
 *
 *  0 means return immediately
 * -1 means wait till next event.
 */
int get_next_event(enum cont_src_en cont_src, long ms, bool cont_src_all)
{
	unsigned int i;
	int n;

	rebuild_poll_list();

	rcu_thread_offline();
	n = zmq_poll(todo.items, todo.list_size, ms * ZMQ_POLL_MSEC);
	rcu_thread_online();

	if (n < 0) {
		if (errno == EINTR || errno == EAGAIN)
			return 0;

		rte_panic("%s(): poll failed: %s\n", __func__,
			  strerror(errno));
	}

	for (i = 0; i < todo.list_size; i++) {
		struct event *ev = todo.events[i];

		/* ignore if cont_src not in state ready for event handling */
		if (!cont_src_all && (ev->cont_src != cont_src))
			continue;

		if (todo.items[i].revents & ZMQ_POLLIN) {
			if (ev->rdfunc(ev->arg) < 0) {
				RTE_LOG(NOTICE, DATAPLANE,
					"%s(): read error - ignoring future events\n",
					__func__);
				delete_event(ev);
			}

		}

	}

	return n;
}
