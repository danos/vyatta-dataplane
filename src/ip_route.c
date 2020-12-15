/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <urcu/list.h>
#include <rte_debug.h>

#include "dp_event.h"
#include "if_var.h"
#include "ip_forward.h"
#include "ip_route.h"
#include "urcu.h"
#include "vplane_debug.h"

static struct cds_list_head rt_signal_unusable_list_head =
	CDS_LIST_HEAD_INIT(rt_signal_unusable_list_head);

struct rt_signal_unusable_client {
	const char *source;
	dp_rt_get_path_state_fn *get_state_fn;
	struct cds_list_head list_entry;
};

static void dp_rt_path_state_uninit(void)
{
	struct cds_list_head *this_entry, *next;
	struct rt_signal_unusable_client *client;

	cds_list_for_each_safe(this_entry, next,
			       &rt_signal_unusable_list_head) {
		client = cds_list_entry(this_entry,
					struct rt_signal_unusable_client,
					list_entry);
		free((char *)client->source);
		free(client);
	}
}

struct dp_event_ops rt_signal_dp_event_ops = {
	.uninit = dp_rt_path_state_uninit,
};

/*
 * Provide a function that can be used to query the path state.
 */
int dp_rt_register_path_state(const char *source,
			      dp_rt_get_path_state_fn *get_state_fn)
{
	struct rt_signal_unusable_client *client;
	static int initialised;

	cds_list_for_each_entry_rcu(client, &rt_signal_unusable_list_head,
				    list_entry) {
		if (strcmp(source, client->source) == 0)
			return -EINVAL;
	}

	client = malloc(sizeof(*client));
	if (!client)
		return -ENOMEM;

	client->source = strdup(source);
	client->get_state_fn = get_state_fn;
	if (!client->source) {
		free(client);
		return -ENOMEM;
	}
	cds_list_add_rcu(&client->list_entry, &rt_signal_unusable_list_head);

	if (!initialised) {
		initialised = true;
		dp_event_register(&rt_signal_dp_event_ops);
	}
	return 0;
}

enum dp_rt_path_state
dp_rt_signal_check_paths_state(const struct dp_rt_path_unusable_key *key)
{
	struct rt_signal_unusable_client *client;
	enum dp_rt_path_state state;

	cds_list_for_each_entry_rcu(client, &rt_signal_unusable_list_head,
				    list_entry) {
		state = client->get_state_fn(key);
		if (state == DP_RT_PATH_USABLE ||
		    state == DP_RT_PATH_UNUSABLE)
			return state;
	}

	return DP_RT_PATH_UNKNOWN;
}

static const char *dp_rt_path_state_to_str(enum dp_rt_path_state state)
{
	switch (state) {
	case DP_RT_PATH_USABLE:
		return "usable";
	case DP_RT_PATH_UNUSABLE:
		return "unusable";
	default:
		return "unknown";
	}
};


void dp_rt_signal_path_state(const char *source,
			     enum dp_rt_path_state state,
			     const struct dp_rt_path_unusable_key *key)
{
	char buf[INET6_ADDRSTRLEN];

	if (key->type == DP_RT_PATH_UNUSABLE_KEY_INTF) {
		struct ifnet *ifp;

		ifp = dp_ifnet_byifindex(key->ifindex);
		if (!ifp)
			return;

		DP_DEBUG(ROUTE, DEBUG, ROUTE,
			 "paths using if %s marked %s by %s\n",
			 ifnet_indextoname(key->ifindex),
			 dp_rt_path_state_to_str(state),
			 source);
		if_set_usability(ifp, (state == DP_RT_PATH_USABLE) ?
				       true : false);
	} else
		DP_DEBUG(ROUTE, DEBUG, ROUTE,
			 "paths using if %s, gw %s marked %s by %s\n",
			 ifnet_indextoname(key->ifindex),
			 inet_ntop(key->nexthop.type,
				   &key->nexthop.address,
				   buf, sizeof(buf)),
			 dp_rt_path_state_to_str(state),
			 source);

	if (state == DP_RT_PATH_USABLE ||
	    state == DP_RT_PATH_UNUSABLE)
		next_hop_mark_path_state(state, key);
}
