/*-
 * Copyright (c) 2018-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Communication with controller
 */
#ifndef CONTROL_H
#define CONTROL_H

#include <czmq.h>
#include "urcu.h"
#include <linux/if.h>

/* Which controller is the source of the information */
enum cont_src_en {
	CONT_SRC_MAIN, /* main vplaned for VR */
	CONT_SRC_UPLINK,  /* local vplaned for uplink */
};
#define CONT_SRC_COUNT (CONT_SRC_UPLINK + 1)

void controller_init(enum cont_src_en cont_src);
void controller_init_event_handler(enum cont_src_en cont_src);
void controller_unsubscribe(enum cont_src_en cont_src);
const char *cont_src_name(enum cont_src_en cont_src);
int controller_snapshot(enum cont_src_en cont_src);
void enable_authentication(zsock_t *socket);

zsock_t *cont_socket_create(enum cont_src_en cont_src);
zsock_t *cont_socket_get(enum cont_src_en cont_src);

unsigned int cont_src_ifindex(enum cont_src_en cont_src, int ifindex);

/* Generic command handler for console or config messages */
typedef int (*cmd_func_t)(FILE *f, int argc, char **argv);

/* Helper functions to handle interface config replay */

/*
 * Entries are identified by name
 */
struct cfg_if_list_entry {
	struct cds_list_head  le_node;
	char                  le_ifname[IFNAMSIZ];
	char                  *le_buf;
	char                  **le_argv;
	int                   le_argc;
};

struct cfg_if_list {
	struct cds_list_head  if_list;
	int                   if_list_count;
};

struct cfg_if_list *cfg_if_list_create(void);
int cfg_if_list_replay(struct cfg_if_list **cfg_list, const char *ifname,
		       cmd_func_t handler);
struct cfg_if_list_entry *
cfg_if_list_lookup(struct cfg_if_list *if_list,
				   const char *ifname);
/* 1 entry per interface, will overwrite if already present */
int cfg_if_list_add(struct cfg_if_list *if_list, const char *ifname,
					int argc, char *argv[]);
/* multiple entries per interface */
int cfg_if_list_add_multi(struct cfg_if_list *if_list, const char *ifname,
			  int argc, char *argv[]);
int cfg_if_list_bin_add(struct cfg_if_list *if_list, const char *ifname,
			char *msg, int len);
int cfg_if_list_del(struct cfg_if_list *if_list, const char *ifname);
int cfg_if_list_destroy(struct cfg_if_list **if_list);
int cfg_if_list_cache_command(struct cfg_if_list **if_list, const char *ifname,
			      int argc, char **argv);

zsock_t *cont_src_get_broker_ctrl(enum cont_src_en cont_src);
zsock_t *cont_src_get_broker_data(enum cont_src_en cont_src);
void cont_src_set_broker_ctrl(enum cont_src_en cont_src, zsock_t *sock);
void cont_src_set_broker_data(enum cont_src_en cont_src, zsock_t *sock);

void list_all_main_msg_versions(FILE *f);

#endif /* CONTROL_H */
