/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef VHOST_H
#define VHOST_H

#include <stdio.h>

#include "json_writer.h"

struct ifnet;
struct vhost_info;

void vhost_devinfo(json_writer_t *wr, const struct ifnet *ifp);
void vhost_update_guests(struct ifnet *ifp);
int cmd_vhost(FILE *f, int argc, char **argv);
int cmd_vhost_cfg(FILE *f, int argc, char **argv);
int cmd_vhost_client(FILE *f, int argc, char **argv);
int cmd_vhost_client_cfg(FILE *f, int argc, char **argv);

void vhost_info_free(struct vhost_info *vi);
void vhost_event_init(void);
void vhost_event_handler(void);

#endif /* VHOST_H */
