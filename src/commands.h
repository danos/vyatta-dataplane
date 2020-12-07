/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.
 * All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef COMMANDS_H
#define COMMANDS_H

#include <stdbool.h>
#include <stdio.h>

#include "control.h"
#include "json_writer.h"

struct ifnet;

int cmd_arp(FILE *f, int argc, char **argv);
int cmd_route(FILE *f, int argc, char **argv);
int cmd_multicast(FILE *f, int argc, char **argv);
int cmd_npf_cfg(FILE *f, int argc, char **argv);
int cmd_npf_op(FILE *f, int argc, char **argv);
int cmd_cgn(FILE *f, int argc, char **argv);
int cmd_npf_ut(FILE *f, int argc, char **argv);
int cmd_cgn_op(FILE *f, int argc, char **argv);
int cmd_cgn_ut(FILE *f, int argc, char **argv);
int cmd_nat(FILE *f, int argc, char **argv);
int cmd_nat_op(FILE *f, int argc, char **argv);
int cmd_nat_ut(FILE *f, int argc, char **argv);
int cmd_nd6(FILE *f, int argc, char **argv);
int cmd_qos_cfg(FILE *f, int argc, char **argv);
int cmd_qos_op(FILE *f, int argc, char **argv);
int cmd_ecmp(FILE *f, int argc, char **argv);
int cmd_hotplug(FILE *f, int argc, char **argv);
int cmd_pipeline(FILE *f, int argc, char **argv);
int op_pipeline(FILE *f, int argc, char **argv);
int cmd_pathmonitor(FILE *f, int argc, char **argv);
int cmd_portmonitor(FILE *f, int argc, char **argv);
int cmd_gre(FILE *f, int argc, char **argv);
int cmd_mpls(FILE *f, int argc, char **argv);
int cmd_affinity_cfg(FILE *f, int argc, char **argv);
int cmd_xconnect_cfg(FILE *f, int argc, char **argv);
int cmd_poe(FILE *f, int argc, char **argv);
int cmd_ip(FILE *f, int argc, char **argv);
int cmd_cpp_rl_op(FILE *f, int argc, char **argv);

void list_all_cmd_versions(FILE *f);

int console_cmd(char *line, char **outbuf, size_t *outsize, cmd_func_t fn,
		bool on_main);
int console_bind(enum cont_src_en cont_src);
void console_unbind(enum cont_src_en cont_src);
void console_endpoint_set(const char *endpoint);

void show_address(json_writer_t *wr, const struct ifnet *ifp);
int cmd_incomplete(FILE *f, int argc, char **argv);
int cmd_switchport(FILE *f, int argc, char **argv);

#endif
