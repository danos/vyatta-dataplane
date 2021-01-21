/*-
 * Copyright (c) 2020-2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Generalised Packet Classification (GPF) op-mode command handling
 */

#include <errno.h>
#include <stdio.h>
#include <urcu/list.h>
#include <vplane_log.h>
#include <vplane_debug.h>

#include "commands.h"
#include "gpc_pb.h"
#include "gpc_util.h"
#include "json_writer.h"
#include "urcu.h"
#include "util.h"

#define PREFIX_STRLEN (INET6_ADDRSTRLEN + sizeof("/128"))

/*
 * Handle: "gpc show [<feature-name> [<ifname> [<location> [<traffic-type>]]]]"
 * Output in Yang compatible JSON.
 */
static int
gpc_show(FILE *f __unused, int argc __unused, char **argv __unused)
{
	return 0;
}

int
cmd_gpc_op(FILE *f, int argc, char **argv)
{
	--argc, ++argv;		/* skip "gpc" */
	if (argc < 1) {
		fprintf(f, "usage: missing qos command\n");
		return -1;
	}

	/* Check for op-mode commands first */
	if (strcmp(argv[0], "show") == 0)
		return gpc_show(f, argc, argv);

	return 0;
}
