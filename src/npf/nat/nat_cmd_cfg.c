/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @file nat_cmd_cfg.c - NAT Pool config
 *
 * -----------------------------------------------
 * Pool config
 * -----------------------------------------------
 *
 * cgn-cfg pool add <pool-name>
 *   type=<type>
 *   address-range=<start>-<end>
 *   prefix=<prefix>/<length>
 *   port-range=<start>-<end>
 *   port-alloc={sequential | random}
 *   block-size=<block-size>
 *   max-blocks=<max-blocks-per-user>
 *   addr-pooling=paired
 *   addr-alloc={round-robin | sequential}
 *
 * Up to 16 address ranges and/or prefixs may be specified.
 * At least one address range or prefix MUST be specified.
 *
 * The following pool items may *not* be updated:
 *
 * type, block-size, addr-pooling, add-alloc, port-range
 *
 * cgn-cfg pool delete <pool-name>
 */

#include <errno.h>
#include <netinet/in.h>
#include <linux/if.h>

#include "commands.h"
#include "compiler.h"
#include "config.h"
#include "util.h"
#include "vplane_log.h"

#include "npf/nat/nat_pool_public.h"
#include "npf/nat/nat_cmd_cfg.h"


/*
 * nat-cfg pool ...
 */
static int nat_pool_cfg(FILE *f, int argc, char **argv)
{
	int rc = 0;

	if (argc < 3)
		goto usage;

	/* Pool */
	if (strcmp(argv[2], "add") == 0)
		rc = nat_pool_cfg_add(f, argc, argv);

	else if (strcmp(argv[2], "update") == 0)
		rc = nat_pool_cfg_add(f, argc, argv);

	else if (strcmp(argv[2], "delete") == 0)
		rc = nat_pool_cfg_delete(f, argc, argv);

	else
		goto usage;

	return rc;
usage:
	if (f)
		fprintf(f, "%s: nat-cfg pool {add|delete} ... ",
			__func__);

	return -1;
}

/*
 * nat-cfg [pool] ...
 * nat-ut  ...
 */
int cmd_nat(FILE *f, int argc, char **argv)
{
	int rc = 0;

	if (argc < 2)
		goto usage;

	if (strcmp(argv[1], "pool") == 0)
		rc = nat_pool_cfg(f, argc, argv);
	else
		goto usage;

	return rc;

usage:
	if (f)
		fprintf(f, "%s: nat-cfg {pool} {add|delete} ... ",
			__func__);

	return -1;
}

int cmd_nat_ut(FILE *f, int argc, char **argv)
{
	return cmd_nat(f, argc, argv);
}
