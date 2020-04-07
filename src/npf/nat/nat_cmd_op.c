/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @file nat_cmd_op.c - NAT Pool op-mode
 */

#include <errno.h>
#include <netinet/in.h>
#include <linux/if.h>

#include "commands.h"
#include "compiler.h"
#include "config_internal.h"
#include "util.h"
#include "vplane_log.h"

#include "npf/npf_addr.h"
#include "npf/nat/nat_pool_public.h"


/*
 * nat-op ....
 */
int cmd_nat_op(FILE *f, int argc, char **argv)
{
	int rc = 0;

	if (argc < 3)
		goto usage;

	if (!strcmp(argv[1], "show") && !strcmp(argv[2], "pool"))
		nat_pool_show(f, argc, argv);
	else
		goto usage;

	return rc;

usage:
	if (f)
		fprintf(f, "%s: nat-op show  ... ",
			__func__);

	return -1;
}
