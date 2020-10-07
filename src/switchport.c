/*-
 * Copyright (c) 2018-2020, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * switchport command handling
 */

#include <stdio.h>
#include "control.h"
#include "fal.h"
#include "if_var.h"
#include <string.h>
#include "vplane_log.h"
#include <rte_log.h>
#include "commands.h"

int cmd_switchport(FILE *f, int argc, char **argv)
{
	struct ifnet *ifp;

	if (argc != 4) {
		if (f) {
			fprintf(f, "\nInvalid command : ");
			for (int i = 0; i < argc; i++)
				fprintf(f, "%s ", argv[i]);
			fprintf(f,
					"\nUsage: switchport <ifname> hw-switching <enable|disable>\n");
		}
		return -EINVAL;
	}

	ifp = dp_ifnet_byifname(argv[1]);
	if (!ifp) {
		RTE_LOG(INFO, DATAPLANE,
			"switchport command but interface missing %s\n",
			argv[1]);
		fprintf(f, "%s: failed to find %s\n", __func__, argv[1]);
		return -EINVAL;
	}

	if (!strcmp(argv[2], "hw-switching")) {
		if (!strcmp(argv[3], "enable"))
			ifp->hw_forwarding = true;
		else if (!strcmp(argv[3], "disable"))
			ifp->hw_forwarding = false;
		else
			return -EINVAL;
		if_change_features_mode(ifp,
					ifp->hw_forwarding ?
					IF_FEAT_MODE_FLAG_L2_FAL_ENABLE :
					IF_FEAT_MODE_FLAG_L2_FAL_DISABLE);
		return 0;
	}

	return -EINVAL;
}
