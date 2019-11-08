/*
 * pl_plugin.c
 *
 *
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 * Copyright (c) 2017, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <rte_log.h>
#include <stdio.h>
#include <string.h>

#include "pl_internal.h"
#include "vplane_log.h"

#define PL_DLL_LOC PKGLIB_DIR"/pipeline/plugins"

void pl_load_plugins(void)
{
	/*
	 * Iterate through directory loading pipeline plugins
	 */
	DIR *dp;
	struct dirent *ep;
	dp = opendir(PL_DLL_LOC);
	if (dp != NULL)	{
		while ((ep = readdir(dp))) {
			/* restrict to .so files only */
			char *tmp = strrchr(ep->d_name, '.');
			if (!tmp)
				continue;
			if (strcmp(tmp, ".so") != 0)
				continue;

			char buf[1024];
			snprintf(buf, 1024, "%s/%s",
				 PL_DLL_LOC, ep->d_name);
			void *handle = dlopen(buf, RTLD_NOW);
			if (handle == NULL) {
				RTE_LOG(ERR, DATAPLANE,
					"failed to load pipeline plug-in: %s\n",
				       dlerror());
				continue;
			}
			RTE_LOG(INFO, DATAPLANE,
				"loaded pipeline plug-in: %s\n", buf);
		}
	} else {
		/*
		 * The directory not existing is normal so don't log
		 * an error in that case.
		 */
		if (errno != ENOENT)
			RTE_LOG(ERR, DATAPLANE,
				"error opening pipeline plug-in directory \"%s\": %s\n",
				PL_DLL_LOC, strerror(errno));
		return;
	}
	closedir(dp);
}
