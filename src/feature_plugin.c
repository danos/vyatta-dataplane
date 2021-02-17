/*
 * feature_plugin.c
 *
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <rte_log.h>
#include <stdio.h>
#include <string.h>

#include "feature_plugin_internal.h"
#include "json_writer.h"
#include "pl_internal.h"
#include "urcu.h"
#include "vplane_log.h"

#define PL_DLL_LOC PKGLIB_DIR"/pipeline/plugins"
static const char *feat_plugin_dir;

struct plugin_handle {
	char *lib_name;
	char *feat_name;
	void *handle;
	struct cds_list_head  list_entry;
	struct rcu_head rcu_head;
};

static struct cds_list_head feature_plugin_list_head =
	CDS_LIST_HEAD_INIT(feature_plugin_list_head);

static void feature_load_plugin(const char *buf)
{
	int (*feature_plugin_init)(const char **name);
	int rv;
	void *handle;
	struct plugin_handle *pl_handle;

	handle = dlopen(buf, RTLD_NOW);
	if (handle == NULL) {
		RTE_LOG(ERR, DATAPLANE,
			"failed to load feature plug-in: %s\n",
			dlerror());
		return;
	}

	/* Check it has an init func */
	feature_plugin_init = dlsym(handle, "dp_feature_plugin_init");
	if (!feature_plugin_init) {
		/* Not a feature plugin library */
		dlclose(handle);
		return;
	}

	pl_handle = malloc(sizeof(*pl_handle));
	if (!pl_handle) {
		RTE_LOG(INFO, DATAPLANE,
			"Failed to load feature plug-in: %s out of memory\n",
			buf);
		dlclose(handle);
		return;
	}
	pl_handle->handle = handle;
	pl_handle->lib_name = strdup(buf);
	if (!pl_handle->lib_name) {
		RTE_LOG(INFO, DATAPLANE,
			"Failed to load feature plug-in: %s out of memory\n",
			buf);
		free(pl_handle);
		dlclose(handle);
		return;
	}

	RTE_LOG(INFO, DATAPLANE,
		"loaded feature plug-in: %s\n", buf);
	rv = feature_plugin_init((const char **)&pl_handle->feat_name);
	if (rv) {
		RTE_LOG(INFO, DATAPLANE,
			"Failed to initialised feature plug-in: %s\n", buf);
		free(pl_handle->lib_name);
		free(pl_handle);
		dlclose(handle);
		return;
	}

	RTE_LOG(INFO, DATAPLANE,
		"initialised feature plug-in: %s\n", buf);
	cds_list_add_rcu(&pl_handle->list_entry, &feature_plugin_list_head);
}

static void feature_load_plugins_internal(const char *dir)
{
	/*
	 * Iterate through directory loading pipeline plugins
	 */
	DIR *dp;
	struct dirent *ep;

	dp = opendir(dir);
	RTE_LOG(INFO, DATAPLANE, "Checking for feature plugins in %s\n",
		dir);

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
				 dir, ep->d_name);
			feature_load_plugin(buf);
		}
	} else {
		/*
		 * The directory not existing is normal so don't log
		 * an error in that case.
		 */
		if (errno != ENOENT)
			RTE_LOG(ERR, DATAPLANE,
				"error opening feature plug-in directory \"%s\": %s\n",
				dir, strerror(errno));
		return;
	}
	closedir(dp);
}

void feature_load_plugins(void)
{
	feature_load_plugins_internal(PL_DLL_LOC);
	if (feat_plugin_dir)
		feature_load_plugins_internal(feat_plugin_dir);
}

static void feature_plugin_free(struct rcu_head *head)
{
	struct plugin_handle *handle;

	handle = caa_container_of(head, struct plugin_handle, rcu_head);
	free(handle->lib_name);
	free(handle);
}

void feature_unload_plugins(void)
{
	struct plugin_handle *pl_handle;
	struct cds_list_head *this_entry, *next;
	int (*feature_plugin_cleanup)(void);
	int rv;

	cds_list_for_each_safe(this_entry, next, &feature_plugin_list_head) {
		pl_handle = cds_list_entry(this_entry,
					   struct plugin_handle,
					   list_entry);

		cds_list_del_rcu(&pl_handle->list_entry);

		feature_plugin_cleanup = dlsym(pl_handle->handle,
					       "dp_feature_plugin_cleanup");
		if (feature_plugin_cleanup) {
			rv = feature_plugin_cleanup();
			if (rv)
				RTE_LOG(INFO, DATAPLANE,
					"Failed to clean up feature plug-in: %s\n",
					pl_handle->lib_name);
			else
				RTE_LOG(INFO, DATAPLANE,
					"Cleaned up feature plug-in: %s\n",
					pl_handle->lib_name);
		}
		dp_rcu_barrier();
		dlclose(pl_handle->handle);
		call_rcu(&pl_handle->rcu_head, feature_plugin_free);
	}

	feature_unregister_all_string_op_handlers();
	feature_unregister_all_string_cfg_handlers();
}

static void cmd_feat_plugin_show(FILE *f)
{
	json_writer_t *json;
	struct plugin_handle *pl_handle;
	struct cds_list_head *this_entry, *next;

	json = jsonw_new(f);
	jsonw_pretty(json, true);

	jsonw_name(json, "feature_plugin");
	jsonw_start_array(json);

	cds_list_for_each_safe(this_entry, next, &feature_plugin_list_head) {
		pl_handle = cds_list_entry(this_entry,
					   struct plugin_handle,
					   list_entry);
		jsonw_start_object(json);
		jsonw_string_field(json, "lib", pl_handle->lib_name);
		jsonw_string_field(json, "feature_name", pl_handle->feat_name);
		pl_show_plugin_state(json, pl_handle->feat_name);
		jsonw_end_object(json);
	}

	jsonw_end_array(json);
	jsonw_destroy(&json);

}

/*
 * feat_plugin show
 */
int cmd_feat_plugin(FILE *f, int argc, char **argv)
{
	if (argc != 2)
		goto error;

	if (strcmp(argv[1], "show") == 0) {
		cmd_feat_plugin_show(f);
		return 0;
	}

error:
	fprintf(f, "Usage: feat_plugin show");
	return -1;
}

void set_feat_plugin_dir(const char *filename)
{
	feat_plugin_dir = filename;
}
