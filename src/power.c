/*-
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 * Copyright (c) 2017,2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <urcu/uatomic.h>

#include "compiler.h"
#include "json_writer.h"
#include "power.h"
#include "urcu.h"
#include "util.h"

/* pre-defined power profiles */
static struct power_profile pm_profiles[] __hot_data = {
	/* name          thresh min     max */
	{ "balanced",	 100,	10,	250  },	/* default */
	{ "low-latency", 1000,	20,	20   },
	{ "power-save",	 10,	10,	1000 },
};

static struct power_profile *cur_pm __hot_data = pm_profiles;

static void show_power_mode(FILE *f)
{
	json_writer_t *wr = jsonw_new(f);

	jsonw_name(wr, "mode");
	jsonw_start_object(wr);
	jsonw_string_field(wr, "name", cur_pm->name);
	jsonw_uint_field(wr, "idle_thresh", cur_pm->idle_thresh);
	jsonw_uint_field(wr, "min_sleep", cur_pm->min_sleep);
	jsonw_uint_field(wr, "max_sleep", cur_pm->max_sleep);
	jsonw_end_object(wr);
	jsonw_destroy(&wr);
}

static void change_power_mode(struct power_profile *pm)
{
	struct power_profile *old = rcu_xchg_pointer(&cur_pm, pm);

	/* unsafe to call defer_rcu with rcu read lock held. */
	dp_rcu_read_unlock();

	if (!strcmp(old->name, "custom"))
		defer_rcu(free, old);

	dp_rcu_read_lock();
}


const struct power_profile *get_current_pm(void)
{
	return rcu_dereference(cur_pm);
}

int cmd_power_show(FILE *f, int argc, char **argv)
{
	--argc, ++argv;
	if (argc == 0) {
		show_power_mode(f);
		return 0;
	}
	fprintf(f, "usage: mode\n");
	return -1;
}

int cmd_power_cfg(FILE *f, int argc, char **argv)
{
	unsigned int i;

	--argc, ++argv;
	if (argc == 0) {
		return -1;
	}

	if (strcmp(argv[0], "custom") == 0) {
		if (argc != 4) {
			fprintf(f, "custom wrong number of args\n");
			return -1;
		}

		struct power_profile *pm = zmalloc_aligned(sizeof(*pm));
		if (!pm) {
			fprintf(f, "custom out of memory\n");
			return -1;
		}

		pm->name = "custom";
		pm->idle_thresh = strtoul(argv[1], NULL, 0);
		pm->min_sleep = strtoul(argv[2], NULL, 0);
		pm->max_sleep = strtoul(argv[3], NULL, 0);

		change_power_mode(pm);
		return 0;
	}

	for (i = 0; i < ARRAY_SIZE(pm_profiles); i++) {
		struct power_profile *pm = pm_profiles + i;

		if (!strcmp(argv[0], pm->name)) {
			change_power_mode(pm);
			return 0;
		}
	}

	fprintf(f, "unknown power profile %s\n", argv[0]);
	return -1;
}
