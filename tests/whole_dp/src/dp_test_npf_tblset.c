/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Whole dataplane tests of npf tablesets
 */
#include <libmnl/libmnl.h>
#include <linux/random.h>
#include <netinet/in.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "npf/npf.h"
#include "npf/npf_cache.h"
#include "npf/npf_rule_gen.h"
#include "npf/npf_session.h"
#include "npf/npf_ruleset.h"
#include "npf/npf_tblset.h"
#include "npf/config/npf_config.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_npf_fw_lib.h"

DP_DECL_TEST_SUITE(npf_tblset);

DP_DECL_TEST_CASE(npf_tblset, npf_tblset_case1, NULL, NULL);

#define DSET_SZ 10

static uint32_t *td[DSET_SZ] = {0};

static uint32_t id[DSET_SZ] = {0};

static uint32_t g_data[DSET_SZ] = {
	0xba5eba11,
	0xbedabb1e,
	0xb01dface,
	0xcab005e,
	0xca11ab1e,
	0xca55e77e,
	0xdeadbea7,
	0xf01dab1e,
	0xf005ba11,
	0x5ca1ab1e
};

/*
 * Tableset walk callback.  We simply check the tableset entry data with
 * g_data.
 */
static int
npf_test_tbl_walk_cb(const char *name, uint id, void *data, void *ctx)
{
	uint32_t *d = data;

	dp_test_fail_unless(*d == g_data[id],
			    "%d Expected 0x%08X found 0x%08X",
			    id, g_data[id], *d);
	return 0;
}

static void npf_test_tbl_entry_free_cb(void *data __unused)
{
	/* Nothing to do */
}

/*
 * Tests npf_tblset.c
 */
DP_START_TEST(npf_tblset_case1, test1)
{
	struct npf_tbl *nt;
	uint32_t *tmp, *entry1, *entry2;
	int rc;
	uint32_t entry1_id, entry2_id;

	/*
	 * Create a tableset with 8 entries initially.
	 */
	uint8_t tbl_id = 0;
	uint tbl_sz    = 8;
	uint tbl_sz_max = 128;
	uint tbl_entry_sz  = sizeof(uint32_t);
	uint8_t tbl_flags = TS_TBL_RESIZE;

	nt = npf_tbl_create(tbl_id, tbl_sz, tbl_sz_max, tbl_entry_sz,
			    tbl_flags);
	dp_test_fail_unless(nt, "npf_tbl_create");

	/* Set entry-free function */
	npf_tbl_set_entry_freefn(nt, npf_test_tbl_entry_free_cb);

	/* Create entry "TABLE1" */
	entry1 = npf_tbl_entry_create(nt, "TABLE1");
	dp_test_fail_unless(entry1, "npf_tbl_entry_create");

	/* Init user data */
	*entry1 = g_data[0];

	/* Insert entry into table */
	npf_tbl_entry_insert(nt, entry1, &entry1_id);
	dp_test_fail_unless(entry1_id != NPF_TBLID_NONE,
			    "npf_tbl_entry_insert");

	dp_test_fail_unless(npf_tbl_size(nt) == 1,
			    "Table size %u", npf_tbl_size(nt));

	/* Lookup by ID */
	tmp = npf_tbl_id_lookup(nt, entry1_id);
	dp_test_fail_unless(tmp == entry1, "npf_tbl_id_lookup");

	/* Lookup by name */
	tmp = npf_tbl_name_lookup(nt, "TABLE1");
	dp_test_fail_unless(tmp == entry1, "npf_tbl_name_lookup");

	/* Create duplicate entry "TABLE1" */
	entry2 = npf_tbl_entry_create(nt, "TABLE1");
	dp_test_fail_unless(entry2, "npf_tbl_entry_create");

	/* Try and insert duplicate entry into table */
	rc = npf_tbl_entry_insert(nt, entry2, &entry2_id);
	dp_test_fail_unless(rc < 0, "npf_tbl_entry_insert");

	/* Destroyed duplicate entry */
	npf_tbl_entry_destroy(entry2);

	/* Remove and destroy entry1 */
	rc = npf_tbl_entry_remove(nt, entry1);
	dp_test_fail_unless(rc == 0, "npf_tbl_entry_remove");

	/* Try and remove and destroy an entry twice */
	rc = npf_tbl_entry_remove(nt, entry1);
	dp_test_fail_unless(rc != 0, "npf_tbl_entry_remove");

	dp_test_fail_unless(npf_tbl_size(nt) == 0,
			    "Table size %u", npf_tbl_size(nt));

	/*
	 * Add multiple entries, causing a table resize
	 */
	char name[20];
	uint i;

	for (i = 0; i < ARRAY_SIZE(td); i++) {
		snprintf(name, sizeof(name), "ENTRY%d", i);

		td[i] = npf_tbl_entry_create(nt, name);
		dp_test_fail_unless(td[i], "npf_tbl_entry_create");

		*td[i] = g_data[i];

		rc = npf_tbl_entry_insert(nt, td[i], &id[i]);
		dp_test_fail_unless(rc == 0,
				    "npf_tbl_entry_insert id[%u], rc = %d",
				    i, rc);
	}

	dp_test_fail_unless(npf_tbl_size(nt) == ARRAY_SIZE(td),
			    "npf_tbl_size %u",
			    npf_tbl_size(nt));

	/*
	 * Delete then re-add an entry from the middle
	 */
	i = 2;
	rc = npf_tbl_entry_remove(nt, td[i]);
	dp_test_fail_unless(rc == 0, "npf_tbl_entry_remove");

	snprintf(name, sizeof(name), "ENTRY%d", i);

	td[i] = npf_tbl_entry_create(nt, name);
	dp_test_fail_unless(td[i], "npf_tbl_entry_create");

	*td[i] = g_data[i];

	rc = npf_tbl_entry_insert(nt, td[i], &id[i]);
	dp_test_fail_unless(rc == 0, "npf_tbl_entry_insert");


	/* Lookup by ID */
	i = 4;
	snprintf(name, sizeof(name), "ENTRY%d", i);

	tmp = npf_tbl_id_lookup(nt, id[i]);
	dp_test_fail_unless(tmp, "npf_tbl_id_lookup");

	/* Lookup by name */
	tmp = npf_tbl_name_lookup(nt, name);
	dp_test_fail_unless(tmp, "npf_tbl_name_lookup");

	/* Walk all entries */
	npf_tbl_walk(nt, npf_test_tbl_walk_cb, NULL);

	/* Destroy table with entries */
	rc = npf_tbl_destroy(nt);
	dp_test_fail_unless(!rc, "npf_tbl_destroy");

} DP_END_TEST;
