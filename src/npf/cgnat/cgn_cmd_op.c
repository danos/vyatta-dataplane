/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @file cgn_cmd_op.c - CGNAT op-mode
 */

#include <errno.h>
#include <netinet/in.h>
#include <linux/if.h>

#include "commands.h"
#include "compiler.h"
#include "config_internal.h"
#include "if_var.h"
#include "util.h"
#include "vplane_log.h"
#include "dp_event.h"

#include "npf/npf_addr.h"

#include "npf/nat/nat_pool_public.h"

#include "npf/cgnat/cgn.h"
#include "npf/apm/apm.h"
#include "npf/cgnat/cgn_rc.h"
#include "npf/cgnat/cgn_if.h"
#include "npf/cgnat/cgn_policy.h"
#include "npf/cgnat/cgn_session.h"
#include "npf/cgnat/cgn_source.h"
#include "npf/cgnat/cgn_log_protobuf_zmq.h"


static void cgn_show_summary(FILE *f, int argc __unused, char **argv __unused)
{
	json_writer_t *json;

	json = jsonw_new(f);
	if (!json)
		return;

	jsonw_name(json, "summary");
	jsonw_start_object(json);

	cgn_policy_jsonw_summary(json);

	jsonw_uint_field(json, "sess_count",
			 rte_atomic32_read(&cgn_sessions_used));
	jsonw_uint_field(json, "sess2_count",
			 rte_atomic32_read(&cgn_sess2_used));
	jsonw_uint_field(json, "max_sess", cgn_sessions_max);
	jsonw_bool_field(json, "sess_table_full", cgn_session_table_full);

	jsonw_uint_field(json, "subs_table_used", cgn_source_get_used());
	jsonw_uint_field(json, "subs_table_max", cgn_source_get_max());

	jsonw_uint_field(json, "apm_table_used", apm_get_used());
	jsonw_uint_field(json, "apm_table_max", 0); /* deprecated */

	jsonw_uint_field(json, "pkts_hairpinned",
			 cgn_rc_read(CGN_DIR_OUT, CGN_HAIRPINNED));

	if (rte_atomic64_read(&cgn_sess2_ht_created) > 0) {
		jsonw_uint_field(json, "sess_ht_created",
				 rte_atomic64_read(&cgn_sess2_ht_created));
		jsonw_uint_field(json, "sess_ht_destroyed",
				 rte_atomic64_read(&cgn_sess2_ht_destroyed));
	}

	/*
	 * Also summarize select error counts.  Mosts counts will only ever
	 * increment in the outbound direction since that is when we are
	 * allocating resources.
	 */
	uint64_t count;

	count = cgn_rc_read(CGN_DIR_OUT, CGN_PCY_ENOENT);
	jsonw_uint_field(json, "nopolicy", count);

	count = cgn_rc_read(CGN_DIR_IN, CGN_SESS_ENOENT);
	jsonw_uint_field(json, "nosess", count);

	count = cgn_rc_read(CGN_DIR_OUT, CGN_PCY_BYPASS);
	jsonw_uint_field(json, "bypass", count);

	count = cgn_rc_read(CGN_DIR_IN, CGN_POOL_ENOENT);
	jsonw_uint_field(json, "nopool", count);

	count = cgn_rc_read(CGN_DIR_OUT, CGN_BUF_PROTO);
	count += cgn_rc_read(CGN_DIR_OUT, CGN_BUF_ICMP);
	jsonw_uint_field(json, "etrans", count);

	count = 0;
	count += cgn_rc_read(CGN_DIR_OUT, CGN_S1_ENOMEM);
	count += cgn_rc_read(CGN_DIR_OUT, CGN_S2_ENOMEM);
	count += cgn_rc_read(CGN_DIR_OUT, CGN_PB_ENOMEM);
	count += cgn_rc_read(CGN_DIR_OUT, CGN_APM_ENOMEM);
	count += cgn_rc_read(CGN_DIR_OUT, CGN_SRC_ENOMEM);
	jsonw_uint_field(json, "enomem", count);

	count = 0;
	count += cgn_rc_read(CGN_DIR_OUT, CGN_MBU_ENOSPC);
	count += cgn_rc_read(CGN_DIR_OUT, CGN_SRC_ENOSPC);
	count += cgn_rc_read(CGN_DIR_OUT, CGN_BLK_ENOSPC);
	count += cgn_rc_read(CGN_DIR_OUT, CGN_APM_ENOSPC);
	count += cgn_rc_read(CGN_DIR_OUT, CGN_POOL_ENOSPC);
	count += cgn_rc_read(CGN_DIR_OUT, CGN_S1_ENOSPC);
	count += cgn_rc_read(CGN_DIR_OUT, CGN_S2_ENOSPC);
	jsonw_uint_field(json, "enospc", count);

	count = 0;
	count += cgn_rc_read(CGN_DIR_OUT, CGN_S1_EEXIST);
	count += cgn_rc_read(CGN_DIR_OUT, CGN_S2_EEXIST);
	count += cgn_rc_read(CGN_DIR_OUT, CGN_SRC_ENOENT);
	jsonw_uint_field(json, "ethread", count);

	count = 0;
	count += cgn_rc_read(CGN_DIR_OUT, CGN_BUF_ENOL3);
	count += cgn_rc_read(CGN_DIR_OUT, CGN_BUF_ENOL4);
	count += cgn_rc_read(CGN_DIR_OUT, CGN_BUF_ENOMEM);
	count += cgn_rc_read(CGN_DIR_IN, CGN_BUF_ENOL3);
	count += cgn_rc_read(CGN_DIR_IN, CGN_BUF_ENOL4);
	count += cgn_rc_read(CGN_DIR_IN, CGN_BUF_ENOMEM);
	jsonw_uint_field(json, "embuf", count);

	jsonw_uint_field(json, "icmp_echoreq",
			 cgn_rc_read(CGN_DIR_IN, CGN_ICMP_ECHOREQ));

	jsonw_uint_field(json, "pcp_ok",
			 cgn_rc_read(CGN_DIR_OUT, CGN_PCP_OK));
	jsonw_uint_field(json, "pcp_err",
			 cgn_rc_read(CGN_DIR_OUT, CGN_PCP_ERR));

	jsonw_end_object(json);
	jsonw_destroy(&json);
}

/*
 * Write json for errors in one direction
 */
static void cgn_show_errors_dir(json_writer_t *json, enum cgn_dir dir,
				const char *name)
{
	uint64_t count;
	int err;

	jsonw_name(json, name);
	jsonw_start_array(json);

	for (err = 1; err <= CGN_RC_LAST; err++) {
		jsonw_start_object(json);

		count = cgn_rc_read(dir, err);
		jsonw_string_field(json, "name", cgn_rc_str(err));
		jsonw_string_field(json, "desc", cgn_rc_detail_str(err));
		jsonw_uint_field(json, "errno", err);
		jsonw_uint_field(json, "count", count);

		jsonw_end_object(json);
	}

	jsonw_end_array(json);
}

/*
 * Write json for in and out errors
 */
static void cgn_show_errors(FILE *f, int argc __unused, char **argv __unused)
{
	json_writer_t *json;

	json = jsonw_new(f);
	if (!json)
		return;

	jsonw_name(json, "errors");
	jsonw_start_object(json);

	cgn_show_errors_dir(json, CGN_DIR_OUT, "out");
	cgn_show_errors_dir(json, CGN_DIR_IN, "in");

	jsonw_end_object(json);
	jsonw_destroy(&json);
}

static void cgn_clear_errors(int argc __unused, char **argv __unused)
{
	uint err;

	for (err = 1; err <= CGN_RC_LAST; err++) {
		cgn_rc_clear(CGN_DIR_OUT, err);
		cgn_rc_clear(CGN_DIR_IN, err);
	}
}

/*
 * Unit-test specific op commands
 */
static int cgn_op_ut(FILE *f __unused, int argc, char **argv)
{
	if (argc < 3)
		return 0;

	if (!strcmp(argv[2], "gc")) {
		if (argc < 4) {
			cgn_session_gc_pass();
			cgn_source_gc_pass();
			apm_gc_pass();
		} else {
			if (!strcmp(argv[3], "session"))
				cgn_session_gc_pass();
			else if (!strcmp(argv[3], "subs"))
				cgn_source_gc_pass();
			else if (!strcmp(argv[3], "pub"))
				apm_gc_pass();
		}
	}

	return 0;
}

/*
 * cgn-op [ut] ....
 */
int cmd_cgn_op(FILE *f, int argc, char **argv)
{
	if (argc < 3)
		goto usage;

	/*
	 * Clear ...
	 */
	if (!strcmp(argv[1], "clear")) {
		if (!strcmp(argv[2], "policy"))
			cgn_policy_clear(argc, argv);

		else if (!strcmp(argv[2], "subscriber"))
			cgn_source_clear_or_update(argc, argv, true);

		else if (!strcmp(argv[2], "session"))
			cgn_session_clear(f, argc, argv);

		else if (!strcmp(argv[2], "errors"))
			cgn_clear_errors(argc, argv);

		return 0;
	}

	/*
	 * Update ...
	 */
	if (!strcmp(argv[1], "update")) {
		if (!strcmp(argv[2], "subscriber"))
			cgn_source_clear_or_update(argc, argv, false);

		else if (!strcmp(argv[2], "session"))
			cgn_session_update(f, argc, argv);

		return 0;
	}

	/*
	 * Show ...
	 */
	if (!strcmp(argv[1], "show")) {
		if (!strcmp(argv[2], "policy"))
			cgn_policy_show(f, argc, argv);

		else if (!strcmp(argv[2], "subscriber"))
			cgn_source_show(f, argc, argv);

		else if (!strcmp(argv[2], "session"))
			cgn_session_show(f, argc, argv);

		else if (!strcmp(argv[2], "apm"))
			apm_show(f, argc, argv);

		else if (!strcmp(argv[2], "errors"))
			cgn_show_errors(f, argc, argv);

		else if (!strcmp(argv[2], "summary"))
			cgn_show_summary(f, argc, argv);

		else if (!strcmp(argv[2], "zmq"))
			cgn_show_zmq(f);

		else if (!strcmp(argv[2], "interface"))
			cgn_show_interface(f, argc, argv);

		return 0;
	}

	/*
	 * List ...
	 */
	if (!strcmp(argv[1], "list")) {
		if (argc >= 4 &&
		    !strcmp(argv[2], "session") &&
		    !strcmp(argv[3], "id"))
			cgn_session_id_list(f, argc, argv);

		else if (!strcmp(argv[2], "subscribers"))
			cgn_source_list(f, argc, argv);

		else if (!strcmp(argv[2], "public"))
			apm_public_list(f, argc, argv);

		return 0;
	}

	/*
	 * Map ...
	 */
	if (!strcmp(argv[1], "map")) {
		cgn_op_session_map(f, argc, argv);
		return 0;
	}

	if (!strcmp(argv[1], "ut")) {
		cgn_op_ut(f, argc, argv);
		return 0;
	}

	return 0;

usage:
	if (f)
		fprintf(f, "%s: cgn-op {clear | show | list} ... ",
			__func__);

	return -1;
}
