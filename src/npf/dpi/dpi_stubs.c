/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * dpi_stubs.c
 *
 * Stubs for non-DPI builds.
 *
 * See dpi.c for the equivalent full functions.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include "compiler.h"
#include "dpi.h"
#include "npf/dpi/dpi_internal.h"
#include "npf/npf_cache.h"
#include "npf/rproc/npf_rproc.h"
#include "app_cmds.h"

bool
dpi_init(void)
{
	return true;
}

void
dpi_session_flow_destroy(struct dpi_flow *flow __unused)
{
}

int
dpi_session_first_packet(struct npf_session *se __unused,
			 npf_cache_t *npc __unused,
			 struct rte_mbuf *mbuf __unused,
			 int dir __unused)
{
	return -ENOMEM;
}

uint32_t
dpi_flow_get_app_proto(struct dpi_flow *flow __unused)
{
	return DPI_APP_NA;
}

uint32_t
dpi_flow_get_app_name(struct dpi_flow *flow __unused)
{
	return DPI_APP_NA;
}

uint64_t
dpi_flow_get_app_type(struct dpi_flow *flow __unused)
{
	return 0;
}

bool
dpi_flow_get_offloaded(struct dpi_flow *flow __unused)
{
	return true;
}

bool
dpi_flow_get_error(struct dpi_flow *flow __unused)
{
	return false;
}

const struct dpi_flow_stats *
dpi_flow_get_stats(struct dpi_flow *flow __unused, bool forw __unused)
{
	return NULL;
}

uint32_t
dpi_app_name_to_id(const char *app_name __unused)
{
	return DPI_APP_NA;
}

const char *
dpi_app_id_to_name(uint32_t app_id __unused)
{
	return NULL;
}

uint32_t
dpi_app_type_name_to_id(const char *type_name __unused)
{
	return DPI_APP_NA;
}

const char *
dpi_app_type_to_name(uint32_t app_type __unused)
{
	return NULL;
}

const npf_rproc_ops_t npf_dpi_ops = {
	.ro_name   = "dpi",
	.ro_type   = NPF_RPROC_TYPE_MATCH,
	.ro_id     = NPF_RPROC_ID_DPI,
	.ro_bidir  = false,
	.ro_ctor   = NULL,
	.ro_dtor   = NULL,
	.ro_action = NULL,
	.ro_match  = NULL,
};

int dp_dpi_enable(struct ifnet *ifp __unused)
{
	return 0;
}

int dp_dpi_disable(struct ifnet *ifp __unused)
{
	return 0;
}

bool dp_dpi_is_enabled(void)
{
	return false;
}

uint32_t dp_dpi_get_app_id(struct rte_mbuf *mbuf __unused)
{
	return DPI_APP_NA;
}

void
dpi_info_json(struct dpi_flow *dpi_flow __unused, json_writer_t *json __unused)
{
}

void
dpi_info_log(struct dpi_flow *dpi_flow __unused, char *buf __unused,
	     size_t buf_len __unused)
{
}

const npf_rproc_ops_t npf_appfw_ops = {
	.ro_name   = "app-firewall",
	.ro_type   = NPF_RPROC_TYPE_ACTION,
	.ro_id     = NPF_RPROC_ID_APPFW,
	.ro_bidir  = false,
	.ro_ctor   = NULL,
	.ro_dtor   = NULL,
	.ro_action = NULL,
	.ro_match  = NULL,
};

const npf_rproc_ops_t npf_app_ops = {
	.ro_name   = "app",
	.ro_type   = NPF_RPROC_TYPE_ACTION,
	.ro_id     = NPF_RPROC_ID_APP,
	.ro_bidir  = false,
	.ro_ctor   = NULL,
	.ro_dtor   = NULL,
	.ro_action = NULL,
	.ro_match  = NULL,
};

int
cmd_app_op(FILE *f __unused, int argc __unused, char **argv __unused)
{
	return 0;
}
