/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "compiler.h"
#include "vplane_log.h"
#include "if_var.h"
#include "json_writer.h"

#include "npf/config/gpc_cntr_query.h"
#include "npf/config/gpc_db_query.h"
#include "npf/config/pmf_att_rlgrp.h"
#include "npf/config/pmf_rule.h"
#include "npf/config/gpc_acl_cli.h"
#include "npf/config/pmf_hw.h"

/* Op-mode commands : dump internals */

void
gpc_acl_dump(FILE *fp)
{
	struct gpc_rlset *gprs;

	/* Rulesets */
	GPC_RLSET_FOREACH(gprs) {
		bool rs_in = gpc_rlset_is_ingress(gprs);
		struct ifnet *rs_ifp = gpc_rlset_get_ifp(gprs);
		bool rs_if_created = gpc_rlset_is_if_created(gprs);
		char const *ifname = gpc_rlset_get_ifname(gprs);
		uint32_t if_index = rs_ifp ? rs_ifp->if_index : 0;
		fprintf(fp, " RLS:%p: %s(%u)/%s%s%s\n",
			gprs, ifname, if_index,
			rs_in ? "In " : "Out",
			rs_ifp ? " IFP" : "",
			rs_if_created ? " IfCrt" : ""
			);
		/* Groups - i.e. TABLES */
		struct gpc_group *gprg;
		GPC_GROUP_FOREACH(gprg, gprs) {
			void *attr_rule = NULL;
			uint32_t num_rules = 0;

			if (gpc_group_get_feature(gprg) == GPC_FEAT_ACL) {
				void *earg = gpc_group_get_owner(gprg);
				attr_rule = pmf_arlg_earg_get_attr_rule(earg);
				num_rules = pmf_arlg_earg_get_rule_count(earg);
			}

			bool rg_published = gpc_group_is_published(gprg);
			bool rg_attached = gpc_group_is_attached(gprg);
			bool rg_deferred = gpc_group_is_deferred(gprg);
			bool rg_attr_rl = !!attr_rule;
			bool rg_family = gpc_group_has_family(gprg);
			bool rg_v6 = gpc_group_is_v6(gprg);
			bool rg_ll_create = gpc_group_is_ll_created(gprg);
			bool rg_ll_attach = gpc_group_is_ll_attached(gprg);
			fprintf(fp,
				"  GRP:%p(%lx): %s(%u/%x)%s%s%s%s%s%s%s\n",
				gprg, gpc_group_get_objid(gprg),
				gpc_group_get_name(gprg),
				num_rules,
				gpc_group_get_summary(gprg),
				rg_published ? " Pub" : "",
				rg_ll_create ? " LLcrt" : "",
				rg_attached ? " Att" : "",
				rg_ll_attach ? " LLatt" : "",
				rg_deferred ? " Defr" : "",
				rg_attr_rl ? " GAttr" : "",
				rg_family ? rg_v6 ? " v6" : " v4" : ""
				);
			struct gpc_cntg *cntg = gpc_group_get_cntg(gprg);
			struct gpc_cntr *cntr;
			GPC_CNTR_FOREACH(cntr, cntg) {
				bool ct_published = gpc_cntr_is_published(cntr);
				if (!ct_published)
					continue;
				bool ct_ll_create
					= gpc_cntr_is_ll_created(cntr);
				bool ct_cnt_packet = gpc_cntr_pkt_enabled(cntr);
				bool ct_cnt_byte = gpc_cntr_byt_enabled(cntr);
				fprintf(fp, "   CT:%p(%lx): %s%s%s%s%s\n",
					cntr, gpc_cntr_get_objid(cntr),
					gpc_cntr_get_name(cntr),
					ct_published ? " Pub" : "",
					ct_ll_create ? " LLcrt" : "",
					ct_cnt_packet ? " Pkt" : "",
					ct_cnt_byte ? " Byte" : ""
					);
				uint64_t val_pkt = -1;
				uint64_t val_byt = -1;
				pmf_hw_counter_read(cntr, &val_pkt, &val_byt);
				fprintf(fp, "      %s(%lu/%lx)) %s(%lu/%lx)\n",
					ct_cnt_packet ? "Pkt" : "-",
					(unsigned long)val_pkt,
					(unsigned long)val_pkt,
					ct_cnt_byte ? "Byte" : "-",
					(unsigned long)val_byt,
					(unsigned long)val_byt
					);
			}
			/* Rules - i.e. ENTRIES */
			struct gpc_rule *gprl;
			GPC_RULE_FOREACH(gprl, gprg) {
				bool rl_published = gpc_rule_is_published(gprl);
				bool rl_ll_create
					= gpc_rule_is_ll_created(gprl);
				fprintf(fp, "   RL:%p(%lx): %u(%x)%s%s\n",
					gprl, gpc_rule_get_objid(gprl),
					gpc_rule_get_index(gprl),
					gpc_rule_get_rule(gprl)->pp_summary,
					rl_published ? " Pub" : "",
					rl_ll_create ? " LLcrt" : ""
					);
			}
		}
	}
}

/* Op-mode commands : show counters */

static void
gpc_acl_show_cntr_ruleset(json_writer_t *json, struct gpc_rlset *gprs)
{
	bool rs_in = gpc_rlset_is_ingress(gprs);

	jsonw_string_field(json, "interface", gpc_rlset_get_ifname(gprs));
	jsonw_string_field(json, "direction", rs_in ? "in" : "out");
}

static void
gpc_acl_show_hw_cntr(json_writer_t *json, struct gpc_cntr *cntr)
{
	if (!gpc_cntr_is_ll_created(cntr))
		return;

	bool ct_cnt_packet = gpc_cntr_pkt_enabled(cntr);
	bool ct_cnt_byte = gpc_cntr_byt_enabled(cntr);

	uint64_t val_pkt = -1;
	uint64_t val_byt = -1;
	bool ok = pmf_hw_counter_read(cntr, &val_pkt, &val_byt);
	if (!ok)
		return;

	jsonw_name(json, "hw");
	jsonw_start_object(json);

	if (ct_cnt_packet)
		jsonw_uint_field(json, "pkts", val_pkt);
	if (ct_cnt_byte)
		jsonw_uint_field(json, "bytes", val_byt);

	jsonw_end_object(json);
}

static void
gpc_acl_show_cntr(json_writer_t *json, struct gpc_cntr *cntr)
{
	if (!gpc_cntr_is_published(cntr))
		return;

	bool ct_cnt_packet = gpc_cntr_pkt_enabled(cntr);
	bool ct_cnt_byte = gpc_cntr_byt_enabled(cntr);

	jsonw_start_object(json);

	jsonw_string_field(json, "name", gpc_cntr_get_name(cntr));
	jsonw_bool_field(json, "cnt-pkts", ct_cnt_packet);
	jsonw_bool_field(json, "cnt-bytes", ct_cnt_byte);

	gpc_acl_show_hw_cntr(json, cntr);

	jsonw_end_object(json);
}

int
gpc_acl_cmd_show_counters(FILE *fp, char const *ifname, int dir,
			   char const *rgname)
{
	json_writer_t *json = jsonw_new(fp);
	if (!json) {
		RTE_LOG(ERR, DATAPLANE, "failed to create json stream\n");
		return -ENOMEM;
	}

	/* Enforce filter heirarchy */
	if (!ifname)
		dir = 0;
	if (!dir)
		rgname = NULL;

	jsonw_pretty(json, true);

	/* Rulesets */
	struct gpc_rlset *gprs;
	jsonw_name(json, "rulesets");
	jsonw_start_array(json);
	GPC_RLSET_FOREACH(gprs) {
		/* Skip rulesets w/o an interface */
		if (!gpc_rlset_get_ifp(gprs))
			continue;
		/* Filter on interface & direction */
		if (ifname && strcmp(ifname, gpc_rlset_get_ifname(gprs)))
			continue;
		if (dir < 0 && !gpc_rlset_is_ingress(gprs))
			continue;
		if (dir > 0 && gpc_rlset_is_ingress(gprs))
			continue;

		jsonw_start_object(json);
		gpc_acl_show_cntr_ruleset(json, gprs);

		/* Groups - i.e. TABLES */
		struct gpc_group *gprg;
		jsonw_name(json, "groups");
		jsonw_start_array(json);
		GPC_GROUP_FOREACH(gprg, gprs) {
			if (gpc_group_get_feature(gprg) != GPC_FEAT_ACL)
				continue;

			/* Filter on group name */
			if (rgname && strcmp(rgname, gpc_group_get_name(gprg)))
				continue;

			jsonw_start_object(json);

			jsonw_string_field(json, "name",
					   gpc_group_get_name(gprg));

			struct gpc_cntg *cntg = gpc_group_get_cntg(gprg);

			struct gpc_cntr *cntr;
			jsonw_name(json, "counters");
			jsonw_start_array(json);
			GPC_CNTR_FOREACH(cntr, cntg)
				gpc_acl_show_cntr(json, cntr);
			jsonw_end_array(json);

			jsonw_end_object(json);
		}
		jsonw_end_array(json);

		jsonw_end_object(json);
	}
	jsonw_end_array(json);

	jsonw_destroy(&json);

	return 0;
}
