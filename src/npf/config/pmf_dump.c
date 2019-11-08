#include <stdbool.h>
#include <arpa/inet.h>

#include "compiler.h"
#include "util.h"
#include "json_writer.h"
#include "npf/config/pmf_rule.h"
#include "npf/config/pmf_dump.h"

static char const *attr_name[] = {
	[PMAT_ETH_MAC] = "eth-mac",
	[PMAT_ETH_TYPE] = "eth-type",
	[PMAT_ETH_PCP] = "eth-pcp",
	[PMAT_IP_FAMILY] = "ip-version",
	[PMAT_IPV4_PREFIX] = "ipv4-prefix",
	[PMAT_IPV6_PREFIX] = "ipv6-prefix",
	[PMAT_IPV4_RANGE] = "ipv4-range",
	[PMAT_IP_PROTO] = "ip-proto",
	[PMAT_IP_DSCP] = "dscp",
	[PMAT_IP_TTL] = "ip-ttl",
	[PMAT_IP_FRAG] = "frag",
	[PMAT_IPV6_RH] = "ipv6-rh",
	[PMAT_L4_PORT_RANGE] = "port-range",
	[PMAT_L4_TCP_FLAGS] = "tcp-flags",
	[PMAT_L4_ICMP_V4_VALS] = "icmpv4-vals",
	[PMAT_L4_ICMP_V6_VALS] = "icmpv6-vals",
	[PMAT_GROUP_REF] = "group-ref",
	[PMAT_IP_ADDR_GROUP] = "ip-addr-group",
	[PMAT_IP_PROTO_GROUP] = "ip-proto-group",
	[PMAT_IP_DSCP_GROUP] = "dscp-group",
	[PMAT_L4_PORT_GROUP] = "port-group",
	[PMAT_L4_ICMP_V4_GROUP] = "icmpv4-group",
	[PMAT_L4_ICMP_V6_GROUP] = "icmpv6-group",
	[PMAT_MEXTENSION] = "match-rproc",
	[PMAT_HEXTENSION] = "handle-rproc",
	[PMAT_AEXTENSION] = "action-rproc",
	[PMAT_RPROC_RAW] = "rproc-raw",
};

static char const *l2field_name[] = {
	[PMF_L2F_ETH_SRC] = "ETH-SRC",
	[PMF_L2F_ETH_DST] = "ETH-DST",
	[PMF_L2F_ETH_TYPE] = "ETH-TYPE",
	[PMF_L2F_ETH_PCP] = "ETH-PCP",
	[PMF_L2F_IP_FAMILY] = "IP-FAMILY",
};
static char const *l3field_name[] = {
	[PMF_L3F_SRC] = "IP-SRC",
	[PMF_L3F_DST] = "IP-DST",
	[PMF_L3F_PROTOF] = "PROTO-FINAL",
	[PMF_L3F_PROTOB] = "PROTO-BASE",
	[PMF_L3F_PROTO] = "PROTO",
	[PMF_L3F_DSCP] = "DSCP",
	[PMF_L3F_TTL] = "TTL",
	[PMF_L3F_FRAG] = "FRAG",
	[PMF_L3F_RH] = "V6RH",
};
static char const *l4field_name[] = {
	[PMF_L4F_SRC] = "SPORT",
	[PMF_L4F_DST] = "DPORT",
	[PMF_L4F_TCP_FLAGS] = "TCPF",
	[PMF_L4F_ICMP_VALS] = "ICMP",
};

static char const *
pmf_attr_name(uint8_t tag)
{
	if (tag >= ARRAY_SIZE(attr_name))
		return "-ATTR-UNKNOWN-";
	return attr_name[tag];
}

static char const *
pmf_l2field_name(uint32_t field)
{
	if (field >= ARRAY_SIZE(l2field_name))
		return "-L2-UNKNOWN-";
	return l2field_name[field];
}

static char const *
pmf_l3field_name(uint32_t field)
{
	if (field >= ARRAY_SIZE(l3field_name))
		return "-L3-UNKNOWN-";
	return l3field_name[field];
}

static char const *
pmf_l4field_name(uint32_t field)
{
	if (field >= ARRAY_SIZE(l4field_name))
		return "-L4-UNKNOWN-";
	return l4field_name[field];
}

static void
pmf_dump_attr_type_json(json_writer_t *json, void *attr)
{
	struct pmf_attr_any *any = attr;

	jsonw_uint_field(json, "attr-type", any->pm_tag);
	jsonw_string_field(json, "attr-name", pmf_attr_name(any->pm_tag));
}

static void
pmf_dump_any_attr_json(json_writer_t *json, struct pmf_attr_any *any)
{
	jsonw_start_object(json);

	pmf_dump_attr_type_json(json, any);

	jsonw_end_object(json);
}

static void
pmf_dump_group_ref_attr_json(json_writer_t *json,
			struct pmf_attr_group_ref *grp)
{
	jsonw_start_object(json);

	pmf_dump_attr_type_json(json, grp);

	jsonw_uint_field(json, "ref-type", grp->pm_ref);
	jsonw_string_field(json, "ref-name", pmf_attr_name(grp->pm_ref));

	jsonw_string_field(json, "group-name", grp->pm_name);

	jsonw_end_object(json);
}

static void
pmf_dump_emac_attr_json(json_writer_t *json, struct pmf_attr_emac *emac)
{
	jsonw_start_object(json);

	pmf_dump_attr_type_json(json, emac);

	uint8_t *ab = &emac->pm_emac[0];
	char scratch[sizeof("01:23:45:67:89:ab")];

	snprintf(scratch, sizeof(scratch), "%02x:%02x:%02x:%02x:%02x:%02x",
			ab[0], ab[1], ab[2], ab[3], ab[4], ab[5]);

	jsonw_string_field(json, "addr", scratch);

	jsonw_end_object(json);
}

static void
pmf_dump_etype_attr_json(json_writer_t *json, struct pmf_attr_etype *etype)
{
	jsonw_start_object(json);

	pmf_dump_attr_type_json(json, etype);

	jsonw_uint_field(json, "type", etype->pm_etype);

	jsonw_end_object(json);
}

static void
pmf_dump_epcp_attr_json(json_writer_t *json, struct pmf_attr_epcp *epcp)
{
	jsonw_start_object(json);

	pmf_dump_attr_type_json(json, epcp);

	jsonw_uint_field(json, "pcp", epcp->pm_pcp);

	jsonw_end_object(json);
}

static void
pmf_dump_ipfam_attr_json(json_writer_t *json, struct pmf_attr_ip_family *fam)
{
	jsonw_start_object(json);

	pmf_dump_attr_type_json(json, fam);

	jsonw_bool_field(json, "v6", fam->pm_v6);

	jsonw_end_object(json);
}

static void
pmf_dump_v4pref_attr_json(json_writer_t *json, struct pmf_attr_v4_prefix *pref)
{
	jsonw_start_object(json);

	pmf_dump_attr_type_json(json, pref);

	jsonw_bool_field(json, "invert", pref->pm_invert);
	jsonw_uint_field(json, "plen", pref->pm_plen);

	uint8_t *by = &pref->pm_bytes[0];
	char astr[sizeof("255.255.255.255")];

	snprintf(astr, sizeof(astr), "%u.%u.%u.%u",
		by[0], by[1], by[2], by[3]);

	jsonw_string_field(json, "addr", astr);

	jsonw_end_object(json);
}

static void
pmf_dump_v6pref_attr_json(json_writer_t *json, struct pmf_attr_v6_prefix *pref)
{
	jsonw_start_object(json);

	pmf_dump_attr_type_json(json, pref);

	jsonw_bool_field(json, "invert", pref->pm_invert);
	jsonw_uint_field(json, "plen", pref->pm_plen);

	char astr[INET6_ADDRSTRLEN + 1];
	struct in6_addr in6;

	memcpy(&in6, &pref->pm_bytes[0], sizeof(pref->pm_bytes));
	if (inet_ntop(AF_INET6, &in6, astr, sizeof(astr)) == NULL)
		astr[0] = '\0';

	jsonw_string_field(json, "addr", astr);

	jsonw_end_object(json);
}

static void
pmf_dump_v4range_attr_json(json_writer_t *json, struct pmf_attr_v4_range *rng)
{
	jsonw_start_object(json);

	pmf_dump_attr_type_json(json, rng);

	uint8_t *by;
	char astr[sizeof("255.255.255.255")];

	by = &rng->pm_first[0];
	snprintf(astr, sizeof(astr), "%u.%u.%u.%u",
		by[0], by[1], by[2], by[3]);

	jsonw_string_field(json, "addr-first", astr);

	by = &rng->pm_last[0];
	snprintf(astr, sizeof(astr), "%u.%u.%u.%u",
		by[0], by[1], by[2], by[3]);

	jsonw_string_field(json, "addr-last", astr);

	jsonw_end_object(json);
}

static void
pmf_dump_proto_attr_json(json_writer_t *json, struct pmf_attr_proto *prot)
{
	jsonw_start_object(json);

	pmf_dump_attr_type_json(json, prot);

	if (prot->pm_final) {
		if (!prot->pm_unknown)
			jsonw_uint_field(json, "proto-final", prot->pm_proto);
		else
			jsonw_string_field(json, "proto-final", "unknown");
	} else if (prot->pm_base)
		jsonw_uint_field(json, "proto-base", prot->pm_proto);
	else
		jsonw_uint_field(json, "proto", prot->pm_proto);

	jsonw_end_object(json);
}

static void
pmf_dump_dscp_attr_json(json_writer_t *json, struct pmf_attr_dscp *dscp)
{
	jsonw_start_object(json);

	pmf_dump_attr_type_json(json, dscp);

	jsonw_uint_field(json, "dscp", dscp->pm_dscp);

	jsonw_end_object(json);
}

static void
pmf_dump_ttl_attr_json(json_writer_t *json, struct pmf_attr_ttl *ttl)
{
	jsonw_start_object(json);

	pmf_dump_attr_type_json(json, ttl);

	jsonw_uint_field(json, "ttl", ttl->pm_ttl);

	jsonw_end_object(json);
}

static void
pmf_dump_frag_attr_json(json_writer_t *json, struct pmf_attr_frag *frag)
{
	jsonw_start_object(json);

	pmf_dump_attr_type_json(json, frag);

	jsonw_end_object(json);
}

static void
pmf_dump_v6rh_attr_json(json_writer_t *json, struct pmf_attr_v6_rh *v6rh)
{
	jsonw_start_object(json);

	pmf_dump_attr_type_json(json, v6rh);

	jsonw_uint_field(json, "type", v6rh->pm_type);

	jsonw_end_object(json);
}

static void
pmf_dump_l4ports_attr_json(json_writer_t *json,
				struct pmf_attr_l4port_range *l4ports)
{
	jsonw_start_object(json);

	pmf_dump_attr_type_json(json, l4ports);

	jsonw_uint_field(json, "loport", l4ports->pm_loport);
	jsonw_uint_field(json, "hiport", l4ports->pm_hiport);

	jsonw_end_object(json);
}

static void
pmf_dump_tcpfl_attr_json(json_writer_t *json, struct pmf_attr_l4tcp_flags *tcp)
{
	jsonw_start_object(json);

	pmf_dump_attr_type_json(json, tcp);

	jsonw_uint_field(json, "mask", tcp->pm_mask);
	jsonw_uint_field(json, "match", tcp->pm_match);

	jsonw_end_object(json);
}

static void
pmf_dump_icmp_attr_json(json_writer_t *json, struct pmf_attr_l4icmp_vals *icmp)
{
	jsonw_start_object(json);

	pmf_dump_attr_type_json(json, icmp);

	jsonw_uint_field(json, "type", icmp->pm_type);
	jsonw_uint_field(json, "code", icmp->pm_code);

	jsonw_bool_field(json, "any_code", icmp->pm_any_code);
	jsonw_bool_field(json, "named", icmp->pm_named);

	jsonw_end_object(json);
}

static void
pmf_dump_proc_raw_attr_json(json_writer_t *json, struct pmf_proc_raw *raw)
{
	jsonw_start_object(json);

	pmf_dump_attr_type_json(json, raw);

	jsonw_uint_field(json, "id", raw->pm_id);
	jsonw_string_field(json, "name", raw->pm_name);

	uint32_t argoff = raw->pm_argoff;
	if (argoff)
		jsonw_string_field(json, "args", &raw->pm_name[argoff]);

	jsonw_end_object(json);
}

static void
pmf_dump_pext_attr_json(json_writer_t *json, struct pmf_pext_list *pext)
{
	jsonw_start_object(json);

	pmf_dump_attr_type_json(json, pext);

	jsonw_uint_field(json, "unknown", pext->pm_unknown);
	jsonw_uint_field(json, "num", pext->pm_num);

	jsonw_name(json, "procs");
	jsonw_start_array(json);

	uint32_t num_procs = pext->pm_num;
	for (uint32_t idx = 0; idx < num_procs; ++idx) {
		struct pmf_proc_any *proc = pext->pm_procs[idx].pp_any;
		switch (proc->pm_tag) {
		case PMAT_RPROC_RAW:
			pmf_dump_proc_raw_attr_json(json, (void *)proc);
			break;
		default:
			pmf_dump_any_attr_json(json, (void *)proc);
			break;
		}
	}

	jsonw_end_array(json);

	jsonw_end_object(json);
}

static void
pmf_dump_attr_json(json_writer_t *json, char const *name, void *attr)
{
	struct pmf_attr_any *any = attr;

	jsonw_name(json, name);

	switch (any->pm_tag) {
	case PMAT_ETH_MAC:
		pmf_dump_emac_attr_json(json, attr);
		return;
	case PMAT_ETH_TYPE:
		pmf_dump_etype_attr_json(json, attr);
		return;
	case PMAT_ETH_PCP:
		pmf_dump_epcp_attr_json(json, attr);
		return;
	case PMAT_IP_FAMILY:
		pmf_dump_ipfam_attr_json(json, attr);
		return;
	case PMAT_IPV4_PREFIX:
		pmf_dump_v4pref_attr_json(json, attr);
		return;
	case PMAT_IPV6_PREFIX:
		pmf_dump_v6pref_attr_json(json, attr);
		return;
	case PMAT_IPV4_RANGE:
		pmf_dump_v4range_attr_json(json, attr);
		return;
	case PMAT_IP_PROTO:
		pmf_dump_proto_attr_json(json, attr);
		return;
	case PMAT_IP_DSCP:
		pmf_dump_dscp_attr_json(json, attr);
		return;
	case PMAT_IP_TTL:
		pmf_dump_ttl_attr_json(json, attr);
		return;
	case PMAT_IP_FRAG:
		pmf_dump_frag_attr_json(json, attr);
		return;
	case PMAT_IPV6_RH:
		pmf_dump_v6rh_attr_json(json, attr);
		return;
	case PMAT_L4_PORT_RANGE:
		pmf_dump_l4ports_attr_json(json, attr);
		return;
	case PMAT_L4_TCP_FLAGS:
		pmf_dump_tcpfl_attr_json(json, attr);
		return;
	case PMAT_L4_ICMP_V4_VALS:
	case PMAT_L4_ICMP_V6_VALS:
		pmf_dump_icmp_attr_json(json, attr);
		break;
	case PMAT_GROUP_REF:
		pmf_dump_group_ref_attr_json(json, attr);
		return;
	case PMAT_IP_ADDR_GROUP:
	case PMAT_IP_PROTO_GROUP:
	case PMAT_IP_DSCP_GROUP:
	case PMAT_L4_PORT_GROUP:
	case PMAT_L4_ICMP_V4_GROUP:
	case PMAT_L4_ICMP_V6_GROUP:
		break;
	case PMAT_MEXTENSION:
	case PMAT_HEXTENSION:
	case PMAT_AEXTENSION:
		pmf_dump_pext_attr_json(json, attr);
		return;
	case PMAT_RPROC_RAW:
		pmf_dump_proc_raw_attr_json(json, attr);
		return;
	default:
		break;
	}

	pmf_dump_any_attr_json(json, any);
}

/* Generate the match sub-tree */
static void
pmf_dump_rule_match_json(struct pmf_rule *rule __unused, json_writer_t *json,
			  bool got_l2, bool got_l3, bool got_l4)
{
	jsonw_name(json, "match");
	jsonw_start_object(json);

	if (got_l2) {
		union pmf_mattr_l2 *l2m = rule->pp_match.l2;
		for (uint32_t idx = 0; idx < PMF_L2F__LEN; ++idx) {
			struct pmf_attr_any *l2attr = l2m[idx].pm_any;
			if (!l2attr)
				continue;

			pmf_dump_attr_json(json, pmf_l2field_name(idx), l2attr);
		}
	}

	if (got_l3) {
		union pmf_mattr_l3 *l3m = rule->pp_match.l3;
		for (uint32_t idx = 0; idx < PMF_L3F__LEN; ++idx) {
			struct pmf_attr_any *l3attr = l3m[idx].pm_any;
			if (!l3attr)
				continue;

			pmf_dump_attr_json(json, pmf_l3field_name(idx), l3attr);
		}
	}

	if (got_l4) {
		union pmf_mattr_l4 *l4m = rule->pp_match.l4;
		for (uint32_t idx = 0; idx < PMF_L4F__LEN; ++idx) {
			struct pmf_attr_any *l4attr = l4m[idx].pm_any;
			if (!l4attr)
				continue;

			pmf_dump_attr_json(json, pmf_l4field_name(idx), l4attr);
		}
	}

	if (rule->pp_match.extend)
		pmf_dump_attr_json(json, "mprocs", rule->pp_match.extend);

	jsonw_end_object(json);
}

/* Generate the nat sub-tree */
static void
pmf_dump_rule_nat_json(struct pmf_nat *nat, json_writer_t *json)
{
	jsonw_name(json, "nat");
	jsonw_start_object(json);

	enum pmf_nat_type nat_type = nat->pan_type;
	if (nat_type != PMN_UNSET)
		jsonw_string_field(json, "type",
			(nat_type == PMN_DNAT) ? "dnat" : "snat");

	enum pmf_value pinhole = nat->pan_pinhole;
	if (pinhole != PMV_UNSET)
		jsonw_bool_field(json, "pinhole", (pinhole == PMV_TRUE));

	enum pmf_value exclude = nat->pan_exclude;
	if (exclude != PMV_UNSET)
		jsonw_bool_field(json, "exclude", (exclude == PMV_TRUE));

	enum pmf_value masquerade = nat->pan_masquerade;
	if (masquerade != PMV_UNSET)
		jsonw_bool_field(json, "masquerade", (masquerade == PMV_TRUE));

	if (nat->pan_taddr.any)
		pmf_dump_attr_json(json, "taddr", nat->pan_taddr.any);

	if (nat->pan_tports)
		pmf_dump_attr_json(json, "tports", nat->pan_tports);

	jsonw_end_object(json);
}

void
pmf_dump_rule_json(struct pmf_rule *rule, json_writer_t *json)
{
	jsonw_start_object(json);

	/* Determine if we have match terms */
	bool got_l2 = false;
	for (uint32_t idx = 0; idx < PMF_L2F__LEN; ++idx)
		if (rule->pp_match.l2[idx].pm_any) {
			got_l2 = true;
			break;
		}

	bool got_l3 = false;
	for (uint32_t idx = 0; idx < PMF_L3F__LEN; ++idx)
		if (rule->pp_match.l3[idx].pm_any) {
			got_l3 = true;
			break;
		}

	bool got_l4 = false;
	for (uint32_t idx = 0; idx < PMF_L4F__LEN; ++idx)
		if (rule->pp_match.l4[idx].pm_any) {
			got_l4 = true;
			break;
		}

	/* Generate the match sub-tree */
	if (got_l2 || got_l3 || got_l4 || rule->pp_match.extend)
		pmf_dump_rule_match_json(rule, json, got_l2, got_l3, got_l4);

	/* Determine if we have action terms */
	bool got_fate = rule->pp_action.fate != PMV_UNSET;
	bool got_state = rule->pp_action.stateful != PMV_UNSET;
	bool got_nat = rule->pp_action.nat;
	bool got_hproc = rule->pp_action.handle;
	bool got_aproc = rule->pp_action.extend;

	/* Generate the action sub-tree */
	if (got_fate || got_state || got_nat || got_hproc || got_aproc) {
		jsonw_name(json, "action");
		jsonw_start_object(json);

		if (got_fate)
			jsonw_string_field(json, "fate",
				(rule->pp_action.fate == PMV_TRUE) ? "accept"
								   : "drop");
		if (got_state)
			jsonw_bool_field(json, "stateful",
				rule->pp_action.stateful == PMV_TRUE);

		if (got_nat)
			pmf_dump_rule_nat_json(rule->pp_action.nat, json);

		if (rule->pp_action.handle)
			pmf_dump_attr_json(json, "hprocs",
						rule->pp_action.handle);

		if (rule->pp_action.extend)
			pmf_dump_attr_json(json, "aprocs",
						rule->pp_action.extend);

		jsonw_end_object(json);
	}

	jsonw_end_object(json);
}
