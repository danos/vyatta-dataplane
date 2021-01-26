/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_RULE_GEN_H
#define NPF_RULE_GEN_H

#include <czmq.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/un.h>

#include "npf/npf.h"
#include "npf/npf_session.h"
#include "src/npf/npf_cache.h"

/* Used for building grouper */
struct npf_rule_grouper_info {
	uint8_t g_v4_match[NPC_GPR_SIZE_v4];
	uint8_t g_v4_mask[NPC_GPR_SIZE_v4];
	uint8_t g_v6_mask[NPC_GPR_SIZE_v6];
	uint8_t g_v6_match[NPC_GPR_SIZE_v6];
	sa_family_t g_family;
};

void buf_app_printf(char *buf, size_t *used_buf_len,
		    const size_t total_buf_len, const char *format, ...)
		    __attribute__ ((__format__(__printf__, 4, 5)));

int npf_parse_ip_addr(char *value, sa_family_t *fam, npf_addr_t *addr,
		      npf_netmask_t *masklen, bool *negate);

void npf_masklen_to_grouper_mask(sa_family_t fam, npf_netmask_t masklen,
			    npf_addr_t *addr_mask);

int npf_gen_ncode(zhashx_t *config_ht, void **ncode, uint32_t *size,
		  bool any_match_rprocs,
		  struct npf_rule_grouper_info *grouper_info);

int npf_process_nat_config(npf_rule_t *rl, zhashx_t *config_ht);

int npf_parse_rule_line(zhashx_t *config_ht, const char *rule_line);

void npf_get_rule_match_string(zhashx_t *config_ht, char *buf,
			       size_t *used_buf_len,
			       const size_t total_buf_len);

void npf_nat_get_map_string(zhashx_t *config_ht, char *buf,
			    size_t *used_buf_len, const size_t total_buf_len);

int npf_dscp_group_getmask(char *group_name, uint64_t *dscp_set);

#endif /* NPF_RULE_GEN_H */
