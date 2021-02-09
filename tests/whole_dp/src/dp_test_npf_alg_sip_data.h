/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef __DP_TEST_NPF_ALG_SIP_DATA_H__
#define __DP_TEST_NPF_ALG_SIP_DATA_H__

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

#define SIP_FORW true
#define SIP_BACK false

/*
 * SIP Data Set #1
 */
#define SIPD1_SZ 6
extern const bool sipd1_dir[SIPD1_SZ];
extern const uint sipd1_rtp_index;
extern const char *sipd1[SIPD1_SZ];
extern const char *sipd1_pre_snat[SIPD1_SZ];
extern const char *sipd1_post_snat[SIPD1_SZ];
extern const char *sipd1_pre_dnat[SIPD1_SZ];
extern const char *sipd1_post_dnat[SIPD1_SZ];

char *sipd_descr(uint index, bool forw, const char *pload);
bool sipd_check_content_length(const char *pload, uint *hdr_clen,
			       uint *body_clen);

#endif /* __DP_TEST_NPF_ALG_SIP_DATA_H__ */
