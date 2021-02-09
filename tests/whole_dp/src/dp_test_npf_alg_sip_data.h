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

/*
 * SIP Data Set #2
 */
#define SIPD2_SZ 6
extern const bool sipd2_dir[SIPD2_SZ];
extern const uint sipd2_rtp_index;
extern const char *sipd2[SIPD2_SZ];
extern const char *sipd2_pre_snat[SIPD2_SZ];
extern const char *sipd2_post_snat[SIPD2_SZ];

/*
 * SIP Data Set #3
 */
#define SIPD3_SZ 8
extern const bool sipd3_dir[SIPD3_SZ];
extern const uint sipd3_rtp_early_media_index;
extern const uint sipd3_rtp_media_index;
extern const char *sipd3_pre_snat[SIPD3_SZ];
extern const char *sipd3_post_snat[SIPD3_SZ];


/*
 * SIP Data Set #4
 */
#define SIPD4_SZ 7
extern const bool sipd4_dir[SIPD4_SZ];
extern const char *sipd4_pre_dnat[SIPD4_SZ];
extern const char *sipd4_post_dnat[SIPD4_SZ];


char *sipd_descr(uint index, bool forw, const char *pload);
bool sipd_check_content_length(const char *pload, uint *hdr_clen,
			       uint *body_clen);

#endif /* __DP_TEST_NPF_ALG_SIP_DATA_H__ */
