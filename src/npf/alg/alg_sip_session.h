/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _ALG_SIP_SESSION_H_
#define _ALG_SIP_SESSION_H_

#include <stdint.h>

struct osip_call_id;

/*
 * SIP ALG session data
 *
 * Only valid in sessions with SIP_ALG_CNTL_FLOW flag set in ALG session data
 * sa_flags.
 */
struct sip_alg_session {
	uint16_t		ss_via_port;
	uint8_t			ss_via_alen;
	uint32_t		ss_ifx;
	npf_addr_t		ss_via_addr;
	int			ss_call_id_count;
	struct osip_call_id	**ss_call_ids;
};

#endif /* ALG_SIP_SESSION_H */
