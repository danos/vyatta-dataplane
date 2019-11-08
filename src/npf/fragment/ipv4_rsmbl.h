/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef IPV4_RSMBL_H
#define IPV4_RSMBL_H

#include "vrf.h"

struct vrf;

/*
 * Index into the fragment set table.  We store the last and first
 * fragments at the start, then the intermediate fragments up to the
 * max (IPV4_MAX_FRAGS_PER_SET or IPV6_MAX_FRAGS_PER_SET)
 */
enum {
	LAST_FRAG_IDX,
	FIRST_FRAG_IDX,
	FIRST_INTERMEDIATE_FRAG_IDX,
};

extern int ipv6_fragment_table_init(struct vrf *vrf);
extern void ipv6_fragment_table_uninit(struct vrf *vrf);
extern void ipv6_fragment_tables_timer_init(void);

extern int fragment_tables_init(struct vrf *vrf);
extern void fragment_tables_uninit(struct vrf *vrf);
extern void fragment_tables_timer_init(void);

#endif
