/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef DPI_PRIVATE_H
#define DPI_PRIVATE_H

/* Per session DPI information */
struct dpi_flow {
	struct qmdpi_flow *key;
	uint32_t app_proto;	/* L5 */
	uint32_t app_name;	/* L7 */
	uint64_t app_type;	/* Type bitfield */
	struct dpi_flow_stats stats[2];
	uint8_t wrkr_id;
	uint8_t offloaded: 1;
	uint8_t error: 1;
	uint8_t update_stats: 1;
};

#endif /* DPI_PRIVATE_H */
