/*
 * Copyright (c) 2020 AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef DPI_USER_H
#define DPI_USER_H

#include <stdbool.h>
#include <stdint.h>

struct user_flow {
	struct dpi_engine_flow ef;	// Must be first.
	uint32_t application;
	uint32_t protocol;
	uint32_t type;
};

#define USER_FLOW_ENGINE_ID	ef.engine_id
#define USER_FLOW_STATS		ef.stats
#define USER_FLOW_UPDATE_STATS	ef.update_stats

#endif /* DPI_USER_H */
