/*-
 * Copyright (c) 2020-2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Generalised Packet Classification (GPF) configuration handling
 */

#ifndef GPC_UTIL_H
#define GPC_UTIL_H

#include <stdint.h>

/**
 * Return the gpc feature type string.
 *
 * @param type The numeric gpc feature type
 * @return Returns a string pointer
 */
const char *gpc_get_feature_type_str(uint32_t type);

/**
 * Return the gpc table location string.
 *
 * @param type The numeric gpc location type
 * @return Returns a string pointer
 */
const char *gpc_get_table_location_str(uint32_t location);

/**
 * Return the gpc traffic-type string.
 *
 * @param type The numeric gpc traffic type
 * @return Returns a string pointer
 */
const char *gpc_get_traffic_type_str(uint32_t traffic_type);

#endif /* GPC_UTIL_H */
