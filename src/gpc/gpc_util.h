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
 * Return the gpc action-type string.
 *
 * @param type The numeric gpc action type
 * @return Returns a string pointer
 */
const char *gpc_get_action_type_str(uint32_t action);

/**
 * Return the gpc counter-format string.
 *
 * @param type The numeric gpc counter-format type
 * @return Returns a string pointer
 */
const char *gpc_get_cntr_format_str(uint32_t format);

/**
 * Return the gpc feature type string.
 *
 * @param type The numeric gpc feature type
 * @return Returns a string pointer
 */
const char *gpc_get_feature_type_str(uint32_t type);

/**
 * Return the gpc match-type string.
 *
 * @param type The numeric gpc match type
 * @return Returns a string pointer
 */
const char *gpc_get_match_type_str(uint32_t match);

/**
 * Return the gpc packet-colour string.
 *
 * @param type The numeric gpc counter-format type
 * @return Returns a string pointer
 */
const char *gpc_get_pkt_colour_str(uint32_t colour);

/**
 * Return the gpc packet-decision string.
 *
 * @param type The numeric gpc packet decision value
 * @return Returns a string pointer
 */
const char *gpc_get_pkt_decision_str(uint32_t decision);

/**
 * Return the gpc policer-awareness string.
 *
 * @param type The numeric gpc policer awareness value
 * @return Returns a string pointer
 */
const char *gpc_get_policer_awareness_str(uint32_t awareness);

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

/**
 * Return the gpc feature type based upon a feature string
 *
 * @param str The string to convert into a feature type
 * @return Returns a gpc feature, or 0 for unknown feature
 */
uint32_t gpc_feature_str_to_type(const char *str);

/**
 * Return the gpc table location value based upon a location string
 *
 * @param str The string to convert into a location value
 * @return Returns a gpc location, or 0 for unknown location
 */
uint32_t gpc_table_location_str_to_value(const char *str);

/**
 * Return the gpc traffic-type value based upon a traffic-type string
 *
 * @param str The string to convert into a traffic-type value
 * @return Returns a gpc traffic-type, or 0 for unknown traffic-type
 */
uint32_t gpc_traffic_type_str_to_value(const char *str);

#endif /* GPC_UTIL_H */
