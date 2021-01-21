/*-
 * Copyright (c) 2020-2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Generalised Packet Classification (GPF) configuration handling
 */

#include <stdint.h>
#include "gpc_util.h"
#include "protobuf/GPCConfig.pb-c.h"
#include "util.h"
#include "vplane_log.h"

/*
 * GPC enum to string mapping definitions and functions
 */

const char *gpc_feature_type_str[] = {
	[GPCCONFIG__FEATURE_TYPE__FEATURE_UNKNOWN] = "unknown",
	[GPCCONFIG__FEATURE_TYPE__QOS] = "qos",
	[GPCCONFIG__FEATURE_TYPE__ACL] = "acl",
};

const char *gpc_table_location_str[] = {
	[GPCTABLE__FEATURE_LOCATION__LOCATION_UNKNOWN] = "unknown",
	[GPCTABLE__FEATURE_LOCATION__INGRESS] = "ingress",
	[GPCTABLE__FEATURE_LOCATION__EGRESS] = "egress",
	[GPCTABLE__FEATURE_LOCATION__PUNT_PATH] = "punt-path",
};

const char *gpc_traffic_type_str[] = {
	[TRAFFIC_TYPE__TRAFFIC_UNKNOWN] = "unknown",
	[TRAFFIC_TYPE__IPV4] = "ipv4",
	[TRAFFIC_TYPE__IPV6] = "ipv6",
};


static const char *
gpc_get_str(uint32_t index, uint32_t size, const char *str_array[])
{
	if (index >= size) {
		RTE_LOG(WARNING, GPC,
			"Unexpected string index %u for str-array %p\n",
			index, str_array);
		index = 0;
	}

	return str_array[index];
}

const char *
gpc_get_feature_type_str(uint32_t type)
{
	return gpc_get_str(type, ARRAY_SIZE(gpc_feature_type_str),
			   gpc_feature_type_str);
}

const char *
gpc_get_table_location_str(uint32_t location)
{
	return gpc_get_str(location, ARRAY_SIZE(gpc_table_location_str),
			   gpc_table_location_str);
}

const char *
gpc_get_traffic_type_str(uint32_t traffic_type)
{
	return gpc_get_str(traffic_type, ARRAY_SIZE(gpc_traffic_type_str),
			   gpc_traffic_type_str);
}

