/*-
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <fal_plugin.h>
#include <rte_log.h>
#include "compiler.h"

#define LOG(l, t, ...)						\
	rte_log(RTE_LOG_ ## l,					\
		RTE_LOGTYPE_USER1, # t ": " __VA_ARGS__)

#define DEBUG(...)						\
	do {							\
		if (dp_test_debug_get() == 2)			\
			LOG(DEBUG, FAL_TEST, __VA_ARGS__);	\
	} while (0)

#define INFO(...) LOG(INFO, FAL_TEST,  __VA_ARGS__)
#define ERROR(...) LOG(ERR, FAL_TEST, __VA_ARGS__)

__FOR_EXPORT
int fal_plugin_mirror_session_create(uint32_t attr_count,
			     const struct fal_attribute_t *attr_list,
			     fal_object_t *obj)
{
	INFO("To be implemented %s\n", __func__);
	return 0;
}

__FOR_EXPORT
int fal_plugin_mirror_session_delete(fal_object_t obj)
{

	INFO("To be implemented %s\n", __func__);
	return 0;
}

__FOR_EXPORT
int fal_plugin_mirror_session_set_attr(fal_object_t obj,
				 const struct fal_attribute_t *attr)
{
	INFO("To be implemented %s\n", __func__);
	return 0;
}

__FOR_EXPORT
int fal_plugin_mirror_session_get_attr(fal_object_t obj,
				       uint32_t attr_count,
				       struct fal_attribute_t *attr_list)
{
	INFO("To be implemented %s\n", __func__);
	return 0;
}
