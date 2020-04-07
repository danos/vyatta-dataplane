/*
 * FAL APIs for Bidirectional Forwarding Detection
 *
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef	VYATTA_DATAPLANE_FAL_BFD_H
#define	VYATTA_DATAPLANE_FAL_BFD_H

/* types defined in fal_plugin.h */
#ifndef fal_object_t
typedef uintptr_t fal_object_t;
#endif
struct fal_attribute_t;

/**
 * @brief Create BFD session.
 *
 * @param[out] bfd_session_id BFD session id
 * @param[in]  attr_count     Number of attributes
 * @param[in]  attr_list      Value of attributes
 *
 * @return 0 if operation is successful otherwise a different
 * error code is returned.
 */
int dp_fal_bfd_create_session(fal_object_t *bfd_session_id,
	uint32_t attr_count, const struct fal_attribute_t *attr_list);

/**
 * @brief Delete BFD session.
 *
 * @param[in] bfd_session_id  BFD session id
 *
 * @return 0 if operation is successful otherwise a different
 * error code is returned.
 */
int dp_fal_bfd_delete_session(fal_object_t bfd_session_id);

/**
 * @brief Set BFD session attributes.
 *
 * @param[in] bfd_session_id  BFD session id
 * @param[in] attr_count      Number of attributes
 * @param[in] attr_list       Value of attributes
 *
 * @return 0 if operation is successful otherwise a different
 * error code is returned.
 */
int dp_fal_bfd_set_session_attribute(fal_object_t bfd_session_id,
	uint32_t attr_count, const struct fal_attribute_t *attr_list);

/**
 * @brief Get BFD session attributes.
 *
 * @param[in] bfd_session_id BFD session id
 * @param[in] attr_count     Number of attributes
 * @param[inout] attr_list   Value of attribute
 *
 * @return 0 if operation is successful otherwise a different
 * error code is returned.
 */
int dp_fal_bfd_get_session_attribute(fal_object_t bfd_session_id,
	uint32_t attr_count, struct fal_attribute_t *attr_list);

/**
 * @brief Get BFD session statistics counters.
 *
 * @param[in] bfd_session_id   BFD session id
 * @param[in] num_of_counters  Number of counters in the array
 * @param[in] counter_ids      Specifies the array of counter ids
 * @param[out] counters        Array of resulting counter values.
 *
 * @return 0 on success, failure status code on error
 */
int dp_fal_bfd_get_session_stats(fal_object_t bfd_session_id,
	uint32_t num_of_counters,
	const enum fal_bfd_session_stat_t *counter_ids,
	uint64_t *counters);

/**
 * @brief Get BFD switch attributes.
 *
 * @param[in] attr_count     Number of attributes
 * @param[inout] attr_list   Value of attribute
 *
 * @return 0 if operation is successful otherwise a different
 * error code is returned.
 */
int dp_fal_bfd_get_switch_attrs(uint32_t attr_count,
	struct fal_attribute_t *attr_list);

/**
 * @brief Set BFD switch attributes.
 *
 * @param[in] attr       Value of attribute
 *
 * @return 0 if operation is successful otherwise a different
 * error code is returned.
 */
int dp_fal_bfd_set_switch_attr(const struct fal_attribute_t *attr);

#endif /* VYATTA_DATAPLANE_FAL_BFD_H */
