/*
 * Copyright (c) 2017-2019,2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_AUTO_ATTACH_H
#define NPF_AUTO_ATTACH_H

/**
 * @brief API for auto attaching when adding rules to groups
 *
 * This is the API which adds or removes rules from groups, but
 * also allows automatically attaching to an attach point on first
 * rule in the group, and automatically detaching when last rule is
 * removed. It can be used for rule classes where the user does
 * not separately control the attach point, and it can be worked out
 * from the name of the group.
 *
 * Rule classes which currently auto attach are: dnat, snat, qos
 * and custom-timeout. The API can be called for all classes, but
 * if the class does not support it them only the rule will be added
 * to the group, and not auto-attach is performed.
 */

#include <stdint.h>

#include "npf/config/npf_rule_group.h"


/**
 * Add a rule to a rule group and automatically attach if supported
 *
 * The group is created if it does not yet exist.
 *
 * For supported classes, the group is automatically attached to
 * an attach point on first rule in the group.
 *
 * See also: npf_config_rule_add().
 *
 * @param group_class The class of the group.
 * @param group The name of the group
 * @param index The location that the rule should be added to the group.
 *              If this is 0, then it indicates an unordered group and
 *              the rules will be added in alphabetical order.
 * @param rule This is a string holding the rule to be added. This string
 *             will be copied.
 *
 * @return Returns 0 on successfully addition, or negative errno on failure.
 * @note if a rule already exists at the index, then it is replaced. If index
 * is 0, it will replaced a rule if the string passed in is identical.
 *
 */
int npf_cfg_auto_attach_rule_add(enum npf_rule_class group_class,
				 const char *group, uint32_t index,
				 const char *rule);

/**
 * Delete a rule from a rule group and automatically detach if supported
 *
 * The group is deleted if it has no rules in it.
 *
 * For supported classes, the group is automatically detached from
 * an attach point on last rule in the group being removed.
 *
 * See also: npf_config_rule_delete().
 *
 * @param group_class The class of the group.
 * @param group The name of the group
 * @param index The location of the rule to be delete from the group.
 *              If this is 0, then it indicates an unordered group and
 *              the rule will be deleted if the rule string matches.
 * @param rule This is a string holding the rule to be deleted. This is
 *             only needed if index is 0, and will be used to delete a
 *             rule which has the identical string.
 *
 * @return Returns 0 on successfully deletion, or negative errno on failure.
 * Note the return will be -ENOENT if the entry is not found.
 */
int npf_cfg_auto_attach_rule_delete(enum npf_rule_class group_class,
				    const char *group, uint32_t index,
				    const char *rule);

#endif /* NPF_AUTO_ATTACH_H */
