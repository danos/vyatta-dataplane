/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_RULE_GROUP_H
#define NPF_RULE_GROUP_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief API for handling groups of rules
 *
 * This is the API to handle the groups of rules which are used by the NPF
 * code. It allows adding rules to a group, removing rules from a group,
 * and walking a group executing a function.
 *
 * As different uses of NPF require different sets of rules, each group
 * of rules has a class. This allows different classes to have groups with
 * the same names as other classes. Only users of the same class need to
 * ensure that their names do not clash with other using that class.
 *
 * Users of rule groups can register to be notified of changes to the
 * group. This is, for example, to allow firewall rules to be rebuilt.
 */

struct pmf_rule;

/**
 * Identifies the class of the groups of rules. This allows the same name
 * to be used for a group, as long as the class is different.
 *
 * @note: NPF_RULE_CLASS_*_GROUP are global resources and hold unordered rules.
 */
enum npf_rule_class {
	NPF_RULE_CLASS_PORT_GROUP,
	NPF_RULE_CLASS_ICMP_GROUP,
	NPF_RULE_CLASS_ICMPV6_GROUP,
	NPF_RULE_CLASS_ACL,
	NPF_RULE_CLASS_FW,
	NPF_RULE_CLASS_PBR,
	NPF_RULE_CLASS_DNAT,
	NPF_RULE_CLASS_SNAT,
	NPF_RULE_CLASS_NAT64,
	NPF_RULE_CLASS_NAT46,
	NPF_RULE_CLASS_QOS,
	NPF_RULE_CLASS_IPSEC,
	NPF_RULE_CLASS_CUSTOM_TIMEOUT,
	NPF_RULE_CLASS_SESSION_LIMITER,
	NPF_RULE_CLASS_APP_FW,
	NPF_RULE_CLASS_DSCP_GROUP,
	NPF_RULE_CLASS_PROTOCOL_GROUP,
	NPF_RULE_CLASS_ACTION_GROUP,
	NPF_RULE_CLASS_APPLICATION,
	NPF_RULE_CLASS_NPTV6_IN,
	NPF_RULE_CLASS_NPTV6_OUT,
	NPF_RULE_CLASS_COUNT	/** must be last entry */
};

/**
 * A type to name a rule group
 */
struct npf_rlgrp_key {
	enum npf_rule_class	rgk_class;
	const char		*rgk_name;
};

/**
 * Initialise the rule group code.
 *
 * This should be called a single time, before any other APIs in this file
 * are called.
 */
void npf_rule_group_init(void);

/**
 * Add a rule to a rule group.
 *
 * The group is created if it does not yet exist.
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
int npf_cfg_rule_add(enum npf_rule_class group_class, const char *group,
		     uint32_t index, const char *rule);

/**
 * Delete a rule from a rule group.
 *
 * The group is deleted if it has no rules in it.
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
int npf_cfg_rule_delete(enum npf_rule_class group_class, const char *group,
			uint32_t index, const char *rule);

/**
 * Delete a group and all rules in the group.
 *
 * @param group_class The class of the group.
 * @param group The name of the group
 *
 * @return Returns 0 on successfully deletion, or negative errno on failure.
 * Note the return will be -ENOENT if the group is not found.
 */
int npf_cfg_group_delete(enum npf_rule_class group_class, const char *group);

/**
 * Delete all groups and all rules in the group.
 *
 * @return Returns 0 on successfully deletion of groups, or negative errno
 * on failure.
 * Note that it does not delete users of a group, so group configuration will
 * still remain if there are users.
 */
int npf_cfg_all_group_delete(void);

/**
 * Count number of rules in a rule group.
 *
 * @param group_class The class of the group.
 * @param group The name of the group
 *
 * @return Returns the number of rules in the group. If a group does not
 * exist or class is invalid 0 will be returned, indicating there are no
 * rules.
 */
size_t npf_cfg_rule_count(enum npf_rule_class group_class, const char *group);

/**
 * Event type informed via notifications.
 */
enum npf_cfg_rule_group_event_type {
	NPF_EVENT_GROUP_CREATE,
	NPF_EVENT_GROUP_DELETE,
	NPF_EVENT_GROUP_RULE_ADD,
	NPF_EVENT_GROUP_RULE_CHANGE,
	NPF_EVENT_GROUP_RULE_DELETE,
	NPF_EVENT_GROUP_RULE_COUNT /** must be last entry */
};

/**
 * Structure passed into the notification calls.
 */
struct npf_cfg_rule_group_event {
	enum npf_cfg_rule_group_event_type event_type;
	enum npf_rule_class group_class;
	const char *group;
	uint32_t index;
		/* valid for NPF_EVENT_GROUP_RULE_* */
	const char *old_rule;
		/* valid for NPF_EVENT_GROUP_RULE_DELETE or _CHANGE */
	const char *new_rule;
		/* valid for NPF_EVENT_GROUP_RULE_ADD or _CHANGE */
	struct pmf_rule *parsed;
};

/**
 * Type for function passed in as a parameter in calls to
 * npf_cfg_rule_group_reg_user()
 */
typedef void (*npf_cfg_rule_group_event_cb)(void *param,
	      struct npf_cfg_rule_group_event *event);

/**
 * Register as a user of a group and be notified of events
 *
 * @param group_class The class of the group.
 * @param group The name of the group
 * @param param This is a parameter to be passed to the function event_cb.
 *              It is also passed in to npf_cfg_rule_group_dereg_user() to
 *              release registration.
 * @param event_cb This is a function to be called when an event occurs.
 *                 It is passed in param and a pointer to an
 *                 "struct npf_cfg_rule_group_event". If the function is NULL
 *                 then no notifications will be performed.
 * @return Returns 0 on successfully registering, or negative errno on failure.
 *
 * @note It is possible to register multiple times with the same "param".
 * Each registration will get invoked on an event occurring. If registering
 * with the same "param" more than once, then deregister the same
 * number of times to stop all invocations.
 */
int npf_cfg_rule_group_reg_user(enum npf_rule_class group_class,
				const char *group, void *param,
				npf_cfg_rule_group_event_cb event_cb);

/**
 * Cancel registration as a user of a group and not be notified of events
 *
 * @param group_class The class of the group.
 * @param group The name of the group
 * @param param This must be the value of param passed into
 *		 the call to npf_cfg_rule_group_reg_user() when registering.
 * @return Returns 0 on successfully deregistering, or negative errno on
 *         failure.
 */
int npf_cfg_rule_group_dereg_user(enum npf_rule_class group_class,
				  const char *group, void *param);

/**
 * Holds information relating to a rule, and is passed to the callback
 * function walker_cb() when used with npf_cfg_rule_group_walk().
 */
struct npf_cfg_rule_walk_state {
	enum npf_rule_class group_class;
	const char *group;
	uint32_t index;
	const char *rule;
	struct pmf_rule *parsed;
};

/**
 * Type for function passed in as a parameter in calls to
 * npf_cfg_rule_group_walk() and npf_cfg_rule_group_walk_all()
 */
typedef bool (*npf_cfg_rule_group_walker_cb)(void *param,
	      struct npf_cfg_rule_walk_state *state);

/**
 * Walk over the rules of a group, calling a function for each rule
 *
 * @param group_class The class of the group.
 * @param group The name of the group
 * @param param This is passed into the walker_cb() function.
 * @param walker_cb This function is called back. It is also passed in
 *	a @p state parameter, which is information on the entry
 *	The function should return "true" to continue to the next entry,
 *	or "false" to end the walk of entries.
 */
void npf_cfg_rule_group_walk(enum npf_rule_class group_class, const char *group,
			     void *param,
			     npf_cfg_rule_group_walker_cb walker_cb);

/**
 * Walk over the all groups, calling a function for each rule
 *
 * @param param This is passed into the walker_cb() function.
 * @param walker_cb This function is called back. It is also passed in
 *	a @p state parameter, which is information on the entry
 *	The function should return "true" to continue to the next entry,
 *	or "false" to end the walk of entries.
 */
void npf_cfg_rule_group_walk_all(void *param,
				 npf_cfg_rule_group_walker_cb walker_cb);

/**
 * Get the name associated with a rule class
 *
 * @param group_class The class of the group to find its name
 * @return Returns the name of the class - NULL will be returned
 *         if an invalid type is passed in.
 */
const char *npf_get_rule_class_name(enum npf_rule_class group_class);

/**
 * Get the rule class associated with a given name
 *
 * @param name The name to look up
 * @param type A pointer to a class which will be filled in with
 *        the enum value on success.
 *
 * @return Returns 0 on success and a negative errno on failure
 */
int npf_get_rule_class(const char *name, enum npf_rule_class *group_class);

#endif /* NPF_RULE_GROUP_H */
