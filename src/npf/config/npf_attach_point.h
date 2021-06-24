/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_ATTACH_POINT_H
#define NPF_ATTACH_POINT_H

/**
 * @brief API for assigning rule groups to attach points
 *
 * This is the API to handle attaching a group of rules that are used by
 * the NPF code to a point that the rules should be executed. It allows
 * adding the group to an attach point, removing them and walking
 * the attach points executing a function on each group of rules.
 *
 * When attaching rules, the ruleset type to use is specified.
 * This allows multiple types of rulesets on a given attach point -
 * for different rule use or direction (e.g. FW in, NAT out, local, QoS).
 * Even though some types may only make sense at certain attach points
 * (e.g. interface versus global), currently all can be configured.
 *
 * Note that attaching a group can be done prior to creating a group and
 * adding rules to it.  The only ordering imposed is that a group must
 * have been set-up before activation, or otherwise either there will
 * be no group applied or an incomplete group of rules applied.
 *
 * To allow different types of attach points, there is a type associated
 * with the name of an attach point.  Only users of the same type need to
 * ensure that their names do not clash with others using that type.
 * *
 * Currently the types are:
 *
 * NPF_ATTACH_TYPE_INTERFACE
 *
 * This is for attaching rules to an interface, and the name should be
 * an interface name
 *
 * NPF_ATTACH_TYPE_GLOBAL
 *
 * This is for rules that are attached on a global basis (i.e. may be run
 * for every packet). Currently it should take as a name the empty string
 * (other values are for future use).
 *
 * NPF_ATTACH_TYPE_QOS
 *
 * This is used for attaching to a QoS point.  Its name is specific to the
 * QoS code, but should uniquely identify the point at which it is attached.
 *
 * NPF_ATTACH_TYPE_VRF
 *
 * This is for attaching rules to a VRF id, and the name should be
 * the id associated wth the VRF.
 *
 * NPF_ATTACH_TYPE_ZONE
 *
 * This is for attaching rules to a zone pairing, and the name should be of
 * the form "FROM_ZONE>TO_ZONE".
 *
 * NPF_ATTACH_TYPE_ALL
 *
 * This is used to indicate that there is no associated attach type. It
 * should be used for attach types used in matching rules (see below),
 * and should never be registered for. It is also used to request actions
 * on all attach types.
 */

/**
 * Identifies the type of the attach. This allows the same name
 * to be used for an attach point, as long as the type is different.
 */
enum npf_attach_type {
	NPF_ATTACH_TYPE_ALL,
	NPF_ATTACH_TYPE_INTERFACE,
	NPF_ATTACH_TYPE_GLOBAL,
	NPF_ATTACH_TYPE_QOS,
	NPF_ATTACH_TYPE_VRF,
	NPF_ATTACH_TYPE_ZONE,
	NPF_ATTACH_TYPE_COUNT	/** This must be the last value */
};

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>

#include "npf/config/npf_rule_group.h"
#include "npf/config/npf_ruleset_type.h"

struct npf_config;

/**
 * A type to name an attach point
 */
struct npf_attpt_key {
	enum npf_attach_type	apk_type;
	const char		*apk_point;
};

/**
 * An incomplete type for a group in a ruleset attached to a point
 */
struct npf_attpt_group;
/**
 * An incomplete type for an installed attach point.
 */
struct npf_attpt_item;
/**
 * An incomplete type for a ruleset attached to a point
 */
struct npf_attpt_rlset;

/**
 * Initialise the attach point code.
 *
 * This should be called a single time, before any other APIs in this file
 * are called.
 */
void npf_attach_point_init(void);

/**
 * This is a function relating to the data context stored on the attach
 * point which could be called passing in the context for an action to
 * be performed on the attach point (e.g. allocating or freeing and
 * storing at the attach point).
 */
typedef int (npf_attpt_item_fn_ctx)(struct npf_config **npf_conf, bool alloc);

/**
 * Place a rule-group at an attach point
 *
 * This will mean that the rules will be executed at that attach point
 * at a location appropriate for the ruleset. Note that the rule-groups of
 * the same class will be executed in the order added.
 *
 * @param attach_type The type of the attach point (e.g. interface) that
 *                    the sets of rules should be associated with.
 * @param attach_point The name of the attach point (e.g. interface name).
 * @param ruleset_type Identifies the ruleset type which are being attached
 *                     (e.g. firewall in, NAT out, etc.)
 * @param group_class The class of the rule-group that is being attached.
 * @param group The name of the rule-group within the class.
 *
 * @return Returns 0 on successfully attachment, or negative errno on failure.
 */
int npf_cfg_attach_group(enum npf_attach_type attach_type,
			 const char *attach_point,
			 enum npf_ruleset_type ruleset_type,
			 enum npf_rule_class group_class, const char *group);

/**
 * Remove a rule-group from an attach point
 *
 * @param attach_type The type of the attach point (e.g. interface).
 * @param attach_point The name of the attach point (e.g. interface name).
 * @param ruleset_type Identifies the rule-set type which is being removed
 *                     (e.g. firewall in, NAT out, etc.)
 * @param group_class The class of the rule-group that is being removed.
 * @param group The name of the rule-group within the class.
 *
 * @return Returns 0 on successfully removal, or negative errno on failure.
 */
int npf_cfg_detach_group(enum npf_attach_type attach_type,
			 const char *attach_point,
			 enum npf_ruleset_type ruleset_type,
			 enum npf_rule_class group_class, const char *group);

/**
 * Types of event sent
 */
enum npf_attpt_ev_type {
	/* The following pass no additional data */
	NPF_ATTPT_EV_UP,
	NPF_ATTPT_EV_DOWN,
	/* The following pass an rlset */
	NPF_ATTPT_EV_RLSET_ADD,
	NPF_ATTPT_EV_RLSET_DEL,
	/* The following pass a group */
	NPF_ATTPT_EV_GRP_ADD,
	NPF_ATTPT_EV_GRP_DEL,
	/* The following pass a pointer to a ruleset type */
	NPF_ATTPT_EV_RLSET_ADD_COMMIT,
	NPF_ATTPT_EV_RLSET_DEL_COMMIT,
};

/**
 * Type for the handler function registered via npf_attpt_listen().
 */
typedef void (npf_attpt_ev_cb)(
	enum npf_attpt_ev_type event, struct npf_attpt_item *ap, void *data);

int npf_attpt_ev_listen(enum npf_attach_type type, uint32_t events,
			npf_attpt_ev_cb *fn);

void npf_attpt_ev_notify(enum npf_attpt_ev_type event,
	struct npf_attpt_item *ap, void *data);

/**
 * Delete all groups from all attach points.
 *
 * @return Returns 0 on successfully deletion, or negative errno on failure.
 * Note that it does not delete registered users. It will call
 * npf_cfg_detach_group() for each entry, so that the expected events
 * are invoked.
 */
int npf_cfg_detach_all(void);

/**
 * Return the attach point state
 *
 * @param handle A pointer to the attach point item
 * @return True if UP, false if down
 */
bool
npf_attpt_item_is_up(const struct npf_attpt_item *handle);

/**
 * Access the key for an attach point
 *
 * @param handle A pointer to the attach point item
 * @return A reference to the key for this attach point.
 */
const struct npf_attpt_key *
npf_attpt_item_key(const struct npf_attpt_item *handle);

/**
 * Return the context data saved when an attach point was set to UP
 *
 * @param ap The attach point item
 * @return The pointer to the context data saved when the attach point went
 *         up, or NULL if the attach point is down.
 */
void *npf_attpt_item_up_data_context(const struct npf_attpt_item *ap);

/**
 * Return the context function saved when an attach point was set to UP
 *
 * @param ap The attach point item
 * @return The pointer to the context fn when the attach point went up,
 *         or NULL if the attach point is down.
 */
npf_attpt_item_fn_ctx *npf_attpt_item_up_fn_context(
		const struct npf_attpt_item *ap);

/**
 * Set the state of an attach point to up. It can now have configuration
 * applied to it.
 *
 * @param attach_type The type of the attach point (e.g. interface) that
 *                    the sets of rules should be associated with.
 * @param attach_point The name of the attach point (e.g. interface name).
 * @param context An arbitrary pointer associated with the attach point.
 * @param npf_attpt_item_fn A function associated with the attach point.
 *
 * @return Returns 0 on successfully set, or negative errno on failure.
 */
int npf_attpt_item_set_up(enum npf_attach_type attach_type,
			  const char *attach_point,
			  void *context,
			  npf_attpt_item_fn_ctx npf_attpt_item_fn);

/**
 * Set the state of an attach point to down. Any configuration applied
 * should be removed.
 *
 * @param attach_type The type of the attach point (e.g. interface) that
 *                    the sets of rules should be associated with.
 * @param attach_point The name of the attach point (e.g. interface name).
 *
 * @return Returns 0 on successfully set, or negative errno on failure.
 */
int npf_attpt_item_set_down(enum npf_attach_type attach_type,
			    const char *attach_point);

/**
 * Find an attach point item; irrespective of state.
 *
 * @param attach_type The type of the attach point (e.g. interface).
 * @param attach_point The name of the attach point (e.g. interface name).
 * @param ap_p The attach point item found, if any.
 *	 It is only filled in on success.
 * @return Returns 0 on successfully finding the attach point, or
 *         a negative errno on failure.
 */
int npf_attpt_item_find_any(enum npf_attach_type attach_type,
			    const char *attach_point,
			    struct npf_attpt_item **ap_p);

/**
 * Find an attach point item; but only if in the UP state.
 *
 * @param attach_type The type of the attach point (e.g. interface).
 * @param attach_point The name of the attach point (e.g. interface name).
 * @param ap_p The attach point item found, if any.
 *	 It is only filled in on success.
 * @return Returns 0 on successfully finding the attach point, or
 *         a negative errno on failure.
 */
int npf_attpt_item_find_up(enum npf_attach_type attach_type,
			   const char *attach_point,
			   struct npf_attpt_item **ap_p);

/**
 * Type for function passed in as a parameter in calls to the various
 * npf_attpt_walk_items() variants.
 */
typedef bool (npf_attpt_walk_items_cb)(struct npf_attpt_item *ap, void *ctx);

/**
 * Walks all attach points (irrespective of state), calling a function for each.
 *
 * @param fn The function to call
 * @param ctx A context pointer to supply to the called function
 */
void npf_attpt_item_walk_all(npf_attpt_walk_items_cb *fn, void *ctx);

/**
 * Walks attach points which are up, calling a function for each one
 *
 * @param fn The function to call
 * @param ctx A context pointer to supply to the called function
 */
void npf_attpt_item_walk_up(npf_attpt_walk_items_cb *fn, void *ctx);

/**
 * Walks attach points of a specified type which are up,
 * calling a function for each one
 *
 * @param type The type of attach point of interest
 * @param fn The function to call
 * @param ctx A context pointer to supply to the called function
 */
void npf_attpt_item_walk_type(
	enum npf_attach_type type, npf_attpt_walk_items_cb *fn, void *ctx);

/**
 * Return the type of an attached ruleset
 *
 * @param ars The ruleset attached to a point
 * @return The type of the ruleset
 */
enum npf_ruleset_type
npf_attpt_rlset_type(const struct npf_attpt_rlset *ars);


/**
 * Lookup a ruleset associated with an attachment point
 *
 * @param ap The attach point item.
 * @param ruleset_type Identifies the rule-set type which is being looked-up
 *                     (e.g. firewall in, NAT out, etc.)
 * @param ars_p The requested ruleset.
 * @return Returns 0 on successfully finding the ruleset type, or
 *         a negative errno on failure.
 */
int npf_attpt_rlset_find(struct npf_attpt_item *ap,
			 enum npf_ruleset_type ruleset_type,
			 struct npf_attpt_rlset **ars_p);

/**
 * Type for function passed in as a parameter in calls to
 * npf_attpt_walk_rlsets().
 */
typedef bool (npf_attpt_walk_rlsets_cb)(struct npf_attpt_rlset *ars, void *ctx);

/**
 * Walks all rulesets under an attach point, calling a function for each one
 *
 * @param ap This is the attach point to be walked.
 * @fn A function called for each ruleset.
 *     It should return true to continue walking and false to stop.
 *
 * @param ctx A context pointer passed into the function provided.
 */
void npf_attpt_walk_rlsets(
	struct npf_attpt_item *ap, npf_attpt_walk_rlsets_cb *fn, void *ctx);

/**
 * Return the ruleset a group is attached to
 *
 * @param handle The attached group
 * @return The ruleset the group is attached to
 */
struct npf_attpt_rlset *
npf_attpt_group_rlset(const struct npf_attpt_group *handle);

/**
 * Access the key for an attached group
 *
 * @param handle Handle provided by attached ruleset group walker callback.
 * @return A reference to the key for this attached ruleset group.
 */
const struct npf_rlgrp_key *
npf_attpt_group_key(const struct npf_attpt_group *handle);

/**
 * Access the direction mask for an attached group
 *
 * @param handle Handle provided by attached ruleset group walker callback.
 * @return A reference to the key for this attached ruleset group.
 */
uint32_t
npf_attpt_group_dir_mask(const struct npf_attpt_group *handle);

/**
 * Type for function passed in as a parameter to npf_attpt_walk_rlset_grps()
 */
typedef bool (npf_attpt_walk_groups_cb)(
	const struct npf_attpt_group *rsg, void *ctx);

/**
 * Walks all groups under an attached ruleset, calling a function for each one
 *
 * @param ars The attached ruleset to be walked.
 * @fn A function called for each ruleset.
 *     It should return true to continue walking and false to stop.
 *
 * @param ctx A context pointer passed into the function provided.
 */
void npf_attpt_walk_rlset_grps(
	struct npf_attpt_rlset *ars, npf_attpt_walk_groups_cb *fn, void *ctx);

/**
 * Walks all groups under an attach point, calling a function for each one
 *
 * @param ap The attach point to be walked.
 * @param fn A function called for each ruleset.
 *     It should return true to continue walking and false to stop.
 *
 * @param ctx A context pointer passed into the function provided.
 */
void npf_attpt_walk_all_grps(
	struct npf_attpt_item *ap, npf_attpt_walk_groups_cb *fn, void *ctx);

/**
 * Get the name associated with an attach type
 *
 * @param attach_type The attach-type to find the name for
 * @return Returns the name of the attach type - NULL will be returned
 *         if an invalid type is passed in.
 */
const char *npf_get_attach_type_name(enum npf_attach_type attach_type);

/**
 * Get the attach type associated with a given name
 *
 * @param name The name to look up
 * @param type A pointer to an attach type which will be filled in with
 *        the enum value on success.
 *
 * @return Returns 0 on success and a negative errno on failure
 */
int npf_get_attach_type(const char *name, enum npf_attach_type *attach_type);

/**
 * Set and Get the extension pointer assocated with an attached ruleset
 */
bool npf_attpt_rlset_set_extend(struct npf_attpt_rlset *ars, void *extend);
void *npf_attpt_rlset_get_extend(const struct npf_attpt_rlset *ars);

/**
 * Set and Get the extension pointer assocated with an attached group
 */
bool npf_attpt_group_set_extend(struct npf_attpt_group *rsg, void *extend);
void *npf_attpt_group_get_extend(const struct npf_attpt_group *handle);

#endif /*  NPF_ATTACH_POINT_H */
