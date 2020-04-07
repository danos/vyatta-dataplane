/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <czmq.h>
#include <errno.h>
#include <rte_debug.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/config/npf_attach_point.h"
#include "npf/config/npf_rule_group.h"
#include "npf/config/npf_ruleset_type.h"

struct npf_attpt_group {
	struct npf_attpt_rlset	*ag_ars;
	void			*ag_extend;
	struct npf_rlgrp_key	ag_key;
	uint32_t		ag_dir_mask;
};

struct ag_handle {
	void *h;
};

struct npf_attpt_rlset {
	enum npf_ruleset_type	ars_type;
	zlistx_t		*ars_groups;	/* groups on a ruleset */
	void			*ars_extend;
};

struct ar_handle {
	void *h;
};

struct npf_attpt_item {
	struct npf_attpt_key ap_key;
	zlistx_t *ap_rulesets;			/* rulesets on attach point */
	void *ap_data_context;			/* context when in UP state */
	npf_attpt_item_fn_ctx *ap_fn_context;	/* alt. fn to alloc/free cxt */
	uint32_t ap_busy;			/* block del during event */
	bool ap_state;				/* is up or down */
};

struct npf_attpt_evh {
	struct npf_attpt_evh *evh_next;
	npf_attpt_ev_cb *evh_fn;
	uint32_t evh_events;			/* Bitmask of desired events */
};

static zhashx_t	*attach_point_hash;		/* attach point hash table */

/* All the event handlers */
static struct npf_attpt_evh *attact_point_evh[NPF_ATTACH_TYPE_COUNT];

/* Helpers for readability */
static inline bool
attach_point_valid(enum npf_attach_type attach_type, const char *attach_point)
{
	if (attach_type >= NPF_ATTACH_TYPE_COUNT)
		return false;
	if (!attach_point)
		return false;
	return true;
}

static inline bool
ruleset_valid(enum npf_ruleset_type ruleset_type)
{
	if (ruleset_type >= NPF_RS_TYPE_COUNT)
		return false;
	return true;
}

static inline bool
group_valid(enum npf_rule_class group_class, const char *group)
{
	if (group_class >= NPF_RULE_CLASS_COUNT)
		return false;
	if (!group)
		return false;
	return true;
}

/*
 * Destructor, duplicator, and compare functions for attached ruleset groups
 */

static void attached_group_destroy(void **object)
{
	struct npf_attpt_group *ag = *object;

	free((void *)ag->ag_key.rgk_name);
	ag->ag_extend = NULL;
	free(ag);
	*object = NULL;
}

static void *attached_group_dup(const void *object)
{
	const struct npf_attpt_group *ag = object;
	struct npf_attpt_group *new = malloc(sizeof(*new));

	if (new) {
		new->ag_key.rgk_class = ag->ag_key.rgk_class;
		new->ag_key.rgk_name = strdup(ag->ag_key.rgk_name);
		if (new->ag_key.rgk_name == NULL) {
			free(new);
			return NULL;
		}
		new->ag_dir_mask = ag->ag_dir_mask;
		new->ag_ars = ag->ag_ars;
		new->ag_extend = ag->ag_extend;
	}
	return new;
}

static int attached_group_compare(const void *object1, const void *object2)
{
	const struct npf_attpt_group *ag1 = object1;
	const struct npf_attpt_group *ag2 = object2;
	int class_diff = ag1->ag_key.rgk_class - ag2->ag_key.rgk_class;

	if (class_diff != 0)
		return class_diff;

	return strcmp(ag1->ag_key.rgk_name, ag2->ag_key.rgk_name);
}


/*
 * Destructor, duplicator, and compare functions for attached rulesets
 */

static void attached_ruleset_destroy(void **object)
{
	struct npf_attpt_rlset *ars = *object;

	zlistx_destroy(&ars->ars_groups);
	ars->ars_extend = NULL;
	free(ars);
	*object = NULL;
}

static void *attached_ruleset_dup(const void *object)
{
	const struct npf_attpt_rlset *ars = object;
	struct npf_attpt_rlset *new = malloc(sizeof(*new));

	if (new) {
		new->ars_type = ars->ars_type;
		new->ars_extend = ars->ars_extend;
		if (ars->ars_groups)
			new->ars_groups = zlistx_dup(ars->ars_groups);
		else {
			new->ars_groups = zlistx_new();
			if (new->ars_groups) {
				zlistx_set_destructor(new->ars_groups,
						      attached_group_destroy);
				zlistx_set_duplicator(new->ars_groups,
						      attached_group_dup);
				zlistx_set_comparator(new->ars_groups,
						      attached_group_compare);
			}
		}
		if (new->ars_groups == NULL) {
			attached_ruleset_destroy((void **) &new);
			return NULL;
		}
	}
	return new;
}

static int attached_ruleset_compare(const void *object1, const void *object2)
{
	const struct npf_attpt_rlset *ars1 = object1;
	const struct npf_attpt_rlset *ars2 = object2;

	return ars1->ars_type - ars2->ars_type;
}

static size_t attach_point_hasher(const void *key)
{
	const struct npf_attpt_key *apk = key;
	size_t key_hash = apk->apk_type;
	const char *pointer = apk->apk_point;

	while (*pointer)
		key_hash = 33 * key_hash ^ *pointer++;
	return key_hash;
}

/*
 * Destructor, duplicator, and compare functions for attach point keys
 */

static void attach_point_key_destroy(void **object)
{
	struct npf_attpt_key *apk = *object;

	free((void *)apk->apk_point);
	free(apk);
	*object = NULL;
}

static void *attach_point_key_dup(const void *object)
{
	const struct npf_attpt_key *apk = object;
	struct npf_attpt_key *new = malloc(sizeof(*new));

	if (new) {
		new->apk_type = apk->apk_type;
		new->apk_point = strdup(apk->apk_point);
		if (new->apk_point == NULL) {
			free(new);
			return NULL;
		}
	}
	return new;
}

static int attach_point_key_compare(const void *object1, const void *object2)
{
	const struct npf_attpt_key *apk1 = object1;
	const struct npf_attpt_key *apk2 = object2;
	int type_diff = apk1->apk_type - apk2->apk_type;

	return type_diff ? type_diff :
		strcmp(apk1->apk_point, apk2->apk_point);
}


/*
 * Destructor, duplicator, and compare functions for attach point items
 */

static void attach_point_item_destroy(void **object)
{
	struct npf_attpt_item *ap = *object;

	zlistx_destroy(&ap->ap_rulesets);
	free((char *)ap->ap_key.apk_point);
	free(ap);
	*object = NULL;
}

static void *attach_point_item_dup(const void *object)
{
	const struct npf_attpt_item *ap = object;
	struct npf_attpt_item *new = malloc(sizeof(*new));

	if (new) {
		if (ap) {
			new->ap_key.apk_type = ap->ap_key.apk_type;
			new->ap_key.apk_point = strdup(ap->ap_key.apk_point);
			new->ap_rulesets = zlistx_dup(ap->ap_rulesets);
			new->ap_data_context = ap->ap_data_context;
			new->ap_fn_context = ap->ap_fn_context;
			new->ap_state = ap->ap_state;
		} else {
			new->ap_key.apk_type = NPF_ATTACH_TYPE_COUNT;
			new->ap_key.apk_point = NULL;
			new->ap_rulesets = zlistx_new();
			if (new->ap_rulesets) {
				zlistx_set_destructor(new->ap_rulesets,
						      attached_ruleset_destroy);
				zlistx_set_duplicator(new->ap_rulesets,
						      attached_ruleset_dup);
				zlistx_set_comparator(new->ap_rulesets,
						      attached_ruleset_compare);
			}

			new->ap_data_context = NULL;
			new->ap_fn_context = NULL;
			new->ap_state = false;
		}
		if (new->ap_rulesets == NULL) {
			attach_point_item_destroy((void **) &new);
			return NULL;
		}
		new->ap_busy = 0;
	}

	return new;
}

void npf_attach_point_init(void)
{
	/* Create list */
	attach_point_hash = zhashx_new();

	if (attach_point_hash == NULL)
		rte_panic("NPF cannot init attach point hash\n");

	zhashx_set_key_hasher(attach_point_hash, attach_point_hasher);
	zhashx_set_key_destructor(attach_point_hash, attach_point_key_destroy);
	zhashx_set_key_duplicator(attach_point_hash, attach_point_key_dup);
	zhashx_set_key_comparator(attach_point_hash, attach_point_key_compare);
	zhashx_set_destructor(attach_point_hash, attach_point_item_destroy);
	zhashx_set_duplicator(attach_point_hash, attach_point_item_dup);
}

/*
 * Notify about an event on attach point.
 */

/*
 * Find the attach point, creating it if not already present.
 * Notify about its creation.
 */
static struct npf_attpt_item *
attach_point_find_andor_create(enum npf_attach_type attach_type,
			       const char *attach_point, bool create)
{
	struct npf_attpt_key ap_match = {
		.apk_type = attach_type,
		.apk_point = attach_point
	};

	struct npf_attpt_item *ap = zhashx_lookup(attach_point_hash, &ap_match);
	if (ap)
		return ap;

	if (!create)
		return NULL;

	if (zhashx_insert(attach_point_hash, &ap_match, NULL) == -1)
		return NULL;

	/* Ensure that the item has a copy of the key */
	ap = zhashx_lookup(attach_point_hash, &ap_match);
	if (!ap)
		return NULL;

	ap->ap_key.apk_type = attach_type;
	ap->ap_key.apk_point = strdup(attach_point);
	if (!ap->ap_key.apk_point) {
		zhashx_delete(attach_point_hash, &ap_match);
		return NULL;
	}

	return ap;
}

static struct npf_attpt_item *
attach_point_find_or_create(enum npf_attach_type attach_type,
			    const char *attach_point)
{
	return attach_point_find_andor_create(attach_type, attach_point, true);
}

static struct npf_attpt_item *
attach_point_find(enum npf_attach_type attach_type, const char *attach_point)
{
	return attach_point_find_andor_create(attach_type, attach_point, false);
}

const struct npf_attpt_key *
npf_attpt_item_key(const struct npf_attpt_item *ap)
{
	return &ap->ap_key;
}

static size_t
attach_point_rls_count(const struct npf_attpt_item *ap)
{
	return zlistx_size(ap->ap_rulesets);
}

/*
 * Determine if an attach point is deletable, i.e. there are no
 * users / clients / rulesets remaining.
 */
static bool
attach_point_deletable(struct npf_attpt_item *ap)
{
	if (attach_point_rls_count(ap))
		return false;
	if (ap->ap_busy)
		return false;
	if (ap->ap_state)
		return false;

	return true;
}

/*
 * Delete an attach point, notify about the deletion.
 */
static void
attach_point_delete(enum npf_attach_type attach_type, const char *attach_point)
{
	struct npf_attpt_key ap_match = {
		.apk_type = attach_type,
		.apk_point = attach_point
	};

	/* First acquire the attach point */
	struct npf_attpt_item *ap
		= attach_point_find(attach_type, attach_point);
	if (!ap)
		return;

	zhashx_delete(attach_point_hash, &ap_match);
}


/*
 * Find a ruleset attached to an attach point, creating it if not already
 * present.  Notify about its creation.
 */
static struct npf_attpt_rlset *
attached_ruleset_find_andor_create(struct npf_attpt_item *ap,
				   enum npf_ruleset_type ruleset_type,
				   struct ar_handle *arh, bool create)
{
	struct npf_attpt_rlset ar_match = {
		.ars_type = ruleset_type
	};

	void *ars_handle = arh->h = zlistx_find(ap->ap_rulesets, &ar_match);
	if (!ars_handle && !create)
		return NULL;

	struct npf_attpt_rlset *ars = zlistx_handle_item(ars_handle);
	if (ars)
		return ars;

	if (!create)
		return NULL;

	ars_handle = arh->h = zlistx_add_end(ap->ap_rulesets, &ar_match);

	ars = zlistx_handle_item(ars_handle);

	if (ars)
		npf_attpt_ev_notify(NPF_ATTPT_EV_RLSET_ADD, ap, ars);

	return ars;
}

static struct npf_attpt_rlset *
attached_ruleset_find_or_create(struct npf_attpt_item *ap,
				enum npf_ruleset_type ruleset_type,
				struct ar_handle *arh)
{
	return attached_ruleset_find_andor_create(ap, ruleset_type, arh, true);
}

static struct npf_attpt_rlset *
attached_ruleset_find(struct npf_attpt_item *ap,
		      enum npf_ruleset_type ruleset_type,
		      struct ar_handle *arh)
{
	return attached_ruleset_find_andor_create(ap, ruleset_type, arh, false);
}

/*
 * Determine if an attached ruleset is deletable.
 */
static bool
attached_ruleset_deletable(struct npf_attpt_rlset *ars)
{
	if (zlistx_size(ars->ars_groups))
		return false;

	return true;
}

/*
 * Delete an attached ruleset, notify about the deletion.
 */
static void
attached_ruleset_delete(struct npf_attpt_item *ap,
			struct npf_attpt_rlset *ars,
			struct ar_handle arh)
{
	npf_attpt_ev_notify(NPF_ATTPT_EV_RLSET_DEL, ap, ars);

	zlistx_delete(ap->ap_rulesets, arh.h);
}


/*
 * Find a group within a ruleset attached to an attach point,
 * creating it if not already present.  Notify about its creation.
 */
static struct npf_attpt_group *
attached_group_find_andor_create(struct npf_attpt_item *ap,
				 struct npf_attpt_rlset *ars,
				 const struct npf_rlgrp_key *rgk,
				 struct ag_handle *agh, uint32_t dir_mask)
{
	struct npf_attpt_group ag_match = {
		.ag_key = *rgk,
	};

	void *ag_handle = agh->h = zlistx_find(ars->ars_groups, &ag_match);
	if (!ag_handle && !ap)
		return NULL;

	struct npf_attpt_group *agr = zlistx_handle_item(ag_handle);
	if (agr)
		return agr;

	/* Need ap to signal the create */
	if (!ap)
		return NULL;

	ag_handle = agh->h = zlistx_add_end(ars->ars_groups, &ag_match);

	if (!ag_handle)
		return NULL;

	agr = zlistx_handle_item(ag_handle);

	agr->ag_dir_mask = dir_mask;
	agr->ag_ars = ars;

	npf_attpt_ev_notify(NPF_ATTPT_EV_GRP_ADD, ap, agr);

	return agr;
}

static struct npf_attpt_group *
attached_group_find_or_create(struct npf_attpt_item *ap,
			      struct npf_attpt_rlset *ars,
			      const struct npf_rlgrp_key *rgk,
			      uint32_t dir_mask)
{
	struct ag_handle agh;
	return attached_group_find_andor_create(ap, ars, rgk, &agh, dir_mask);
}

static struct npf_attpt_group *
attached_group_find(struct npf_attpt_rlset *ars,
		    const struct npf_rlgrp_key *rgk,
		    struct ag_handle *agh)
{
	return attached_group_find_andor_create(NULL, ars, rgk, agh, 0);
}

/*
 * Delete an attached group, notify about the deletion.
 */
static void
attached_group_delete(struct npf_attpt_item *ap,
		      struct npf_attpt_group *agr, struct ag_handle agh)
{
	struct npf_attpt_rlset *ars = agr->ag_ars;

	npf_attpt_ev_notify(NPF_ATTPT_EV_GRP_DEL, ap, agr);

	zlistx_delete(ars->ars_groups, agh.h);
}


/*
 * Add a group to, and remove one from an attach point.
 */

static int
npf_cfg_attach_masked_group(
	enum npf_attach_type attach_type, const char *attach_point,
	enum npf_ruleset_type ruleset_type,
	enum npf_rule_class group_class, const char *group,
	uint32_t dir_mask)
{
	if (!attach_point_valid(attach_type, attach_point) ||
	    !ruleset_valid(ruleset_type) ||
	    !group_valid(group_class, group))
		return -EINVAL;

	/* First acquire the attach point */
	struct npf_attpt_item *ap
		= attach_point_find_or_create(attach_type, attach_point);
	if (!ap)
		return -ENOMEM;

	/* Now acquire the attached ruleset */
	struct ar_handle arh;
	struct npf_attpt_rlset *ars
		= attached_ruleset_find_or_create(ap, ruleset_type, &arh);
	if (!ars)
		goto ar_fail;

	/* Finally acquire the attached group */
	struct npf_rlgrp_key rg_key = {
		.rgk_class = group_class,
		.rgk_name = group,
	};
	struct npf_attpt_group *agr
		= attached_group_find_or_create(ap, ars, &rg_key, dir_mask);
	if (agr)
		return 0;

	/* Delete this attached ruleset if no longer in use */
	if (attached_ruleset_deletable(ars))
		attached_ruleset_delete(ap, ars, arh);

ar_fail:
	/* Delete this attach point if no longer in use */
	if (attach_point_deletable(ap))
		attach_point_delete(attach_type, attach_point);

	return -ENOMEM;
}

int npf_cfg_attach_group(enum npf_attach_type attach_type,
			 const char *attach_point,
			 enum npf_ruleset_type ruleset_type,
			 enum npf_rule_class group_class, const char *group)
{
	return npf_cfg_attach_masked_group(
			attach_type, attach_point, ruleset_type,
			group_class, group, 0);
}

int npf_cfg_attach_dir_group(
	enum npf_attach_type attach_type, const char *attach_point,
	enum npf_ruleset_type ruleset_type,
	enum npf_rule_class group_class, const char *group,
	uint32_t dir)
{
	if (!dir)
		return -EINVAL;
	if (dir & ~(NPF_RS_FLAG_DIR_IN|NPF_RS_FLAG_DIR_OUT))
		return -EINVAL;

	return npf_cfg_attach_masked_group(
			attach_type, attach_point, ruleset_type,
			group_class, group, ~dir);
}

int npf_cfg_detach_group(enum npf_attach_type attach_type,
			 const char *attach_point,
			 enum npf_ruleset_type ruleset_type,
			 enum npf_rule_class group_class, const char *group)
{
	if (!attach_point_valid(attach_type, attach_point) ||
	    !ruleset_valid(ruleset_type) ||
	    !group_valid(group_class, group))
		return -EINVAL;

	/* First acquire the attach point */
	struct npf_attpt_item *ap
		= attach_point_find(attach_type, attach_point);
	if (!ap)
		return -ENOENT;

	/* Now acquire the attached ruleset */
	struct ar_handle arh;
	struct npf_attpt_rlset *ars
		= attached_ruleset_find(ap, ruleset_type, &arh);
	if (!ars)
		return -ENOENT;

	/* Finally acquire the attached group */
	struct npf_rlgrp_key rg_key = {
		.rgk_class = group_class,
		.rgk_name = group,
	};
	struct ag_handle agh;
	struct npf_attpt_group *agr
		= attached_group_find(ars, &rg_key, &agh);
	if (!agr)
		return -ENOENT;

	attached_group_delete(ap, agr, agh);

	/* Delete this attached ruleset if no longer in use */
	if (attached_ruleset_deletable(ars))
		attached_ruleset_delete(ap, ars, arh);

	/* Delete this attach point if no longer in use */
	if (attach_point_deletable(ap))
		attach_point_delete(attach_type, attach_point);

	return 0;
}

int npf_cfg_detach_all(void)
{
	/*
	 * Note that it is not possible to delete while iterating over the
	 * hash using zhashx_first()/zhashz_next(), so we look up the keys
	 * first, and then iterate over them to delete entries.
	 */
	zlistx_t *keys = zhashx_keys(attach_point_hash);
	if (!keys)
		return -ENOMEM;

	for (const struct npf_attpt_key *apk
			= zlistx_first(keys); apk;
	     apk = zlistx_next(keys)) {

		struct npf_attpt_key ap_match = {
			.apk_type = apk->apk_type,
			.apk_point = apk->apk_point
		};
		struct npf_attpt_item *ap =
			zhashx_lookup(attach_point_hash, &ap_match);
		if (!ap)
			continue;

		for (struct npf_attpt_rlset *ars
				= zlistx_first(ap->ap_rulesets); ars;
		     ars = zlistx_next(ap->ap_rulesets)) {

			for (struct npf_attpt_group *agr
				= zlistx_first(ars->ars_groups); agr;
			     agr = zlistx_next(ars->ars_groups)) {

				struct ag_handle agh = {
					.h = zlistx_cursor(ars->ars_groups)
				};
				attached_group_delete(ap, agr, agh);
			}

			struct ar_handle arh = {
				.h = zlistx_cursor(ap->ap_rulesets)
			};
			attached_ruleset_delete(ap, ars, arh);
		}

		if (attach_point_deletable(ap))
			attach_point_delete(apk->apk_type, apk->apk_point);
	}
	zlistx_destroy(&keys);

	return 0;
}

/*
 * Set the attach point state; create / destroy as needed.
 */

bool
npf_attpt_item_is_up(const struct npf_attpt_item *ap)
{
	return ap->ap_state;
}

void *
npf_attpt_item_up_data_context(const struct npf_attpt_item *ap)
{
	return ap->ap_data_context;
}

npf_attpt_item_fn_ctx *
npf_attpt_item_up_fn_context(const struct npf_attpt_item *ap)
{
	return ap->ap_fn_context;
}

size_t
npf_attpt_item_rls_count(const struct npf_attpt_item *ap)
{
	return attach_point_rls_count(ap);
}

int
npf_attpt_item_set_up(enum npf_attach_type attach_type,
		      const char *attach_point,
		      void *up_context, npf_attpt_item_fn_ctx npf_attpt_item_fn)
{
	if (!attach_point_valid(attach_type, attach_point))
		return -EINVAL;

	struct npf_attpt_item *ap
		= attach_point_find_or_create(attach_type, attach_point);
	if (!ap)
		return -ENOMEM;

	if (ap->ap_state)
		return -EBUSY;

	ap->ap_data_context = up_context;
	ap->ap_fn_context = npf_attpt_item_fn;
	ap->ap_state = true;

	npf_attpt_ev_notify(NPF_ATTPT_EV_UP, ap, NULL);

	return 0;
}

int
npf_attpt_item_set_down(enum npf_attach_type attach_type,
			const char *attach_point)
{
	if (!attach_point_valid(attach_type, attach_point))
		return -EINVAL;

	/* First acquire the attach point */
	struct npf_attpt_item *ap
		= attach_point_find(attach_type, attach_point);
	if (!ap)
		return -ENOENT;

	/* If already down, do nothing */
	if (!ap->ap_state)
		return 0;

	npf_attpt_ev_notify(NPF_ATTPT_EV_DOWN, ap, NULL);

	ap->ap_data_context = NULL;
	ap->ap_fn_context = NULL;
	ap->ap_state = false;

	/* Delete this attach point if no longer in use */
	if (attach_point_deletable(ap))
		attach_point_delete(attach_type, attach_point);

	return 0;
}

/*
 * Find an attach point; either in up state, or irrespective of state.
 */

int
npf_attpt_item_find_any(enum npf_attach_type attach_type,
			const char *attach_point,
			struct npf_attpt_item **ap_p)
{
	if (!attach_point_valid(attach_type, attach_point))
		return -EINVAL;

	struct npf_attpt_item *ap
		= attach_point_find(attach_type, attach_point);
	if (!ap)
		return -ENOENT;

	*ap_p = ap;
	return 0;
}

int
npf_attpt_item_find_up(enum npf_attach_type attach_type,
		       const char *attach_point,
		       struct npf_attpt_item **ap_p)
{
	if (!attach_point_valid(attach_type, attach_point))
		return -EINVAL;

	struct npf_attpt_item *ap
		= attach_point_find(attach_type, attach_point);
	if (!ap)
		return -ENOENT;

	/* Ensure it is in UP state */
	if (!ap->ap_state)
		return -ENOENT;

	*ap_p = ap;
	return 0;
}

/*
 * The attach point event notification mechanism.
 */
int
npf_attpt_ev_listen(enum npf_attach_type type, uint32_t events,
		    npf_attpt_ev_cb *fn)
{
	if (type >= NPF_ATTACH_TYPE_COUNT)
		return -EINVAL;

	struct npf_attpt_evh *evh = malloc(sizeof(*evh));
	if (!evh)
		return -ENOMEM;

	evh->evh_events = events;
	evh->evh_fn = fn;

	evh->evh_next = attact_point_evh[type];
	attact_point_evh[type] = evh;

	return 0;
}

void
npf_attpt_ev_notify(enum npf_attpt_ev_type event, struct npf_attpt_item *ap,
		    void *data)
{
	const struct npf_attpt_key *apk = npf_attpt_item_key(ap);
	enum npf_attach_type ap_type = apk->apk_type;
	uint32_t ev_bit = (1 << event);

	++ap->ap_busy;
	struct npf_attpt_evh *evh = attact_point_evh[ap_type];
	for (; evh; evh = evh->evh_next) {
		if (evh->evh_events & ev_bit)
			evh->evh_fn(event, ap, data);
	}
	--ap->ap_busy;
}

static void
npf_attpt_item_walk_core(enum npf_attach_type ap_type, bool up_only,
			 npf_attpt_walk_items_cb *fn, void *ctx)
{
	struct npf_attpt_item *ap;
	const struct npf_attpt_key *apk;

	const bool one_type = (ap_type != NPF_ATTACH_TYPE_COUNT);
	for (ap = zhashx_first(attach_point_hash);
	     ap;
	     ap = zhashx_next(attach_point_hash)) {
		apk = zhashx_cursor(attach_point_hash);

		if (one_type && apk->apk_type != ap_type)
			continue;
		if (!up_only || ap->ap_state) {
			if (!(*fn)(ap, ctx))
				break;
		}
	}
}

void
npf_attpt_item_walk_all(npf_attpt_walk_items_cb *fn, void *ctx)
{
	npf_attpt_item_walk_core(NPF_ATTACH_TYPE_COUNT, false, fn, ctx);
}

void
npf_attpt_item_walk_up(npf_attpt_walk_items_cb *fn, void *ctx)
{
	npf_attpt_item_walk_core(NPF_ATTACH_TYPE_COUNT, true, fn, ctx);
}

void
npf_attpt_item_walk_type(enum npf_attach_type ap_type,
			 npf_attpt_walk_items_cb *fn, void *ctx)
{
	if (ap_type > NPF_ATTACH_TYPE_COUNT)
		return;

	npf_attpt_item_walk_core(ap_type, true, fn, ctx);
}

enum npf_ruleset_type
npf_attpt_rlset_type(const struct npf_attpt_rlset *ars)
{
	return ars->ars_type;
}

bool
npf_attpt_rlset_set_extend(struct npf_attpt_rlset *ars, void *extend)
{
	if (ars->ars_extend && extend)
		return false;

	ars->ars_extend = extend;

	return true;
}

void *
npf_attpt_rlset_get_extend(const struct npf_attpt_rlset *ars)
{
	return ars->ars_extend;
}

int npf_attpt_rlset_find(struct npf_attpt_item *ap,
			 enum npf_ruleset_type ruleset_type,
			 struct npf_attpt_rlset **ars_p)
{
	if (ruleset_type >= NPF_RS_TYPE_COUNT || !ap || !ars_p)
		return -EINVAL;

	/* Now acquire the attached ruleset */
	struct ar_handle arh;
	struct npf_attpt_rlset *ars
		= attached_ruleset_find(ap, ruleset_type, &arh);
	if (!ars)
		return -ENOENT;

	*ars_p = ars;

	return 0;
}

void npf_attpt_walk_rlsets(struct npf_attpt_item *ap,
			   npf_attpt_walk_rlsets_cb *fnp, void *ctx)
{
	struct npf_attpt_rlset *ars;
	bool ret;

	if (ap == NULL)
		return;

	ars = zlistx_first(ap->ap_rulesets);

	while (ars) {
		ret = (*fnp)(ars, ctx);
		if (!ret)
			break;

		ars = zlistx_next(ap->ap_rulesets);
	}
}

int npf_attpt_group_find(struct npf_attpt_rlset *ars,
			 enum npf_rule_class group_class, const char *group)
{
	if (!ars || !group_valid(group_class, group))
		return -EINVAL;

	/* Acquire the attached group */
	struct npf_rlgrp_key rg_key = {
		.rgk_class = group_class,
		.rgk_name = group,
	};
	struct ag_handle agh;
	struct npf_attpt_group *agr
		= attached_group_find(ars, &rg_key, &agh);
	if (!agr)
		return -ENOENT;

	return 0;
}

struct npf_attpt_rlset *
npf_attpt_group_rlset(const struct npf_attpt_group *rsg)
{
	return rsg->ag_ars;
}

const struct npf_rlgrp_key *
npf_attpt_group_key(const struct npf_attpt_group *rsg)
{
	return &rsg->ag_key;
}

bool
npf_attpt_group_set_extend(struct npf_attpt_group *rsg, void *extend)
{
	if (rsg->ag_extend && extend)
		return false;

	rsg->ag_extend = extend;

	return true;
}

void *
npf_attpt_group_get_extend(const struct npf_attpt_group *rsg)
{
	return rsg->ag_extend;
}

uint32_t
npf_attpt_group_dir_mask(const struct npf_attpt_group *rsg)
{
	return rsg->ag_dir_mask;
}

void
npf_attpt_walk_rlset_grps(struct npf_attpt_rlset *ars,
			  npf_attpt_walk_groups_cb *fn, void *ctx)
{
	struct npf_attpt_group *rsg;
	bool ret;

	if (!ars)
		return;

	rsg = zlistx_first(ars->ars_groups);

	while (rsg) {
		ret = (*fn)(rsg, ctx);
		if (!ret)
			break;

		rsg = zlistx_next(ars->ars_groups);
	}
}

void npf_attpt_walk_all_grps(struct npf_attpt_item *ap,
			     npf_attpt_walk_groups_cb *fn, void *ctx)
{
	struct npf_attpt_rlset *ars;

	if (!ap)
		return;

	ars = zlistx_first(ap->ap_rulesets);

	while (ars) {
		struct npf_attpt_group *rsg
			= zlistx_first(ars->ars_groups);

		while (rsg) {
			bool more = (*fn)(rsg, ctx);
			if (!more)
				return;

			rsg = zlistx_next(ars->ars_groups);
		}

		ars = zlistx_next(ap->ap_rulesets);
	}
}

static const char *npf_attach_type_names[NPF_ATTACH_TYPE_COUNT] = {
	[NPF_ATTACH_TYPE_ALL] = "all",
	[NPF_ATTACH_TYPE_INTERFACE] = "interface",
	[NPF_ATTACH_TYPE_GLOBAL] = "global",
	[NPF_ATTACH_TYPE_QOS] = "qos",
	[NPF_ATTACH_TYPE_VRF] = "vrf",
	[NPF_ATTACH_TYPE_ZONE] = "zone",
};

const char *npf_get_attach_type_name(enum npf_attach_type attach_type)
{
	if (attach_type >= NPF_ATTACH_TYPE_COUNT)
		return NULL;
	return npf_attach_type_names[attach_type];
}

int npf_get_attach_type(const char *name, enum npf_attach_type *attach_type)
{
	enum npf_attach_type t;

	for (t = 0; t < NPF_ATTACH_TYPE_COUNT; t++) {
		if (strcmp(name, npf_attach_type_names[t]) == 0) {
			*attach_type = t;
			return 0;
		}
	}

	return -ENOENT;
}
