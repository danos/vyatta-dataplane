/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <string.h>

#include <sys/queue.h>		/* TAILQ macros */
#include <rte_debug.h>

#include "compiler.h"
#include "vplane_log.h"

#include "npf/config/gpc_cntr_query.h"
#include "npf/config/gpc_cntr_control.h"
#include "npf/config/gpc_db_query.h"
#include "npf/config/pmf_hw.h"

/* -- counter group -- */

enum gpc_cntg_flags {
	GPC_CNTG_TYPE_NAMED	= (1 << 0),
	GPC_CNTG_WHAT_PCKT	= (1 << 1),
	GPC_CNTG_WHAT_L3BY	= (1 << 2),
	GPC_CNTG_SHR_IF		= (1 << 3),
};

struct gpc_cntg {
	TAILQ_ENTRY(gpc_cntg)	cntg_list;
	struct gpc_group	*cntg_gprg;
	TAILQ_HEAD(gpc_cnqh, gpc_cntr) cntg_cntrs;
	uint32_t		cntg_flags;
	uint16_t		cntg_refcount;
};

/* -- counter -- */

#define CNTR_NAME_LEN	8

enum gpc_cntr_flags {
	GPC_CNTF_CNT_PACKET	= (1 << 0),
	GPC_CNTF_CNT_BYTE	= (1 << 1),
	GPC_CNTF_PUBLISHED	= (1 << 2),
	GPC_CNTF_LL_CREATED	= (1 << 3),
};

struct gpc_cntr {
	TAILQ_ENTRY(gpc_cntr)	cntr_list;
	struct gpc_cntg		*cntr_cntg;
	char			cntr_name[CNTR_NAME_LEN];
	uintptr_t		cntr_objid;	/* FAL object */
	uint16_t		cntr_flags;
	uint16_t		cntr_refcount;
};

/* -- locals -- */

static TAILQ_HEAD(, gpc_cntg) cntr_groups[GPC_FEAT__MAX] = {
	[GPC_FEAT_ACL] = TAILQ_HEAD_INITIALIZER(cntr_groups[GPC_FEAT_ACL]),
	[GPC_FEAT_QOS] = TAILQ_HEAD_INITIALIZER(cntr_groups[GPC_FEAT_QOS]),
};

/* -- counter group accessors -- */

enum gpc_cntr_type
gpc_cntg_type(struct gpc_cntg const *cntg)
{
	if (cntg->cntg_flags & GPC_CNTG_TYPE_NAMED)
		return GPC_CNTT_NAMED;
	else					// NOLINT: silence clang-tidy
		return GPC_CNTT_NUMBERED;
}

enum gpc_cntr_what
gpc_cntg_what(struct gpc_cntg const *cntg)
{
	enum gpc_cntr_what what = 0;

	if (cntg->cntg_flags & GPC_CNTG_WHAT_PCKT)
		what |= GPC_CNTW_PACKET;
	if (cntg->cntg_flags & GPC_CNTG_WHAT_L3BY)
		what |= GPC_CNTW_L3BYTE;

	return what;
}

enum gpc_cntr_share
gpc_cntg_share(struct gpc_cntg const *cntg)
{
	enum gpc_cntr_share share = 0;

	if (cntg->cntg_flags & GPC_CNTG_SHR_IF)
		share = GPC_CNTS_INTERFACE;

	return share;
}

struct gpc_group *
gpc_cntg_get_group(struct gpc_cntg const *cntg)
{
	return cntg->cntg_gprg;
}

/* -- counter group DB refcount -- */

static void gpc_cntg_delete(struct gpc_cntg *cntg);

void gpc_cntg_retain(struct gpc_cntg *cntg)
{
	/* Should be impossible */
	if (cntg->cntg_refcount == UINT16_MAX)
		return;
	++cntg->cntg_refcount;
}

void gpc_cntg_release(struct gpc_cntg *cntg)
{
	/* Should be impossible */
	if (!cntg->cntg_refcount)
		return;

	if (!cntg->cntg_refcount)
		gpc_cntg_delete(cntg);
}

/* -- counter group DB walk -- */

struct gpc_cntg *
gpc_cntg_first(enum gpc_feature feat)
{
	if (!gpc_feature_is_valid(feat))
		return NULL;

	return TAILQ_FIRST(&cntr_groups[feat]);
}

struct gpc_cntg *
gpc_cntg_next(struct gpc_cntg const *cursor)
{
	return TAILQ_NEXT(cursor, cntg_list);
}

/* -- counter group DB manipulation -- */

struct gpc_cntg *
gpc_cntg_create(struct gpc_group *gprg, enum gpc_cntr_type type,
		enum gpc_cntr_what what, enum gpc_cntr_share share)
{
	struct gpc_cntg *cntg = calloc(1, sizeof(*cntg));
	if (!cntg)
		return NULL;

	cntg->cntg_gprg = gprg;
	TAILQ_INIT(&cntg->cntg_cntrs);
	cntg->cntg_flags = 0;
	cntg->cntg_refcount = 1;

	/* Record the type */
	switch (type) {
	case GPC_CNTT_NAMED:
		cntg->cntg_flags |= GPC_CNTG_TYPE_NAMED;
		break;
	case GPC_CNTT_NUMBERED:
		break;
	default:
		goto error;
	}

	/* Record the sharing */
	switch (share) {
	case GPC_CNTS_INTERFACE:
		cntg->cntg_flags |= GPC_CNTG_SHR_IF;
		break;
	default:
		goto error;
	}

	/* Record what to count */
	if (!what)
		goto error;
	if (what & GPC_CNTW_PACKET) {
		cntg->cntg_flags |= GPC_CNTG_WHAT_PCKT;
		what &= ~GPC_CNTW_PACKET;
	}
	if (what & GPC_CNTW_L3BYTE) {
		cntg->cntg_flags |= GPC_CNTG_WHAT_L3BY;
		what &= ~GPC_CNTW_L3BYTE;
	}
	if (what)
		goto error;

	/* Identify the feature list to insert in to */
	enum gpc_feature feat = gpc_group_get_feature(gprg);
	if (!gpc_feature_is_valid(feat))
		goto error;

	TAILQ_INSERT_TAIL(&cntr_groups[feat], cntg, cntg_list);

	return cntg;

error:
	free(cntg);
	return NULL;
}

static void
gpc_cntg_delete(struct gpc_cntg *cntg)
{
	enum gpc_feature feat = gpc_group_get_feature(cntg->cntg_gprg);

	TAILQ_REMOVE(&cntr_groups[feat], cntg, cntg_list);
	free(cntg);
}

/*
 * For a counter group, notify creation or deletion of all counters.
 *
 * These are used for deferred notifications based upon the
 * change in the group status.
 */
void
gpc_cntg_hw_ntfy_cntrs_create(struct gpc_cntg *cntg)
{
	struct gpc_group *gprg = cntg->cntg_gprg;

	if (!gpc_group_is_published(gprg))
		return;

	struct gpc_cntr *cntr;
	TAILQ_FOREACH(cntr, &cntg->cntg_cntrs, cntr_list)
		gpc_cntr_hw_ntfy_create(cntg, cntr);
}

void
gpc_cntg_hw_ntfy_cntrs_delete(struct gpc_cntg *cntg)
{
	struct gpc_group *gprg = cntg->cntg_gprg;

	if (!gpc_group_is_published(gprg))
		return;

	struct gpc_cntr *cntr;
	TAILQ_FOREACH(cntr, &cntg->cntg_cntrs, cntr_list)
		gpc_cntr_hw_ntfy_delete(cntg, cntr);
}

/* -- counter accessors -- */

struct gpc_cntg *
gpc_cntr_get_cntg(struct gpc_cntr const *cntr)
{
	return cntr->cntr_cntg;
}

char const *
gpc_cntr_get_name(struct gpc_cntr const *cntr)
{
	return cntr->cntr_name;
}

bool
gpc_cntr_pkt_enabled(struct gpc_cntr const *cntr)
{
	enum gpc_cntr_what what = gpc_cntg_what(cntr->cntr_cntg);

	return (what & GPC_CNTW_PACKET);
}

bool
gpc_cntr_byt_enabled(struct gpc_cntr const *cntr)
{
	enum gpc_cntr_what what = gpc_cntg_what(cntr->cntr_cntg);

	return (what & GPC_CNTW_L3BYTE);
}

uintptr_t
gpc_cntr_get_objid(struct gpc_cntr const *cntr)
{
	if (!cntr)
		return 0;

	return cntr->cntr_objid;
}

bool
gpc_cntr_is_published(struct gpc_cntr const *cntr)
{
	return cntr->cntr_flags & GPC_CNTF_PUBLISHED;
}

bool
gpc_cntr_is_ll_created(struct gpc_cntr const *cntr)
{
	return cntr->cntr_flags & GPC_CNTF_LL_CREATED;
}

/* -- counter manipulators -- */

void
gpc_cntr_set_objid(struct gpc_cntr *cntr, uintptr_t objid)
{
	cntr->cntr_objid = objid;
}

static void
gpc_cntr_set_published(struct gpc_cntr *cntr)
{
	cntr->cntr_flags |= GPC_CNTF_PUBLISHED;
}

static void
gpc_cntr_clear_published(struct gpc_cntr *cntr)
{
	cntr->cntr_flags &= ~GPC_CNTF_PUBLISHED;
}

static void
gpc_cntr_set_ll_created(struct gpc_cntr *cntr)
{
	cntr->cntr_flags |= GPC_CNTF_LL_CREATED;
}

static void
gpc_cntr_clear_ll_created(struct gpc_cntr *cntr)
{
	cntr->cntr_flags &= ~GPC_CNTF_LL_CREATED;
}

/* -- counter DB walk -- */

struct gpc_cntr *
gpc_cntr_first(struct gpc_cntg const *cntg)
{
	return cntg ? TAILQ_FIRST(&cntg->cntg_cntrs) : NULL;
}

struct gpc_cntr *
gpc_cntr_last(struct gpc_cntg const *cntg)
{
	return cntg ? TAILQ_LAST(&cntg->cntg_cntrs, gpc_cnqh) : NULL;
}

struct gpc_cntr *
gpc_cntr_next(struct gpc_cntr const *cursor)
{
	return TAILQ_NEXT(cursor, cntr_list);
}

/* -- counter DB refcount -- */

static void gpc_cntr_delete(struct gpc_cntr *cntr);

void gpc_cntr_retain(struct gpc_cntr *cntr)
{
	/* Should be impossible */
	if (cntr->cntr_refcount == UINT16_MAX)
		return;
	++cntr->cntr_refcount;
}

void gpc_cntr_release(struct gpc_cntr *cntr)
{
	/* Should be impossible */
	if (!cntr->cntr_refcount)
		return;

	if (!cntr->cntr_refcount)
		gpc_cntr_delete(cntr);
}

/* -- counter DB lookup -- */

static struct gpc_cntr *
gpc_cntr_find(struct gpc_cntg *cntg, char const *name)
{
	struct gpc_cntr *cursor;

	TAILQ_FOREACH(cursor, &cntg->cntg_cntrs, cntr_list)
		if (strcmp(name, cursor->cntr_name) == 0)
			return cursor;

	return NULL;
}

struct gpc_cntr *
gpc_cntr_find_and_retain(struct gpc_cntg *cntg, char const *name)
{
	struct gpc_cntr *cntr = gpc_cntr_find(cntg, name);

	if (cntr)
		gpc_cntr_retain(cntr);

	return cntr;
}

/* -- counter DB manipulation -- */

static struct gpc_cntr *
gpc_cntr_create(struct gpc_cntg *cntg, char const *name)
{
	struct gpc_cntr *cntr = calloc(1, sizeof(*cntr));
	if (!cntr)
		return NULL;

	if (strlen(name) >= sizeof(cntr->cntr_name))
		goto error;
	strcpy(cntr->cntr_name, name);

	TAILQ_INSERT_TAIL(&cntg->cntg_cntrs, cntr, cntr_list);
	gpc_cntg_retain(cntg);

	cntr->cntr_cntg = cntg;
	cntr->cntr_objid = 0;
	cntr->cntr_flags = 0;
	cntr->cntr_refcount = 1;

	/* Cache these for easy access */
	enum gpc_cntr_what what = gpc_cntg_what(cntg);
	if (what & GPC_CNTW_PACKET)
		cntr->cntr_flags |= GPC_CNTF_CNT_PACKET;
	if (what & GPC_CNTW_L3BYTE)
		cntr->cntr_flags |= GPC_CNTF_CNT_BYTE;

	return cntr;

error:
	free(cntr);
	return NULL;
}

static void
gpc_cntr_delete(struct gpc_cntr *cntr)
{
	struct gpc_cntg *cntg = cntr->cntr_cntg;

	gpc_cntr_hw_ntfy_delete(cntg, cntr);

	TAILQ_REMOVE(&cntg->cntg_cntrs, cntr, cntr_list);
	gpc_cntg_release(cntg);
	cntr->cntr_cntg = NULL;
	free(cntr);
}

struct gpc_cntr *
gpc_cntr_create_named(struct gpc_cntg *cntg, char const *name)
{
	struct gpc_cntr *cntr = gpc_cntr_create(cntg, name);

	return cntr;
}

struct gpc_cntr *
gpc_cntr_create_numbered(struct gpc_cntg *cntg, uint16_t number)
{
	char cntr_name[CNTR_NAME_LEN];

	snprintf(cntr_name, sizeof(cntr_name), "%u", number);

	/* This check can probably be removed */
	if (gpc_cntr_find(cntg, cntr_name)) {
		RTE_LOG(ERR, FIREWALL,
			"Error: Attempt to alloc numbered counter that already exists (%u)\n",
			number);
		return NULL;
	}

	struct gpc_cntr *cntr = gpc_cntr_create(cntg, cntr_name);

	return cntr;
}

/* -- counter hardware notify -- */

void
gpc_cntr_hw_ntfy_create(struct gpc_cntg *cntg, struct gpc_cntr *cntr)
{
	struct gpc_group *gprg = cntg->cntg_gprg;

	if (!gpc_group_is_published(gprg))
		return;
	if (gpc_cntr_is_published(cntr))
		return;

	if (gpc_hw_counter_create(cntr))
		gpc_cntr_set_ll_created(cntr);

	gpc_cntr_set_published(cntr);
}

void
gpc_cntr_hw_ntfy_delete(struct gpc_cntg *cntg, struct gpc_cntr *cntr)
{
	struct gpc_group *gprg = cntg->cntg_gprg;

	if (!gpc_group_is_published(gprg))
		return;
	if (!gpc_cntr_is_published(cntr))
		return;

	gpc_hw_counter_delete(cntr);

	gpc_cntr_clear_ll_created(cntr);
	gpc_cntr_clear_published(cntr);
}
