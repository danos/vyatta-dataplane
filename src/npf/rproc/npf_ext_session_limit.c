/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * NPF session limiter rproc extension
 */

#include <errno.h>
#include <limits.h>
#include <rte_atomic.h>
#include <rte_spinlock.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <urcu/list.h>

#include "compiler.h"
#include "json_writer.h"
#include "npf/npf.h"
#include "npf/npf_cmd.h"
#include "npf/npf_ruleset.h"
#include "npf/npf_session.h"
#include "npf/npf_state.h"
#include "npf/rproc/npf_ext_session_limit.h"
#include "npf/rproc/npf_rproc.h"
#include "util.h"

struct ifnet;
struct rte_mbuf;

/*
 * NPF session limiter
 */

/* Defines relative to soft_ticks */
#define	ONE_SECOND		1000
#define	ONE_MINUTE		(ONE_SECOND * 60)
#define	FIVE_MINUTES		(ONE_MINUTE * 5)

/* session limiter instance */
struct npf_sess_limit_inst {
	struct cds_list_head	li_param_list;
	uint32_t		li_param_count;
};

/*
 * Monitor session creation or block rates.
 */
struct npf_sess_rate {
	/* Count events that occur during interval */
	uint32_t	sr_count;
	uint32_t	sr_pad;

	/* Set to soft_ticks every sr_interval */
	uint64_t	sr_time;

	/* Number of ticks over which rate is measured */
	uint64_t	sr_interval;

	/* Rate is evaluated at the end of every sr_interval */
	uint32_t	sr_rate;

	/* Max rate and time when max rate occurred */
	uint32_t	sr_max_rate;
	uint64_t	sr_max_rate_time;
};

/*
 * Limit session creation rate
 */
struct npf_sess_rate_limit {
	/* timestamp at start of interval */
	uint64_t	rl_time;
	/* duration of interval in ticks (millisecs) */
	uint64_t	rl_interval;
	/* configured sessions per sec */
	uint32_t	rl_rate;
	/* max burst, or sessions per interval */
	uint32_t	rl_burst;
	/* tokens remaining for current interval */
	int32_t		rl_tokens;
};

/* session limit parameter */
struct npf_sess_limit_param_t {
	struct cds_list_head	lp_node;
	char			*lp_name;
	rte_spinlock_t		lp_lock;

	/*
	 * Incremented once when added to instance list, and once for each
	 * referencing rproc
	 */
	rte_atomic32_t		lp_refcnt;

	/* Config */
	uint8_t			lp_flags;
	uint32_t		lp_halfopen_max;
	uint32_t		lp_ratelimit_rate;
	uint32_t		lp_ratelimit_burst;

	/* Counters */
	uint32_t		lp_new_ct;	/* new */
	uint32_t		lp_estab_ct;	/* established */
	uint32_t		lp_term_ct;	/* terminating */

	/* Max values since last clear */
	uint32_t		lp_max_new_ct;
	uint32_t		lp_max_estab_ct;
	uint32_t		lp_max_term_ct;

	/* Sessions blocked by max-halfopen */
	uint64_t		lp_ho_block_ct;
	/* Sessions blocked by rate-limit */
	uint64_t		lp_rl_block_ct;
	/* Sessions allowed */
	uint64_t		lp_allowed_ct;

	/* Timestamp (ticks) when last session created */
	uint64_t		lp_last_sess_created;

	/* Timestamp (ticks) when last session blocked */
	uint64_t		lp_last_sess_blocked;

	/*
	 * Monitored session creation rates.  Average sessions/second
	 * over last 1 sec, 1 minute, and 5 minutes.
	 */
	struct npf_sess_rate	lp_rate_1sec;
	struct npf_sess_rate	lp_rate_1min;
	struct npf_sess_rate	lp_rate_5min;

	struct npf_sess_rate	lp_rate_blocks_1sec;
	struct npf_sess_rate	lp_rate_blocks_1min;
	struct npf_sess_rate	lp_rate_blocks_5min;

	/* Rate limiting cfg value and state */
	struct npf_sess_rate_limit lp_rate_limit;
};

#define SESS_LIMIT_HALFOPEN_MAX		(1 << 0)
#define SESS_LIMIT_RATELIMIT_RATE	(1 << 1)
#define SESS_LIMIT_RATELIMIT_BURST	(1 << 2)


/* Single, global session limit instance */
static struct npf_sess_limit_inst *limit_inst;

/* Forward reference */
static void
npf_sess_limit_param_remove_all(struct npf_sess_limit_inst *li);


/***************************   instance   **********************************/

/*
 * Session limit instance
 */
static struct npf_sess_limit_inst *
npf_sess_limit_inst_create(void)
{
	struct npf_sess_limit_inst *li;

	li = zmalloc_aligned(sizeof(*li));
	if (!li)
		return NULL;

	CDS_INIT_LIST_HEAD(&li->li_param_list);

	return li;
}

static struct npf_sess_limit_inst *
npf_sess_limit_inst_find(void)
{
	if (!limit_inst)
		limit_inst = npf_sess_limit_inst_create();

	return limit_inst;
}

void
npf_sess_limit_inst_destroy(void)
{
	if (!limit_inst)
		return;

	npf_sess_limit_param_remove_all(limit_inst);
	free(limit_inst);
	limit_inst = NULL;
}

/*************************  parameter rate  ********************************/

static void
npf_sess_limit_init_rate(struct npf_sess_rate *sr, uint64_t interval,
			 uint64_t ticks)
{
	sr->sr_interval = interval;
	sr->sr_count = 0;
	sr->sr_time = ticks;
	sr->sr_rate = 0;
	sr->sr_max_rate_time = 0;
	sr->sr_max_rate = 0;
}

static void
npf_sess_limit_update_rate(struct npf_sess_rate *sr, uint64_t ticks)
{
	uint64_t lapsed;

	sr->sr_count++;
	lapsed = ticks - sr->sr_time;

	if (lapsed >= sr->sr_interval) {
		/* Calculate sessions per second */
		sr->sr_rate = sr->sr_count / (lapsed/ONE_SECOND);

		if (sr->sr_rate > 0 && sr->sr_rate >= sr->sr_max_rate) {
			sr->sr_max_rate = sr->sr_rate;
			sr->sr_max_rate_time = ticks;
		}

		/* Start new period */
		sr->sr_time = ticks;
		sr->sr_count = 0;
	}
}

/*
 * limit - sessions per second
 */
static void
npf_sess_limit_init_rate_limit(struct npf_sess_rate_limit *rl,
				uint32_t rate, uint32_t burst,
				bool init)
{
	/* Set burst the same as rate, if not configured */
	if (burst == 0)
		burst = rate;

	rl->rl_rate = rate;
	rl->rl_burst = burst;
	rl->rl_interval = ((burst * ONE_SECOND) / rate);
	rl->rl_tokens = rl->rl_burst;

	if (init)
		rl->rl_time = soft_ticks;
}

/*
 * Return true if there are no more tokens left for this interval.  Refresh
 * limit tokens if we are starting a new interval.  rl_tokens is only
 * decremented when a new session is actually created.
 */
static bool
npf_sess_rate_limit(struct npf_sess_rate_limit *rl, uint64_t ticks)
{
	uint64_t lapsed;

	lapsed = ticks - rl->rl_time;

	if (lapsed >= rl->rl_interval) {
		/*
		 * Start new interval.  Replenish tokens and reset time
		 */
		rl->rl_time = ticks;
		rl->rl_tokens = rl->rl_burst;
	}

	/* rl_tokens is decremented in the session_activate callback */
	return rl->rl_tokens <= 0;
}

/****************************  parameter  **********************************/

/*
 * Session limit parameter
 */
static struct npf_sess_limit_param_t *
npf_sess_limit_param_find(const char *name)
{
	struct npf_sess_limit_param_t *lp;
	struct npf_sess_limit_inst *li;

	li = npf_sess_limit_inst_find();
	if (!li)
		return NULL;

	if (li->li_param_count == 0)
		return NULL;

	cds_list_for_each_entry(lp, &li->li_param_list, lp_node) {
		if (!strcmp(name, lp->lp_name))
			return lp;
	}

	return NULL;
}

static struct npf_sess_limit_param_t *
npf_sess_limit_param_create(const char *name)
{
	struct npf_sess_limit_param_t *lp;
	uint64_t ticks = soft_ticks;

	lp = calloc(1, sizeof(*lp));
	if (!lp)
		return NULL;

	rte_spinlock_init(&lp->lp_lock);
	lp->lp_name = strdup(name);

	npf_sess_limit_init_rate(&lp->lp_rate_1sec, ONE_SECOND, ticks);
	npf_sess_limit_init_rate(&lp->lp_rate_1min, ONE_MINUTE, ticks);
	npf_sess_limit_init_rate(&lp->lp_rate_5min, FIVE_MINUTES, ticks);

	npf_sess_limit_init_rate(&lp->lp_rate_blocks_1sec, ONE_SECOND, ticks);
	npf_sess_limit_init_rate(&lp->lp_rate_blocks_1min, ONE_MINUTE, ticks);
	npf_sess_limit_init_rate(&lp->lp_rate_blocks_5min, FIVE_MINUTES, ticks);

	return lp;
}

static void
npf_sess_limit_param_destroy(struct npf_sess_limit_param_t **lpp)
{
	struct npf_sess_limit_param_t *lp = *lpp;

	*lpp = NULL;
	free(lp->lp_name);
	free(lp);
}

static void
npf_sess_limit_param_get(struct npf_sess_limit_param_t *lp)
{
	rte_atomic32_inc(&lp->lp_refcnt);
}

static void
npf_sess_limit_param_put(struct npf_sess_limit_param_t **lpp)
{
	struct npf_sess_limit_param_t *lp = *lpp;

	if (lp && rte_atomic32_dec_and_test(&lp->lp_refcnt))
		npf_sess_limit_param_destroy(lpp);
}

static int
npf_sess_limit_param_insert(struct npf_sess_limit_param_t *lp)
{
	struct npf_sess_limit_inst *li;

	li = npf_sess_limit_inst_find();
	if (!li)
		return -1;

	rte_atomic32_set(&lp->lp_refcnt, 1);

	cds_list_add_tail(&lp->lp_node, &li->li_param_list);
	li->li_param_count++;

	return 0;
}

static int
npf_sess_limit_param_remove(struct npf_sess_limit_param_t **lpp)
{
	struct npf_sess_limit_inst *li;
	struct npf_sess_limit_param_t *lp = *lpp;

	if (cds_list_empty(&lp->lp_node))
		/* param not in list! */
		return -1;

	li = npf_sess_limit_inst_find();
	if (!li)
		return -1;

	cds_list_del(&lp->lp_node);
	li->li_param_count--;

	npf_sess_limit_param_put(lpp);

	return 0;
}

static void
npf_sess_limit_param_remove_all(struct npf_sess_limit_inst *li)
{
	struct npf_sess_limit_param_t *lp, *tmp;

	if (li->li_param_count == 0)
		return;

	cds_list_for_each_entry_safe(lp, tmp, &li->li_param_list, lp_node) {
		cds_list_del(&lp->lp_node);
		li->li_param_count--;
		npf_sess_limit_param_put(&lp);
	}
}

static int npf_sess_limit_param_add(const char *name)
{
	struct npf_sess_limit_param_t *lp;
	int rc = 0;

	lp = npf_sess_limit_param_find(name);
	if (lp)
		return 0;

	lp = npf_sess_limit_param_create(name);
	if (!lp)
		return -1;

	rc = npf_sess_limit_param_insert(lp);
	if (rc < 0)
		npf_sess_limit_param_destroy(&lp);

	return rc;
}

static int npf_sess_limit_param_del(const char *name)
{
	struct npf_sess_limit_param_t *lp;
	int rc;

	lp = npf_sess_limit_param_find(name);
	if (!lp)
		return 0;

	if (lp->lp_flags != 0)
		return -1;

	rc = npf_sess_limit_param_remove(&lp);
	if (rc < 0)
		return rc;

	return rc;
}

static int
npf_sess_limit_param_add_maxhalfopen(const char *name, uint32_t max)
{
	struct npf_sess_limit_param_t *lp;

	lp = npf_sess_limit_param_find(name);
	if (!lp)
		return 0;

	lp->lp_halfopen_max = max;
	lp->lp_flags |= SESS_LIMIT_HALFOPEN_MAX;

	return 0;
}

static int
npf_sess_limit_param_del_maxhalfopen(const char *name)
{
	struct npf_sess_limit_param_t *lp;

	lp = npf_sess_limit_param_find(name);
	if (!lp)
		return 0;

	lp->lp_halfopen_max = 0;
	lp->lp_flags &= ~SESS_LIMIT_HALFOPEN_MAX;

	return 0;
}

static int
npf_sess_limit_param_add_rl_rate(const char *name, uint32_t rate)
{
	struct npf_sess_limit_param_t *lp;
	bool init = false;

	lp = npf_sess_limit_param_find(name);
	if (!lp)
		return 0;

	lp->lp_ratelimit_rate = rate;

	if ((lp->lp_flags & SESS_LIMIT_RATELIMIT_RATE) == 0) {
		init = true;
		lp->lp_flags |= SESS_LIMIT_RATELIMIT_RATE;
	}

	npf_sess_limit_init_rate_limit(&lp->lp_rate_limit,
					rate,
					lp->lp_ratelimit_burst,
					init);

	return 0;
}

static int
npf_sess_limit_param_del_rl_rate(const char *name)
{
	struct npf_sess_limit_param_t *lp;

	lp = npf_sess_limit_param_find(name);
	if (!lp)
		return 0;

	lp->lp_ratelimit_rate = 0;
	lp->lp_flags &= ~SESS_LIMIT_RATELIMIT_RATE;

	return 0;
}

static int
npf_sess_limit_param_add_rl_burst(const char *name, uint32_t burst)
{
	struct npf_sess_limit_param_t *lp;

	lp = npf_sess_limit_param_find(name);
	if (!lp)
		return 0;

	lp->lp_ratelimit_burst = burst;
	lp->lp_flags |= SESS_LIMIT_RATELIMIT_BURST;

	if ((lp->lp_flags & SESS_LIMIT_RATELIMIT_RATE) != 0)
		npf_sess_limit_init_rate_limit(&lp->lp_rate_limit,
					       lp->lp_ratelimit_rate,
					       burst, false);

	return 0;
}

static int
npf_sess_limit_param_del_rl_burst(const char *name)
{
	struct npf_sess_limit_param_t *lp;

	lp = npf_sess_limit_param_find(name);
	if (!lp)
		return 0;

	lp->lp_ratelimit_burst = 0;
	lp->lp_flags &= ~SESS_LIMIT_RATELIMIT_BURST;

	return 0;
}

static void
npf_sess_limit_jsonw_rate(json_writer_t *json, const char *str,
			  const struct npf_sess_rate *sr,
			  uint64_t ticks)
{
	char tmp[40];

	snprintf(tmp, sizeof(tmp), "%s", str);
	jsonw_uint_field(json, tmp, sr->sr_rate);

	snprintf(tmp, sizeof(tmp), "max_%s", str);
	jsonw_uint_field(json, tmp, sr->sr_max_rate);

	snprintf(tmp, sizeof(tmp), "max_%s_time", str);
	if (sr->sr_max_rate_time == 0)
		/* Use a very large value to denote never */
		jsonw_uint_field(json, tmp, UINT_MAX);
	else {
		uint64_t elapsed;

		elapsed = ticks - sr->sr_max_rate_time;
		jsonw_uint_field(json, tmp, (uint32_t)(elapsed / ONE_SECOND));
	}
}

static void
npf_sess_limit_param_show_one(json_writer_t *json,
			      struct npf_sess_limit_param_t *lp,
			      uint64_t ticks)
{
	jsonw_name(json, lp->lp_name);
	jsonw_start_object(json);

	jsonw_name(json, "summary");
	jsonw_start_object(json);

	jsonw_uint_field(json, "new_ct", lp->lp_new_ct);
	jsonw_uint_field(json, "estab_ct", lp->lp_estab_ct);
	jsonw_uint_field(json, "term_ct", lp->lp_term_ct);

	jsonw_uint_field(json, "max_new_ct", lp->lp_max_new_ct);
	jsonw_uint_field(json, "max_estab_ct", lp->lp_max_estab_ct);
	jsonw_uint_field(json, "max_term_ct", lp->lp_max_term_ct);

	npf_sess_limit_jsonw_rate(json, "rate_1sec", &lp->lp_rate_1sec, ticks);
	npf_sess_limit_jsonw_rate(json, "rate_1min", &lp->lp_rate_1min, ticks);
	npf_sess_limit_jsonw_rate(json, "rate_5min", &lp->lp_rate_5min, ticks);

	npf_sess_limit_jsonw_rate(json, "rate_blocks_1sec",
				   &lp->lp_rate_blocks_1sec, ticks);
	npf_sess_limit_jsonw_rate(json, "rate_blocks_1min",
				   &lp->lp_rate_blocks_1min, ticks);
	npf_sess_limit_jsonw_rate(json, "rate_blocks_5min",
				   &lp->lp_rate_blocks_5min, ticks);

	jsonw_uint_field(json, "allowed_ct", lp->lp_allowed_ct);

	if (lp->lp_last_sess_created == 0)
		/* never */
		jsonw_uint_field(json, "last_sess_created", UINT_MAX);
	else {
		uint64_t elapsed;

		elapsed = ticks - lp->lp_last_sess_created;
		jsonw_uint_field(json, "last_sess_created",
				 (uint32_t)(elapsed / ONE_SECOND));
	}

	if (lp->lp_last_sess_blocked == 0)
		/* never */
		jsonw_uint_field(json, "last_sess_blocked", UINT_MAX);
	else {
		uint64_t elapsed;

		elapsed = ticks - lp->lp_last_sess_blocked;
		jsonw_uint_field(json, "last_sess_blocked",
				 (uint32_t)(elapsed / ONE_SECOND));
	}

	if ((lp->lp_flags & SESS_LIMIT_RATELIMIT_RATE) != 0) {
		jsonw_name(json, "ratelimit");
		jsonw_start_object(json);

		jsonw_uint_field(json, "ratelimit_rate",
				 lp->lp_rate_limit.rl_rate);
		jsonw_uint_field(json, "ratelimit_burst",
				 lp->lp_rate_limit.rl_burst);
		jsonw_uint_field(json, "blocked_ct",
				 lp->lp_rl_block_ct);

		jsonw_end_object(json);	/* ratelimit */
	}

	if ((lp->lp_flags & SESS_LIMIT_HALFOPEN_MAX) != 0) {
		jsonw_name(json, "halfopen");
		jsonw_start_object(json);

		jsonw_uint_field(json, "halfopen_max",
				 lp->lp_halfopen_max);

		jsonw_uint_field(json, "blocked_ct",
				 lp->lp_ho_block_ct);

		jsonw_end_object(json);	/* halfopen */
	}

	jsonw_end_object(json);	/* summary */
	jsonw_end_object(json);	/* name */
}

static int
npf_sess_limit_param_show(FILE *f, const char *name)
{
	struct npf_sess_limit_param_t *lp;
	struct npf_sess_limit_inst *li;
	json_writer_t *json;
	uint64_t ticks = soft_ticks;

	json = jsonw_new(f);
	if (!json)
		return -1;

	jsonw_name(json, "session-limit");
	jsonw_start_object(json);

	jsonw_name(json, "parameter");
	jsonw_start_object(json);

	li = npf_sess_limit_inst_find();
	if (!li || li->li_param_count == 0)
		goto end;

	cds_list_for_each_entry(lp, &li->li_param_list, lp_node) {
		if (name) {
			if (!strcmp(name, lp->lp_name)) {
				npf_sess_limit_param_show_one(json, lp, ticks);
				break;
			}
		} else
			npf_sess_limit_param_show_one(json, lp, ticks);
	}

end:
	jsonw_end_object(json); /* parameter */
	jsonw_end_object(json); /* session-limit */
	jsonw_destroy(&json);
	return 0;
}

static void
npf_sess_limit_param_clear_one(struct npf_sess_limit_param_t *lp)
{
	lp->lp_max_new_ct   = 0;
	lp->lp_max_estab_ct = 0;
	lp->lp_max_term_ct  = 0;

	lp->lp_ho_block_ct = 0;
	lp->lp_rl_block_ct = 0;
	lp->lp_allowed_ct = 0;

	lp->lp_rate_1sec.sr_max_rate = 0;
	lp->lp_rate_1min.sr_max_rate = 0;
	lp->lp_rate_5min.sr_max_rate = 0;

	lp->lp_rate_blocks_1sec.sr_max_rate = 0;
	lp->lp_rate_blocks_1min.sr_max_rate = 0;
	lp->lp_rate_blocks_5min.sr_max_rate = 0;
}

static int
npf_sess_limit_param_clear(const char *name)
{
	struct npf_sess_limit_param_t *lp;
	struct npf_sess_limit_inst *li;

	li = npf_sess_limit_inst_find();
	if (!li || li->li_param_count == 0)
		return 0;

	cds_list_for_each_entry(lp, &li->li_param_list, lp_node) {
		if (name) {
			if (!strcmp(name, lp->lp_name)) {
				npf_sess_limit_param_clear_one(lp);
				break;
			}
		} else
			npf_sess_limit_param_clear_one(lp);
	}
	return 0;
}

/******************************  cfg/op  ***********************************/

/* session limiter max halfopen */
static int
cmd_npf_sess_limit_param_halfopen_parse(FILE *f, int argc, char **argv,
					uint32_t *halfopenp)
{
	char *endp;

	if (argc < 1) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}

	*halfopenp = strtoul(argv[0], &endp, 10);
	if (*halfopenp == 0 || *endp) {
		npf_cmd_err(f, "invalid session limit "
			    "maxhalfopen value");
		return -1;
	}

	return 0;
}

/* session limiter rate-limit */
static int
cmd_npf_sess_limit_param_rl_parse(FILE *f, int argc, char **argv,
				  uint32_t *ratep, uint32_t *burstp)
{
	char *endp;
	int i;

	if (argc < 2) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}

	/* Params are keyword-value pairs */
	for (i = 0; i < argc - 1; i++) {
		if (!strcmp(argv[i], "rate")) {
			i++;
			*ratep = strtoul(argv[i], &endp, 10);

			if (*ratep == 0 || *endp) {
				npf_cmd_err(f, "invalid session limit "
					    "ratelimit rate");
				return -1;
			}
			continue;
		}
		if (!strcmp(argv[i], "burst")) {
			i++;
			*burstp = strtoul(argv[i], &endp, 10);

			if (*endp) {
				npf_cmd_err(f, "invalid session limit "
					    "ratelimit burst");
				return -1;
			}
			continue;
		}
		/* Ignore other keyword-value pairs */
		i++;
	}

	/* rate must be set.  burst is optional */
	if (*ratep == 0) {
		npf_cmd_err(f, "ratelimit rate not set");
		return -1;
	}

	return 0;
}

/*
 * Create a session limit parameter
 *
 * A limit parameter may be cfgd without either max-halfopen or ratelimit, in
 * which case it will act as a session monitor if sorts.
 */
int
cmd_npf_sess_limit_param_add(FILE *f, int argc, char **argv)
{
	const char *name = NULL;
	int rc = 0;

	if (argc < 2) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}

	/* Name is always first */
	if (strcmp(argv[0], "name") == 0) {
		name = argv[1];
		argc -= 2;
		argv += 2;
	}

	if (name == NULL) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}

	rc = npf_sess_limit_param_add(name);
	if (rc < 0)
		return rc;

	if (argc > 0 && !strcmp(argv[0], "maxhalfopen")) {
		uint32_t maxho;

		argc -= 1;
		argv += 1;
		rc = cmd_npf_sess_limit_param_halfopen_parse(f, argc,
							     argv, &maxho);
		if (rc < 0)
			return -1;

		rc = npf_sess_limit_param_add_maxhalfopen(name, maxho);
		if (rc < 0)
			return rc;
	}

	if (argc > 0 && !strcmp(argv[0], "ratelimit")) {
		uint32_t rate = UINT32_MAX, burst = UINT32_MAX;

		argc -= 1;
		argv += 1;
		rc = cmd_npf_sess_limit_param_rl_parse(f, argc, argv,
						       &rate, &burst);
		if (rc < 0)
			return -1;

		if (rate != UINT32_MAX) {
			rc = npf_sess_limit_param_add_rl_rate(name, rate);
			if (rc < 0)
				return rc;
		}

		if (burst != UINT32_MAX) {
			rc = npf_sess_limit_param_add_rl_burst(name, burst);
			if (rc < 0)
				return rc;
		}
	}

	return 0;
}

/*
 * Delete a session limit parameter
 */
int
cmd_npf_sess_limit_param_delete(FILE *f, int argc, char **argv)
{
	const char *name = NULL;
	int rc = 0;

	if (argc < 2) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}

	/* Name is always first */
	if (strcmp(argv[0], "name") == 0) {
		name = argv[1];
		argc -= 2;
		argv += 2;
	}

	if (name == NULL) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}

	bool del_halfopen = true;
	bool del_rl_rate = true;
	bool del_rl_burst = true;
	bool del_param = true;

	if (argc > 0) {
		if (!strcmp(argv[0], "maxhalfopen")) {
			del_rl_rate = false;
			del_rl_burst = false;
			del_param = false;
		} else if (!strcmp(argv[0], "ratelimit")) {
			argc -= 1;
			argv += 1;

			if (argc > 0) {
				if (!strcmp(argv[1], "rate")) {
					del_rl_burst = false;
				} else if (!strcmp(argv[1], "burst")) {
					del_rl_rate = false;
				} else {
					npf_cmd_err(f, "unknown option");
					return -1;
				}
			}
			del_param = false;
			del_halfopen = false;
		} else {
			npf_cmd_err(f, "unknown option");
			return -1;
		}
	}

	if (del_halfopen)
		npf_sess_limit_param_del_maxhalfopen(name);

	if (del_rl_rate)
		npf_sess_limit_param_del_rl_rate(name);

	if (del_rl_burst)
		npf_sess_limit_param_del_rl_burst(name);

	if (del_param)
		rc = npf_sess_limit_param_del(name);

	return rc;
}

/*
 * session limit parameter
 */
int
cmd_npf_sess_limit_show(FILE *f, int argc, char **argv)
{
	char *name = NULL;
	int rc = -1;

	if (argc == 0)
		goto show_all;

	if (strcmp(argv[0], "name") == 0) {
		if (argc < 2) {
			npf_cmd_err(f, "missing session limit "
				    "parameter name");
			return -1;
		}
		/* Leave name as NULL if "all" specified  */
		if (strcmp(argv[1], "all") != 0)
			name = argv[1];
	}

show_all:
	rc = npf_sess_limit_param_show(f, name);
	return rc;
}

/*
 * Clear session limit parameter counters
 */
int
cmd_npf_sess_limit_clear(FILE *f __unused, int argc, char **argv)
{
	char *name = NULL;
	int rc = -1;

	if (argc == 0)
		goto clear_all;

	if (strcmp(argv[0], "name") == 0) {
		if (argc < 2) {
			npf_cmd_err(f, "missing session limit "
				    "parameter name");
			return -1;
		}
		/* Leave name as NULL if "all" specified  */
		if (strcmp(argv[1], "all") != 0)
			name = argv[1];
	}

clear_all:
	rc = npf_sess_limit_param_clear(name);
	return rc;
}

/*******************************  rproc  ***********************************/

/*
 * rproc constructor.  args should be of the form "parameter=PARAM1"
 */
static int
npf_sess_limit_ctor(npf_rule_t *rl __unused, const char *args, void **handle)
{
	const char *name_pfx = "parameter=";
	struct npf_sess_limit_param_t *lp;
	char *name;

	if (!args)
		return -EINVAL;

	/* Look for parameter name prefix */
	name = strstr(args, name_pfx);
	if (!name)
		return -EINVAL;

	/* Name is stored just after prefix */
	name += strlen(name_pfx);
	if (strlen(name) < 2)
		return -EINVAL;

	lp = npf_sess_limit_param_find(name);
	if (!lp)
		return -EINVAL;

	npf_sess_limit_param_get(lp);
	*handle = lp;

	return 0;
}

/*
 * session limit rproc destructor
 */
static void
npf_sess_limit_dtor(void *handle)
{
	struct npf_sess_limit_param_t *lp;

	lp = handle;
	npf_sess_limit_param_put(&lp);
}

/*
 * Called from npf_session_establish to determine if we want to allow this
 * session to be created. Returns 'true' to prevent session being created.
 */
bool npf_sess_limit_check(npf_rule_t *rl)
{
	struct npf_sess_limit_param_t *lp;

	lp = npf_rule_rproc_handle_from_id(rl, NPF_RPROC_ID_SLIMIT);
	if (!lp)
		/* Should never happen */
		return false;

	uint64_t ticks = soft_ticks;

	if ((lp->lp_flags &
	     (SESS_LIMIT_RATELIMIT_RATE | SESS_LIMIT_HALFOPEN_MAX)) == 0)
		return false;

	rte_spinlock_lock(&lp->lp_lock);

	if ((lp->lp_flags & SESS_LIMIT_RATELIMIT_RATE) != 0) {

		if (npf_sess_rate_limit(&lp->lp_rate_limit, ticks)) {

			lp->lp_rl_block_ct++;
			lp->lp_last_sess_blocked = ticks;

			/* Update session block rates */
			npf_sess_limit_update_rate(&lp->lp_rate_blocks_1sec,
						   ticks);
			npf_sess_limit_update_rate(&lp->lp_rate_blocks_1min,
						   ticks);
			npf_sess_limit_update_rate(&lp->lp_rate_blocks_5min,
						   ticks);

			/* block session creation */
			rte_spinlock_unlock(&lp->lp_lock);
			return true;
		}
	}

	if ((lp->lp_flags & SESS_LIMIT_HALFOPEN_MAX) != 0) {

		if (lp->lp_new_ct >= lp->lp_halfopen_max) {

			lp->lp_ho_block_ct++;
			lp->lp_last_sess_blocked = ticks;

			/* Update session block rates */
			npf_sess_limit_update_rate(&lp->lp_rate_blocks_1sec,
						   ticks);
			npf_sess_limit_update_rate(&lp->lp_rate_blocks_1min,
						   ticks);
			npf_sess_limit_update_rate(&lp->lp_rate_blocks_5min,
						   ticks);

			/* block session creation */
			rte_spinlock_unlock(&lp->lp_lock);
			return true;
		}
	}

	rte_spinlock_unlock(&lp->lp_lock);
	return false;
}

/*
 * Update rate limit counts when a session is activated
 */
static void
npf_sess_limit_update_rates(struct npf_sess_limit_param_t *lp)
{
	uint64_t ticks = soft_ticks;

	lp->lp_allowed_ct++;
	lp->lp_last_sess_created = ticks;

	/* Update session creation rates */
	npf_sess_limit_update_rate(&lp->lp_rate_1sec, ticks);
	npf_sess_limit_update_rate(&lp->lp_rate_1min, ticks);
	npf_sess_limit_update_rate(&lp->lp_rate_5min, ticks);

	/* Only decrement the rl tokens when a session is activated. */
	if ((lp->lp_flags & SESS_LIMIT_RATELIMIT_RATE) != 0)
		lp->lp_rate_limit.rl_tokens--;
}

/*
 * Called when the session belonging to a limit-enabled rproc rule changes
 * state.  May be called from both main and forwarding threads.
 */
void npf_sess_limit_state_change(void *handle, uint8_t proto_idx,
				 uint8_t prev_state, uint8_t state)
{
	struct npf_sess_limit_param_t *lp = handle;

	/*
	 * We dont care about the various types of TCP half-open state, for
	 * example, so convert to a generic state
	 */
	state = npf_state_get_generic_state(proto_idx, state);
	prev_state = npf_state_get_generic_state(proto_idx, prev_state);

	if (state == prev_state)
		return;

	rte_spinlock_lock(&lp->lp_lock);

	switch (prev_state) {
	case SESSION_STATE_NONE:
		/* do nothing */
		break;

	case SESSION_STATE_NEW:
		lp->lp_new_ct--;
		break;

	case SESSION_STATE_ESTABLISHED:
		lp->lp_estab_ct--;
		break;

	case SESSION_STATE_TERMINATING:
		/* Only occurs for TCP sessions */
		lp->lp_term_ct--;
		break;

	case SESSION_STATE_CLOSED:
		/* Will not happen */
		break;
	};

	switch (state) {
	case SESSION_STATE_NONE:
		/* do nothing */
		break;

	case SESSION_STATE_NEW:
		lp->lp_new_ct++;

		if (lp->lp_new_ct >= lp->lp_max_new_ct)
			lp->lp_max_new_ct = lp->lp_new_ct;

		npf_sess_limit_update_rates(lp);
		break;

	case SESSION_STATE_ESTABLISHED:
		lp->lp_estab_ct++;

		if (lp->lp_estab_ct >= lp->lp_max_estab_ct)
			lp->lp_max_estab_ct = lp->lp_estab_ct;
		break;

	case SESSION_STATE_TERMINATING:
		/* Only occurs for TCP sessions */
		lp->lp_term_ct++;

		if (lp->lp_term_ct >= lp->lp_max_term_ct)
			lp->lp_max_term_ct = lp->lp_term_ct;
		break;

	case SESSION_STATE_CLOSED:
		break;
	};

	rte_spinlock_unlock(&lp->lp_lock);
}

const npf_rproc_ops_t npf_session_limiter_ops = {
	.ro_name    = "session-limiter",
	.ro_type   = NPF_RPROC_TYPE_HANDLE,
	.ro_id     = NPF_RPROC_ID_SLIMIT,
	.ro_bidir   = false,
	.ro_ctor    = npf_sess_limit_ctor,
	.ro_dtor    = npf_sess_limit_dtor,
	.ro_action  = NULL,
};
