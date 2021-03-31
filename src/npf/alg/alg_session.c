/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "npf/npf_nat.h"
#include "npf/npf_session.h"
#include "npf/alg/alg_apt.h"
#include "npf/alg/alg_npf.h"
#include "npf/alg/alg_session.h"


/*
 * Set ALG session private data
 */
void npf_alg_session_set_private(struct npf_session *se, void *data)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);

	if (sa)
		sa->sa_private = data;
}

/*
 * Get ALG session private data
 */
void *npf_alg_session_get_private(const struct npf_session *se)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);

	if (sa)
		return sa->sa_private;
	return NULL;
}

/*
 * Get previous ALG session private data, and set new value as one operation
 */
void *npf_alg_session_get_and_set_private(const npf_session_t *se, void *data)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);
	if (sa)
		return rcu_xchg_pointer(&(sa->sa_private), data);
	return NULL;
}

/*
 * Test ALG session flag
 */
int npf_alg_session_test_flag(const struct npf_session *se, uint32_t flag)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);

	if (sa)
		return sa->sa_flags & flag;

	return 0;
}

/*
 * Set ALG session flag
 */
void npf_alg_session_set_flag(struct npf_session *se, uint32_t flag)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);

	if (sa)
		sa->sa_flags |= flag;
}

/*
 * Get all ALG session flags
 */
uint32_t npf_alg_session_get_flags(const struct npf_session *se)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);

	if (sa)
		return sa->sa_flags;

	return 0;
}

/*
 * Set inspect state in ALG session data.  This determines if inspection of
 * (mostly) non-NATd packets will occur.
 */
void npf_alg_session_set_inspect(struct npf_session *se, bool v)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);

	if (sa)
		sa->sa_inspect = v;
}

/*
 * Link session to specific ALG instance.  An ALG session struct is created to
 * hold a reference pointer to the specific ALG instance.
 */
int npf_alg_session_set_alg(struct npf_session *se, const struct npf_alg *alg)
{
	struct npf_session_alg *sa = zmalloc_aligned(sizeof(*sa));

	if (!sa)
		return -ENOMEM;

	/* ALG session data takes a reference on ALG instance data */
	sa->sa_alg = npf_alg_get((struct npf_alg *)alg);

	npf_session_set_alg_ptr(se, sa);

	return 0;
}

/*
 * Release reference that session ALG data holds on an ALG instance.
 *
 * Called via npf_session_destroy, npf_alg_session_destroy
 */
void npf_alg_session_clear_alg(struct npf_session *se,
			       struct npf_session_alg *sa)
{
	struct npf_alg *alg = (struct npf_alg *)sa->sa_alg;

	/* Clear s_alg pointer in the npf session */
	npf_session_set_alg_ptr(se, NULL);

	sa->sa_alg = NULL;

	/* Release reference on ALG instance data */
	if (alg)
		npf_alg_put(alg);

	/* Free ALG session data */
	free(sa);
}

/*
 * Get the ALG instance (sip, ftp etc.) for this session
 */
struct npf_alg *npf_alg_session_get_alg(const struct npf_session *se)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);

	if (sa)
		return (struct npf_alg *)sa->sa_alg;
	return NULL;
}

/*
 * Get the NAT structure from a sessions base parent
 */
struct npf_nat *npf_alg_parent_nat(npf_session_t *se)
{
	return npf_session_get_nat(npf_session_get_base_parent(se));
}
