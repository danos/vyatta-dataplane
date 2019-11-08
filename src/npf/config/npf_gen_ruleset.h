/*
 * Copyright (c) 2018, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2016-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef NPF_GEN_RULESET_H
#define NPF_GEN_RULESET_H

#include "npf/config/npf_attach_point.h"
#include "npf/config/npf_ruleset_type.h"
#include "npf/npf_ruleset.h"

/**
 * Requests creation of the dataplane ruleset
 *
 * @param dp_ruleset This is a pointer to the location where a
 *                   pointer to the created ruleset should be stored.
 *                   On success this will be filled in with a pointer
 *                   to the created ruleset. If the ruleset does not exist
 *                   it will be filled with NULL.
 * @param attach_type The type of the attach point (e.g. interface).
 * @param attach_point The name of the attach point (e.g. interface name).
 * @param ruleset_type Identifies the ruleset type to build the ruleset for
 *                     (e.g. firewall in, NAT out, etc.)
 * @return Returns 0 on successfully building the rules, or negative errno
 *         on failure to create the ruleset.
 */
int npf_cfg_build_ruleset(npf_ruleset_t **dp_ruleset,
			  enum npf_attach_type attach_type,
			  const char *attach_point,
			  enum npf_ruleset_type ruleset_type);

/**
 * Replaces a ruleset with a new ruleset
 *
 * Note that if the new ruleset is NULL, then it will just delete the
 * existing ruleset. If the existing ruleset is NULL then it will just
 * create the new ruleset and not destroy the existing one.
 *
 * @param ruleset_type Identifies the ruleset type being deleted
 *                     (e.g. firewall in, NAT out, etc.)
 * @param dp_ruleset This is a pointer to the location where a
 *                   pointer to an existing ruleset is stored. This location
 *		     will be updated to contain the new ruleset and any
 *		     ruleset that was here will be destroyed.
 * @param new_dp_ruleset This is a pointer to the new ruleset. If this is
 *			 NULL then the old ruleset will be destroyed and
 *			 set to NULL.
 */
void npf_replace_ruleset(npf_ruleset_t **dp_ruleset,
			 npf_ruleset_t *new_dp_ruleset);

#endif
