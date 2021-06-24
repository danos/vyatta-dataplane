/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "npf/apm/apm.h"
#include "npf/cgnat/cgn_session.h"
#include "npf/cgnat/cgn_source.h"
#include "npf/cgnat/cgn_test.h"

/*
 * Only used by CGNAT unit-tests
 */
void dp_test_npf_clear_cgnat(void)
{
	cgn_session_cleanup();
	apm_cleanup();
	cgn_source_cleanup();
}
