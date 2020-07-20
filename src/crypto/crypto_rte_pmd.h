/*-
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef CRYPTO_RTE_PMD_H

#define CRYPTO_RTE_PMD_H

#include <linux/xfrm.h>

int crypto_rte_setup(void);

void crypto_rte_shutdown(void);

int crypto_rte_set_session_parameters(struct crypto_session *ctx,
				      const struct xfrm_algo *algo_crypt,
				      const struct xfrm_algo_auth *algo_auth);

#endif
