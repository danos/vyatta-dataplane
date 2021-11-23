/*
 * Copyright (c) 2021, Ciena Corporation. All rights reserved.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "main.h"

#include "dp_test.h"

DP_DECL_TEST_SUITE(driver_conf_suite);

DP_DECL_TEST_CASE(driver_conf_suite, driver_conf_default, NULL, NULL);

/* Check that entries uniquely match. */
DP_START_TEST(driver_conf_default, default_entry_exists)
{
	const struct rxtx_param *default_entry, *entry1, *entry2;

	default_entry = get_driver_param("default", 0);
	if (default_entry == NULL)
		dp_test_fail("default driver entry does not exist!");

	entry1 = get_driver_param("mlx5", 0);
	if (default_entry == entry1)
		dp_test_fail("mlx5 driver entry does not exist!");

	entry2 = get_driver_param("mlx5_pci", 0);
	if (default_entry == entry2)
		dp_test_fail("mlx5_pci driver entry does not exist!");

	if (entry1 == entry2)
		dp_test_fail("mlx5 matched mlx5_pci driver entry!");
} DP_END_TEST;
