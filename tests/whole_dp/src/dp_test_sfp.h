/*
 * Copyright (c) 2018, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef __DP_TEST_SFP_H__

#define __DP_TEST_SFP_H__

int dp_test_get_module_info(struct rte_eth_dev *dev,
			    struct rte_eth_dev_module_info *modinfo);

int dp_test_get_module_eeprom(struct rte_eth_dev *dev,
			      struct rte_dev_eeprom_info *info);

#endif
