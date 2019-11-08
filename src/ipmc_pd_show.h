/*
 * Copyright (c) 2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef IPMC_PD_SHOW_H
#define IPMC_PD_SHOW_H

uint32_t *mroute_hw_stats_get(void);
int mroute_get_pd_subset_data(json_writer_t *json, enum pd_obj_state subset);
uint32_t *mroute6_hw_stats_get(void);
int mroute6_get_pd_subset_data(json_writer_t *json, enum pd_obj_state subset);

#endif /* IPMC_PD_SHOW_H */
