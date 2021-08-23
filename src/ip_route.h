/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef IP_ROUTE
#define IP_ROUTE

#include "ip_forward.h"

enum dp_rt_path_state
dp_rt_signal_check_paths_state(const struct dp_rt_path_unusable_key *key);

#endif /* IP_ROUTE_H */
