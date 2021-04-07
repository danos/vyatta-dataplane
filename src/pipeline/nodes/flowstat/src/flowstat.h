/*
 * Flow stat pipeline feature node
 *
 * Copyright (c) 2021, SafePoint.  All rights reserved.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef FLOWSTAT_H
#define FLOWSTAT_H

#ifdef UNIT_TEST
#define FLOWSTAT_LOG "/tmp/flowstat_test.log"
#define LOG_ES_SESSION_INTERVAL 2
#else
#define FLOWSTAT_LOG "/var/log/flowstat.log"
#define LOG_ES_SESSION_INTERVAL 60
#endif

/* Used by unit-test */
void export_log(void);

#endif
