/*
 * Path monitor dataplane code
 *
 * Copyright (c) 2017-2019,2021, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef PATHMONITOR_H
#define PATHMONITOR_H

/* Possible states for a pathmon entry.
 */
enum pathmon_status {
	PM_COMPLIANT,
	PM_NONCOMPLIANT,
	PM_DEFAULT = PM_NONCOMPLIANT
};


/* Client registration for the named pathmon entry.
 *
 * Return: handle to pathmon entry.
 */
struct pathmon_entry_t *pathmon_register(const char *name);

/* Client deregistration for the specified pathmonitor entry.
 */
void pathmon_deregister(struct pathmon_entry_t *entry);

/* Return the compliance status of the specified pathmon entry. */
enum pathmon_status pathmon_get_status(struct pathmon_entry_t *entry);

#endif /* PATHMONITOR_H */
