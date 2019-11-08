/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef HOTPLUG_H
#define HOTPLUG_H

int detach_device(const char *name);
int attach_device(const char *name);

#endif /* HOTPLUG_H */
