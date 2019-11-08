/*-
 * Copyright (c) 2017-2018, AT&T Intellectual Property.
 * All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef BRIDGE_FLAGS_H
#define BRIDGE_FLAGS_H

/* Bridge STP port states */
enum bridge_ifstate {
	STP_IFSTATE_DISABLED,
	STP_IFSTATE_LISTENING,
	STP_IFSTATE_LEARNING,
	STP_IFSTATE_FORWARDING,
	STP_IFSTATE_BLOCKING,
	__STP_IFSTATE_MAX
};

#define STP_IFSTATE_MAX (__STP_IFSTATE_MAX - 1)
#define STP_IFSTATE_SIZE (STP_IFSTATE_MAX + 1)

/*
 * External (FAL) symbols associated with (M)STP
 */
#define STP_INST_COUNT 16
#define STP_INST_MAX   (STP_INST_COUNT - 1)
#define STP_INST_IST   0

#endif /* BRIDGE_FLAGS_H */
