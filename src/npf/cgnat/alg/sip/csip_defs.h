/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef CSIP_DEFS_H
#define CSIP_DEFS_H

/*
 * SIP Request Methods.  There are 14 Request methods.  SIP_REQ_OTHER is used
 * to classify any that we do not recognise.
 */
enum csip_req {
	SIP_REQ_NONE,
	SIP_REQ_OTHER,
	SIP_REQ_INVITE,
	SIP_REQ_ACK,
	SIP_REQ_BYE,
	SIP_REQ_CANCEL,
	SIP_REQ_REGISTER,
	SIP_REQ_OPTIONS,
	/* Above are the most basic methods defined in rfc3261 */
	SIP_REQ_PRACK,
	SIP_REQ_SUBSCRIBE,
	SIP_REQ_NOTIFY,
	SIP_REQ_PUBLISH,
	SIP_REQ_INFO,
	SIP_REQ_REFER,
	SIP_REQ_MESSAGE,
	SIP_REQ_UPDATE,
};

#define SIP_REQ_FIRST		SIP_REQ_INVITE
#define SIP_REQ_LAST		SIP_REQ_UPDATE
#define SIP_REQ_MAX		(SIP_REQ_LAST + 1)

#endif /* CSIP_DEFS_H */
