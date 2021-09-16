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

/*
 * Each line in a SIP message is classified as one of the following
 */
enum csip_line_type {
	SIP_LINE_NONE,
	SIP_LINE_REQ,	/* Request start line */
	SIP_LINE_RESP,	/* Response start line */
	SIP_LINE_SIP,	/* SIP header line */
	SIP_LINE_SEPARATOR, /* Separates SIP and SDP parts */
	SIP_LINE_SDP,	/* SDP header line */
};

/*
 * SIP message header fields that the ALG might be interested in.  Note, this
 * is *not* a complete list of the 40+ possible headers.
 *
 * Headers not in this list will simply be copied from the original to the
 * translation message buffers.  Not all the headers in this list will be
 * translated.  Some are only picked-out in order to glean information from
 * that header (e.g. Call-ID and Content-Type).
 */
enum csip_hdr_type {
	SIP_HDR_NONE,
	SIP_HDR_SEP,		/* Separator */
	SIP_HDR_OTHER,		/* A header we are not interested in */

	SIP_HDR_VIA,		/* Via */
	SIP_HDR_ROUTE,		/* Route */
	SIP_HDR_RR,		/* Record-route */
	SIP_HDR_FROM,		/* From */
	SIP_HDR_TO,		/* To */
	SIP_HDR_CALLID,		/* Call-ID */
	SIP_HDR_CONTACT,	/* Contact */
	SIP_HDR_UA,		/* User-agent */
	SIP_HDR_CTYPE,		/* Content-Type */
	SIP_HDR_CLEN,		/* Content-Length */
};

/* First and last actual values */
#define SIP_HDR_FIRST	SIP_HDR_VIA
#define SIP_HDR_LAST	SIP_HDR_CLEN
#define SIP_HDR_MAX	(SIP_HDR_LAST + 1)

#endif /* CSIP_DEFS_H */
