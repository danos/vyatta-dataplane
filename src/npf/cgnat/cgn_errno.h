/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * CGNAT error numbers.  We try to account for every packet disposition in
 * both directions.
 */

#ifndef _CGN_ERRNO_H_
#define _CGN_ERRNO_H_


/*
 * cgnat error numbers
 *
 * To some extent these have been ordered in the order they are most likely to
 * appear, and also grouped into logical blocks relating to the type of
 * exception.
 *
 * Any error or exception starting "CGN_S2_" do not prevent translation.  They
 * just mean a nested session was not created and activated.
 */
enum cgn_errno {
	CGN_OK = 0,

	/*
	 * Operational or config decisions
	 */
	CGN_PCY_ENOENT,	/* Src did not match policy */
	CGN_SESS_ENOENT, /* Inbound pkt did not match a session */

	/*
	 * Packet buffer exceptions
	 */
	CGN_BUF_PROTO,	/* Untranslatable protocol type */
	CGN_BUF_ICMP,	/* ICMP other than ECHO or ECHO REPLY */

	/*
	 * Resource limitations
	 */
	CGN_MBU_ENOSPC,	 /* Subscriber port-block limit */
	CGN_BLK_ENOSPC,	 /* No free blocks on apm */
	CGN_POOL_ENOSPC, /* No free addrs in NAT pool */
	CGN_SRC_ENOSPC,	 /* Subscriber table full */
	CGN_APM_ENOSPC,	 /* apm table full */
	CGN_S1_ENOSPC,	 /* 3-tuple session table full */
	CGN_S2_ENOSPC,	 /* 2-tuple session table full */

	/*
	 * Memory allocation errors
	 */
	CGN_S1_ENOMEM,	/* Failed to alloc outer session */
	CGN_S2_ENOMEM,	/* Failed to alloc inner session */
	CGN_PB_ENOMEM,	/* Failed to alloc port block */
	CGN_APM_ENOMEM,	/* Failed to alloc apm */
	CGN_SRC_ENOMEM,	/* Failed to alloc src */

	/*
	 * Thread contention errors or races
	 */
	CGN_S1_EEXIST,	/* Lost race to insert sentry in table */
	CGN_S2_EEXIST,	/* Lost race to insert sentry in table */
	CGN_APM_ENOENT,	/* apm destroyed while waiting for lock */
	CGN_SRC_ENOENT,	/* src destroyed while waiting for lock */

	/*
	 * Packet buffer errors
	 */
	CGN_BUF_ENOL3,	/* IP header not available */
	CGN_BUF_ENOL4,	/* L4 header not available */
	CGN_BUF_ENOMEM,	/* Prep for hdr change failed */
	CGN_BUF_ENOSPC,	/* Cannot advance beyond end of buffer */

	/*
	 * Other
	 */
	CGN_ERR_UNKWN,	/* Unknown error */
};

#define CGN_ERRNO_LAST	CGN_ERR_UNKWN
#define CGN_ERRNO_SZ	(CGN_ERRNO_LAST + 1)

extern rte_atomic64_t cgn_errors[][CGN_ERRNO_SZ];

static inline const char *cgn_errno_str(int error)
{
	if (error < 0)
		error = -error;

	switch (error) {
	case CGN_OK:
		return "ok";
	case CGN_SRC_ENOMEM:
		return "SRC_ENOMEM";
	case CGN_SRC_ENOENT:
		return "SRC_ENOENT";
	case CGN_MBU_ENOSPC:
		return "MBU_ENOSPC";
	case CGN_SRC_ENOSPC:
		return "SRC_ENOSPC";
	case CGN_APM_ENOMEM:
		return "APM_ENOMEM";
	case CGN_APM_ENOSPC:
		return "APM_ENOSPC";
	case CGN_BLK_ENOSPC:
		return "BLK_ENOSPC";
	case CGN_APM_ENOENT:
		return "APM_ENOENT";
	case CGN_PB_ENOMEM:
		return "PB_ENOMEM";
	case CGN_S1_ENOSPC:
		return "S1_ENOSPC";
	case CGN_S2_ENOSPC:
		return "S2_ENOSPC";
	case CGN_S1_EEXIST:
		return "S1_EEXIST";
	case CGN_S1_ENOMEM:
		return "S1_ENOMEM";
	case CGN_BUF_ENOL3:
		return "BUF_ENOL3";
	case CGN_BUF_ENOL4:
		return "BUF_ENOL4";
	case CGN_BUF_ENOMEM:
		return "BUF_ENOMEM";
	case CGN_BUF_ENOSPC:
		return "BUF_ENOSPC";
	case CGN_BUF_ICMP:
		return "BUF_ICMP";
	case CGN_BUF_PROTO:
		return "BUF_PROTO";
	case CGN_PCY_ENOENT:
		return "PCY_ENOENT";
	case CGN_SESS_ENOENT:
		return "SESS_ENOENT";
	case CGN_POOL_ENOSPC:
		return "POOL_ENOSPC";
	case CGN_S2_EEXIST:
		return "S2_EEXIST";
	case CGN_S2_ENOMEM:
		return "S2_ENOMEM";
	case CGN_ERR_UNKWN:
		return "ERR_UNKWN";
	}
	return "ERR_UNKWN2";
}

static inline const char *cgn_errno_detail_str(int error)
{
	if (error < 0)
		error = -error;

	switch (error) {
	case CGN_OK:
		return "ok";

	/*
	 * Operational or config decisions
	 */
	case CGN_PCY_ENOENT:
		return "Subscriber address did not match a CGNAT policy";
	case CGN_SESS_ENOENT:
		return "Packet did not match a CGNAT session";

	/*
	 * Packet buffer exceptions
	 */
	case CGN_BUF_PROTO:
		return "Untranslatable IP protocol";
	case CGN_BUF_ICMP:
		return "Untranslatable ICMP message";

	/*
	 * Resource limitations
	 */
	case CGN_MBU_ENOSPC:
		return "Subscriber port-block limit";
	case CGN_SRC_ENOSPC:
		return "Subscriber table full";
	case CGN_BLK_ENOSPC:
		return "No free port-blocks on selected public address";
	case CGN_APM_ENOSPC:
		return "Mapping table full";
	case CGN_POOL_ENOSPC:
		return "No free public addresses in NAT pool";
	case CGN_S1_ENOSPC:
		return "Session table full";
	case CGN_S2_ENOSPC:
		return "Dest session table full";

	/*
	 * Memory allocation errors
	 */
	case CGN_S1_ENOMEM:
		return "Failed to allocate session";
	case CGN_S2_ENOMEM:
		return "Failed to allocate destination session";
	case CGN_PB_ENOMEM:
		return "Failed to allocate port block";
	case CGN_APM_ENOMEM:
		return "Failed to allocate public address";
	case CGN_SRC_ENOMEM:
		return "Failed to allocate subscriber address";

	/*
	 * Thread contention errors or races
	 */
	case CGN_S1_EEXIST:
		return "Lost race to insert session into table";
	case CGN_S2_EEXIST:
		return "Lost race to insert destination session into table";
	case CGN_APM_ENOENT:
		return "Public address destroyed while waiting "
			"for lock";
	case CGN_SRC_ENOENT:
		return "Subscriber address destroyed while "
			"waiting for lock";

	/*
	 * Packet buffer errors
	 */
	case CGN_BUF_ENOL3:
		return "IP header not available in message buffer";
	case CGN_BUF_ENOL4:
		return "L4 header not available in message buffer";
	case CGN_BUF_ENOMEM:
		return "Prepare message buffer for header change failed";
	case CGN_BUF_ENOSPC:
		return "Cannot advance beyond end of message buffer";

	/*
	 * Other
	 */
	case CGN_ERR_UNKWN:
		return "Unknown error";
	}
	return "Unknown";
}

void cgn_error_inc(int error, int dir);

#endif
