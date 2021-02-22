/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2013-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <netinet/in.h>
#include <rte_log.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>

#include "config_internal.h"
#include "main.h"

static ssize_t
do_log_write(__unused void *c, const char *buf, size_t bufsize)
{
	const char *cp, *ep;
	uint32_t loglevel;
	size_t size = bufsize;

	/* truncate message if too big (should not happen) */
	if (size > BUFSIZ)
		size = BUFSIZ;

	/*
	 * At most one '\n' should be in the buffer due to the stream being in
	 * line buffered mode, if there are any characters after the '\n'
	 * discard them.
	 *
	 * NB: It is possible in odd cases to have multiple newlines,
	 * e.g. "foo\n\n"  appears in one call to this routine.
	 *
	 * The callback API suggests we should be able to leave the extra
	 * characters in the buffer for next time by returning a short count,
	 * however glibc does not honour that - always treating all characters
	 * as consumed.
	 */
	for (cp = buf + size - 1; cp > buf; --cp)
		if (*cp == '\n') {
			size = cp - buf + 1;
			break;
		}
	if (*cp != '\n')
		return bufsize;

	char dp_id_name[INET6_ADDRSTRLEN+3];

	if (!is_local_controller()) {
		snprintf(dp_id_name, sizeof(dp_id_name), "dp%u", 0u);
	}

	/* Syslog error levels are from 0 to 7, so subtract 1 to convert */
	loglevel = rte_log_cur_msg_loglevel() - 1;

	/* Handle messages with new lines as multiple messages */
	for (cp = buf; (ep = memchr(cp, '\n', size)); cp = ep) {
		size_t len = ++ep - cp;
		if (*cp != '\n') {			/* drop empty lines */
			if (is_local_controller())
				syslog(loglevel, "%.*s", (int)len-1, cp);
			else
				syslog(loglevel, "%s: %.*s",
					dp_id_name, (int)len-1, cp);
		}
		size -= len;
	}

	return bufsize;
}

static cookie_io_functions_t local_log_func = {
	.write = do_log_write,
};

int open_log(void)
{
	FILE *stream = fopencookie(NULL, "w", local_log_func);
	if (stream == NULL)
		return -1;
	/* fopencookie() defaults to fully buffered */
	setvbuf(stream, NULL, _IOLBF, 0);

	return rte_openlog_stream(stream);
}
