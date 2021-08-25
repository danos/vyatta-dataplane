/*
 * Copyright (c) 2019,2021, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane test portmonitor library
 */

#ifndef __DP_TEST_LIB_PORTMONITOR_H__
#define __DP_TEST_LIB_PORTMONITOR_H__

#include <stdint.h>
#include <stdbool.h>
#include <json-c/json.h>


#define dp_test_portmonitor_request(cmd, debug)				\
	_dp_test_portmonitor_request(cmd, debug, __FILE__, __LINE__)

void
_dp_test_portmonitor_request(const char *cmd, bool print,
				const char *file, int line);

void
dp_test_portmonitor_create_filter(const char *filter, uint32_t rule, bool pass,
				const char *fromaddr, const char *toaddr);

void
dp_test_portmonitor_delete_filter(const char *filter);

void
dp_test_portmonitor_attach_filter(const char *filter, const char *type,
				const char *intf);

void
dp_test_portmonitor_detach_filter(const char *filter, const char *type,
				const char *intf);

void
dp_test_portmonitor_delete_session(uint32_t sessionid);

void
dp_test_portmonitor_create_span(uint32_t id, const char *srcif,
				const char *dstif, const char *ifilter,
				const char *ofilter);

void
dp_test_portmonitor_create_rspansrc(uint32_t id, const char *srcif,
				const char *dstif, uint8_t vid,
				const char *ifilter, const char *ofilter);

void
dp_test_portmonitor_create_rspandst(uint32_t id, const char *srcif,
				uint8_t vid, const char *dstif);

void
dp_test_portmonitor_create_erspansrc(uint32_t id, const char *srcif,
				const char *dstif, uint16_t erspanid,
				uint8_t erspanhdr, const char *ifilter,
				const char *ofilter);

void
dp_test_portmonitor_create_erspandst(uint32_t id, const char *srcif,
				const char *dstif, uint16_t erspanid,
				uint8_t erspanhdr);

#endif /* DP_TEST_LIB_PORTMONITOR_H */
