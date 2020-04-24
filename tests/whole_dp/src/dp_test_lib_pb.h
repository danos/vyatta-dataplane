/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef DP_TEST_LIB_PB
#define DP_TEST_LIB_PB

#include <stdbool.h>

#include "dp_test.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_cmd.h"
#include "dp_test_console.h"
#include "dp_test_controller.h"
#include "dp_test_netlink_state_internal.h"

#include "protobuf.h"
#include "protobuf_util.h"
#include "protobuf/DataplaneEnvelope.pb-c.h"

/* Helpers to manage interactions with protobufs */

/*
 * Given an ip address (either v4 or v6) in string format, populate
 * the protobuf formatted addr.
 *
 * @param addr        [out] The protobuf address structure to be populated.
 * @param str         [in]  The address, formatted as a string that is to be
 *                          populated into the address.
 * @param data        [out] A scratch buffer of at least 16 bytes that is
 *                          used in the case when the string is a V6 address
 *                          as the addr needs space to store the address.
 *
 * Populate the addr with the address in the string, using the 'data' as the
 * storage for this in the case of an IPv6 address. This is done to avoid
 * having this function doing a malloc for the data and the requirement to
 * then free it.
 */
void dp_test_lib_pb_set_ip_addr(IPAddress *addr, const char *str, void *data);


#endif /* DP_TEST_LIB_PB */
