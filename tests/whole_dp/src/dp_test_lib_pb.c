/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "dp_test_lib_pb.h"

#include "protobuf.h"
#include "protobuf_util.h"
#include "protobuf/IPAddress.pb-c.h"

void dp_test_lib_pb_set_ip_addr(IPAddress *addr, const char *str, void *data)
{
	struct dp_test_addr test_addr;

	if (!dp_test_addr_str_to_addr(str, &test_addr))
		dp_test_assert_internal(0);
	switch (test_addr.family) {
	case AF_INET:
		addr->address_oneof_case =
			IPADDRESS__ADDRESS_ONEOF_IPV4_ADDR;
		addr->ipv4_addr = test_addr.addr.ipv4;
		break;
	case AF_INET6:
		addr->address_oneof_case =
			IPADDRESS__ADDRESS_ONEOF_IPV6_ADDR;

		/* Use the data passed in */
		addr->ipv6_addr.data = data;
		memcpy(addr->ipv6_addr.data, &test_addr.addr.ipv6,
		       16);
		addr->ipv6_addr.len = 16;
		break;
	default:
		dp_test_assert_internal(0);
	}
}


void dp_test_lib_pb_wrap_and_send_pb(const char *str,
				     void *data, size_t data_len)
{
	DataplaneEnvelope msg = DATAPLANE_ENVELOPE__INIT;
	void *buf;
	size_t len;
	size_t packed_len;

	msg.type = strdup(str);
	dp_test_assert_internal(msg.type);

	msg.msg.data = data;
	msg.msg.len = data_len;

	len = dataplane_envelope__get_packed_size(&msg);

	buf = malloc(len);
	dp_test_assert_internal(buf);

	packed_len = dataplane_envelope__pack(&msg, buf);
	dp_test_assert_internal(len == packed_len);

	dp_test_send_config_src_pb(dp_test_cont_src_get(), buf, len);

	free(msg.type);
	free(buf);
	free(data);
}
