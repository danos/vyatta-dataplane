/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Unit-tests for ESP functions
 *
 *
 */

#include "dp_test.h"
#include "dp_test_lib_internal.h"

#include "crypto/crypto_internal.h"
#include "crypto/esp.h"

struct esp_header {
	uint32_t spi;
	uint32_t seq;
};

DP_DECL_TEST_SUITE(esp_replay_suite);

DP_DECL_TEST_CASE(esp_replay_suite, sequence_number_check, NULL, NULL);

/*
 * Are various combinations of incoming sequence number and prior
 * window state handled by the replay check function?
 */
DP_START_TEST(sequence_number_check, sequence_number_check)
{
	struct sadb_sa sa;
	struct esp_header hdr;
	unsigned int i;

	sa.replay_window = 0;
	sa.replay_bitmap = 0;
	sa.seq = 0;
	sa.spi = 0;
	hdr.spi = 0;
	hdr.seq = 1;

	dp_test_fail_unless((esp_replay_check((uint8_t *) &hdr, &sa) == 0),
			    "check defaults if no replay window is set");

	hdr.seq = 0;
	sa.replay_window = 32;

	dp_test_fail_unless((esp_replay_check((uint8_t *) &hdr, &sa) == -1),
			    "check should fail if sequence number is zero");

	sa.seq = 10;
	hdr.seq = htonl(11);

	dp_test_fail_unless((esp_replay_check((uint8_t *) &hdr, &sa) == 0),
			    "check should pass if sequence number "
			    "is to the right of the window");

	sa.seq = 43;
	hdr.seq = htonl(sa.seq - (sa.replay_window + 1));

	dp_test_fail_unless((esp_replay_check((uint8_t *) &hdr, &sa) == -2),
			    "check should fail if sequence number "
			    "is to the left of the window");
	sa.seq = 43;
	hdr.seq = htonl(sa.seq - (sa.replay_window));

	dp_test_fail_unless((esp_replay_check((uint8_t *) &hdr, &sa) == -2),
			    "check should fail if sequence number "
			    "is to the left of the window");

	sa.replay_bitmap = 0;
	sa.seq = 128;
	hdr.seq = htonl(sa.seq - 31);

	for (i = 0; i < 32; i++) {
		dp_test_fail_unless((esp_replay_check((uint8_t *) &hdr,
						      &sa) == 0),
				    "check should pass if sequence number (%d) "
				    "is new and within window", ntohl(hdr.seq));
		hdr.seq = htonl(ntohl(hdr.seq) + 1);
	}

	sa.replay_bitmap = 5;
	hdr.seq = htonl(1);
	sa.seq = 3;

	dp_test_fail_unless(esp_replay_check((uint8_t *) &hdr, &sa) == -3,
			    "check should fail if sequence number (%d) "
			    "is _not_ new and within window", i);

	hdr.seq = htonl(2);

	dp_test_fail_unless((esp_replay_check((uint8_t *) &hdr, &sa) == 0),
			    "check should pass if sequence number (%d) "
			    "is new and within window", i);

	hdr.seq = htonl(3);

	dp_test_fail_unless((esp_replay_check((uint8_t *) &hdr, &sa) == -3),
			    "check should fail if sequence number (%d) "
			    "Is _not_ new and within window", i);
} DP_END_TEST;

DP_DECL_TEST_CASE(esp_replay_suite, sequence_number_advance, NULL, NULL);

/*
 * Are various combinations of incoming sequence number and existing
 * window state handled by the advance function?
 */
DP_START_TEST(sequence_number_advance, sequence_number_advance)
{
	struct sadb_sa sa;
	struct esp_header hdr;

	sa.replay_window = 3;
	sa.replay_bitmap = 0;
	sa.seq = 0;
	hdr.spi = 0;
	hdr.seq = htonl(1);

	esp_replay_advance((uint8_t *) &hdr, &sa);
	dp_test_fail_unless((sa.seq == 1),
			    "sequence number failed to advance to 1");
	dp_test_fail_unless((sa.replay_bitmap == 1), "bitmap should be 1");

	hdr.seq = htonl(2);
	esp_replay_advance((uint8_t *) &hdr, &sa);
	dp_test_fail_unless((sa.seq == 2),
			    "sequence number failed to advance to 2");
	dp_test_fail_unless((sa.replay_bitmap == 3), "bitmap should be 3");

	hdr.seq = htonl(4);
	esp_replay_advance((uint8_t *) &hdr, &sa);
	dp_test_fail_unless((sa.seq == 4),
			    "sequence number failed to advance to 4");
	dp_test_fail_unless((sa.replay_bitmap == 13), "bitmap should be 13");

	hdr.seq = htonl(3);
	esp_replay_advance((uint8_t *) &hdr, &sa);
	dp_test_fail_unless((sa.seq == 4),
			    "sequence number should still be 4");
	dp_test_fail_unless((sa.replay_bitmap == 15), "bitmap should be 15");

	hdr.seq = htonl(5);
	esp_replay_advance((uint8_t *) &hdr, &sa);
	dp_test_fail_unless((sa.seq == 5),
			    "sequence number failed to advance to 5");
	dp_test_fail_unless((sa.replay_bitmap == 31), "bitmap should be 31");

	hdr.seq = htonl(7);
	esp_replay_advance((uint8_t *) &hdr, &sa);
	dp_test_fail_unless((sa.seq == 7),
			    "sequence number failed to advance to 7");
	dp_test_fail_unless((sa.replay_bitmap == 125), "bitmap should be 125");
} DP_END_TEST;
