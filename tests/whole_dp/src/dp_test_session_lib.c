/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <libmnl/libmnl.h>
#include <linux/random.h>
#include <netinet/in.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "dp_session.h"
#include "npf/npf_pack.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_session_internal_lib.h"

#include "dp_test/dp_test_session_lib.h"

void *_dp_test_session_msg_unpack_pb(void *buf, uint32_t size,
				  const char *file, int line)
{
	PackedDPSessionMsg *psm = npf_unpack_pb(buf, size);
	_dp_test_fail_unless((psm != NULL), file, line,
			      "npf_pack protobuf invalid\n");
	return psm;
}

void _dp_test_session_msg_free_unpack_pb(void *buf, const char *file, int line)
{
	_dp_test_fail_unless((buf != NULL), file, line,
			      "NULL pointer in free unpack pb\n");
	npf_unpack_free_pb(buf);
}

void _dp_test_session_msg_valid(void *msg, uint32_t size,
				const char *file, int line)
{
	struct npf_pack_message *n_msg = msg;
	if (is_npf_pack_pb_version(n_msg->hdr.pmh_version)) {
		PackedDPSessionMsg *psm;
		psm = _dp_test_session_msg_unpack_pb(msg, size, file, line);
		_dp_test_fail_unless(psm != NULL, file, line,
				"Invalid npf_protobuf message\n");
		_dp_test_session_msg_free_unpack_pb(psm, file, line);
		return;
	}

	_dp_test_fail_unless(npf_pack_validate_msg(n_msg, size), file, line,
				"npf_pack message invalid\n");
}

bool _dp_test_session_msg_full(void *msg,
				const char *file, int line)
{
	struct npf_pack_message *n_msg = msg;

	if (npf_pack_get_msg_type(n_msg) == SESSION_PACK_FULL)
		return true;
	return false;
}

bool _dp_test_session_msg_update(void *msg,
				const char *file, int line)
{
	struct npf_pack_message *n_msg = msg;

	if (npf_pack_get_msg_type(n_msg) == SESSION_PACK_UPDATE)
		return true;
	return false;
}

static uint64_t _dp_test_session_msg_get_id_pb(void *msg, uint32_t size,
					       const char *file, int line)
{
	PackedDPSessionMsg *psm;
	DPSessionMsg *dpsm;
	uint64_t id;

	psm = _dp_test_session_msg_unpack_pb(msg, size, file, line);
	_dp_test_fail_unless(psm != NULL, file, line,
			"Invalid npf_protobuf message\n");
	_dp_test_fail_unless((psm->n_pds_sessions > 0 && psm->pds_sessions[0]),
		file, line, "protobuf has no session\n");
	dpsm = psm->pds_sessions[0];
	_dp_test_fail_unless(dpsm->has_ds_id, file, line,
			"protobuf has no session id\n");
	id = dpsm->ds_id;
	_dp_test_session_msg_free_unpack_pb(psm, file, line);
	return id;
}

uint64_t _dp_test_session_msg_get_id(void *msg,
				const char *file, int line)
{
	struct npf_pack_message *n_msg = msg;
	if (is_npf_pack_pb_version(n_msg->hdr.pmh_version))
		return _dp_test_session_msg_get_id_pb(msg, n_msg->hdr.pmh_len,
						      file, line);

	return npf_pack_get_session_id(n_msg);
}

void _dp_test_session_msg_get_cntrs_pb(void *msg, uint32_t size,
				       uint64_t *pkts_in, uint64_t *bytes_in,
				       uint64_t *pkts_out, uint64_t *bytes_out,
				       const char *file, int line)
{
	PackedDPSessionMsg *psm;
	DPSessionMsg *dpsm;
	DPSessionCounterMsg *cntrs;

	psm = _dp_test_session_msg_unpack_pb(msg, size, file, line);
	_dp_test_fail_unless(psm != NULL, file, line,
			"Invalid npf_protobuf message\n");
	_dp_test_fail_unless((psm->n_pds_sessions > 0 && psm->pds_sessions[0]),
		file, line, "protobuf has no session\n");
	dpsm = psm->pds_sessions[0];
	_dp_test_fail_unless(dpsm->has_ds_id, file, line,
			"protobuf has no session id\n");
	cntrs = dpsm->ds_counters;
	if (pkts_in)
		*pkts_in = cntrs->sc_pkts_in;
	if (bytes_in)
		*bytes_in = cntrs->sc_bytes_in;
	if (pkts_out)
		*pkts_out = cntrs->sc_pkts_out;
	if (bytes_out)
		*bytes_out = cntrs->sc_bytes_out;
	_dp_test_session_msg_free_unpack_pb(psm, file, line);
}

void _dp_test_session_msg_get_cntrs(void *msg,
				    uint64_t *pkts_in, uint64_t *bytes_in,
				    uint64_t *pkts_out, uint64_t *bytes_out,
				    const char *file, int line)
{
	struct npf_pack_message *n_msg = msg;
	struct npf_pack_dp_sess_stats *stats;

	if (is_npf_pack_pb_version(n_msg->hdr.pmh_version)) {
		_dp_test_session_msg_get_cntrs_pb(msg, n_msg->hdr.pmh_len,
			pkts_in, bytes_in, pkts_out, bytes_out, file, line);
		return;
	}

	stats = npf_pack_get_session_stats(n_msg);
	_dp_test_fail_unless(stats, file, line,
			"Couldn't get stats from npf_pack message\n");
	if (pkts_in)
		*pkts_in = stats->pdss_pkts_in;
	if (bytes_in)
		*bytes_in = stats->pdss_bytes_in;
	if (pkts_out)
		*pkts_out = stats->pdss_pkts_out;
	if (bytes_out)
		*bytes_out = stats->pdss_bytes_out;
}

void _dp_test_session_msg_check_rcvd(void *msg,
				uint64_t pkts_per_session,
				struct dp_test_session sess[],
				const char *file, int line)
{
	int i;
	uint64_t se_id;
	struct npf_pack_message *n_msg = msg;
	uint64_t pkts_in = 0;
	uint64_t pkts_out = 0;

	_dp_test_fail_unless(sess, file, line,
			"npf_pack sess input invalid\n");

	_dp_test_fail_unless(is_npf_pack_pb_version(n_msg->hdr.pmh_version),
			file, line, "Unexpected protobuf version\n");
	se_id = _dp_test_session_msg_get_id_pb(n_msg,
				n_msg->hdr.pmh_len, file, line);
	_dp_test_session_msg_get_cntrs_pb(msg, n_msg->hdr.pmh_len,
				&pkts_in, NULL,
				&pkts_out, NULL, file, line);

	if (pkts_in == pkts_per_session &&
	    pkts_out == pkts_per_session) {
		for (i = 0; i < DP_TEST_MAX_TEST_SESSIONS; i++) {
			if (sess[i].se_id == se_id) {
				sess[i].completed = true;
				return;
			}
		}
		for (i = 0; i < DP_TEST_MAX_TEST_SESSIONS; i++) {
			if (sess[i].se_id == 0) {
				sess[i].se_id = se_id;
				sess[i].completed = true;
				return;
			}
		}
	}
}

bool _dp_test_session_msg_pulled_all(void *msg,
				uint64_t pkts_per_session,
				struct dp_test_session sess[],
				const char *file, int line)
{
	int i;
	struct npf_pack_message *n_msg = msg;

	_dp_test_fail_unless(sess, file, line,
			"npf_pack sess input invalid\n");
	dp_test_session_msg_check_rcvd(n_msg, pkts_per_session, sess);

	for (i = 0; i < DP_TEST_MAX_TEST_SESSIONS; i++) {
		if (sess[i].completed == false)
			return false;
	}
	return true;
}
