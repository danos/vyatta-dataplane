/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Peter W. Morreale
 *
 * dataplane UT Session test lib
 */

#include <libmnl/libmnl.h>
#include <linux/random.h>
#include <netinet/in.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "urcu.h"
#include "main.h"
#include "session/session.h"
#include "session/session_feature.h"
#include "npf/npf.h"
#include "npf/npf_cache.h"
#include "npf/npf_session.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_session_internal_lib.h"


int _dp_test_session_establish(struct rte_mbuf *m, const struct ifnet *ifp,
		uint32_t timeout, struct session **se, bool *created,
		const char *file, int line)
{
	int rc;
	struct session *s = NULL;

	rc = session_establish(m, ifp, timeout, &s, created);

	if (*created) {
		_dp_test_fail_unless(s, file, line,
			"session establish, no session\n");
		_dp_test_fail_unless(s->se_timeout == timeout,
			file, line, "session establish, bad timeout\n");
		_dp_test_fail_unless(s->se_link == NULL, file, line,
			"session establish: link defined\n");
		_dp_test_fail_unless(s->se_vrfid == pktmbuf_get_vrf(m),
				file, line,
				"session establish: bad session vrfid\n");
		_dp_test_fail_unless(rte_atomic16_read(&s->se_link_cnt) == 0,
			file, line, "session establish: bad link cnt %u\n",
			rte_atomic16_read(&s->se_link_cnt));
		_dp_test_fail_unless(rte_atomic16_read(&s->se_sen_cnt) == 2,
			file, line,
			"session establish: bad sentry cnt %u\n",
			rte_atomic16_read(&s->se_sen_cnt));
		_dp_test_fail_unless(
			rte_atomic16_read(&s->se_feature_count) == 0,
			file, line, "session establish: bad feature cnt %u\n",
			rte_atomic16_read(&s->se_feature_count));
	}
	*se = s;

	return rc;
}

/* Certain test want this to fail, only for continuity */
int _dp_test_session_lookup(struct rte_mbuf *m, uint32_t if_index,
		struct session **se, bool *forw)
{
	return session_lookup(m, if_index, se, forw);
}

void _dp_test_session_expire(struct session *s, struct rte_mbuf *m,
		const char *file, int line)
{
	session_expire(s, m);

	_dp_test_fail_unless(s->se_flags & SESSION_EXPIRED, file, line,
			"session expire: bad flags: %u\n", s->se_flags);

	/*
	 * If we were linked, ensure that all is cleaned up
	 */
	if (s->se_link) {
		_dp_test_fail_unless(cds_list_empty(&s->se_link->sl_children),
				file, line,
				"session expire: linked children\n");
		_dp_test_fail_unless(cds_list_empty(&s->se_link->sl_link),
				file, line,
				"session expire: still linked\n");
		_dp_test_fail_unless(s->se_link->sl_parent == NULL, file, line,
				"session expire: parent exists\n");
	}

	if (m)
		_dp_test_fail_unless(
			!pktmbuf_mdata_exists(m, PKT_MDATA_SESSION_SENTRY),
			file, line,
			"session expire: pkt not cleared\n");
}

int _dp_test_session_init_sentry_packet(struct sentry_packet *sp,
		uint32_t if_index, uint16_t flags, uint8_t proto,
		vrfid_t vrfid, uint16_t sid, void *saddr,
		uint16_t did, void *daddr, const char *file, int line)
{
	return session_init_sentry_packet(sp, if_index, flags, proto,
			vrfid, sid, saddr, did, daddr);
}


int _dp_test_session_create_from_sentry_packets(struct rte_mbuf *m,
		struct sentry_packet *sp_forw, struct sentry_packet *sp_back,
		const struct ifnet *ifp,
		uint32_t timeout, struct session **se, bool *created,
		const char *file, int line)
{
	int rc;
	struct session *s = NULL;

	rc = session_create_from_sentry_packets(m, sp_forw, sp_back, ifp,
			timeout, &s, created);
	_dp_test_fail_unless((rc == 0 && s), file, line,
			"session create from sentry packets: %d s: %p\n",
			rc, s);
	*se = s;
	return rc;
}

int _dp_test_session_sentry_insert(struct session *s, uint32_t if_index,
		uint16_t flags, uint16_t sid, void *saddr, uint16_t did,
		void *daddr, const char *file, int line)
{
	int rc;
	uint16_t sen_cnt = rte_atomic16_read(&s->se_sen_cnt);

	rc = session_sentry_insert(s, if_index, flags, sid, saddr, did, daddr);

	/*
	 * Only on success, some want the failure returned
	 */
	if (!rc) {
		uint16_t new_sen_cnt = rte_atomic16_read(&s->se_sen_cnt);

		_dp_test_fail_unless(new_sen_cnt - sen_cnt == 1, file, line,
			"session sentry insert: bad sen cnt: %u:%u\n",
			new_sen_cnt, sen_cnt);
	}

	return rc;
}

static int print_sen(struct sentry *sen, void *data)
{
	printf("sentry walk: session: %p flags: %u len: %u\n",
			sen->sen_session, sen->sen_flags, sen->sen_len);
	return 0;

}

static int print_se(struct session *s, void *data)
{
	printf("session walk: session: %p flags: %u link_cnt: %u sen_cnt: %u\n",
			s, s->se_flags, rte_atomic16_read(&s->se_link_cnt),
			rte_atomic16_read(&s->se_sen_cnt));

	return 0;
}

void _dp_test_session_reset(const char *file, int line)
{
	int rc;
	unsigned long sen;
	unsigned long se;

	rc = session_table_destroy_all();

	_dp_test_fail_unless(rc == 0, file, line,
			"session table destroy all: %d\n", rc);

	session_table_counts(&sen, &se);

	if (sen)
		sentry_table_walk(print_sen, NULL);
	if (se)
		session_table_walk(print_se, NULL);

	_dp_test_fail_unless(sen == 0, file, line,
			"session table counts: sentries: %lu\n", sen);
	_dp_test_fail_unless(se == 0, file, line,
			"session table counts: sessions: %lu\n", se);
}

void dp_test_session_reset_session_id(void)
{
	session_reset_session_id();
}

int _dp_test_session_feature_add(struct session *s, uint32_t if_index,
		enum session_feature_type type, void *data,
		const char *file, int line)
{
	int rc;
	uint16_t old = rte_atomic16_read(&s->se_feature_count);
	uint16_t new;

	rc = session_feature_add(s, if_index, type, data);
	if (!rc) {
		new = rte_atomic16_read(&s->se_feature_count);
		_dp_test_fail_unless(new - old == 1, file, line,
			"session feature add: bad counts: %u:%u\n", new, old);
	}
	return rc;
}

int _dp_test_session_feature_request_expiry(struct session *s,
		uint32_t if_index, enum session_feature_type type,
		const char *file, int line)
{
	int rc;
	uint16_t old = rte_atomic16_read(&s->se_feature_exp_count);
	uint16_t new;

	rc = session_feature_request_expiry(s, if_index, type);
	if (!rc) {
		new = rte_atomic16_read(&s->se_feature_exp_count);
		_dp_test_fail_unless(new - old == 1, file, line,
			"session feature add: bad counts: %u:%u\n", old, new);
	}
	return rc;
}

void *_dp_test_session_feature_get(struct session *s, uint32_t if_index,
		enum session_feature_type type)
{
	return session_feature_get(s, if_index, type);
}

static struct session_link *lookup_link(struct session_link *sl,
		struct cds_list_head *head)
{
	struct session_link *tmp;

	cds_list_for_each_entry(tmp, head, sl_link) {
		if (sl == tmp)
			return sl;
	}
	return NULL;
}

int _dp_test_session_link(struct session *parent, struct session *child,
		const char *file, int line)
{
	uint16_t parent_linkcnt = rte_atomic16_read(&parent->se_link_cnt);
	uint16_t child_linkcnt = rte_atomic16_read(&child->se_link_cnt);
	uint16_t new_linkcnt;
	struct session_link *sl;
	int rc;

	rc = session_link(parent, child);
	if (rc)
		return rc;

	new_linkcnt = rte_atomic16_read(&parent->se_link_cnt);
	_dp_test_fail_unless(new_linkcnt - parent_linkcnt == 1, file, line,
			"session link: bad parent link cnt: %u:%u\n",
			new_linkcnt, parent_linkcnt);

	/* Child does not inc */
	new_linkcnt = rte_atomic16_read(&child->se_link_cnt);
	_dp_test_fail_unless(new_linkcnt - child_linkcnt == 0, file, line,
			"session link: bad child link cnt: %u:%u\n",
			new_linkcnt, child_linkcnt);

	/* Must have link structs on both parent and child */
	_dp_test_fail_unless(parent->se_link, file, line,
			"session link: No parent link\n");
	_dp_test_fail_unless(child->se_link, file, line,
			"session link: No child link\n");

	/* Ensure session pointers in the link struct are correct. */
	_dp_test_fail_unless(child->se_link->sl_self == child, file, line,
			"session link: No child self\n");
	_dp_test_fail_unless(child->se_link->sl_parent == parent, file, line,
			"session link: No child parent\n");

	/* Child list link cannot be empty */
	_dp_test_fail_unless(!cds_list_empty(&child->se_link->sl_link),
			file, line, "session link: No child link\n");

	/* Ensure the child is on the parent */
	sl = lookup_link(child->se_link, &parent->se_link->sl_children);
	_dp_test_fail_unless(sl == child->se_link, file, line,
			"session link: child not on parent\n");
	return 0;
}

int _dp_test_session_unlink(struct session *s, const char *file, int line)
{
	struct session_link *sl;
	struct session *parent;
	uint16_t link_cnt;

	/* Not an error if not linked */
	if (!s->se_link)
		return 0;

	/* Not an error if already unlinked */
	parent = s->se_link->sl_parent;
	if (!parent)
		return 0;

	link_cnt = rte_atomic16_read(&parent->se_link_cnt);

	session_unlink(s);

	_dp_test_fail_unless(rte_atomic16_read(&parent->se_link_cnt) ==
			(link_cnt - 1), file, line,
			"session unlink: bad parent link cnt: %u:%u\n",
			link_cnt, rte_atomic16_read(&parent->se_link_cnt));

	_dp_test_fail_unless(s->se_link->sl_parent == NULL, file, line,
			"session unlink: parent not cleared\n");
	_dp_test_fail_unless(cds_list_empty(&s->se_link->sl_link), file, line,
			"session unlink: not unlinked\n");

	sl = lookup_link(s->se_link, &parent->se_link->sl_children);
	_dp_test_fail_unless(sl == NULL, file, line,
			"session unlink: exists on parent\n");
	return 0;
}

/* Simulate running the GC */
void _dp_test_session_gc(const char *file, int line)
{
	session_gc();
}

/* unlink everything */
void _dp_test_session_unlink_all(struct session *s, const char *file, int line)
{
	session_unlink_all(s);

	_dp_test_fail_unless(rte_atomic16_read(&s->se_link_cnt) == 0,
			file, line,
			"session unlink_all: bad link cnt: %u\n",
			rte_atomic16_read(&s->se_link_cnt));

	_dp_test_fail_unless(cds_list_empty(&s->se_link->sl_link), file, line,
			"session unlink_all: not unlinked\n");
}
