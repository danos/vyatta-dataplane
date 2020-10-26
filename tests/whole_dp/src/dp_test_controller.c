/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * A test controller for the dataplane test harness.
 * This file provides a minimal implementation of a controller
 * so that the dataplane can be programmed.
 *
 * The majority of this file is copied from controller source.
 */

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include <libmnl/libmnl.h>
#include <czmq.h>
#include <syslog.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <ini.h>
#include <pthread.h>

#include "main.h"
#include "if_var.h"
#include "compat.h"

#include "dp_test_controller.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_json_utils.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test.h"
#include "dp_test_route_broker.h"

uint64_t nl_msg_seqno;

struct dp_test_cont_info {
	zactor_t *req_actor;
	zsock_t *pub_sock;
	char *pub_url;
};

static struct dp_test_cont_info cont_info[CONT_SRC_COUNT];

uint32_t dp_test_ctrl_debug;

void
dp_test_controller_debug_set(int debug_val)
{
	dp_test_ctrl_debug = debug_val;
}

/* All zero's in IPv4 or IPv6 */
static const char anyaddr[16];

void logit(int level, char c, const char *format, ...)
	__attribute__((format(printf, 3, 4)));
#define dbg(format, args...)						\
	do {								\
		if (dp_test_ctrl_debug)                                 \
			logit(LOG_DEBUG, 'D', format, ##args);	        \
	} while (0)

#define info(format, args...)   logit(LOG_INFO, 'I', format, ##args)
#define notice(format, args...) logit(LOG_NOTICE, 'N', format, ##args)
#define err(format, args...)    logit(LOG_ERR, 'E', format, ##args)

void logit(int level, char c, const char *format, ...)
{
	char line[DP_TEST_TMP_BUF];
	va_list ap;

	va_start(ap, format);
	vsnprintf(line, sizeof(line), format, ap);
	va_end(ap);


	printf("%s", line);
}

typedef struct _snapshot snapshot_t;
struct _snapshot {
	uint64_t last_seqno;

	zhash_t *link;
	zhash_t *vlan;
	zhash_t *bridge_link;
	zhash_t *address;
	zhash_t *route;
	zhash_t *neighbour;
	zhash_t *netconf;
	zhash_t *xfrm;
	zhash_t *l2tp_tunnel;
	zhash_t *l2tp_session;
};

struct _nlmsg {
	int	  refcnt;
	char	  *topic;
	uint64_t  seqno;

	size_t	  size;		/* number of bytes of data */
	byte     data[];	/* variable length */
};
typedef struct _nlmsg nlmsg_t;

/*
 * Construct a netlink message object from
 */
static nlmsg_t *
nlmsg_new(const char *str, uint64_t seqno,
		   const void *data, size_t len)
{
	nlmsg_t *self = malloc(sizeof(*self) + len);
	if (!self)
		return NULL;

	self->refcnt = 1;
	self->topic = strdup(str);
	self->seqno = seqno;
	self->size = len;
	memcpy(self->data, data, len);

	return self;
}

static void
nlmsg_free(nlmsg_t *self)
{
	if (--self->refcnt == 0) {
		free(self->topic);
		free(self);
	}
}

static int
seqno_sendm(zsock_t *socket, uint64_t seqno)
{
	zmsg_t *m = zmsg_new();
	if (zmsg_addmem(m, &seqno, sizeof(uint64_t)) == -1)
		return -1;
	if (zmsg_sendm(&m, socket) == -1)
		return -1;
	return 0;
}

static int
ifindex_sendm(zsock_t *socket, uint32_t ifindex)
{
	zmsg_t *m = zmsg_new();
	if (zmsg_addmem(m, &ifindex, sizeof(uint32_t)) == -1)
		return -1;
	if (zmsg_sendm(&m, socket) == -1)
		return -1;
	return 0;
}

static void
nlmsg_send_free(void *data, void *hint)
{
	if (hint)
		nlmsg_free(hint);
}

/* Send topic/seqno/netlink.
   If successful then destroyed after sending. */
static int
nlmsg_send(nlmsg_t *self, zsock_t *socket, bool broker)
{
	int rc;

	/* Broker message have no topic or seq */
	if (!broker) {
		rc = zstr_sendm(socket, self->topic);
		if (rc)
			goto err;


		rc = seqno_sendm(socket, self->seqno);
		if (rc)
			goto err;
	}

	zmq_msg_t m;
	zmq_msg_init_data(&m, self->data, self->size,
			  nlmsg_send_free, self);

	rc = zmq_msg_send(&m, zsock_resolve(socket), 0);
	if (rc < 0)
		goto err;

	return 0;

 err:
	err("failed to send nlm message (%s)", strerror(errno));
	nlmsg_free(self);
	return rc;
}

static void
nlmsg_dump(const char *prefix, nlmsg_t *self)
{
	unsigned int l = 0;
	char buf[BUFSIZ];

	if (!self)
		return;

	if (prefix) {
		if (dp_test_ctrl_debug > 2)
			l = snprintf(buf, sizeof(buf), "--- %s ---\n", prefix);
		else
			l = snprintf(buf, sizeof(buf), "%s ", prefix);
	}

	l += snprintf(buf + l, sizeof(buf) - l,
		      "[%"PRIu64"] %s",
		      self->seqno, self->topic);

	if (dp_test_ctrl_debug > 2) {
		unsigned int i;

		l += snprintf(buf + l, sizeof(buf) - l,
			      "\n %4zu\t", self->size);
		for (i = 0; i < self->size && i < 32; i++) {
			l += snprintf(buf + l, sizeof(buf) - l,
				      "%02x", self->data[i]);
		}
	}

	zclock_log("Z: %s", buf);
}

static uint64_t
snapshot_seqno(const snapshot_t *self)
{
	return self->last_seqno;
}

static void
snapshot_destroy(snapshot_t **selfp)
{
	snapshot_t *self = *selfp;

	if (self) {
		zhash_destroy(&self->link);
		zhash_destroy(&self->vlan);
		zhash_destroy(&self->bridge_link);
		zhash_destroy(&self->address);
		zhash_destroy(&self->route);
		zhash_destroy(&self->neighbour);
		zhash_destroy(&self->netconf);
		zhash_destroy(&self->xfrm);
		zhash_destroy(&self->l2tp_tunnel);
		zhash_destroy(&self->l2tp_session);
		free(self);
		*selfp = NULL;
	}
}

static snapshot_t *
snapshot_new(void)
{
	snapshot_t *self = malloc(sizeof(snapshot_t));

	if (self) {
		self->last_seqno = 0;
		self->link = zhash_new();
		self->vlan = zhash_new();
		self->bridge_link = zhash_new();
		self->address = zhash_new();
		self->route = zhash_new();
		self->neighbour = zhash_new();
		self->netconf = zhash_new();
		self->xfrm = zhash_new();
		self->l2tp_tunnel = zhash_new();
		self->l2tp_session = zhash_new();

		if (!self->link || !self->vlan || !self->bridge_link ||
		    !self->address || !self->route || !self->neighbour ||
		    !self->netconf || !self->xfrm || !self->l2tp_tunnel ||
		    !self->l2tp_session)
			snapshot_destroy(&self);
	}

	return self;
}

static void
delport_request(zsock_t *sock, zmsg_t *msg, zframe_t **envelope)
{
	return;
}

static void
snapshot_send(snapshot_t *self, zsock_t *socket, zframe_t *to)
{
	return;
}

static void
config_send(zsock_t *socket, zframe_t *to)
{
	return;
}

static void send_som(snapshot_t *snap, zsock_t *sock, zframe_t **envelope,
		     uint32_t ifindex)
{
	nlmsg_t *msg = nlmsg_new("IFQUERY",
				 snapshot_seqno(snap),
				 &ifindex, sizeof(ifindex));
	if (dp_test_ctrl_debug)
		nlmsg_dump("send som", msg);

	dp_test_assert_internal(msg);

	zframe_send(envelope, sock, ZFRAME_MORE + ZFRAME_REUSE);
	nlmsg_send(msg, sock, false);
}

static void
send_eom(snapshot_t *snap, zsock_t *sock, zframe_t **envelope)
{
	nlmsg_t *msg = nlmsg_new("THATSALLFOLKS!",
				 snapshot_seqno(snap),  "", 0);
	if (dp_test_ctrl_debug)
		nlmsg_dump("send eom", msg);

	dp_test_assert_internal(msg);

	zframe_send(envelope, sock, ZFRAME_MORE);
	nlmsg_send(msg, sock, false);
}

int
dp_test_zmsg_popu32(zmsg_t *msg, uint32_t *p)
{
	zframe_t *frame = zmsg_pop(msg);

	dp_test_assert_internal(frame);
	dp_test_assert_internal(zframe_size(frame) == sizeof(uint32_t));

	memcpy(p, zframe_data(frame), sizeof(uint32_t));
	zframe_destroy(&frame);
	return 0;
}

static int
zmsg_popu64(zmsg_t *msg, uint64_t *p)
{
	zframe_t *frame = zmsg_pop(msg);

	dp_test_assert_internal(frame);
	dp_test_assert_internal(zframe_size(frame) == sizeof(uint64_t));

	memcpy(p, zframe_data(frame), sizeof(uint64_t));
	zframe_destroy(&frame);
	return 0;
}

static int
zmsg_popip(zmsg_t *msg, struct ip_addr *ip)
{

	zframe_t *frame = zmsg_pop(msg);

	dp_test_assert_internal(frame);
	dp_test_assert_internal(zframe_size(frame) == sizeof(*ip));

	memcpy(ip, zframe_data(frame), sizeof(*ip));
	zframe_destroy(&frame);
	return 0;
}

static int
zactor_terminated(zloop_t *loop __rte_unused, zsock_t *sock,
		  void *arg __rte_unused)
{
	int interrupted = 0;
	char *msg = zstr_recv(sock);

	if (zsys_interrupted || (msg && !strcmp(msg, "$TERM")))
		interrupted = -1;

	free(msg);
	return interrupted;
}

/* Parse port creation message.
 *   [1] <seqno> 64bit
 *   [2] <myip> 32bits - network byte order
 *   [3] <info> string - JSON encoded slot related info
 *
 * Return ifindex of resulting device
 * -1 if failed
 */
static int
port_create(zmsg_t *msg, uint64_t *seqno, bool ippresent)
{
	struct ip_addr myip;
	char err_str[BUFSIZ];
	char *json_str;
	int port = -1;
	json_object *jresp;

	if (zmsg_popu64(msg, seqno) < 0) {
		err("missing sequence no");
		return -1;
	}

	if (ippresent)
		if (zmsg_popip(msg, &myip) < 0) {
			err("missing local ip");
			return -1;
		}

	json_str = zmsg_popstr(msg);
	if (!json_str) {
		err("missing json port info");
		return -1;
	}

	jresp = parse_json(json_str, err_str, sizeof(err_str));
	if (!jresp) {
		err("bad json: %s", err_str);
		return -1;
	}

	if (!dp_test_json_int_field_from_obj(jresp, "port", &port)) {
		err("missing port");
		return -1;
	}
	json_object_put(jresp);
	free(json_str);

	return port;
}

static void
connect_request(zsock_t *sock, zmsg_t *msg, zframe_t **envelope)
{
	uint32_t version = 0;
	char *control = NULL;
	char *uuid = NULL;

	if (dp_test_zmsg_popu32(msg, &version) < 0) {
		err("no version in connect");
		return;
	}
	uuid = zmsg_popstr(msg);
	if (uuid == NULL) {
		err("no uuid in connect");
		return;
	}
	control = zmsg_popstr(msg);
	if (control == NULL) {
		err("no control in connect");
		free(uuid);
		return;
	}

	/*
	 * Convert the UUID to an integer to be used as the
	 * ID for the accept message.
	 */
	uint16_t id = atoi(uuid);
	zmsg_t *reply = zmsg_new();
	int rc = 0;

	if (!reply) {
		errno = ENOMEM;
		rc = -1;
	}

	if (rc == 0)
		rc = zmsg_addstr(reply, "ACCEPT");
	if (rc == 0)
		rc = zmsg_addstr(reply, uuid);
	if (rc == 0)
		rc = zmsg_addmem(reply, &id, sizeof(id));

	if (rc == 0)
		rc = zframe_send(envelope, sock, ZFRAME_MORE);
	if (rc == 0)
		rc = zmsg_send(&reply, sock);

	if (rc < 0) {
		err("failed to send connect response (%s)", strerror(errno));
		zmsg_destroy(&reply);
	}

	free(uuid);
	free(control);
}

static void
newport_request(zsock_t *sock, zmsg_t *msg, zframe_t **envelope)
{
	uint64_t seqno;
	int port, ifindex;
	char ifname[IFNAMSIZ];

	dp_test_assert_internal(msg);

	port = port_create(msg, &seqno, true);
	if (port < 0)
		return;

	if (port >= dp_test_intf_count_local() +
	    dp_test_intf_switch_port_count()) {
		err("port %u out of range", port);
		return;
	}

	ifindex = dp_test_intf_port2index(port);
	dp_test_intf_port2name(port, ifname);

	zframe_send(envelope, sock, ZFRAME_MORE);
	zstr_sendm(sock, "OK");
	seqno_sendm(sock, seqno);
	ifindex_sendm(sock, (uint32_t) ifindex);
	zstr_send(sock, ifname);
}

static void
iniport_request(zsock_t *sock, zmsg_t *msg, zframe_t **envelope)
{
	uint64_t seqno;
	int port;
	uint32_t cookie;
	char ifname[IFNAMSIZ];

	dp_test_assert_internal(msg);

	port = port_create(msg, &seqno, false);
	if (port < 0)
		return;

	if (port >= dp_test_intf_count_local() +
	    dp_test_intf_switch_port_count()) {
		err("port %u out of range", port);
		return;
	}

	dp_test_intf_port2name(port, ifname);
	cookie = port;
	zframe_send(envelope, sock, ZFRAME_MORE);
	zstr_sendm(sock, "OK");
	seqno_sendm(sock, seqno);
	ifindex_sendm(sock, cookie);
	zstr_send(sock, ifname);
}

static void
addport_request(zsock_t *sock, zmsg_t *msg, zframe_t **envelope)
{
	uint64_t seqno;
	int port, ifindex;
	char *ifname1;
	uint32_t cookie;
	char ifname2[IFNAMSIZ];

	dp_test_assert_internal(msg);

	if (zmsg_popu64(msg, &seqno) < 0) {
		err("missing sequence no");
		return;
	}
	if (dp_test_zmsg_popu32(msg, &cookie) < 0) {
		err("missing cookie");
		return;
	}
	ifname1 = zmsg_popstr(msg);
	port = cookie;
	if ((port < 0) || (port >= dp_test_intf_count_local() +
			   dp_test_intf_switch_port_count())) {
		err("port %u out of range", port);
		return;
	}

	ifindex = dp_test_intf_port2index(port);
	dp_test_intf_port2name(port, ifname2);

	if (!streq(ifname1, ifname2)) {
		err("port %u name mismatch %s %s", port,
		    ifname1, ifname2);
		return;
	}

	zframe_send(envelope, sock, ZFRAME_MORE);
	zstr_sendm(sock, "OK");
	seqno_sendm(sock, seqno);
	ifindex_sendm(sock, (uint32_t) ifindex);
	zstr_send(sock, ifname1);
	free(ifname1);
}

static void
link_request(const char *state, zsock_t *sock, zmsg_t *msg, zframe_t **envelope)
{
	return;
}

static void
stats_update(zmsg_t *msg)
{
	return;
}

static void
mrt_request(zsock_t *sock, zmsg_t *msg, zframe_t **envelope)
{
	return;
}

static void
mrt6_request(zsock_t *sock, zmsg_t *msg, zframe_t **envelope)
{
	return;
}

static void
ifquery_request(snapshot_t *snap, zsock_t *sock, zmsg_t *msg,
		zframe_t **envelope)
{
	uint32_t ifindex;

	if (dp_test_zmsg_popu32(msg, &ifindex) < 0) {
		err("no ifindex in connect");
		return;
	}

	send_som(snap, sock, envelope, ifindex);
	send_eom(snap, sock, envelope);
}

/* Reply to config request with publisher url */
static void
confquery_request(enum cont_src_en cont_src, void *sock, zmsg_t *msg,
		  zframe_t **envelope)
{
	zframe_send(envelope, sock, ZFRAME_MORE);
	zstr_sendm(sock, "CONF");
	zstr_sendm(sock, "PUBLISH");
	zstr_send(sock, cont_info[cont_src].pub_url);
}

static void
uplink_msg(zmsg_t *msg)
{
}

static int expected_conf_err;

void dp_test_set_config_err(int error)
{
	expected_conf_err = error;
}

static void
config_error(zmsg_t *msg)
{
	char *cmd;
	zframe_t *frame;
	int error;
	uint16_t dp_id;

	frame = zmsg_pop(msg);
	if (!frame) {
		err("no dp id in config error message");
		return;
	}

	dp_id = *(uint16_t *) zframe_data(frame);
	zframe_destroy(&frame);

	cmd = zmsg_popstr(msg);
	if (!cmd) {
		err("no cmd string in config error message");
		return;
	}

	frame = zmsg_pop(msg);
	if (!frame) {
		err("no err code in config error message");
		free(cmd);
		return;
	}

	error = *(int *) zframe_data(frame);
	zframe_destroy(&frame);

	dp_test_fail_unless(error == expected_conf_err,
			    "Config error from dp %d for cmd \"%s\":\n"
			    " Error %d (%s)", dp_id, cmd, error,
			    strerror(abs(error)));
	free(cmd);
	expected_conf_err = 0;
}

static void
ext_buf_congestion(zmsg_t *msg)
{

}

static dp_test_event_msg_hdlr *msg_call_back;

void dp_test_register_event_msg(dp_test_event_msg_hdlr handler)
{
	msg_call_back = handler;
}

void dp_test_unregister_event_msg(void)
{
	msg_call_back = NULL;
}

static void
dp_event_msg(zmsg_t *msg)
{
	char *event = zmsg_popstr(msg);
	if (dp_test_ctrl_debug)
		zclock_log("Z: %s", event);

	if (streq(event, "CONFERR"))
		config_error(msg);
	else if (streq(event, "QosExtBufCongestion"))
		ext_buf_congestion(msg);
	else if (msg_call_back) {
		if ((msg_call_back)(event, msg))
			dp_test_assert_internal(0);
	} else {
		dp_test_assert_internal(0);
	}
	free(event);
}

static void
process_msg(enum cont_src_en cont_src, snapshot_t *snap, zsock_t *sock,
	    zmsg_t *msg)
{
	/* Remove and save client return envelope */
	zframe_t *envelope = zmsg_unwrap(msg);
	dp_test_assert_internal(envelope);

	if (dp_test_ctrl_debug > 1)
		zmsg_dump(msg);

	char *action = zmsg_popstr(msg);
	if (dp_test_ctrl_debug)
		zclock_log("Z: %s", action);

	if (streq(action, "CONNECT"))
		connect_request(sock, msg, &envelope);
	else if (streq(action, "NEWPORT"))
		newport_request(sock, msg, &envelope);
	else if (streq(action, "DELPORT"))
		delport_request(sock, msg, &envelope);
	else if (streq(action, "INIPORT"))
		iniport_request(sock, msg, &envelope);
	else if (streq(action, "ADDPORT"))
		addport_request(sock, msg, &envelope);
	else if (streq(action, "WHATSUP?")) {
		snapshot_send(snap, sock, envelope);
		config_send(sock, envelope);
		send_eom(snap, sock, &envelope);
	} else if (strncmp(action, "LINK", 4) == 0)
		link_request(action+4, sock, msg, &envelope);
	else if (strncmp(action, "STATS", 5) == 0)
		stats_update(msg);
	else if (strncmp(action, "MRTSTAT", 7) == 0)
		mrt_request(sock, msg, &envelope);
	else if (strncmp(action, "MRT6STAT", 8) == 0)
		mrt6_request(sock, msg, &envelope);
	else if (strncmp(action, "IFQUERY", 7) == 0)
		ifquery_request(snap, sock, msg, &envelope);
	else if (strncmp(action, "CONFQUERY", 9) == 0)
		confquery_request(cont_src, sock, msg, &envelope);
	else if (strncmp(action, "UPADDRADD", 9) == 0)
		uplink_msg(msg);
	else if (strncmp(action, "UPADDRDEL", 9) == 0)
		uplink_msg(msg);
	else if (strncmp(action, "DPEVENT", 7) == 0)
		dp_event_msg(msg);
	else
		dp_test_assert_internal(0);

	free(action);
	zframe_destroy(&envelope);
}

static int dataplane_req_src(enum cont_src_en cont_src, zloop_t *loop,
			     zsock_t *requests, void *arg)
{
	snapshot_t *snap = arg;

	zmsg_t *msg = zmsg_recv(requests);
	if (msg) {
		process_msg(cont_src, snap, requests, msg);
		zmsg_destroy(&msg);
	}
	return 0;
}

static int dataplane_req(zloop_t *loop, zsock_t *requests, void *arg)
{
	return dataplane_req_src(CONT_SRC_MAIN, loop, requests, arg);
}

static int dataplane_req_uplink(zloop_t *loop, zsock_t *requests, void *arg)
{
	return dataplane_req_src(CONT_SRC_UPLINK, loop, requests, arg);
}

static int link_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attr to avoid issues with newer kernels */
	if (mnl_attr_type_valid(attr, IFLA_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case IFLA_MTU:
	case IFLA_LINK:
	case IFLA_MASTER:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			notice("link attribute %d not u32\n", type);
			return MNL_CB_ERROR;
		}
		break;

	case IFLA_IFNAME:
	case IFLA_QDISC:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			notice("link ifname not a valid string\n");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

/* Topic string for link messages
 * Note: trailing space is intentional because dataplane subscribes
 * to prefix.
 *  char filter[] = "link 5 "
 *  zsockopt_set_subscribe(subscriber, filter);
 * and should match "link 5 " and not "link 50 "
 */
static int link_topic(const struct nlmsghdr *nlh, char *buf, size_t len)
{
	const struct ifinfomsg *ifi = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[IFLA_MAX + 1] = { NULL };

	if (mnl_attr_parse(nlh, sizeof(*ifi), link_attr, tb) != MNL_CB_OK) {
		notice("netlink: can't parse link attributes\n");
		return -1;
	}

	if (ifi->ifi_family == AF_BRIDGE)
		return snprintf(buf, len, "bridge_link %u ", ifi->ifi_index);

	if (!tb[IFLA_IFNAME]) {
		notice("netlink: missing ifname in link msg\n");
		return -1;
	}

	/* Dataplane interprets name formats as interface types :( */
	const char *ifname = mnl_attr_get_str(tb[IFLA_IFNAME]);

	if (ifname[0] == 'v' && ifname[1] == 'x' && ifname[2] == 'l' &&
	    isdigit(ifname[3]))
		return snprintf(buf, len, "vxlan %u ", ifi->ifi_index);

	if (strncmp(ifname, "tun", 3) == 0)
		return snprintf(buf, len, "tunnel %u ", ifi->ifi_index);

	/* For nested device types like VLAN, publish with id of parent */
	if (tb[IFLA_LINK]) {
		uint32_t iflink = mnl_attr_get_u32(tb[IFLA_LINK]);
		if (iflink)
			return snprintf(buf, len, "link %u ifindex %u ",
					iflink, ifi->ifi_index);
	}

	return snprintf(buf, len, "link %u ", ifi->ifi_index);
}

/* Kernel scope id to string */
static const char *addr_scope(int id)
{
	static char buf[64];

	switch (id) {
	case 0:
		return "global";
	case 255:
		return "nowhere";
	case 254:
		return "host";
	case 253:
		return "link";
	case 200:
		return "site";
	default:
		snprintf(buf, sizeof(buf), "%d", id);
		return buf;
	}
}

/* Call back from libmnl to store attribute */
static int addr_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	unsigned int type = mnl_attr_get_type(attr);

	if (type <= IFA_MAX)
		tb[type] = attr;

	return MNL_CB_OK;
}

/*
 * Format up a topic string in format similar to 'ip address'
 * to describe address.
 */
static int address_topic(const struct nlmsghdr *nlh, char *buf, size_t len)
{
	const struct ifaddrmsg *ifa = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[IFA_MAX + 1] = { NULL };
	void *addr;
	char b1[INET6_ADDRSTRLEN];

	if (!(ifa->ifa_family == AF_INET || ifa->ifa_family == AF_INET6)) {
		info("netlink: ignore address family %u", ifa->ifa_family);
		return -1;
	}

	if (mnl_attr_parse(nlh, sizeof(*ifa), addr_attr, tb) != MNL_CB_OK) {
		notice("netlink: can't parse address attributes\n");
		return -1;
	}

	if (tb[IFA_LOCAL])
		addr = mnl_attr_get_payload(tb[IFA_LOCAL]);
	else {
		notice("missing address in netlink message\n");
		return -1;
	}

	return snprintf(buf, len,
			"address %u inet %s/%d scope %s",
			ifa->ifa_index,
			inet_ntop(ifa->ifa_family, addr, b1, sizeof(b1)),
			ifa->ifa_prefixlen, addr_scope(ifa->ifa_scope));
}

/* Callback to store route attributes */
static int route_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	unsigned int type = mnl_attr_get_type(attr);

	if (type <= RTA_MAX)
		tb[type] = attr;
	return MNL_CB_OK;
}

static const char *rt_type(unsigned int type)
{
	static char buf[64];

	switch (type) {
	case RTN_UNSPEC:
		return "unspec";
	case RTN_LOCAL:
		return "local";
	case RTN_BROADCAST:
		return "broadcast";
	case RTN_ANYCAST:
		return "anycast";
	case RTN_MULTICAST:
		return "multicast";
	case RTN_BLACKHOLE:
		return "blackhole";
	case RTN_UNREACHABLE:
		return "unreachable";
	case RTN_PROHIBIT:
		return "prohibit";
	case RTN_THROW:
		return "throw";
	case RTN_NAT:
		return "nat";
	case RTN_XRESOLVE:
		return "xresolve";
	default:
		snprintf(buf, sizeof(buf), "%u", type);
		return buf;
	}
}

static const char *mroute_ntop(int af, const void *src,
			       char *dst, socklen_t size)
{
	switch (af) {
	case RTNL_FAMILY_IPMR:
		return inet_ntop(AF_INET, src, dst, size);
		break;

	case RTNL_FAMILY_IP6MR:
		return inet_ntop(AF_INET6, src, dst, size);
		break;

	default:
		notice("netlink: multicast: bad family %d\n", af);
	}
	return NULL;
}

static int mroute_topic(const struct nlmsghdr *nlh, char *buf, size_t len,
			const struct rtmsg *rtm)
{
	struct nlattr *tb[RTA_MAX+1] = { NULL };
	int ifindex = 0, oifindex = 0;
	const void *mcastgrp, *origin;
	char b1[INET6_ADDRSTRLEN], b2[INET6_ADDRSTRLEN];

	if (dp_test_ctrl_debug)
		notice("netlink: route %s table %d\n",
			nlh->nlmsg_type == RTM_NEWROUTE ? "new" : "delete",
			rtm->rtm_table);

	if (mnl_attr_parse(nlh, sizeof(*rtm), route_attr, tb) != MNL_CB_OK) {
		notice("netlink: %s can't parse address attributes\n",
		       __func__);
		return -1;
	}

	if (tb[RTA_DST])
		mcastgrp = mnl_attr_get_payload(tb[RTA_DST]);
	else {
		mcastgrp = anyaddr;
		notice("netlink: %s tb[RTA_DST] any\n", __func__);
	}

	if (tb[RTA_SRC])
		origin = mnl_attr_get_payload(tb[RTA_SRC]);
	else {
		origin = anyaddr;
		notice("netlink: %s tb[RTA_SRC] any\n", __func__);
	}

	if (tb[RTA_IIF])
		ifindex = mnl_attr_get_u32(tb[RTA_IIF]);

	if (tb[RTA_OIF]) {
		oifindex = mnl_attr_get_u32(tb[RTA_OIF]);
		notice("netlink: %s tb[RTA_OIF] %d\n", __func__, ifindex);
	}

	return snprintf(buf, len, "route %d %d %s %s/%u %s/%u",
			ifindex, oifindex, rt_type(rtm->rtm_type),
			mroute_ntop(rtm->rtm_family, mcastgrp, b1, sizeof(b1)),
			rtm->rtm_dst_len,
			mroute_ntop(rtm->rtm_family, origin, b2, sizeof(b2)),
			rtm->rtm_src_len);
}

static int route_topic(const struct nlmsghdr *nlh, char *buf, size_t len)
{
	const struct rtmsg *rtm = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[RTA_MAX + 1] = { NULL };
	int ifindex = 0;
	const void *dest, *nexthop;
	char b1[INET6_ADDRSTRLEN], b2[INET6_ADDRSTRLEN];

	if (rtm->rtm_type == RTN_MULTICAST)
		return mroute_topic(nlh, buf, len, rtm);

	/* Ignore cached host routes */
	if (rtm->rtm_flags & RTM_F_CLONED)
		return -1;

	if (mnl_attr_parse(nlh, sizeof(*rtm), route_attr, tb) != MNL_CB_OK) {
		notice("netlink: can't parse address attributes\n");
		return -1;
	}

	if (tb[RTA_DST])
		dest = mnl_attr_get_payload(tb[RTA_DST]);
	else
		dest = anyaddr;

	if (tb[RTA_GATEWAY])
		nexthop = mnl_attr_get_payload(tb[RTA_GATEWAY]);
	else
		nexthop = anyaddr;

	if (tb[RTA_OIF])
		ifindex = mnl_attr_get_u32(tb[RTA_OIF]);

	return snprintf(buf, len,
			"route %d %s %s/%u %s", ifindex, rt_type(rtm->rtm_type),
			inet_ntop(rtm->rtm_family, dest, b1, sizeof(b1)),
			rtm->rtm_dst_len,
			inet_ntop(rtm->rtm_family, nexthop, b2, sizeof(b2)));
}

/* Call back from libmnl to validate netlink message */
static int neigh_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NDA_MAX) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

static int neigh_topic(const struct nlmsghdr *nlh, char *buf, size_t len)
{
	const struct ndmsg *ndm = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[NDA_MAX + 1] = { NULL };
	const void *dst;
	char b1[INET6_ADDRSTRLEN];

	if (!(ndm->ndm_family == AF_INET
	      || ndm->ndm_family == AF_INET6 || ndm->ndm_family == AF_BRIDGE)) {
		info("netlink: ignore neighbor family %d", ndm->ndm_family);
		return -1;
	}

	if (mnl_attr_parse(nlh, sizeof(*ndm), neigh_attr, tb) != MNL_CB_OK) {
		notice("netlink: can't parse neigh attributes\n");
		return -1;
	}

	if (tb[NDA_DST])
		dst = mnl_attr_get_payload(tb[NDA_DST]);
	else
		dst = anyaddr;

	const char *addr = inet_ntop(ndm->ndm_family, dst, b1, sizeof(b1));
	if (nlh->nlmsg_type == RTM_DELNEIGH) {
		return snprintf(buf, len,
				"neigh %d del %s",
				ndm->ndm_ifindex, addr);
	}

	return snprintf(buf, len,
			"neigh %d new %s",
			ndm->ndm_ifindex, addr);
}

/* Call back from libmnl to validate netlink message */
static int netconf_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NETCONFA_MAX) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

static int netconf_topic(const struct nlmsghdr *nlh, char *buf, size_t len)
{
	const struct netconfmsg *ncm = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[NETCONFA_MAX + 1] = { NULL };
	int32_t ifindex;

	/* Ignore families that we don't care about */
	switch (ncm->ncm_family) {
	case AF_INET6:
	case AF_INET:
	case AF_MPLS:

	case RTNL_FAMILY_IPMR:
	case RTNL_FAMILY_IP6MR:
		break;

	default:
		return -1;
	}

	if (mnl_attr_parse(nlh, sizeof(*ncm), netconf_attr, tb) != MNL_CB_OK) {
		notice("netconf: can't parse netconf attributes\n");
		return -1;
	}

	if (!tb[NETCONFA_IFINDEX]) {
		notice("netconf: missing ifindex\n");
		return -1;
	}

	ifindex = (int)mnl_attr_get_u32(tb[NETCONFA_IFINDEX]);
	if (ifindex == NETCONFA_IFINDEX_ALL ||
	    ifindex == NETCONFA_IFINDEX_DEFAULT) {
		if (!tb[NETCONFA_MC_FORWARDING]) {
			dbg("netconf: ifindex %d is global: ignored", ifindex);
			return -1;
		}
	}

	return snprintf(buf, len, "netconf %d %d", ifindex, ncm->ncm_family);
}

/* Generate a topic string to be sent by as subject
 * 0mq uses strings as pub/sub filtering.
 */
int
nl_generate_topic(const struct nlmsghdr *nlh, char *buf, size_t buflen)
{
	switch (nlh->nlmsg_type) {
	case RTM_NEWLINK:
	case RTM_DELLINK:
		return link_topic(nlh, buf, buflen);

	case RTM_NEWADDR:
	case RTM_DELADDR:
		return address_topic(nlh, buf, buflen);

	case RTM_NEWROUTE:
	case RTM_DELROUTE:
		return route_topic(nlh, buf, buflen);

	case RTM_NEWNEIGH:
	case RTM_DELNEIGH:
		return neigh_topic(nlh, buf, buflen);

	case RTM_NEWNETCONF:
	case RTM_DELNETCONF:
		return netconf_topic(nlh, buf, buflen);

	default:
		info("unknown expected type %d", nlh->nlmsg_type);
		return -1;
	}
}

static void
nl_propagate_src(enum cont_src_en cont_src, const char *topic,
		 const struct nlmsghdr *nlh, zsock_t *sock, bool broker)
{
	nlmsg_t *nmsg;

	nmsg = nlmsg_new(topic, ++nl_msg_seqno, nlh, nlh->nlmsg_len);
	dp_test_assert_internal(nmsg);

	if (dp_test_ctrl_debug) {
		char tmp_str[DP_TEST_TMP_BUF_SMALL];

		snprintf(tmp_str, sizeof(tmp_str), "%s publish",
			 cont_src_name(cont_src));
		nlmsg_dump(tmp_str, nmsg);
	}

	/* and publish original */
	nlmsg_send(nmsg, sock, broker);
}

static enum cont_src_en cont_src_current = CONT_SRC_MAIN;

void
dp_test_cont_src_set(enum cont_src_en cont_src_new)
{
	if (cont_src_new == cont_src_current)
		return;
	if (dp_test_debug_get() > 1)
		printf("%s: Changing controller source from %s to %s\n",
		       dp_test_pname, cont_src_name(cont_src_current),
		       cont_src_name(cont_src_new));
	cont_src_current = cont_src_new;
}

enum cont_src_en
dp_test_cont_src_get(void)
{
	return cont_src_current;
}

void
nl_propagate(const char *topic, const struct nlmsghdr *nlh)
{
	nl_propagate_src(cont_src_current, topic, nlh,
			 cont_info[cont_src_current].pub_sock, false);
}

static void
data_send_free(void *data, void *hint)
{
	free(data);
}

void nl_propagate_xfrm(zsock_t *sock, void *data, size_t size)
{
	zmq_msg_t m;

	zmq_msg_init_data(&m, data, size,
			  NULL, NULL);
	zmq_msg_send(&m, zsock_resolve(sock), 0);
}

void
nl_propagate_broker(const char *topic, void *data, size_t size)
{
	if (cont_src_current == CONT_SRC_MAIN &&
	    dp_test_route_broker_protobuf) {
		zmq_msg_t m;

		zmq_msg_init_data(&m, data, size,
				  data_send_free, NULL);

		zmq_msg_send(&m, zsock_resolve(broker_data_sock), 0);
	} else if (cont_src_current == CONT_SRC_MAIN)
		nl_propagate_src(cont_src_current, topic, data,
				 broker_data_sock, true);
	else
		nl_propagate_src(cont_src_current, topic, data,
				 cont_info[cont_src_current].pub_sock, false);
}


/* callback from zloop in the request_thread. */
static int check_expired(zloop_t *loop,
			 int poller,
			 void *arg)
{
	/* We are done. */
	if (running == 0)
		return -1;

	return 0;
}

/*
 * The pipe is back to the creator of this thread.
 */
static void
dp_test_request_thread(zsock_t *pipe, void *args)
{
	enum cont_src_en cont_src = (uintptr_t)args;
	const char *thread_name;
	zloop_reader_fn *req_handler;
	char *endpoint;

	int ret;

	switch (cont_src) {
	case CONT_SRC_MAIN:
		thread_name = "control/req";
		req_handler = &dataplane_req;
		break;
	case CONT_SRC_UPLINK:
		thread_name = "control/req_uplink";
		req_handler = &dataplane_req_uplink;
		break;
	default:
		thread_name = "";
		req_handler = NULL;
		break;
	}

	pthread_setname_np(pthread_self(), thread_name);

	snapshot_t *snap = snapshot_new();
	zsock_t *requests = zsock_new_router("ipc://*");
	dp_test_assert_internal(requests);

	zloop_t *loop = zloop_new();
	dp_test_assert_internal(loop);

	/* zactor API will send a $TERM ZMQ message on termination */
	if (zloop_reader(loop, pipe, zactor_terminated, NULL))
		dp_test_assert_internal(0);

	if (zloop_reader(loop, requests, req_handler, snap))
		dp_test_assert_internal(0);

	ret = zloop_timer(loop, 1000, 0, check_expired, snap);
	dp_test_assert_internal(ret >= 0);

	/* Tell test thread we are ready */
	zsock_signal(pipe, 0);
	endpoint = zsock_last_endpoint(requests);
	zstr_send(pipe, endpoint);
	free(endpoint);

	zloop_start(loop);

	zloop_destroy(&loop);
	zsock_destroy(&requests);

	assert(loop == NULL);
	snapshot_destroy(&snap);
}

void
dp_test_controller_init(enum cont_src_en cont_src, char **req_ipc)
{
	/*
	 * ZMQ channel for sending Netlink etc. to the dataplane from the
	 * controller.
	 *
	 */
	cont_info[cont_src].pub_sock = zsock_new_pub("ipc://*");
	dp_test_assert_internal(cont_info[cont_src].pub_sock);
	cont_info[cont_src].pub_url =
		zsock_last_endpoint(cont_info[cont_src].pub_sock);

	/*
	 * ZMQ request channel that allows the dataplane to request
	 * data from the controller.
	 */
	cont_info[cont_src].req_actor = zactor_new(dp_test_request_thread,
						   (void *)cont_src);
	dp_test_assert_internal(cont_info[cont_src].req_actor);
	*req_ipc = zstr_recv(cont_info[cont_src].req_actor);
}

void
dp_test_controller_close(enum cont_src_en cont_src)
{
	zactor_destroy(&cont_info[cont_src].req_actor);
	zsock_destroy(&cont_info[cont_src].pub_sock);
	free(cont_info[cont_src].pub_url);
	cont_info[cont_src].pub_url = NULL;
}

static char *
extract_topic(const char *line)
{
	char topic[BUFSIZ], *tmp = NULL;
	topic[0] = '\0';
	/* For now... grab first two entries as topic */
	/* NEED to fix this up so that topic is pulled from config cmd */
	char *token = strtok_r((char *)line, " ", &tmp);
	int ct = 0;
	while (token != NULL && ct < 2) {
		strcat(topic, token);
		strcat(topic, " ");
		token = strtok_r(NULL, " ", &tmp);
		++ct;
	}
	if (ct == 2)
		return strdup(topic);

	return NULL;
}


static
void dp_test_send_config_inner(enum cont_src_en cont_src,
			       const char *cmd_fmt_str, va_list ap)
{
	char cmd[DP_TEST_TMP_BUF];
	char *cmd_copy;
	nlmsg_t *nmsg;
	char *topic;
	int len;

	len = vsnprintf(cmd, sizeof(cmd), cmd_fmt_str, ap);
	dp_test_assert_internal(len < DP_TEST_TMP_BUF);

	cmd_copy = strdup(cmd);
	topic = extract_topic(cmd_copy);
	nmsg = nlmsg_new(topic, ++nl_msg_seqno, cmd, strlen(cmd) + 1);
	free(topic);
	free(cmd_copy);
	dp_test_assert_internal(nmsg);

	if (dp_test_ctrl_debug) {
		char tmp_str[DP_TEST_TMP_BUF_SMALL];

		snprintf(tmp_str, sizeof(tmp_str), "%s publish",
			 cont_src_name(cont_src));
		nlmsg_dump(tmp_str, nmsg);
	}

	/* and publish original */
	nlmsg_send(nmsg, cont_info[cont_src].pub_sock, false);
}

void dp_test_send_config_src(enum cont_src_en cont_src,
			     const char *cmd_fmt_str, ...)
{
	va_list ap;

	va_start(ap, cmd_fmt_str);
	dp_test_send_config_inner(cont_src, cmd_fmt_str, ap);
	va_end(ap);
}

void dp_test_send_config(const char *cmd_fmt_str, ...)
{
	va_list args;

	va_start(args, cmd_fmt_str);
	dp_test_send_config_inner(dp_test_cont_src_get(), cmd_fmt_str, args);
	va_end(args);
}

void dp_test_send_config_src_pb(enum cont_src_en cont_src,
				void *cmd, size_t cmd_len)
{
	nlmsg_t *nmsg;

	nmsg = nlmsg_new("protobuf", ++nl_msg_seqno, cmd, cmd_len);
	dp_test_assert_internal(nmsg);

	if (dp_test_ctrl_debug) {
		char tmp_str[DP_TEST_TMP_BUF_SMALL];

		snprintf(tmp_str, sizeof(tmp_str), "%s publish",
			 cont_src_name(cont_src));
		nlmsg_dump(tmp_str, nmsg);
	}

	/* and publish original */
	nlmsg_send(nmsg, cont_info[cont_src].pub_sock, false);
}
