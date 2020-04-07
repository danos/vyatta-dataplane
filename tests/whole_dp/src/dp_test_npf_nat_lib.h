/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dp NAT library
 */

#ifndef __DP_TEST_NPF_NAT_LIB_H__
#define __DP_TEST_NPF_NAT_LIB_H__

#include <stdint.h>
#include <stdbool.h>
#include <json-c/json.h>

#include "npf/npf_nat.h"
#include "dp_test_lib_pkt.h"


#define NAT_TRANS_ADDR	"0.0.0.0-255.255.255.255"
#define NAT_NULL_PROTO  -1

struct dp_test_npf_nat_rule_t {
	const char *desc;
	const char *rule;
	const char *ifname;
	int         proto;
	const char *map;
	const char *from_addr;
	const char *from_port;
	const char *to_addr;
	const char *to_port;
	const char *trans_addr;
	const char *trans_port;
};

/*
 * Enable/disable NAT debugging
 *
 * 1. Prints the npf string during _dp_test_npf_nat_add
 * 2. Printd the json object for the nat rule during _dp_test_npf_nat_verify
 */
void dp_test_npf_nat_set_debug(bool on);
bool dp_test_npf_nat_get_debug(void);

/* Simple SNAT and DNAT config */
void dpt_snat_cfg(const char *intf, uint8_t ipproto,
		  const char *from_addr, const char *trans_addr,
		  bool add);

void dpt_dnat_cfg(const char *intf, uint8_t ipproto,
		  const char *to_addr, const char *trans_addr,
		  bool add);

/*
 * Add a NAT rule
 */
void
_dp_test_npf_nat_add(const struct dp_test_npf_nat_rule_t *nat, bool snat,
		     bool verify, const char *file, int line);

#define dp_test_npf_dnat_add(nat, verify)                               \
	_dp_test_npf_nat_add(nat, false, verify, __FILE__, __LINE__)

#define dp_test_npf_snat_add(nat, verify)                               \
	_dp_test_npf_nat_add(nat, true, verify, __FILE__, __LINE__)

/*
 * Delete a NAT rule
 */
void
_dp_test_npf_nat_del(const char *ifname, const char *rule, bool snat,
		     bool verify, const char *file, int line);

#define dp_test_npf_dnat_del(ifname, rule, verify)                      \
	_dp_test_npf_nat_del(ifname, rule, false, verify, __FILE__, __LINE__)

#define dp_test_npf_snat_del(ifname, rule, verify)                      \
	_dp_test_npf_nat_del(ifname, rule, true, verify, __FILE__, __LINE__)

/*
 * Verify NAT
 */
void
_dp_test_npf_nat_verify(const struct dp_test_npf_nat_rule_t *nat, bool snat,
			bool print, const char *file, int line);

/*
 * Get the packet count of a NAT rule
 */
bool
dp_test_npf_nat_get_pkts(const char *ifname, const char *rule, bool snat,
			 uint *packets);

/*
 * Verify the packet count of a NAT rule
 */
void
_dp_test_npf_nat_verify_pkts(const char *ifname, const char *rule, bool snat,
			     uint exp_pkts, const char *file, int line);

#define dp_test_npf_snat_verify_pkts(ifname, rule, pkts)                     \
	_dp_test_npf_nat_verify_pkts(ifname, rule, true, pkts,               \
				     __FILE__, __LINE__)

#define dp_test_npf_dnat_verify_pkts(ifname, rule, pkts)                \
	_dp_test_npf_nat_verify_pkts(ifname, rule, false, pkts,         \
				     __FILE__, __LINE__)
/*
 * Add a NAT64 rule
 */
struct dp_test_npf_nat64_rule_t {
	const char *rule;
	const char *ifname;
	const char *from_addr;
	const char *to_addr;
	int spl;
	int dpl;
};

void
_dp_test_npf_nat64_add(const struct dp_test_npf_nat64_rule_t *rule,
		       bool verify, const char *file, int line);

#define dp_test_npf_nat64_add(rule, verify)                             \
	_dp_test_npf_nat64_add(rule, verify, __FILE__, __LINE__)

/*
 * Delete a NAT64 rule
 */
void
_dp_test_npf_nat64_del(const struct dp_test_npf_nat64_rule_t *rule,
		       bool verify, const char *file, int line);

#define dp_test_npf_nat64_del(rule, verify)                             \
	_dp_test_npf_nat64_del(rule, verify, __FILE__, __LINE__)


/*
 * Different translations occur dependent upon the NAT flavour
 */
enum dp_test_trans_type {
	DP_TEST_TRANS_SNAT,
	DP_TEST_TRANS_DNAT,
	_DP_TEST_TRANS_SIZE
};

#define DP_TEST_TRANS_FIRST (_DP_TEST_TRANS_SNAT)
#define DP_TEST_TRANS_LAST  (_DP_TEST_TRANS_SIZE - 1)
#define DP_TEST_TRANS_NONE  (_DP_TEST_TRANS_SIZE)

/*
 * NAT validation context helper functions.
 *
 * For convenience, addresses and ports are stored as both numbers and
 * strings.  For example, for ALGs we need the string representations.
 */

enum dp_test_nat_dir {
	DP_TEST_NAT_DIR_FORW,
	DP_TEST_NAT_DIR_BACK,
};

/*
 * Wrapper around dp_test_pak_receive to create, send, and verify NAT'd
 * packets.
 *
 * descr	Description of the packet being sent
 * pre		pre-NAT packet descriptor
 * post		post-NAT packet descriptor
 * dir		Direction of the packet relative to the NAT session
 * ttype	SNAT or DNAT
 * verify_sess	Verify the NAT session exists during packet validation callback
 * count	Number of packets to send
 * delay	Delay in seconds between packets
 *
 * Note, the delay is for use when sending mutliple packets, however this
 * should *only* be used in a private build, i.e. dont commit test code with a
 * non-zero delay.
 */
void
_dpt_npf_nat_pak_receive(const char *descr,
			 struct dp_test_pkt_desc_t *pre,
			 struct dp_test_pkt_desc_t *post,
			 enum dp_test_nat_dir dir,
			 enum dp_test_trans_type ttype,
			 bool verify_sess,
			 uint count, uint delay,
			 const char *file, int line);

#define dpt_npf_nat_pak_receive(descr, pre, post, dir, ttype, vs)	\
	_dpt_npf_nat_pak_receive(descr, pre, post, dir, ttype,		\
				 vs, 1, 0, __FILE__, __LINE__)

#define dpt_npf_nat_pak_receive_n(descr, pre, post, dir, ttype, vs,	\
				  count, dly)				\
	_dpt_npf_nat_pak_receive(descr, pre, post, dir, ttype, vs,	\
				 count, dly, __FILE__, __LINE__)

/*
 * NAT validation context.  Expectation is as follows:
 *
 * DNAT Forwards  - dest   addr translated to 'taddr'
 * DNAT Backwards - source addr translated to 'oaddr'
 *
 * SNAT Forwards  - source addr translated to 'taddr'
 * SNAT Backwards - dest   addr translated to 'oaddr'
 *
 * If an SNAT port range is used then tport and tport_end should be set
 * accordingly (tport_end should otherwise be 0).  In this case, the
 * validation callback will update the exp packet with the source port in the
 * tx packet. It will also set 'eport' with the port used.
 */
struct dp_test_nat_ctx {
	char		desc[40];
	bool		dnat; /* dnat or snat */
	enum dp_test_nat_dir dir; /* forwards or backwards */
	uint32_t	flags;
	uint32_t	flags_mask;
	uint32_t	oaddr;
	char		oaddr_str[INET_ADDRSTRLEN];
	uint16_t	oport; /* host order */
	char		oport_str[8];
	uint32_t	taddr;
	char		taddr_str[INET_ADDRSTRLEN];
	uint16_t	tport; /* host order */
	char		tport_str[8];
	uint16_t	tport_end; /* 0 if no port range */
	uint16_t	eport; /* Use for port ranges */
	char		tport_end_str[8];

	/*
	 * We only want to verify sessions for forwards direction packets,
	 * except when we have an ALG secondary flow and its initial packet is
	 * reversed relative to the parent session.
	 */
	bool		verify_session;

	struct dp_test_pkt_desc_t *pre;
	struct dp_test_pkt_desc_t *post;
};

/*
 * NAT validation context.  Typically used in the packet validation callback
 * function to verify a NAT translation.
 */
struct dp_test_nat_cb_ctx {
	char			file[50];
	int			line;
	struct dp_test_nat_ctx	*dnat;
	struct dp_test_nat_ctx	*snat;

	/* Original dp_test validate callback */
	validate_cb		saved_cb;
};

void
dp_test_npf_nat_ctx_set_dnat(struct dp_test_nat_ctx *ctx);

void
dp_test_npf_nat_ctx_set_snat(struct dp_test_nat_ctx *ctx);

void
dp_test_npf_nat_ctx_set_dir(struct dp_test_nat_ctx *ctx,
			    enum dp_test_nat_dir dir);

void
dp_test_npf_nat_ctx_set_oaddr(struct dp_test_nat_ctx *ctx, uint32_t oaddr);

void
dp_test_npf_nat_ctx_set_oaddr_str(struct dp_test_nat_ctx *ctx,
				  const char *oaddr_str);

void
dp_test_npf_nat_ctx_set_taddr(struct dp_test_nat_ctx *ctx, uint32_t taddr);

void
dp_test_npf_nat_ctx_set_taddr_str(struct dp_test_nat_ctx *ctx,
				  const char *taddr_str);

void
dp_test_npf_nat_ctx_set_oport(struct dp_test_nat_ctx *ctx, uint16_t oport);

void
dp_test_npf_nat_ctx_set_tport(struct dp_test_nat_ctx *ctx, uint16_t tport,
			      uint16_t tport_end);

void
dp_test_nat_set_ctx(struct dp_test_nat_ctx *ctx,
		    enum dp_test_nat_dir dir,
		    enum dp_test_trans_type ttype,
		    struct dp_test_pkt_desc_t *pre,
		    struct dp_test_pkt_desc_t *post,
		    bool verify_session);

bool
dp_test_nat_validate(struct rte_mbuf *mbuf, struct ifnet *ifp,
		     struct dp_test_nat_ctx *nat, char *str, int len);

void
_dp_test_nat_set_validation(struct dp_test_nat_cb_ctx *ctx,
			    struct dp_test_expected *test_exp,
			    const char *file, int line);

#define dp_test_nat_set_validation(ctx, test_exp)			\
	_dp_test_nat_set_validation(ctx, test_exp, __FILE__, __LINE__)

/*
 * Return the json object for a specific source or dest NAT rule
 *
 *	jnat = dp_test_npf_json_nat_rule(ifname, "10", true);
 *
 * The returned json object has its ref count incremented, so json_object_put
 * should be called once the caller has finished with the object.
 */
json_object *
dp_test_npf_json_get_nat_rule(const char *ifname, const char *num, bool snat);

/*
 * Pretty print NAT firewall rules
 */
void
dp_test_npf_print_nat(const char *desc);

#endif
