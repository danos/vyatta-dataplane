/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * API between dp-test and osip2 library
 */

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "netinet6/ip6_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "npf/npf.h"
#include "npf/npf_cache.h"

#include "dp_test_lib_internal.h"
#include "dp_test_str.h"
#include "dp_test_npf_nat_lib.h"
#include "dp_test_npf_alg_sip_lib.h"

#include <osip2/osip.h>
#include <osipparser2/sdp_message.h>

/*
 * This details which SIP message parts are considered for translation,
 * dependent upon SNAT or DNAT, SIP request or response, and packet direction
 * (forwards or reverse, relative to the NAT config.)
 *
 * DNAT, SIP request, Forwards
 *   Request URI
 *   To
 *
 * DNAT, SIP request, Backwards
 *   Request URI
 *   To
 *   Contact
 *
 * DNAT, SIP response, Forwards
 *   To
 *   Record-Route
 *   Route
 *
 * DNAT, SIP response, Backwards
 *   Request URI
 *   To
 *   Contact
 *   Record-Route
 *   Route
 *
 * SNAT, SIP request, Forwards
 *   From
 *   UserAgent
 *   Call ID
 *   Via
 *   Contact
 *   Record-Route
 *   Route
 *
 * SNAT, SIP request, Backwards
 *   Request URI
 *
 * SNAT, SIP response, Forwards
 *   To
 *   Contact
 *   Record-Route
 *
 * SNAT, SIP response, Backwards
 *   From
 *   Call ID
 *   Via
 *   Record-Route
 *   Route
 */


/*
 *
 * This file validates SIP messages via the dp test packet validation callback
 * mechanism.
 *
 * It makes use of the same SIP libraries (osip2) as the npf code to parse the
 * SIP messages to access the embedded address and port string.
 *
 * We need the following information in order to check if a particular address
 * or port:
 *
 * 1. should have been translated,
 * 2. is translated to the correct value
 *
 * This information is (typical variable names in brackets):
 *
 * 1. NAT config (o_host, o_port, t_host, t_port)
 * 2. NAT type, snat or dnat (ttype)
 * 3. Direction of packet flow relevant to the NAT config (forwards or back)
 * 4. Original SIP message before translation (orig_sr)
 * 5. SIP message after translation (sr)
 * 6. Is packet a SIP Request or a SIP response
 * 7. The particular part of the SIP messages (req_uri, to, from etc)
 *
 * #3 and #6 are combined to create a 'flow' variable.  See 'enum
 * dp_test_sip_flow'.
 *
 * In the npf code, the functions sip_alg_translate_snat and
 * sip_alg_translate_dnat decide which parts of a SIP messages are translated
 * or not based on the 'flow' (req/resp and forw/back).
 *
 * This test code uses all the above to create an array of data which details
 * if a particlar SIP part should be translated or not.
 *
 */

/*
 * SIP request struct
 */
struct sip_alg_request {
	struct osip_message	*sr_sip;
	struct sdp_message	*sr_sdp;
};

/*
 * Parts of a SIP or SDP message that are translated.
 *
 * See sip_alg_translate_snat and sip_alg_translate_dnat
 */
enum dp_test_alg_sip_part {
	DP_TEST_SIP_PART_REQ_URI,
	DP_TEST_SIP_PART_TO,
	DP_TEST_SIP_PART_RROUTE,
	DP_TEST_SIP_PART_ROUTE,
	DP_TEST_SIP_PART_CONTACT,
	DP_TEST_SIP_PART_FROM,
	DP_TEST_SIP_PART_USER_AGENT,
	DP_TEST_SIP_PART_VIA,
	DP_TEST_SIP_PART_CALL_ID,
	_DP_TEST_SIP_PART_SIZE
};

#define DP_TEST_SIP_PART_FIRST (_DP_TEST_SIP_PART_REQ_URI)
#define DP_TEST_SIP_PART_LAST  (_DP_TEST_SIP_PART_SIZE - 1)

/*
 * Different translations occur dependent SIP type (request or response), and
 * direction of packet (forwards or backwards)
 */
enum dp_test_sip_flow {
	DP_TEST_SIP_FLOW_OTHER,
	DP_TEST_SIP_FLOW_REQ_FORW,
	DP_TEST_SIP_FLOW_REQ_BACK,
	DP_TEST_SIP_FLOW_RES_FORW,
	DP_TEST_SIP_FLOW_RES_BACK,
	_DP_TEST_SIP_FLOW_SIZE
};

#define DP_TEST_SIP_FLOW_FIRST (_DP_TEST_SIP_FLOW_REQ_FORW)
#define DP_TEST_SIP_FLOW_LAST  (_DP_TEST_SIP_FLOW_SIZE - 1)

/*
 * Minimum msg size.
 *
 * While the protocol does not define a minimum size directly, the Osip
 * parser assumes minimum of 4 bytes during parsing.
 *
 * A 'real' SIP message must have multiple header fields to be valid and
 * a minimum ACK msg with options stripped out will be > 200 bytes,
 * so let's use that as our min msg size.
 */
#define SIP_MSG_MIN_LENGTH	200


/*
 * SIP translation validation matrix
 *
 * A 'true' indicates that we expect a translation to occur for the specific
 * tuple of 1. message part, 2. NAT flavour and 2. req/resp and direction.
 */
bool    sip_test[_DP_TEST_SIP_PART_SIZE]
		[_DP_TEST_TRANS_SIZE]
		[_DP_TEST_SIP_FLOW_SIZE] = {
	/* REQ_URI */
	{
		/* SNAT */
		{
			false,	/* Other */
			false,	/* Req, forw */
			true,	/* Req, back */
			false,	/* Res, forw */
			false	/* Res, back */
		},
		/* DNAT */
		{
			false,	/* Other */
			true,	/* Req, forw */
			true,	/* Req, back */
			false,	/* Res, forw */
			true	/* Res, back */
		}
	},
	/* TO */
	{
		/* SNAT */
		{
			false,	/* Other */
			false,	/* Req, forw */
			false,	/* Req, back */
			true,	/* Res, forw */
			false	/* Res, back */
		},
		/* DNAT */
		{
			false,	/* Other */
			true,	/* Req, forw */
			true,	/* Req, back */
			true,	/* Res, forw */
			true	/* Res, back */
		}
	},
	/* RECORD_ROUTE */
	{
		/* SNAT */
		{
			false,	/* Other */
			true,	/* Req, forw */
			false,	/* Req, back */
			true,	/* Res, forw */
			true	/* Res, back */
		},
		/* DNAT */
		{
			false,	/* Other */
			false,	/* Req, forw */
			false,	/* Req, back */
			true,	/* Res, forw */
			true	/* Res, back */
		}
	},
	/* ROUTE */
	{
		/* SNAT */
		{
			false,	/* Other */
			true,	/* Req, forw */
			false,	/* Req, back */
			true,	/* Res, forw */
			true	/* Res, back */
		},
		/* DNAT */
		{
			false,	/* Other */
			false,	/* Req, forw */
			false,	/* Req, back */
			true,	/* Res, forw */
			true	/* Res, back */
		}
	},
	/* CONTACT */
	{
		/* SNAT */
		{
			false,	/* Other */
			true,	/* Req, forw */
			false,	/* Req, back */
			true,	/* Res, forw */
			false	/* Res, back */
		},
		/* DNAT */
		{
			false,	/* Other */
			false,	/* Req, forw */
			true,	/* Req, back */
			false,	/* Res, forw */
			true	/* Res, back */
		}
	},
	/* FROM */
	{
		/* SNAT */
		{
			false,	/* Other */
			true,	/* Req, forw */
			false,	/* Req, back */
			false,	/* Res, forw */
			true	/* Res, back */
		},
		/* DNAT */
		{
			false,	/* Other */
			false,	/* Req, forw */
			false,	/* Req, back */
			false,	/* Res, forw */
			false	/* Res, back */
		}
	},
	/* USER_AGENT */
	{
		/* SNAT */
		{
			false,	/* Other */
			true,	/* Req, forw */
			false,	/* Req, back */
			false,	/* Res, forw */
			false	/* Res, back */
		},
		/* DNAT */
		{
			false,	/* Other */
			false,	/* Req, forw */
			false,	/* Req, back */
			false,	/* Res, forw */
			false	/* Res, back */
		}
	},
	/* VIA */
	{
		/* SNAT */
		{
			false,	/* Other */
			true,	/* Req, forw */
			false,	/* Req, back */
			false,	/* Res, forw */
			true	/* Res, back */
		},
		/* DNAT */
		{
			false,	/* Other */
			false,	/* Req, forw */
			false,	/* Req, back */
			false,	/* Res, forw */
			false	/* Res, back */
		}
	},
	/* CALL_ID */
	{
		/* SNAT */
		{
			false,	/* Other */
			true,	/* Req, forw */
			false,	/* Req, back */
			false,	/* Res, forw */
			true	/* Res, back */
		},
		/* DNAT */
		{
			false,	/* Other */
			false,	/* Req, forw */
			false,	/* Req, back */
			false,	/* Res, forw */
			false	/* Res, back */
		}
	}
};

/*
 * Message part strings
 */
const char *dp_test_sip_part_str[_DP_TEST_SIP_PART_SIZE] = {
	"req_uri",
	"to",
	"record_routes",
	"routes",
	"contacts",
	"from",
	"user_agent",
	"via",
	"call_id",
};

/*
 * NAT flavour strings
 */
const char *dp_test_sip_trans_str[_DP_TEST_TRANS_SIZE] = {
	"SNAT",
	"DNAT"
};

const char *dp_test_sip_flow_str[_DP_TEST_SIP_FLOW_SIZE] = {
	"OTHER",
	"REQ FORW",
	"REQ BACK",
	"RES FORW",
	"RES BACK"
};

/*
 * Pull together the various common parameters we need to validate each SIP
 * part
 */
struct dp_test_alg_sip_validate_t {
	struct dp_test_nat_ctx	*nat;
	bool			forw;
	enum dp_test_trans_type	ttype;
	enum dp_test_sip_flow	flow;
	struct sip_alg_request	*orig_sr;	/* pre-trans pkt */
	struct sip_alg_request	*sr;		/* post-trans pkt */
};


/*
 * Derive SIP message flow type
 */
static enum dp_test_sip_flow
dp_test_sip_alg_get_flow(bool is_req, bool is_resp, bool forw)
{
	enum dp_test_sip_flow flow;

	if (!is_resp && !is_req)
		flow = DP_TEST_SIP_FLOW_OTHER;
	else
		flow = (((is_resp ? 1 : 0) << 1) | (forw ? 0 : 1)) + 1;

	return flow;
}

/*
 * Lookup SIP translation matrix to see if a translation is expected for this
 * part-ttype-flow tuple.
 */
static bool dp_test_alg_sip_exp_trans(enum dp_test_alg_sip_part part,
				      enum dp_test_trans_type ttype,
				      enum dp_test_sip_flow flow)
{
	if (part > DP_TEST_SIP_PART_LAST ||
	    ttype > DP_TEST_TRANS_LAST ||
	    flow > DP_TEST_SIP_FLOW_LAST)
		return false;

	return sip_test[part][ttype][flow];
}

/*
 * Tuple to string
 */
static const char *dp_test_alg_sip_desc(enum dp_test_alg_sip_part part,
					enum dp_test_trans_type ttype,
					enum dp_test_sip_flow flow,
					char *str, uint len)
{
	uint l = 0;

	if (ttype <= DP_TEST_TRANS_LAST)
		l += spush(str + l, len - l, "%s",
			   dp_test_sip_trans_str[ttype]);
	else
		l += spush(str + l, len - l, " ttype %u", ttype);

	if (flow <= DP_TEST_SIP_FLOW_LAST)
		l += spush(str + l, len - l, " %s", dp_test_sip_flow_str[flow]);
	else
		l += spush(str + l, len - l, " flow %u", flow);

	if (part <= DP_TEST_SIP_PART_LAST)
		l += spush(str + l, len - l, " %s", dp_test_sip_part_str[part]);
	else
		l += spush(str + l, len - l, " part %u", part);

	return str;
}

/*
 * Allocate a SIP ALG req
 */
static struct sip_alg_request *sip_alg_request_alloc(bool init_sip)
{
	struct sip_alg_request *sr;

	sr = calloc(1, sizeof(struct sip_alg_request));
	if (!sr)
		return NULL;

	if (init_sip && osip_message_init(&sr->sr_sip)) {
		free(sr);
		sr = NULL;
	}

	return sr;
}

/*
 * Free a SIP ALG req
 */
void
dp_test_sip_alg_request_free(struct sip_alg_request *sr)
{
	if (sr->sr_sip)
		osip_message_free(sr->sr_sip);

	if (sr->sr_sdp)
		sdp_message_free(sr->sr_sdp);

	free(sr);
}

/*
 *  Do we have an SDP message in the SIP message?
 */
static bool sip_alg_body_is_sdp(struct sip_alg_request *sr)
{
	osip_content_type_t *ct;

	ct = osip_message_get_content_type(sr->sr_sip);
	if (!ct)
		return false;

	if (ct->type && !strstr(ct->type, "application"))
		return false;

	if (ct->subtype && !strstr(ct->subtype, "sdp"))
		return false;

	return true;
}

/*
 * Get an SDP message from the SIP message bode, and parse it
 */
static int sip_alg_get_sdp(struct sip_alg_request *sr)
{
	osip_body_t *sdp_body;
	sdp_message_t *sdp;
	int rc;

	if (!sip_alg_body_is_sdp(sr))
		return 0;

	rc = osip_message_get_body(sr->sr_sip, 0, &sdp_body);
	if (rc >= 0) {
		sdp_message_init(&sdp);
		rc = sdp_message_parse(sdp, sdp_body->body);
		if (!rc)
			sr->sr_sdp = sdp;
		else
			sdp_message_free(sdp);
	}

	return rc;
}

/*
 * Verify fields we always expect to see in SIP messages
 */
static int
dp_test_sip_alg_verify(struct sip_alg_request *sr, char *err, int len)
{
	if (MSG_IS_REQUEST(sr->sr_sip)) {
		if (!sr->sr_sip->sip_version) {
			if (err)
				spush(err, len, "REQ sip_version");
			return -1;
		}
		if (!sr->sr_sip->req_uri) {
			if (err)
				spush(err, len, "REQ req_uri");
			return -1;
		}
		if (!sr->sr_sip->sip_method) {
			if (err)
				spush(err, len, "REQ sip_method");
			return -1;
		}
	}

	if (MSG_IS_RESPONSE(sr->sr_sip)) {
		if (!sr->sr_sip->reason_phrase) {
			if (err)
				spush(err, len, "RESP reason_phrase");
			return -1;
		}
	}

	if (!sr->sr_sip->to) {
		if (err)
			spush(err, len, "NULL to");
		return -1;
	}
	if (!sr->sr_sip->from) {
		if (err)
			spush(err, len, "NULL from");
		return -1;
	}
	if (!sr->sr_sip->cseq) {
		if (err)
			spush(err, len, "NULL cseq");
		return -1;
	}
	if (!sr->sr_sip->call_id) {
		if (err)
			spush(err, len, "NULL call_id");
		return -1;
	}

	int nvias = osip_list_size(&sr->sr_sip->vias);

	if (nvias <= 0) {
		if (err)
			spush(err, len, "no VIAs");
		return -1;
	}

	return 0;
}

/*
 * Parse a SIP packet using the osip2 library
 */
struct sip_alg_request *
dp_test_sip_alg_parse(struct rte_mbuf *nbuf, bool verify_sip,
		      char *err, int len)
{
	struct sip_alg_request *sr = NULL;
	npf_cache_t npf_cache, *npc;
	uint16_t plen;
	char payload[SIP_MESSAGE_MAX_LENGTH + 1];
	int rc;
	const struct rte_ether_hdr *eh;
	uint16_t ether_type;

	if (!nbuf || !err)
		return NULL;

	/*
	 * setup npf cache
	 */
	npc = &npf_cache;
	npf_cache_init(npc);

	ether_type = 0;
	if (nbuf->l2_len >= ETHER_ADDR_LEN) {
		eh = rte_pktmbuf_mtod(nbuf, struct rte_ether_hdr *);
		ether_type = eh->ether_type;
	} else if (nbuf->l2_len == 0) {
		if (dp_test_mbuf_is_ipv4(nbuf))
			ether_type = htons(ETHER_TYPE_IPv4);
		else if (dp_test_mbuf_is_ipv6(nbuf))
			ether_type = htons(ETHER_TYPE_IPv6);
	}
	if (ether_type == 0) {
		spush(err, len, "Failed to find ether type");
		return NULL;
	}
	if (npf_cache_all(npc, nbuf, ether_type) == false) {
		spush(err, len, "Failed to cache packet");
		return NULL;
	}

	sr = sip_alg_request_alloc(true);
	if (!sr) {
		spush(err, len, "SIP msg alloc");
		return NULL;
	}

	plen = npf_payload_len(npc);
	if (plen > SIP_MESSAGE_MAX_LENGTH || plen < SIP_MSG_MIN_LENGTH) {
		dp_test_sip_alg_request_free(sr);
		spush(err, len, "payload length %u error", plen);
		return NULL;
	}

	if (npf_payload_fetch(npc, nbuf, payload, plen, plen) != plen) {
		dp_test_sip_alg_request_free(sr);
		spush(err, len, "payload fetch failed");
		return NULL;
	}

	/* Make the payload a string */
	payload[plen] = '\0';

	/*
	 * Verify that the SIP msg header content-length value matches the
	 * actual length of the SIP msg body (the SDP part).
	 */
	char *clp;
	uint cl1, cl2;

	clp = dp_test_npf_sip_get_content_length(payload, &cl1);
	if (clp) {
		cl2 = dp_test_npf_sip_calc_content_length(payload);
		if (cl2 != cl1) {
			dp_test_sip_alg_request_free(sr);
			spush(err, len,
			      "SIP content-length field %u "
			      "does not match actual length %u",
			      cl1, cl2);
			printf("\n%s\n\n", payload);
			return NULL;
		}
	}

	rc = osip_message_parse(sr->sr_sip, payload, plen);
	if (rc != 0) {
		dp_test_sip_alg_request_free(sr);
		spush(err, len, "OSIP msg parse (%d)", rc);
		return NULL;
	}

	/* Get the sdp portion if present */
	rc = sip_alg_get_sdp(sr);
	if (rc) {
		dp_test_sip_alg_request_free(sr);
		spush(err, len, "failed to get SDP msg");
		return NULL;
	}

	/*
	 * Conditionally verify that the SIP messages contains a minimum set
	 * of message parts.  (This is conditional in case we want to next the
	 * SIP ALG with an incomplete SIP message.)
	 */
	if (verify_sip) {
		char verr[140];

		rc = dp_test_sip_alg_verify(sr, verr, sizeof(verr));
		if (rc < 0) {
			spush(err, len, "SIP verify failed (%s)", verr);
			dp_test_sip_alg_request_free(sr);
			return NULL;
		}
	}

	return sr;
}

/*
 * SIP uri to string
 */
static char *
dp_test_sip_alg_uri_str(struct osip_uri *uri, char *str, int len)
{
	int l = 0;

	str[0] = '\0';
	if (!uri)
		return str;

	if (uri->host)
		l += spush(str + l, len - l, "%s", uri->host);

	if (uri->port)
		l += spush(str + l, len - l, "%s%s",
			   l > 0 ? " ":"", uri->port);

	return str;
}

/*
 * Is this a SIP request message that we expect to translate?
 */
static bool
dp_test_sip_alg_is_req(struct sip_alg_request *sr)
{
	return MSG_IS_REQUEST(sr->sr_sip);
}

/*
 * Is this a SIP response message that we expect to translate?
 */
static bool
dp_test_sip_alg_is_resp(struct sip_alg_request *sr)
{
	return MSG_IS_RESPONSE(sr->sr_sip);
}

/*
 * Validate SIP uri
 *
 * orig_uri - uri in pre-nat packet
 * uri      - uri in post-nat packet
 * o_uri    - original host and port, derived from nat config
 * e_uri    - expected host and port, derived from nat config, may be
 *            the same as o_uri
 *
 * We only compare the post-nat uri with the expected host or port *if* the
 * pre-nat uri matched the original addr/port (forwards dir) or the
 * translation addr/port (backwards dir).  This avoids us comparing uri's that
 * are FQD names.
 */
static bool
dp_test_sip_alg_validate_uri(struct osip_uri *orig_uri,
			     struct osip_uri *uri,
			     struct osip_uri *o_uri,
			     struct osip_uri *e_uri,
			     char *str, int slen)
{
	char orig_uri_str[40];
	char uri_str[40];
	char o_uri_str[40];
	char e_uri_str[40];

	dp_test_sip_alg_uri_str(orig_uri, orig_uri_str, sizeof(orig_uri_str));
	dp_test_sip_alg_uri_str(uri, uri_str, sizeof(uri_str));
	dp_test_sip_alg_uri_str(o_uri, o_uri_str, sizeof(o_uri_str));
	dp_test_sip_alg_uri_str(e_uri, e_uri_str, sizeof(e_uri_str));

	if (uri->host && orig_uri->host) {
		/*
		 * Does the pre-nat host match the address to be translated?
		 */
		if (strcmp(orig_uri->host, o_uri->host) == 0) {
			/*
			 * Does post-nat host match translation addr?
			 */
			if (strcmp(uri->host, e_uri->host) != 0) {
				spush(str, slen, ", Expected %s, found %s",
				      e_uri->host, uri->host);
				return false;
			}
		} else {
			/*
			 * pre-nat host does not match the address to be
			 * translated, so check that the post-NAT host matches
			 * thes pre-NAT host.
			 */
			if (strcmp(orig_uri->host, uri->host) != 0) {
				spush(str, slen, ", Expected %s, found %s",
				      orig_uri->host, uri->host);
				return false;
			}
		}
	}

	if (uri->port && orig_uri->port) {
		/* Does the pre-nat port match the port to be translated? */
		if (strcmp(orig_uri->port, o_uri->port) == 0) {
			/* Does post-nat port match translation port? */
			if (strcmp(uri->port, e_uri->port) != 0) {
				spush(str, slen, ", Expected %s, found %s",
				      e_uri_str, uri_str);
				return false;
			}
		} else {
			if (strcmp(orig_uri->port, uri->port) != 0) {
				spush(str, slen, ", Expected %s, found %s",
				      orig_uri_str, uri_str);
				return false;
			}
		}
	}

	return true;
}

static void
dp_test_sip_alg_pre_trans(struct dp_test_nat_ctx *nat,
			  bool forw, char **hostp,
			  char **portp)
{
	if (forw) {
		if (hostp)
			*hostp = nat->oaddr_str;
		if (portp)
			*portp = nat->oport_str;
	} else {
		if (hostp)
			*hostp = nat->taddr_str;
		if (portp)
			*portp = nat->tport_str;
	}
}

static void
dp_test_sip_alg_post_trans(struct dp_test_nat_ctx *nat,
			   bool exp_trans, bool forw, char **hostp,
			   char **portp)
{
	if (exp_trans) {
		/*
		 * Translation expected
		 */
		if (forw) {
			if (hostp)
				*hostp = nat->taddr_str;
			if (portp)
				*portp = nat->tport_str;
		} else {
			if (hostp)
				*hostp = nat->oaddr_str;
			if (portp)
				*portp = nat->oport_str;
		}
	} else {
		/*
		 * No translation expected.  Check the oaddr in the forwards
		 * direction, or the taddr in the reverse direction, have not
		 * changed.
		 */
		if (forw) {
			if (hostp)
				*hostp = nat->oaddr_str;
			if (portp)
				*portp = nat->oport_str;
		} else {
			if (hostp)
				*hostp = nat->taddr_str;
			if (portp)
				*portp = nat->tport_str;
		}
	}
}

/*
 * Validate a message part uri
 */
static bool
dp_test_sip_alg_validate_part(enum dp_test_alg_sip_part part,
			      struct dp_test_alg_sip_validate_t *v,
			      struct osip_uri *orig_uri,
			      struct osip_uri *uri,
			      char *err, int len)
{
	struct osip_uri o_uri, e_uri;
	struct dp_test_nat_ctx	*nat;
	const char *part_str;
	bool exp_trans;
	bool rv;

	nat = v->nat;
	part_str = dp_test_sip_part_str[part];

	/* Exit if both uri's not present */
	if (orig_uri == NULL && uri == NULL)
		return true;

	if (orig_uri == NULL) {
		spush(err, len, "Orig %s missing", part_str);
		return false;
	}
	if (uri == NULL) {
		spush(err, len, "Trans %s missing", part_str);
		return false;
	}

	/* Do we expect this uri to be translated? */
	exp_trans = dp_test_alg_sip_exp_trans(part, v->ttype, v->flow);

	/*
	 * Get the address and port strings to look for in the original
	 * message.
	 */
	dp_test_sip_alg_pre_trans(nat, v->forw,
				  &o_uri.host, &o_uri.port);

	/*
	 * Get the address and port strings we expect to find in the
	 * translated message. These may be the same as those in the original
	 * message if no translation has occurred.
	 */
	dp_test_sip_alg_post_trans(nat, exp_trans, v->forw,
				   &e_uri.host, &e_uri.port);

	char desc[100];

	dp_test_alg_sip_desc(part, v->ttype, v->flow, desc, sizeof(desc));

	/*
	 * Validate the uri is either the translate value or the original
	 * value
	 */
	rv = dp_test_sip_alg_validate_uri(orig_uri, uri, &o_uri, &e_uri,
					  desc + strlen(desc),
					  sizeof(desc) - strlen(desc));
	if (!rv)
		spush(err, len, "%s", desc);

	return rv;
}

/*
 * Validate "req_uri" uri
 */
static bool
dp_test_sip_alg_validate_req_uri(struct dp_test_alg_sip_validate_t *v,
				 char *err, int len)
{
	struct sip_alg_request *orig_sr = v->orig_sr;
	struct sip_alg_request *sr = v->sr;
	bool rv;

	rv = dp_test_sip_alg_validate_part(DP_TEST_SIP_PART_REQ_URI, v,
					   orig_sr->sr_sip->req_uri,
					   sr->sr_sip->req_uri,
					   err, len);
	return rv;
}

/*
 * Validate "to" uri
 */
static bool
dp_test_sip_alg_validate_to(struct dp_test_alg_sip_validate_t *v,
			    char *err, int len)
{
	struct sip_alg_request *orig_sr = v->orig_sr;
	struct sip_alg_request *sr = v->sr;
	bool rv;

	rv = dp_test_sip_alg_validate_part(DP_TEST_SIP_PART_TO, v,
					   orig_sr->sr_sip->to->url,
					   sr->sr_sip->to->url,
					   err, len);
	return rv;
}

/*
 * Validate "record_routes" list uris
 *
 * Note, there is currently a bug in our code such that only the first URI is
 * translated.
 */
static bool
dp_test_sip_alg_validate_rroutes(struct dp_test_alg_sip_validate_t *v,
				 char *err, int len)
{
	struct sip_alg_request *sr, *orig_sr;
	osip_record_route_t *rr, *orig_rr;
	osip_list_iterator_t iterator;
	uint pos;
	bool rv;
	int rc;

	orig_sr = v->orig_sr;
	sr = v->sr;

	rr = osip_list_get_first(&sr->sr_sip->record_routes, &iterator);
	if (!rr)
		return true;
	pos = 0;

	while (osip_list_iterator_has_elem(iterator)) {
		rc = osip_message_get_record_route(orig_sr->sr_sip, pos,
						   &orig_rr);
		if (rc < 0) {
			spush(err, len,
			      "Failed to get orig record_route %u", pos);
			return false;
		}

		rv = dp_test_sip_alg_validate_part(DP_TEST_SIP_PART_RROUTE, v,
						   orig_rr->url, rr->url,
						   err, len);

		if (!rv)
			break;
		rr = osip_list_get_next(&iterator);
		pos++;
	}

	return rv;
}

/*
 * Validate "routes" list uris
 */
static bool
dp_test_sip_alg_validate_routes(struct dp_test_alg_sip_validate_t *v,
				char *err, int len)
{
	struct sip_alg_request *orig_sr = v->orig_sr;
	struct sip_alg_request *sr = v->sr;
	bool rv;
	int rc;
	osip_list_iterator_t iterator;
	osip_route_t *r, *orig_r;
	uint pos;

	r = osip_list_get_first(&sr->sr_sip->routes, &iterator);
	if (!r)
		return true;
	pos = 0;

	while (osip_list_iterator_has_elem(iterator)) {
		rc = osip_message_get_route(orig_sr->sr_sip, pos,
					    &orig_r);
		if (rc < 0) {
			spush(err, len,
			      "Failed to get orig route %u", pos);
			return false;
		}

		rv = dp_test_sip_alg_validate_part(DP_TEST_SIP_PART_ROUTE, v,
						   orig_r->url, r->url,
						   err, len);

		if (!rv)
			break;
		r = osip_list_get_next(&iterator);
		pos++;
	}

	return rv;
}

/*
 * Validate "contacts" list uris
 */
static bool
dp_test_sip_alg_validate_contacts(struct dp_test_alg_sip_validate_t *v,
				  char *err, int len)
{
	struct sip_alg_request *orig_sr = v->orig_sr;
	struct sip_alg_request *sr = v->sr;
	bool rv;
	int rc;
	osip_list_iterator_t iterator;
	osip_contact_t *c, *orig_c;
	uint pos;

	c = osip_list_get_first(&sr->sr_sip->contacts, &iterator);
	if (!c)
		return true;
	pos = 0;

	while (osip_list_iterator_has_elem(iterator)) {
		rc = osip_message_get_contact(orig_sr->sr_sip, pos, &orig_c);
		if (rc < 0) {
			spush(err, len,
			      "Failed to get orig contact %u", pos);
			return false;
		}

		rv = dp_test_sip_alg_validate_part(DP_TEST_SIP_PART_CONTACT, v,
						   orig_c->url, c->url,
						   err, len);

		if (!rv)
			break;
		c = osip_list_get_next(&iterator);
		pos++;
	}

	return rv;
}

/*
 * Validate "from" uri
 */
static bool
dp_test_sip_alg_validate_from(struct dp_test_alg_sip_validate_t *v,
			      char *err, int len)
{
	struct sip_alg_request *orig_sr = v->orig_sr;
	struct sip_alg_request *sr = v->sr;
	bool rv;

	rv = dp_test_sip_alg_validate_part(DP_TEST_SIP_PART_FROM, v,
					   orig_sr->sr_sip->from->url,
					   sr->sr_sip->from->url,
					   err, len);
	return rv;
}

/*
 * Validate "user_agent" uri
 */
static bool
dp_test_sip_alg_validate_user_agent(struct dp_test_alg_sip_validate_t *v,
				    char *err, int len)
{
	struct sip_alg_request *orig_sr = v->orig_sr;
	struct sip_alg_request *sr = v->sr;
	osip_header_t *ua, *orig_ua;
	bool forw = v->forw;
	bool exp_trans;
	char desc[30];

	osip_message_get_user_agent(sr->sr_sip, 0, &ua);
	osip_message_get_user_agent(orig_sr->sr_sip, 0, &orig_ua);

	if (!ua || !orig_ua)
		return true;

	dp_test_alg_sip_desc(DP_TEST_SIP_PART_USER_AGENT, v->ttype, v->flow,
			     desc, sizeof(desc));

	/* Do we expect this to be translated? */
	exp_trans = dp_test_alg_sip_exp_trans(DP_TEST_SIP_PART_USER_AGENT,
					      v->ttype, v->flow);

	char *o_host, *e_host;

	dp_test_sip_alg_pre_trans(v->nat, forw, &o_host, NULL);
	dp_test_sip_alg_post_trans(v->nat, exp_trans, forw, &e_host, NULL);

	/*
	 * Does pre-trans packet user_agent contain the orig address?
	 */
	char *p, *orig_p;

	orig_p = strstr(orig_ua->hvalue, o_host);
	if (!orig_p)
		return true;

	/*
	 * Does the post-trans user_agent string contain the expected host?
	 */
	p = strstr(ua->hvalue, e_host);

	if (!p) {
		spush(err, len,
		      "%s, Failed to find \"%s\" in user_agent \"%s\"",
		      desc, e_host, ua->hvalue);
		return false;
	}

	return true;
}

/*
 * Validate "via" uri
 */
static bool
dp_test_sip_alg_validate_via(struct dp_test_alg_sip_validate_t *v,
			     char *err, int len)
{
	struct sip_alg_request *orig_sr = v->orig_sr;
	struct sip_alg_request *sr = v->sr;
	bool forw = v->forw;
	char desc[30];

	dp_test_alg_sip_desc(DP_TEST_SIP_PART_VIA, v->ttype, v->flow,
			     desc, sizeof(desc));

	osip_via_t *via = NULL, *orig_via = NULL;
	char *host = NULL;		/* host in post-nat pkt */
	char *orig_host = NULL;		/* host in pre-nat pkt */
	char *o_host = NULL;		/* original addr from NAT cfg */
	char *e_host = NULL;		/* expected host in translated pkt */
	char *port = NULL, *orig_port = NULL, *o_port = NULL, *e_port = NULL;
	bool exp_trans;

	osip_message_get_via(sr->sr_sip, 0, &via);
	osip_message_get_via(orig_sr->sr_sip, 0, &orig_via);

	if (!via && !orig_via)
		return true;

	if (!orig_via) {
		spush(err, len, "Orig via missing, %s", desc);
		return false;
	}
	if (!via) {
		spush(err, len, "Trans via missing, %s", desc);
		return false;
	}

	/* Do we expect this to be translated? */
	exp_trans = dp_test_alg_sip_exp_trans(DP_TEST_SIP_PART_VIA,
					      v->ttype, v->flow);

	host = osip_via_get_host(via);
	orig_host = osip_via_get_host(orig_via);

	port = osip_via_get_port(via);
	orig_port = osip_via_get_port(orig_via);

	dp_test_sip_alg_pre_trans(v->nat, forw, &o_host, &o_port);
	dp_test_sip_alg_post_trans(v->nat, exp_trans, forw, &e_host, &e_port);

	if (o_host && orig_host)
		/* Does the pre-nat host match the address to be translated? */
		if (strcmp(orig_host, o_host) == 0)
			/* Does post-nat host match translation addr? */
			if (strcmp(host, e_host) != 0) {
				spush(err, len, "%s, Expd: %s, Found: %s",
				      desc, e_host, host);
				return false;
			}

	if (o_port && orig_port)
		/* Does the pre-nat port match the address to be translated? */
		if (strcmp(orig_port, o_port) == 0)
			/* Does post-nat port match translation addr? */
			if (e_port && strcmp(port, e_port) != 0) {
				spush(err, len, "%s, Expd: %s, Found: %s",
				      desc, e_port, port);
				return false;
			}

	return true;
}

/*
 * Validate "call_id" uri
 */
static bool
dp_test_sip_alg_validate_call_id(struct dp_test_alg_sip_validate_t *v,
				 char *err, int len)
{
	struct sip_alg_request *orig_sr = v->orig_sr;
	struct sip_alg_request *sr = v->sr;
	bool forw = v->forw;
	char desc[30];

	dp_test_alg_sip_desc(DP_TEST_SIP_PART_CALL_ID, v->ttype, v->flow,
			     desc, sizeof(desc));

	char *host = NULL;	/* host in post-nat pkt */
	char *orig_host = NULL;	/* host in pre-nat pkt */
	char *o_host = NULL;	/* original addr from NAT cfg */
	char *e_host = NULL;	/* expected addr in translated pkt */
	bool exp_trans;

	osip_call_id_t *cid, *orig_cid;

	cid = osip_message_get_call_id(sr->sr_sip);
	host = osip_call_id_get_host(cid);

	orig_cid = osip_message_get_call_id(orig_sr->sr_sip);
	orig_host = osip_call_id_get_host(orig_cid);

	if (!host && !orig_host)
		return true;

	if (!host) {
		spush(err, len, "Orig call_id missing, %s", desc);
		return false;
	}
	if (!orig_host) {
		spush(err, len, "Trans call_id missing, %s", desc);
		return false;
	}

	/* Do we expect this to be translated? */
	exp_trans = dp_test_alg_sip_exp_trans(DP_TEST_SIP_PART_CALL_ID,
					      v->ttype, v->flow);

	dp_test_sip_alg_pre_trans(v->nat, forw, &o_host, NULL);
	dp_test_sip_alg_post_trans(v->nat, exp_trans, forw, &e_host, NULL);

	if (o_host && orig_host)
		/* Does the pre-nat host match the address to be translated? */
		if (strcmp(orig_host, o_host) == 0)
			/* Does post-nat host match translation addr? */
			if (strcmp(host, e_host) != 0) {
				spush(err, len, "%s, Expd: %s, Found: %s",
				      desc, e_host, host);
				return false;
			}

	return true;
}

/*
 * This is called *after* the packet has been modified by NAT, but *before*
 * the pkt queued on the tx ring is checked.
 *
 * It parses the SIP message using the SIP library, and checks that embedded
 * uri's have been translated or not, dependent upon DNAT or SNAT, direction,
 * and whether its a Request or a Response.
 */
static void
dp_test_alg_sip_validate_cb(struct rte_mbuf *mbuf, struct ifnet *ifp,
			    struct dp_test_expected *expected,
			    enum dp_test_fwd_result_e fwd_result)
{
	struct dp_test_alg_sip_ctx *ctx = NULL;
	struct dp_test_nat_ctx *nat = NULL;
	struct sip_alg_request *sr = NULL;
	char err[120];
	bool rv;

	err[0] = '\0';

	if (!mbuf || !ifp || !expected)
		return;

	ctx = dp_test_exp_get_validate_ctx(expected);

	if (!ctx) {
		spush(expected->description, sizeof(expected->description),
		      "NULL ctx");
		goto end;
	}

	/*
	 * First, do basic NAT validation
	 */
	if (!dp_test_nat_validate(mbuf, ifp, ctx->nat, err, sizeof(err)))
		goto nat_error;

	nat = ctx->nat;

	/*
	 * Check that the packet can be parsed by the SIP library
	 */
	sr = dp_test_sip_alg_parse(mbuf, true, ctx->file, ctx->line);
	if (!sr) {
		spush(expected->description, sizeof(expected->description),
		      "SIP parse error");
		_dp_test_fail(expected->file, expected->line,
			      "SIP parse error");
		goto end;
	}

	/*
	 * Conditionally validate each URL in the SIP message
	 */
	struct dp_test_alg_sip_validate_t val;

	val.nat = nat;
	val.sr = sr;
	val.orig_sr = ctx->orig_sr;
	val.forw = (nat->dir == DP_TEST_NAT_DIR_FORW);
	val.ttype = nat->dnat ? DP_TEST_TRANS_DNAT : DP_TEST_TRANS_SNAT;
	val.flow = dp_test_sip_alg_get_flow(dp_test_sip_alg_is_req(sr),
					    dp_test_sip_alg_is_resp(sr),
					    val.forw);

	/*
	 * Validate "req_uri"
	 */
	rv = dp_test_sip_alg_validate_req_uri(&val, err, sizeof(err));
	if (!rv)
		goto error;

	/*
	 * Validate "to"
	 */
	rv = dp_test_sip_alg_validate_to(&val, err, sizeof(err));
	if (!rv)
		goto error;

	/*
	 * Validate "record_route" list
	 */
	rv = dp_test_sip_alg_validate_rroutes(&val, err, sizeof(err));
	if (!rv)
		goto error;

	/*
	 * Validate "route" list
	 */
	rv = dp_test_sip_alg_validate_routes(&val, err, sizeof(err));
	if (!rv)
		goto error;

	/*
	 * Validate "contact" list
	 */
	rv = dp_test_sip_alg_validate_contacts(&val, err, sizeof(err));
	if (!rv)
		goto error;

	/*
	 * Validate "from"
	 */
	rv = dp_test_sip_alg_validate_from(&val, err, sizeof(err));
	if (!rv)
		goto error;

	/*
	 * Validate "user_agent"
	 */
	rv = dp_test_sip_alg_validate_user_agent(&val, err, sizeof(err));
	if (!rv)
		goto error;

	/*
	 * Validate "via"
	 */
	rv = dp_test_sip_alg_validate_via(&val, err, sizeof(err));
	if (!rv)
		goto error;

	/*
	 * Validate "call_id"
	 */
	rv = dp_test_sip_alg_validate_call_id(&val, err, sizeof(err));
	if (!rv)
		goto error;

	goto end;

error:
	spush(expected->description, sizeof(expected->description),
	      "SIP error %s", err);

	_dp_test_fail(expected->file, expected->line,
		      "SIP validation error \"%s\"", err);
	goto end;

nat_error:
	spush(expected->description, sizeof(expected->description),
	      "NAT error %s", err);
	_dp_test_fail(expected->file, expected->line,
		      "NAT validation error \"%s\"", err);

end:
	if (sr)
		dp_test_sip_alg_request_free(sr);

	if (ctx) {
		if (ctx->orig_sr) {
			dp_test_sip_alg_request_free(ctx->orig_sr);
			ctx->orig_sr = NULL;
		}

		/* finally, call the saved check routine */
		if (ctx->saved_cb)
			(ctx->saved_cb)(mbuf, ifp, expected, fwd_result);
	}
}

/*
 * Setup SIP packet validation callback and context
 */
void
_dp_test_alg_sip_set_validation(struct dp_test_alg_sip_ctx *ctx,
				struct rte_mbuf *test_pak,
				struct rte_mbuf *trans_pak,
				struct dp_test_expected *test_exp,
				const char *file, int line)
{
	struct sip_alg_request *orig_sr, *sr;
	char err[120];

	orig_sr = dp_test_sip_alg_parse(test_pak, true, err, sizeof(err));
	_dp_test_fail_unless(orig_sr, file, line,
			     "%s\n"
			     "test_pak sip parse error (%s)",
			     test_exp->description,
			     err);

	/* Check the trans_pak is a valid SIP message */
	sr = dp_test_sip_alg_parse(trans_pak, true, err, sizeof(err));
	_dp_test_fail_unless(sr, file, line,
			     "%s\n"
			     "trans_pak sip parse error (%s)",
			     test_exp->description,
			     err);

	if (sr)
		dp_test_sip_alg_request_free(sr);

	ctx->orig_sr = orig_sr;
	strncpy(ctx->file, file, sizeof(ctx->file) - 1);
	ctx->file[sizeof(ctx->file) - 1] = '\0';
	ctx->line = line;

	dp_test_exp_set_validate_ctx(test_exp, ctx, false);
	dp_test_exp_set_validate_cb(test_exp, dp_test_alg_sip_validate_cb);
}

/*
 * Creates a test packet from a packet descriptor and a SIP payload string.
 */
struct rte_mbuf *
dp_test_npf_alg_sip_pak(struct dp_test_pkt_desc_t *pkt, const char *payload)
{
	struct rte_mbuf *m;
	struct iphdr *ip;
	struct udphdr *udp;

	if (!pkt || !payload || strlen(payload) == 0)
		return NULL;

	pkt->len = strlen(payload);

	m = dp_test_v4_pkt_from_desc(pkt);
	ip = iphdr(m);
	udp = (struct udphdr *)(ip + 1);
	udp->check = 0;

	memcpy((char *)(udp + 1), payload, strlen(payload));

	ip->check = 0;
	ip->check = ip_checksum(ip, ip->ihl*4);

	udp->check = 0;
	udp->check = dp_test_ipv4_udptcp_cksum(m, ip, udp);

	return m;
}

/*
 * Creates a test packet from a packet descriptor and an RTP data array.
 */
struct rte_mbuf *
dp_test_npf_alg_rtp_pak(struct dp_test_pkt_desc_t *pkt,	const uint8_t *payload,
			uint plen)
{
	struct rte_mbuf *m;
	struct iphdr *ip;
	struct udphdr *udp;

	if (!pkt || !payload)
		return NULL;

	pkt->len = plen;

	m = dp_test_v4_pkt_from_desc(pkt);
	ip = iphdr(m);
	udp = (struct udphdr *)(ip + 1);

	memcpy((char *)(udp + 1), payload, plen);

	return m;
}

/*
 * Run a SIP payload through the parser to check it is valid
 */
bool
_dp_test_npf_alg_sip_payload_check(const char *payload, uint plen, bool sdp,
				   char *file, int line)
{
	struct sip_alg_request *sr = NULL;
	char err[120];
	int rc;

	sr = sip_alg_request_alloc(true);
	_dp_test_fail_unless(sr != NULL, file, line,
			     "Failed to alloc or init SIP req");
	if (sr == NULL)
		return false;

	rc = osip_message_parse(sr->sr_sip, payload, plen);
	_dp_test_fail_unless(rc == 0, file, line,
			     "SIP parse error %d", rc);

	/* Get the sdp portion if present */
	if (sdp) {
		rc = sip_alg_get_sdp(sr);
		_dp_test_fail_unless(rc == 0, file, line,
				     "Failed to get SDP");
	}

	rc = dp_test_sip_alg_verify(sr, err, sizeof(err));
	_dp_test_fail_unless(rc == 0, file, line, "SIP verify failed");

	dp_test_sip_alg_request_free(sr);
	return true;
}

__attribute__((format(printf, 1, 2)))
void
dp_test_npf_sip_debug(const char *fmt, ...)
{
	char buf[1000];
	int l = 0;
	va_list args;

#if DP_TEST_SIP_DEBUG == 0
	return;
#endif

	if (!fmt)
		return;

	va_start(args, fmt);
	l += vsnprintf(buf + l, sizeof(buf) - l, fmt, args);
	va_end(args);

	printf("%s\n", buf);
}
