/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef ALG_RC_H
#define ALG_RC_H

#include <compiler.h>
#include "util.h"
#include "npf/cgnat/cgn_dir.h"

/*
 * A simple global counter mechanism to get a snapshot of how CGNAT ALG is
 * operating.  It aims to count CGNAT ALG packet errors.  It only applies to
 * the main parent flow inspection routine.
 */
enum alg_rc_en {
	ALG_INFO_OK = 0,

	ALG_ERR_PLOAD_FETCH,
	ALG_ERR_PLOAD_UPDATE,
	ALG_ERR_PLOAD_NOSPC,

	ALG_ERR_PHOLE_NOMEM,
	ALG_ERR_PHOLE_EXIST,

	/* PPTP */
	ALG_ERR_PPTP_MAP,
	ALG_ERR_PPTP_MC,
	ALG_ERR_PPTP_OUT_REQ,
	ALG_ERR_PPTP_OUT_REPLY,

	/* SIP */
	ALG_ERR_SIP_MAP,
	ALG_ERR_SIP_UNSP,
	ALG_ERR_SIP_NOSPC,
	ALG_ERR_SIP_DREQ,
	ALG_ERR_SIP_NOENT,
	ALG_ERR_SIP_NOMEM,
	ALG_ERR_SIP_MEDIA,
	ALG_ERR_SIP_PHOLE,
	ALG_ERR_SIP_MAXCID,

	/* SIP msg header parse errors */
	ALG_ERR_SIP_PARSE_REQ,
	ALG_ERR_SIP_PARSE_RSP,
	ALG_ERR_SIP_PARSE_CID,
	ALG_ERR_SIP_PARSE_VIA,
	ALG_ERR_SIP_PARSE_CTYPE,
	ALG_ERR_SIP_PARSE_CLEN,

	/* SDP msg header parse errors */
	ALG_ERR_SIP_PARSE_SDP,
	ALG_ERR_SIP_PARSE_C,	/* SDP Connection */
	ALG_ERR_SIP_PARSE_M,	/* SDP media */
	ALG_ERR_SIP_PARSE_A,	/* SDP attribute */

	/* FTP */
	ALG_ERR_FTP_MAP,
	ALG_ERR_FTP_PARSE_PORT,
	ALG_ERR_FTP_PARSE_EPRT,
	ALG_ERR_FTP_PARSE_227,
	ALG_ERR_FTP_PARSE_229,

	ALG_ERR_INT,		/* Internal errors */
	ALG_ERR_OTHER,
};

#define ALG_RC_ERR_FIRST	ALG_ERR_PHOLE
#define ALG_RC_LAST		ALG_ERR_OTHER
#define ALG_RC_SZ		(ALG_RC_LAST + 1)

struct alg_rc_dir {
	uint64_t	count[ALG_RC_SZ];
};

struct alg_rc_t {
	struct alg_rc_dir dir[CGN_DIR_SZ];
};

extern struct alg_rc_t *alg_rc;

static inline void alg_rc_inc(enum cgn_dir dir, int error)
{
	if (error < 0)
		error = -error;

	if (unlikely(error > ALG_RC_LAST))
		error = ALG_ERR_OTHER;

	if (likely(alg_rc != NULL))
		alg_rc[dp_lcore_id()].dir[dir].count[error]++;
}

uint64_t alg_rc_read(enum cgn_dir dir, enum alg_rc_en rc);
void alg_rc_clear(enum cgn_dir dir, enum alg_rc_en rc);
void alg_rc_init(void);
void alg_rc_uninit(void);

static inline const char *alg_rc_str(int error)
{
	if (error < 0)
		error = -error;

	switch ((enum alg_rc_en)error) {
	case ALG_INFO_OK:
		return "INFO_OK";

	case ALG_ERR_PLOAD_FETCH:
		return "ERR_PLOAD_FETCH";
	case ALG_ERR_PLOAD_UPDATE:
		return "ERR_PLOAD_UPDATE";
	case ALG_ERR_PLOAD_NOSPC:
		return "ERR_PLOAD_NOSPC";

	case ALG_ERR_PHOLE_NOMEM:
		return "ERR_PHOLE_NOMEM";
	case ALG_ERR_PHOLE_EXIST:
		return "ERR_PHOLE_EXIST";

	case ALG_ERR_PPTP_MAP:
		return "ERR_PPTP_MAP";
	case ALG_ERR_PPTP_OUT_REQ:
		return "ERR_PPTP_OUT_REQ";
	case ALG_ERR_PPTP_OUT_REPLY:
		return "ERR_PPTP_OUT_REPLY";
	case ALG_ERR_PPTP_MC:
		return "ERR_PPTP_MC";

	case ALG_ERR_SIP_MAP:
		return "ERR_SIP_MAP";
	case ALG_ERR_SIP_UNSP:
		return "ERR_SIP_UNSP";
	case ALG_ERR_SIP_NOSPC:
		return "ERR_SIP_NOSPC";
	case ALG_ERR_SIP_DREQ:
		return "ERR_SIP_DREQ";
	case ALG_ERR_SIP_NOENT:
		return "ERR_SIP_NOENT";
	case ALG_ERR_SIP_NOMEM:
		return "ERR_SIP_NOMEM";
	case ALG_ERR_SIP_MEDIA:
		return "ERR_SIP_MEDIA";
	case ALG_ERR_SIP_PHOLE:
		return "ERR_SIP_PHOLE";
	case ALG_ERR_SIP_MAXCID:
		return "ERR_SIP_MAXCID";

	case ALG_ERR_SIP_PARSE_REQ:
		return "ERR_SIP_PARSE_REQ";
	case ALG_ERR_SIP_PARSE_RSP:
		return "ERR_SIP_PARSE_RSP";
	case ALG_ERR_SIP_PARSE_CID:
		return "ERR_SIP_PARSE_CID";
	case ALG_ERR_SIP_PARSE_VIA:
		return "ERR_SIP_PARSE_VIA";
	case ALG_ERR_SIP_PARSE_CTYPE:
		return "ERR_SIP_PARSE_CTYPE";
	case ALG_ERR_SIP_PARSE_CLEN:
		return "ERR_SIP_PARSE_CLEN";

	case ALG_ERR_SIP_PARSE_SDP:
		return "ERR_SIP_PARSE_SDP";
	case ALG_ERR_SIP_PARSE_C:
		return "ERR_SIP_PARSE_C";
	case ALG_ERR_SIP_PARSE_M:
		return "ERR_SIP_PARSE_M";
	case ALG_ERR_SIP_PARSE_A:
		return "ERR_SIP_PARSE_A";

	case ALG_ERR_FTP_PARSE_PORT:
		return "ERR_FTP_PARSE_PORT";
	case ALG_ERR_FTP_PARSE_EPRT:
		return "ERR_FTP_PARSE_EPRT";
	case ALG_ERR_FTP_PARSE_227:
		return "ERR_FTP_PARSE_227";
	case ALG_ERR_FTP_PARSE_229:
		return "ERR_FTP_PARSE_229";
	case ALG_ERR_FTP_MAP:
		return "ERR_FTP_MAP";

	case ALG_ERR_INT:
		return "ERR_INT";

	case ALG_ERR_OTHER:
		break;
	}
	return "ERR_UNKWN";
}

static inline const char *alg_rc_detail_str(int error)
{
	if (error < 0)
		error = -error;

	switch ((enum alg_rc_en)error) {
	case ALG_INFO_OK:
		return "ok";

	case ALG_ERR_PLOAD_FETCH:
		return "Payload fetch failed";

	case ALG_ERR_PLOAD_UPDATE:
		return "Payload update failed";

	case ALG_ERR_PLOAD_NOSPC:
		return "No space at end of buffer";

	case ALG_ERR_PHOLE_NOMEM:
		return "No memory for pinhole entry";

	case ALG_ERR_PHOLE_EXIST:
		return "Pinhole already exists";

	case ALG_ERR_PPTP_MAP:
		return "PPTP failed to get a mapping";

	case ALG_ERR_PPTP_OUT_REQ:
		return "PPTP out call request";

	case ALG_ERR_PPTP_OUT_REPLY:
		return "PPTP out call reply";

	case ALG_ERR_PPTP_MC:
		return "PPTP magic cookie";

	case ALG_ERR_SIP_MAP:
		return "SIP failed to get a mapping";

	case ALG_ERR_SIP_UNSP:
		return "SIP message not supported";

	case ALG_ERR_SIP_NOSPC:
		return "SIP no space in new message";

	case ALG_ERR_SIP_DREQ:
		return "SIP duplicate Invite Request";

	case ALG_ERR_SIP_NOENT:
		return "SIP media table does not exist";

	case ALG_ERR_SIP_NOMEM:
		return "SIP no memory for media entry";

	case ALG_ERR_SIP_MEDIA:
		return "SIP failed to add media entry";

	case ALG_ERR_SIP_PHOLE:
		return "SIP failed to add pinhole entry";

	case ALG_ERR_SIP_MAXCID:
		return "SIP max unresolved call limit";

	case ALG_ERR_SIP_PARSE_REQ:
		return "SIP parse request start-line";

	case ALG_ERR_SIP_PARSE_RSP:
		return "SIP parse response start-line";

	case ALG_ERR_SIP_PARSE_CID:
		return "SIP parse call-id";

	case ALG_ERR_SIP_PARSE_VIA:
		return "SIP parse via";

	case ALG_ERR_SIP_PARSE_CTYPE:
		return "SIP parse content-type";

	case ALG_ERR_SIP_PARSE_CLEN:
		return "SIP parse content-len";

	case ALG_ERR_SIP_PARSE_SDP:
		return "SDP parse";

	case ALG_ERR_SIP_PARSE_C:
		return "SDP parse c-header";

	case ALG_ERR_SIP_PARSE_M:
		return "SDP parse m-header";

	case ALG_ERR_SIP_PARSE_A:
		return "SDP parse a-header";

	case ALG_ERR_FTP_PARSE_PORT:
		return "ftp parse PORT control";

	case ALG_ERR_FTP_PARSE_EPRT:
		return "ftp parse EPRT control";

	case ALG_ERR_FTP_PARSE_227:
		return "ftp parse 227 response";

	case ALG_ERR_FTP_PARSE_229:
		return "ftp parse 229 response";

	case ALG_ERR_FTP_MAP:
		return "ftp failed to get a mapping";

	case ALG_ERR_INT:
		return "Internal";

	case ALG_ERR_OTHER:
		break;
	}
	return "Unknown";
}

#endif /* ALG_RC_H */
