/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _ALG_FTP_H_
#define _ALG_FTP_H_

struct npf_session;
struct npf_cache;
struct apt_tuple;
struct rte_mbuf;
struct npf_nat;

/**
 * Setup FTP ALG parent session.  Called a new npf session is created, and the
 * destination port matches the configured FTP ALG port and protocol is TCP.
 *
 * @param se Pointer to the parent session
 * @param npc Pointer to the npf packet cache
 * @param nt Pointer to the ALG tuple (pinhole) that was matched
 * @param di Direction of packet relative to interface (in or out)
 * @return 0 if successful
 */
int ftp_alg_session_init(struct npf_session *se, struct npf_cache *npc,
			 struct apt_tuple *nt, const int di);

/**
 * An FTP ALG session is being destroyed
 *
 * @param se Pointer to the session
 */
void ftp_alg_session_destroy(struct npf_session *se);

/**
 * Inspect non-NATd packets
 *
 * @param parent Pointer to the parent session
 * @param npc Pointer to the npf packet cache
 * @param nbuf Packet buffer
 * @param ftp ALG data
 */
void ftp_alg_inspect(struct npf_session *parent, struct npf_cache *npc,
		     struct rte_mbuf *nbuf, struct npf_alg *ftp);

/**
 * Is this an FTP control session?
 *
 * @param sa ALG session data
 * @return true is FTP_ALG_CNTL flag set
 */
bool ftp_alg_cntl_session(struct npf_session_alg *sa);

/**
 * ALG protocol and port configuration
 *
 * @param ftp ALG data instance
 * @param op ALG config operations
 * @param argc Number of args
 * @param argv Argument list
 * @return 0 if successful
 */
int ftp_alg_config(struct npf_alg *ftp, enum alg_config_op op, int argc,
		   char *const argv[]);

#endif
