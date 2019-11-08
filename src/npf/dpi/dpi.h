/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef DPI_H
#define DPI_H

#include <stdbool.h>
#include <stdint.h>
#include "json_writer.h"

/*
 * Everything declared here MUST be defined in BOTH dpi.c and dpi_stubs.c
 * for builds with, and without, DPI.
 */

/*
 * From
 * https://www.iana.org/assignments/ipfix/ipfix.xhtml#classification-engine-ids
 */
#define IANA_RESERVED		0
#define IANA_USER		6
#define IANA_QOSMOS		21

#define DPI_ENGINE_RESERVED	(IANA_RESERVED << DPI_ENGINE_SHIFT)
#define DPI_ENGINE_QOSMOS	(IANA_QOSMOS << DPI_ENGINE_SHIFT)
#define DPI_ENGINE_USER		(IANA_USER << DPI_ENGINE_SHIFT)

/* Error codes */
#define _DPI_APP_NA		0	/* Not available, e.g. not in image */
#define _DPI_APP_ERROR		1	/* Error occurred during processing */
#define _DPI_APP_UNDETERMINED	2	/* Determination not yet available */
#define DPI_APP_BASE		3	/* First app ID; equals Q_PROTO_BASE */

/* Generic error codes */
#define DPI_APP_NA		(DPI_ENGINE_RESERVED | _DPI_APP_NA)
#define DPI_APP_ERROR		(DPI_ENGINE_RESERVED | _DPI_APP_ERROR)
#define DPI_APP_UNDETERMINED	(DPI_ENGINE_RESERVED | _DPI_APP_UNDETERMINED)

/*
 * User engine error codes.
 * Set the engine bits to indicate that the determination was made by
 * the user engine (app DB).
 */
#define DPI_APP_USER_NA		(DPI_ENGINE_USER | _DPI_APP_NA)

#define DPI_APP_TYPE_NONE	0

#define DPI_SUCCESS QMDPI_SUCCESS
#define DPI_FAILURE QMDPI_EPERM

/*
 * Application ID format:
 *
 *  33222222 22221111 11111100 00000000
 *  10987654 32109876 54321098 76543210
 * +--------+--------+--------+--------+
 * | Engine |Q      Application ID     |
 * +--------+--------+--------+--------+
 *
 * Engine: IANA_QOSMOS or IANA_USER
 *
 * Q: For user-defined applications:
 *    0 = Qosmos compatible ID; 1 = internally allocated ID.
 *    Q is the topmost bit in the application ID.
 *
 * Application ID: unique identifier per application.
 *
 *
 * There are three application classes:
 *
 * 1. Qosmos:
 *	Engine = IANA_QOSMOS; Q doesn't apply. AppID is assigned by Qosmos.
 *	No entry is made in the app DB.
 *
 * 2a. User-defined, Qosmos compatible (ie, shared app name):
 *	Engine = IANA_USER; Q = 0. AppID is assigned by Qosmos.
 *	An entry (or refcount) is made in the app DB.
 *
 * 2b. User-defined, Qosmos incompatible (ie, unique user app name):
 *	Engine = IANA_USER;  Q = 1. AppID is assigned internally by vRouter.
 *	An entry (or refcount) is made in the app DB.
 */

/* DPI engine is in the topmost bits */
#define DPI_ENGINE_SHIFT	24

/*
 * The Q bit is the topmost appID bit.
 * It indicates an internally-assigned application ID.
 */
#define APP_ID_Q		(1 << 23)

/* Mask out the DPI engine bits, leaving just Q + the app ID. */
#define DPI_APP_MASK		0x00ffffff

/* Whether the given appID is a Qosmos ID or Qosmos compatible. */
#define APP_ID_QOSMOS(app_id) \
	((app_id >> DPI_ENGINE_SHIFT == IANA_QOSMOS) || \
	 ((app_id >> DPI_ENGINE_SHIFT == IANA_USER) && !(app_id & APP_ID_Q)))

/* dpi_status should be an enum provided by Qosmos in qmdpi_const.h. */
typedef int dpi_status;

/* App DB walker callback function type */
typedef int (*app_walker_t)(json_writer_t *json, void *data);

struct dpi_flow;
/* forward declare some structures */
struct npf_cache;
struct npf_session;
struct rte_mbuf;

struct dpi_flow_stats {
	uint16_t pkts;
	uint16_t bytes;
};

bool dpi_init(void);
void dpi_session_flow_destroy(struct dpi_flow *flow);
int dpi_session_first_packet(struct npf_session *se, struct npf_cache *npc,
			     struct rte_mbuf *mbuf, int dir);
uint32_t dpi_flow_get_app_proto(struct dpi_flow *flow);
uint32_t dpi_flow_get_app_name(struct dpi_flow *flow);
uint64_t dpi_flow_get_app_type(struct dpi_flow *flow);
bool dpi_flow_get_offloaded(struct dpi_flow *flow);
bool dpi_flow_get_error(struct dpi_flow *flow);
const struct dpi_flow_stats *dpi_flow_get_stats(struct dpi_flow *flow,
						bool forw);
uint32_t dpi_app_name_to_id(const char *app_name);
uint32_t dpi_app_name_to_id_qosmos(const char *app_name);
const char *dpi_app_id_to_name(uint32_t app_id);
uint32_t dpi_app_type_name_to_id(const char *type_name);
const char *dpi_app_type_to_name(uint32_t app_type);
void dpi_info_json(struct dpi_flow *dpi_flow, json_writer_t *json);
int appdb_name_walk(json_writer_t *json, app_walker_t callback);
int appdb_id_walk(json_writer_t *json, app_walker_t callback);
int appdb_name_entry_to_json(json_writer_t *json, void *data);
int appdb_id_entry_to_json(json_writer_t *json, void *data);

/* The recommended minimum size to pass as buf_len to dpi_info_log() */
#define MAX_DPI_LOG_SIZE 256
void dpi_info_log(struct dpi_flow *dpi_flow, char *buf, size_t buf_len);

uint32_t appdb_name_to_id(const char *name);
char *appdb_id_to_name(uint32_t app_id);

#endif /* DPI_H */
