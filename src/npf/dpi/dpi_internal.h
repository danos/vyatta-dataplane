/*
 * Copyright (c) 2017-2018,2020, AT&T Intellectual Property.
 * All rights reserved.
 *
 * Copyright (c) 2016-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef DPI_H
#define DPI_H

#include <stdbool.h>
#include <stdint.h>
#include <rte_mbuf.h>
#include "json_writer.h"
#include "npf/npf_cache.h"

/*
 * From
 * https://www.iana.org/assignments/ipfix/ipfix.xhtml#classification-engine-ids
 */
#define IANA_RESERVED		0
#define IANA_USER		6
#define IANA_NDPI		22

#define DPI_ENGINE_RESERVED	(IANA_RESERVED << DPI_ENGINE_SHIFT)
#define DPI_ENGINE_USER		(IANA_USER << DPI_ENGINE_SHIFT)
#define DPI_ENGINE_NDPI		(IANA_NDPI << DPI_ENGINE_SHIFT)

/* Error codes */
#define _DPI_APP_NA		0	/* Not available, e.g. not in image */
#define _DPI_APP_ERROR		1	/* Error occurred during processing */
#define _DPI_APP_UNDETERMINED	2	/* Determination not yet available */
#define DPI_APP_BASE		3	/* First app ID */

/* Generic error codes */
#define DPI_APP_NA		(DPI_ENGINE_RESERVED | _DPI_APP_NA)
#define DPI_APP_ERROR		(DPI_ENGINE_RESERVED | _DPI_APP_ERROR)
#define DPI_APP_UNDETERMINED	(DPI_ENGINE_RESERVED | _DPI_APP_UNDETERMINED)

/*
 * User engine error codes.
 * Set the engine bits to indicate that the determination was made by
 * the user engine (app DB).
 */
#define DPI_APP_USER_NA		   (DPI_ENGINE_USER | _DPI_APP_NA)
#define DPI_APP_USER_ERROR	   (DPI_ENGINE_USER | _DPI_APP_ERROR)
#define DPI_APP_USER_UNDETERMINED  (DPI_ENGINE_USER | _DPI_APP_UNDETERMINED)

/* ID for the first user-defined application. */
#define DPI_APP_USER_BASE		(DPI_ENGINE_USER | DPI_APP_BASE)

/* Application type codes. */
#define DPI_APP_TYPE_NONE	0

/*
 * Application ID format:
 *
 *  33222222 22221111 11111100 00000000
 *  10987654 32109876 54321098 76543210
 * +--------+--------+--------+--------+
 * | Engine |       Application ID     |
 * +--------+--------+--------+--------+
 *
 * Engine: IANA defined engine ID, such as IANA_NPDI or IANA_USER.
 *
 * Application ID: unique identifier per application, not necessarily unique
 * across engines.
 */

/* DPI engine is in the topmost bits */
#define DPI_ENGINE_SHIFT	24

/* Mask out the DPI engine bits, leaving just the app ID. */
#define DPI_APP_MASK		0x00ffffff

/* DPI direction */
enum dpi_dir {
	DPI_DIR_FORW,
	DPI_DIR_BACK
};

/* Forward declare some structures */
struct npf_cache;
struct npf_session;
struct rte_mbuf;
struct dpi_flow;

struct dpi_flow_stats {
	uint16_t pkts;
	uint16_t bytes;
};

/**
 * "Super type" for all DPI flows.
 * All dpi flow subtypes must include this struct as their first member.
 */
struct dpi_engine_flow {
	uint8_t engine_id;
	struct dpi_flow_stats stats[2];
	bool update_stats;
};


/**
 * Return the global DPI engine.
 * This is a temporary solution until netflow can provide engine IDs.
 */
uint8_t dpi_global_engine(void);

/**
 * Attempt to find the ID of the engine with the given name.
 * Returns IANA_RESERVED if name is NULL or no engine is found, otherwise
 * returns the ID of the engine.
 */
uint8_t dpi_engine_name_to_id(const char *name);

/**
 * Attempt to find the index of the engine with the given ID.
 * Returns -1 if no engine has the given ID,
 * otherwise returns the index of the engine.
 */
int32_t dpi_engine_id_to_idx(uint8_t id);

/**
 * Initialise the engine with the given ID, or all installed engines if the
 * given ID is IANA_RESERVED.
 *
 * Returns:
 *
 *   - if ID is IANA_RESERVED:
 *       errno if any engine's initialisation function fails
 *
 *   - if ID is not IANA_RESERVED:
 *       errno if there is no engine with the given ID,
 *       or the engine's initialisation function fails
 *
 *   - otherwise returns zero indicating success.
 */
int dpi_init(uint8_t engine_id);

/**
 * Terminate the engine with the given ID, or all installed engines if the
 * given ID is IANA_RESERVED.
 *
 * Returns:
 *   - if ID is IANA_RESERVED, false if any engine's termination function
 *     returns false
 *   - if ID is not IANA_RESERVED, false if there is no engine with the given
 *     ID, or the engine's termination function returns false
 *   - otherwise returns true
 */
bool dpi_terminate(uint8_t engine_id);

/**
 * Destroy the given flow using the given engine's flow destructor.
 */
void dpi_session_flow_destroy(struct dpi_flow *flow);

/**
 * Attach DPI to the given session, using mbuf as the first packet of the
 * session.
 *
 * Returns 0 on success, otherwise return the first non-zero return value
 * from the underlying DPI engines.
 */
int dpi_session_first_packet(struct npf_session *se, struct npf_cache *npc,
			     struct rte_mbuf *mbuf, int dir,
			     size_t engines_len, const uint8_t *engines);

/**
 * Invoke the given callback for each DPI engine
 * associated with the given flow.
 *
 * The callback receives the engine, app, proto, type, and data.
 */
void dpi_flow_for_each_engine(struct dpi_flow *flow,
		int (*call)(uint8_t engine, uint32_t app, uint32_t proto,
			uint32_t type, void *data),
		void *data);

/**
 * Get the protocol ID the given flow is detected to be according to the given
 * engine.
 * Returns DPI_APP_ERROR if there is no engine with the given ID, or the flow
 * is in an error state, otherwise returns the protocol ID, which can be
 * undetermined.
 */
uint32_t dpi_flow_get_app_proto(uint8_t engine_id, struct dpi_flow *flow);

/**
 * Get the application ID the given flow is detected to be according to the
 * given engine.
 * Returns DPI_APP_ERROR if there is no engine with the given ID, or the flow
 * is in an error state, otherwise returns the application ID, which can be
 * undetermined.
 */
uint32_t dpi_flow_get_app_id(uint8_t engine_id, struct dpi_flow *flow);

/**
 * Get the application type ID the given flow is detected to be according to
 * the given engine.
 * Returns DPI_APP_ERROR if there is no engine with the given ID, or the flow
 * is in an error state, otherwise returns the application type ID, which can
 * be undetermined.
 */
uint32_t dpi_flow_get_app_type(uint8_t engine_id, struct dpi_flow *flow);

/**
 * Check if all DPI engines running on the given flow deem the given flow is
 * offloaded - ie, they no longer need to see packets for this flow.
 * Returns false if any DPI engine is not finished with the given flow,
 * otherwise returns true.
 */
bool dpi_flow_get_offloaded(struct dpi_flow *flow);

/**
 * Check if all DPI engines running on the given flow deem the given flow to
 * be in an error state.
 * Returns true if all DPI engines deem the flow to be in an error state,
 * otherwise returns true
 */
bool dpi_flow_get_error(struct dpi_flow *flow);

/**
 * Get the packet and byte statistics for the given flow in the given direction.
 * Returns a pointer to the flow stats in the given direction.
 */
const struct dpi_flow_stats *dpi_flow_get_stats(struct dpi_engine_flow *flow,
						bool forw);

/**
 * Get the ID corresponding to the given application name, according to the
 * given engine.
 * Returns DPI_APP_ERROR if there is no engine with the given ID, otherwise
 * returns the ID corresponding to the given application name.
 */
uint32_t dpi_app_name_to_id(uint8_t engine_id, const char *app_name);

/**
 * Get the ID corresponding to the given application type, according to the
 * given engine.
 * Returns DPI_APP_ERROR if there is no engine with the given ID, otherwise
 * returns the ID corresponding to the given application type.
 */
uint32_t dpi_app_type_name_to_id(uint8_t engine_id, const char *type_name);

/**
 * Export the given flow to JSON, with the given writer.
 */
void dpi_info_json(struct dpi_flow *dpi_flow,
		   json_writer_t *json);

/* The recommended maximum size to pass as buf_len to dpi_info_log() */
#define MAX_DPI_LOG_SIZE 256

/**
 * Log the given flow to the given buffer.
 */
void dpi_info_log(struct dpi_flow *dpi_flow, char *buf,
		  size_t buf_len);

/**
 * Get the engine flow from the given flow corresponding to the given
 * engine ID. Packets with no data are not included in the stats
 * (i.e TCP SYN/ACK).
 * Returns NULL if the given flow is NULL or there is no flow for the given
 * engine ID, otherwise returns the engine flow.
 */
struct dpi_engine_flow *dpi_get_engine_flow(struct dpi_flow *flow,
					    uint8_t engine_id);

/*
 * Converts an application ID into a string, writing it to the buffer at
 * "used_buf_len", ensuring it does not go off the end of the buffer.
 *
 * This also handles ids DPI_APP_NA, ERROR and UNDETERMINED.
 */
void dpi_app_id_to_buf(char *buf, size_t *used_buf_len,
		       const size_t total_buf_len, uint32_t id,
		       const char *(*id_to_name)(uint32_t));

/*
 * Converts an application type into a string, writing it to the buffer at
 * "used_buf_len", ensuring it does not go off the end of the buffer.
 *
 * This also handles DPI_APP_TYPE_NONE.
 */
void dpi_app_type_to_buf(char *buf, size_t *used_buf_len,
			 const size_t total_buf_len, uint32_t type,
			 const char *(*id_to_type)(uint32_t));

struct dpi_engine_procs {
	/**
	 * ID of the engine
	 */
	uint8_t id;

	/**
	 * Engine initialisation function
	 * Returns zero if the engine successfully initialised
	 * or has already been initialised; errno otherwise.
	 */
	int (*init)(void);

	/**
	 * Engine termination function
	 * Returns true if the engine successfully terminated
	 * or has already been terminated, false otherwise.
	 */
	bool (*terminate)(void);


	/**
	 * Refcount.
	 */
	void (*refcount_inc)(void);
	uint32_t (*refcount_dec)(void);

	/**
	 * Flow destructor.
	 */
	void (*destructor)(struct dpi_engine_flow *flow);

	/**
	 * Initialise a new flow, setting *flow to the pointer to the new flow,
	 * and running the engine on the first packet. The data_len argument is
	 * the size of the packet without L3 and L4 headers.
	 * The first packet may have no contents (i.e TCP SYN), data_len will
	 * be 0 in this case.
	 * Non-zero return values are propagated up.
	 */
	int (*first_packet)(struct npf_session *se, struct npf_cache *npc,
			    struct rte_mbuf *mbuf, int dir, uint32_t data_len,
			    struct dpi_engine_flow **flow);

	/**
	 * Process the given packet.
	 * This is called for each non-first, non-empty packet for the given
	 * flow, unless the flow is in an error state or offloaded, as defined
	 * by 'is_error', and 'is_offloaded' respectively.
	 * Return true on success, false otherwise.
	 */
	bool (*process_pkt)(struct dpi_engine_flow *flow,
			    struct rte_mbuf *mbuf,
			    int dir);

	/**
	 * If a flow is in an error state, no further processing will be
	 * carried out.
	 * Return true if the given flow is in an error state, false otherwise.
	 */
	bool (*is_error)(struct dpi_engine_flow *flow);

	/**
	 * A flow should be deemed as offloaded when there should be no more
	 * DPI processing carried out on the flow.
	 *
	 * For example:
	 *   - the flow's application cannot be determined with any further
	 *     processing
	 *   - The flow's application has been determined
	 *
	 * Return true if the given flow is offloaded, false otherwise.
	 */
	bool (*is_offloaded)(struct dpi_engine_flow *flow);

	/**
	 * Get the protocol ID of the given flow.
	 */
	uint32_t (*flow_get_proto)(struct dpi_engine_flow *flow);

	/**
	 * Get the application ID of the given flow.
	 */
	uint32_t (*flow_get_id)(struct dpi_engine_flow *flow);

	/**
	 * Get the application type ID of the given flow.
	 */
	uint32_t (*flow_get_type)(struct dpi_engine_flow *flow);

	/**
	 * Get the ID for the given name.
	 */
	uint32_t (*name_to_id)(const char *name);

	/**
	 * Get the ID for the given type.
	 */
	uint32_t (*type_to_id)(const char *type);

	/**
	 * Write the JSON representation of the given flow to the given
	 * writer. Return false if nothing was written, else true.
	 */
	bool (*info_json)(struct dpi_engine_flow *flow, json_writer_t *json);

	/**
	 * Log the given flow to the given buf.
	 * Return amount of buf used to log the flow.
	 */
	size_t (*info_log)(struct dpi_engine_flow *flow, char *buf,
			   size_t buf_len);

	/**
	 * Get name of app id.
	 */
	const char* (*appid_to_name)(uint32_t app);

	/**
	 * Get type of type id.
	 */
	const char* (*apptype_to_name)(uint32_t type);
};

const char *dpi_app_id_to_name(uint8_t engine_id, uint32_t app);
const char *dpi_app_type_to_name(uint8_t engine_id, uint32_t type);


bool no_app_id(uint32_t app_id);
bool no_app_type(uint32_t app_type);

void dpi_refcount_inc(uint8_t engine_id);
uint32_t dpi_refcount_dec(uint8_t engine_id);

/* Return true if the sum of the forward and backward packet counts
 * for the given dpi_flow is greater than the specified maximum.
 */
bool dpi_flow_pkt_count_maxed(struct dpi_flow *dpi_flow, uint32_t max);

#endif /* DPI_H */
