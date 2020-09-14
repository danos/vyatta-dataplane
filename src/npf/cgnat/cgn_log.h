/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _CGN_LOG_H_
#define _CGN_LOG_H_

struct nat_pool;
struct cgn_sess2;

enum cgn_resource_type {
	CGN_RESOURCE_FULL,
	CGN_RESOURCE_AVAILABLE,
	CGN_RESOURCE_THRESHOLD
};

/* subscriber session start */
void cgn_log_subscriber_start(uint32_t addr);

/* subscriber session end */
void cgn_log_subscriber_end(uint32_t addr,
			    uint64_t start_time, uint64_t end_time,
			    uint64_t pkts_out, uint64_t bytes_out,
			    uint64_t pkts_in, uint64_t bytes_in,
			    uint64_t sessions);

/*
 * Logs for subscriber resource limit
 */
void cgn_log_resource_subscriber_mbpu(enum cgn_resource_type type,
				      uint32_t addr, uint8_t ipproto,
				      uint16_t count, uint16_t max_count);

/*
 * Logs for public address blocks resource limits
 */
void cgn_log_resource_public_pb(enum cgn_resource_type type,
				uint32_t addr, uint16_t blocks_used,
				uint16_t nblocks);

/* Port block allocation and release */
void cgn_log_pb_alloc(uint32_t pvt_addr, uint32_t pub_addr,
		      uint16_t port_start, uint16_t port_end,
		      uint64_t start_time,
		      const char *policy_name, const char *pool_name);

void cgn_log_pb_release(uint32_t pvt_addr, uint32_t pub_addr,
			uint16_t port_start, uint16_t port_end,
			uint64_t start_time, uint64_t end_time,
			const char *policy_name, const char *pool_name);

/* Session logging */
void cgn_log_sess_start(struct cgn_sess2 *s2);
void cgn_log_sess_active(struct cgn_sess2 *s2);
void cgn_log_sess_end(struct cgn_sess2 *s2, uint64_t end_time);
void cgn_log_sess_clear(const char *desc, uint count, uint64_t clear_time);

/* Resource constraint logging */
void cgn_log_resource_subscriber_table(enum cgn_resource_type type,
				       int32_t count, int32_t max_count);
void cgn_log_resource_session_table(enum cgn_resource_type type,
				    int32_t count, int32_t max_count);
void cgn_log_resource_dest_session_table(enum cgn_resource_type type,
					 struct cgn_session *cse,
					 int16_t count, int16_t max_count);
void cgn_log_resource_pool(enum cgn_resource_type type, struct nat_pool *np,
			   int32_t count, int32_t max_count);

enum cgn_log_type {
	CGN_LOG_TYPE_SESSION,
	CGN_LOG_TYPE_PORT_BLOCK_ALLOCATION,
	CGN_LOG_TYPE_SUBSCRIBER,
	CGN_LOG_TYPE_RES_CONSTRAINT,

	CGN_LOG_TYPE_COUNT		/* Must be last */
};

/**
 * Get the name associated with the given CGNAT log type
 *
 * @param type The type of the log to get the name
 * @return returns the name of the log type - NULL will be returned
 *	   if an invalid type is passed in.
 */
const char *cgn_get_log_type_name(enum cgn_log_type type);

/**
 * Get the log type associated with a given CGNAT log type name
 *
 * @param name the name to look up
 * @param type a pointer to a type which will be filled in with
 *	  the enum value on success.
 *
 * @return returns 0 on success and a negative errno on failure
 */
int cgn_get_log_type(const char *name, enum cgn_log_type *type);

enum cgn_log_format {
	CGN_LOG_FORMAT_RTE_LOG,
	CGN_LOG_FORMAT_PROTOBUF,

	CGN_LOG_FORMAT_COUNT		/* Must be last */
};

/* Enable and disable a named log handler for a give log type */
int cgn_log_enable_handler(enum cgn_log_type ltype, const char *name);
int cgn_log_disable_handler(enum cgn_log_type ltype, const char *name);

/* Free resources used by all active handles */
void cgn_log_disable_all_handlers(void);

struct cgn_session_log_fns {
	void (*cl_sess_start)(struct cgn_sess2 *s2);
	void (*cl_sess_active)(struct cgn_sess2 *s2);
	void (*cl_sess_end)(struct cgn_sess2 *s2, uint64_t end_time);
};

struct cgn_port_block_alloc_log_fns {
	void (*cl_pb_alloc)(uint32_t pvt_addr, uint32_t pub_addr,
			    uint16_t port_start, uint16_t port_end,
			    uint64_t start_time, const char *policy_name,
			    const char *pool_name);
	void (*cl_pb_release)(uint32_t pvt_addr, uint32_t pub_addr,
			      uint16_t port_start, uint16_t port_end,
			      uint64_t start_time, uint64_t end_time,
			      const char *policy_name, const char *pool_name);
};

struct cgn_subscriber_log_fns {
	void (*cl_subscriber_start)(uint32_t addr);
	void (*cl_subscriber_end)(uint32_t addr,
				  uint64_t start_time, uint64_t end_time,
				  uint64_t pkts_out, uint64_t bytes_out,
				  uint64_t pkts_in, uint64_t bytes_in,
				  uint64_t sessions);
};

struct cgn_res_constraint_log_fns {
	void (*cl_resource_subscriber_mbpu)(enum cgn_resource_type type,
					    uint32_t addr, uint8_t ipproto,
					    uint16_t count,
					    uint16_t max_count);
	void (*cl_resource_public_pb)(enum cgn_resource_type type,
				      uint32_t addr, uint16_t blocks_used,
				      uint16_t nblocks);
	void (*cl_sess_clear)(const char *desc, uint count,
			      uint64_t clear_time);
	void (*cl_resource_subscriber_table)(enum cgn_resource_type type,
					     int32_t count, int32_t max_count);
	void (*cl_resource_session_table)(enum cgn_resource_type type,
					  int32_t count, int32_t max_count);
	void (*cl_resource_dest_session_table)(enum cgn_resource_type type,
					       struct cgn_session *cse,
					       int16_t count,
					       int16_t max_count);
	void (*cl_resource_apm_table)(enum cgn_resource_type type,
				      int32_t count, int32_t limit_count);
	void (*cl_resource_pool)(enum cgn_resource_type type,
				 struct nat_pool *np, int32_t count,
				 int32_t max_count);
};

union cgn_log_type_fns {
	const struct cgn_session_log_fns *session;
	const struct cgn_port_block_alloc_log_fns *port_block_alloc;
	const struct cgn_subscriber_log_fns *subscriber;
	const struct cgn_res_constraint_log_fns *res_constraint;
};

struct cgn_log_fns {
	const char *cl_name;
	int (*cl_init)(enum cgn_log_type ltype, const struct cgn_log_fns *fns);
	void (*cl_fini)(enum cgn_log_type ltype, const struct cgn_log_fns *fns);

	union cgn_log_type_fns logfn[CGN_LOG_TYPE_COUNT];
};

#endif /* _CGN_LOG_H_ */
