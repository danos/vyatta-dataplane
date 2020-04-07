/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _APT_PUBLIC_H_
#define _APT_PUBLIC_H_

/**
 * @file apt_public.h - Public header file for APT tables
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "json_writer.h"
#include "vrf.h"
#include "alg/alg_feat.h"

struct json_writer;
struct apt_instance;
struct apt_dport;
struct apt_tuple;
struct vrf;

/*
 * Destination port (dport) hash table key.  Must be multiple of 4-bytes.
 * k_dport is in network byte order.
 *
 * Hash table match function uses memcmp.
 */
struct apt_dport_key {
	uint8_t		k_feat;		/* enum alg_feat */
	uint8_t		k_expired;
	uint8_t		k_proto;	/* IPPROTO_TCP or IPPROTO_UDP */
	uint8_t		k_pad1;
	uint16_t	k_dport;
	uint16_t	k_pad2;
} __attribute__((__packed__));

/*
 * Tuple hash table key.  Must be multiple of 4-bytes.  Ports and addresses
 * are in network byte order.
 *
 * Hash table match function uses memcmp.
 *
 * Asserts are used to ensure that objects up to ifindex are at same offsets
 * in both apt_v4_key and apt_v6_key.
 */
struct apt_v4_key {
	uint8_t		k4_feat;	/* enum alg_feat */
	uint8_t		k4_expired;
	uint8_t		k4_proto;	/* IPPROTO_TCP or IPPROTO_UDP */
	uint8_t		k4_alen;
	uint16_t	k4_dport;
	uint16_t	k4_sport;
	uint32_t	k4_ifindex;
	/* End of common offsets */

	uint32_t	k4_daddr;
	uint32_t	k4_saddr;
	uint32_t	k4_pad2;
} __attribute__((__packed__));

struct apt_v6_key {
	uint8_t		k6_feat;	/* enum alg_feat */
	uint8_t		k6_expired;
	uint8_t		k6_proto;	/* IPPROTO_TCP or IPPROTO_UDP */
	uint8_t		k6_alen;
	uint16_t	k6_dport;
	uint16_t	k6_sport;
	uint32_t	k6_ifindex;
	/* End of common offsets */

	uint32_t	k6_pad2;
	struct in6_addr	k6_daddr;
	struct in6_addr	k6_saddr;
} __attribute__((__packed__));

struct apt_key {
	union {
		struct apt_v4_key	v4_key;
		struct apt_v6_key	v6_key;
	};
};

typedef bool (*apt_match_func_t)(void *ctx, void *match_key);
typedef int (*apt_walk_cb_func_t)(struct apt_tuple *te, void *ctx);


/***************************************************************************
 *  Destination Port Table Public API
 ***************************************************************************/

/**
 * @brief Get count of entries in the dport table for the given feature or for
 * all features.
 */
uint32_t apt_dport_tbl_count(struct apt_instance *ai, enum alg_feat feat);

/**
 * @brief Add destination port entry
 *
 * @param ai     APT instance handle
 * @param feat   Feature (e.g. ALG_FEAT_NPF)
 * @param ctx    Feature context pointer.  Private data to be stored with
 *               the entry.
 * @param proto  Protocol (IPPROTO_TCP or IPPROTO_UDP)
 * @param dport  Service destination port in network byte order
 * @param name   Optional service name, e.g. "sip", "ftp" etc.
 *
 * @return 0 if successful, else error code
 */
int apt_dport_add(struct apt_instance *ai, enum alg_feat feat, void *ctx,
		  uint8_t proto, uint16_t dport, const char *name);

/**
 * @brief Lookup destination port
 *
 * @param ai    apt vrf instance
 * @param feat  Feature (e.g. ALG_FEAT_NPF)
 * @param proto Protocol (IPPROTO_TCP or IPPROTO_UDP)
 * @param dport Destination port in network byte order
 * @param inc_count Increment counter in dport entry if found
 *
 * @return pointer to feat context if successful.
 */
void *apt_dport_lookup(struct apt_instance *ai, enum alg_feat feat,
		       uint8_t proto, uint16_t dport, bool inc_count);

/**
 * @brief Lookup destination port and expire if found
 *
 * @param ai    apt vrf instance
 * @param feat  Feature (e.g. ALG_FEAT_NPF)
 * @param proto Protocol (IPPROTO_TCP or IPPROTO_UDP)
 * @param dport Destination port in network byte order
 *
 * @return 0 if found and expired
 */
int apt_dport_lookup_and_expire(struct apt_instance *ai, enum alg_feat feat,
				uint8_t proto, uint16_t dport);

/**
 * @brief Set ALG private data handle in dest port entry
 */
void apt_dport_set_feat_ctx(struct apt_dport *de, void *ctx);

/**
 * @brief Format a dest port entry to a string
 */
char *apt_dport_str(struct apt_dport *de, char *dst, size_t sz);

/**
 * @brief Write json dport entries for select entries
 */
void apt_dport_jsonw_matching(json_writer_t *json, struct apt_instance *ai,
			      int feat, apt_match_func_t match_fn,
			      void *match_key);

/*
 * Temporary placeholder functions that will be replaced when ALG change is
 * committed.
 */
static inline void alg_apt_dport_delete(struct apt_dport *de __unused,
					void *ctx __unused)
{
}
static inline void alg_apt_tuple_delete(struct apt_tuple *te __unused,
					void *ctx __unused)
{
}
static inline void alg_apt_tuple_jsonw(json_writer_t *json __unused,
				       enum alg_feat feat __unused,
				       void *ctx __unused,
				       bool expired __unused)
{
}


/***************************************************************************
 *  APT Tuple Table Public API
 ***************************************************************************/

/**
 * @brief Get count of entries in the tuple table for the given feature
 */
uint32_t apt_tuple_tbl_count(struct apt_instance *ai, enum alg_feat feat);

/**
 * @brief Add an IPv4 or IPv6 tuple to the hash table
 *
 * @param ai      apt vrf instance
 * @param feat    Feature (npf or cgnat)
 * @param ctx     Feature context pointer.  Private data to be stored with
 *                the entry.
 * @param key     Key is copied to new tuple entry
 * @param timeout Timeout in secs.  If 0 then default is used.
 * @param replace Replace any existing tuple by expiring it
 * @param keep    Do not expire via generic alg infra.
 * @param error   Pointer to error return code
 * @return Pointer to tuple
 *
 * The following MUST be initialized in the key: k4_ifindex, k4_proto,
 * k4_dport, k4_sport, k4_daddr and k4_saddr.  k4_sport may be zero ('any' src
 * port match).
 */
struct apt_tuple *apt_tuple_add(struct apt_instance *ai, enum alg_feat feat,
				void *ctx, const struct apt_key *key,
				uint16_t timeout, bool replace, bool keep,
				int *error);

/**
 * @brief Expire a tuple
 */
void apt_tuple_expire(struct apt_tuple *te);

/**
 * @brief Lookup an IPv4 or IPv6 tuple.  Expire if found (and not a 'keep'
 * tuple)
 *
 * @param ai      apt vrf instance
 * @param feat    Feature (npf or cgnat)
 * @param key     Key to lookup
 * @param drop    Caller should not create a session
 * @param expire  Expire non-keep tuple if found
 * @return Pointer to tuple, or NULL.
 *
 * This is typically used in a feature just after a session lookup has failed.
 * If the feature finds a tuple then it will usually create a new session from
 * it, in which case the tuple is no longer needed.
 *
 * This will do two lookups - one with the source port in the key, and one
 * where the source port in the key is temporarily set to 0.
 */
struct apt_tuple *apt_tuple_lookup_and_expire(struct apt_instance *ai,
					      enum alg_feat feat,
					      struct apt_key *key,
					      bool *drop);

/**
 * @brief Lookup an IPv4 tuple
 *
 * @param ai      apt vrf instance
 * @param feat    Feature (npf or cgnat)
 * @param key     Key to lookup
 * @return Pointer to tuple, or NULL.
 */
struct apt_tuple *apt_tuple_v4_lookup(struct apt_instance *ai,
				      enum alg_feat feat,
				      struct apt_v4_key *key);

/**
 * @brief Link two tuples together
 *
 * For some ALGs we do not know which direction the secondary flow will start
 * in.  In these cases symmetrical tuples are created - one in each direction.
 * When one is matched and a session created, then both are expired.
 */
int apt_tuple_pair(struct apt_tuple *te1, struct apt_tuple *te2);

/**
 * @brief Clear tuple entry feature context
 */
void apt_tuple_clear_feat_ctx(struct apt_tuple *te);

/**
 * @brief Accessor to get tuple entry feat context
 */
void *apt_tuple_get_feat_ctx(struct apt_tuple *te);

/**
 * @brief Print a tuple entry to a string
 */
char *apt_tuple_str(struct apt_tuple *te, char *dst, size_t sz);

/**
 * @brief Write json tuple entries for select entries
 */
void apt_tuple_jsonw_matching(json_writer_t *json, struct apt_instance *ai,
			      int feat, apt_match_func_t match_fn,
			      void *match_key);

/**
 * @brief Call walk_cb for select entries.  walk_cb may return non-zero to
 * terminate the walk.
 */
int apt_tuple_walk(struct apt_instance *ai, int feat,
		   apt_match_func_t match_fn, void *match_key,
		   apt_walk_cb_func_t walk_cb, void *ctx);


/***************************************************************************
 *  APT Instance
 ***************************************************************************/

/**
 * @brief Take reference on an apt instance
 */
struct apt_instance *apt_instance_get(struct apt_instance *ai);

/**
 * @brief Release reference on an apt instance
 */
void apt_instance_put(struct apt_instance *ai);

/**
 * @brief Get apt instance from an internal vrf_id
 */
struct apt_instance *apt_instance_from_vrfid(vrfid_t vrf_id);

/**
 * @brief Find or create an apt vrf instance
 */
struct apt_instance *apt_instance_find_or_create(struct vrf *vrf);


/***************************************************************************
 *  Other
 ***************************************************************************/

/**
 * @brief Format and apt key to a string.
 */
int apt_key_str(struct apt_key *key, char *dst, size_t sz);

/**
 * @brief Flush all table entries on an apt instance.
 *
 * Expired entries are deleted.  Unexpired entried are expired.
 *
 * If flush_all is *not* set true then only non-keep tuple entries are expired.
 * If flush_all *is* set true then all dport and tuple entries are expired.
 */
void apt_flush_instance(struct apt_instance *ai, int feat, bool flush_all);

/**
 * @brief Flush matching tuple entries
 *
 * Typically used when a feature session expires to expire tuples created by
 * that session.  Also used when the VRF instance is being destroyed.
 */
void apt_flush_matching_tuples(struct apt_instance *ai, int feat,
			       bool flush_all, apt_match_func_t match_fn,
			       void *match_key);

/**
 * @brief Write json for all apt tables on all vrfs
 *
 * vrf_id is either VRF_INVALID_ID (indicating all vrfs) or an internal vrf id
 */
void apt_jsonw(FILE *f, vrfid_t vrf_id);

/* Unit-test cleanup */
void dpt_apt_vrf_delete(vrfid_t vrf_id);

#endif /* _APT_PUBLIC_H_ */
