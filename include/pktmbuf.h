/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef VYATTA_DATAPLANE_PKTMBUF_H
#define VYATTA_DATAPLANE_PKTMBUF_H

#include <rte_mbuf.h>
#include "vrf.h"

/*
 * Allocate an mbuf from the default pool and initialise it.
 *
 * @param[in] vrf_id The vrf_id to set in the meta data of the mbuf.
 *
 * @return
 *   - The pointer to the new mbuf on success.
 *   - NULL if allocation failed.
 */
struct rte_mbuf *dp_pktmbuf_alloc_from_default(vrfid_t vrf_id);

/*
 * Get the vrf associated with the packet.
 *
 * @param[in] m The buffer to get the vrf from.
 *
 * @return the ID of the vrf the packet is associated with.
 */
vrfid_t
dp_pktmbuf_get_vrf(const struct rte_mbuf *m);

/*
 * Mark a packet as having been locally generated. Locally generated
 * packets may get put in a higher priority qos queue if configured.
 * and so this should be set for all locally generated packets.
 *
 * @param[out] m The buffer to set as locally generated.
 */
void dp_pktmbuf_mark_locally_generated(struct rte_mbuf *m);

/*
 * A macro that points to the start of the L3 data in the mbuf.
 *
 * The returned pointer is cast to type t. Before using this
 * function, the user must ensure that m_headlen(m) is large enough to
 * read its data, and must ensure that the L2 length is set in the mbuf.
 *
 * @param[in,out] m The packet mbuf.
 * @param[in,out] t The type to cast the result into.
 */
#define dp_pktmbuf_mtol3(m, t) ((t)(rte_pktmbuf_mtod(m, char *) +	\
				    (m)->l2_len))

/*
 * A macro that points to the start of the L4 data in the mbuf.
 *
 * The returned pointer is cast to type t. Before using this
 * function, the user must ensure that m_headlen(m) is large enough to
 * read its data , and must ensure that the L2 and L3 lengths are set
 * in the mbuf.
 *
 * @param[in,out] m The packet mbuf.
 * @param[in,out] t The type to cast the result into.
 */
#define dp_pktmbuf_mtol4(m, t) ((t)(rte_pktmbuf_mtod(m, char *) + \
				    (m)->l2_len + (m)->l3_len))

/*
 * A macro that returns the length of the L2 header in the mbuf.
 *
 * The value can be read or assigned.
 *
 * @param[in,out] m The packet mbuf.
 */
#define dp_pktmbuf_l2_len(m) ((m)->l2_len)

/*
 * A macro that returns the length of the L3 header in the mbuf.
 *
 * The value can be read or assigned.
 *
 * @param[in,out] m The packet mbuf.
 */
#define dp_pktmbuf_l3_len(m) ((m)->l3_len)

/*
 * Pointers that the features can use in the invar meta data. Features must
 * register for use of this, and they will get returned an index into the
 * array if successful. Features should unregister when they no longer need it.
 *
 * The invar feature meta data is invariant for the lifetime of the packet,
 * i.e. even if encapped or decapped, or reswitched through another
 * interface.
 */
#define DP_PKTMBUF_MAX_INVAR_FEATURE_PTRS 1

/*
 * Register for a feature pointer in the packet meta data.
 * This must be called on the main thread
 *
 * @param[in] name The name of the feature registering. Used for debug and for
 *            unregistering.
 * @return 0 or +ve if successful. The return value is the array index assigned.
 *         -ve for a failure. There was no space available.
 */
int dp_pktmbuf_mdata_invar_feature_register(const char *name);

/*
 * unregister a previously resisted feature pointer in the meta data.
 * This must be called on the main thread
 *
 * @param[in] name The name that was used when registering.
 * @param[in] slot The array slot that was given upon registration.
 *
 * @return 0 for success
 *         -ve for an error
 */
int dp_pktmbuf_mdata_invar_feature_unregister(const char *name, int slot);

/*
 * Mark the feature_ptr of the given ID as set within the packet meta data and
 * set the value.
 *
 * @param[out] m The mbuf to set the flags in.
 * @param[in]  feature_id The offset into the array that the feature should use.
 * @param[in]  ptr Value to store in the meta data.
 */
void
dp_pktmbuf_mdata_invar_ptr_set(struct rte_mbuf *m,
			       uint32_t feature_id,
			       void *ptr);

/*
 * Check if the given feature pointer is set within the packet meta data.
 * If it is then return the stored value.
 *
 * @param[out] m The mbuf to check
 * @param[in]  feature_id The offset into the array to be checked
 * @param[out] ptr Place to return the ptr in.

 * @return True if the feature pointer is set. Return the value in *ptr.
 *         False if the feature pointer is not set. In this case ptr will
 *         not be changed.
 */
bool
dp_pktmbuf_mdata_invar_ptr_get(const struct rte_mbuf *m,
			       uint32_t feature_id,
			       void **ptr);

/*
 * Clear the given feature pointer flag within the packet meta data
 *
 * @param[out] m The mbuf to clear the flags in.
 * @param[in]  feature_id The offset into the array to clear.
 */
void
dp_pktmbuf_mdata_invar_ptr_clear(struct rte_mbuf *m,
				 uint32_t feature_id);

#endif /* VYATTA_DATAPLANE_PKTMBUF_H */
