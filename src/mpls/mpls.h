/*
 * MPLS label stack encoding/decoding
 *
 * Copyright (c) 2017-2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef MPLS_H
#define MPLS_H

#include <rte_branch_prediction.h>

#ifndef MPLS_LS_LABEL_MASK
# define MPLS_LS_LABEL_MASK      0xFFFFF000
#endif
#ifndef MPLS_LS_LABEL_SHIFT
# define MPLS_LS_LABEL_SHIFT     12
#endif
#ifndef MPLS_LS_TC_MASK
# define MPLS_LS_TC_MASK         0x00000E00
#endif
#ifndef MPLS_LS_TC_SHIFT
# define MPLS_LS_TC_SHIFT        9
#endif
#ifndef MPLS_LS_S_MASK
# define MPLS_LS_S_MASK          0x00000100
#endif
#ifndef MPLS_LS_S_SHIFT
# define MPLS_LS_S_SHIFT         8
#endif
#ifndef MPLS_LS_TTL_MASK
# define MPLS_LS_TTL_MASK        0x000000FF
#endif
#ifndef MPLS_LS_TTL_SHIFT
# define MPLS_LS_TTL_SHIFT       0
#endif

typedef uint32_t label_t;

#define NH_MAX_OUT_LABELS 16
#define MAX_LABEL_STACK_DEPTH NH_MAX_OUT_LABELS

enum mpls_rsvlbls_t {
	MPLS_IPV4EXPLICITNULL = 0,
	MPLS_ROUTERALERT = 1,
	MPLS_IPV6EXPLICITNULL = 2,
	MPLS_IMPLICITNULL = 3,
	MPLS_GAC_LABEL = 13,
	MPLS_FIRSTUNRESERVED = 16,
};

static inline uint32_t mpls_ls_get_label(uint32_t ls)
{
	return (ntohl(ls) & MPLS_LS_LABEL_MASK) >> MPLS_LS_LABEL_SHIFT;
}

static inline uint32_t mpls_ls_get_exp(uint32_t ls)
{
	return (ntohl(ls) & MPLS_LS_TC_MASK) >> MPLS_LS_TC_SHIFT;
}

static inline uint32_t mpls_ls_get_bos(uint32_t ls)
{
	return (ntohl(ls) & MPLS_LS_S_MASK) >> MPLS_LS_S_SHIFT;
}

static inline uint32_t mpls_ls_get_ttl(uint32_t ls)
{
	return (ntohl(ls) & MPLS_LS_TTL_MASK) >> MPLS_LS_TTL_SHIFT;
}

static inline void mpls_ls_set_label(uint32_t *ls, uint32_t val)
{
	*ls = htonl((ntohl(*ls) & ~MPLS_LS_LABEL_MASK) |
		      ((val << MPLS_LS_LABEL_SHIFT) &
		       MPLS_LS_LABEL_MASK));
}

static inline void mpls_ls_set_exp(uint32_t *ls, uint32_t val)
{
	*ls = htonl((ntohl(*ls) & ~MPLS_LS_TC_MASK) |
		      ((val << MPLS_LS_TC_SHIFT) &
		       MPLS_LS_TC_MASK));
}

static inline void mpls_ls_set_bos(uint32_t *ls, uint32_t val)
{
	*ls = htonl((ntohl(*ls) & ~MPLS_LS_S_MASK) |
			((val << MPLS_LS_S_SHIFT) &
			 MPLS_LS_S_MASK));
}
static inline void mpls_ls_set_ttl(uint32_t *ls, uint32_t val)
{
	*ls = htonl((ntohl(*ls) & ~MPLS_LS_TTL_MASK) |
		      ((val << MPLS_LS_TTL_SHIFT) &
		       MPLS_LS_TTL_MASK));
}

int rta_encap_get_labels(void *payload, uint16_t payload_len,
			 uint16_t max_labels, label_t *labels,
			 uint16_t *num_labels);

/* label block used where label stack exceeds the max out label threshold */
struct label_block {
	label_t      lb_count;
	label_t      *labels;
} __attribute__ ((__packed__));

/* stack of out labels in nh - top byte of labels[0] holds label count */
#define NH_MAX_OUT_ARRAY_LABELS 3
union next_hop_outlabels {
	label_t      labels[NH_MAX_OUT_ARRAY_LABELS];
	struct label_block lbl_blk;
};

static inline bool
nh_outlabels_present(const union next_hop_outlabels *olbls)
{
	return olbls->labels[0] != 0;
}

static inline unsigned int
nh_outlabels_get_cnt(const union next_hop_outlabels *olbls)
{
	return olbls->labels[0] >> 24;
}

/*
 * Get the value of an outlabel. Note the labels are stored
 * in push order - i.e. reverse order with respect to how
 * they appear from the start of the frame.
 */
static inline label_t
nh_outlabels_get_value(const union next_hop_outlabels *olbls,
		       unsigned int idx)
{
	if (likely(nh_outlabels_get_cnt(olbls) <= NH_MAX_OUT_ARRAY_LABELS))
		return olbls->labels[idx] & 0x00FFFFFF;
	return *(olbls->lbl_blk.labels + idx) & 0x00FFFFFF;
}

/*
 * Walk all the labels - note again this is a reverse order walk
 * with the innermost label visited first and the outermost last.
 */
#define NH_FOREACH_OUTLABEL(olbls, idx, lbl)				\
	for (idx = 0;							\
	     idx < nh_outlabels_get_cnt(olbls) &&			\
		     (lbl = nh_outlabels_get_value(olbls, idx), true);	\
	     idx++)

/*
 * Walk all the labels in top-to-bottom order for display.
 */
#define NH_FOREACH_OUTLABEL_TOP(olbls, idx, lbl)			\
	for (idx = nh_outlabels_get_cnt(olbls);				\
	     idx > 0 &&							\
		(lbl = nh_outlabels_get_value(olbls, idx - 1), true);	\
	     idx--)

static inline bool
nh_outlabels_cmpfn(const union next_hop_outlabels *lbls1,
		   const union next_hop_outlabels *lbls2)
{
	unsigned int idx;

	if (nh_outlabels_get_cnt(lbls1) != nh_outlabels_get_cnt(lbls2))
		return false;

	for (idx = 0; idx < nh_outlabels_get_cnt(lbls1); idx++)
		if (nh_outlabels_get_value(lbls1, idx) !=
		    nh_outlabels_get_value(lbls2, idx))
			return false;

	return true;
}

bool nh_outlabels_set(union next_hop_outlabels *olbls, uint16_t num_labels,
		      label_t *labels);
void nh_outlabels_destroy(union next_hop_outlabels *olbls);
char *mpls_labels_ntop(const uint32_t *label_stack, unsigned int num_labels,
		       char *buffer, size_t len);
bool nh_outlabels_copy(union next_hop_outlabels *old,
		       union next_hop_outlabels *copy);

#endif /* MPLS_H_*/
