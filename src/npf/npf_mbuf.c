/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */

/*	$NetBSD: npf_mbuf.c,v 1.7 2012/04/14 19:01:21 rmind Exp $	*/

/*-
 * Copyright (c) 2009-2011 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-2-Clause-NETBSD)
 *
 * This material is based upon work partially supported by The
 * NetBSD Foundation under a contract with Mindaugas Rasiukevicius.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <errno.h>
#include <rte_branch_prediction.h>
#include <rte_mbuf.h>
#include <stdint.h>
/*
 * NPF network buffer management interface.
 *
 * Network buffer in NetBSD is mbuf.  Internal mbuf structures are
 * abstracted within this source.
 */
#include <stdlib.h>
#include <string.h>

#include "npf/npf_mbuf.h"

/*
 * nbuf_advance: advance in mbuf or chain by specified amount of bytes.
 *
 * => Returns new pointer to data in mbuf and NULL if offset gets invalid.
 * => Sets nbuf to current (after advance) mbuf in the chain.
 */
void *nbuf_advance(struct rte_mbuf **mbuf, void *n_ptr, u_int n)
{
	u_int off, wmark;
	uint8_t *d;
	struct rte_mbuf *m = *mbuf;

	/* Offset with amount to advance. */
	off = (char *)n_ptr - (char *)rte_pktmbuf_mtod(m, char*) + n;
	wmark = m->data_len;

	/* Find the mbuf according to offset. */
	while (wmark <= off) {
		m = m->next;
		if (m == NULL) {
			/*
			 * If out of chain, then offset is
			 * higher than packet length.
			 */
			return NULL;
		}
		wmark += m->data_len;
	}

	/* Offset in mbuf data. */
	d = rte_pktmbuf_mtod(m, uint8_t *);
	assert(off >= (wmark - m->data_len));
	d += (off - (wmark - m->data_len));

	*mbuf = (void *)m;
	return d;
}

/*
 * nbuf_rw_datum: read or write a datum of specified length at current
 * offset in the nbuf chain and copy datum into passed buffer.
 *
 * => Datum is allowed to overlap between two or more mbufs.
 * => Note: all data in nbuf is in network byte order.
 * => Returns 0 on success, error code on failure.
 *
 * Note: this function must be static inline with constant operation
 * parameter - we expect constant propagation.
 */

#define	NBUF_DATA_READ		0
#define	NBUF_DATA_WRITE		1

static int
nbuf_rw_datum(const int wr, struct rte_mbuf *m, void *n_ptr, size_t len,
	      void *buf)
{
	uint8_t *d = n_ptr, *b = buf;
	u_int off, wmark, end;

	/* Current offset in mbuf. */
	off = (char *)n_ptr - (char *)rte_pktmbuf_mtod(m, char*);
	assert(off < (u_int)rte_pktmbuf_pkt_len(m));
	wmark = m->data_len;

	/* Is datum overlapping? */
	end = off + len;
	while (end > wmark) {
		u_int l;

		/* Get the part of current mbuf. */
		l = m->data_len - off;
		assert(l < len);
		len -= l;
		if (wr == NBUF_DATA_WRITE) {
			while (l--)
				*d++ = *b++;
		} else {
			assert(wr == NBUF_DATA_READ);
			while (l--)
				*b++ = *d++;
		}
		assert(len > 0);

		/* Take next mbuf and continue. */
		m = m->next;
		if (m == NULL) {
			/*
			 * If out of chain, then offset with datum
			 * length exceed the packet length.
			 */
			return -EINVAL;
		}
		wmark += m->data_len;
		d = rte_pktmbuf_mtod(m, uint8_t *);
		off = 0;
	}
	assert(n_ptr == d || rte_pktmbuf_mtod(m, uint8_t *) == d);
	assert(len <= (u_int)m->data_len);

	/* Non-overlapping case: fetch the actual data. */
	if (wr == NBUF_DATA_WRITE) {
		while (len--)
			*d++ = *b++;
	} else {
		assert(wr == NBUF_DATA_READ);
		while (len--)
			*b++ = *d++;
	}
	return 0;
}

/* following code is generic and buf cast is ok */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"

/*
 * nbuf_{fetch|store}_datum: read/write absraction calls on nbuf_rw_datum().
 */
int
nbuf_fetch_datum(struct rte_mbuf *m, const void *n_ptr, size_t len, void *buf)
{
	/* Optimize for case of in first segment */
	if (unlikely((char *)n_ptr + len
		     >= rte_pktmbuf_mtod(m, char *) + m->data_len))
		return nbuf_rw_datum(NBUF_DATA_READ, m,
				     (void *)n_ptr, len, buf);

	memcpy(buf, n_ptr, len);
	return 0;
}

static int
nbuf_store_datum(struct rte_mbuf *nbuf, void *n_ptr, size_t len,
		 const void *buf)
{
	struct rte_mbuf *m = nbuf;

	return nbuf_rw_datum(NBUF_DATA_WRITE, m, n_ptr, len,
			     (void *) buf);
}
#pragma GCC diagnostic pop

/*
 * nbuf_advfetch: advance and fetch the datum.
 */
int nbuf_advfetch(struct rte_mbuf **nbuf, void **n_ptr, u_int n, size_t len,
		void *buf)
{
	struct rte_mbuf *orig_nbuf = *nbuf;
	void *orig_nptr = *n_ptr;
	int error;

	*n_ptr = nbuf_advance(nbuf, *n_ptr, n);
	if (likely(*n_ptr != NULL))
		error = nbuf_fetch_datum(*nbuf, *n_ptr, len, buf);
	else
		error = -EINVAL;

	if (error) {
		*nbuf = orig_nbuf;
		*n_ptr = orig_nptr;
	}
	return error;
}

/*
 * nbuf_advstore: advance and store the datum.
 */
int nbuf_advstore(struct rte_mbuf **nbuf, void **n_ptr, u_int n, size_t len,
	      const void *buf)
{
	struct rte_mbuf *orig_nbuf = *nbuf;
	void *orig_nptr = *n_ptr;
	int error;

	*n_ptr = nbuf_advance(nbuf, *n_ptr, n);
	if (likely(*n_ptr != NULL))
		error = nbuf_store_datum(*nbuf, *n_ptr, len, buf);
	else
		error = -EINVAL;

	if (error) {
		*nbuf = orig_nbuf;
		*n_ptr = orig_nptr;
	}
	return error;
}
