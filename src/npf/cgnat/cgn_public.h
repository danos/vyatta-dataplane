/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _CGN_PUBLIC_H_
#define _CGN_PUBLIC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct ifnet;
struct rte_mbuf;

/*
 * May be called by icmp_do_error if pkt meta data indicates a CGNAT packet.
 */
struct rte_mbuf *cgn_copy_or_clone_and_undo(struct rte_mbuf *mbuf,
					    const struct ifnet *in_ifp,
					    const struct ifnet *out_if,
					    bool copy);

#endif /* CGN_PUBLIC_H */
