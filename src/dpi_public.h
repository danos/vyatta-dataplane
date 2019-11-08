/*
 * Public APIs for DPI.
 *
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef DPI_PUBLIC_H
#define DPI_PUBLIC_H

#include <stdbool.h>
#include <stdint.h>

struct rte_mbuf;
struct ifnet;

/* The caller requires DPI to run on the given interface.
 *
 * Note that this can be called by multiple clients.
 * DPI will be enabled if at least one client requests it.
 *
 * The call returns 0 on success an a negative errno on failure.
 */
int dpi_enable(struct ifnet *ifp);


/* The caller no nonger requires DPI to run on the given interface.
 *
 * When no more clients require DPI, the engine will be stopped.
 *
 * Note that this must only be called if the caller previously
 * called dpi_enable() and it returned success.
 *
 * The call returns 0 on success an a negative errno on failure.
 */
int dpi_disable(struct ifnet *ifp);


/* Returns true if DPI is enabled on any interface, else false.
 *
 * NB DPI state is not tracked per interface.
 */
bool dpi_is_enabled(void);


/* Return the L7 DPI application ID for the given packet.
 *
 * If DPI is not enabled or DPI is not available in the image,
 * then DPI_APP_NA is returned.  A failure in the DPI engine
 * can result in DPI_APP_ERROR being returned.  If processing
 * is not yet complete DPI_APP_UNDETERMINED can be returned.
 */
uint32_t dpi_get_app_id(struct rte_mbuf *mbuf);

#endif /* DPI_PUBLIC_H */
