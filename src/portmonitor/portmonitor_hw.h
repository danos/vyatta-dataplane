/*
 * Copyright (c) 2018, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 * Portmonitor hardware specific functions
 */
#ifndef PORTMONITOR_HW_H
#define PORTMONITOR_HW_H

#include <fal_plugin.h>
#include "../if_var.h"

/**
 * @brief Portmonitor processing for packets already mirrored in hardware
 *
 * @param[in] ifp Source port interface
 * @param[in] m Pointer to mbuf
 * @param[inout] fal_pm Portmonitor specific feature info from fal plugin
 *
 * @return 1 when packet consumed, 0 failure, mbuf not consumed
 */
int portmonitor_src_hw_mirror_process(struct ifnet *ifp, struct rte_mbuf *m,
		struct fal_pkt_portmonitor_info *fal_pm);


#endif /* PORTMONITOR_HW_H */
