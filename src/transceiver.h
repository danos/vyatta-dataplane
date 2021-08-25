/*-
 * Copyright (c) 2018-2019,2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef TRANSCEIVER_H

#define TRANSCEIVER_H

#include <json_writer.h>
#include <rte_dev_info.h>
#include "if_var.h"

void
sfp_status(bool up, const struct rte_eth_dev_module_info *module_info,
	   const struct rte_dev_eeprom_info *eeprom_info,
	   json_writer_t *wr);

int sfpd_open_socket(void);
void sfpd_unsubscribe(void);

#endif /* TRANSCEIVER_H */
