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

struct xcvr_info {
	struct rte_eth_dev_module_info module_info;
	struct rte_dev_eeprom_info     eeprom_info;
};

void
sfp_status(bool up, const struct rte_eth_dev_module_info *module_info,
	   const struct rte_dev_eeprom_info *eeprom_info, bool include_static,
	   json_writer_t *wr);

int sfpd_open_socket(void);
void sfpd_unsubscribe(void);

#define SFP_PERMIT_CONFIG_FILE "/var/run/vyatta/sfp_permit.conf"

int cmd_sfp_permit_op(FILE *f, int argc, char **argv);

void sfpd_process_presence_update(void);

int cmd_sfp_monitor_op(FILE *f, int argc, char **argv);

#endif /* TRANSCEIVER_H */
