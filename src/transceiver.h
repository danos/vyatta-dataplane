/*-
 * Copyright (c) 2018-2019,2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef TRANSCEIVER_H

#define TRANSCEIVER_H

#include <ieee754.h>
#include <json_writer.h>
#include <rte_dev_info.h>
#include "if_var.h"

#define SFP_DYN_DATA_MAX_LEN     128

struct xcvr_info {
	struct rte_eth_dev_module_info module_info;
	struct rte_dev_eeprom_info     eeprom_info;

	/* previous measurements & warning/alarm data */
	uint8_t prev_dyn_data[SFP_DYN_DATA_MAX_LEN];
	uint8_t dyn_data_len;

	/* offset from the beginning of the EEPROM area */
	uint16_t offset;

	/* Calibration constant data */
	struct sfp_calibration_constants c_consts;
};

void
sfp_status(bool up, struct xcvr_info *xcvr_info, bool include_static,
	   json_writer_t *wr);

int sfpd_open_socket(void);
void sfpd_unsubscribe(void);

#define SFP_PERMIT_CONFIG_FILE "/var/run/vyatta/sfp_permit.conf"

int cmd_sfp_permit_op(FILE *f, int argc, char **argv);

void sfpd_process_presence_update(void);

int cmd_sfp_monitor_op(FILE *f, int argc, char **argv);

void
get_sfp_calibration_constants(const struct rte_dev_eeprom_info *eeprom_info,
			      struct sfp_calibration_constants *c_consts);

bool
sfp_has_ddm(const struct rte_dev_eeprom_info *eeprom_info);

#endif /* TRANSCEIVER_H */
