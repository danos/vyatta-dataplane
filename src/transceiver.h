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

#define SFP_CALIB_CONST_RX_PWR_SIZE    4
#define SFP_CALIB_CONST_RX_PWR_CNT     5
#define SFP_CALIB_CONST_SL_OFF_START   0x4c
#define SFP_CALIB_CONST_SL_OFF_SIZE    2

/*
 * Type of calibration constant
 * The enum values are in the order in which the
 * entries appear in EEPROM
 */
enum sfp_calib_const_type {
	SFP_CALIB_CONST_LASER_BIAS,
	SFP_CALIB_CONST_TX_PWR,
	SFP_CALIB_CONST_TEMPERATURE,
	SFP_CALIB_CONST_VOLTAGE,
	SFP_CALIB_CONST_MAX
};

struct slope_off {
	float    slope;
	int16_t  offset;
};

struct sfp_calibration_constants {
	union ieee754_float rx_pwr[SFP_CALIB_CONST_RX_PWR_CNT];
	struct slope_off    slope_offs[SFP_CALIB_CONST_MAX];
};

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
