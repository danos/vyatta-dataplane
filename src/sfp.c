/*
 * This module is derived from freebsd/sys/net/sfp.c
 * The changes made are
 *   - removal of i2c functions since the EEPROM info is passed in
 *     as a single buffer
 *   - conversion of printf to json_xxx APIs
 *   - checkpatch fixup
 */
/*-
 * Copyright (c) 2018-2021, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2014 Alexander V. Chernikov. All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-2-Clause-FREEBSD)
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "sff8436.h"
#include "sff8472.h"

#include <math.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <vplane_log.h>
#include <vplane_debug.h>
#include <event.h>
#include <json_writer.h>
#include <rte_dev_info.h>
#include <transceiver.h>
#include <ieee754.h>
#include <transceiver.h>
#include "protobuf.h"
#include "protobuf/SFPMonitor.pb-c.h"
#include "if/dpdk-eth/dpdk_eth_if.h"
#include "if_var.h"

struct _nv {
	int v;
	const char *n; /* json field name */
};

/*
 * extended name value struct to include log msg content
 */
struct _nv_ext {
	int v;
	const char *n; /* json field name */
	const char *l; /* log msg field */
};

/* Offset in the EEPROM data for all base queries. */
#define	SFF_8472_BASE_OFFSET 0
#define	SFF_8436_BASE_OFFSET 0

/* Offset in the EEPROM data for all diag data */
#define	SFF_8472_DIAG_OFFSET 256

static const char *find_value(struct _nv *x, int value);
static const char *find_zero_bit(struct _nv *x, int value, int sz);

/* SFF-8024 Rev. 4.1 Table 4-3: Connector Types */
static struct _nv conn[] = {
	{ 0x00, "Unknown" },
	{ 0x01, "SC" },
	{ 0x02, "Fibre Channel Style 1 copper" },
	{ 0x03, "Fibre Channel Style 2 copper" },
	{ 0x04, "BNC/TNC" },
	{ 0x05, "Fibre Channel coaxial" },
	{ 0x06, "FiberJack" },
	{ 0x07, "LC" },
	{ 0x08, "MT-RJ" },
	{ 0x09, "MU" },
	{ 0x0A, "SG" },
	{ 0x0B, "Optical pigtail" },
	{ 0x0C, "MPO Parallel Optic" },
	{ 0x20, "HSSDC II" },
	{ 0x21, "Copper pigtail" },
	{ 0x22, "RJ45" },
	{ 0x23, "No separable connector" },
	{ 0x24, "MXC 2x16" },
	{ 0, NULL }
};

/* SFF-8472 Rev. 11.4 table 3.5: Transceiver codes */
/* 10G Ethernet/IB compliance codes, byte 3 */
static struct _nv eth_10g[] = {
	{ 0x80, "10G Base-ER" },
	{ 0x40, "10G Base-LRM" },
	{ 0x20, "10G Base-LR" },
	{ 0x10, "10G Base-SR" },
	{ 0x08, "1X SX" },
	{ 0x04, "1X LX" },
	{ 0x02, "1X Copper Active" },
	{ 0x01, "1X Copper Passive" },
	{ 0, NULL }
};

/* Ethernet compliance codes, byte 6 */
static struct _nv eth_compat[] = {
	{ 0x80, "BASE-PX" },
	{ 0x40, "BASE-BX10" },
	{ 0x20, "100BASE-FX" },
	{ 0x10, "100BASE-LX/LX10" },
	{ 0x08, "1000BASE-T" },
	{ 0x04, "1000BASE-CX" },
	{ 0x02, "1000BASE-LX" },
	{ 0x01, "1000BASE-SX" },
	{ 0, NULL }
};

/* FC link length, byte 7 */
static struct _nv fc_len[] = {
	{ 0x80, "very long distance" },
	{ 0x40, "short distance" },
	{ 0x20, "intermediate distance" },
	{ 0x10, "long distance" },
	{ 0x08, "medium distance" },
	{ 0, NULL }
};

/* Channel/Cable technology, byte 7-8 */
static struct _nv cab_tech[] = {
	{ 0x0400, "Shortwave laser (SA)" },
	{ 0x0200, "Longwave laser (LC)" },
	{ 0x0100, "Electrical inter-enclosure (EL)" },
	{ 0x80, "Electrical intra-enclosure (EL)" },
	{ 0x40, "Shortwave laser (SN)" },
	{ 0x20, "Shortwave laser (SL)" },
	{ 0x10, "Longwave laser (LL)" },
	{ 0x08, "Active Cable" },
	{ 0x04, "Passive Cable" },
	{ 0, NULL }
};

/* FC Transmission media, byte 9 */
static struct _nv fc_media[] = {
	{ 0x80, "Twin Axial Pair" },
	{ 0x40, "Twisted Pair" },
	{ 0x20, "Miniature Coax" },
	{ 0x10, "Viao Coax" },
	{ 0x08, "Miltimode, 62.5um" },
	{ 0x04, "Multimode, 50um" },
	{ 0x02, "" },
	{ 0x01, "Single Mode" },
	{ 0, NULL }
};

/* FC Speed, byte 10 */
static struct _nv fc_speed[] = {
	{ 0x80, "1200 MBytes/sec" },
	{ 0x40, "800 MBytes/sec" },
	{ 0x20, "1600 MBytes/sec" },
	{ 0x10, "400 MBytes/sec" },
	{ 0x08, "3200 MBytes/sec" },
	{ 0x04, "200 MBytes/sec" },
	{ 0x01, "100 MBytes/sec" },
	{ 0, NULL }
};

/* SFF-8436 Rev. 4.8 table 33: Specification compliance  */

/* 10/40G Ethernet compliance codes, byte 128 + 3 */
static struct _nv eth_1040g[] = {
	{ 0x80, "Extended" },
	{ 0x40, "10GBASE-LRM" },
	{ 0x20, "10GBASE-LR" },
	{ 0x10, "10GBASE-SR" },
	{ 0x08, "40GBASE-CR4" },
	{ 0x04, "40GBASE-SR4" },
	{ 0x02, "40GBASE-LR4" },
	{ 0x01, "40G Active Cable" },
	{ 0, NULL }
};
#define	SFF_8636_EXT_COMPLIANCE	0x80

/* SFF-8024 Rev. 4.2 table 4-4: Extended Specification Compliance */
static struct _nv eth_extended_comp[] = {
	{ 0xFF, "Reserved" },
	{ 0x21, "100G PAM4 BiDi" },
	{ 0x20, "100G SWDM4" },
	{ 0x1F, "40G SWDM4" },
	{ 0x1E, "2.5GBASE-T" },
	{ 0x1D, "5GBASE-T" },
	{ 0x1C, "10GBASE-T Short Reach" },
	{ 0x1B, "100G 1550nm WDM" },
	{ 0x1A, "100GE-DWDM2" },
	{ 0x19, "100G ACC or 25GAUI C2M ACC" },
	{ 0x18, "100G AOC or 25GAUI C2M AOC" },
	{ 0x17, "100G CLR4" },
	{ 0x16, "10GBASE-T with SFI electrical interface" },
	{ 0x15, "G959.1 profile P1L1-2D2" },
	{ 0x14, "G959.1 profile P1S1-2D2" },
	{ 0x13, "G959.1 profile P1I1-2D1" },
	{ 0x12, "40G PSM4 Parallel SMF" },
	{ 0x11, "4 x 10GBASE-SR" },
	{ 0x10, "40GBASE-ER4" },
	{ 0x0F, "Reserved" },
	{ 0x0E, "Reserved" },
	{ 0x0D, "25GBASE-CR CA-N" },
	{ 0x0C, "25GBASE-CR CA-S" },
	{ 0x0B, "100GBASE-CR4 or 25GBASE-CR CA-L" },
	{ 0x0A, "Reserved" },
	{ 0x09, "Obsolete" },
	{ 0x08, "100G ACC (Active Copper Cable) or 25GAUI C2M ACC" },
	{ 0x07, "100G PSM4 Parallel SMF" },
	{ 0x06, "100G CWDM4" },
	{ 0x05, "100GBASE-SR10" },
	{ 0x04, "100GBASE-ER4 or 25GBASE-ER" },
	{ 0x03, "100GBASE-LR4 or 25GBASE-LR" },
	{ 0x02, "100GBASE-SR4 or 25GBASE-SR" },
	{ 0x01, "100G AOC (Active Optical Cable) or 25GAUI C2M AOC" },
	{ 0x00, "Unspecified" }
};

/* SFF-8636 Rev. 2.9 table 6.3: Revision compliance */
static struct _nv rev_compl[] = {
	{ 0x1, "SFF-8436 rev <=4.8" },
	{ 0x2, "SFF-8436 rev <=4.8" },
	{ 0x3, "SFF-8636 rev <=1.3" },
	{ 0x4, "SFF-8636 rev <=1.4" },
	{ 0x5, "SFF-8636 rev <=1.5" },
	{ 0x6, "SFF-8636 rev <=2.0" },
	{ 0x7, "SFF-8636 rev <=2.7" },
	{ 0x8, "SFF-8636 rev >=2.8" },
	{ 0x0, "Unspecified" }
};

/* SFF-8472 table 3.6: Encoding codes */
static struct _nv encoding[] = {
	{ 0x1, "8B/10B" },
	{ 0x2, "4B/5B" },
	{ 0x3, "NRZ" },
	{ 0x4, "Manchester" },
	{ 0x5, "SONET scrambled" },
	{ 0x6, "64B/66B" },
	{ 0x0, "Unspecified" }
};

/* SFF-8636 Rev. 2.9 points to SFF-8024 table 4.2: Encoding values */
static struct _nv qsfp_encoding[] = {
	{ 0x1, "8B/10B" },
	{ 0x2, "4B/5B" },
	{ 0x3, "NRZ" },
	{ 0x4, "SONET scrambled" },
	{ 0x5, "64B/66B" },
	{ 0x6, "Manchester" },
	{ 0x7, "256B/257B" },
	{ 0x8, "PAM4" },
	{ 0x0, "Unspecified" }
};


/* SFF-8472 table 3.12: Compliane */
static struct _nv sff_8472_compl[] = {
	{ 0x1, "SFF_8472 rev 9.3" },
	{ 0x2, "SFF_8472 rev 9.5" },
	{ 0x3, "SFF_8472 rev 10.2" },
	{ 0x4, "SFF_8472 rev 10.4" },
	{ 0x5, "SFF_8472 rev 11.0" },
	{ 0x0, "Undefined" }
};

/* SFF-8472 table 3.3: Extended Identifier values */
static struct _nv ext_id[] = {
	{ 0x1, "MOD_DEF 1" },
	{ 0x2, "MOD_DEF 2" },
	{ 0x3, "MOD_DEF 3" },
	{ 0x4, "" },
	{ 0x5, "MOD_DEF 5" },
	{ 0x6, "MOD_DEF 6" },
	{ 0x7, "MOD_DEF 7" },
	{ 0x0, "Undefined" }
};

static struct _nv ext_8436_id[] = {
	{ 0x1, "Power Class 2(2.0 W max)" },
	{ 0x2, "Power Class 3(2.5 W max)" },
	{ 0x3, "Power Class 4(3.5 W max)" },
	{ 0x0, "Power Class 1(1.5 W max)" }
};

enum SFF_8472_AW_FLAG {
	SFF_8472_AW_TEMP_HIGH    = 0xf,
	SFF_8472_AW_TEMP_LOW     = 0xe,
	SFF_8472_AW_VCC_HIGH     = 0xd,
	SFF_8472_AW_VCC_LOW      = 0xc,
	SFF_8472_AW_TX_BIAS_HIGH = 0xb,
	SFF_8472_AW_TX_BIAS_LOW  = 0xa,
	SFF_8472_AW_TX_PWR_HIGH  = 0x9,
	SFF_8472_AW_TX_PWR_LOW   = 0x8,
	SFF_8472_AW_RX_PWR_HIGH  = 0x7,
	SFF_8472_AW_RX_PWR_LOW   = 0x6,
};

static struct _nv_ext aw_flags[] = {
	{ SFF_8472_AW_TEMP_HIGH,    "temp_high",     "Temperature high"        },
	{ SFF_8472_AW_TEMP_LOW,     "temp_low",      "Temperature low"         },
	{ SFF_8472_AW_VCC_HIGH,     "vcc_high",      "Voltage high"            },
	{ SFF_8472_AW_VCC_LOW,      "vcc_low",       "Voltage low"             },
	{ SFF_8472_AW_TX_BIAS_HIGH, "tx_bias_high",  "Laser bias current high" },
	{ SFF_8472_AW_TX_BIAS_LOW,  "tx_bias_low",   "Laser bias current low"  },
	{ SFF_8472_AW_TX_PWR_HIGH,  "tx_power_high", "Tx power high"           },
	{ SFF_8472_AW_TX_PWR_LOW,   "tx_power_low",  "Tx power low"            },
	{ SFF_8472_AW_RX_PWR_HIGH,  "rx_power_high", "Rx power high"           },
	{ SFF_8472_AW_RX_PWR_LOW,   "rx_power_low",  "Rx power low"            },
	{ 0x00, NULL, NULL }
};

static struct _nv_ext rx_pwr_aw_chan_upper_flags[] = {
	{ 0x4, "rx_power_low_warn",   "Rx power low warning"},
	{ 0x5, "rx_power_high_warn",  "Rx power high warning"},
	{ 0x6, "rx_power_low_alarm",  "Rx power low alarm"},
	{ 0x7, "rx_power_high_alarm", "Rx power high alarm"},
	{ 0x8, NULL, NULL }
};

static struct _nv_ext rx_pwr_aw_chan_lower_flags[] = {
	{ 0x0, "rx_power_low_warn",   "Rx power low warning"},
	{ 0x1, "rx_power_high_warn",  "Rx power high warning"},
	{ 0x2, "rx_power_low_alarm",  "Rx power low alarm"},
	{ 0x3, "rx_power_high_alarm", "Rx power high alarm"},
	{ 0x8, NULL, NULL }
};

static struct _nv_ext tx_pwr_aw_chan_upper_flags[] = {
	{ 0x4, "tx_power_low_warn",   "Tx power low warning"},
	{ 0x5, "tx_power_high_warn",  "Tx power high warning"},
	{ 0x6, "tx_power_low_alarm",  "Tx power low alarm"},
	{ 0x7, "tx_power_high_alarm", "Tx power high alarm"},
	{ 0x8, NULL, NULL }
};

static struct _nv_ext tx_pwr_aw_chan_lower_flags[] = {
	{ 0x0, "tx_power_low_warn",   "Tx power low warning"},
	{ 0x1, "tx_power_high_warn",  "Tx power high warning"},
	{ 0x2, "tx_power_low_alarm",  "Tx power low alarm"},
	{ 0x3, "tx_power_high_alarm", "Tx power high alarm"},
	{ 0x8, NULL, NULL }
};

static struct _nv_ext tx_bias_aw_chan_upper_flags[] = {
	{ 0x4, "tx_bias_low_warn",   "Laser bias low warning"},
	{ 0x5, "tx_bias_high_warn",  "Laser bias high warning"},
	{ 0x6, "tx_bias_low_alarm",  "Laser bias low alarm"},
	{ 0x7, "tx_bias_high_alarm", "Laser bias high alarm"},
	{ 0x8, NULL, NULL }
};

static struct _nv_ext tx_bias_aw_chan_lower_flags[] = {
	{ 0x0, "tx_bias_low_warn",   "Laser bias low warning"},
	{ 0x1, "tx_bias_high_warn",  "Laser bias high warning"},
	{ 0x2, "tx_bias_low_alarm",  "Laser bias low alarm"},
	{ 0x3, "tx_bias_high_alarm", "Laser bias high alarm"},
	{ 0x8, NULL, NULL }
};

static struct _nv_ext temp_alarm_warn_flags[] = {
	{ 0x7, "temp_high_alarm", "Temperature high alarm"},
	{ 0x6, "temp_low_alarm",  "Temperature low alarm"},
	{ 0x5, "temp_high_warn",  "Temperature high warning"},
	{ 0x4, "temp_low_warn",   "Temperature low warning"},
	{ 0x00, NULL, NULL }
};

static struct _nv_ext voltage_alarm_warn_flags[] = {
	{ 0x7, "vcc_high_alarm", "Voltage high alarm"},
	{ 0x6, "vcc_low_alarm",  "Voltage low alarm"},
	{ 0x5, "vcc_high_warn",  "Voltage high warning"},
	{ 0x4, "vcc_low_warn",   "Voltage low warning"},
	{ 0x00, NULL, NULL }
};

/* all values greater than or equal to 0xa
 * correspond to copper SFPs
 */
#define QSFP_DEV_TECH_COPPER_MIN 0xa

static struct _nv sff_8636_dev_tech[] = {
	{ 0x0, "850_nm_vcsel" },
	{ 0x1, "1310_nm_vcsel" },
	{ 0x2, "1550_nm_vcsel" },
	{ 0x3, "1310_nm_fp" },
	{ 0x4, "1310_nm_dfb" },
	{ 0x5, "1550_nm_dfb" },
	{ 0x6, "1310_nm_eml" },
	{ 0x7, "1550_nm_eml" },
	{ 0x8, "others" },
	{ 0x9, "1490_nm_dfb" },
	{ 0xa, "copper_unequalized" },
	{ 0xb, "copper_passive_equalized" },
	{ 0xc, "copper_dual_equalizer" },
	{ 0xd, "copper_far_equalizer" },
	{ 0xe, "copper_near_equalizer" },
	{ 0xf, "copper_linear_equalizer" },
};

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

static const char *sfp_calib_const_strs[SFP_CALIB_CONST_MAX] = {
	"tx_laser",
	"tx_pwr",
	"temperature",
	"voltage"
};

struct slope_off {
	float    slope;
	int16_t  offset;
};

struct sfp_calibration_constants {
	union ieee754_float rx_pwr[SFP_CALIB_CONST_RX_PWR_CNT];
	struct slope_off    slope_offs[SFP_CALIB_CONST_MAX];
};

/*
 * Retrieves a section of eeprom data for parsing & display
 */
static int
get_eeprom_data(const struct rte_dev_eeprom_info *eeprom_info,
		uint8_t base, uint32_t off, uint8_t len, uint8_t *buf)
{
	switch (base) {
	case SFF_8472_BASE:
		off += SFF_8472_BASE_OFFSET;
		if ((off >= eeprom_info->length) ||
		    (len >= eeprom_info->length - SFF_8472_BASE_OFFSET))
			return -EINVAL;


		memcpy(buf, &((const char *)eeprom_info->data)[off], len);
		return 0;

	case SFF_8472_DIAG:
		off += SFF_8472_DIAG_OFFSET;
		if ((off >= eeprom_info->length) ||
		    (len >= eeprom_info->length - SFF_8472_DIAG_OFFSET))
			return -EINVAL;


		memcpy(buf, &((const char *)eeprom_info->data)[off], len);
		return 0;

	case SFF_8436_BASE:
		off += SFF_8436_BASE_OFFSET;
		if ((off >= eeprom_info->length) ||
		    (len >= eeprom_info->length - SFF_8436_BASE_OFFSET))
			return -EINVAL;


		memcpy(buf, &((const char *)eeprom_info->data)[off], len);
		return 0;


	default:
		return -EINVAL;
	}
}

/*
 * Temporarily unused. Will be used with a separate vplsh command
 * to dump raw EEPROM data
 */
#if 0
static void
dump_eeprom_data(const struct rte_dev_eeprom_info *eeprom_info,
		 uint8_t base, uint8_t off, uint8_t len)
{
	int last;

	switch (base) {
	case SFF_8436_BASE:
		if ((off >= eeprom_info->length) ||
		    (len >= eeprom_info->length))
			return;

		printf("\t");
		last = off + len;
		for (int i = off; i < last; i++)
			printf("%hhx ", ((const char *)&eeprom_info->data)[i]);
		printf("\n");
	}
}
#endif

static const char *
find_value(struct _nv *x, int value)
{
	for (; x->n != NULL; x++)
		if (x->v == value)
			return x->n;
	return NULL;
}

static const char *
find_zero_bit(struct _nv *x, int value, int sz)
{
	int v, m;
	const char *s;

	for (v = 1, m = 1 << (8 * sz); v < m; v *= 2) {
		if ((value & v) == 0)
			continue;
		s = find_value(x, value & v);
		if (s != NULL)
			return s;
	}

	return NULL;
}

static void
convert_sff_identifier(json_writer_t *wr, uint8_t value)
{
	const char *x;

	x = NULL;
	if (value <= SFF_8024_ID_LAST)
		x = sff_8024_id[value];
	else {
		if (value > 0x80)
			x = "Vendor specific";
		else
			x = "Reserved";
	}

	jsonw_string_field(wr, "identifier", x);
}

static void
convert_sff_ext_identifier(json_writer_t *wr, uint8_t value)
{
	const char *x;

	if (value > 0x07)
		x = "Unallocated";
	else
		x = find_value(ext_id, value);
	jsonw_string_field(wr, "ext_identifier", x);
}

static void
convert_sff_8436_ext_identifier(json_writer_t *wr, uint8_t value)
{
	const char *x;

	x = find_value(ext_8436_id, (value & 0xc0) >> 6);
	jsonw_string_field(wr, "ext_identifier", x);
}

static void
convert_sff_connector(json_writer_t *wr, uint8_t value)
{
	const char *x;

	x = find_value(conn, value);
	if (x == NULL) {
		if (value >= 0x0D && value <= 0x1F)
			x = "Unallocated";
		else if (value >= 0x24 && value <= 0x7F)
			x = "Unallocated";
		else
			x = "Vendor specific";
	}

	jsonw_string_field(wr, "connector", x);
}

static void
convert_sff_8436_rev_compliance(json_writer_t *wr, uint8_t value)
{
	const char *x;

	if (value > 0x08)
		x = "Unallocated";
	else
		x = find_value(rev_compl, value);

	jsonw_string_field(wr, "8472_compl", x);
}

static void
convert_sff_encoding(json_writer_t *wr, uint8_t value)
{
	const char *x;

	if (value > 0x06)
		x = "Unallocated";
	else
		x = find_value(encoding, value);

	jsonw_string_field(wr, "encoding", x);
}

static void
convert_sff_8436_encoding(json_writer_t *wr, uint8_t value)
{
	const char *x;

	if (value > 0x06)
		x = "Unallocated";
	else
		x = find_value(qsfp_encoding, value);

	jsonw_string_field(wr, "encoding", x);
}

static void
convert_sff_8472_compl(json_writer_t *wr, uint8_t value)
{
	const char *x;

	if (value > 0x05)
		x = "Unallocated";
	else
		x = find_value(sff_8472_compl, value);

	jsonw_string_field(wr, "8472_compl", x);
}

static void
print_sfp_identifier(const struct rte_dev_eeprom_info *eeprom_info,
		     json_writer_t *wr)
{
	uint8_t data;

	if (get_eeprom_data(eeprom_info, SFF_8472_BASE, SFF_8472_ID, 1, &data))
		return;

	convert_sff_identifier(wr, data);
}

static void
print_sfp_ext_identifier(const struct rte_dev_eeprom_info *eeprom_info,
			 json_writer_t *wr)
{
	uint8_t data;

	if (get_eeprom_data(eeprom_info, SFF_8472_BASE, SFF_8472_EXT_ID, 1,
			    &data))
		return;

	convert_sff_ext_identifier(wr, data);
}

static void
print_sfp_connector(const struct rte_dev_eeprom_info *eeprom_info,
		    json_writer_t *wr)
{
	uint8_t data;

	if (get_eeprom_data(eeprom_info, SFF_8472_BASE, SFF_8472_CONNECTOR, 1,
			    &data))
		return;

	convert_sff_connector(wr, data);
}

static void
print_qsfp_identifier(const struct rte_dev_eeprom_info *eeprom_info,
		      json_writer_t *wr)
{
	uint8_t data;

	if (get_eeprom_data(eeprom_info, SFF_8436_BASE, SFF_8436_ID, 1, &data))
		return;

	convert_sff_identifier(wr, data);
}

static void
print_qsfp_ext_identifier(const struct rte_dev_eeprom_info *eeprom_info,
			 json_writer_t *wr)
{
	uint8_t data;

	if (get_eeprom_data(eeprom_info, SFF_8436_BASE, SFF_8436_EXT_ID, 1,
			    &data))
		return;

	convert_sff_8436_ext_identifier(wr, data);
}

static void
print_qsfp_connector(const struct rte_dev_eeprom_info *eeprom_info,
		     json_writer_t *wr)
{
	uint8_t data;

	if (get_eeprom_data(eeprom_info, SFF_8436_BASE, SFF_8436_CONNECTOR, 1,
			    &data))
		return;

	convert_sff_connector(wr, data);
}

static void
print_sfp_transceiver_descr(const struct rte_dev_eeprom_info *eeprom_info,
			    json_writer_t *wr)
{
	uint8_t xbuf[12];
	const char *tech_class, *tech_len, *tech_tech, *tech_media, *tech_speed;

	tech_class = NULL;
	tech_len = NULL;
	tech_tech = NULL;
	tech_media = NULL;
	tech_speed = NULL;

	/* Read bytes 3-10 at once */
	if (get_eeprom_data(eeprom_info, SFF_8472_BASE, SFF_8472_TRANS_START, 8,
			    &xbuf[3]))
		return;

	/* Check 10G ethernet first */
	tech_class = find_zero_bit(eth_10g, xbuf[3], 1);
	if (tech_class == NULL) {
		/* No match. Try 1G */
		tech_class = find_zero_bit(eth_compat, xbuf[6], 1);
	}

	tech_len = find_zero_bit(fc_len, xbuf[7], 1);
	tech_tech = find_zero_bit(cab_tech, xbuf[7] << 8 | xbuf[8], 2);
	tech_media = find_zero_bit(fc_media, xbuf[9], 1);
	tech_speed = find_zero_bit(fc_speed, xbuf[10], 1);

	/* transceiver compliance codes - bytes 3-10 */
	if (tech_class)
		jsonw_string_field(wr, "class", tech_class);
	if (tech_len)
		jsonw_string_field(wr, "length", tech_len);
	if (tech_tech)
		jsonw_string_field(wr, "tech", tech_tech);
	if (tech_media)
		jsonw_string_field(wr, "media", tech_media);
	if (tech_speed)
		jsonw_string_field(wr, "speed", tech_speed);
}

static void
print_sfp_transceiver_class(const struct rte_dev_eeprom_info *eeprom_info,
			    json_writer_t *wr)
{
	const char *tech_class;
	uint8_t code;

	/* Use extended compliance code if it's valid */
	if (get_eeprom_data(eeprom_info, SFF_8472_BASE, SFF_8472_TRANS, 1,
			    &code))
		return;

	if (code != 0)
		tech_class = find_value(eth_extended_comp, code);
	else {
		/* Next, check 10G Ethernet/IB CCs */
		get_eeprom_data(eeprom_info, SFF_8472_BASE,
				SFF_8472_TRANS_START, 1, &code);
		tech_class = find_zero_bit(eth_10g, code, 1);
		if (tech_class == NULL) {
			/* No match. Try Ethernet 1G */
			get_eeprom_data(eeprom_info, SFF_8472_BASE,
					SFF_8472_TRANS_START + 3,
					1, &code);
			tech_class = find_zero_bit(eth_compat, code, 1);
		}
	}

	if (tech_class == NULL)
		tech_class = "Unknown";

	/* extended compliance code - byte 36 */
	jsonw_string_field(wr, "xcvr_class", tech_class);
}

static void
print_qsfp_transceiver_class(const struct rte_dev_eeprom_info *eeprom_info,
			     json_writer_t *wr)
{
	const char *tech_class;
	uint8_t code;

	if (get_eeprom_data(eeprom_info, SFF_8436_BASE,
			    SFF_8436_CODE_E1040100G, 1, &code))
		return;

	/* Check for extended specification compliance */
	if (code & SFF_8636_EXT_COMPLIANCE) {
		get_eeprom_data(eeprom_info, SFF_8436_BASE,
				SFF_8436_OPTIONS_START, 1, &code);
		tech_class = find_value(eth_extended_comp, code);
	} else
		/* Check 10/40G Ethernet class only */
		tech_class = find_zero_bit(eth_1040g, code, 1);

	if (tech_class == NULL)
		tech_class = "Unknown";

	jsonw_string_field(wr, "xcvr_class", tech_class);
}

static bool
is_valid_char(const char c)
{
	return !((c < 0x20) || (c > 0x7e));
}

/*
 * Print SFF-8472/SFF-8436 string to supplied buffer.
 * All (vendor-specific) strings are padded right with '0x20'.
 */
static void
convert_sff_name(json_writer_t *wr, const char *field_name, char *xbuf,
		 uint8_t len)
{
	int i;
	char *p = &xbuf[0];

	for (i = 0; i < len; i++) {
		if (!is_valid_char(*p)) {
			jsonw_string_field(wr, field_name, "");
			return;
		}
		p++;
	}
	*p = '\0';
	jsonw_string_field(wr, field_name, xbuf);
}

static void
convert_sff_vendor_oui(json_writer_t *wr, char *xbuf)
{
	char buf[9];

	snprintf(buf, sizeof(buf),
		 "%02hhx.%02hhx.%02hhx", xbuf[0], xbuf[1], xbuf[2]);
	jsonw_string_field(wr, "vendor_oui", buf);
}

static void
convert_sff_date(json_writer_t *wr, char *xbuf)
{
	char buf[20];
	int i;

	for (i = 0; i < 6; i++) {
		if (!is_valid_char(xbuf[i]))
			return;
	}
	snprintf(buf, 20, "20%c%c-%c%c-%c%c", xbuf[0], xbuf[1],
		 xbuf[2], xbuf[3], xbuf[4], xbuf[5]);
	buf[10] = '\0';
	jsonw_string_field(wr, "date", buf);
}

static void
print_sfp_vendor_name(const struct rte_dev_eeprom_info *eeprom_info,
		      json_writer_t *wr)
{
	char xbuf[17];

	memset(xbuf, 0, sizeof(xbuf));
	if (get_eeprom_data(eeprom_info, SFF_8472_BASE, SFF_8472_VENDOR_START,
			    16, (uint8_t *)xbuf))
		return;

	convert_sff_name(wr, "vendor_name", xbuf, 16);
}

static void
print_sfp_vendor_pn(const struct rte_dev_eeprom_info *eeprom_info,
		    json_writer_t *wr)
{
	char xbuf[17];

	memset(xbuf, 0, sizeof(xbuf));
	if (get_eeprom_data(eeprom_info, SFF_8472_BASE, SFF_8472_PN_START, 16,
			    (uint8_t *)xbuf))
		return;

	convert_sff_name(wr, "vendor_pn", xbuf, 16);
}

static void
print_sfp_vendor_oui(const struct rte_dev_eeprom_info *eeprom_info,
		     json_writer_t *wr)
{
	char xbuf[4];

	memset(xbuf, 0, sizeof(xbuf));
	if (get_eeprom_data(eeprom_info, SFF_8472_BASE,
			    SFF_8472_VENDOR_OUI_START, 3, (uint8_t *)xbuf))
		return;

	convert_sff_vendor_oui(wr, xbuf);
}

static void
print_sfp_vendor_sn(const struct rte_dev_eeprom_info *eeprom_info,
		    json_writer_t *wr)
{
	char xbuf[17];

	memset(xbuf, 0, sizeof(xbuf));
	if (get_eeprom_data(eeprom_info, SFF_8472_BASE, SFF_8472_SN_START, 16,
			    (uint8_t *)xbuf))
		return;

	convert_sff_name(wr, "vendor_sn", xbuf, 16);
}

static void
print_sfp_vendor_rev(const struct rte_dev_eeprom_info *eeprom_info,
		    json_writer_t *wr)
{
	char xbuf[5];

	memset(xbuf, 0, sizeof(xbuf));
	if (get_eeprom_data(eeprom_info, SFF_8472_BASE, SFF_8472_REV_START, 4,
			    (uint8_t *)xbuf))
		return;

	convert_sff_name(wr, "vendor_rev", xbuf, 4);
}

static void
print_sfp_vendor_date(const struct rte_dev_eeprom_info *eeprom_info,
		      json_writer_t *wr)
{
	char xbuf[7];

	memset(xbuf, 0, sizeof(xbuf));
	/* Date code, see Table 3.8 for description */
	if (get_eeprom_data(eeprom_info, SFF_8472_BASE, SFF_8472_DATE_START, 6,
			    (uint8_t *)xbuf))
		return;

	convert_sff_date(wr, xbuf);
}

static void
get_qsfp_device_tech(const struct rte_dev_eeprom_info *eeprom_info,
		     uint8_t *dev_tech)
{
	uint8_t xbuf = 0;

	if (get_eeprom_data(eeprom_info, SFF_8436_BASE, SFF_8436_DEV_TECH,
			    1, (uint8_t *)&xbuf))
		return;

	/*
	 * SFF 8436 Table 37
	 * device technology is in upper nibble
	 */
	xbuf = (xbuf & 0xf0) >> 4;

	*dev_tech = xbuf;
}

static void
print_qsfp_device_tech(const struct rte_dev_eeprom_info *eeprom_info,
		       json_writer_t *wr)
{
	const char *x;
	uint8_t dev_tech = 0;

	get_qsfp_device_tech(eeprom_info, &dev_tech);

	x = find_value(sff_8636_dev_tech, dev_tech);

	if (x)
		jsonw_string_field(wr, "dev_tech", x);
}

static void
print_qsfp_vendor_name(const struct rte_dev_eeprom_info *eeprom_info,
		       json_writer_t *wr)
{
	char xbuf[17];

	memset(xbuf, 0, sizeof(xbuf));
	if (get_eeprom_data(eeprom_info, SFF_8436_BASE, SFF_8436_VENDOR_START,
			    16, (uint8_t *)xbuf))
		return;

	convert_sff_name(wr, "vendor_name", xbuf, 16);
}

static void
print_qsfp_vendor_pn(const struct rte_dev_eeprom_info *eeprom_info,
		     json_writer_t *wr)
{
	char xbuf[17];

	memset(xbuf, 0, sizeof(xbuf));
	if (get_eeprom_data(eeprom_info, SFF_8436_BASE, SFF_8436_PN_START, 16,
			    (uint8_t *)xbuf))
		return;

	convert_sff_name(wr, "vendor_pn", xbuf, 16);
}

static void
print_qsfp_vendor_oui(const struct rte_dev_eeprom_info *eeprom_info,
		     json_writer_t *wr)
{
	char xbuf[4];

	memset(xbuf, 0, sizeof(xbuf));
	if (get_eeprom_data(eeprom_info, SFF_8436_BASE,
			    SFF_8436_VENDOR_OUI_START, 3, (uint8_t *)xbuf))
		return;

	convert_sff_vendor_oui(wr, xbuf);
}

static void
print_qsfp_vendor_sn(const struct rte_dev_eeprom_info *eeprom_info,
		     json_writer_t *wr)
{
	char xbuf[17];

	memset(xbuf, 0, sizeof(xbuf));
	if (get_eeprom_data(eeprom_info, SFF_8436_BASE, SFF_8436_SN_START, 16,
			    (uint8_t *)xbuf))
		return;

	convert_sff_name(wr, "vendor_sn", xbuf, 16);
}

static void
print_qsfp_vendor_rev(const struct rte_dev_eeprom_info *eeprom_info,
		    json_writer_t *wr)
{
	char xbuf[5];

	memset(xbuf, 0, sizeof(xbuf));
	if (get_eeprom_data(eeprom_info, SFF_8436_BASE, SFF_8436_REV_START, 2,
			    (uint8_t *)xbuf))
		return;

	convert_sff_name(wr, "vendor_rev", xbuf, 2);
}

static void
print_qsfp_vendor_date(const struct rte_dev_eeprom_info *eeprom_info,
		       json_writer_t *wr)
{
	char xbuf[6];

	memset(xbuf, 0, sizeof(xbuf));
	if (get_eeprom_data(eeprom_info, SFF_8436_BASE, SFF_8436_DATE_START, 6,
			    (uint8_t *)xbuf))
		return;

	convert_sff_date(wr, xbuf);
}

static void
print_sfp_vendor(const struct rte_eth_dev_module_info *module_info,
		 const struct rte_dev_eeprom_info *eeprom_info,
		 json_writer_t *wr)
{
	if (module_info->type == RTE_ETH_MODULE_SFF_8436) {
		print_qsfp_vendor_name(eeprom_info, wr);
		print_qsfp_vendor_pn(eeprom_info, wr);
		print_qsfp_vendor_sn(eeprom_info, wr);
		print_qsfp_vendor_date(eeprom_info, wr);
	} else if (module_info->type == RTE_ETH_MODULE_SFF_8472 ||
		   module_info->type == RTE_ETH_MODULE_SFF_8079) {
		print_sfp_vendor_name(eeprom_info, wr);
		print_sfp_vendor_pn(eeprom_info, wr);
		print_sfp_vendor_oui(eeprom_info, wr);
		print_sfp_vendor_sn(eeprom_info, wr);
		print_sfp_vendor_rev(eeprom_info, wr);
		print_sfp_vendor_date(eeprom_info, wr);
	}
}

static void
print_qsfp_vendor(const struct rte_dev_eeprom_info *eeprom_info,
		 json_writer_t *wr)
{
	print_qsfp_vendor_name(eeprom_info, wr);
	print_qsfp_vendor_pn(eeprom_info, wr);
	print_qsfp_vendor_oui(eeprom_info, wr);
	print_qsfp_vendor_sn(eeprom_info, wr);
	print_qsfp_vendor_rev(eeprom_info, wr);
	print_qsfp_vendor_date(eeprom_info, wr);
}

/*
 * Converts internal templerature (SFF-8472, SFF-8436)
 * 16-bit unsigned value to human-readable representation:
 *
 * Internally measured Module temperature are represented
 * as a 16-bit signed twos complement value in increments of
 * 1/256 degrees Celsius, yielding a total range of –128C to +128C
 * that is considered valid between –40 and +125C.
 *
 */

static double
__convert_sff_temp(const uint8_t *xbuf,
		   const struct sfp_calibration_constants *c_consts)
{
	int16_t temp;
	double d;
	const struct slope_off *so;

	temp = (xbuf[0] > 0x7f) ? xbuf[0] - (0xff + 1) : xbuf[0];

	d = (double)temp + (double)xbuf[1] / 256;

	if (c_consts) {
		so = &c_consts->slope_offs[SFP_CALIB_CONST_TEMPERATURE];
		d = (so->slope * d) + so->offset;
	}

	return d;
}

static void
convert_sff_temp(json_writer_t *wr, const char *field_name,
		 const uint8_t *xbuf,
		 const struct sfp_calibration_constants *c_consts)
{
	double d;

	d = __convert_sff_temp(xbuf, c_consts);
	jsonw_float_field(wr, field_name, d);
}

/*
 * Retrieves supplied voltage (SFF-8472, SFF-8436).
 * 16-bit usigned value, treated as range 0..+6.55 Volts
 */
static double
__convert_sff_voltage(const uint8_t *xbuf,
		      const struct sfp_calibration_constants *c_consts)
{
	double d;
	const struct slope_off *so;

	d = (double)((xbuf[0] << 8) | xbuf[1]);

	if (c_consts) {
		so = &c_consts->slope_offs[SFP_CALIB_CONST_VOLTAGE];
		d = (so->slope * d) + so->offset;
	}
	return d;
}

static void
convert_sff_voltage(json_writer_t *wr, const char *field_name,
		    const uint8_t *xbuf,
		    const struct sfp_calibration_constants *c_consts)
{
	double d;

	d = __convert_sff_voltage(xbuf, c_consts);
	jsonw_float_field(wr, field_name, d / 10000);
}

/*
 * Retrieves power in mW (SFF-8472).
 * 16-bit unsigned value, treated as a range of 0 - 6.5535 mW
 */
static double
__convert_sff_power(const uint8_t *xbuf, bool rx,
		    const struct sfp_calibration_constants *c_consts)
{
	double mW, tmp_mW;
	int i;

	tmp_mW = (xbuf[0] << 8) + xbuf[1];

	if (c_consts) {
		if (rx) {
			mW = (c_consts->rx_pwr[0].f +
			      c_consts->rx_pwr[1].f * tmp_mW);
			for (i = 2; i < SFP_CALIB_CONST_RX_PWR_CNT; i++)
				mW += c_consts->rx_pwr[i].f * tmp_mW *
					pow(10, i);
		} else {
			const struct slope_off *so =
				&c_consts->slope_offs[SFP_CALIB_CONST_TX_PWR];

			mW = (so->slope * tmp_mW) + so->offset;
		}
	} else
		mW = tmp_mW;

	return mW / 10000;
}

static void
convert_sff_power(json_writer_t *wr, const char *field_name,
		  const uint8_t *xbuf, bool rx,
		  const struct sfp_calibration_constants *c_consts)
{
	double mW;

	mW = __convert_sff_power(xbuf, rx, c_consts);
	jsonw_float_field(wr, field_name, mW);
}

static double
__convert_sff_bias(const uint8_t *xbuf,
		   const struct sfp_calibration_constants *c_consts)
{
	double mA;
	const struct slope_off *so;

	mA = (xbuf[0] << 8) + xbuf[1];

	if (c_consts) {
		so = &c_consts->slope_offs[SFP_CALIB_CONST_LASER_BIAS];
		mA = (so->slope * mA) + so->offset;
	}
	mA /= 500;

	return mA;
}

static void
convert_sff_bias(json_writer_t *wr, const char *field_name,
		 const uint8_t *xbuf,
		 const struct sfp_calibration_constants *c_consts)
{
	double mA;

	mA = __convert_sff_bias(xbuf, c_consts);
	jsonw_float_field(wr, field_name, mA);
}

static void
print_sfp_temp(const struct rte_dev_eeprom_info *eeprom_info,
	       const struct sfp_calibration_constants *c_consts,
	       json_writer_t *wr)
{
	uint8_t xbuf[2];

	memset(xbuf, 0, sizeof(xbuf));
	get_eeprom_data(eeprom_info, SFF_8472_DIAG, SFF_8472_TEMP, 2, xbuf);
	convert_sff_temp(wr, "temperature_C", xbuf, c_consts);
}

static void
print_sfp_voltage(const struct rte_dev_eeprom_info *eeprom_info,
		  const struct sfp_calibration_constants *c_consts,
		  json_writer_t *wr)
{
	uint8_t xbuf[2];

	memset(xbuf, 0, sizeof(xbuf));
	get_eeprom_data(eeprom_info, SFF_8472_DIAG, SFF_8472_VCC, 2, xbuf);
	convert_sff_voltage(wr, "voltage_V", xbuf, c_consts);
}

static void
print_sfp_br(const struct rte_dev_eeprom_info *eeprom_info,
	      json_writer_t *wr)
{
	uint8_t xbuf;
	uint32_t rate;

	xbuf = 0;
	get_eeprom_data(eeprom_info, SFF_8472_BASE, SFF_8472_BITRATE, 1, &xbuf);
	rate = xbuf * 100;
	if (xbuf == 0xFF) {
		get_eeprom_data(eeprom_info, SFF_8472_BASE, SFF_8472_BITRATE,
				1, &xbuf);
		rate = xbuf * 250;
	}

	jsonw_uint_field(wr, "nominal_bit_rate_mbps", rate);
}

static void
print_sfp_diag_type(const struct rte_dev_eeprom_info *eeprom_info,
	      json_writer_t *wr)
{
	uint8_t xbuf;

	xbuf = 0;
	get_eeprom_data(eeprom_info, SFF_8472_BASE, SFF_8472_DIAG_TYPE, 1,
			&xbuf);

	jsonw_uint_field(wr, "diag_type", xbuf);
}

static void
print_sfp_len(const struct rte_dev_eeprom_info *eeprom_info,
	      uint8_t offset, const char *field,
	      json_writer_t *wr)
{
	uint8_t xbuf;

	xbuf = 0;
	get_eeprom_data(eeprom_info, SFF_8472_BASE, offset, 1,
			&xbuf);

	jsonw_uint_field(wr, field, xbuf);
}

static void
print_sfp_encoding(const struct rte_dev_eeprom_info *eeprom_info,
		   json_writer_t *wr)
{
	uint8_t xbuf;

	xbuf = 0;
	get_eeprom_data(eeprom_info, SFF_8472_BASE, SFF_8472_ENCODING, 1,
			&xbuf);

	convert_sff_encoding(wr, xbuf);
}

static void
print_sfp_8472_compl(const struct rte_dev_eeprom_info *eeprom_info,
		     json_writer_t *wr)
{
	uint8_t xbuf;

	xbuf = 0;
	get_eeprom_data(eeprom_info, SFF_8472_BASE, SFF_8472_COMPLIANCE, 1,
			&xbuf);

	convert_sff_8472_compl(wr, xbuf);
}

static void
print_qsfp_len(const struct rte_dev_eeprom_info *eeprom_info,
	      uint8_t offset, const char *field,
	      json_writer_t *wr)
{
	uint8_t xbuf;

	xbuf = 0;
	get_eeprom_data(eeprom_info, SFF_8436_BASE, offset, 1,
			&xbuf);

	jsonw_uint_field(wr, field, xbuf);
}

static void
print_qsfp_encoding(const struct rte_dev_eeprom_info *eeprom_info,
		   json_writer_t *wr)
{
	uint8_t xbuf;

	xbuf = 0;
	get_eeprom_data(eeprom_info, SFF_8436_BASE, SFF_8436_ENCODING, 1,
			&xbuf);

	convert_sff_8436_encoding(wr, xbuf);
}

static void
get_sfp_calibration_constants(const struct rte_dev_eeprom_info *eeprom_info,
			      struct sfp_calibration_constants *c_consts,
			      json_writer_t *wr)
{
	uint16_t i, offset, cursor;
	uint8_t xbuf[4];
	union ieee754_float rx_pwr;
	char json_field_name[30], json_str[40];

	jsonw_name(wr, "raw_calibration_data");
	jsonw_start_object(wr);
	cursor = SFF_8472_RX_POWER4;
	for (i = 0; i < SFP_CALIB_CONST_RX_PWR_CNT; i++) {
		get_eeprom_data(eeprom_info, SFF_8472_DIAG,
				cursor, SFP_CALIB_CONST_RX_PWR_SIZE,
				xbuf);
		snprintf(json_field_name, 30, "%2d: rx_pwr_%d",
			 cursor, SFP_CALIB_CONST_MAX - i);
		snprintf(json_str, 40, "%02x %02x %02x %02x",
			 xbuf[0], xbuf[1], xbuf[2], xbuf[3]);
		jsonw_string_field(wr, json_field_name, json_str);

		rx_pwr.ieee.negative = (xbuf[0] & 0x80) >> 7;
		rx_pwr.ieee.exponent = (((xbuf[0] & 0x7f) << 1) |
					((xbuf[1] & 0x80) >> 7));
		rx_pwr.ieee.mantissa += (((xbuf[1] & 0x7f) << 16) |
					 (xbuf[2] << 8) | xbuf[3]);

		c_consts->rx_pwr[SFP_CALIB_CONST_MAX - i] = rx_pwr;
		cursor += SFP_CALIB_CONST_RX_PWR_SIZE;
	}

	cursor = SFF_8472_TX_I_SLOPE;
	for (i = 0; i < SFP_CALIB_CONST_MAX; i++) {
		get_eeprom_data(eeprom_info, SFF_8472_DIAG,
				cursor, SFP_CALIB_CONST_SL_OFF_SIZE,
				xbuf);

		snprintf(json_field_name, 30, "%02d: %s_slope",
			 cursor, sfp_calib_const_strs[i]);
		snprintf(json_str, 40, "%02x %02x", xbuf[0], xbuf[1]);
		jsonw_string_field(wr, json_field_name, json_str);

		c_consts->slope_offs[i].slope = (float)xbuf[0] +
			(float)xbuf[1]/256;
		cursor += SFP_CALIB_CONST_SL_OFF_SIZE;

		get_eeprom_data(eeprom_info, SFF_8472_DIAG,
				cursor, SFP_CALIB_CONST_SL_OFF_SIZE,
				(uint8_t *)&offset);

		snprintf(json_field_name, 30, "%02d: %s_offset",
			 cursor, sfp_calib_const_strs[i]);
		snprintf(json_str, 40, "%02x %02x", ((uint8_t *)&offset)[0],
			 ((uint8_t *)&offset)[1]);
		jsonw_string_field(wr, json_field_name, json_str);

		c_consts->slope_offs[i].offset = ntohs(offset);
		cursor += SFP_CALIB_CONST_SL_OFF_SIZE;
	}
	jsonw_end_object(wr);
}

static void
print_sfp_calibration_constants(struct sfp_calibration_constants *c_consts,
				json_writer_t *wr)
{
#define CONST_STR_LEN 20
	char const_str[CONST_STR_LEN];
	uint8_t i;

	for (i = 0; i < SFP_CALIB_CONST_RX_PWR_CNT; i++) {
		snprintf(const_str, CONST_STR_LEN, "rx_pwr_%1d", i);
		jsonw_float_field(wr, const_str, c_consts->rx_pwr[i].f);
	}

	for (i = 0; i < SFP_CALIB_CONST_MAX; i++) {
		snprintf(const_str, CONST_STR_LEN, "%s_slope",
			 sfp_calib_const_strs[i]);
		jsonw_float_field(wr, const_str,
				  c_consts->slope_offs[i].slope);
		snprintf(const_str, CONST_STR_LEN, "%s_offset",
			 sfp_calib_const_strs[i]);
		jsonw_int_field(wr, const_str,
				c_consts->slope_offs[i].offset);
	}
}

static void
print_qsfp_temp(const struct rte_dev_eeprom_info *eeprom_info,
		json_writer_t *wr)
{
	uint8_t xbuf[2];

	memset(xbuf, 0, sizeof(xbuf));
	get_eeprom_data(eeprom_info, SFF_8436_BASE, SFF_8436_TEMP, 2, xbuf);
	convert_sff_temp(wr, "temperature_C", xbuf, NULL);
}

static void
print_qsfp_voltage(const struct rte_dev_eeprom_info *eeprom_info,
		   json_writer_t *wr)
{
	uint8_t xbuf[2];

	memset(xbuf, 0, sizeof(xbuf));
	get_eeprom_data(eeprom_info, SFF_8436_BASE, SFF_8436_VCC, 2, xbuf);
	convert_sff_voltage(wr, "voltage_V", xbuf, NULL);
}

static void
print_sfp_rx_power(const struct rte_dev_eeprom_info *eeprom_info,
		   const struct sfp_calibration_constants *c_consts,
		   json_writer_t *wr)
{
	uint8_t xbuf[2];

	memset(xbuf, 0, sizeof(xbuf));
	get_eeprom_data(eeprom_info, SFF_8472_DIAG, SFF_8472_RX_POWER, 2, xbuf);
	convert_sff_power(wr, "rx_power_mW", xbuf, true, c_consts);
}

#define TX_POWER_FIELD_NAME "tx_power_mW"

static void
print_sfp_tx_power(bool up, const struct rte_dev_eeprom_info *eeprom_info,
		   const struct sfp_calibration_constants *c_consts,
		   json_writer_t *wr)
{
	uint8_t xbuf[2];
	uint8_t status_byte;

	if (get_eeprom_data(eeprom_info, SFF_8472_DIAG,
			    SFF_8472_STATUS, 1, &status_byte))
		return;

	if (up || !(status_byte & SFF_8472_STATUS_TX_DISABLE)) {
		memset(xbuf, 0, sizeof(xbuf));
		get_eeprom_data(eeprom_info, SFF_8472_DIAG, SFF_8472_TX_POWER,
				2, xbuf);
		convert_sff_power(wr, TX_POWER_FIELD_NAME, xbuf, false, c_consts);
	} else
		jsonw_float_field(wr, TX_POWER_FIELD_NAME, 0);
}

static void
print_sfp_laser_bias(const struct rte_dev_eeprom_info *eeprom_info,
		     const struct sfp_calibration_constants *c_consts,
		     json_writer_t *wr)
{
	uint8_t xbuf[2];

	memset(xbuf, 0, sizeof(xbuf));
	get_eeprom_data(eeprom_info, SFF_8472_DIAG, SFF_8472_TX_BIAS, 2, xbuf);
	convert_sff_bias(wr, "laser_bias", xbuf, c_consts);
}

static void
print_qsfp_rx_power(const struct rte_dev_eeprom_info *eeprom_info,
		    json_writer_t *wr, int chan)
{
	uint8_t xbuf[2];

	memset(xbuf, 0, sizeof(xbuf));
	get_eeprom_data(eeprom_info, SFF_8436_BASE,
			SFF_8436_RX_CH1_MSB + (chan * 2), 2, xbuf);
	convert_sff_power(wr, "rx_power_mW", xbuf, true, NULL);
}

static void
print_qsfp_tx_power(bool up, const struct rte_dev_eeprom_info *eeprom_info,
		    json_writer_t *wr, int chan)
{
	uint8_t xbuf[2];

	if (up) {
		memset(xbuf, 0, sizeof(xbuf));
		get_eeprom_data(eeprom_info, SFF_8436_BASE,
				SFF_8436_TX_CH1_MSB + (chan * 2), 2, xbuf);
		convert_sff_power(wr, TX_POWER_FIELD_NAME, xbuf, false, NULL);
	} else
		jsonw_float_field(wr, TX_POWER_FIELD_NAME, 0);
}

static void
print_qsfp_laser_bias(const struct rte_dev_eeprom_info *eeprom_info,
		    json_writer_t *wr, int chan)
{
	uint8_t xbuf[2];

	memset(xbuf, 0, sizeof(xbuf));
	get_eeprom_data(eeprom_info, SFF_8436_BASE,
			SFF_8436_TX_BIAS_CH1_MSB + (chan * 2), 2, xbuf);
	convert_sff_bias(wr, "laser_bias", xbuf, NULL);
}

static void
print_qsfp_rev_compliance(const struct rte_dev_eeprom_info *eeprom_info,
			  json_writer_t *wr)
{
	uint8_t xbuf;

	xbuf = 0;
	get_eeprom_data(eeprom_info, SFF_8436_BASE, SFF_8436_STATUS, 1, &xbuf);
	convert_sff_8436_rev_compliance(wr, xbuf);
}

static void
print_qsfp_br(const struct rte_dev_eeprom_info *eeprom_info,
	      json_writer_t *wr)
{
	uint8_t xbuf;
	uint32_t rate;

	xbuf = 0;
	get_eeprom_data(eeprom_info, SFF_8436_BASE, SFF_8436_BITRATE, 1, &xbuf);
	rate = xbuf * 100;
	if (xbuf == 0xFF) {
		get_eeprom_data(eeprom_info, SFF_8436_BASE, SFF_8636_BITRATE,
				1, &xbuf);
		rate = xbuf * 250;
	}

	jsonw_uint_field(wr, "nominal_bit_rate_mbps", rate);
}

static void
print_qsfp_temp_thresholds(const struct rte_dev_eeprom_info *eeprom_info,
		      json_writer_t *wr)
{
	uint8_t xbuf[2];

	memset(xbuf, 0, sizeof(xbuf));
	if (!get_eeprom_data(eeprom_info, SFF_8436_BASE,
			     SFF_8636_TEMP_HIGH_ALARM, 2, xbuf))
		convert_sff_temp(wr, "high_temp_alarm_thresh", xbuf, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8436_BASE,
			     SFF_8636_TEMP_LOW_ALARM, 2, xbuf))
		convert_sff_temp(wr, "low_temp_alarm_thresh", xbuf, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8436_BASE,
			     SFF_8636_TEMP_HIGH_WARN, 2, xbuf))
		convert_sff_temp(wr, "high_temp_warn_thresh", xbuf, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8436_BASE,
			     SFF_8636_TEMP_LOW_WARN, 2, xbuf))
		convert_sff_temp(wr, "low_temp_warn_thresh", xbuf, NULL);
}

static void
print_qsfp_voltage_thresholds(const struct rte_dev_eeprom_info *eeprom_info,
			 json_writer_t *wr)
{
	uint8_t xbuf[2];

	memset(xbuf, 0, sizeof(xbuf));
	if (!get_eeprom_data(eeprom_info, SFF_8436_BASE,
			    SFF_8636_VOLTAGE_HIGH_ALARM, 2, xbuf))
		convert_sff_voltage(wr, "high_voltage_alarm_thresh",
				    xbuf, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8436_BASE,
			     SFF_8636_VOLTAGE_LOW_ALARM, 2, xbuf))
		convert_sff_voltage(wr, "low_voltage_alarm_thresh",
				    xbuf, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8436_BASE,
			     SFF_8636_VOLTAGE_HIGH_WARN, 2, xbuf))
		convert_sff_voltage(wr, "high_voltage_warn_thresh",
				    xbuf, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8436_BASE,
			     SFF_8636_VOLTAGE_LOW_WARN, 2, xbuf))
		convert_sff_voltage(wr, "low_voltage_warn_thresh",
				    xbuf, NULL);
}

static void
print_qsfp_bias_thresholds(const struct rte_dev_eeprom_info *eeprom_info,
		      json_writer_t *wr)
{
	uint8_t xbuf[2];

	memset(xbuf, 0, sizeof(xbuf));
	if (!get_eeprom_data(eeprom_info, SFF_8436_BASE,
			     SFF_8636_TX_BIAS_HIGH_ALARM, 2, xbuf))
		convert_sff_bias(wr, "high_bias_alarm_thresh", xbuf, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8436_BASE,
			     SFF_8636_TX_BIAS_LOW_ALARM, 2, xbuf))
		convert_sff_bias(wr, "low_bias_alarm_thresh", xbuf, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8436_BASE,
			     SFF_8636_TX_BIAS_HIGH_WARN, 2, xbuf))
		convert_sff_bias(wr, "high_bias_warn_thresh", xbuf, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8436_BASE,
			     SFF_8636_TX_BIAS_LOW_WARN, 2, xbuf))
		convert_sff_bias(wr, "low_bias_warn_thresh", xbuf, NULL);
}

static void
print_qsfp_tx_power_thresholds(const struct rte_dev_eeprom_info *eeprom_info,
			  json_writer_t *wr)
{
	uint8_t xbuf[2];

	memset(xbuf, 0, sizeof(xbuf));
	if (!get_eeprom_data(eeprom_info, SFF_8436_BASE,
			     SFF_8636_TX_POWER_HIGH_ALARM, 2, xbuf))
		convert_sff_power(wr, "high_tx_power_alarm_thresh", xbuf,
				  false, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8436_BASE,
			     SFF_8636_TX_POWER_LOW_ALARM, 2, xbuf))
		convert_sff_power(wr, "low_tx_power_alarm_thresh", xbuf,
				  false, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8436_BASE,
			     SFF_8636_TX_POWER_HIGH_WARN, 2, xbuf))
		convert_sff_power(wr, "high_tx_power_warn_thresh", xbuf,
				  false, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8436_BASE,
			     SFF_8636_TX_POWER_LOW_WARN, 2, xbuf))
		convert_sff_power(wr, "low_tx_power_warn_thresh", xbuf,
				  false, NULL);
}

static void
print_qsfp_rx_power_thresholds(const struct rte_dev_eeprom_info *eeprom_info,
			  json_writer_t *wr)
{
	uint8_t xbuf[2];

	memset(xbuf, 0, sizeof(xbuf));
	if (!get_eeprom_data(eeprom_info, SFF_8436_BASE,
			     SFF_8636_RX_POWER_HIGH_ALARM, 2, xbuf))
		convert_sff_power(wr, "high_rx_power_alarm_thresh", xbuf,
				  true, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8436_BASE,
			     SFF_8636_RX_POWER_LOW_ALARM, 2, xbuf))
		convert_sff_power(wr, "low_rx_power_alarm_thresh", xbuf,
				  true, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8436_BASE,
			     SFF_8636_RX_POWER_HIGH_WARN, 2, xbuf))
		convert_sff_power(wr, "high_rx_power_warn_thresh", xbuf,
				  true, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8436_BASE,
			     SFF_8636_RX_POWER_LOW_WARN, 2, xbuf))
		convert_sff_power(wr, "low_rx_power_warn_thresh", xbuf,
				  true, NULL);
}

static void
print_qsfp_thresholds(const struct rte_dev_eeprom_info *eeprom_info,
		      json_writer_t *wr)
{
	print_qsfp_temp_thresholds(eeprom_info, wr);
	print_qsfp_voltage_thresholds(eeprom_info, wr);
	print_qsfp_bias_thresholds(eeprom_info, wr);
	print_qsfp_tx_power_thresholds(eeprom_info, wr);
	print_qsfp_rx_power_thresholds(eeprom_info, wr);
}

static void
print_temp_thresholds(const struct rte_dev_eeprom_info *eeprom_info,
		      json_writer_t *wr)
{
	uint8_t xbuf[2];

	memset(xbuf, 0, sizeof(xbuf));
	if (!get_eeprom_data(eeprom_info, SFF_8472_DIAG,
			     SFF_8472_TEMP_HIGH_ALM, 2, xbuf))
		convert_sff_temp(wr, "high_temp_alarm_thresh", xbuf, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8472_DIAG,
			     SFF_8472_TEMP_LOW_ALM, 2, xbuf))
		convert_sff_temp(wr, "low_temp_alarm_thresh", xbuf, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8472_DIAG,
			     SFF_8472_TEMP_HIGH_WARN, 2, xbuf))
		convert_sff_temp(wr, "high_temp_warn_thresh", xbuf, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8472_DIAG,
			     SFF_8472_TEMP_LOW_WARN, 2, xbuf))
		convert_sff_temp(wr, "low_temp_warn_thresh", xbuf, NULL);
}

static void
print_voltage_thresholds(const struct rte_dev_eeprom_info *eeprom_info,
			 json_writer_t *wr)
{
	uint8_t xbuf[2];

	memset(xbuf, 0, sizeof(xbuf));
	if (!get_eeprom_data(eeprom_info, SFF_8472_DIAG,
			    SFF_8472_VOLTAGE_HIGH_ALM, 2, xbuf))
		convert_sff_voltage(wr, "high_voltage_alarm_thresh", xbuf,
				    NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8472_DIAG,
			     SFF_8472_VOLTAGE_LOW_ALM, 2, xbuf))
		convert_sff_voltage(wr, "low_voltage_alarm_thresh", xbuf,
				    NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8472_DIAG,
			     SFF_8472_VOLTAGE_HIGH_WARN, 2, xbuf))
		convert_sff_voltage(wr, "high_voltage_warn_thresh", xbuf,
				    NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8472_DIAG,
			     SFF_8472_VOLTAGE_LOW_WARN, 2, xbuf))
		convert_sff_voltage(wr, "low_voltage_warn_thresh", xbuf,
				    NULL);
}

static void
print_bias_thresholds(const struct rte_dev_eeprom_info *eeprom_info,
		      json_writer_t *wr)
{
		uint8_t xbuf[2];

	memset(xbuf, 0, sizeof(xbuf));
	if (!get_eeprom_data(eeprom_info, SFF_8472_DIAG,
			     SFF_8472_BIAS_HIGH_ALM, 2, xbuf))
		convert_sff_bias(wr, "high_bias_alarm_thresh", xbuf, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8472_DIAG,
			     SFF_8472_BIAS_LOW_ALM, 2, xbuf))
		convert_sff_bias(wr, "low_bias_alarm_thresh", xbuf, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8472_DIAG,
			     SFF_8472_BIAS_HIGH_WARN, 2, xbuf))
		convert_sff_bias(wr, "high_bias_warn_thresh", xbuf, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8472_DIAG,
			     SFF_8472_BIAS_LOW_WARN, 2, xbuf))
		convert_sff_bias(wr, "low_bias_warn_thresh", xbuf, NULL);
}

static void
print_tx_power_thresholds(const struct rte_dev_eeprom_info *eeprom_info,
			  json_writer_t *wr)
{
	uint8_t xbuf[2];

	memset(xbuf, 0, sizeof(xbuf));
	if (!get_eeprom_data(eeprom_info, SFF_8472_DIAG,
			     SFF_8472_TX_POWER_HIGH_ALM, 2, xbuf))
		convert_sff_power(wr, "high_tx_power_alarm_thresh", xbuf,
				  false, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8472_DIAG,
			     SFF_8472_TX_POWER_LOW_ALM, 2, xbuf))
		convert_sff_power(wr, "low_tx_power_alarm_thresh", xbuf,
				  false, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8472_DIAG,
			     SFF_8472_TX_POWER_HIGH_WARN, 2, xbuf))
		convert_sff_power(wr, "high_tx_power_warn_thresh", xbuf,
				  false, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8472_DIAG,
			     SFF_8472_TX_POWER_LOW_WARN, 2, xbuf))
		convert_sff_power(wr, "low_tx_power_warn_thresh", xbuf,
				  false, NULL);
}

static void
print_rx_power_thresholds(const struct rte_dev_eeprom_info *eeprom_info,
			  json_writer_t *wr)
{
	uint8_t xbuf[2];

	memset(xbuf, 0, sizeof(xbuf));
	if (!get_eeprom_data(eeprom_info, SFF_8472_DIAG,
			     SFF_8472_RX_POWER_HIGH_ALM, 2, xbuf))
		convert_sff_power(wr, "high_rx_power_alarm_thresh", xbuf,
				  false, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8472_DIAG,
			     SFF_8472_RX_POWER_LOW_ALM, 2, xbuf))
		convert_sff_power(wr, "low_rx_power_alarm_thresh", xbuf,
				  false, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8472_DIAG,
			     SFF_8472_RX_POWER_HIGH_WARN, 2, xbuf))
		convert_sff_power(wr, "high_rx_power_warn_thresh", xbuf,
				  false, NULL);
	if (!get_eeprom_data(eeprom_info, SFF_8472_DIAG,
			     SFF_8472_RX_POWER_LOW_WARN, 2, xbuf))
		convert_sff_power(wr, "low_rx_power_warn_thresh", xbuf,
				  false, NULL);
}

static void
print_sfp_thresholds(const struct rte_dev_eeprom_info *eeprom_info,
		     json_writer_t *wr)
{
	print_temp_thresholds(eeprom_info, wr);
	print_voltage_thresholds(eeprom_info, wr);
	print_bias_thresholds(eeprom_info, wr);
	print_tx_power_thresholds(eeprom_info, wr);
	print_rx_power_thresholds(eeprom_info, wr);
}

static void
convert_aw_flags(json_writer_t *wr, struct _nv_ext *x, const uint8_t *xbuf, bool alarm)
{
	uint16_t flags;
	const char *suffix = (alarm ? "alarm" : "warn");
	char aw_field[40];

	flags = (uint16_t)((xbuf[0] << 8) | xbuf[1]);
	for (; x->n != NULL; x++) {
		snprintf(aw_field, sizeof(aw_field), "%s_%s", x->n, suffix);
		jsonw_bool_field(wr, aw_field, flags & (1 << x->v));
	}
}

static void
print_sfp_alarm_flags(const struct rte_dev_eeprom_info *eeprom_info,
		      json_writer_t *wr)
{
	uint8_t xbuf[2];

	memset(xbuf, 0, sizeof(xbuf));
	if (get_eeprom_data(eeprom_info, SFF_8472_DIAG, SFF_8472_ALARM_FLAGS,
			    2, xbuf))
		return;
	convert_aw_flags(wr, aw_flags, xbuf, true);
}

static void
print_sfp_warning_flags(const struct rte_dev_eeprom_info *eeprom_info,
			json_writer_t *wr)
{
	uint8_t xbuf[2];

	memset(xbuf, 0, sizeof(xbuf));
	if (get_eeprom_data(eeprom_info, SFF_8472_DIAG,
			    SFF_8472_WARNING_FLAGS, 2, xbuf))
		return;
	convert_aw_flags(wr, aw_flags, xbuf, false);
}

static void

convert_qsfp_aw_flags(json_writer_t *wr, struct _nv_ext *x,
		  uint8_t flags)
{

	for (; x->n != NULL; x++)
		jsonw_bool_field(wr, x->n, flags & (1 << x->v));
}

static void
print_qsfp_temp_aw_flags(const struct rte_dev_eeprom_info *eeprom_info,
		      json_writer_t *wr)
{
	uint8_t xbuf = 0;

	if (get_eeprom_data(eeprom_info, SFF_8436_BASE, SFF8436_TEMP_AW_OFFSET,
			    1, &xbuf))
		return;

	convert_qsfp_aw_flags(wr, temp_alarm_warn_flags, xbuf);
}

static void
print_qsfp_voltage_aw_flags(const struct rte_dev_eeprom_info *eeprom_info,
		      json_writer_t *wr)
{
	uint8_t xbuf = 0;

	if (get_eeprom_data(eeprom_info, SFF_8436_BASE, SFF8436_VCC_AW_OFFSET,
			    1, &xbuf))
		return;

	convert_qsfp_aw_flags(wr, voltage_alarm_warn_flags, xbuf);
}

static void
print_qsfp_aw_flags(const struct rte_dev_eeprom_info *eeprom_info,
		      json_writer_t *wr)
{
	uint8_t xbuf_tx_bias_12 = 0;
	uint8_t xbuf_tx_bias_34 = 0;
	uint8_t xbuf_tx_pow_12 = 0;
	uint8_t xbuf_tx_pow_34 = 0;
	uint8_t xbuf_rx_pow_12 = 0;
	uint8_t xbuf_rx_pow_34 = 0;

	if (get_eeprom_data(eeprom_info, SFF_8436_BASE,
				SFF8436_TX_BIAS_12_AW_OFFSET,
				1, &xbuf_tx_bias_12))
		return;

	if (get_eeprom_data(eeprom_info, SFF_8436_BASE,
				SFF8436_TX_BIAS_34_AW_OFFSET,
				1, &xbuf_tx_bias_34))
		return;

	if (get_eeprom_data(eeprom_info, SFF_8436_BASE,
				SFF8436_TX_PWR_12_AW_OFFSET,
				1, &xbuf_tx_pow_12))
		return;

	if (get_eeprom_data(eeprom_info, SFF_8436_BASE,
				SFF8436_TX_PWR_34_AW_OFFSET,
				1, &xbuf_tx_pow_34))
		return;

	if (get_eeprom_data(eeprom_info, SFF_8436_BASE,
			SFF8436_RX_PWR_12_AW_OFFSET,
			1, &xbuf_rx_pow_12))
		return;

	if (get_eeprom_data(eeprom_info, SFF_8436_BASE,
			SFF8436_RX_PWR_34_AW_OFFSET,
			1, &xbuf_rx_pow_34))
		return;

	jsonw_name(wr, "alarm_warning");
	jsonw_start_array(wr);

	jsonw_start_object(wr);
	jsonw_uint_field(wr, "channel", 1);
	convert_qsfp_aw_flags(wr, tx_bias_aw_chan_upper_flags, xbuf_tx_bias_12);
	convert_qsfp_aw_flags(wr, tx_pwr_aw_chan_upper_flags, xbuf_tx_pow_12);
	convert_qsfp_aw_flags(wr, rx_pwr_aw_chan_upper_flags, xbuf_rx_pow_12);
	jsonw_end_object(wr);

	jsonw_start_object(wr);
	jsonw_uint_field(wr, "channel", 2);
	convert_qsfp_aw_flags(wr, tx_bias_aw_chan_lower_flags, xbuf_tx_bias_12);
	convert_qsfp_aw_flags(wr, tx_pwr_aw_chan_lower_flags, xbuf_tx_pow_12);
	convert_qsfp_aw_flags(wr, rx_pwr_aw_chan_lower_flags, xbuf_rx_pow_12);
	jsonw_end_object(wr);

	jsonw_start_object(wr);
	jsonw_uint_field(wr, "channel", 3);
	convert_qsfp_aw_flags(wr, tx_bias_aw_chan_upper_flags, xbuf_tx_bias_34);
	convert_qsfp_aw_flags(wr, tx_pwr_aw_chan_upper_flags, xbuf_tx_pow_34);
	convert_qsfp_aw_flags(wr, rx_pwr_aw_chan_upper_flags, xbuf_rx_pow_34);
	jsonw_end_object(wr);

	jsonw_start_object(wr);
	jsonw_uint_field(wr, "channel", 4);
	convert_qsfp_aw_flags(wr, tx_bias_aw_chan_lower_flags, xbuf_tx_bias_34);
	convert_qsfp_aw_flags(wr, tx_pwr_aw_chan_lower_flags, xbuf_tx_pow_34);
	convert_qsfp_aw_flags(wr, rx_pwr_aw_chan_lower_flags, xbuf_rx_pow_34);
	jsonw_end_object(wr);

	jsonw_end_array(wr);
}

static void print_sfp_status_byte(const struct rte_dev_eeprom_info *eeprom_info,
				  json_writer_t *wr)
{
	uint8_t status_byte = 0, i;
	/* strings match definitions of SFF_8472_STATUS_* in sff8472.h */
	static const char *sfp_status_str[BITS_PER_BYTE] = {
		"data_ready",
		"rx_los",
		"tx_fault_state",
		"soft_rate_select",
		"select_state",
		"rs_state",
		"soft_tx_disable",
		"tx_disable"
	};

	if (get_eeprom_data(eeprom_info, SFF_8472_DIAG,
			    SFF_8472_STATUS, 1, &status_byte))
		return;

	/*
	 * return if the data is not ready to be read or if
	 * there are no other bits set
	 */
	if (status_byte & SFF_8472_STATUS_DATA_READY ||
	    !(status_byte & ~SFF_8472_STATUS_DATA_READY))
		return;

	jsonw_name(wr, "status_byte");
	jsonw_start_object(wr);
	for (i = 1; i < BITS_PER_BYTE; i++)
		if (status_byte & (1 << i))
			jsonw_uint_field(wr, sfp_status_str[i], 1);
	jsonw_end_object(wr);
}


static void
print_sfp_status(bool up, const struct rte_eth_dev_module_info *module_info,
		 const struct rte_dev_eeprom_info *eeprom_info,
		 bool include_static, json_writer_t *wr)
{
	struct sfp_calibration_constants c_consts, *c_const_p;
	uint8_t diag_type;
	int do_diag = 0;

	/* Read diagnostic monitoring type */
	if (get_eeprom_data(eeprom_info, SFF_8472_BASE, SFF_8472_DIAG_TYPE,
			    1, &diag_type))
		return;

	/*
	 * Read monitoring data IFF it is supplied
	 */
	if (diag_type & SFF_8472_DDM_DONE)
		do_diag = 1;

	/* Transceiver type */
	print_sfp_identifier(eeprom_info, wr);

	if (include_static) {
		print_sfp_ext_identifier(eeprom_info, wr);
		print_sfp_transceiver_class(eeprom_info, wr);
		print_sfp_connector(eeprom_info, wr);
		print_sfp_vendor(module_info, eeprom_info, wr);
		print_sfp_transceiver_descr(eeprom_info, wr);
		print_sfp_br(eeprom_info, wr);
		print_sfp_diag_type(eeprom_info, wr);
		print_sfp_len(eeprom_info, SFF_8472_LEN_OM4, "copper_len", wr);
		print_sfp_encoding(eeprom_info, wr);
		print_sfp_8472_compl(eeprom_info, wr);
		print_sfp_len(eeprom_info, SFF_8472_LEN_SMF, "smf_100", wr);
		print_sfp_len(eeprom_info, SFF_8472_LEN_SMF_KM, "smf_km", wr);
		print_sfp_len(eeprom_info, SFF_8472_LEN_625UM, "smf_om1", wr);
		print_sfp_len(eeprom_info, SFF_8472_LEN_50UM, "smf_om2", wr);
		print_sfp_len(eeprom_info, SFF_8472_LEN_OM3, "smf_om3", wr);
	}

	/*
	 * Request current measurements iff they are provided:
	 */
	if (do_diag != 0) {
		if (diag_type & SFF_8472_DDM_EXTERNAL) {
			c_const_p = &c_consts;
			get_sfp_calibration_constants(eeprom_info, c_const_p,
						      wr);
			print_sfp_calibration_constants(c_const_p, wr);
		} else
			c_const_p = NULL;
		print_sfp_temp(eeprom_info, c_const_p, wr);
		print_sfp_voltage(eeprom_info, c_const_p, wr);
		print_sfp_rx_power(eeprom_info, c_const_p, wr);
		print_sfp_tx_power(up, eeprom_info, c_const_p, wr);
		print_sfp_laser_bias(eeprom_info, c_const_p, wr);
		print_sfp_status_byte(eeprom_info, wr);

		if (include_static)
			print_sfp_thresholds(eeprom_info, wr);

		print_sfp_alarm_flags(eeprom_info, wr);
		print_sfp_warning_flags(eeprom_info, wr);
	}
}

static void
print_qsfp_status(bool up, const struct rte_dev_eeprom_info *eeprom_info,
		  bool include_static, json_writer_t *wr)
{
	uint8_t dev_tech = 0;

	/* Transceiver type */
	print_qsfp_identifier(eeprom_info, wr);

	if (include_static) {
		print_qsfp_ext_identifier(eeprom_info, wr);
		print_qsfp_transceiver_class(eeprom_info, wr);
		print_qsfp_connector(eeprom_info, wr);
		print_qsfp_device_tech(eeprom_info, wr);
		print_qsfp_vendor(eeprom_info, wr);
		print_qsfp_encoding(eeprom_info, wr);
		print_qsfp_rev_compliance(eeprom_info, wr);
		print_qsfp_br(eeprom_info, wr);

		print_qsfp_len(eeprom_info, SFF_8436_LEN_SMF_KM, "smf_km", wr);
		print_qsfp_len(eeprom_info, SFF_8436_LEN_OM1, "smf_om1", wr);
		print_qsfp_len(eeprom_info, SFF_8436_LEN_OM2, "smf_om2", wr);
		print_qsfp_len(eeprom_info, SFF_8436_LEN_OM3, "smf_om3", wr);
	}

	get_qsfp_device_tech(eeprom_info, &dev_tech);
	if (dev_tech < QSFP_DEV_TECH_COPPER_MIN) {

		/*
		 * The standards in this area are not clear when the
		 * additional measurements are present or not. Use a valid
		 * temperature reading as an indicator for the presence of
		 * voltage and TX/RX power measurements.
		 */
		print_qsfp_temp(eeprom_info, wr);
		print_qsfp_voltage(eeprom_info, wr);

		jsonw_name(wr, "measured_values");
		jsonw_start_array(wr);
		for (int i = 0; i < 4; i++) {
			jsonw_start_object(wr);
			jsonw_uint_field(wr, "channel", i+1);
			print_qsfp_rx_power(eeprom_info, wr, i);
			print_qsfp_tx_power(up, eeprom_info, wr, i);
			print_qsfp_laser_bias(eeprom_info, wr, i);
			jsonw_end_object(wr);
		}
		jsonw_end_array(wr);
		print_qsfp_aw_flags(eeprom_info, wr);
		print_qsfp_temp_aw_flags(eeprom_info, wr);
		print_qsfp_voltage_aw_flags(eeprom_info, wr);

		if (include_static)
			print_qsfp_thresholds(eeprom_info, wr);
	}

}


void
sfp_status(bool up, const struct rte_eth_dev_module_info *module_info,
	   const struct rte_dev_eeprom_info *eeprom_info,
	   bool include_static, json_writer_t *wr)
{
	uint8_t id_byte;

	/*
	 * Try to read byte 0:
	 * Both SFF-8472 and SFF-8436 use it as
	 * 'identification byte'.
	 * Stop reading status on zero as value -
	 * this might happen in case of empty transceiver slot.
	 */
	id_byte = 0;
	get_eeprom_data(eeprom_info, SFF_8472_BASE, SFF_8472_ID, 1,
			&id_byte);
	if (id_byte == 0)
		return;

	switch (id_byte) {
	case SFF_8024_ID_QSFP:
	case SFF_8024_ID_QSFPPLUS:
	case SFF_8024_ID_QSFP28:
		print_qsfp_status(up, eeprom_info, include_static, wr);
		break;
	default:
		print_sfp_status(up, module_info, eeprom_info, include_static, wr);
	}
}

static zsock_t *sfpd_notify_socket;

static void
sfp_save_eeprom_diag_status(struct xcvr_info *xcvr_info, uint16_t offset, uint8_t len)
{
	struct rte_dev_eeprom_info *eeprom_info;

	xcvr_info->offset = offset;
	xcvr_info->dyn_data_len = len;
	eeprom_info = &xcvr_info->eeprom_info;
	memcpy(xcvr_info->prev_dyn_data, eeprom_info->data + offset, len);
}

static void sfp_get_value(struct xcvr_info *xcvr_info __rte_unused,
			  enum SFF_8472_AW_FLAG flag __rte_unused,
			  char *val_str)
{
	val_str[0] = 0;
}

static void sfp_get_thr_value(struct xcvr_info *xcvr_info __rte_unused,
			      enum SFF_8472_AW_FLAG flag __rte_unused,
			      bool alarm __rte_unused,
			      char *thr_str)
{
	thr_str[0] = 0;
}

static void sfp_process_aw_flag_change(struct ifnet *ifp, struct xcvr_info *xcvr_info,
				       uint16_t old_flags, uint16_t new_flags, bool alarm)
{
	struct _nv_ext *x;
	char val_str[20], thr_str[20];
	uint16_t flag;
	char *aw_str = (alarm ? "alarm" : "warning");

	for (x = aw_flags; x->n != NULL; x++) {
		flag = 1 << x->v;
		if ((old_flags & flag) == (new_flags & flag))
			continue;

		sfp_get_value(xcvr_info, x->v, val_str);
		sfp_get_thr_value(xcvr_info, x->v, alarm, thr_str);
		RTE_LOG(ERR, SFP_MON,
			"%s %s %s on %s. Current value = %s, %s %s threshold = %s\n",
			x->l, aw_str, ((new_flags & flag) ? "detected" : "cleared"),
			ifp->if_name, val_str, x->l, aw_str, thr_str);
	}
}

static void
sfp_log_aw_status_change(struct ifnet *ifp, struct xcvr_info *xcvr_info)
{
#define SFF_8472_AW_FLAGS_LEN 6

	uint8_t *old_aw_flags = xcvr_info->prev_dyn_data +
		(SFF_8472_DIAG_OFFSET + SFF_8472_ALARM_FLAGS - xcvr_info->offset);
	uint8_t *new_aw_flags = (uint8_t *)xcvr_info->eeprom_info.data +
		SFF_8472_DIAG_OFFSET + SFF_8472_ALARM_FLAGS;
	uint16_t old_flags, new_flags, warn_offset;

	if (!memcmp(old_aw_flags, new_aw_flags, SFF_8472_AW_FLAGS_LEN))
		return;

	/* process warning flags */
	warn_offset = SFF_8472_WARNING_FLAGS - SFF_8472_ALARM_FLAGS;
	old_flags = (uint16_t)((old_aw_flags[warn_offset] << 8) |
			       old_aw_flags[warn_offset + 1]);
	new_flags = (uint16_t)((new_aw_flags[warn_offset] << 8) |
				new_aw_flags[warn_offset + 1]);
	DP_DEBUG(SFP_MON, DEBUG, DATAPLANE,
		 "%s: old_warn_flags = 0x%x, new_warn_flags = 0x%x\n",
		 ifp->if_name, old_flags, new_flags);

	sfp_process_aw_flag_change(ifp, xcvr_info, old_flags, new_flags, false);

	/* process alarm flags */
	old_flags = (uint16_t)((old_aw_flags[0] << 8) | old_aw_flags[1]);
	new_flags = (uint16_t)((new_aw_flags[0] << 8) | new_aw_flags[1]);
	DP_DEBUG(SFP_MON, DEBUG, DATAPLANE,
		 "%s: old_alarm_flags = 0x%x, new_alarm_flags = 0x%x\n",
		 ifp->if_name, old_flags, new_flags);
	sfp_process_aw_flag_change(ifp, xcvr_info, old_flags, new_flags, true);
}

static void
sfp_qsfp_log_aw_status_change(struct ifnet *ifp, struct xcvr_info *xcvr_info)
{
	DP_DEBUG(SFP_MON, DEBUG, DATAPLANE,
		 "Logging SFP status change for %s, module_type = %d, offset = %d\n",
		 ifp->if_name, xcvr_info->module_info.type, xcvr_info->offset);

	switch (xcvr_info->module_info.type) {
	case RTE_ETH_MODULE_SFF_8472:
		if (xcvr_info->offset < SFF_8472_DIAG_OFFSET)
			return;
		sfp_log_aw_status_change(ifp, xcvr_info);
		break;
	}
}

static void
sfpd_process_notify_msg(SFPStatusList *sfp_msg)
{
	SFPStatusList__SFP *sfp;
	struct ifnet *ifp;
	struct dpdk_eth_if_softc *sc;
	struct rte_dev_eeprom_info *eeprom_info;
	SFPStatusList__EEPROMData *data;

	for (size_t i = 0; i < sfp_msg->n_sfp; i++) {
		sfp = sfp_msg->sfp[i];
		ifp = dp_ifnet_byifname(sfp->name);
		if (!ifp || ifp->if_type != IFT_ETHER) {
			DP_DEBUG(SFP_MON, DEBUG, DATAPLANE,
				 "Could not find ethernet interface with name %s\n",
				 sfp->name);
			continue;
		}

		sc = rcu_dereference(ifp->if_softc);
		if (!sc)
			continue;

		/* if first time, get full EEPROM contents */
		if (!sc->xcvr_info.eeprom_info.length)
			if (dpdk_eth_if_get_xcvr_info(ifp))
				continue;

		/* copy current values of EEPROM dynamic fields from message */
		eeprom_info = &sc->xcvr_info.eeprom_info;

		/*
		 * pick just the first element. Add support for multiple
		 * blocks later if needed
		 */
		data = sfp->data[0];
		if (!data->has_offset || !data->has_length || !data->has_data) {
			DP_DEBUG(SFP_MON, DEBUG, DATAPLANE,
				 "Status msg for %s missing offset (%u) or length (%u)"
				 " or data (%u)\n", ifp->if_name, data->has_offset,
				 data->has_length, data->has_data);
			continue;
		}

		if ((data->offset + data->length) > eeprom_info->length) {
			DP_DEBUG(SFP_MON, DEBUG, DATAPLANE,
				 "Invalid EEPROM offset (%d) or length (%d) rcvd for %s\n",
				 data->offset, data->length, ifp->if_name);
			continue;
		}

		DP_DEBUG(SFP_MON, DEBUG, DATAPLANE,
			 "EEPROM values (offset %d, length %d) being saved for %s\n",
			 data->offset, data->length, ifp->if_name);

		/* save previous values of EEPROM dynamic fields */
		sfp_save_eeprom_diag_status(&sc->xcvr_info, data->offset, data->length);

		/* store current values in EEPROM data block */
		memcpy(eeprom_info->data + data->offset, data->data.data, data->length);

		/* emit logs if necessary */
		sfp_qsfp_log_aw_status_change(ifp, &sc->xcvr_info);
	}
}

static int
sfpd_msg_recv(zsock_t *sock, zmq_msg_t *hdr, zmq_msg_t *msg)
{
	int more;

	zmq_msg_init(hdr);
	zmq_msg_init(msg);

	if (zmq_msg_recv(hdr, zsock_resolve(sock), 0) <= 0)
		goto error;

	if (!zmq_msg_get(hdr, ZMQ_MORE))
		return 0;

	if (zmq_msg_recv(msg, zsock_resolve(sock), 0) <= 0)
		goto error;

	more = zmq_msg_get(msg, ZMQ_MORE);
	while (more) {
		zmq_msg_t sink;
		zmq_msg_init(&sink);
		zmq_msg_recv(&sink, zsock_resolve(sock), 0);
		more = zmq_msg_get(&sink, ZMQ_MORE);
		zmq_msg_close(&sink);
	}

	return 0;

error:
	zmq_msg_close(msg);
	zmq_msg_close(hdr);
	return -1;
}

static int sfpd_notify_recv(void *arg)
{
	zmq_msg_t sfpd_msg, sfpd_hdr;
	zsock_t *sock = arg;
	const char *hdr, *data, *status_msg_hdr;
	uint32_t len;
	int rc;
	errno = 0;
	status_msg_hdr = "SFPDSTATUS_MSG";

	DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
		 "SFPd: Notification\n");

	rc = sfpd_msg_recv(sock, &sfpd_hdr, &sfpd_msg);

	if (rc != 0) {
		/* If the sfpd_msg_recv call failed it is possible for
		 * errno to be set and so we need to clear it.
		 */
		if (errno == 0)
			return 0;
		return -1;
	}

	hdr = zmq_msg_data(&sfpd_hdr);

	if (strncmp("SFP_PRESENCE_NOTIFY", hdr, strlen("SFP_PRESENCE_NOTIFY")) == 0) {
		DP_DEBUG(SFP_LIST, DEBUG, DATAPLANE,
			 "SFPd: SFPD msg SFP_PRESENCE_NOTIFY: %s\n", __func__);
		sfpd_process_presence_update();
		goto end;
	}

	if (strncmp("SFPDSTATUS_NOTIFY", hdr, strlen("SFPDSTATUS_NOTIFY")) == 0) {
		zmq_setsockopt(sock, ZMQ_SUBSCRIBE, status_msg_hdr, strlen(status_msg_hdr));

		rc = sfpd_msg_recv(sock, &sfpd_hdr, &sfpd_msg);

		if (rc != 0) {
			zmq_msg_close(&sfpd_hdr);
			return -1;
		}

		hdr = zmq_msg_data(&sfpd_hdr);

		if (strncmp(status_msg_hdr, hdr, strlen(status_msg_hdr)) == 0) {
			data = zmq_msg_data(&sfpd_msg);
			len = zmq_msg_size(&sfpd_msg);

			SFPStatusList *sfp_msg =
				sfpstatus_list__unpack(NULL, len, (uint8_t *) data);

			sfpd_process_notify_msg(sfp_msg);

			RTE_LOG(INFO, DATAPLANE,
				"SFPd: SFPDSTATUS_NOTIFY data:%p len:%d\n",
				data, len);
		}

		goto end;
	}

	RTE_LOG(ERR, DATAPLANE,
		"SFPd: SFPD unknwown msg received: %s\n", hdr);

end:
	zmq_msg_close(&sfpd_hdr);
	zmq_msg_close(&sfpd_msg);

	return 0;
}

static void sfpd_close_socket(void)
{
	if (sfpd_notify_socket) {
		zsock_destroy(&sfpd_notify_socket);
		sfpd_notify_socket = NULL;
	}
}

int sfpd_open_socket(void)
{
	if (sfpd_notify_socket)
		return -1;

	errno = 0;
	sfpd_notify_socket = zsock_new_sub(config.sfpd_status_upd_url, "");
	if (!sfpd_notify_socket) {
		RTE_LOG(ERR, DATAPLANE,
			"SFP:Failed to open socket errno %d sfpd notify socket %s\n",
			errno, config.sfpd_status_upd_url);
		return -1;
	}

	dp_register_event_socket(
		zsock_resolve(sfpd_notify_socket),
		sfpd_notify_recv,
		sfpd_notify_socket);

	return 0;
}

void sfpd_unsubscribe(void)
{
	if (sfpd_notify_socket)
		dp_unregister_event_socket(
			zsock_resolve(sfpd_notify_socket));

	sfpd_close_socket();
}

#define SFPD_REP_SOCKET "ipc:///var/run/vyatta/sfp_rep.socket"

static int
sfpd_command(const char *format, ...)
	__attribute__ ((__format__(__printf__, 1, 2)));
static int
sfpd_command(const char *format, ...)
{
	int ret;
	va_list ap;
	zsock_t *req;
	char *command;
	char *str;

	va_start(ap, format);
	ret = vasprintf(&command, format, ap);
	va_end(ap);
	if (ret < 0)
		return -ENOMEM;

	req = zsock_new_req(SFPD_REP_SOCKET);
	if (!req) {
		RTE_LOG(ERR, DATAPLANE,
			"unable to create SFP request socket\n");
		ret = -ENOMEM;
		goto exit;
	}

	if (zstr_send(req, command) < 0) {
		RTE_LOG(ERR, DATAPLANE, "unable to send SFP command\n");
		ret = -ECONNREFUSED;
		goto exit;
	}

	do {
		str = zstr_recv(req);
	} while (!str && errno == EINTR && !zsys_interrupted);

	if (str) {
		if (strcmp(str, "{\"result\":\"OK\"}") != 0)
			RTE_LOG(ERR, DATAPLANE,
				"unexpected response: %s to command %s\n",
				str, command);
		free(str);
	}

exit:
	zsock_destroy(&req);
	free(command);
	return ret;
}

static int
cmd_sfp_monitor_cfg(struct pb_msg *msg)
{
	int ret = 0;
	SfpMonitorCfg *sfp_msg =
	       sfp_monitor_cfg__unpack(NULL, msg->msg_len, msg->msg);

	if (!sfp_msg->has_interval) {
		ret = -EINVAL;
		goto done;
	}

	ret = sfpd_command(
		"{"
		"    \"command\": \"SFPMONITORINTERVAL\","
		"    \"value\": \"%u\""
		"}", sfp_msg->interval);

done:
	sfp_monitor_cfg__free_unpacked(sfp_msg, NULL);

	return ret;
}

PB_REGISTER_CMD(sfp_monitor_cmd) = {
	.cmd = "vyatta:sfpmonitor",
	.handler = cmd_sfp_monitor_cfg,
};

static bool
cmd_intf_sfp_status(struct ifnet *ifp, void *arg)
{
	struct dpdk_eth_if_softc *sc;
	json_writer_t *wr = arg;
	int rv;
	uint8_t diag_type = 0;

	sc = rcu_dereference(ifp->if_softc);
	if (!sc)
		return false;

	rv = dpdk_eth_if_get_xcvr_info(ifp);
	if (rv)
		return false;

	switch (sc->xcvr_info.module_info.type) {
	case RTE_ETH_MODULE_SFF_8472:
		/* Read diagnostic monitoring type */
		if (get_eeprom_data(&sc->xcvr_info.eeprom_info, SFF_8472_BASE,
				    SFF_8472_DIAG_TYPE, 1, &diag_type))
			return false;

		/*
		 * Read monitoring data IFF it is supplied
		 */
		if (!(diag_type & SFF_8472_DDM_DONE))
			return false;

		break;

	case RTE_ETH_MODULE_SFF_8436:
	case RTE_ETH_MODULE_SFF_8636:
		/* Some monitoring flags always present */
		break;

	default:
		return false;
	}

	jsonw_start_object(wr);

	jsonw_string_field(wr, "name", ifp->if_name);
	dpdk_eth_if_show_xcvr_info(ifp, false, wr);

	jsonw_end_object(wr);

	return false;
}

static void cmd_sfp_status(json_writer_t *wr, char *ifname)
{
	struct ifnet *ifp;

	jsonw_name(wr, "sfp_status");
	jsonw_start_array(wr);
	if (ifname) {
		ifp = dp_ifnet_byifname(ifname);
		if (!ifp)
			return;

		cmd_intf_sfp_status(ifp, wr);
	} else
		dpdk_eth_if_walk(cmd_intf_sfp_status, wr);

	jsonw_end_array(wr);
}

int cmd_sfp_monitor_op(FILE *f, int argc, char *argv[])
{
	json_writer_t *wr;
	char *ifname = NULL;
	int ret = 0;

	if (f == NULL)
		f = stderr;

	wr = jsonw_new(f);
	if (!wr)
		return -ENOMEM;

	if (argc > 3 || argc < 2) {
		ret = -EINVAL;
		goto done;
	}

	if (!strcmp(argv[1], "show")) {
		if (argc == 3)
			ifname = argv[2];
		cmd_sfp_status(wr, ifname);
	} else
		ret = -EINVAL;

done:
	if (ret)
		fprintf(f, "Usage: sfp-monitor show [ <ifname> ]");
	jsonw_destroy(&wr);
	return ret;
}
