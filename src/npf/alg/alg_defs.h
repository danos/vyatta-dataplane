/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _ALG_DEFS_H_
#define _ALG_DEFS_H_

/* ALG ID */
enum npf_alg_id {
	NPF_ALG_ID_FTP = 1,
	NPF_ALG_ID_TFTP,
	NPF_ALG_ID_RPC,
	NPF_ALG_ID_SIP,
};

#define NPF_ALG_ID_FIRST  NPF_ALG_ID_FTP
#define NPF_ALG_ID_LAST   NPF_ALG_ID_SIP
#define NPF_ALG_ID_SZ    (NPF_ALG_ID_LAST + 1)

/* ALG config ops */
enum alg_config_op {
	NPF_ALG_CONFIG_SET = 1,
	NPF_ALG_CONFIG_DELETE,
	NPF_ALG_CONFIG_ENABLE,
	NPF_ALG_CONFIG_DISABLE,
};

#define NPF_ALG_CONFIG_FIRST  NPF_ALG_CONFIG_SET
#define NPF_ALG_CONFIG_LAST   NPF_ALG_CONFIG_DISABLE
#define NPF_ALG_CONFIG_SZ    (NPF_ALG_CONFIG_LAST + 1)

#endif /* _ALG_DEFS_H_ */
