/*-
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef CRYPTO_DEFS_H

#define CRYPTO_DEFS_H

/* maximum length (in bytes) of initialization vector in any algorithm */
#define CRYPTO_MAX_IV_LENGTH 16

/* maximum length (in bytes) of key in any algorithm */
#define CRYPTO_MAX_KEY_LENGTH 32

/*
 * constants for various encryption/hash algorithms
 */

#define AES_GCM_AAD_LENGTH    8   /* no ESN support yet */
#define AES_GCM_IV_LENGTH     8
#define AES_GCM_NONCE_LENGTH  4

/* iv sizes for different algorithms */
enum {
	IPSEC_AES_CBC_IV_SIZE = 16,
	IPSEC_AES_GCM_IV_SIZE = 12,
	/* TripleDES supports IV size of 32bits or 64bits but he library
	 * only supports 64bits.
	 */
	IPSEC_3DES_IV_SIZE = sizeof(uint64_t),
};

#endif
