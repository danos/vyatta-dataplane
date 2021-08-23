/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _CGN_DIR_H_
#define _CGN_DIR_H_

/*
 * Packet direction relative to interface with cgnat policy.  Note that this
 * is 1 byte in 'struct cgn_sess2'.
 */
enum cgn_dir {
	CGN_DIR_IN = 0,
	CGN_DIR_OUT = 1
} __attribute__ ((__packed__));

#define CGN_DIR_SZ 2

static inline enum cgn_dir cgn_reverse_dir(enum cgn_dir dir)
{
	return (dir == CGN_DIR_OUT) ? CGN_DIR_IN : CGN_DIR_OUT;
}

static inline const char *cgn_dir_str(enum cgn_dir dir)
{
	switch (dir) {
	case CGN_DIR_OUT:
		return "OUT";
	case CGN_DIR_IN:
		return "IN";
	};
	return "???";
}

#endif /* CGN_DIR_H */
