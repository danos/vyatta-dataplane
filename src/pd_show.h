/*
 * Copyright (c) 2018, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef PD_SHOW_H
#define PD_SHOW_H


#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

enum pd_obj_state {
	/* object is fully programmed in HW. Success */
	PD_OBJ_STATE_FULL,
	/* object is partially programmed in HW. */
	PD_OBJ_STATE_PARTIAL,
	/* object was not programmed in HW due to lack of resource. */
	PD_OBJ_STATE_NO_RESOURCE,
	/* object was not programmed in HW due to lack of support in SW or HW */
	PD_OBJ_STATE_NO_SUPPORT,
	/* object was not programmed in HW as it is not needed there. */
	PD_OBJ_STATE_NOT_NEEDED,
	/* object was not programmed in HW due to an error */
	PD_OBJ_STATE_ERROR,
	PD_OBJ_STATE_LAST,
};

struct pd_obj_state_and_flags {
	/* object has successfully been programmed in HW */
	uint16_t created : 1;
	uint16_t unused  : 15;
	enum pd_obj_state state : 16;
};

/* pd show dataplane */
int cmd_pd(FILE *f, int argc, char **argv);

enum pd_obj_state fal_state_to_pd_state(int fal_state);
#endif /* PD_SHOW_H */
