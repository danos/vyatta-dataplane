/*
 * Simple streaming JSON writer
 *
 * This takes care of the annoying bits of JSON syntax like the commas
 * after elements
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef VYATTA_DATAPLANE_JSON_WRITER_H
#define VYATTA_DATAPLANE_JSON_WRITER_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/* Opaque class structure */
typedef struct json_writer json_writer_t;

/* Create a new JSON stream */
json_writer_t *jsonw_new(FILE *f);

/* End output to JSON stream */
void jsonw_destroy(json_writer_t **self_p);

/* Cause output to have pretty whitespace */
void jsonw_pretty(json_writer_t *self, bool on);

/* Add property name */
void jsonw_name(json_writer_t *self, const char *name);

/* Add value  */
void jsonw_string(json_writer_t *self, const char *value);
void jsonw_bool(json_writer_t *self, bool value);
void jsonw_float(json_writer_t *self, double number);
void jsonw_uint(json_writer_t *self, uint64_t number);
void jsonw_int(json_writer_t *self, int64_t number);
void jsonw_null(json_writer_t *self);

/* Useful Combinations of name and value */
void jsonw_string_field(json_writer_t *self, const char *prop, const char *val);
void jsonw_bool_field(json_writer_t *self, const char *prop, bool value);
void jsonw_float_field(json_writer_t *self, const char *prop, double num);
void jsonw_uint_field(json_writer_t *self, const char *prop, uint64_t num);
void jsonw_int_field(json_writer_t *self, const char *prop, int64_t num);
void jsonw_null_field(json_writer_t *self, const char *prop);

/* Collections */
void jsonw_start_object(json_writer_t *self);
void jsonw_end_object(json_writer_t *self);

void jsonw_start_array(json_writer_t *self);
void jsonw_end_array(json_writer_t *self);

/* Override default exception handling */
typedef void (jsonw_err_handler_fn)(const char *);

#endif /* VYATTA_DATAPLANE_JSON_WRITER_H */
