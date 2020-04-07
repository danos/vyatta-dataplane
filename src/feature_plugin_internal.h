/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef FEATURE_PLUGIN_INTERNAL_H
#define FEATURE_PLUGIN_INTERNAL_H

void feature_load_plugins(void);
void feature_unload_plugins(void);

int cmd_feat_plugin(FILE *f, int argc, char **argv);

void feature_unregister_all_string_op_handlers(void);
void feature_unregister_all_string_cfg_handlers(void);

void set_feat_plugin_dir(const char *filename);

#endif /*  FEATURE_PLUGIN_INTERNAL_H */

