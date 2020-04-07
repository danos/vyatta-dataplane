/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef VYATTA_DATAPLANE_CONFIG_H
#define VYATTA_DATAPLANE_CONFIG_H

/*
 * Callback from config parser, in inih lib format for each name value.
 *
 * @param[in, out] arg Argument passed through from the call to
 *                     dp_parse_config_files().
 * @param[in] section  The section with in the config file that the given
 *                     name is in.
 * @param[in] name     The name of the field within the config file.
 * @param[in] value    The value for the given field.
 *
 * @return 0 if an error
 * @return 1 if success.
 */
typedef int (dp_parse_config_fn)(void *arg, const char *section,
				 const char *name, const char *value);

/*
 * Walk through the config files with a user provided parse function. This
 * allows plugins to have access to the config files, without the core
 * dataplane code needing to understand every line in the config file.
 *
 * @param[in] fn       The callback function to call for each line in the
 *                     config file.
 * @param[in, out] arg Argument passed through to the callback function
 *
 * @return 0 on success
 * @return -ve for failure
 */
int dp_parse_config_files(dp_parse_config_fn *fn,
			  void *arg);

#endif /* VYATTA_DATAPLANE_CONFIG_H */
