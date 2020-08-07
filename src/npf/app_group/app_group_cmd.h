/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef APP_GROUP_CMD_H
#define APP_GROUP_CMD_H

/**
 * Add a new application resource group from the given params
 *
 * @param name Application resource group to modify.
 * @param args arguments to parse.
 * @return -ENOMEM if cannot allocate space,
 *         -EINVAL if params doesn't match the required structure,
 *         or 0 on success.
 *
 * Arg structure:
 *
 * args   := apps;protos;types
 *
 * apps   := app | app,...,app
 * app    := engine:app_name
 *
 * protos := proto | proto,...,proto
 * proto  := engine:proto_name
 *
 * types  := type | type,...,type
 * type   := engine:type_name
 *
 * e.g. ndpi:facebook,user:chat_app;ndpi:web;ndpi:chat,user:chat
 *
 */
int app_group_add(char *name, char *args);

/**
 * Delete the application resource group with the given name.
 *
 * @param name name of group
 * @return true on success, false otherwise (i.e. no group found).
 */
bool app_group_del(char *name);

#endif /* APP_GROUP_CMD_H */
