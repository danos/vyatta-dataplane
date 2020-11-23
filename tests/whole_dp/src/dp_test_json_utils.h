/*
 * Copyright (c) 2018,2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _DP_TEST_JSON_UTILS_H_
#define _DP_TEST_JSON_UTILS_H_

#include <json-c/json.h>

struct dp_test_json_mismatches;

#define __JSON_ANY_KEY_VAL__ "__JSON_ANY_KEY_VAL__"

json_object *parse_json(const char *response_str, char *err_str,
			uint err_str_sz);

json_object
*dp_test_json_do_show_cmd(const char *request,
			  struct dp_test_json_mismatches **m_ret,
			  bool print);

bool dp_test_json_subset(json_object *obj1, json_object *obj2,
			 struct dp_test_json_mismatches **mm);

bool dp_test_json_superset(json_object *obj1, json_object *obj2,
			   struct dp_test_json_mismatches **mismatches);

bool dp_test_json_match(json_object *obj1, json_object *obj2,
			struct dp_test_json_mismatches **mismatches);

void dp_test_json_mismatch_free(struct dp_test_json_mismatches *m);

unsigned int dp_test_json_mismatch_print(struct dp_test_json_mismatches *m,
					 unsigned int indent,
					 char *buffer, unsigned int bufsz);

json_object *dp_test_json_val_in_array(json_object *array,
				       json_object *elem_subset);

void dp_test_json_filter(json_object *haystack, json_object *filter);

void
dp_test_json_mismatch_record(struct dp_test_json_mismatches **m_ptr,
			const char *field_name,
			struct dp_test_json_mismatches *sub_obj,
			const char *reason_fmt,
			...);

/*
 * Get the value of a named json_type_string that is contained in an
 * outer json_type_object.
 *
 * Returns true if successful, else false.
 *
 * A pointer to the string is written to 'val'.  The string memory is managed
 * by the json_object and will be freed when the reference count of the
 * json_object drops to zero.
 */
bool
dp_test_json_string_field_from_obj(json_object *jouter, const char *field,
				   const char **val);

/*
 * Get the value of a named json_type_int field that is contained in an
 * outer json_type_object.
 *
 * Returns true if successful, else false.  If successful, the integer is
 * written to '*val'.
 */
bool
dp_test_json_int_field_from_obj(json_object *jouter, const char *field,
				int *val);

/*
 * Get the value of a named json_type_boolean field that is contained in an
 * outer json_type_object.
 *
 * Returns true if successful, else false.  If successful, the boolean is
 * written to '*val'.
 */
bool
dp_test_json_boolean_field_from_obj(json_object *jouter, const char *field,
				    bool *val);

/*
 * json find utility
 *
 * Recursively search a json object or array for a specific object based on a
 * given set of keys.
 *
 * The returned json object has its ref count incremented, so json_object_put
 * should be called once the caller has finished with the object.
 *
 * Examples
 *
 * The following key may be used to get a specific interfaces tx_bytes object
 * from the json object returned from the command "ifconfig -a":
 *
 *	dp_test_json_find_key key[] = { {"interfaces", NULL},
 *					{"name", "dpT10"},
 *					{"statistics", NULL},
 *					{"tx_bytes", NULL}};
 *
 * key to find a specific firewall rule:
 *
 *      dp_test_json_find_key key[] = { {"config", NULL},
 *                                      {"firewall", NULL},
 *                                      {"groups", NULL},
 *                                      {"name", "FW1"},
 *                                      {"rules", NULL},
 *                                      {"10", NULL}};
 *
 * If a key and value are both specified then we use this to identify an object
 * only.  If this is the last key then return the containing object.  If its not
 * the last object, then continue search of containing object.
 *
 * For example, each element of the interfaces array has a "name" object and a
 * "statistics" object.  If the keys are:
 *
 *     {"interfaces", NULL}, {"name", "dpT10"}, {"statistics", NULL}
 *
 * then we will search the interfaces array for an element with "name" equal to
 * "dpT10".  Once found, then we look for a "statistics" object in that array
 * element.
 *
 * If we just want the array element for a specific interface then the following
 * key will return the object containing "name" "dpT10":
 *
 *     {"interfaces", NULL}, {"name", "dpT10"}
 */
struct dp_test_json_find_key {
	const char * const key;
	const char *val;
};

json_object *
dp_test_json_find(json_object *jobj, struct dp_test_json_find_key *key_list,
		  int nkeys);

/*
 * Iterate over all elements in a json array.  Callback function may return
 * true to terminate the iteration, in which case the current array element
 * is returned to the caller
 */
typedef bool (*dp_test_json_array_iterate_cb)(json_object *jvalue, void *arg);

json_object *
dp_test_json_array_iterate(json_object *jarray,
			   dp_test_json_array_iterate_cb cb, void *arg);

struct dp_test_json_search_key {
	const char * const key;
	const char *val;
	const int index;
};

json_object *
dp_test_json_search(json_object *jobj, struct dp_test_json_search_key *key_list,
		    int nkeys);

#endif /* _DP_TEST_JSON_UTILS_H_ */
