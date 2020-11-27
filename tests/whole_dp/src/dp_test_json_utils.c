/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Json utilities built on top of libjson.
 * Various functions to
 *   - create json objects (from show cmds & arbitrary text)
 *   - compare json objects (exact, subset, superset)
 *
 */

#include <libmnl/libmnl.h>
#include <fnmatch.h>

#include <syslog.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_lib_internal.h"
#include "dp_test_controller.h"
#include "dp_test_console.h"

#include "dp_test_json_utils.h"

/*
 * fwd decl
 */
static bool
json_val_subset(json_object *value1, json_object *value2,
		const char *key,
		struct dp_test_json_mismatches **mismatches);

/*
 * Parse for 'response_str' textual representation and return a json
 * object if successful. On failure return NULL and an error string.
 */
json_object *
parse_json(const char *response_str, char *err_str, uint err_str_sz)
{
	json_object *response_obj = NULL;
	enum json_tokener_error jerr;
	json_tokener *tokener;
	int response_str_len;

	if (!response_str) {
		snprintf(err_str, err_str_sz,
			 "NULL response string");
		return NULL;
	}

	response_str_len = strlen(response_str);
	if (response_str_len == 0) {
		snprintf(err_str, err_str_sz,
			 "Zero length response string");
		return NULL;
	}

	tokener = json_tokener_new();
	response_obj = json_tokener_parse_ex(tokener,
					     response_str, response_str_len);

	jerr = json_tokener_get_error(tokener);
	if (jerr != json_tokener_success)
		snprintf(err_str, err_str_sz,
			 "Json tokener error: %s parsing '%s'",
			 json_tokener_error_desc(jerr),
			 response_str);
	json_tokener_free(tokener);
	return response_obj;
}

#define DP_TEST_JSON_MISMATCH_STR_SZ 100
struct dp_test_json_mismatch {
	char field_name[DP_TEST_JSON_MISMATCH_STR_SZ];
	char reason[DP_TEST_JSON_MISMATCH_STR_SZ];
	struct dp_test_json_mismatches *sub_obj_matches;
};

#define DP_TEST_JSON_MISMATCH_SZ 100
struct dp_test_json_mismatches {
	bool global_err;
	char global_err_str[DP_TEST_JSON_MISMATCH_STR_SZ];
	int num;
	struct dp_test_json_mismatch entry[DP_TEST_JSON_MISMATCH_SZ];
};

static void
mismatch_init(struct dp_test_json_mismatches *m)
{
	m->global_err = false;
	m->num = 0;
}

static struct dp_test_json_mismatches *
mismatch_new(void)
{
	struct dp_test_json_mismatches *m;

	m = malloc(sizeof(struct dp_test_json_mismatches));
	assert(m);

	mismatch_init(m);
	return m;
}

void
dp_test_json_mismatch_free(struct dp_test_json_mismatches *m)
{
	struct dp_test_json_mismatch *entry;
	int i;

	/*
	 * As a convenience allow funcs to call free w/o checking whether any
	 * mismatch has been allocated.
	 */
	if (!m)
		return;
	for (i = 0; i < m->num; i++) {
		entry = &m->entry[i];
		if (entry->sub_obj_matches)
			dp_test_json_mismatch_free(entry->sub_obj_matches);
	}
	free(m);
}

__attribute__((format(printf, 2, 3)))
static void
mismatch_glob_err_record(struct dp_test_json_mismatches **m_ptr,
			 const char *err_fmt, ...)
{
	struct dp_test_json_mismatches *m;
	va_list aptr;

	va_start(aptr, err_fmt);
	m = *m_ptr;
	if (!m) {
		/*
		 * Create and return a mismatch if this is the first one
		 * reported
		 */
		m = mismatch_new();
		*m_ptr = m;
	}
	vsnprintf(m->global_err_str, sizeof(m->global_err_str),
		  err_fmt, aptr);

	m->global_err = true;
	va_end(aptr);
}

__attribute__((format(printf, 4, 5)))
void
dp_test_json_mismatch_record(struct dp_test_json_mismatches **m_ptr,
			const char *field_name,
			struct dp_test_json_mismatches *sub_obj,
			const char *reason_fmt,
			...)
{
	struct dp_test_json_mismatch *entry;
	struct dp_test_json_mismatches *m;
	va_list aptr;

	va_start(aptr, reason_fmt);
	m = *m_ptr;
	if (!m) {
		/*
		 * Create and return a mismatch if this is the first one
		 * reported
		 */
		m = mismatch_new();
		*m_ptr = m;
	}

	if (m->num >= DP_TEST_JSON_MISMATCH_SZ) {
		va_end(aptr);
		return;
	}

	entry = &m->entry[m->num++];

	/*
	 * yes, yes but its more portable, perf doesn't matter here
	 * and a truncated string will be better than nothing.
	 */
	strncpy(entry->field_name, field_name, DP_TEST_JSON_MISMATCH_STR_SZ);
	entry->field_name[DP_TEST_JSON_MISMATCH_STR_SZ - 1] = '\0';

	vsnprintf(entry->reason, sizeof(entry->reason), reason_fmt, aptr);

	entry->sub_obj_matches = sub_obj;
	va_end(aptr);
}

/*
 * print a mismatch structure,
 * indent is number of spaces to indent each line by
 * buffer,bufsz describe buffer to write to (if buffer is NULL uses stdio)
 * returns number of chars written.
 */
unsigned int
dp_test_json_mismatch_print (struct dp_test_json_mismatches *m,
			     unsigned int indent,
			     char *buffer, unsigned int bufsz)
{
	struct dp_test_json_mismatch *entry;
	int i, written;

	written = 0;
	if (m->global_err) {
		if (buffer)
			written += spush(buffer + written, bufsz - written,
					 "\n%*s%s", indent, " ",
					 m->global_err_str);
		else
			written += printf("\n%*s%s", indent, " ",
					 m->global_err_str);
	}

	for (i = 0; i < m->num; i++) {
		entry = &m->entry[i];
		if (buffer)
			written += spush(buffer + written, bufsz - written,
					    "\n%*s%s - %s", indent, " ",
					    entry->field_name, entry->reason);
		else
			written += printf("\n%*s%s - %s", indent, " ",
					  entry->field_name, entry->reason);
		if (entry->sub_obj_matches)
			dp_test_json_mismatch_print(entry->sub_obj_matches,
						    indent + 2,
						    buffer ?
						    buffer + written : NULL,
						    buffer ?
						    bufsz - written : 0);
	}
	return written;
}

/*
 * Do a show command using the request string, wait for a response and
 * parse the response as json to return a json_object * or NULL.
 */
json_object *
dp_test_json_do_show_cmd(const char *request,
			 struct dp_test_json_mismatches **m_ret, bool print)
{
	char parse_err_str[10000];
	char *response_str;
	json_object *jobj;
	bool err;

	response_str = dp_test_console_request_w_err(request, &err, print);
	if (!response_str) {
		mismatch_glob_err_record(m_ret,
					 "Empty response received");
		jobj = NULL;
	} else if (err) {
		mismatch_glob_err_record(m_ret,
					 "Error response received");
		jobj = NULL;
	} else {
		jobj = parse_json(response_str, parse_err_str,
				  sizeof(parse_err_str));
		if (!jobj)
			mismatch_glob_err_record(m_ret,
						 "JSON parse error '%s'",
						 parse_err_str);
	}
	free(response_str);
	return jobj;
}

/*
 * helper func to find a field name in a list of names
 */
static bool
key_in_keys_to_copy(const char *key,
		    const int num_keys_to_copy,
		    const char * const *keys_to_copy)
{
	int i;
	/* treat the absence of a list of keys as a match all */
	if ((!keys_to_copy) || (num_keys_to_copy == 0))
		return true;

	for (i = 0; i < num_keys_to_copy; i++) {
		if (keys_to_copy[i] &&
		    strcmp(key, keys_to_copy[i]) == 0)
			return true;
	}
	return false;
}

/*
 * Make a partial (shallow) copy of a json object. The new object will
 * only contains the fields in the list 'keys_to_copy' unless it is empty
 * in which case all fields will be copied.
 *
 * It's a shallow copy so both objects share the same subobjects but
 * the refcounts on these reflect that fact.
 */
static json_object *
json_object_copy(json_object *source, const int num_keys_to_copy,
		 const char * const *keys_to_copy)
{
	json_object *new_obj;

	assert(json_object_get_type(source) == json_type_object);

	new_obj = json_object_new_object();
	json_object_object_foreach(source, key, value1) {
		if (key_in_keys_to_copy(key, num_keys_to_copy, keys_to_copy))
			json_object_object_add(new_obj, key,
					       json_object_get(value1));
	}
	return new_obj;
}

/*
 * Find a subset-match for a json object in an array/list.
 * (Json treats lists as arrays - we call them lists here
 * because typically that's what they map to in the
 * implementation code).
 */
static json_object *
json_val_in_list(json_object *list, json_object *elem_subset)
{
	struct dp_test_json_mismatches *mismatches_unused = NULL;
	int len, i;

	assert(json_object_get_type(list) == json_type_array);

	len = json_object_array_length(list);

	for (i = 0; i < len; i++) {
		if (json_val_subset(elem_subset,
				    json_object_array_get_idx(list, i),
				    "unused",
				    &mismatches_unused)) {
			return json_object_array_get_idx(list, i);
		}
		dp_test_json_mismatch_free(mismatches_unused);
		mismatches_unused = NULL;
	}
	return NULL;
}

static void
compare_lists(const char *key, json_object *subset_list, json_object *list2,
	      struct dp_test_json_mismatches **mismatches)
{
	static const char * const route_key_fields[] = { "prefix", "scope" };
	static const char * const nh_key_fields[] = { "state",
						      "via", "ifname",
						      "labels" };
	static const char * const if_key_fields[] = { "name", "cont_src" };
	static const char * const labelspace_key_fields[] = { "lblspc" };
	static const char * const arp_key_fields[] = { "ip", "ifname"};
	static const char * const mpls_route_key_fields[] = { "address" };
	static const char * const vrf_key_fields[] = { "vrf_id"};

	int subset_list_len = json_object_array_length(subset_list);
	json_object *match_elem, *same_key_elem, *elem_key;
	char key_str[100];
	int i;

	for (i = 0; i < subset_list_len; i++) {
		match_elem = json_object_array_get_idx(subset_list, i);
		/*
		 * Now for special flavours of array we know which attributes
		 * form the 'identity' of the entries so we can compare entries
		 * with identity and report mismatches in the rest of the attrs
		 * instead of just trying to find entries where all the attrs
		 * match.
		 */
		if (strcmp(key, "next_hop") == 0) {
			elem_key =
				json_object_copy(match_elem,
						 (sizeof(nh_key_fields) /
						  sizeof(nh_key_fields[0])),
						 nh_key_fields);

		} else if (strcmp(key, "route_show") == 0) {
			elem_key =
			  json_object_copy(match_elem,
					   (sizeof(route_key_fields) /
					    sizeof(route_key_fields[0])),
					   route_key_fields);
		} else if (strcmp(key, "interfaces") == 0) {
			elem_key =
			  json_object_copy(match_elem,
					   (sizeof(if_key_fields) /
					    sizeof(if_key_fields[0])),
					   if_key_fields);
		} else if (strcmp(key, "labelspaces") == 0) {
			elem_key =
			  json_object_copy(match_elem,
					   (sizeof(labelspace_key_fields) /
					    sizeof(labelspace_key_fields[0])),
					   labelspace_key_fields);
		} else if (strcmp(key, "mpls_route") == 0) {
			elem_key =
			  json_object_copy(match_elem,
					   (sizeof(mpls_route_key_fields) /
					    sizeof(mpls_route_key_fields[0])),
					   mpls_route_key_fields);
		} else if (strcmp(key, "arp") == 0) {
			elem_key =
			  json_object_copy(match_elem,
					   (sizeof(arp_key_fields) /
					    sizeof(arp_key_fields[0])),
					   arp_key_fields);
		} else if (strcmp(key, "vrf_table") == 0) {
			elem_key =
			  json_object_copy(match_elem,
					   (sizeof(vrf_key_fields) /
					    sizeof(vrf_key_fields[0])),
					   vrf_key_fields);
		} else {
			/* otherwise the key is the complete thing to match */
			elem_key = json_object_get(match_elem);
		}
		snprintf(key_str, sizeof(key_str), "%s[%d (=%s)]", key,
			 i, json_object_to_json_string(elem_key));

		same_key_elem =
			json_val_in_list(list2, elem_key);
		if (!same_key_elem)
			dp_test_json_mismatch_record(mismatches, key_str, NULL,
						     "missing");
		else
			json_val_subset(match_elem,
					same_key_elem,
					key_str,
					mismatches);
		json_object_put(elem_key);
	}
}

/*
 * Compare two json values and create/update a mismatches record accordingly.
 */
static bool
json_val_subset(json_object *value1, json_object *value2,
		const char *key,
		struct dp_test_json_mismatches **mismatches)
{
	struct dp_test_json_mismatches *subobj_mismatch = NULL;
	enum json_type type1, type2;

	if (!value1)
		return true;

	if (!value2) {
		dp_test_json_mismatch_record(mismatches, key, NULL,
					     "-- missing");
		return false;
	}
	/*
	 * Field appears in obj1 and obj2 -
	 * compare type and values.
	 */
	type1 = json_object_get_type(value1);
	type2 = json_object_get_type(value2);
	if (type1 != type2) {
		/*
		 * same field name but wrong type
		 */
		dp_test_json_mismatch_record(mismatches, key, NULL,
					     "type mismatch %s != %s",
					     json_type_to_name(type1),
					     json_type_to_name(type2));
	}
	/*
	 * compare the values
	 */
	switch (type1) {
	case json_type_boolean:
		if (json_object_get_boolean(value1) !=
		    json_object_get_boolean(value2)) {
			dp_test_json_mismatch_record(
				mismatches, key, NULL,
				"%s != %s",
				json_object_get_boolean(value1) ?
				"true" : "false",
				json_object_get_boolean(value2) ?
				"true" : "false");
		}
		break;
	case json_type_double:
		if (json_object_get_double(value1) !=
		    json_object_get_double(value2)) {
			dp_test_json_mismatch_record(
				mismatches, key, NULL,
				"%f != %f",
				json_object_get_double(value1),
				json_object_get_double(value2));
		}
		break;
	case json_type_int:
		if (json_object_get_int(value1) !=
		    json_object_get_int(value2)) {
			dp_test_json_mismatch_record(
				mismatches, key, NULL,
				"%d != %d",
				json_object_get_int(value1),
				json_object_get_int(value2));
		}
		break;
	case json_type_string:
		if ((fnmatch(json_object_get_string(value1),
			    json_object_get_string(value2),
			     FNM_EXTMATCH) != 0) &&
		    (fnmatch(json_object_get_string(value2),
			     json_object_get_string(value1),
			     FNM_EXTMATCH) != 0)) {
			dp_test_json_mismatch_record(
				mismatches, key, NULL,
				"'%s' != '%s'",
				json_object_get_string(value1),
				json_object_get_string(value2));
		}
		break;
	case json_type_array:
		compare_lists(key, value1, value2, mismatches);
		break;
	case json_type_object:

		subobj_mismatch = NULL;
		if (!dp_test_json_subset(value1, value2,
					 &subobj_mismatch)) {
			dp_test_json_mismatch_record(mismatches, key,
						     subobj_mismatch, "%s", "");
		}
		break;
	case json_type_null:
		/* two null types always match ? */
		break;
	}

	return (!*mismatches);
}

/*
 * return true if everything in obj1 matches obj2
 */
bool
dp_test_json_subset(json_object *obj1, json_object *obj2,
		    struct dp_test_json_mismatches **mm)
{
	json_object *value2;

	if (!obj1 || !json_object_is_type(obj1, json_type_object)) {
		dp_test_json_mismatch_record(mm,
					     "top-level-obj1", NULL,
					     "missing");
		return true;
	}

	json_object_object_foreach(obj1, key, value1) {
		if (strcmp(__JSON_ANY_KEY_VAL__, key) == 0) {
			/* see if we can value1 to any field in value2 */
			struct dp_test_json_mismatches *mm2 = NULL;
			bool any_match = false;

			json_object_object_foreach(obj2, key2, value2) {
				json_val_subset(value1, value2, key2,
						&mm2);
				if (!mm2) {
					/* matched */
					any_match = true;
				} else {
					dp_test_json_mismatch_free(mm2);
					mm2 = NULL;
				}
			}
			if (!any_match)
				dp_test_json_mismatch_record(mm, key, NULL,
							     "no value match");
		} else {
			if (!json_object_object_get_ex(obj2, key,
						       &value2)) {
				/* check to see if obj2 has wildcard field */
				if (json_object_object_get_ex(
					    obj2, __JSON_ANY_KEY_VAL__,
					    &value2)) {
					/* does the value match ? */
					struct dp_test_json_mismatches *mm2
						= NULL;
					json_val_subset(value1, value2, key,
							&mm2);
					if (mm2)
						/* ! matched */
						dp_test_json_mismatch_record(
							mm, key, mm2,
							"wildcard-mismatch");
				} else {
					/*
					 * obj1 has a field not in obj2 so
					 * is not a subset of obj2.
					 */
					dp_test_json_mismatch_record(mm, key,
								     NULL,
								     "missing");
				}
			} else {
				json_val_subset(value1, value2, key, mm);
			}
		}
	}
	return (!*mm);
}

bool
dp_test_json_superset(json_object *obj1, json_object *obj2,
		      struct dp_test_json_mismatches **mismatches)
{
	return dp_test_json_subset(obj2, obj1, mismatches);
}

bool
dp_test_json_match(json_object *obj1, json_object *obj2,
		   struct dp_test_json_mismatches **mismatches)
{
	return dp_test_json_subset(obj1, obj2, mismatches) &&
		dp_test_json_superset(obj1, obj2, mismatches);
}

void
dp_test_json_filter(json_object *haystack, json_object *filter)
{
	json_object *haystack_value;
	enum json_type type_filter;

	json_object_object_foreach(filter, key, filter_value) {
		if (!json_object_object_get_ex(haystack, key,
					       &haystack_value))
			continue;
		type_filter = json_object_get_type(filter_value);

		if (type_filter != json_object_get_type(haystack_value))
			continue;

		switch (type_filter) {
		case json_type_boolean:
		case json_type_double:
		case json_type_int:
		case json_type_string:
			json_object_object_del(haystack, key);
			break;
		case json_type_object:
			if (json_object_object_length(filter_value) == 0)
				json_object_object_del(haystack, key);
			else
				dp_test_json_filter(haystack_value,
						    filter_value);
			break;
		case json_type_array: {
			int subset_list_len = json_object_array_length(
				haystack_value);
			json_object *haystack_list_elem;
			json_object *filter_list_elem;
			int i;

			filter_list_elem = json_object_array_get_idx(
				filter_value, 0);
			for (i = 0; i < subset_list_len; i++) {
				haystack_list_elem = json_object_array_get_idx(
					haystack_value, i);
				dp_test_json_filter(haystack_list_elem,
						    filter_list_elem);
			}
			break;
		}
		default:
			break;
		}
	}
}

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
				   const char **val)
{
	json_object *jobj;

	if (!jouter || json_object_get_type(jouter) != json_type_object)
		return false;

	if (!json_object_object_get_ex(jouter, field, &jobj))
		return false;

	if (json_object_get_type(jobj) != json_type_string)
		return false;

	*val = json_object_get_string(jobj);

	return true;
}

/*
 * Get the value of a named json_type_int field that is contained in an
 * outer json_type_object.
 *
 * Returns true if successful, else false.  If successful, the integer is
 * written to '*val'.
 */
bool
dp_test_json_int_field_from_obj(json_object *jouter, const char *field,
				int *val)
{
	json_object *jobj;

	if (!jouter || json_object_get_type(jouter) != json_type_object)
		return false;

	if (!json_object_object_get_ex(jouter, field, &jobj))
		return false;

	if (json_object_get_type(jobj) != json_type_int)
		return false;

	*val = json_object_get_int(jobj);

	return true;
}

/*
 * Get the value of a named json_type_boolean field that is contained in an
 * outer json_type_object.
 *
 * Returns true if successful, else false.  If successful, the boolean is
 * written to '*val'.
 */
bool
dp_test_json_boolean_field_from_obj(json_object *jouter, const char *field,
				    bool *val)
{
	json_object *jobj;

	if (!jouter || json_object_get_type(jouter) != json_type_object)
		return false;

	if (!json_object_object_get_ex(jouter, field, &jobj))
		return false;

	if (json_object_get_type(jobj) != json_type_boolean)
		return false;

	*val = json_object_get_boolean(jobj);

	return true;
}

/* Forward reference */
static json_object *
dp_test_json_find_obj(json_object *jobj, struct dp_test_json_find_key *key_list,
		      int nkeys);

/*
 * Recursively search a json array for a specific object based on a given
 * set of keys.  The array element is identified by a specific key and
 * string.
 *
 * Typically a json array in the dataplane contains a single json object that
 * itself contains a mixture of json object, arrays, strings and ints.
 * An array element it typically identified by one of the string values.
 *
 * The returned json object has its ref count incremented, so json_object_put
 * should be called once the caller has finished with the object.
 */
static json_object *
dp_test_json_find_arr(json_object *jarray,
		      struct dp_test_json_find_key *key_list, int nkeys)
{
	uint i, arraylen;
	json_object *jvalue, *rval;

	if (!key_list || nkeys == 0 || !jarray ||
	    json_object_get_type(jarray) != json_type_array)
		return NULL;

	arraylen = json_object_array_length(jarray);

	for (i = 0; i < arraylen; i++) {
		/* Get the array element at position i */
		jvalue = json_object_array_get_idx(jarray, i);

		switch (json_object_get_type(jvalue)) {
		case json_type_boolean:
		case json_type_double:
		case json_type_int:
		case json_type_null:
			break;
		case json_type_string:
			if (key_list[0].val &&
			    !strcmp(key_list[0].val,
				   json_object_get_string(jvalue))) {
				return json_object_get(jvalue);
			}
			break;
		case json_type_array:
			rval = dp_test_json_find_arr(jvalue, key_list,
						     nkeys);
			if (rval)
				return rval;
			break;
		case json_type_object:
			rval = dp_test_json_find_obj(jvalue, key_list,
						     nkeys);
			if (rval)
				return rval;
			break;
		}
	}
	return NULL;
}

/*
 * Recursively walk the json object and return the object or array that
 * matches the key_list.
 *
 * The returned json object has its ref count incremented, so
 * json_object_put should be called once the caller has finished with the
 * object.
 */
static json_object *
dp_test_json_find_obj(json_object *jobj, struct dp_test_json_find_key *key_list,
		      int nkeys)
{
	json_object *jvalue;

	if (!key_list || nkeys == 0 || !jobj ||
	    json_object_get_type(jobj) != json_type_object)
		return NULL;

	if (!json_object_object_get_ex(jobj, key_list[0].key, &jvalue))
		return NULL;

	switch (json_object_get_type(jvalue)) {
	case json_type_boolean:
	case json_type_double:
	case json_type_int:
	case json_type_null:
		if (nkeys == 1)
			return json_object_get(jvalue);
		break;
	case json_type_string:
		if (key_list[0].val) {
			/*
			 * If a key and value were specified then we use this to
			 * identify an object only.  If this is the last key
			 * then return the containing object.  If its not the
			 * last object, then continue search of containing
			 * object.
			 *
			 * For example, each element of the interfaces array has
			 * a "name" object and a "statistics" object.  If the
			 * keys are {"interfaces", NULL}, {"name", "dpT10"},
			 * {"statistics", NULL} then we will search the
			 * interfaces array for an element with "name" equal to
			 * "dpT10".  Once found, then we look for a "statistics"
			 * object in that array element.
			 */
			if (!strcmp(key_list[0].val,
				    json_object_get_string(jvalue))) {
				if (nkeys == 1)
					return json_object_get(jobj);

				return dp_test_json_find_obj(
					jobj, &key_list[1],
					nkeys-1);
			}
		} else {
			if (nkeys == 1)
				return json_object_get(jvalue);
		}
		break;
	case json_type_array:
		if (nkeys == 1)
			return json_object_get(jvalue);

		return dp_test_json_find_arr(jvalue, &key_list[1],
					     nkeys-1);
		break;
	case json_type_object:
		if (nkeys == 1)
			return json_object_get(jvalue);

		return dp_test_json_find_obj(jvalue, &key_list[1],
					     nkeys-1);
		break;
	}

	return NULL;
}

json_object *
dp_test_json_find(json_object *jobj, struct dp_test_json_find_key *key_list,
		  int nkeys)
{
	if (!jobj || !key_list || nkeys < 1)
		return NULL;

	switch (json_object_get_type(jobj)) {
	case json_type_array:
		return dp_test_json_find_arr(jobj, key_list, nkeys);
	case json_type_object:
		return dp_test_json_find_obj(jobj, key_list, nkeys);
	default:
		break;
	}
	return NULL;
}

/*
 * Iterate over all elements in a json array.  Callback function may return
 * true to terminate the iteration, in which case the current array element
 * is returned to the caller.
 */
json_object *
dp_test_json_array_iterate(json_object *jarray,
			   dp_test_json_array_iterate_cb cb, void *arg)
{
	uint arraylen, i;
	json_object *jvalue;

	if (json_object_get_type(jarray) != json_type_array)
		return NULL;

	arraylen = json_object_array_length(jarray);

	for (i = 0; i < arraylen; i++) {
		/* Get the array element at position i */
		jvalue = json_object_array_get_idx(jarray, i);

		if ((*cb)(jvalue, arg))
			return jvalue;
	}
	return NULL;
}

/* Forward reference */
static json_object *
dp_test_json_search_obj(json_object *jobj,
			struct dp_test_json_search_key *key_list,
			int nkeys);

/*
 * Recursively search a json array for a specific object based on a given
 * set of keys.  The array elements are identified by their index.
 *
 * Typically a json array in the dataplane contains a single json object that
 * itself contains a mixture of json object, arrays, strings and ints.
 *
 * The returned json object has its ref count incremented, so json_object_put
 * should be called once the caller has finished with the object.
 */
static json_object *
dp_test_json_search_arr(json_object *jarray,
			struct dp_test_json_search_key *key_list, int nkeys)
{
	int i;
	unsigned int arraylen;
	json_object *jvalue, *rval;

	if (!key_list || nkeys == 0 || !jarray ||
	    json_object_get_type(jarray) != json_type_array)
		return NULL;

	arraylen = json_object_array_length(jarray);
	i = key_list[0].index;
	if (i < 0)
		return json_object_get(jarray);

	if (arraylen < (unsigned int)i) {
		printf("%s index %d out-of-bounds, max-index: %u\n",
		       __func__, i,  arraylen - 1);
		return NULL;
	}

	/* Get the array element at position i */
	jvalue = json_object_array_get_idx(jarray, i);

	switch (json_object_get_type(jvalue)) {
	case json_type_boolean:
	case json_type_double:
	case json_type_int:
	case json_type_null:
	case json_type_string:
		return json_object_get(jvalue);
	case json_type_array:
		if (nkeys == 1)
			return json_object_get(jvalue);

		rval = dp_test_json_search_arr(jvalue, &key_list[1], nkeys-1);
		if (rval)
			return rval;

		break;
	case json_type_object:
		if (nkeys == 1)
			return json_object_get(jvalue);

		rval = dp_test_json_search_obj(jvalue, &key_list[1], nkeys-1);
		if (rval)
			return rval;

		break;
	}
	return NULL;
}

/*
 * Recursively walk the json object and return the object or array that
 * matches the key_list.
 *
 * The returned json object has its ref count incremented, so
 * json_object_put should be called once the caller has finished with the
 * object.
 */
static json_object *
dp_test_json_search_obj(json_object *jobj,
			struct dp_test_json_search_key *key_list,
			int nkeys)
{
	json_object *jvalue;
	unsigned int arraylen;
	int i;

	if (!key_list || nkeys == 0 || !jobj ||
	    json_object_get_type(jobj) != json_type_object)
		return NULL;

	if (!json_object_object_get_ex(jobj, key_list[0].key, &jvalue))
		return NULL;

	switch (json_object_get_type(jvalue)) {
	case json_type_boolean:
	case json_type_double:
	case json_type_int:
	case json_type_null:
		if (nkeys == 1)
			return json_object_get(jvalue);
		break;
	case json_type_string:
		if (key_list[0].val) {
			/*
			 * If a key and value were specified then we use this to
			 * identify an object only.  If this is the last key
			 * then return the containing object.  If its not the
			 * last object, then continue search of containing
			 * object.
			 *
			 * For example, each element of the interfaces array has
			 * a "name" object and a "statistics" object.  If the
			 * keys are {"interfaces", NULL}, {"name", "dpT10"},
			 * {"statistics", NULL} then we will search the
			 * interfaces array for an element with "name" equal to
			 * "dpT10".  Once found, then we look for a "statistics"
			 * object in that array element.
			 */
			if (!strcmp(key_list[0].val,
				    json_object_get_string(jvalue))) {
				if (nkeys == 1)
					return json_object_get(jobj);

				return dp_test_json_search_obj(
					jobj, &key_list[1],
					nkeys-1);
			}
		} else {
			if (nkeys == 1)
				return json_object_get(jvalue);
		}
		break;
	case json_type_array:
		arraylen = json_object_array_length(jvalue);
		i = key_list[0].index;
		if (i < 0)
			return json_object_get(jvalue);

		if (arraylen < (unsigned int)i) {
			printf("%s index %d out-of-bounds, max-index: "
			       "%u\n", __func__, i, arraylen - 1);
			return NULL;
		}

		/* Get the array element at position i */
		jvalue = json_object_array_get_idx(jvalue, i);
		if (nkeys == 1)
			return json_object_get(jvalue);

		return dp_test_json_search(jvalue, &key_list[1], nkeys-1);

	case json_type_object:
		if (nkeys == 1)
			return json_object_get(jvalue);

		return dp_test_json_search_obj(jvalue, &key_list[1],
					       nkeys-1);
		break;
	}

	return NULL;
}

json_object *
dp_test_json_search(json_object *jobj, struct dp_test_json_search_key *key_list,
		    int nkeys)
{
	if (!jobj || !key_list || nkeys < 1)
		return NULL;

	switch (json_object_get_type(jobj)) {
	case json_type_array:
		return dp_test_json_search_arr(jobj, key_list, nkeys);
	case json_type_object:
		return dp_test_json_search_obj(jobj, key_list, nkeys);
	default:
		break;
	}
	return NULL;
}
