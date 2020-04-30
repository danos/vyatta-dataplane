/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <assert.h>
#include "compiler.h"
#include <fal_plugin.h>
#include <rte_log.h>
#include <rte_sched.h>
#include <stdint.h>
#include <stdio.h>
#include <bsd/sys/tree.h>

#define LOG(l, t, ...)						\
	rte_log(RTE_LOG_ ## l,					\
		RTE_LOGTYPE_USER1, # t ": " __VA_ARGS__)

#define DEBUG(...)						\
	do {							\
		if (dp_test_debug_get() == 2)			\
			LOG(DEBUG, FAL_TEST, __VA_ARGS__);	\
	} while (0)

#define INFO(...) LOG(INFO, FAL_TEST,  __VA_ARGS__)
#define ERROR(...) LOG(ERR, FAL_TEST, __VA_ARGS__)

/**
 * Local structure definitions
 */

struct cpp_limiter_protocol_obj {
	enum fal_cpp_limiter_attr_t protocol;
	fal_object_t policer_obj;
	TAILQ_ENTRY(cpp_limiter_protocol_obj) entries;
};

struct cpp_limiter_obj {
	TAILQ_HEAD(tailq_prot, cpp_limiter_protocol_obj) protocol_list;
};

static void free_limiter(struct cpp_limiter_obj *limiter)
{
	if (limiter) {
		struct cpp_limiter_protocol_obj *prot_obj;

		while ((prot_obj = TAILQ_FIRST(&limiter->protocol_list))
		       != NULL) {
			TAILQ_REMOVE(&limiter->protocol_list,
				     prot_obj, entries);
			free(prot_obj);
		}
		fal_free_deferred(limiter);
	}
}

int fal_plugin_create_cpp_limiter(uint32_t attr_count,
				  const struct fal_attribute_t *attr_list,
				  fal_object_t *new_limiter_id)
{
	struct cpp_limiter_obj *limiter = NULL;
	bool seen_default = false;
	int ret = 0;
	uint32_t i;

	INFO("%s, attr-count: %u\n", __func__, attr_count);

	limiter = fal_calloc(1, sizeof(*limiter));
	if (!limiter) {
		ret = -ENOMEM;
		goto error;
	}
	TAILQ_INIT(&limiter->protocol_list);

	for (i = 0; i < attr_count; i++) {
		switch (attr_list[i].id) {
		case FAL_CPP_LIMITER_ATTR_DEFAULT:
			seen_default = true;
			/* fall through */
		case FAL_CPP_LIMITER_ATTR_LL_MC:
		case FAL_CPP_LIMITER_ATTR_IPV6_EXT:
		case FAL_CPP_LIMITER_ATTR_IPV4_FRAGMENT:
		case FAL_CPP_LIMITER_ATTR_OSPF_MC:
		case FAL_CPP_LIMITER_ATTR_OSPF:
		case FAL_CPP_LIMITER_ATTR_BGP:
		case FAL_CPP_LIMITER_ATTR_ICMP:
		case FAL_CPP_LIMITER_ATTR_LDP_UDP:
		case FAL_CPP_LIMITER_ATTR_BFD_UDP:
		case FAL_CPP_LIMITER_ATTR_RSVP:
		case FAL_CPP_LIMITER_ATTR_UDP:
		case FAL_CPP_LIMITER_ATTR_TCP:
		{
			fal_object_t policer_obj = attr_list[i].value.objid;
			struct cpp_limiter_protocol_obj *protocol_obj;

			if (!policer_obj) {
				ERROR("%s: NULL obj-id for attribute-id %u\n",
				      __func__, attr_list[i].id);
				ret = -EINVAL;
				goto error;
			}

			protocol_obj = calloc(1, sizeof(*protocol_obj));
			if (!protocol_obj) {
				ret = -ENOMEM;
				goto error;
			}

			protocol_obj->protocol = attr_list[i].id;
			protocol_obj->policer_obj = policer_obj;
			TAILQ_INSERT_TAIL(&limiter->protocol_list,
					  protocol_obj, entries);
			break;
		}
		default:
			ERROR("%s: unknown cpp rate limiter attribute-id %u\n",
			      __func__, attr_list[i].id);
			ret = -EINVAL;
			goto error;
		}
	}

	if (!seen_default) {
		ERROR("%s: mandatory cpp rate limiter attribute "
		      " `default` is missing\n", __func__);
		ret = -EINVAL;
		goto error;
	}

	*new_limiter_id = (fal_object_t)limiter;
	return 0;

error:
	free_limiter(limiter);
	return ret;
}

int fal_plugin_remove_cpp_limiter(fal_object_t limiter_id)
{
	struct cpp_limiter_obj *limiter = (struct cpp_limiter_obj *)limiter_id;

	INFO("%s - 0x%lx\n", __func__, limiter_id);

	if (!limiter) {
		ERROR("%s: limiter ID is NULL\n", __func__);
		return -EINVAL;
	}

	free_limiter(limiter);
	return 0;
}

static int get_policer_obj(struct cpp_limiter_obj *limiter,
			   enum fal_cpp_limiter_attr_t protocol,
			   fal_object_t *policer_obj)
{
	struct cpp_limiter_protocol_obj *protocol_obj;

	TAILQ_FOREACH(protocol_obj, &limiter->protocol_list, entries) {
		if (protocol_obj->protocol == protocol) {
			*policer_obj = protocol_obj->policer_obj;
			return 0;
		}
	}

	return -ENOENT;
}

int fal_plugin_get_cpp_limiter_attribute(fal_object_t limiter_id,
					 uint32_t attr_count,
					 struct fal_attribute_t *attr_list)
{
	struct cpp_limiter_obj *limiter = (struct cpp_limiter_obj *)limiter_id;
	int ret;
	uint32_t i;

	INFO("%s - 0x%lx\n", __func__, limiter_id);

	if (!limiter) {
		ERROR("%s: limiter ID is NULL\n", __func__);
		return -EINVAL;
	}

	for (i = 0; i < attr_count; i++) {
		switch (attr_list[i].id) {
		case FAL_CPP_LIMITER_ATTR_DEFAULT:
		case FAL_CPP_LIMITER_ATTR_LL_MC:
		case FAL_CPP_LIMITER_ATTR_IPV6_EXT:
		case FAL_CPP_LIMITER_ATTR_IPV4_FRAGMENT:
		case FAL_CPP_LIMITER_ATTR_OSPF_MC:
		case FAL_CPP_LIMITER_ATTR_OSPF:
		case FAL_CPP_LIMITER_ATTR_BGP:
		case FAL_CPP_LIMITER_ATTR_ICMP:
		case FAL_CPP_LIMITER_ATTR_LDP_UDP:
		case FAL_CPP_LIMITER_ATTR_BFD_UDP:
		case FAL_CPP_LIMITER_ATTR_RSVP:
		case FAL_CPP_LIMITER_ATTR_UDP:
		case FAL_CPP_LIMITER_ATTR_TCP:
		{
			fal_object_t policer_obj;
			ret = get_policer_obj(limiter, attr_list[i].id,
						  &policer_obj);
			if (ret) {
				ERROR("%s: failed to get object for "
				      "attribute-id %u\n", __func__,
				      attr_list[i].id);
				goto error;
			}
			attr_list[i].value.objid = policer_obj;
			break;
		}
		default:
			ERROR("%s: unknown cpp rate limiter attribute-id %u\n",
			      __func__, attr_list[i].id);
			ret = -EINVAL;
			goto error;
		}
	}

	return 0;

error:
	return ret;
}

static fal_object_t committed_cpp_limiter = FAL_NULL_OBJECT_ID;

/*
 * On hardware the following would perform the required rate limiting
 * given by object limiter_id (if not FAL_NULL_OBJECT_ID), and remove
 * any previously configured rate limter (if not
 * FAL_NULL_OBJECT_ID).
 */
static int fal_commit_cpp_limiter(fal_object_t limiter_id)
{
	if (limiter_id == FAL_NULL_OBJECT_ID) {
		if (committed_cpp_limiter != FAL_NULL_OBJECT_ID) {
			/* NB: hardware would remove the old limiter here */
			committed_cpp_limiter = FAL_NULL_OBJECT_ID;
		}
	} else {
		if (committed_cpp_limiter == FAL_NULL_OBJECT_ID) {
			/* NB: hardware would install initial limiter here */
			committed_cpp_limiter = limiter_id;
		} else {
			/*
			 * NB: hardware would replace old limiter with the
			 * new one here
			 */
			committed_cpp_limiter = limiter_id;
		}
	}
	return 0;
}

/*
 * Note that the following function could be merged with any other test
 * versions of the function that are added.
 */
int fal_plugin_set_switch_attribute(const struct fal_attribute_t *attr)
{
	int ret = 0;

	switch (attr->id) {
	case FAL_SWITCH_ATTR_CPP_RATE_LIMITER:
		ret = fal_commit_cpp_limiter(attr->value.objid);
		break;
	default:
		ERROR("%s: unknown switch "
		      "attribute-id %u\n", __func__, attr->id);
		ret = -EINVAL;
		break;
	}

	return ret;
}

int fal_plugin_get_switch_attribute(uint32_t attr_count,
				    struct fal_attribute_t *attr_list)
{
	struct fal_attribute_t *attr;

	for (uint32_t i = 0; i < attr_count; i++) {
		attr = &attr_list[i];
		switch (attr->id) {
		case FAL_SWITCH_ATTR_MAX_BURST_SIZE:
			attr->value.u32 = 130048;
			break;
		default:
			ERROR("%s(%d): unknown switch attribute %d\n",
			      __func__, attr_count, attr->id);
			return -EINVAL;
		}
	}

	return 0;
}
