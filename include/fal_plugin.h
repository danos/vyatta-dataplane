/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.
 * All rights reserved.
 * Copyright (c) 2016-2017 by Brocade Communication Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Forwarding Abstraction Layer
 *
 * Intro
 * =====
 *
 * The forwarding abstraction layer is designed to provide abstraction
 * around a forwarding layer that is independent from the dataplane
 * forwarding path. This is typically a hardware forwarding chip, but
 * could be used to implement specialised software forwarding paths
 * too.
 *
 * The dataplane is referred to as "the application" and the
 * implementation of the FAL API that talks to the specialised
 * forwarding path/hardware forwarding chip is referred to as "the FAL
 * plugin". The FAL plugin is a shared object library that lives
 * within the application address space.
 *
 * Architectural Overview
 * ======================
 *
 * +-------------------------------------+
 * | Dataplane                 | DPDK    |
 * |                           |         | <-----+
 * +-------------------------------------+       |
 *     ^                           ^             |
 *     |            DPDK ops &     |             |
 *     |            notifications  |             |
 *     |                           v             |
 *     |           +--------------------+        |
 *     |           | vyatta-dpdk-swport |        |
 *     |           +--------------------+        |
 *     | FAL ops        ^                        |
 *     |         swport |       Bkplane to-/for- |
 *     |          ops   |       us (optional)    |
 *     v                v                        |
 * +-------------------------------------+       |
 * | FAL plugin                          |       |
 * +-------------------------------------+       |
 *                     ^                         |
 *                     | Chip SDK ops            |
 *                     v                         |
 * +-------------------------------------+       |
 * | Switch chip                         | <-----+
 * +-------------------------------------+
 *
 * Design principles
 * =================
 *
 * The API is designed to be compatible with SAI objects, attributes
 * and operations with minimal translation required, if any.
 *
 * The first port of call for any new objects or attributes introduced
 * should be suitable existing SAI objects or attributes and only
 * diverging if nothing suitable is present. The reasons for this are
 * twofold:
 * 1. There are often multiple ways of implementing something and
 *    defaulting to a certain approach shortcircuits the less
 *    functionally-impacting parts of the design.
 * 2. It allows leveraging SAI adapters in the future should adapters
 *    with useful feature set and hardware support combinations
 *    materialise.
 *
 * In general, FAL APIs for each object consist of:
 * 1. Create
 * 2. Update
 * 3. Delete
 * 4. Get
 * In general each API is related to one and only one object.
 *
 * A create operation may include multiple attributes, some of which
 * may be mandatory and some of which may be optional. Keys for the
 * object will typically be represented in the mandatory
 * attributes. Having these represented in attributes means that
 * semantics for an API can easily be extended later on without
 * changing existing FAL plugins (such as would be the case with
 * listing keys and data in the function signature directly). The
 * operation in general instantiates a handle that can then be used to
 * identify the object for subsequent operations and sometimes from
 * other objects in the object model.
 *
 * An update operation only works on one attribute at a time and the
 * object it is operating on is expected to be identified by the
 * object handle passed in. The reason for only supporting one
 * attribute to be modified at a time is that it avoids ambiguity
 * about what state the FAL plugin should be in on failure, or which
 * attribute caused the failure, which may be the case had multiple
 * attributes been supported. Unless otherwise specified failure of an
 * update should leave the object in the same state as before the
 * update.
 *
 * A delete operation in general will not have any attributes
 * associated with it since the object should be uniquely identified
 * by its handle and should not have any residual state after it has
 * been deleted. Failures can be reported by the delete, but the
 * application can not do anything with these other than log the
 * error or increment counters.
 *
 * The application (dataplane) makes certain promises to the FAL
 * plugin which may be relied upon:
 * 1. An update, delete or get API will not be called on a FAL object
 *    unless that FAL object ID is one that has been returned by a
 *    successful create API of the same object type, with no
 *    intervening delete having been performed on it. Similarly, a FAL
 *    object will not be referenced by an attribute unless it is one
 *    that has been returned by a successful create API of one of the
 *    documented expected object types, and with no intervening delete
 *    having been performed on it. The reasoning behind this promise
 *    is that it allows simplicity of object management in the FAL
 *    plugin with reduced scope for ambiguity in error cases.
 * 2. An object will not be deleted whilst it is still referenced via
 *    a handle in an attribute, i.e. until that attribute is modified
 *    to refer to the handle of another object (or the null handle) or
 *    until the referring object is deleted. The reasoning behind this
 *    promise is simplicity of object management and to reduce the
 *    cases where walks of (a potentially large number of) dependent
 *    objects is required.
 * 3. A create will not be called on a FAL object with the same key as
 *    a previous FAL object create, without there being an intervening
 *    delete.
 *
 * Return Codes
 * ============
 *
 * Success from FAL APIs is signalled as an integer >= 0, but unless
 * otherwise specified 0. Failures can consist of:
 *  * -ENOMEM: Out of CPU memory.
 *  * -ENOSPC: Out of hardware resources.
 *  * -EINVAL: Violation of contract between application and FAL plugin.
 *  * -EOPNOTSUPP: Object or attribute not supported. The application
 *    (dataplane) may fall back to another mode of operation, if
 *    possible, and not signal this as an error to the operator.
 *  * Any other negative errno valid on the system. This will be
 *    treated as a general error.
 *
 * Threading Model
 * ===============
 *
 * In theory, a FAL plugin could be issued any operation on any thread.
 * However, currently creates, updates and deletes will (unless
 * otherwise specified) be issued from a single thread from the
 * application to the FAL plugin. The FAL plugin should only rely on
 * this at its own risk and be prepared for it to change without
 * warning in the future for existing and new objects. Gets may be
 * issued from any thread and so the FAL plugin should be implemented
 * accordingly.
 *
 * The threading model of packet forwarding, framing and other DPDK
 * interactions follows that of the DPDK threading model.
 *
 * DPDK
 * ====
 *
 * In order to fit with the model that dataplane-type interfaces are
 * backed by a DPDK port and to provide a high-speed punt path,
 * switchports are correspondingly backed by a DPDK port and it is
 * expected that the FAL plugin react to operations on the DPDK port
 * as driven by the dataplane accordingly and in preference to,
 * possibly conflicting, FAL operations.
 *
 * A hardware platform may choose to implement a punt path via one or
 * more DPDK-supported host-CPU-connected interfaces in order to
 * provide a high-speed punt path. In this case, traffic from all
 * switch ports will be multiplexed over this/these interface(s) and
 * as such requires a header that gives the original input
 * interface. The format of this header is private to the switch chip
 * and its FAL plugin. Similarly, traffic being sent out of a
 * switchport will be multiplexed over the same DPDK-supported
 * host-CPU-connected interface and will need to have a header
 * inserted that identifies the output interface. These facilities are
 * known as the RX/TX framers.
 *
 * Backplane interfaces need to be signalled to the dataplane through
 * the use of the /run/dataplane/platform.conf file. E.g.:
 *
 *  [dataplane]
 *  backplane_port1 = 2:0.0
 *  backplane_port2 = 2:0.1
 *
 * Syntax gives identity of interface in the form of a PCI address:
 *  backplane_port<n> = <domain>:<bus>:<devid>.<function>
 *
 * Loading FAL plugin
 * ==================
 *
 * The FAL plugin is loaded dynamically according to the contents of
 * /run/dataplane/platform.conf. E.g.:
 *
 *  [dataplane]
 *  fal_plugin = /usr/lib/libfal-example.so.1
 *
 * The FAL plugin is expected to discover via some means before the
 * dataplane starts that it is needed to be loaded on this system (as
 * opposed to some other FAL plugin) via a discovery script. This
 * script may be located in /lib/vplane/prestart.d/ and which case it
 * will be run just prior to the dataplane starting and so can
 * populate the platform.conf file accordingly.
 *
 * The application (dataplane) will then initialise in the following
 * sequence:
 * 1. <Application inits runtime environment>
 * 2. FAL plugin is loaded (if specified)
 * 3. fal_plugin_init_log() called.
 * 4. fal_plugin_init() called.
 * 5. <Application caches FAL object function pointers>
 * 6. fal_plugin_setup_interfaces() called.
 * 7. <Application discovers available interfaces via DPDK>
 *
 * Multiple Switch Instances
 * =========================
 *
 * Due to the complexities associated with programming selective
 * forwarding information on different switch/forwarding chips (switch
 * instances) and particularly the complexities around the
 * chip-specific requirements of what forwarding information is
 * required on each switch instance, then the presence of multiple
 * switch instances isn't modelled through the FAL API (other than for
 * diagnostic purposes).
 *
 * Therefore the dataplane will give the FAL plugin the full set of
 * notifications and it is up to the FAL plugin to deal with multiple
 * switch instances, either by programming the full set of forwarding
 * information on each switch instance or selectively programming the
 * required forwarding information on each switch instance according
 * to its own algorithm.
 *
 * Multiple FAL plugins
 * ====================
 *
 * For simplicity of implementation the dataplane talks to one FAL
 * plugin (or none if running on a software-dataplane only
 * platform). However, it would be possible (in theory) to implement a
 * FAL plugin whose role would be to multiplex/demultiplex FAL
 * operations/notifications as required to multiple FAL plugins
 * underneath. Therefore, when adding new FAL APIs consideration
 * should be given to not break this potential use-case.
 *
 * Why not SAI
 * ===========
 *
 * Unlike the FAL, SAI doesn't have a high-speed punt path. By this we
 * mean a polling-mode receive function where the packet is received
 * in a zero-copied, if possible, (i.e. by DMA) manner from hardware
 * and on a dedicated forwarding thread (to avoid scheduler overhead
 * and to allow the use of per-core storage). Similarly, a zero-copy
 * transmit function is desirable where it can assume it is called
 * from an appropriate thread-context and be optimised
 * accordingly. This could have been worked around using a
 * side-channel between the SAI adapter and the dataplane, but would
 * have involved a fair amount of extra code, especially translating
 * between DPDK interface APIs and SAI port attributes.
 *
 * In addition, there are a number of objects and attributes that
 * don't fit well with the way the dataplane is currently
 * designed. Such objects include the router interface (there is no
 * distinction between L2 and L3 interface in the dataplane), and not
 * all interface types are represented in SAI and some of the
 * interface types have special handling in certain places (tunnels
 * use different attributes in L3 nexthops vs other interfaces),
 * whereas it simplifies the dataplane side not to have to deal with
 * such differences, even if the interface types are not fully modeled
 * in the FAL yet. Another difference is that the SAI model does not
 * account for having a multipath connected route (which could be
 * present in certain use cases, e.g. VRRP) and it also requires the
 * neighbour to be created before a nexthop can refer to it.
 *
 * However, the biggest reason for not using SAI at this point is so
 * we can move quickly and diverge from the API where using SAI would
 * make both the dataplane and FAL plugin more complicated, or is
 * incompatible with use cases that we would like to support, and be
 * able to introduce new object models and attributes to support
 * features not available in SAI without having to worry about
 * conflicts in a later version of SAI.
 */

#ifndef VYATTA_DATAPLANE_FAL_PLUGIN_H
#define VYATTA_DATAPLANE_FAL_PLUGIN_H

#include <stdint.h>
#include <netinet/in.h>
#include <rte_ether.h>
#include <stdbool.h>
#include <linux/if.h>
#include "json_writer.h"

#define PLATFORM_FILE  "/run/dataplane/platform.conf"

/* An IP address */

enum fal_ip_addr_family_t {
	FAL_IP_ADDR_FAMILY_IPV4,
	FAL_IP_ADDR_FAMILY_IPV6
};

struct fal_ip_address_t {
	enum fal_ip_addr_family_t addr_family;
	union _ip_addr {
		struct in_addr addr4;
		struct in6_addr addr6;
		uint32_t ip4;
		uint8_t ip6[16];
	} addr;
};

struct fal_next_hop;

enum fal_traffic_type {
	FAL_TRAFFIC_UCAST = 0,
	FAL_TRAFFIC_MCAST,
	FAL_TRAFFIC_BCAST,
	FAL_TRAFFIC_MAX
};

/* Off the chip external packet bundle buffer counters to be
 * stored in an array.
 */
enum fal_qos_external_buf_counters {
	FAL_QOS_EXTERNAL_BUFFER_DESC_FREE = 0,
	FAL_QOS_EXTERNAL_BUFFER_PKT_REJECT,

	/* Add J2 QOS external buffer counters */
	FAL_QOS_EXTERNAL_BUFFER_MAX_COUNTER
};

/* Off the chip external packet bundle buffer counter ids for FAL to
 * retrieve from ASIC.
 */
enum fal_qos_external_buf_counter_ids {
	FAL_QOS_EXTERNAL_BUFFER_COUNTER_ID = 0,
	FAL_QOS_EXTERNAL_BUFFER_PKT_REJECT_COUNTER_ID,

	/* Add J2 QOS external buffer counter ids */
	FAL_QOS_EXTERNAL_BUFFER_MAX_ID
};

int fal_plugin_qos_get_counters(const uint32_t *cntr_ids,
				uint32_t num_cntrs,
				uint64_t *cntrs);

/*
 * Context handle used for FAL plugins to store state against a given
 * object type.
 */
typedef uintptr_t fal_object_t;

#define FAL_NULL_OBJECT_ID 0x0

struct fal_object_list_t {
	uint32_t count;
	fal_object_t list[0];
};

/*
 * Structure for a list of uint32_t objects
 */
struct fal_u32_list_t {
	uint32_t count;
	uint32_t list[0];
};

/*
 * modeled after sai_packet_color_t
 * used to set actions based on packet colour
 */
enum fal_packet_colour {
	FAL_PACKET_COLOUR_GREEN,
	FAL_PACKET_COLOUR_YELLOW,
	FAL_PACKET_COLOUR_RED,
	FAL_NUM_PACKET_COLOURS
};

/*
 * The fal_qos_map_params_t and fal_qos_map_t structures can be used for
 * several different mapping purposes.  In the fal_qos_map_t the key field
 * provides the "from", while the value field provides the "to".  The
 * type and number of values that the key and value take depends upon the
 * type of map.  For example a DSCP-to-PCP map will have a DSCP key field
 * and a dot1p value field, while a DSCP-to-TC-WRR-DP map will have a
 * DSCP key field and a value with a tc, wrr and dp fields set.
 */
struct fal_qos_map_params_t {
	uint8_t dscp;
	uint8_t dot1p;
	uint8_t tc;
	uint8_t des;
	uint8_t wrr;
	uint8_t des_used;
	union {
		int dp; /* deprecated */
		enum fal_packet_colour color;
	};
};

struct fal_qos_map_t {
	struct fal_qos_map_params_t key;
	struct fal_qos_map_params_t value;
};

#define FAL_QOS_MAP_DSCP_VALUES 64
#define FAL_QOS_MAP_PCP_VALUES 8
#define	FAL_QOS_MAP_DESIGNATION_VALUES 8

#define FAL_QOS_MAP_DES_DP_VALUES \
	(FAL_QOS_MAP_DESIGNATION_VALUES * FAL_NUM_PACKET_COLOURS)

struct fal_qos_map_list_t {
	uint8_t des_used;
	uint32_t count;
	struct fal_qos_map_t list[FAL_QOS_MAP_DSCP_VALUES];
};

struct fal_acl_field_data_t;
struct fal_acl_action_data_t;

/* An attribute */

union fal_attribute_value_t {
	bool booldata;
	uint8_t u8;
	int8_t i8;
	uint16_t u16;
	uint32_t u32;
	int32_t i32;
	uint64_t u64;
	fal_object_t objid;
	const void *ptr;
	struct rte_ether_addr mac;
	struct fal_ip_address_t ipaddr;
	struct fal_object_list_t *objlist;
	struct fal_qos_map_list_t *maplist;
	struct fal_acl_field_data_t *aclfield;
	struct fal_acl_action_data_t *aclaction;
	char if_name[IFNAMSIZ];
	uint8_t eui64[8];
	struct fal_u32_list_t *u32list;
};

struct fal_attribute_t {
	uint32_t id;
	union fal_attribute_value_t value;
};

/*
 * Used by plugin to convert ifindex to dpdk portid.
 */
extern int fal_port_byifindex(int ifindex, uint16_t *portid);

/**
 * Allocate a block of memory that can be freed in a deferred manner
 *
 * The memory must be freed by fal_free_deferred().
 *
 * @param[in] size Size of block of memory to be allocated
 * @return Block of memory allocated or NULL if out of memory or some
 * other error.
 */
void *fal_malloc(size_t size);

/**
 * Allocate an array of memory that can be freed in a deferred manner
 *
 * The memory must be freed by fal_free_deferred().
 *
 * @param[in] nmemb Number of members of array to be allocated
 * @param[in] size Size of array element to be allocated
 * @return Block of zero'd memory allocated or NULL if out of memory
 * or some other error.
 */
void *fal_calloc(int nmemb, size_t size);

/**
 * Free in a deferred manner some memory
 *
 * The memory must have been allocated by either fal_malloc() or fal_calloc().
 *
 * @param[in] ptr Pointer to memory to be freed in a deferred manner.
 */
void fal_free_deferred(void *ptr);

/*
 * All of the functions for plugins are optional, if one is not
 * provided the plugin framework will skip that function for this plugin.
 */
int fal_plugin_init(void);
int fal_plugin_init_log(void);


/*
 * fal_plugin_setup_interfaces should get all the interfaces ready to
 * receive traffic. It should also create any DPDK VDEV devices to
 * represent the interface in question.
 */
void fal_plugin_setup_interfaces(void);


/**
 * @brief Attribute data for #FAL_PORT_ATTR_POE_PRIORITY
 */
typedef enum _fal_port_poe_priority_t {
	/** Low priority */
	FAL_PORT_POE_PRIORITY_LOW = 0,

	/** High priority */
	FAL_PORT_POE_PRIORITY_HIGH = 1,

	/** Critical priority */
	FAL_PORT_POE_PRIORITY_CRITICAL = 2,
} fal_port_poe_priority_t;

/**
 * @brief Attribute data for #FAL_PORT_ATTR_POE_CLASS
 */
typedef enum _fal_port_poe_class_t {
	/** Unknown or unsupported */
	FAL_PORT_POE_CLASS_UNKNOWN,

	/** 12.95W */
	FAL_PORT_POE_CLASS_TYPE1_CLASS0,

	/** 3.84W */
	FAL_PORT_POE_CLASS_TYPE1_CLASS1,

	/** 6.49W */
	FAL_PORT_POE_CLASS_TYPE1_CLASS2,

	/** 12.95W */
	FAL_PORT_POE_CLASS_TYPE1_CLASS3,

	/** 12.95W */
	FAL_PORT_POE_CLASS_TYPE2_CLASS0,

	/** 3.84W */
	FAL_PORT_POE_CLASS_TYPE2_CLASS1,

	/** 6.49W */
	FAL_PORT_POE_CLASS_TYPE2_CLASS2,

	/** 12.95W */
	FAL_PORT_POE_CLASS_TYPE2_CLASS3,

	/** 25.5W */
	FAL_PORT_POE_CLASS_TYPE2_CLASS4,

} fal_port_poe_class_t;


/**
 * @brief Attribute data for #FAL_PORT_ATTR_GLOBAL_FLOW_CONTROL_MODE
 */
enum fal_port_flow_control_mode_t {
	/** Disable flow control for both tx and rx */
	FAL_PORT_FLOW_CONTROL_MODE_DISABLE,

	/** Enable flow control for rx only */
	FAL_PORT_FLOW_CONTROL_MODE_RX_ONLY,

	/** Enable flow control for tx only */
	FAL_PORT_FLOW_CONTROL_MODE_TX_ONLY,

	/** Enable flow control for both tx and rx */
	FAL_PORT_FLOW_CONTROL_MODE_BOTH_ENABLE,

};

/* Layer 2 operations */

enum fal_port_attr_t {
	FAL_PORT_ATTR_KIND,		/* .ptr -- kind: "vlan", "tun", etc */
	FAL_PORT_ATTR_IFI_TYPE,		/* .ptr -- ifi_type: "ether", etc */
	FAL_PORT_ATTR_IFI_FLAGS,	/* .u32 -- ifi_flags */
	FAL_PORT_ATTR_VRF_ID,		/* .u32 -- VRF id - deprecated */
	FAL_PORT_ATTR_DPDK_PORT,	/* .u8 -- port */
	FAL_PORT_ATTR_VLAN_ID,		/* .u16 -- VLAN ID - deprecated */
	FAL_PORT_ATTR_PARENT_IFINDEX,	/* .u32 -- if_index */
	FAL_PORT_ATTR_MTU,		/* .u16 -- MTU */
	FAL_PORT_ATTR_HW_SWITCH_MODE, /* .u8 - enable/disable */
	FAL_PORT_ATTR_MAC_ADDRESS,	/* .mac -- primary MAC address */

	/**
	 * @brief PoE administrative status
	 * @flags CREATE_AND_SET
	 * @type bool
	 */
	FAL_PORT_ATTR_POE_ADMIN_STATUS,

	/**
	 * @brief PoE operating status
	 * @flags READ_ONLY
	 * @type bool
	 */
	FAL_PORT_ATTR_POE_OPER_STATUS,

	/**
	 * @brief PoE port priority
	 * @flags CREATE_AND_SET
	 * @type u8 fal_port_poe_priority_t
	 */
	FAL_PORT_ATTR_POE_PRIORITY,

	/**
	 * @brief PoE current power class
	 * @flags READ_ONLY
	 * @type u8 fal_port_poe_class_t
	 */
	FAL_PORT_ATTR_POE_CLASS,

	/**
	 * @brief Interface name
	 * @flags READ_ONLY
	 * @type .if_name (char[IFNAMSIZ])
	 */
	FAL_PORT_ATTR_NAME,

	/**
	 * @brief Interface breakout - number of subports
	 * @flags CREATE_AND_SET
	 * @type u8
	 * @default 0
	 */
	FAL_PORT_ATTR_BREAKOUT,

	/**
	 * @brief Enable/Disable Mirror session
	 * Enable ingress mirroring by assigning list of mirror session object
	 * as attribute value, disable ingress mirroring by assigning
	 * object_count as 0 in objlist.
	 * @type fal_object_list_t
	 * @flags CREATE_AND_SET
	 * @objects FAL_OBJECT_TYPE_MIRROR_SESSION
	 * @default empty
	 */
	FAL_PORT_ATTR_INGRESS_MIRROR_SESSION,

	/**
	 * @brief Enable/Disable Mirror session
	 * Enable egress mirroring by assigning list of mirror session object
	 * as attribute value, disable egress mirroring by assigning
	 * object_count as 0 in objlist.
	 * @type fal_object_list_t
	 * @flags CREATE_AND_SET
	 * @objects FAL_OBJECT_TYPE_MIRROR_SESSION
	 * @default empty
	 */
	FAL_PORT_ATTR_EGRESS_MIRROR_SESSION,
	/**
	 * @brief Ingress Mirror vlan list
	 * Ingress mirroring vlan list
	 * Delete all vlans for Ingress if count 0 in objlist.
	 * @type fal_object_list_t
	 * @flags CREATE_AND_SET
	 * @default empty
	 */
	FAL_PORT_ATTR_INGRESS_MIRROR_VLAN,
	/**
	 * @brief Egress Mirror vlan list
	 * Egress(Tx) mirroring vlan list
	 * Delete all vlans for Egress if count 0 in objlist.
	 * @type fal_object_list_t
	 * @flags CREATE_AND_SET
	 * @default empty
	 */
	FAL_PORT_ATTR_EGRESS_MIRROR_VLAN,
	/**
	 * @brief Is mirroring in hardware enabled
	 * True means mirroring will be done in hardware, false
	 * indicates that mirroring will not be done in hardware
	 * @type bool
	 * @flags READ_ONLY
	 */
	FAL_PORT_ATTR_HW_MIRRORING,

	/**
	 * @brief Enable unicast storm control policer on port
	 *
	 * Set policer id = FAL_NULL_OBJECT_ID to disable policer on port.
	 * @type fal_object_t
	 * @flags CREATE_AND_SET
	 * @default FAL_NULL_OBJECT_ID
	 *
	 */
	FAL_PORT_ATTR_UNICAST_STORM_CONTROL_POLICER_ID,

	/**
	 * @brief Enable broadcast storm control policer on port
	 *
	 * Set policer id = FAL_NULL_OBJECT_ID to disable policer on port.
	 * @type fal_object_t
	 * @flags CREATE_AND_SET
	 * @default FAL_NULL_OBJECT_ID
	 *
	 */
	FAL_PORT_ATTR_BROADCAST_STORM_CONTROL_POLICER_ID,

	/**
	 * @brief Enable multicast storm control policer on port
	 *
	 * Set policer id = FAL_NULL_OBJECT_ID to disable policer on port.
	 * @type fal_object_t
	 * @flags CREATE_AND_SET
	 * @default FAL_NULL_OBJECT_ID
	 *
	 */
	FAL_PORT_ATTR_MULTICAST_STORM_CONTROL_POLICER_ID,

	/**
	 * @brief Dynamic FDB entry aging time in seconds
	 *
	 * Only valid on parts that encompass one or more bridging
	 * domains. Zero means aging is disabled.
	 *
	 * @type u32
	 * @flags CREATE_AND_SET
	 * @default 0
	 */
	FAL_PORT_ATTR_FDB_AGING_TIME,

	/**
	 * @brief Enable ingress QoS classification on port
	 *
	 * Set map id = FAL_NULL_OBJECT_ID to remove map
	 * @type fal_object_t
	 * @flags CREATE_AND_SET
	 * @default FAL_NULL_OBJECT_ID
	 *
	 */
	FAL_PORT_ATTR_QOS_INGRESS_MAP_ID,

	/**
	 * @brief Enable (bind) or disable (unbind) packet capture on this port
	 *
	 * Pass a capture object to enable packet capture, pass
	 * FAL_NULL_OBJECT_ID to disable packet capture.
	 *
	 * @type fal_object_t
	 * @flags CREATE_AND_SET
	 * @default FAL_NULL_OBJECT_ID
	 */
	FAL_PORT_ATTR_CAPTURE_BIND,

	/**
	 * @brief Is hardware packet capture enabled on this port
	 *
	 * @type bool
	 * @flags READ_ONLY
	 */
	FAL_PORT_ATTR_HW_CAPTURE,

	/**
	 * @brief Global pause-frame flow control on Interface.
	 * @type fal_port_flow_control_mode_t
	 * @flags CREATE_AND_SET
	 * @default FAL_PORT_FLOW_CONTROL_MODE_DISABLE
	 **/
	FAL_PORT_ATTR_GLOBAL_FLOW_CONTROL_MODE,

	/**
	 * @brief Query Remote port Advertised flow control mode
	 * @type fal_port_flow_control_mode_t
	 * @flags READ_ONLY
	 **/
	FAL_PORT_ATTR_REMOTE_ADVERTISED_FLOW_CONTROL_MODE,

	/**
	 * @brief Enable egress QoS marking on port
	 *
	 * Set map id = FAL_NULL_OBJECT_ID to remove map
	 * @type fal_object_t
	 * @flags CREATE_AND_SET
	 * @default FAL_NULL_OBJECT_ID
	 *
	 */
	FAL_PORT_ATTR_QOS_EGRESS_MAP_ID,

	/** @brief Enable/Disable SyncE on interface
	 *
	 * @type u8 - disable/enable
	 * @default - FAL_PORT_SYNCE_DISABLE
	 */
	FAL_PORT_ATTR_SYNCE_ADMIN_STATUS,

};

enum fal_port_hw_switching_t {
	FAL_PORT_HW_SWITCHING_DISABLE,
	FAL_PORT_HW_SWITCHING_ENABLE
};

enum fal_port_synce_admin_status_t {
	FAL_PORT_SYNCE_DISABLE,
	FAL_PORT_SYNCE_ENABLE
};

void fal_plugin_l2_new_port(unsigned int if_index,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list);

/**
 * @brief Get port attributes from interface if_index.
 *
 * @param[in] if_index The if_index of the interface
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return 0 on success. If an attribute in attr_list is
 *	   unsupported by the FAL plugin, it should return
 *	   an error.
 */
int fal_plugin_l2_get_attrs(unsigned int if_index,
			    uint32_t attr_count,
			    struct fal_attribute_t *attr_list);

/*
 * Update the attributes on interface if_index
 */
int fal_plugin_l2_upd_port(unsigned int if_index,
			   struct fal_attribute_t *attr);

/*
 * Delete the interface if_index
 */
void fal_plugin_l2_del_port(unsigned int if_index);

/* No attributes */

/*
 * Add the address to the interface if_index
 */
void fal_plugin_l2_new_addr(unsigned int if_index,
			    const struct rte_ether_addr *addr,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list);

/*
 * Update the addr on the interface if_index
 */
void fal_plugin_l2_upd_addr(unsigned int if_index,
			    const struct rte_ether_addr *addr,
			    struct fal_attribute_t *attr);

/*
 * Delete the address on the interface if_index
 */
void fal_plugin_l2_del_addr(unsigned int if_index,
			    const struct rte_ether_addr *addr);

/* Router interface operations */

enum fal_router_interface_attr_t {
	/**
	 * @brief Router Interface IF Index
	 *
	 * @flags MANDATORY_ON_CREATE
	 * @type  uint32_t
	 */
	FAL_ROUTER_INTERFACE_ATTR_IFINDEX,
	/**
	 * @brief Router Interface parent IF Index
	 *
	 * @flags MANDATORY_ON_CREATE
	 * @type  uint32_t
	 */
	FAL_ROUTER_INTERFACE_ATTR_PARENT_IFINDEX,
	/**
	 * @brief VRF ID
	 *
	 * @flags MANDATORY_ON_CREATE
	 * @type  uint32_t
	 */
	FAL_ROUTER_INTERFACE_ATTR_VRF_ID,
	/**
	 * @brief Associated Vlan
	 *
	 * @flags CREATE_AND_SET
	 * @type  uint16_t
	 */
	FAL_ROUTER_INTERFACE_ATTR_VLAN_ID,
	/**
	 * @brief MTU
	 *
	 * @flags CREATE_AND_SET
	 * @type uint16_t
	 * @default 1500
	 */
	FAL_ROUTER_INTERFACE_ATTR_MTU,
	/**
	 * @brief MAC Address
	 *
	 * @flags CREATE_AND_SET
	 * @type  eth_addr
	 */
	FAL_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS,
	/**
	 * @brief Admin IPv4 state
	 *
	 * If an L3 interface is admin disabled or IPv4 forwarding is explicitly
	 * disabled then the FAL plugin is expected to set this to false. This
	 * is then used in hardware forwarding pipeline to disallow L3 IPv4
	 * lookups for transit traffic.
	 *
	 * @type bool
	 * @flags CREATE_AND_SET
	 * @default true
	 */
	FAL_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE,
	/**
	 * @brief Admin IPv6 state
	 *
	 * If an L3 interface is admin disabled or IPv6 forwarding is explicitly
	 * disabled then the FAL plugin is expected to set this to false. This
	 * is then used in hardware forwarding pipeline to disallow L3 IPv6
	 * lookups for transit traffic.
	 *
	 * @type bool
	 * @flags CREATE_AND_SET
	 * @default true
	 */
	FAL_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE,
	/**
	 * @brief Admin MPLS state
	 *
	 * If an L3 interface is admin disabled or MPLS forwarding is explicitly
	 * disabled then the FAL plugin is expected to set this to false. This
	 * is then used in hardware forwarding pipeline to disallow L3 MPLS
	 * lookups for transit traffic.
	 *
	 * @type bool
	 * @flags CREATE_AND_SET
	 * @default true
	 */
	FAL_ROUTER_INTERFACE_ATTR_ADMIN_MPLS_STATE,
	/**
	 * @brief Bind point for IPv4 ingress ACL object
	 *
	 * Bind an ingress IPv4 ACL table to (or remove it from) an
	 * L3 interface.  Ingress filtering is enabled (or updated) by
	 * assigning a valid ACL table; similarly ingress filtering
	 * is disabled by assigning FAL_NULL_OBJECT_ID
	 *
	 * @type fal_acl_table_t
	 * @flags CREATE_AND_SET
	 * @allownull true
	 * @default FAL_NULL_OBJECT_ID
	 */
	FAL_ROUTER_INTERFACE_ATTR_V4_INGRESS_ACL,
	/**
	 * @brief Bind point for IPv4 egress ACL object
	 *
	 * Bind an egress IPv4 ACL table to (or remove it from) an
	 * L3 interface.  Egress filtering is enabled (or updated) by
	 * assigning a valid ACL table; similarly egress filtering
	 * is disabled by assigning FAL_NULL_OBJECT_ID
	 *
	 * @type fal_acl_table_t
	 * @flags CREATE_AND_SET
	 * @allownull true
	 * @default FAL_NULL_OBJECT_ID
	 */
	FAL_ROUTER_INTERFACE_ATTR_V4_EGRESS_ACL,
	/**
	 * @brief Bind point for IPv6 ingress ACL object
	 *
	 * Bind an ingress IPv6 ACL table to (or remove it from) an
	 * L3 interface.  Ingress filtering is enabled (or updated) by
	 * assigning a valid ACL table; similarly ingress filtering
	 * is disabled by assigning FAL_NULL_OBJECT_ID
	 *
	 * @type fal_acl_table_t
	 * @flags CREATE_AND_SET
	 * @allownull true
	 * @default FAL_NULL_OBJECT_ID
	 */
	FAL_ROUTER_INTERFACE_ATTR_V6_INGRESS_ACL,
	/**
	 * @brief Bind point for IPv6 egress ACL object
	 *
	 * Bind an egress IPv6 ACL ruleset to (or remove it from) an
	 * L3 interface.  Egress filtering is enabled (or updated) by
	 * assigning a valid ACL ruleset; similarly egress filtering
	 * is disabled by assigning FAL_NULL_OBJECT_ID
	 *
	 * @type fal_acl_table_t
	 * @flags CREATE_AND_SET
	 * @allownull true
	 * @default FAL_NULL_OBJECT_ID
	 */
	FAL_ROUTER_INTERFACE_ATTR_V6_EGRESS_ACL,
	/**
	 * @brief IPv4 mcast enable
	 *
	 * If an L3 interface is not enabled for IPv4 PIM or IPv4
	 * multicast routing is not explicitly enabled then the FAL
	 * plugin is expected to set this to false. This is then used
	 * in hardware forwarding pipeline to disallow L3 IPv4 mcast
	 * lookups for transit traffic.
	 *
	 * @type bool
	 * @flags CREATE_AND_SET
	 * @default true
	 */
	FAL_ROUTER_INTERFACE_ATTR_V4_MCAST_ENABLE,
	/**
	 * @brief IPv6 mcast enable
	 *
	 * If an L3 interface is not enabled for IPv6 PIM or IPv6
	 * multicast routing is not explicitly enabled then the FAL
	 * plugin is expected to set this to false. This is then used
	 * in hardware forwarding pipeline to disallow L3 IPv6 mcast
	 * lookups for transit traffic.
	 *
	 * @type bool
	 * @flags CREATE_AND_SET
	 * @default true
	 */
	FAL_ROUTER_INTERFACE_ATTR_V6_MCAST_ENABLE,

	/**
	 * @brief Egress QOS Marking map
	 *
	 * If an egress map is applied on a L3 interface then the
	 * traffic sent out of the interface is subjected to egress
	 * marking and will be sent out with the remarked values
	 * corresponding to the egress map.
	 *
	 * @type fal_object_t
	 * @flags CREATE_AND_SET
	 * @default FAL_NULL_OBJECT_ID
	 */
	FAL_ROUTER_INTERFACE_ATTR_EGRESS_QOS_MAP,
	FAL_ROUTER_INTERFACE_ATTR_MAX
};

/**
 * @brief Router interface stat counter IDs in
 * fal_plugin_get_router_interface_stats() call
 */
enum fal_router_interface_stat_t {
	FAL_ROUTER_INTERFACE_STAT_MIN,

	/** Ingress byte stat count */
	FAL_ROUTER_INTERFACE_STAT_IN_OCTETS = FAL_ROUTER_INTERFACE_STAT_MIN,

	/** Ingress packet stat count */
	FAL_ROUTER_INTERFACE_STAT_IN_PACKETS,

	FAL_ROUTER_INTERFACE_STAT_IN_MAX,

	/** Egress byte stat count */
	FAL_ROUTER_INTERFACE_STAT_OUT_OCTETS = FAL_ROUTER_INTERFACE_STAT_IN_MAX,

	/** Egress packet stat count */
	FAL_ROUTER_INTERFACE_STAT_OUT_PACKETS,

	FAL_ROUTER_INTERFACE_STAT_MAX,
};

/**
 * @brief Create router interface
 *
 * @param[in]  attr_count Number of attributes
 * @param[in]  attr_list  Array of attributes
 * @param[out] obj        Object id for router intf, non-zero on success
 *
 * @return 0 on success, error code for failure
 */
int fal_plugin_create_router_interface(uint32_t attr_count,
				       struct fal_attribute_t *attr_list,
				       fal_object_t *obj);

/**
 * @brief Delete router interface
 *
 * @param[in]  obj Object id for router intf
 *
 * @return 0 on success, error code for failure
 */
int fal_plugin_delete_router_interface(fal_object_t obj);

/**
 * @brief Set attributes on the router interface
 *
 * @param[in] obj  Object id for router intf
 * @param[in] attr Array of Attribute
 *
 * @return 0 on success.
 */
int
fal_plugin_set_router_interface_attr(fal_object_t obj,
				     const struct fal_attribute_t *attr_list);

/**
 * @brief Get router interface stats
 *
 * @param[in]  obj        Router interface object ID
 * @param[in]  cntr_count Number of counters in the array
 * @param[in]  cntr_ids   Specifies the array of counter IDs
 * @param[out] cntrs      Counters array of resulting counter values
 *
 * @return 0 on success, error code for failure
 */
int fal_plugin_get_router_interface_stats(
	fal_object_t obj, uint32_t cntr_count,
	const enum fal_router_interface_stat_t *cntr_ids,
	uint64_t *cntrs);

/**
 * @brief Dump router interface
 *
 * @param[in]  obj Object id for router intf
 * @param[inout] json JSON writer object
 */
void fal_plugin_dump_router_interface(fal_object_t obj, json_writer_t *wr);

/* Tunnel operations */

/**
 * @brief Defines tunnel type
 */
enum fal_tunnel_type_t {
	/* IPv4/v6 over GRE IPv4 */
	FAL_TUNNEL_TYPE_L3INIP_GRE,
	/* IPv4/v6 over GRE IPv6 */
	FAL_TUNNEL_TYPE_L3INIP6_GRE,
};

/**
 * @brief Defines tunnel TTL mode
 */
enum fal_tunnel_ttl_mode_t {
	/**
	 * @brief The uniform model
	 *
	 * Where the TTL field is preserved end-to-end by copying into the outer
	 * header on encapsulation and copying from the outer header on
	 * decapsulation.
	 */
	FAL_TUNNEL_TTL_MODE_UNIFORM_MODEL,

	/**
	 * @brief The pipe model
	 *
	 * Where the outer header is independent of that in the inner header so
	 * it hides the TTL field of the inner header from any interaction
	 * with nodes along the tunnel.
	 *
	 * TTL field is user-defined for outer header on encapsulation. TTL
	 * field of inner header remains the same on decapsulation.
	 */
	FAL_TUNNEL_TTL_MODE_PIPE_MODEL

};

/**
 * @brief Defines tunnel DSCP mode
 */
enum fal_tunnel_dscp_mode_t {
	/**
	 * @brief The uniform model
	 *
	 * Where the DSCP field is preserved end-to-end by copying into the
	 * outer header on encapsulation and copying from the outer header on
	 * decapsulation.
	 */
	FAL_TUNNEL_DSCP_MODE_UNIFORM_MODEL,

	/**
	 * @brief The pipe model
	 *
	 * Where the outer header is independent of that in the inner header so
	 * it hides the DSCP field of the inner header from any interaction
	 * with nodes along the tunnel.
	 *
	 * DSCP field is user-defined for outer header on encapsulation. DSCP
	 * field of inner header remains the same on decapsulation.
	 */
	FAL_TUNNEL_DSCP_MODE_PIPE_MODEL
};

enum fal_tunnel_attr_t {

	/* Tunnel encap attributes */

	/**
	 * @brief Tunnel local IP
	 *
	 * @type fal_ip_address_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_TUNNEL_ATTR_LOCAL_IP,

	/**
	 * @brief Tunnel remote IP
	 *
	 * @type fal_ip_address_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_TUNNEL_ATTR_REMOTE_IP,

	/**
	 * @brief Tunnel type
	 *
	 * @type fal_tunnel_type_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_TUNNEL_ATTR_TYPE,

	/**
	 * @brief Tunnel underlay interface if_index
	 *
	 * Underlay interface to provide transport reachability for the tunnel.
	 *
	 * @type uint32_t
	 */
	FAL_TUNNEL_ATTR_UNDERLAY_INTERFACE,

	/**
	 * @brief Tunnel Next-Hop
	 *
	 * Tunnel nexthop on the underlay network.
	 * In cases where the Tunnel End Point is an attached nexthop itself,
	 * this attribute is expected to be set to IPADDR_ANY (0.0.0.0)
	 *
	 * @type fal_ip_address_t
	 */
	FAL_TUNNEL_ATTR_NEXTHOP,

	/**
	 * @brief Tunnel overlay interface if_index
	 *
	 * Overlay interface is router interface.
	 *
	 * @type uint32_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_TUNNEL_ATTR_OVERLAY_INTERFACE,

	/** ENCAP attributes */

	/**
	 * @brief Tunnel TTL mode
	 *
	 * @type fal_tunnel_ttl_mode_t
	 * @flags MANDATORY_ON_CREATE
	 */
	FAL_TUNNEL_ATTR_ENCAP_TTL_MODE,

	/**
	 * @brief Tunnel TTL value
	 *
	 * @type uint8_t
	 * @flags MANDATORY_ON_CREATE
	 * @condition FAL_TUNNEL_ATTR_ENCAP_TTL_MODE ==
	 *                                   FAL_TUNNEL_TTL_MODE_PIPE_MODEL
	 */
	FAL_TUNNEL_ATTR_ENCAP_TTL_VAL,

	/**
	 * @brief Tunnel DSCP mode (pipe or uniform model)
	 *
	 * @type fal_tunnel_dscp_mode_t
	 * @condition MANDATORY_ON_CREATE
	 */
	FAL_TUNNEL_ATTR_ENCAP_DSCP_MODE,

	/**
	 * @brief Tunnel DSCP value (6 bits)
	 *
	 * @type uint8_t
	 * @condition FAL_TUNNEL_ATTR_ENCAP_DSCP_MODE ==
	 *                                  SAI_TUNNEL_DSCP_MODE_PIPE_MODEL
	 */
	FAL_TUNNEL_ATTR_ENCAP_DSCP_VAL,
};

/**
 * @brief Create tunnel
 *
 * @param[in]  attr_count Number of attributes
 * @param[in]  attr_list  Array of attributes
 * @param[out] obj        Object ID of the tunnel
 *
 * @return 0 on success, error code for failure
 */
int fal_plugin_create_tunnel(uint32_t attr_count,
			     struct fal_attribute_t *attr_list,
			     fal_object_t *obj);

/**
 * @brief Delete tunnel
 *
 * @param[in] obj Object ID of the tunnel
 *
 * @return 0 on success, error code on failure
 */
int fal_plugin_delete_tunnel(fal_object_t obj);

/**
 * @brief Set tunnel attribute
 *
 * @param[in] obj       Object ID of the tunnel
 * @param[in] nattrs    Number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return 0 on success, error code on failure
 */
int fal_plugin_set_tunnel_attr(fal_object_t obj, uint32_t nattrs,
			       const struct fal_attribute_t *attr_list);

/*
 * Bridge port operations
 */

enum fal_br_port_attr_t {
	FAL_BRIDGE_PORT_ATTR_STATE,		/* .u8 */
	FAL_BRIDGE_PORT_ATTR_PORT_VLAN_ID,	/* .u16 */
	FAL_BRIDGE_PORT_ATTR_TAGGED_VLANS,	/* .ptr */
	FAL_BRIDGE_PORT_ATTR_UNTAGGED_VLANS,	/* .ptr */
};

/*
 * Add child_ifindex to bridge_ifindex
 */
void fal_plugin_br_new_port(unsigned int bridge_ifindex,
			    unsigned int child_ifindex,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list);

/*
 * Update attributes on the interface child_ifindex
 */
void fal_plugin_br_upd_port(unsigned int child_ifindex,
			    struct fal_attribute_t *attr);

/*
 * Remove the interface child_ifindex from interface bridge_ifindex
 */
void fal_plugin_br_del_port(unsigned int bridge_ifindex,
			    unsigned int child_ifindex);

/* LAG operations */

enum fal_lag_attr_t {
	/**
	 * @brief Start of LAG attributes
	 */
	FAL_LAG_ATTR_START,

	/**
	 * @brief LAG port list
	 *
	 * @flags READ_ONLY
	 * @type fal_object_list_t
	 * @objects FAL_OBJECT_TYPE_LAG_MEMBER
	 */
	FAL_LAG_ATTR_PORT_LIST = FAL_LAG_ATTR_START,

	FAL_LAG_ATTR_MAX
};

enum fal_lag_member_attr_t {
	/**
	 * @brief Start of LAG member attributes
	 */
	FAL_LAG_MEMBER_ATTR_START,

	/**
	 * @brief LAG ID
	 *
	 * @type fal_object_id_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 * @objects FAL_OBJECT_TYPE_LAG
	 */
	FAL_LAG_MEMBER_ATTR_LAG_ID = FAL_LAG_MEMBER_ATTR_START,

	/**
	 * @brief LAG member port IF Index
	 *
	 * @type uint32_t
	 * @flags MANDATORY_ON_CREATE
	 */
	FAL_LAG_MEMBER_ATTR_IFINDEX,

	/**
	 * @brief Disable traffic distribution to this port as part of LAG
	 *
	 * @flags CREATE_AND_SET
	 * @type bool
	 * @default false
	 */
	FAL_LAG_MEMBER_ATTR_EGRESS_DISABLE,

	/**
	 * @brief Disable traffic collection from this port as part of LAG
	 *
	 * @flags CREATE_AND_SET
	 * @type bool
	 * @default false
	 */
	FAL_LAG_MEMBER_ATTR_INGRESS_DISABLE,

	FAL_LAG_MEMBER_ATTR_MAX
};

/**
 * @brief Create a LAG interface
 *
 * @param[in]  attr_count Number of attributes
 * @param[in]  attr_list  Array of attributes
 * @param[out] obj        Object id for LAG intf, non-zero on success
 *
 * @return 0 on success, error code for failure
 */
int fal_plugin_create_lag(uint32_t attr_count,
			  struct fal_attribute_t *attr_list,
			  fal_object_t *obj);

/**
 * @brief Delete a LAG interface
 *
 * @param[in]  obj Object id for the LAG
 *
 * @return 0 on success, error code for failure
 */
int fal_plugin_delete_lag(fal_object_t obj);

/**
 * @brief Set attributes on the LAG
 *
 * @param[in] obj    Object id for the LAG
 * @param[in] nattrs Number of attributes
 * @param[in] attr   Array of Attribute
 *
 * @return 0 on success.
 */
int
fal_plugin_set_lag_attr(fal_object_t obj, uint32_t nattrs,
			const struct fal_attribute_t *attr_list);

/**
 * @brief Get attributes fn the LAG
 *
 * @param[in] obj    Object id for the LAG
 * @param[in] nattrs Number of attributes
 * @param[in] attr   Array of Attribute
 *
 * @return 0 on success.
 */
int
fal_plugin_get_lag_attr(fal_object_t obj, uint32_t nattrs,
			struct fal_attribute_t *attr_list);

/**
 * @brief Dump LAG interface
 *
 * @param[in]    obj  Object id for the LAG
 * @param[inout] json JSON writer object
 */
void fal_plugin_dump_lag(fal_object_t obj, json_writer_t *wr);

/* LAG member functions */

/**
 * @brief Create a LAG member
 *
 * @param[in]  attr_count Number of attributes
 * @param[in]  attr_list  Array of attributes
 * @param[out] obj        Object id for LAG member
 *
 * @return 0 on success, error code for failure
 */
int fal_plugin_create_lag_member(uint32_t attr_count,
				 struct fal_attribute_t *attr_list,
				 fal_object_t *obj);

/**
 * @brief Delete a LAG member
 *
 * @param[in] obj Object id for LAG member
 *
 * @return 0 on success, error code for failure
 */
int fal_plugin_delete_lag_member(fal_object_t obj);

/**
 * @brief Set LAG member's attribute
 *
 * @param[in]  obj  Object id of the LAG member
 * @param[in]  attr Attribute to be updated
 *
 * @return 0 on success, error code for failure
 */
int fal_plugin_set_lag_member_attr(fal_object_t obj,
				   const struct fal_attribute_t *attr);

/**
 * @brief Get LAG member's attributea
 *
 * @param[in]     obj        Object id of the LAG member
 * @param[in]     attr_count Number of attributes
 * @param[inout]  attr_list  List of attributes
 *
 * @return 0 on success, error code for failure
 */
int fal_plugin_get_lag_member_attr(fal_object_t obj,
				   uint32_t attr_count,
				   struct fal_attribute_t *attr_list);

/*
 * Bridge neighbor operations
 */

enum fal_br_neigh_entry_attr_t {
	FAL_BRIDGE_NEIGH_ATTR_STATE,		/* .u16 */
	FAL_BRIDGE_NEIGH_ATTR_AGEING,		/* .u32 */
};

/*
 * Add layer 2 destination to the interface child_ifindex and vlanid.
 */
void fal_plugin_br_new_neigh(unsigned int child_ifindex,
			     uint16_t vlanid,
			     const struct rte_ether_addr *dst,
			     uint32_t attr_count,
			     const struct fal_attribute_t *attr_list);

/*
 * Update attribute layer 2 destination on the interface child_ifindex
 * and vlanid.
 */
void fal_plugin_br_upd_neigh(unsigned int child_ifindex,
			     uint16_t vlanid,
			     const struct rte_ether_addr *dst,
			     struct fal_attribute_t *attr);

/*
 * Delete layer 2 destination on the interface child_ifindex and vlanid.
 */
void fal_plugin_br_del_neigh(unsigned int child_ifindex,
			     uint16_t vlanid,
			     const struct rte_ether_addr *dst);

/**
 * @brief Iterator function for walk of bridge neighbours
 *
 * @param[in] vlanid VLAN
 * @param[in] dst Address
 * @param[in] child_ifindex Interface index
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list List of all available attributes
 * @param[in] arg Opaque caller context
 *
 * @return 0 on success. Negative errno on failure, terminating walk
 */
typedef int (*fal_br_walk_neigh_fn)(uint16_t vlanid,
				    const struct rte_ether_addr *dst,
				    unsigned int child_ifindex,
				    uint32_t attr_count,
				    const struct fal_attribute_t *attr_list,
				    void *arg);

/**
 * @brief Walk selected number of bridge neighbours
 *
 * @param[in] bridge_ifindex Index of bridge interface to walk neighbours for
 * @param[in] vlanid VLAN to match
 * @param[in] dst Destination address to match
 * @param[in] child_ifindex Index of child interface to match
 * @param[in] cb Callback function called for each neighbour walked
 * @param[in] arg Opaque caller context
 *
 * @return 0 on success. Negative errno on failure.
 */
int fal_plugin_br_walk_neigh(unsigned int bridge_ifindex,
			     uint16_t vlanid,
			     const struct rte_ether_addr *dst,
			     unsigned int child_ifindex,
			     fal_br_walk_neigh_fn cb,
			     void *arg);

enum fal_br_fdb_flush_entry_type_t {
	FAL_BRIDGE_FDB_FLUSH_TYPE_ALL,
	FAL_BRIDGE_FDB_FLUSH_TYPE_DYNAMIC,
	FAL_BRIDGE_FDB_FLUSH_TYPE_STATIC
};

/*
 * The flush attributes can be combined to restrict or expand the
 * range of MAC addresses to be removed. For example, VLAN+PORT will
 * remove any/all MAC addresses associated with the indicated VLAN ID
 * on the indicated switch port. Specifying just a PORT will remove
 * any/all MAC addresses associated with the indicated switch port.
 *
 * Some combinations do nothing, for example STATIC+VLAN (there is no
 * configuration mechanism to produce a static VLAN MAC address).
 */
enum fal_br_fdb_flush_attr_t {
	/*
	 * Flush a specific MAC address entry. The address may be
	 * restricted by the type and/or port qualifiers.
	 */
	FAL_BRIDGE_FDB_FLUSH_MAC,

	/*
	 * Flush all dynamic MAC addresses associated with a specific
	 * VLAN ID. The set of addresses may be restricted to a
	 * specific port.
	 */
	FAL_BRIDGE_FDB_FLUSH_VLAN,

	/*
	 * Limit the flush action to a particular class of MAC
	 * address. In the absence of this attribute, all addresses
	 * are removed.
	 */
	FAL_BRIDGE_FDB_FLUSH_TYPE,

	/*
	 * Limit the flush action to a specific port. In the absence
	 * of this attribute, all ports are considered.
	 */
	FAL_BRIDGE_FDB_FLUSH_PORT
};

/*
 * Delete one or more MAC addresses from the bridge forward database
 * (FDB). In the absence of any attributes, all MAC addresses are
 * removed.
 *
 * Note that fal_plugin_br_flush_neigh(TYPE=STATIC, MAC) would be the
 * equivalent of the above fal_plugin_br_del_neigh() function.
 */
void fal_plugin_br_flush_neigh(unsigned int bridge_ifindex,
			       uint32_t attr_count,
			       const struct fal_attribute_t *attr);

/*
 * VLAN counter IDs
 *
 * modeled on sai_vlan_stat_t
 */
enum fal_vlan_stat_type {
	FAL_VLAN_STAT_IN_OCTETS,
	FAL_VLAN_STAT_IN_PACKETS,
	FAL_VLAN_STAT_IN_UCAST_PKTS,
	FAL_VLAN_STAT_IN_NON_UCAST_PKTS,
	FAL_VLAN_STAT_IN_DISCARDS,
	FAL_VLAN_STAT_IN_ERRORS,
	FAL_VLAN_STAT_RX_MAX,
	FAL_VLAN_STAT_OUT_OCTETS = FAL_VLAN_STAT_RX_MAX,
	FAL_VLAN_STAT_OUT_PACKETS,
	FAL_VLAN_STAT_OUT_UCAST_PKTS,
	FAL_VLAN_STAT_OUT_NON_UCAST_PKTS,
	FAL_VLAN_STAT_OUT_DISCARDS,
	FAL_VLAN_STAT_OUT_ERRORS,
	FAL_VLAN_STAT_MAX
};

int fal_plugin_vlan_get_stats(uint16_t vlan, uint32_t num_cntrs,
			      const enum fal_vlan_stat_type *cntr_ids,
			      uint64_t *cntrs);

int fal_plugin_vlan_clear_stats(uint16_t vlan, uint32_t num_cntrs,
				const enum fal_vlan_stat_type *cntr_ids);


enum fal_stp_attr_t {
	/*
	 * STP instance number: 0..STP_INST_MAX
	 */
	FAL_STP_ATTR_INSTANCE = 1,          /* .u8 */

	/*
	 * MSTP instance identifier: 1..4094
	 */
	FAL_STP_ATTR_MSTI,                  /* .u16 */

	/*
	 * MSTP vlans assigned to this instance
	 */
	FAL_STP_ATTR_MSTP_VLANS             /* .ptr */
};

enum fal_stp_port_attr_t {
	/*
	 * STP instance object as returned by fal_stp_create()
	 */
	FAL_STP_PORT_ATTR_INSTANCE = 1,     /* .objid */

	/*
	 * STP port state - enum bridge_ifstate
	 */
	FAL_STP_PORT_ATTR_STATE,            /* .u8 */

	/*
	 * Hardware port forward state
	 */
	FAL_STP_PORT_ATTR_HW_FORWARDING    /* .booldata */
};

int fal_plugin_stp_create(unsigned int bridge_ifindex,
			  uint32_t attr_count,
			  const struct fal_attribute_t *attr_list,
			  fal_object_t *obj);
int fal_plugin_stp_delete(fal_object_t obj);
int fal_plugin_stp_set_attribute(fal_object_t obj,
				 const struct fal_attribute_t *attr);
int fal_plugin_stp_get_attribute(fal_object_t obj, uint32_t attr_count,
				 struct fal_attribute_t *attr_list);

/*
 * Since the L2/BR plugins do not produce a port object/handle, the
 * STP handle is passed as an attribute (rather than being a child of
 * the port handle). Thus two attributes are passed - STP instance and
 * an "action" attribute (see above).
 */
int fal_plugin_stp_set_port_attribute(unsigned int child_ifindex,
				      uint32_t attr_count,
				      const struct fal_attribute_t *attr_list);
int fal_plugin_stp_get_port_attribute(unsigned int child_ifindex,
				      uint32_t attr_count,
				      struct fal_attribute_t *attr_list);

/* Global switch operations */

enum fal_switch_attr_t {
	/**
	 * @brief Action for Packets that result in ICMP Redirect
	 *
	 * @type .u32 fal_packet_action_t
	 * @flags CREATE_AND_SET
	 * @default FAL_PACKET_ACTION_TRAP
	 */
	FAL_SWITCH_ATTR_RX_ICMP_REDIR_ACTION,

	/**
	 * @brief Create, update, or remove a CPP rate limiter
	 *
	 * @type fal_object_t
	 * @flags CREATE_AND_SET
	 * @default FAL_NULL_OBJECT_ID
	 */
	FAL_SWITCH_ATTR_CPP_RATE_LIMITER,

	/**
	 * @brief Commit ACL changes to hardware
	 *
	 * @type .u32 (dummy counter)
	 * @flags CREATE_AND_SET
	 * @default 0
	 */
	FAL_SWITCH_ATTR_ACL_COMMIT,

	/**
	 * @brief Does the platform always punt PVST frames?
	 *
	 * @type bool
	 * @flags READ_ONLY
	 * @default false
	 */
	FAL_SWITCH_ATTR_PUNT_PVST,

	/**
	 * @brief Maximum allocated bundle buffer descriptors
	 *
	 * @type .u32
	 * @flags READ_ONLY
	 * @default false
	 */
	FAL_SWITCH_ATTR_MAX_BUF_DESCRIPTOR,

	/**
	 * @brief The maximum burst size supported by the platform
	 *
	 * @type .u32
	 * @flags READ_ONLY
	 * @default 0
	 */
	FAL_SWITCH_ATTR_MAX_BURST_SIZE,

	/**
	 * @brief Set Switch BFD session state change event notification
	 * callback function passed to the adapter.
	 *
	 * Use fal_bfd_session_state_change_notification_fn as notification
	 * function.
	 *
	 * @type .ptr
	 * @flags CREATE_AND_SET
	 * @default NULL
	 */
	FAL_SWITCH_ATTR_BFD_SESSION_STATE_NOTIFY,

	/**
	 * @brief Max number of BFD IPv4 session supported in on-chip BFD
	 *
	 * @type .u32
	 * @flags READ_ONLY
	 */
	FAL_SWITCH_ATTR_MAX_BFD_IPV4_SESSION,

	/**
	 * @brief Max number of BFD IPv6 session supported in on-chip BFD
	 *
	 * @type .u32
	 * @flags READ_ONLY
	 */
	FAL_SWITCH_ATTR_MAX_BFD_IPV6_SESSION,

	/**
	 * @brief Max number of UDP source ports supported in on-chip IPv4 BFD
	 *
	 * @type .u32
	 * @flags READ_ONLY
	 */
	FAL_SWITCH_ATTR_MAX_BFD_IPV4_UDP_SRC_PORT_CNT,

	/**
	 * @brief Max number of UDP source ports supported in on-chip IPv6 BFD
	 *
	 * @type .u32
	 * @flags READ_ONLY
	 */
	FAL_SWITCH_ATTR_MAX_BFD_IPV6_UDP_SRC_PORT_CNT,

	/**
	 * @brief BFD IPv4 hw session running mode
	 *
	 * @type enum fal_bfd_hw_mode
	 * @flags READ_ONLY
	 */
	FAL_SWITCH_ATTR_BFD_IPV4_HW_MODE,

	/**
	 * @brief BFD IPv6 hw session running mode
	 *
	 * @type enum fal_bfd_hw_mode
	 * @flags READ_ONLY
	 */
	FAL_SWITCH_ATTR_BFD_IPV6_HW_MODE,

	/**
	 * @brief Max number of unique interval values supported in the HW
	 * for BFD sessions
	 *
	 * @type  .u32
	 * @flags READ_ONLY
	 */
	FAL_SWITCH_ATTR_MAX_BFD_INTERVAL_CNT,

	/**
	 * @brief SyncE Lock clock to interface
	 *
	 * @type u32 - ifindex for interface for clk lock
	 * @default 0
	 */
	FAL_SWITCH_ATTR_SYNCE_CLOCK_SOURCE_PORT,

};

/*
 * Set switch global parameters
 */
int fal_plugin_set_switch_attribute(const struct fal_attribute_t *attr);

/*
 * Get switch global parameter values
 */
int fal_plugin_get_switch_attribute(uint32_t attr_count,
				    struct fal_attribute_t *attr_list);

/* IP operations */

enum fal_address_entry_attr_t {
	FAL_ADDR_ENTRY_ATTR_PREFIXLEN,	/* .u8 -- network prefix length */
	FAL_ADDR_ENTRY_ATTR_BROADCAST,	/* .ipaddr -- broadcast, if any */
	FAL_ADDR_ENTRY_ATTR_SCOPE,	/* .u8 -- address scope */
};

/*
 * Add the IP address to the interface if_index
 */
void fal_plugin_ip_new_addr(unsigned int if_index,
			    struct fal_ip_address_t *ipaddr,
			    uint8_t prefixlen,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list);

/*
 * Update the IP address on the interface if_index
 */
void fal_plugin_ip_upd_addr(unsigned int if_index,
			    struct fal_ip_address_t *ipaddr,
			    uint8_t prefixlen,
			    struct fal_attribute_t *attr);

/*
 * Delete the IP address on the interface if_index
 */
void fal_plugin_ip_del_addr(unsigned int if_index,
			    struct fal_ip_address_t *ipaddr,
			    uint8_t prefixlen);


/*
 * IP neighbor operations
 */

enum fal_neighbor_entry_attr_t {
	FAL_NEIGH_ENTRY_ATTR_DST_MAC_ADDRESS,	/* .mac */
	FAL_NEIGH_ENTRY_ATTR_STATE,		/* .u16 -- deprecated */
	FAL_NEIGH_ENTRY_ATTR_NTF_FLAGS,		/* .u8 -- deprecated */

	/**
	 * @brief Indication of whether neighbour has been used
	 *
	 * If a neighbour entry gets used for forwarding and supports
	 * detection of this, then the FAL plugin is expected to set
	 * this to true. The application can then query this
	 * periodically and clear it, enabling it to detect whether
	 * the neighbour entry has been used in the last period and
	 * thus to control the state machine for the neighbour
	 * resolution protocol.
	 *
	 * @type bool
	 * @flags CREATE_AND_SET
	 * @default false
	 */
	FAL_NEIGH_ENTRY_ATTR_USED,
};

/**
 * @brief Create an IP neighbor for address on interface if_index
 *
 * @param[in] if_index Index of interface to add neighbour to
 * @param[in] ipaddr Address of neighbour to add
 * @param[in] attr_count Count of the attributes
 * @param[in] attr_list List of attributes
 *
 * @return 0 on success. Negative errno on failure.
 */
int fal_plugin_ip_new_neigh(unsigned int if_index,
			    struct fal_ip_address_t *ipaddr,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list);

/**
 * @brief Update an IP neighbor
 *
 * @param[in] if_index Index of interface to update neighbour on
 * @param[in] ipaddr Address of neighbour to update
 * @param[in] attr Attribute to update
 *
 * @return 0 on success. Negative errno on failure.
 */
int fal_plugin_ip_upd_neigh(unsigned int if_index,
			    struct fal_ip_address_t *ipaddr,
			    struct fal_attribute_t *attr);

/**
 * @brief Query attributes for an IP neighbor
 *
 * @param[in] if_index Index of interface for neighbour to query
 * @param[in] ipaddr Address of neighbour to query
 * @param[in] attr_count Count of the attributes
 * @param[in] attr_list List of attributes to query
 *
 * @return 0 on success. Negative errno on failure.
 */
int fal_plugin_ip_get_neigh_attrs(unsigned int if_index,
				  struct fal_ip_address_t *ipaddr,
				  uint32_t attr_count,
				  struct fal_attribute_t *attr_list);

/**
 * @brief Delete an IP neighbor for address on interface if_index
 *
 * @param[in] if_index Index of interface to delete neighbour on
 * @param[in] ipaddr Address of neighbour to delete
 *
 * @return 0 on success. Negative errno on failure.
 */
int fal_plugin_ip_del_neigh(unsigned int if_index,
			    struct fal_ip_address_t *ipaddr);

/**
 * @brief Dump info for an IP neighbor
 *
 * @param[in] if_index Index of interface to dump neighbour on
 * @param[in] ipaddr Address of neighbour to dump
 * @param[inout] json writer object
 */
void fal_plugin_ip_dump_neigh(unsigned int if_index,
			      struct fal_ip_address_t *ipaddr,
			      json_writer_t *wr);

/*
 * IP Route operations
 */

enum fal_packet_action_t {
	/** Drop the packet in hardware. */
	FAL_PACKET_ACTION_DROP,
	/** Forward the packet in hardware. */
	FAL_PACKET_ACTION_FORWARD,
	/**
	 * Copy the packet to software and drop the packet in
	 * hardware.
	 */
	FAL_PACKET_ACTION_TRAP,
};

enum fal_route_entry_attr_t {
	FAL_ROUTE_ENTRY_ATTR_NEXT_HOP_GROUP,	/* .objid */
	FAL_ROUTE_ENTRY_ATTR_PACKET_ACTION,	/* .u32 - fal_packet_action_t */
};

/* Route walk type enum */
enum fal_route_walk_type_t {
	FAL_ROUTE_WALK_TYPE_ALL,
};

/*
 * Route walk attributes
 */

enum fal_route_walk_attr_t {
	FAL_ROUTE_WALK_ATTR_VRFID,	/* .u32 - Vrf id */
	FAL_ROUTE_WALK_ATTR_TABLEID,	/* .u32 - Table id */
	FAL_ROUTE_WALK_ATTR_CNT,	/* .u32 - count */
	FAL_ROUTE_WALK_ATTR_FAMILY,	/* .u32 - fal_ip_addr_family_t */
	FAL_ROUTE_WALK_ATTR_TYPE,	/* .u32 - fal_route_walk_type_t */
};

int fal_plugin_ip_new_route(unsigned int vrf_id,
			    struct fal_ip_address_t *ipaddr,
			    uint8_t prefixlen,
			    uint32_t tableid,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list);

int fal_plugin_ip_upd_route(unsigned int vrf_id,
			    struct fal_ip_address_t *ipaddr,
			    uint8_t prefixlen,
			    uint32_t tableid,
			    struct fal_attribute_t *attr);

int fal_plugin_ip_del_route(unsigned int vrf_id,
			    struct fal_ip_address_t *ipaddr,
			    uint8_t prefixlen,
			    uint32_t tableid);

/**
 * @brief Query attributes for a route
 *
 * @param[in] vrf VRF ID of the route to be queried
 * @param[in] ipaddr Network address of the route to be queried
 * @param[in] prefixlen Prefix length of the route to be queried
 * @param[in] tableid Prefix length of the route to be queried
 * @param[in] attr_count Count of the attributes
 * @param[inout] attr_list List of attributes to query
 *
 * @return 0 on success. Negative errno on failure.
 */
int fal_plugin_ip_get_route_attrs(unsigned int vrf_id,
				  struct fal_ip_address_t *ipaddr,
				  uint8_t prefixlen,
				  uint32_t tableid,
				  uint32_t attr_count,
				  struct fal_attribute_t *attr_list);

/**
 * @brief Iterator function for walk of routes
 *
 * @param[in] prefix
 * @param[in] prefixlen
 * @param[in] attr_count attribute counts
 * @param[in] attr_list List of attributes
 * @param[in] arg Arg passed to the walker function
 * @return 0 on success. Negative errno on failure
 */
typedef int (*fal_plugin_route_walk_fn)(const struct fal_ip_address_t *pfx,
					uint8_t prefixlen,
					uint32_t attr_count,
					const struct
					fal_attribute_t *attr_list,
					void *arg);

/**
 * @brief Walk routes
 * @param[in] attr_cnt number of fal attributes
 * @param[in] attr_list list of FAL attributes
 * @param[inout] json writer object
 */
int fal_plugin_ip_walk_routes(fal_plugin_route_walk_fn cb,
			      uint32_t attr_cnt,
			      struct fal_attribute_t *attr_list,
			      void *arg);

/*
 * IP Nexthop Group operations
 */

/**
 * @brief Create a next hop group object
 *
 * @param[in] attr_count Count of the attributes
 * @param[in] attr_list List of attributes
 * @param[out] obj Object ID for the next-hop-group returned
 *
 * @return 0 on success. Negative errno on failure.
 */
int fal_plugin_ip_new_next_hop_group(uint32_t attr_count,
				     const struct fal_attribute_t *attr_list,
				     fal_object_t *obj);

/**
 * @brief In-place modify a next hop group object
 *
 * @param[in] obj Object ID of the next-hop-group to be updated
 * @param[in] attr Attributes to be updated
 *
 * @return 0 on success. Negative errno on failure.
 */
int fal_plugin_ip_upd_next_hop_group(fal_object_t obj,
				     const struct fal_attribute_t *attr);

/**
 * @brief Delete a next hop group object
 *
 * @param[in] obj Object ID of the next-hop-group to be deleted
 *
 * @return 0 on success. Negative errno on failure.
 */
int fal_plugin_ip_del_next_hop_group(fal_object_t obj);

/**
 * @brief Dump info for a next hop group object
 *
 * @param[in] obj Object ID of the next-hop-group to be dumped
 * @param[inout] json writer object
 */
void fal_plugin_ip_dump_next_hop_group(fal_object_t obj,
				       json_writer_t *wr);

enum fal_next_hop_group_attr_t {
	/**
	 * @brief Next hop group next hop count
	 *
	 * @type uint32_t
	 * @flags READ_ONLY
	 */
	FAL_NEXT_HOP_GROUP_ATTR_NEXTHOP_COUNT,	/* .u32 */
	/**
	 * @brief Next hop group next hop object
	 *
	 * @type fal_object_id_t
	 * @flags READ_ONLY
	 */
	FAL_NEXT_HOP_GROUP_ATTR_NEXTHOP_OBJECT,	/* .objid */
};
/**
 * @brief Query attributes for a next hop group object
 *
 * @param[in] obj Object ID of the next-hop-group to be queried
 * @param[in] attr_count Count of the attributes
 * @param[inout] attr_list List of attributes to query
 *
 * @return 0 on success. Negative errno on failure.
 */
int fal_plugin_ip_get_next_hop_group_attrs(fal_object_t obj,
					   uint32_t attr_count,
					   struct fal_attribute_t *attr_list);

enum fal_next_hop_configured_role {
	/**
	 * @brief Next hop is primary
	 *
	 * The next hop is a primary next hop and by default will
	 * contribute to forwarding.
	 */
	FAL_NEXT_HOP_CONFIGURED_ROLE_PRIMARY,

	/**
	 * @brief Next hop is standby
	 *
	 * The next hop is a standby next hop and won't contribute to
	 * forwarding, unless the corresponding primary next hop(s)
	 * become unusable. For PIC Edge primary/standbies the standby
	 * next hop(s) should only be used if all primary next hops
	 * are unusable.
	 */
	FAL_NEXT_HOP_CONFIGURED_ROLE_STANDBY,
};

enum fal_next_hop_usability {
	/**
	 * @brief Next hop is usable
	 *
	 * The next hop is usable and if a primary next hop can
	 * contribute to forwarding.
	 */
	FAL_NEXT_HOP_USABLE,
	/**
	 * @brief Next hop is unusable
	 *
	 * The next hop is not usable and shouldn't contribute to
	 * forwarding. If there is a backup next hop then forwarding
	 * should cut over to that if there are no usable primary
	 * nexthops.
	 */
	FAL_NEXT_HOP_UNUSABLE,
};

/*
 * IP Nexthop operations
 */
enum fal_next_hop_attr_t {
	/**
	 * @brief Next hop group id
	 *
	 * @type fal_object_id_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_NEXT_HOP_ATTR_NEXT_HOP_GROUP,	/* .objid */
	/**
	 * @brief Next hop interface's if index
	 *
	 * Deprecated in favour of FAL_NEXT_HOP_ATTR_ROUTER_INTF.
	 *
	 * @type uint32_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_NEXT_HOP_ATTR_INTF,			/* .u32 */
	/**
	 * @brief Next hop router interface
	 *
	 * @type fal_object_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 * @default FAL_NULL_OBJECT_ID
	 */
	FAL_NEXT_HOP_ATTR_ROUTER_INTF,		/* .objid */
	/**
	 * @brief Next hop IP address
	 *
	 * @type fal_ip_address_t
	 * @flags CREATE_ONLY
	 */
	FAL_NEXT_HOP_ATTR_IP,			/* .ipaddr */
	/**
	 * @brief Configured role for this next hop
	 *
	 * A next-hop group must not consist of only
	 * FAL_NEXT_HOP_CONFIGURED_ROLE_STANDBY nexthop(s).
	 *
	 * @type enum fal_next_hop_configured_role
	 * @flags CREATE_ONLY
	 * @default FAL_NEXT_HOP_CONFIGURED_ROLE_PRIMARY
	 */
	FAL_NEXT_HOP_ATTR_CONFIGURED_ROLE,			/* .i32 */
	/**
	 * @brief Next hop usability
	 *
	 * @type enum fal_next_hop_usability
	 * @flags CREATE_AND_SET
	 */
	FAL_NEXT_HOP_ATTR_USABILITY,			/* .i32 */
};

/**
 * @brief Bulk create next hops and add them to a next-hop-group
 *
 * @param[in] nh_count The number of new next hops
 * @param[in] attr_count An array of the count of attributes for each next-hop
 * @param[in] attr_list An array of the list of attributes for each next-hop
 * @param[out] obj_list List of object IDs returned, one for each next-hop
 *
 * @return 0 on success. Negative errno on failure.
 *
 * @note All next-hops must have the same
 * FAL_NEXT_HOP_ATTR_NEXT_HOP_GROUP attribute.
 */
int fal_plugin_ip_new_next_hops(uint32_t nh_count,
				const uint32_t *attr_count,
				const struct fal_attribute_t **attr_list,
				fal_object_t *obj_list);

/**
 * @brief In-place modify a next-hop
 *
 * @param[in] obj ID of next-hop object to be updated
 * @param[in] attr Attribute to be updated
 *
 * @return 0 on success. Negative errno on failure.
 */
int fal_plugin_ip_upd_next_hop(fal_object_t obj,
			       const struct fal_attribute_t *attr);

/**
 * @brief Bulk delete next hops and remove them from a next-hop-group
 *
 * @param[in] nh_count The number of next hops to be deleted and removed
 * @param[in] obj_list List of IDs for the next-hop objects to be deleted
 *
 * @return 0 on success. Negative errno on failure.
 *
 * @note All next-hops must belong to the same next-hop-group.
 */
int fal_plugin_ip_del_next_hops(uint32_t nh_count,
				const fal_object_t *obj_list);

/**
 * @brief Query attributes for a next hop object
 *
 * @param[in] obj Object ID of the next-hop to be queried
 * @param[in] attr_count Count of the attributes
 * @param[inout] attr_list List of attributes to query
 *
 * @return 0 on success. Negative errno on failure.
 */
int fal_plugin_ip_get_next_hop_attrs(fal_object_t obj,
				     uint32_t attr_count,
				     struct fal_attribute_t *attr_list);

/**
 * @brief Dump info for a next hop object
 *
 * @param[in] obj Object ID of the next-hop to be dumped
 * @param[inout] json writer object
 */
void fal_plugin_ip_dump_next_hop(fal_object_t obj,
				 json_writer_t *wr);

/*
 * IP Multicast Route operations
 */

/**
 * @brief IPMC entry type.
 */
enum fal_ipmc_entry_type_t {
	/** IPMC entry with type (S,G) */
	FAL_IPMC_ENTRY_TYPE_SG,

	/** IPMC entry with type (*,G) */
	FAL_IPMC_ENTRY_TYPE_XG,

};

/**
 * @brief Attribute ID for IPMC entry
 */
enum fal_ipmc_entry_attr_t {
	/**
	 * @brief Start of attributes
	 */
	FAL_IPMC_ENTRY_ATTR_START,

	/**
	 * @brief IPMC entry type
	 *
	 * @type fal_packet_action_t
	 * @flags MANDATORY_ON_CREATE | CREATE_AND_SET
	 */
	FAL_IPMC_ENTRY_ATTR_PACKET_ACTION = FAL_IPMC_ENTRY_ATTR_START,

	/**
	 * @brief IPMC entry output group id
	 *
	 * This attribute only takes effect when ATTR_PACKET_ACTION is set to
	 * FORWARD If the group has no member, packets will be discarded.
	 *
	 * @type fal_object_id_t
	 * @flags CREATE_AND_SET
	 * @objects FAL_OBJECT_TYPE_IPMC_GROUP
	 * @allownull true
	 * @default FAL_NULL_OBJECT_ID
	 * @validonly FAL_IPMC_ENTRY_ATTR_PACKET_ACTION ==
	 *					FAL_PACKET_ACTION_FORWARD
	 */
	FAL_IPMC_ENTRY_ATTR_OUTPUT_GROUP_ID,

	/**
	 * @brief IPMC entry RPF interface group id
	 *
	 * If not set or the group has no member, RPF checking will be disabled.
	 *
	 * @type fal_object_id_t
	 * @flags MANDATORY_ON_CREATE | CREATE_AND_SET
	 * @objects FAL_OBJECT_TYPE_RPF_GROUP
	 */
	FAL_IPMC_ENTRY_ATTR_RPF_GROUP_ID,

	/**
	 * @brief End of attributes
	 */
	FAL_IPMC_ENTRY_ATTR_END,
};

/**
 * @brief IPMC forwarding entry key
 */
struct fal_ipmc_entry_t {
	/** VRF ID */
	unsigned int vrf_id;

	/** type **/
	enum fal_ipmc_entry_type_t type;

	/** IP destination address */
	struct fal_ip_address_t destination;

	/** IP source address */
	struct fal_ip_address_t source;
};

/**
 * @brief Create an IP multicast forwarding entry
 *
 * @param[in]  ipmc_entry An mcast forwarding entry key
 * @param[in]  attr_count Number of attributes
 * @param[in]  attr_list  Array of attributes
 * @param[out] obj        Object id for mcast entry, non-zero on success
 *
 * @return 0 on success, error code for failure
 */
int fal_plugin_create_ip_mcast_entry(const struct fal_ipmc_entry_t *ipmc_entry,
				     uint32_t attr_count,
				     const struct fal_attribute_t *attr_list,
				     fal_object_t *obj);

/**
 * @brief Delete an IP multicast forwarding entry
 *
 * @param[in] obj Object id for mcast entry
 *
 * @return 0 on success, error code for failure
 */
int fal_plugin_delete_ip_mcast_entry(fal_object_t obj);

/**
 * @brief Set attributes on an IP multicast forwarding entry
 *
 * @param[in] obj  Object id for mcast entry
 * @param[in] attr Attribute to be updated
 *
 * @return 0 on success.
 */
int fal_plugin_set_ip_mcast_entry_attr(fal_object_t obj,
				       const struct fal_attribute_t *attr);

/**
 * @brief Get IPMC entry attribute values
 *
 * @param[in]    obj  Object id for mcast entry
 * @param[in]    attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
int fal_plugin_get_ip_mcast_entry_attr(fal_object_t obj,
				       uint32_t attr_count,
				       const struct fal_attribute_t *attr_list);

enum fal_ip_mcast_entry_stat_type {
	FAL_IP_MCAST_GROUP_STAT_IN_PACKETS,
	FAL_IP_MCAST_GROUP_STAT_IN_OCTETS,
	FAL_IP_MCAST_GROUP_STAT_MAX
};

/**
 * @brief Get the counters from the given IP multicast group
 *
 * @param[in] obj IP Multicast Group object
 * @param[in] num_counters The size of the stats array being asked for
 * @param[in] cntr_ids Array of stats to return
 * @param[out] stats And array to write the requested stats values into.
 * @return Returns 0 for success, error code on failure
 */
int fal_plugin_get_ip_mcast_entry_stats(
	fal_object_t obj, uint32_t num_counters,
	const enum fal_ip_mcast_entry_stat_type *cntr_ids,
	uint64_t *stats);

/**
 * @brief Clear IP Multicast group counters.
 *
 * @param[in] obj IP Multicast Group object
 * @param[in] num_counters The number of counters in the array
 * @param[in] cntr_ids Array of stats to be cleared
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_clear_ip_mcast_entry_stats(
	fal_object_t obj, uint32_t num_counters,
	const enum fal_ip_mcast_entry_stat_type *cntr_ids);


/**
 * @brief Attributes for IPMC group
 */
enum fal_ipmc_group_attr_t {
	/**
	 * @brief Start of attributes
	 */
	FAL_IPMC_GROUP_ATTR_START,

	/**
	 * @brief Number of IPMC interfaces in the group
	 *
	 * @type  uint32_t
	 * @flags READ_ONLY
	 */
	FAL_IPMC_GROUP_ATTR_IPMC_OUTPUT_COUNT = FAL_IPMC_GROUP_ATTR_START,

	/**
	 * @brief IPMC member list
	 *
	 * @type fal_object_list_t
	 * @flags READ_ONLY
	 * @objects FAL_OBJECT_TYPE_IPMC_GROUP_MEMBER
	 */
	FAL_IPMC_GROUP_ATTR_IPMC_MEMBER_LIST,

	/**
	 * @brief End of attributes
	 */
	FAL_IPMC_GROUP_ATTR_END,
};

enum fal_ipmc_group_member_attr_t {
	/**
	 * @brief Start of attributes
	 */
	FAL_IPMC_GROUP_MEMBER_ATTR_START,

	/**
	 * @brief IPMC group id
	 *
	 * @type fal_object_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 * @objects FAL_OBJECT_TYPE_IPMC_GROUP
	 */
	FAL_IPMC_GROUP_MEMBER_ATTR_IPMC_GROUP_ID =
	FAL_IPMC_GROUP_MEMBER_ATTR_START,

	/**
	 * @brief IPMC output id
	 *
	 * @type fal_object_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 * @objects FAL_OBJECT_TYPE_ROUTER_INTERFACE, FAL_OBJECT_TYPE_TUNNEL
	 */
	FAL_IPMC_GROUP_MEMBER_ATTR_IPMC_OUTPUT_ID,

	/**
	 * @brief End of attributes
	 */
	FAL_IPMC_GROUP_MEMBER_ATTR_END,
};

/**
 * @brief Create IP multicast group
 *
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 * @param[out] obj  Object id for mcast group, non-zero on success
 *
 * @return #FAL_STATUS_SUCCESS on success, failure status code on error
 */
int fal_plugin_create_ip_mcast_group(uint32_t attr_count,
				     const struct fal_attribute_t *attr_list,
				     fal_object_t *obj);

/**
 * @brief Delete an IP multicast group
 *
 * @param[in] obj Object id for mcast group
 *
 * @return #FAL_STATUS_SUCCESS on success, failure status code on error
 */
int fal_plugin_delete_ip_mcast_group(fal_object_t obj);

/**
 * @brief Set IP Multicast Group attribute
 *
 * @param[in] obj Object id for mcast group
 * @param[in] attr Attribute to be updated
 *
 * @return #FAL_STATUS_SUCCESS on success, failure status code on error
 */
int fal_plugin_set_ip_mcast_group_attr(fal_object_t obj,
				       const struct fal_attribute_t *attr);

/**
 * @brief Get IPMC Group attribute values
 *
 * @param[in]    obj  Object id for mcast group
 * @param[in]    attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
int fal_plugin_get_ip_mcast_group_attr(fal_object_t obj,
				       uint32_t attr_count,
				       const struct fal_attribute_t *attr_list);

/**
 * @brief Create IP multicast group member
 *
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 * @param[out] obj  Object id for mcast group member, non-zero on success
 *
 * @return #FAL_STATUS_SUCCESS on success, failure status code on error
 */
int fal_plugin_create_ip_mcast_group_member(uint32_t attr_count,
					    const struct fal_attribute_t
					    *attr_list,
					    fal_object_t *obj);
/**
 * @brief Delete IPMC group member
 *
 * @param[in] obj Object id for mcast group member
 *
 * @return #FAL_STATUS_SUCCESS on success, failure status code on error
 */
int fal_plugin_delete_ip_mcast_group_member(fal_object_t obj);

/**
 * @brief Set IP Multicast Group Member attribute
 *
 * @param[in] obj Object id for mcast group member
 * @param[in] attr Attribute to be updated
 *
 * @return #FAL_STATUS_SUCCESS on success, failure status code on error
 */
int fal_plugin_set_ip_mcast_group_member_attr(fal_object_t obj,
					      const struct fal_attribute_t
					      *attr);

/**
 * @brief Get IPMC Group Member attribute values
 *
 * @param[in]    obj  Object id for mcast group member
 * @param[in]    attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return #FAL_STATUS_SUCCESS on success, failure status code on error
 */
int fal_plugin_get_ip_mcast_group_member_attr(fal_object_t obj,
					      uint32_t attr_count,
					      const struct fal_attribute_t
					      *attr_list);

/**
 * @brief Attributes for RPF group
 */
enum fal_rpf_group_attr_t {
	/**
	 * @brief Start of attributes
	 */
	FAL_RPF_GROUP_ATTR_START,

	/**
	 * @brief Number of RPF interfaces in the group
	 *
	 * @type  uint32_t
	 * @flags READ_ONLY
	 */
	FAL_RPF_GROUP_ATTR_RPF_INTERFACE_COUNT = FAL_RPF_GROUP_ATTR_START,

	/**
	 * @brief RPF member list
	 *
	 * @type fal_object_list_t
	 * @flags READ_ONLY
	 * @objects FAL_OBJECT_TYPE_RPF_GROUP_MEMBER
	 */
	FAL_RPF_GROUP_ATTR_RPF_MEMBER_LIST,

	/**
	 * @brief End of attributes
	 */
	FAL_RPF_GROUP_ATTR_END,
};

enum fal_rpf_group_member_attr_t {
	/**
	 * @brief Start of attributes
	 */
	FAL_RPF_GROUP_MEMBER_ATTR_START,

	/**
	 * @brief RPF interface group id
	 *
	 * @type fal_object_id_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 * @objects FAL_OBJECT_TYPE_RPF_GROUP
	 */
	FAL_RPF_GROUP_MEMBER_ATTR_RPF_GROUP_ID =
		FAL_RPF_GROUP_MEMBER_ATTR_START,

	/**
	 * @brief RPF interface id
	 *
	 * @type fal_object_id_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 * @objects FAL_OBJECT_TYPE_ROUTER_INTERFACE
	 */
	FAL_RPF_GROUP_MEMBER_ATTR_RPF_INTERFACE_ID,

	/**
	 * @brief End of attributes
	 */
	FAL_RPF_GROUP_MEMBER_ATTR_END,
};

/**
 * @brief Create RPF group
 *
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 * @param[out] obj  Object id for rpf group, non-zero on success
 *
 * @return #FAL_STATUS_SUCCESS on success, failure status code on error
 */
int fal_plugin_create_rpf_group(uint32_t attr_count,
				const struct fal_attribute_t *attr_list,
				fal_object_t *obj);

/**
 * @brief Delete an RPF group
 *
 * @param[in] obj Object id for rpf group
 *
 * @return #FAL_STATUS_SUCCESS on success, failure status code on error
 */
int fal_plugin_delete_rpf_group(fal_object_t obj);

/**
 * @brief Set RPF Group attribute
 *
 * @param[in] obj Object id for rpf group
 * @param[in] attr Attribute to be updated
 *
 * @return #FAL_STATUS_SUCCESS on success, failure status code on error
 */
int fal_plugin_set_rpf_group_attr(fal_object_t obj,
				  const struct fal_attribute_t *attr);

/**
 * @brief Get RPF Group attribute values
 *
 * @param[in]    obj  Object id for rpf group
 * @param[in]    attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return #FAL_STATUS_SUCCESS on success, failure status code on error
 */
int fal_plugin_get_rpf_group_attr(fal_object_t obj,
				  uint32_t attr_count,
				  const struct fal_attribute_t *attr_list);

/**
 * @brief Create RPF group member
 *
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 * @param[out] obj  Object id for rpf group member, non-zero on success
 *
 * @return #FAL_STATUS_SUCCESS on success, failure status code on error
 */
int fal_plugin_create_rpf_group_member(uint32_t attr_count,
				       const struct fal_attribute_t *attr_list,
				       fal_object_t *obj);
/**
 * @brief Delete RPF group member
 *
 * @param[in] obj Object id for rpf group member
 *
 * @return #FAL_STATUS_SUCCESS on success, failure status code on error
 */
int fal_plugin_delete_rpf_group_member(fal_object_t obj);

/**
 * @brief Set RPF Group Member attribute
 *
 * @param[in] obj Object id for rpf group member
 * @param[in] attr Attribute to be updated
 *
 * @return #FAL_STATUS_SUCCESS on success, failure status code on error
 */
int fal_plugin_set_rpf_group_member_attr(fal_object_t obj,
					 const struct fal_attribute_t *attr);

/**
 * @brief Get RPF Group Member attribute values
 *
 * @param[in]    obj  Object id for rpf group member
 * @param[in]    attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return #FAL_STATUS_SUCCESS on success, failure status code on error
 */
int fal_plugin_get_rpf_group_member_attr(fal_object_t obj,
					 uint32_t attr_count,
					 const struct fal_attribute_t
					 *attr_list);

void fal_plugin_cleanup(void);

void fal_plugin_command(FILE *f, int argc, char **argv);
int fal_plugin_command_ret(FILE *f, int argc, char **argv);

/** @brief Portmonitor direction flags to specify packet mirror direction */
#define FAL_PORTMONITOR_DIRECTION_RX	0x01
#define FAL_PORTMONITOR_DIRECTION_TX	0x02

/* Portmonitor per packet feature information returned by plugin */
struct fal_pkt_portmonitor_info {
	uint8_t	mirror_dir;      /* Mirror direction, RX or TX */
};

/**
 * @brief Feature specific information from fal plugin
 */
union fal_pkt_feature_info {
	struct fal_pkt_portmonitor_info fal_pm;
};

/**
 * @brief Return enum of hw specific processing function (Rx framer)
 */
enum fal_feat_framer_ret_value {
	FAL_RET_ETHER_INPUT,
	FAL_RET_PORTMONITOR_HW_INPUT,
	FAL_RET_CAPTURE_HW_INPUT
};

/*
 * Queue mbufs from the fal plugin directly to a tx port, typically
 * used to queue mbufs to a backplane port.
 * NOT safe to call from any threads on the main core.
 *
 * Returns: Number of mbufs queued, Unqueued mbufs are returned to the
 * caller.
 */
uint16_t fal_tx_pkt_burst(uint16_t tx_port, struct rte_mbuf **bufs,
			  uint16_t nb_bufs);

/**
 * @brief Enable per-packet callback for packets received off of backplane
 * interface. The callback may strip off backplane encapsulation in
 * preparation for normal packet processing, or provide information
 * for specific packet processing actions
 *
 * @param[in] enable true to enable hw processing, false to disable
 * @param[in] bp_port back plane port
 * @param[in] shared_channel true if shared channel false otherwise
 * @param[in] plugin framer function with feature support that will be
 * called for plugin specific recv processing and can return
 * fal_feat_framer_ret_value to specify next processing node or -1
 * for failure
 *
 * @return 0 for success -1 for failure
 */
int fal_rx_bp_framer_enable(bool enable, uint32_t bp_port,
			    bool shared_channel, uint16_t ether_proto,
			    int (*feat_framer)(struct rte_mbuf *buf,
					       uint16_t *dpdk_port,
					       union fal_pkt_feature_info
						     *feat_info));

bool l2_hw_hdr_rx_enable(bool enable, uint32_t bp_port,
			 bool shared_channel, uint16_t ether_proto,
			 bool (*framer)(struct rte_mbuf *buf,
					uint16_t *dpdk_port));

void fal_pkt_mark_set_framed(struct rte_mbuf *m);

bool fal_pkt_mark_is_framed(struct rte_mbuf *m);

int
fal_prepare_for_header_change(struct rte_mbuf **m,
			      uint16_t header_len);

/*
 * policer stats. Currently used just for storm control
 * modeled after _sai_policer_stat_t
 */
enum fal_policer_stat_type {
	/** accepted packets */
	FAL_POLICER_STAT_GREEN_PACKETS,

	/** accepted bytes */
	FAL_POLICER_STAT_GREEN_BYTES,

	/** dropped packets */
	FAL_POLICER_STAT_RED_PACKETS,

	/** dropped bytes */
	FAL_POLICER_STAT_RED_BYTES,

	FAL_POLICER_STAT_MAX
};

/**
 * @brief Clear the stats from the given policer
 *
 * @param[in] obj Policer object id
 * @param[in] num_counters The number of counters in the array
 * @param[in] cntr_ids Array of stats to clear
 * @return Returns 0 for success, error code on failure
 */
int fal_plugin_policer_clear_stats(fal_object_t obj,
				   uint32_t num_counters,
				   const enum fal_policer_stat_type *cntr_ids);

enum fal_policer_meter_type {
	FAL_POLICER_METER_TYPE_PACKETS,
	FAL_POLICER_METER_TYPE_BYTES,
	FAL_POLICER_METER_TYPE
};

enum fal_policer_mode_type {
	FAL_POLICER_MODE_STORM_CTL,
	FAL_POLICER_MODE_CPP,
	FAL_POLICER_MODE_MAX
};

enum fal_stats_mode {
	FAL_STATS_MODE_READ,
	FAL_STATS_MODE_READ_AND_CLEAR,
};

/**
 * @brief FAL attributes for policers
 */
enum fal_policer_attr_t {
	/**
	 * @brief Policer Meter type
	 * @type fal_policer_meter_type
	 * @flags CREATE_AND_SET
	 */
	FAL_POLICER_ATTR_METER_TYPE = 0x00000001,
	/**
	 * @brief Policer mode
	 * @type fal_policer_mode_type
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_POLICER_ATTR_MODE = 0x00000002,
	/**
	 * @brief Committed burst size/packets
	 * @type uint64_t
	 * @flags CREATE_AND_SET
	 */
	FAL_POLICER_ATTR_CBS  = 0x00000003,
	/**
	 * @brief Committed information rate BPS/PPS
	 * @type uint64_t
	 * @flags CREATE_AND_SET
	 */
	FAL_POLICER_ATTR_CIR  = 0x00000004,
	/**
	 * @brief Action to take for RED colour packets
	 * @type fal_packet_action_t
	 * @flags CREATE_AND_SET
	 */
	FAL_POLICER_ATTR_RED_PACKET_ACTION  = 0x00000005,
};

/**
 * @brief New Policer
 *
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 * @param[out] obj Policer object id
 * @return Returns 0 for success, error code on failure
 */
int fal_plugin_policer_create(uint32_t attr_count,
			      const struct fal_attribute_t *attr_list,
			      fal_object_t *obj);

/**
 * @brief Delete Policer
 *
 * @param[out] obj Policer object id
 * @return Returns 0 for success, error code on failure
 */
int fal_plugin_policer_delete(fal_object_t obj);

/**
 * @brief Set Policer attribute
 *
 * @param[in] obj Policer object id
 * @param[in] attr Fal attribute
 * @return Returns 0 for success, error code on failure
 */
int fal_plugin_policer_set_attr(fal_object_t obj,
				const struct fal_attribute_t *attr);

/**
 * @brief Get Policer attribute
 *
 * @param[in] obj Policer object id
 * @param[in] attr Fal attribute
 * @return Returns 0 for success, error code on failure
 */
int fal_plugin_policer_get_attr(fal_object_t obj,
				uint32_t attr_count,
				struct fal_attribute_t *attr_list);

/**
 * @brief Get the stats from the given policer
 *
 * @param[in] obj Policer object id
 * @param[in] num_counters The size of the stats array being asked for
 * @param[in] cntr_ids Array of stats to return
 * @param[in] mode Get stats or, get and clear.
 * @param[out] stats And array to write the requested stats values into.
 * @return Returns 0 for success, error code on failure
 */
int fal_plugin_policer_get_stats_ext(
	fal_object_t obj,
	uint32_t num_counters,
	const enum fal_policer_stat_type *cntr_ids,
	enum fal_stats_mode mode,
	uint64_t *stats);

/**
 * @brief dump policer info in FAL
 *
 * @param[in] obj Policer object id
 * @param[in] json writer object
 */
void fal_plugin_policer_dump(fal_object_t obj,
			     json_writer_t *wr);


/* QoS objects, attributes and types */

#define FAL_QOS_NULL_OBJECT_ID 0x0

/**
 * @brief Enum defining Queue types.
 */
enum fal_qos_queue_type_t {
	/** H/w Queue for all types of traffic */
	FAL_QOS_QUEUE_TYPE_ALL = 0x00000000,

	/** H/w Unicast Queue */
	FAL_QOS_QUEUE_TYPE_UNICAST = 0x00000001,

	/** H/w Multicast (Broadcast, Unknown unicast, Multicast) Queue */
	FAL_QOS_QUEUE_TYPE_NON_UNICAST = 0x00000002,

	/** Max value */
	FAL_QOS_QUEUE_TYPE_MAX = FAL_QOS_QUEUE_TYPE_NON_UNICAST,
};

/**
 * @brief Enum defining queue attributes.
 */
enum fal_qos_queue_attr_t {
	/**
	 * @brief Queue type
	 *
	 * @type fal_qos_queue_type_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY | KEY
	 */
	FAL_QOS_QUEUE_ATTR_TYPE = 0x00000000,

	/**
	 * @brief Queue index
	 *
	 * @type uint8_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY | KEY
	 */
	FAL_QOS_QUEUE_ATTR_INDEX = 0x00000001,

	/**
	 * @brief Parent scheduler node
	 *
	 * In case of Hierarchical QOS not supported, the parent node is the
	 * port.  Conditional on whether Hierarchical QOS is supported or not,
	 * need to remove the MANDATORY_ON_CREATE FLAG when HQoS is introduced.
	 *
	 * @type fal_object_t
	 * @flags MANDATORY_ON_CREATE | CREATE_AND_SET
	 * @objects FAL_QOS_OBJECT_TYPE_SCHEDULER_GROUP,
	 *          FAL_QOS_OBJECT_TYPE_PORT
	 */
	FAL_QOS_QUEUE_ATTR_PARENT_ID = 0x00000002,

	/**
	 * @brief Attach WRED ID to queue
	 *
	 * ID = #FAL_QOS_NULL_OBJECT_ID to disable WRED
	 *
	 * @type fal_object_t
	 * @flags CREATE_AND_SET
	 * @objects FAL_QOS_OBJECT_TYPE_WRED
	 * @allownull true
	 * @default FAL_QOS_NULL_OBJECT_ID
	 */
	FAL_QOS_QUEUE_ATTR_WRED_ID = 0x00000003,

	/**
	 * @brief Attach buffer profile to queue
	 *
	 * @type fal_object_t
	 * @flags CREATE_AND_SET
	 * @objects FAL_QOS_OBJECT_TYPE_BUFFER
	 * @allownull true
	 * @default FAL_QOS_NULL_OBJECT_ID
	 */
	FAL_QOS_QUEUE_ATTR_BUFFER_ID = 0x00000004,

	/**
	 * @brief Attach scheduler to queue
	 *
	 * @type fal_object_t
	 * @flags CREATE_AND_SET
	 * @objects FAL_QOS_OBJECT_TYPE_SCHEDULER
	 * @allownull true
	 * @default FAL_QOS_NULL_OBJECT_ID
	 */
	FAL_QOS_QUEUE_ATTR_SCHEDULER_ID = 0x00000005,

	/**
	 * @brief Maximum queue length
	 *
	 * @type uint32_t
	 * @flags CREATE_AND_SET
	 * @default 64 packets
	 * @default 65536 bytes
	 */
	FAL_QOS_QUEUE_ATTR_QUEUE_LIMIT = 0x00000006,

	/**
	 * @brief The TC that the queue is a member of
	 *
	 * @type uint8_t
	 * @flags CREATE_AND_SET
	 */
	FAL_QOS_QUEUE_ATTR_TC = 0x00000007,

	/**
	 * @brief Local control traffic priority queue
	 *
	 * A queue may be reserved for locally generated control traffic.
	 * For example, BGP or other routing packets (with a DSCP value
	 * of CS6) that have been generated on the local system.
	 *
	 * The need to reserve this queue is controlled explicitly by the
	 * QoS CLI configuration.
	 *
	 * Defaults: not required
	 *
	 * @type boolean
	 * @flags MANDATORY_ON_CREATE | CREATE_AND_SET
	 */
	FAL_QOS_QUEUE_ATTR_LOCAL_PRIORITY = 0x00000008,

	/**
	 * @brief Designator used to classify traffic to the queue
	 *
	 * @type uint8_t
	 * @flags MANDATORY_ON_CREATE | CREATE_AND_SET
	 */
	FAL_QOS_QUEUE_ATTR_DESIGNATOR = 0x00000009,

	/** Max value */
	FAL_QOS_QUEUE_ATTR_MAX = FAL_QOS_QUEUE_ATTR_DESIGNATOR,
};

/**
 * @brief Enum defining statistics for Queue.
 */
enum fal_qos_queue_stat_t {
	/** Get/set tx packets count [uint64_t] */
	FAL_QOS_QUEUE_STAT_PACKETS = 0x00000000,

	/** Get/set tx bytes count [uint64_t] */
	FAL_QOS_QUEUE_STAT_BYTES = 0x00000001,

	/** Get/set dropped packets count [uint64_t] */
	FAL_QOS_QUEUE_STAT_DROPPED_PACKETS = 0x00000002,

	/** Get/set dropped bytes count [uint64_t] */
	FAL_QOS_QUEUE_STAT_DROPPED_BYTES = 0x00000003,

	/** Get/set green color tx packets count [uint64_t] */
	FAL_QOS_QUEUE_STAT_GREEN_PACKETS = 0x00000004,

	/** Get/set green color tx bytes count [uint64_t] */
	FAL_QOS_QUEUE_STAT_GREEN_BYTES = 0x00000005,

	/** Get/set green color dropped packets count [uint64_t] */
	FAL_QOS_QUEUE_STAT_GREEN_DROPPED_PACKETS = 0x00000006,

	/** Get/set green color dropped packets count [uint64_t] */
	FAL_QOS_QUEUE_STAT_GREEN_DROPPED_BYTES = 0x00000007,

	/** Get/set yellow color tx packets count [uint64_t] */
	FAL_QOS_QUEUE_STAT_YELLOW_PACKETS = 0x00000008,

	/** Get/set yellow color tx bytes count [uint64_t] */
	FAL_QOS_QUEUE_STAT_YELLOW_BYTES = 0x00000009,

	/** Get/set yellow color dropped packets count [uint64_t] */
	FAL_QOS_QUEUE_STAT_YELLOW_DROPPED_PACKETS = 0x0000000a,

	/** Get/set yellow color dropped packets count [uint64_t] */
	FAL_QOS_QUEUE_STAT_YELLOW_DROPPED_BYTES = 0x0000000b,

	/** Get/set red color tx packets count [uint64_t] */
	FAL_QOS_QUEUE_STAT_RED_PACKETS = 0x0000000c,

	/** Get/set red color tx bytes count [uint64_t] */
	FAL_QOS_QUEUE_STAT_RED_BYTES = 0x0000000d,

	/** Get/set red color dropped packets count [uint64_t] */
	FAL_QOS_QUEUE_STAT_RED_DROPPED_PACKETS = 0x0000000e,

	/** Get/set red color dropped packets count [uint64_t] */
	FAL_QOS_QUEUE_STAT_RED_DROPPED_BYTES = 0x0000000f,

	/** Get/set WRED green color dropped packets count [uint64_t] */
	FAL_QOS_QUEUE_STAT_GREEN_WRED_DROPPED_PACKETS = 0x00000010,

	/** Get/set WRED green color dropped bytes count [uint64_t] */
	FAL_QOS_QUEUE_STAT_GREEN_WRED_DROPPED_BYTES = 0x00000011,

	/** Get/set WRED yellow color dropped packets count [uint64_t] */
	FAL_QOS_QUEUE_STAT_YELLOW_WRED_DROPPED_PACKETS = 0x00000012,

	/** Get/set WRED yellow color dropped bytes count [uint64_t] */
	FAL_QOS_QUEUE_STAT_YELLOW_WRED_DROPPED_BYTES = 0x00000013,

	/** Get/set WRED red color dropped packets count [uint64_t] */
	FAL_QOS_QUEUE_STAT_RED_WRED_DROPPED_PACKETS = 0x00000014,

	/** Get/set WRED red color dropped bytes count [uint64_t] */
	FAL_QOS_QUEUE_STAT_RED_WRED_DROPPED_BYTES = 0x00000015,

	/** Get/set WRED dropped packets count [uint64_t] */
	FAL_QOS_QUEUE_STAT_WRED_DROPPED_PACKETS = 0x00000016,

	/** Get/set WRED dropped bytes count [uint64_t] */
	FAL_QOS_QUEUE_STAT_WRED_DROPPED_BYTES = 0x00000017,

	/** Get current queue occupancy in bytes [uint64_t] */
	FAL_QOS_QUEUE_STAT_CURR_OCCUPANCY_BYTES = 0x00000018,

	/** Get watermark queue occupancy in bytes [uint64_t] */
	FAL_QOS_QUEUE_STAT_WATERMARK_BYTES = 0x00000019,

	/** Max value */
	FAL_QOS_QUEUE_STAT_MAX = FAL_QOS_QUEUE_STAT_WATERMARK_BYTES
};

/**
 * @brief New QoS queue
 *
 * @param[in] switch_id Switch id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 * @param[out] new_queue_id Queue id
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_new_queue(fal_object_t switch_id, uint32_t attr_count,
			     const struct fal_attribute_t *attr_list,
			     fal_object_t *new_queue_id);

/**
 * @brief Delete QoS queue
 *
 * @param[in] queue_id Queue id of QoS queue to delete
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_del_queue(fal_object_t queue_id);

/**
 * @brief Set attribute to Queue
 *
 * @param[in] queue_id Queue ID to set the attribute
 * @param[in] attr Attribute to set
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_upd_queue(fal_object_t queue_id,
			     const struct fal_attribute_t *attr);

/**
 * @brief Get attributes from Queue
 *
 * @param[in] queue_id Queue id to get the attributes
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_get_queue_attrs(fal_object_t queue_id, uint32_t attr_count,
				   struct fal_attribute_t *attr_list);

/**
 * @brief Get queue statistics counters.
 *
 * @param[in] queue_id Queue id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 * @param[out] counters Array of resulting counter values.
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_get_queue_stats(fal_object_t queue_id,
				   uint32_t number_of_counters,
				   const uint32_t *counter_ids,
				   uint64_t *counters);

/**
 * @brief Get queue statistics counters extended.
 *
 * Operates in two ways: just read the counter, or read and clear the counter.
 *
 * @param[in] queue_id Queue id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 * @param[in] read_and_clear Determines the mode of operation
 * @param[out] counters Array of resulting counter values
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_get_queue_stats_ext(fal_object_t queue_id,
				       uint32_t number_of_counters,
				       const uint32_t *counter_ids,
				       bool read_and_clear, uint64_t *counters);

/**
 * @brief Clear queue statistics counters.
 *
 * @param[in] queue_id Queue id of queue to clear counters for
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_clear_queue_stats(fal_object_t queue_id,
				     uint32_t number_of_counters,
				     const uint32_t *counter_ids);

/**
 * @brief Enum defining QOS map types.
 */
enum fal_qos_map_type_t {
	/** QOS Map to set DOT1P to Traffic class */
	FAL_QOS_MAP_TYPE_DOT1P_TO_TC = 0x00000000,

	/** QOS Map to set DOT1P to color */
	FAL_QOS_MAP_TYPE_DOT1P_TO_COLOR = 0x00000001,

	/** QOS Map to set DSCP to Traffic class */
	FAL_QOS_MAP_TYPE_DSCP_TO_TC = 0x00000002,

	/** QOS Map to set DSCP to color */
	FAL_QOS_MAP_TYPE_DSCP_TO_COLOR = 0x00000003,

	/** QOS Map to set traffic class to queue */
	FAL_QOS_MAP_TYPE_TC_TO_QUEUE = 0x00000004,

	/** QOS Map to set traffic class and color to DSCP */
	FAL_QOS_MAP_TYPE_TC_AND_COLOR_TO_DSCP = 0x00000005,

	/** QOS Map to set traffic class and color to DOT1P */
	FAL_QOS_MAP_TYPE_TC_AND_COLOR_TO_DOT1P = 0x00000006,

	/** QOS Map to set traffic class to priority group */
	FAL_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP = 0x00000007,

	/** QOS Map to set DSCP to DOT1P */
	FAL_QOS_MAP_TYPE_DSCP_TO_DOT1P = 0x00000008,

	/** QOS Map to set DSCP to designator */
	FAL_QOS_MAP_TYPE_DSCP_TO_DESIGNATOR = 0x00000009,

	/** QOS Map to set DOT1P to designator */
	FAL_QOS_MAP_TYPE_DOT1P_TO_DESIGNATOR = 0x0000000a,

	/** QOS Map to set designator to DOT1P */
	FAL_QOS_MAP_TYPE_DESIGNATOR_TO_DOT1P = 0x0000000b,

	/** QOS Map to set designator to DSCP */
	FAL_QOS_MAP_TYPE_DESIGNATOR_TO_DSCP = 0x0000000c,

	/** Max value */
	FAL_QOS_MAP_TYPE_MAX = FAL_QOS_MAP_TYPE_DESIGNATOR_TO_DSCP,
};

/**
 * @brief Enum defining attributes for QOS Maps.
 */
enum fal_qos_map_attr_t {
	/**
	 * @brief QOS Map type
	 *
	 * @type fal_qos_qos_map_type_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_QOS_MAP_ATTR_TYPE = 0x00000000,

	/**
	 * @brief Dot1p/DSCP to TC Mapping
	 *
	 * Defaults:
	 * - All Dot1p/DSCP maps to traffic class 0
	 * - All Dot1p/DSCP maps to color #FAL_PACKET_COLOR_GREEN
	 * - All traffic class maps to queue 0
	 *
	 * @type fal_qos_map_list_t
	 * @flags MANDATORY_ON_CREATE | CREATE_AND_SET
	 */
	FAL_QOS_MAP_ATTR_MAP_TO_VALUE_LIST = 0x00000001,

	/**
	 * @brief Local control traffic priority queue
	 *
	 * A queue may be reserved for locally generated control traffic.
	 * For example, BGP or other routing packets (with a DSCP value
	 * of CS6) that have been generated on the local system.
	 *
	 * The need to reserve this queue is controlled explicitly by the
	 * QoS CLI configuration.
	 *
	 * This queue if required has the highest priority of all queues.
	 *
	 * Defaults: not required
	 *
	 * @type boolean
	 * @flags MANDATORY_ON_CREATE | CREATE_AND_SET
	 */
	FAL_QOS_MAP_ATTR_LOCAL_PRIORITY_QUEUE = 0x00000002,

	/**
	 * @brief System default setting
	 *
	 * A map may be applied as the system default for ingress
	 * classification. If a QoS policy is applied to any port or
	 * port/vlan then this map is applied to all ingress ports and
	 * port/vlans that do not have a specific ingress map applied
	 *
	 * Defaults: not required
	 *
	 * @type boolean
	 * @flags MANDATORY_ON_CREATE | CREATE_AND_SET
	 */
	FAL_QOS_MAP_ATTR_INGRESS_SYSTEM_DEFAULT = 0x00000003,

	/** Max value */
	FAL_QOS_MAP_ATTR_MAX = FAL_QOS_MAP_ATTR_INGRESS_SYSTEM_DEFAULT,
};

/**
 * @brief New QOS Map
 *
 * @param[in] switch_id Switch id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 * @param[out] new_map_id QOS Map Id
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_new_map(fal_object_t switch_id, uint32_t attr_count,
			   const struct fal_attribute_t *attr_list,
			   fal_object_t *new_map_id);

/**
 * @brief Delete QOS Map
 *
 * @param[in] map_id QOS Map id to be delete.
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_del_map(fal_object_t map_id);

/**
 * @brief Update attribute for QOS map
 *
 * @param[in] map_id QOS Map Id
 * @param[in] attr Attribute to set
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_upd_map(fal_object_t map_id,
			   const struct fal_attribute_t *attr);

/**
 * @brief dump QoS map info in FAL
 *
 * @param[in] map object id
 * @param[in] json writer object
 */
void fal_plugin_qos_dump_map(fal_object_t map,
			     json_writer_t *wr);

/**
 * @brief Get attributes of QOS map
 *
 * @param[in] map Map id
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_get_map_attrs(fal_object_t map_id, uint32_t attr_count,
				 struct fal_attribute_t *attr_list);

/**
 * @brief Enum defining Meter types.
 */
enum fal_qos_meter_type_t {
	/* Metering in bytes per second */
	FAL_QOS_METER_TYPE_BYTES = 0x00000000,

	/* Metering in packets per second */
	FAL_QOS_METER_TYPE_PACKETS = 0x00000001,

	/* Max value */
	FAL_QOS_METER_TYPE_MAX = FAL_QOS_METER_TYPE_PACKETS,
};

/**
 * @brief Enum defining scheduling algorithm.
 */
enum fal_qos_scheduler_type_t {
	/** Strict Scheduling */
	FAL_QOS_SCHEDULING_TYPE_STRICT = 0x00000000,

	/** Weighted Round-Robin Scheduling */
	FAL_QOS_SCHEDULING_TYPE_WRR = 0x00000001,

	/** Deficit Weighted Round-Robin Scheduling */
	FAL_QOS_SCHEDULING_TYPE_DWRR = 0x00000002,

	/* Max value */
	FAL_QOS_SCHEDULING_TYPE_MAX = FAL_QOS_SCHEDULING_TYPE_DWRR,
};

/**
 * @brief Enum defining scheduler attributes.
 */
enum fal_qos_scheduler_attr_t {
	/**
	 * @brief Scheduling algorithm
	 *
	 * @type fal_qos_scheduling_type_t
	 * @flags CREATE_AND_SET
	 * @default FAL_QOS_SCHEDULING_TYPE_WRR
	 */
	FAL_QOS_SCHEDULER_ATTR_SCHEDULING_TYPE = 0x00000000,

	/**
	 * @brief Scheduling algorithm weight
	 *
	 * Range [1 - 100].
	 *
	 * @type uint8_t
	 * @flags CREATE_AND_SET
	 * @default 1
	 * @validonly FAL_QOS_SCHEDULER_ATTR_SCHEDULING_TYPE ==
	 * FAL_QOS_SCHEDULING_TYPE_DWRR
	 */
	FAL_QOS_SCHEDULER_ATTR_SCHEDULING_WEIGHT = 0x00000001,

	/**
	 * @brief Shaper
	 *
	 * @type fal_qos_meter_type_t
	 * @flags CREATE_AND_SET
	 * @default FAL_QOS_METER_TYPE_BYTES
	 */
	FAL_QOS_SCHEDULER_ATTR_METER_TYPE = 0x00000002,

	/**
	 * @brief Maximum Bandwidth shape rate [bytes/sec or PPS]
	 *
	 * Value 0 to no limit.
	 *
	 * @type uint64_t
	 * @flags CREATE_AND_SET
	 * @default 0
	 */
	FAL_QOS_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE = 0x00000003,

	/**
	 * @brief Maximum Burst for Bandwidth shape rate [bytes or Packets]
	 *
	 * @type uint64_t
	 * @flags CREATE_AND_SET
	 * @default 0
	 */
	FAL_QOS_SCHEDULER_ATTR_MAX_BANDWIDTH_BURST_RATE = 0x00000004,

	/**
	 * @brief Frame-overhead to be added/subtracted to a packet
	 *
	 * @type uint8_t
	 * @flags CREATE_AND_SET
	 * @default FAL_QOS_FRAME_OVERHEAD
	 */
	FAL_QOS_SCHEDULER_ATTR_FRAME_OVERHEAD = 0x00000005,

	/* Max value */
	FAL_QOS_SCHEDULER_ATTR_MAX =
		FAL_QOS_SCHEDULER_ATTR_FRAME_OVERHEAD,
};

/**
 * @brief Create Scheduler Profile
 *
 * @param[in] switch_id Switch id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 * @param[out] new_sched_id Scheduler id
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_new_scheduler(fal_object_t switch_id, uint32_t attr_count,
				 const struct fal_attribute_t *attr_list,
				 fal_object_t *new_sched_id);

/**
 * @brief Delete Scheduler profile
 *
 * @param[in] sched_id Scheduler id of scheduler to delete
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_del_scheduler(fal_object_t sched_id);

/**
 * @brief Set Scheduler Attribute
 *
 * @param[in] sched_id Scheduler id of scheduler to update
 * @param[in] attr Attribute to set
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_upd_scheduler(fal_object_t sched_id,
				 const struct fal_attribute_t *attr);

/**
 * @brief Get Scheduler attributes
 *
 * @param[in] sched_id Scheduler id
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_get_scheduler_attrs(fal_object_t sched_id,
				       uint32_t attr_count,
				       struct fal_attribute_t *attr_list);

/**
 * @brief Enum defining scheduler group levels.
 *
 * The level also defines how many ids are required to identify an object
 * at that level, i.e. an pipe needs three ids.
 */
enum fal_qos_sched_group_level_t {
	FAL_QOS_SCHED_GROUP_LEVEL_NOT_USED = 0,
	FAL_QOS_SCHED_GROUP_LEVEL_PORT = 1,
	FAL_QOS_SCHED_GROUP_LEVEL_SUBPORT = 2,
	FAL_QOS_SCHED_GROUP_LEVEL_PIPE = 3,
	FAL_QOS_SCHED_GROUP_LEVEL_TC = 4,
	FAL_QOS_SCHED_GROUP_LEVEL_QUEUE = 5,
	FAL_QOS_SCHED_GROUP_MAX_LEVEL = FAL_QOS_SCHED_GROUP_LEVEL_QUEUE,
	FAL_QOS_SCHED_GROUP_TOTAL_IDS = FAL_QOS_SCHED_GROUP_MAX_LEVEL + 1,
};

/**
 * @brief Enum defining scheduler group attributes.
 */
enum fal_qos_sched_group_attr_t {
	/**
	 * @brief Number of queues/groups children added to scheduler
	 *
	 * @type uint32_t
	 * @flags READ_ONLY
	 */
	FAL_QOS_SCHED_GROUP_ATTR_CHILD_COUNT = 0x00000000,

	/**
	 * @brief Scheduler Group child object id list
	 *
	 * @type fal_object_list_t
	 * @flags READ_ONLY
	 * @objects FAL_QOS_OBJECT_TYPE_SCHED_GROUP, FAL_QOS_OBJECT_TYPE_QUEUE
	 */
	FAL_QOS_SCHED_GROUP_ATTR_CHILD_LIST = 0x00000001,

	/**
	 * @brief Scheduler group index
	 *
	 * For FAL_QOS_SCHED_GROUP_LEVEL_PORT this is the if_index of the
	 * port on which the scheduler group should be applied. For all
	 * other levels, this is a 0-based unique identifier particular to
	 * the level that may be used for debugging purposes or configuration
	 * hint when a static hierarchy is assumed in the plugin.
	 *
	 * @type uint32_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_QOS_SCHED_GROUP_ATTR_SG_INDEX = 0x00000002,

	/**
	 * @brief Scheduler group level
	 *
	 * @type fal_qos_sched_level_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_QOS_SCHED_GROUP_ATTR_LEVEL = 0x00000003,

	/**
	 * @brief Maximum number of children on group
	 *
	 * @type uint8_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_QOS_SCHED_GROUP_ATTR_MAX_CHILDREN = 0x00000004,

	/**
	 * @brief Scheduler id
	 *
	 * @type fal_object_t
	 * @flags CREATE_AND_SET
	 * @objects FAL_QOS_OBJECT_TYPE_SCHEDULER
	 * @allownull true
	 * @default FAL_QOS_NULL_OBJECT_ID
	 */
	FAL_QOS_SCHED_GROUP_ATTR_SCHEDULER_ID = 0x00000005,

	/**
	 * @brief Scheduler group parent node
	 *
	 * This is conditional when the level > 1, when level == 1, the
	 * parent is the port.
	 *
	 * @type fal_object_t
	 * @flags MANDATORY_ON_CREATE | CREATE_AND_SET
	 * @objects FAL_QOS_OBJECT_TYPE_SCHEDULER_GROUP,
	 *          FAL_QOS_OBJECT_TYPE_PORT
	 */
	FAL_QOS_SCHED_GROUP_ATTR_PARENT_ID = 0x00000006,

	/**
	 * @brief Scheduler group ingress map node
	 *
	 * This is only valid when the level == 3, i.e. the sched-group
	 * represents a vyatta pipe.
	 *
	 * @type fal_object_t
	 * @flags CREATE_AND_SET
	 * @objects FAL_QOS_OBJECT_TYPE_MAP
	 */
	FAL_QOS_SCHED_GROUP_ATTR_INGRESS_MAP_ID = 0x00000007,

	/**
	 * @brief Scheduler group vlan id
	 *
	 * VLAN id of traffic this scheduler group applies to.
	 * This is only valid when the level == 2, i.e. the sched-group
	 * represents a vyatta subport.
	 *
	 * @type uint16_t
	 * @flags CREATE_AND_SET
	 */
	FAL_QOS_SCHED_GROUP_ATTR_VLAN_ID = 0x00000008,

	/**
	 * @brief Scheduler group egress map node
	 *
	 * This is only valid when the level == 3, i.e. the sched-group
	 * represents a vyatta pipe.
	 *
	 * @type fal_object_t
	 * @flags CREATE_AND_SET
	 * @objects FAL_QOS_OBJECT_TYPE_MAP
	 */
	FAL_QOS_SCHED_GROUP_ATTR_EGRESS_MAP_ID = 0x00000009,

	/**
	 * @brief Scheduler group local priority queue designator
	 *
	 * The designator to be applied to locally generated priority traffic
	 * to classify it to the local priority queue.
	 * This is only valid when the level == 3, i.e. the sched-group
	 * represents a vyatta pipe.
	 *
	 * @type uint8_t
	 * @flags MANDATORY_ON_CREATE| CREATE_AND_SET
	 */
	FAL_QOS_SCHED_GROUP_ATTR_LOCAL_PRIORITY_DESIGNATOR = 0x0000000a,

	/* Max value */
	FAL_QOS_SCHED_GROUP_ATTR_MAX =
		FAL_QOS_SCHED_GROUP_ATTR_LOCAL_PRIORITY_DESIGNATOR,
};

/**
 * @brief New Scheduler group
 *
 * @param[in] switch_id The Switch id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 * @param[out] sched_group_id Scheduler group id
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_new_sched_group(fal_object_t switch_id, uint32_t attr_count,
				   const struct fal_attribute_t *attr_list,
				   fal_object_t *sched_group_id);

/**
 * @brief Delete Scheduler group
 *
 * @param[in] sched_group_id Scheduler group id
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_del_sched_group(fal_object_t scheduler_group);

/**
 * @brief Update a scheduler group attribute
 *
 * @param[in] sched_group_id Scheduler group id
 * @param[in] attr Attribute to set
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_upd_sched_group(fal_object_t sched_group_id,
				   const struct fal_attribute_t *attr);

/**
 * @brief Get Scheduler Group attributes
 *
 * @param[in] sched_group_id Scheduler group id
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_get_sched_group_attrs(fal_object_t sched_group_id,
					 uint32_t attr_count,
					 struct fal_attribute_t *attr_list);

/**
 * @brief dump QoS sched group info in FAL
 *
 * @param[in] sched group object id
 * @param[in] json writer object
 */
void fal_plugin_qos_dump_sched_group(fal_object_t sg,
				     json_writer_t *wr);

void fal_plugin_dump_memory_buffer_errors(json_writer_t *wr);

/**
 * @brief Enum defining WRED profile attributes
 */
enum fal_qos_wred_attr_t {
	/**
	 * @brief Green enable
	 *
	 * @type bool
	 * @flags CREATE_AND_SET
	 * @default false
	 */
	FAL_QOS_WRED_ATTR_GREEN_ENABLE = 0x00000000,

	/**
	 * @brief Green minimum threshold bytes
	 *
	 * Range 1 - Max Buffer size.
	 *
	 * Default to 0 i.e. maximum buffer size.
	 *
	 * @type uint32_t
	 * @flags CREATE_AND_SET
	 * @default 0
	 * @validonly FAL_QOS_WRED_ATTR_GREEN_ENABLE == true
	 */
	FAL_QOS_WRED_ATTR_GREEN_MIN_THRESHOLD = 0x00000001,

	/**
	 * @brief Green maximum threshold
	 *
	 * Range 1 - Max Buffer size.
	 * Default to 0 i.e. maximum buffer size.
	 *
	 * @type uint32_t
	 * @flags CREATE_AND_SET
	 * @default 0
	 * @validonly FAL_QOS_WRED_ATTR_GREEN_ENABLE == true
	 */
	FAL_QOS_WRED_ATTR_GREEN_MAX_THRESHOLD = 0x00000002,

	/**
	 * @brief Percentage 0 ~ 100
	 *
	 * @type uint32_t
	 * @flags CREATE_AND_SET
	 * @default 100
	 */
	FAL_QOS_WRED_ATTR_GREEN_DROP_PROBABILITY = 0x00000003,

	/**
	 * @brief Weight 0 ~ 15
	 *
	 * @type uint8_t
	 * @flags CREATE_AND_SET
	 * @default 0
	 */
	FAL_QOS_WRED_ATTR_WEIGHT = 0x00000004,

	/**
	 * @brief Yellow enable
	 *
	 * @type bool
	 * @flags CREATE_AND_SET
	 * @default false
	 */
	FAL_QOS_WRED_ATTR_YELLOW_ENABLE = 0x00000005,

	/**
	 * @brief Yellow minimum threshold bytes
	 *
	 * Range 1 - Max Buffer size.
	 *
	 * Default to 0 i.e. maximum buffer size.
	 *
	 * @type uint32_t
	 * @flags CREATE_AND_SET
	 * @default 0
	 * @validonly FAL_QOS_WRED_ATTR_YELLOW_ENABLE == true
	 */
	FAL_QOS_WRED_ATTR_YELLOW_MIN_THRESHOLD = 0x00000006,

	/**
	 * @brief Yellow maximum threshold
	 *
	 * Range 1 - Max Buffer size.
	 * Default to 0 i.e. maximum buffer size.
	 *
	 * @type uint32_t
	 * @flags CREATE_AND_SET
	 * @default 0
	 * @validonly FAL_QOS_WRED_ATTR_GREEN_ENABLE == true
	 */
	FAL_QOS_WRED_ATTR_YELLOW_MAX_THRESHOLD = 0x00000007,

	/**
	 * @brief Yellow Percentage 0 ~ 100
	 *
	 * @type uint32_t
	 * @flags CREATE_AND_SET
	 * @default 100
	 */
	FAL_QOS_WRED_ATTR_YELLOW_DROP_PROBABILITY = 0x00000008,

	/**
	 * @brief Red enable
	 *
	 * @type bool
	 * @flags CREATE_AND_SET
	 * @default false
	 */
	FAL_QOS_WRED_ATTR_RED_ENABLE = 0x00000009,

	/**
	 * @brief Red minimum threshold bytes
	 *
	 * Range 1 - Max Buffer size.
	 *
	 * Default to 0 i.e. maximum buffer size.
	 *
	 * @type uint32_t
	 * @flags CREATE_AND_SET
	 * @default 0
	 * @validonly FAL_QOS_WRED_ATTR_RED_ENABLE == true
	 */
	FAL_QOS_WRED_ATTR_RED_MIN_THRESHOLD = 0x0000000A,

	/**
	 * @brief Red maximum threshold
	 *
	 * Range 1 - Max Buffer size.
	 * Default to 0 i.e. maximum buffer size.
	 *
	 * @type uint32_t
	 * @flags CREATE_AND_SET
	 * @default 0
	 * @validonly FAL_QOS_WRED_ATTR_RED_ENABLE == true
	 */
	FAL_QOS_WRED_ATTR_RED_MAX_THRESHOLD = 0x0000000B,

	/**
	 * @brief Red percentage 0 ~ 100
	 *
	 * @type uint32_t
	 * @flags CREATE_AND_SET
	 * @default 100
	 */
	FAL_QOS_WRED_ATTR_RED_DROP_PROBABILITY = 0x0000000C,

	/* Max value */
	FAL_QOS_WRED_ATTR_MAX = FAL_QOS_WRED_ATTR_RED_DROP_PROBABILITY
};

/**
 * @brief New WRED Profile
 *
 * @param[in] switch_id Switch Id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 * @param[out] wred_id WRED profile Id
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_new_wred(fal_object_t switch_id, uint32_t attr_count,
			    const struct fal_attribute_t *attr_list,
			    fal_object_t *new_wred_id);

/**
 * @brief Delete WRED Profile
 *
 * @param[in] wred_id WRED profile Id of WRED object to delete.
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_del_wred(fal_object_t wred_id);

/**
 * @brief Update an attribute of a WRED profile.
 *
 * @param[in] wred_id WRED profile Id.
 * @param[in] attr Attribute
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_upd_wred(fal_object_t wred_id,
			    const struct fal_attribute_t *attr);

/**
 * @brief Get WRED profile attributes
 *
 * @param[in] wred_id WRED Profile Id
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_get_wred_attrs(fal_object_t wred_id, uint32_t attr_count,
				  struct fal_attribute_t *attr_list);

/**
 * @brief attach device in s/w dataplane
 *        Used by plugin to attach device to s/w forwarding engine
 *
 * @param[in] char *devargs - device argument string used by DPDK to
 *                            instantiate device
 *
 * @return 0 on success, -1 on failure
 */
int fal_attach_device(const char *devargs);

/**
 * @brief attach device in s/w dataplane
 *        Used by plugin to detach device from s/w forwarding engine
 *
 * @param[in] char *device - name of device to be detached
 *
 * @return 0 on success, -1 on failure
 */
int fal_detach_device(const char *device);

/**
 * @brief An enum to specify the portmonitor(mirror) session
 */
enum fal_mirror_session_type_t {
	/** Local SPAN */
	FAL_MIRROR_SESSION_TYPE_LOCAL = 0,
	/** Remote SPAN */
	FAL_MIRROR_SESSION_TYPE_REMOTE,
	/** Enhanced Remote SPAN */
	FAL_MIRROR_SESSION_TYPE_ENHANCED_REMOTE,
};
/**
 * @brief FAL attributes for portmonitor(mirror) session
 */
enum fal_mirror_session_attr_t {
	/**
	 * @brief Portmonitor Session Id, mandatory on create, create only
	 * @type uint8_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_MIRROR_SESSION_ATTR_ID,
	/**
	 * @brief Portmonitor session type
	 * @type enum fal_mirror_session_type_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_MIRROR_SESSION_ATTR_TYPE,
	/**
	 * @brief Portmonitor session state
	 * @type bool, false by default so sessions
	 *  are enabled by default
	 * @flags CREATE_AND_SET
	 */
	FAL_MIRROR_SESSION_ATTR_STATE_DISABLE,
	/**
	 * @brief Portmonitor session destination mirror port
	 * @flags CREATE_AND_SET
	 * @type unsigned int, Interface index for destination port
	 */
	FAL_MIRROR_SESSION_ATTR_MONITOR_PORT,
};

/**
 * @brief New Portmonitor(mirror) Session
 *
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 * @param[out] obj Mirror object id
 * @return Returns 0 for success, error code on failure
 */
int fal_plugin_mirror_session_create(uint32_t attr_count,
			     const struct fal_attribute_t *attr_list,
			     fal_object_t *obj);
/**
 * @brief Delete Portmonitor(mirror) Session
 *
 * @param[out] obj Mirror object id
 * @return Returns 0 for success, error code on failure
 */
int fal_plugin_mirror_session_delete(fal_object_t obj);
/**
 * @brief Set Portmonitor(mirror) Session attribute
 *
 * @param[in] obj Mirror object id
 * @param[in] attr Fal attribute
 * @return Returns 0 for success, error code on failure
 */
int fal_plugin_mirror_session_set_attr(fal_object_t obj,
				 const struct fal_attribute_t *attr);
/**
 * @brief Get Portmonitor(mirror) Session attribute
 *
 * @param[in] obj Mirror object id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 * @return Returns 0 for success, error code on failure
 */
int fal_plugin_mirror_session_get_attr(fal_object_t obj, uint32_t attr_count,
				 struct fal_attribute_t *attr_list);

enum fal_vlan_feature_attr_t {
	/**
	 * @brief The interface to associate this with
	 * @type uint32_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 * @default FAL_NULL_OBJECT_ID
	 */
	FAL_VLAN_FEATURE_INTERFACE_ID,
	/**
	 * @brief The vlan to associate this with
	 * @type uint16_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 * @default FAL_NULL_OBJECT_ID
	 */
	FAL_VLAN_FEATURE_VLAN_ID,
	/**
	 * @brief Enable unicast storm control policer on vlan on port
	 *
	 * Set policer id = FAL_NULL_OBJECT_ID to disable policer
	 * @type fal_object_t
	 * @flags CREATE_AND_SET
	 * @default FAL_NULL_OBJECT_ID
	 *
	 */
	FAL_VLAN_FEATURE_ATTR_UNICAST_STORM_CONTROL_POLICER_ID,

	/**
	 * @brief Enable broadcast storm control policer on vlan on port
	 *
	 * Set policer id = FAL_NULL_OBJECT_ID to disable policer
	 * @type fal_object_t
	 * @flags CREATE_AND_SET
	 * @default FAL_NULL_OBJECT_ID
	 *
	 */
	FAL_VLAN_FEATURE_ATTR_BROADCAST_STORM_CONTROL_POLICER_ID,

	/**
	 * @brief Enable multicast storm control policer on vlan on port
	 *
	 * Set policer id = FAL_NULL_OBJECT_ID to disable policer
	 * @type fal_object_t
	 * @flags CREATE_AND_SET
	 * @default FAL_NULL_OBJECT_ID
	 *
	 */
	FAL_VLAN_FEATURE_ATTR_MULTICAST_STORM_CONTROL_POLICER_ID,

	/**
	 * @brief Enable ingress QoS classification on vlan on port
	 *
	 * Set map id = FAL_NULL_OBJECT_ID to remove map
	 * @type fal_object_t
	 * @flags CREATE_AND_SET
	 * @default FAL_NULL_OBJECT_ID
	 *
	 */
	FAL_VLAN_FEATURE_ATTR_QOS_INGRESS_MAP_ID,

	/**
	 * @brief Upper limit of number of MACs permitted
	 * in the MAC table for a given vlan on the port.
	 * @type uint32_t
	 * @flags CREATE_AND_SET
	 */
	FAL_VLAN_FEATURE_ATTR_MAC_LIMIT,

	/**
	 * @brief Get the current MAC count for a given vlan on the port.
	 * @type uint32_t
	 * @flags READ_ONLY
	 */
	FAL_VLAN_FEATURE_ATTR_MAC_COUNT,

	/**
	 * @brief Enable egress QoS marking on vlan on port
	 *
	 * Set map id = FAL_NULL_OBJECT_ID to remove map
	 * @type fal_object_t
	 * @flags CREATE_AND_SET
	 * @default FAL_NULL_OBJECT_ID
	 *
	 */
	FAL_VLAN_FEATURE_ATTR_QOS_EGRESS_MAP_ID,
};

/**
 * @brief vlan_feature. This allows us to create a new vlan
 * feature that we can add 'features' to. We can then add this to
 * a port to enable those features per vlan per port.
 *
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 * @param[out] obj vlan_feature object id
 * @return Returns 0 for success, error code on failure
 */
int fal_plugin_vlan_feature_create(uint32_t attr_count,
				   const struct fal_attribute_t *attr_list,
				   fal_object_t *obj);
/**
 * @brief Delete vlan_feature
 *
 * @param[out] obj vlan_feature object id
 * @return Returns 0 for success, error code on failure
 */
int fal_plugin_vlan_feature_delete(fal_object_t obj);

/**
 * @brief Set vlan_feature attribute
 *
 * @param[in] obj vlan_feature object id
 * @param[in] attr vlan_feat fal attribute
 * @return Returns 0 for success, error code on failure
 */
int fal_plugin_vlan_feature_set_attr(fal_object_t obj,
				     const struct fal_attribute_t *attr);

/**
 * @brief Get vlan_feature attribute
 *
 * @param[in] obj vlan_feature object id
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return 0 on success. If an attribute in attr_list is
 *	   unsupported by the FAL plugin, it should return
 *	   an error.
 */
int fal_plugin_vlan_feature_get_attr(fal_object_t obj,
				     uint32_t attr_count,
				     struct fal_attribute_t *attr_list);

/**
 * @brief set backplane port
 * @param[in] bp_ifindex backplane interface ifindex
 * @param[in] if_index interface for which backplane binding
 *            is to be set
 * @return Returns 0 for success, error code on failure
 */
int fal_plugin_backplane_bind(unsigned int bp_ifindex, unsigned int if_index);

/**
 * @brief dump backplane information for specified backplane port
 * @param[in] bp_ifindex backplane interface ifindex
 */
void fal_plugin_backplane_dump(unsigned int bp_ifindex, json_writer_t *wr);

/*
 * The following attributes and APIs are for configuring control plane
 * protection (CPP) rate limiters.
 */

/**
 * @brief Enum defining attributes for CPP limiters
 */
enum fal_cpp_limiter_attr_t {
	/**
	 * @brief Rate limiter for link local multicast packets
	 *
	 * @type fal_object_t
	 * @flags CREATE_ONLY
	 */
	FAL_CPP_LIMITER_ATTR_LL_MC = 1,

	/**
	 * @brief Rate limiter for IPv6 packets with extension headers
	 *
	 * @type fal_object_t
	 * @flags CREATE_ONLY
	 */
	FAL_CPP_LIMITER_ATTR_IPV6_EXT = 2,

	/**
	 * @brief Rate limiter for IPv4 fragmented packets
	 *
	 * @type fal_object_t
	 * @flags CREATE_ONLY
	 */
	FAL_CPP_LIMITER_ATTR_IPV4_FRAGMENT = 3,

	/**
	 * @brief Rate limiter for OSPF multicast packets
	 *
	 * @type fal_object_t
	 * @flags CREATE_ONLY
	 */
	FAL_CPP_LIMITER_ATTR_OSPF_MC = 4,

	/**
	 * @brief Rate limiter for OSPF packets
	 *
	 * @type fal_object_t
	 * @flags CREATE_ONLY
	 */
	FAL_CPP_LIMITER_ATTR_OSPF = 5,

	/**
	 * @brief Rate limiter for BGP packets
	 *
	 * @type fal_object_t
	 * @flags CREATE_ONLY
	 */
	FAL_CPP_LIMITER_ATTR_BGP = 6,

	/**
	 * @brief Rate limiter for ICMP packets
	 *
	 * @type fal_object_t
	 * @flags CREATE_ONLY
	 */
	FAL_CPP_LIMITER_ATTR_ICMP = 7,

	/**
	 * @brief Rate limiter for LDP UDP packets
	 *
	 * @type fal_object_t
	 * @flags CREATE_ONLY
	 */
	FAL_CPP_LIMITER_ATTR_LDP_UDP = 8,

	/**
	 * @brief Rate limiter for BFD UDP packets
	 *
	 * @type fal_object_t
	 * @flags CREATE_ONLY
	 */
	FAL_CPP_LIMITER_ATTR_BFD_UDP = 9,

	/**
	 * @brief Rate limiter for RSVP packets
	 *
	 * @type fal_object_t
	 * @flags CREATE_ONLY
	 */
	FAL_CPP_LIMITER_ATTR_RSVP = 10,

	/**
	 * @brief Rate limiter for UDP packets
	 *
	 * @type fal_object_t
	 * @flags CREATE_ONLY
	 */
	FAL_CPP_LIMITER_ATTR_UDP = 11,

	/**
	 * @brief Rate limiter for TCP packets
	 *
	 * @type fal_object_t
	 * @flags CREATE_ONLY
	 */
	FAL_CPP_LIMITER_ATTR_TCP = 12,

	/**
	 * @brief Default rate limiter
	 *
	 * @type fal_object_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_CPP_LIMITER_ATTR_DEFAULT = 13,

	/**
	 * @brief Rate limiter for PIM packets
	 *
	 * @type fal_object_t
	 * @flags CREATE_ONLY
	 */
	FAL_CPP_LIMITER_ATTR_PIM = 14,

	/**
	 * @brief Rate limiter for IP multicast packets
	 *
	 * @type fal_object_t
	 * @flags CREATE_ONLY
	 */
	FAL_CPP_LIMITER_ATTR_IP_MC = 15,
};

/*
 * Create a CPP rate-limiter object
 */
int fal_plugin_create_cpp_limiter(uint32_t attr_count,
				  const struct fal_attribute_t *attr_list,
				  fal_object_t *new_limiter_id);

/*
 * Remove a CPP rate-limiter object
 */
int fal_plugin_remove_cpp_limiter(fal_object_t limiter_id);

/*
 * Get the attributes of a CPP rate-limiter object
 */
int fal_plugin_get_cpp_limiter_attribute(fal_object_t limiter_id,
					 uint32_t attr_count,
					 struct fal_attribute_t *attr_list);

enum fal_ptp_clock_attr_t {
	/**
	 * @brief The clock number (instance) of the PTP clock
	 * @type uint32_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_PTP_CLOCK_CLOCK_NUMBER,

	/**
	 * @brief The domain number of the PTP clock
	 * @type uint8_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_PTP_CLOCK_DOMAIN_NUMBER,

	/**
	 * @brief The clock identity of the PTP clock
	 * @type eui64
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_PTP_CLOCK_CLOCK_IDENTITY,

	/**
	 * @brief The maximum number of ports on this PTP clock
	 * @type uint16_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_PTP_CLOCK_NUMBER_PORTS,

	/**
	 * @brief The priority1 value of the PTP clock
	 * @type uint8_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_PTP_CLOCK_PRIORITY1,

	/**
	 * @brief The priority2 value of the PTP clock
	 * @type uint8_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_PTP_CLOCK_PRIORITY2,

	/**
	 * @brief If set to true, this PTP clock is slave only.
	 *	  If not set, or false, the clock will be capable
	 *	  of running as a master or slave.
	 * @type boolean
	 * @flags CREATE_ONLY
	 */
	FAL_PTP_CLOCK_SLAVE_ONLY,

	/**
	 * @brief If set to true, this PTP clock will use a
	 *	  two-step clock. If not present or false,
	 *	  use a one-step clock.
	 * @type boolean
	 * @flags CREATE_ONLY
	 */
	FAL_PTP_CLOCK_TWO_STEP_FLAG,

	/**
	 * @brief A PTP profile that should be applied to
	 *	  the clock.
	 * @type fal_ptp_clock_profile_t
	 * @flags CREATE_ONLY
	 */
	FAL_PTP_CLOCK_PROFILE,

	/**
	 * @brief An antenna delay in nanoseconds that should
	 *	  be applied to the clock's GPS. Only useful
	 *	  with the G.8275.2 APTS profile.
	 * @type int32_t
	 * @flags CREATE_ONLY
	 */
	FAL_PTP_CLOCK_ANTENNA_DELAY,

	FAL_PTP_CLOCK_MAX
};

enum fal_ptp_clock_profile_t {
	FAL_PTP_CLOCK_DEFAULT_PROFILE = 1, /** IEEE 1588-2008 default profile */
	FAL_PTP_CLOCK_G82752_PROFILE = 2, /** G.8275.2 Telecom profile */
	FAL_PTP_CLOCK_G82752_APTS_PROFILE = 3,
					/** G.8275.2 w/ APTS Telecom profile */
	FAL_PTP_CLOCK_G82751_FWD_PROFILE = 4,
	FAL_PTP_CLOCK_G82751_NON_FWD_PROFILE = 5,
};

/**
 * @brief Create a PTP clock.
 *
 * @param[in]  attr_count Number of attributes
 * @param[in]  attr_list  Array of attributes
 * @param[out] clock      Object id for a PTP clock
 *
 * @return 0 on success, error code for failure
 */
int fal_plugin_create_ptp_clock(uint32_t attr_count,
				struct fal_attribute_t *attr_list,
				fal_object_t *clock);

/**
 * @brief Delete a PTP clock.
 *
 * @param[in]  clock Object id for router intf
 *
 * @return 0 on success, error code for failure
 */
int fal_plugin_delete_ptp_clock(fal_object_t clock);

/**
 * @brief Dump the status of a PTP clock.
 *
 * @param[in] obj  PTP clock
 * @param[in] json JSON writer object
 */
int fal_plugin_dump_ptp_clock(fal_object_t clock, json_writer_t *wr);

enum fal_ptp_port_attr_t {
	/**
	 * @brief The PTP clock object to which this port
	 *	  belongs.
	 * @type fal_object_id
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_PTP_PORT_PTP_CLOCK,

	/**
	 * @brief The port number that should be
	 *	  associated with this port.
	 * @type uint16_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_PTP_PORT_PORT_NUMBER,

	/**
	 * @brief The ifindex of the interface underlying
	 *	  this PTP port.
	 * @type uint32_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_PTP_PORT_UNDERLYING_INTERFACE,

	/**
	 * @brief The VLAN ID that should be used for PTP protocol
	 *	  traffic on this port.
	 * @type uint16_t
	 * @flags CREATE_ONLY
	 */
	FAL_PTP_PORT_VLAN_ID,

	/**
	 * @brief Base-two logarithm of the minDelayReqInterval
	 * @type int8_t
	 * @flags CREATE_ONLY
	 */
	FAL_PTP_PORT_LOG_MIN_DELAY_REQ_INTERVAL,

	/**
	 * @brief Base-two logarithm of the mean announceInterval.
	 * @type int8_t
	 * @flags CREATE_ONLY
	 */
	FAL_PTP_PORT_LOG_ANNOUNCE_INTERVAL,

	/**
	 * @brief Number of announceInterval that have to pass
	 *	  without receipt of an Announce message before
	 *	  generating an event.
	 * @type uint8_t
	 * @flags CREATE_ONLY
	 */
	FAL_PTP_PORT_ANNOUNCE_RECEIPT_TIMEOUT,

	/**
	 * @brief Base-two logarithm of the minPdelayReqInterval.
	 * @type int8_t
	 * @flags CREATE_ONLY
	 */
	FAL_PTP_PORT_LOG_MIN_PDELAY_REQ_INTERVAL,

	/**
	 * @brief Base-two logarithm of the logSyncInterval.
	 * @type int8_t
	 * @flags CREATE_ONLY
	 */
	FAL_PTP_PORT_LOG_SYNC_INTERVAL,

	/**
	 * @brief The IP address of the port.
	 * @type fal_ip_address_t
	 * @flags CREATE_ONLY
	 */
	FAL_PTP_PORT_IP_ADDRESS,

	/**
	 * @brief The MAC address of the port.
	 * @type mac
	 * @flags CREATE_ONLY
	 */
	FAL_PTP_PORT_MAC_ADDRESS,

	/**
	 * @brief The DSCP value to be marked in outgoing packets.
	 * @type uint8_t
	 * @flags CREATE_ONLY
	 */
	FAL_PTP_PORT_DSCP,

	FAL_PTP_PORT_MAX
};

/**
 * @brief Create a PTP port on a PTP clock.
 *
 * @param[in]  attr_count Number of attributes
 * @param[in]  attr_list  Array of attributes
 * @param[out] port       Object id for a PTP port
 *
 * @return 0 on success, error code for failure
 */
int fal_plugin_create_ptp_port(uint32_t attr_count,
			       struct fal_attribute_t *attr_list,
			       fal_object_t *port);

/**
 * @brief Delete a PTP port on a PTP clock.
 *
 * @param[in] port Object id for port
 *
 * @return 0 on success, error code for failure
 */
int fal_plugin_delete_ptp_port(fal_object_t port);

enum fal_ptp_peer_type_t {
	FAL_PTP_PEER_MASTER,	/**< PTP master */
	FAL_PTP_PEER_SLAVE,	/**< PTP slave */
	FAL_PTP_PEER_ALLOWED,	/**< Whitelisted PTP peer */
};

enum fal_ptp_peer_attr_t {
	/**
	 * @brief The PTP port to which this peer should
	 *	  be associated.
	 * @type fal_object_id
	 * @flags MANDATORY_ON_CREATE
	 */
	FAL_PTP_PEER_PTP_PORT,

	/**
	 * @brief The type of this peer.
	 * @type fal_ptp_peer_type_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_PTP_PEER_TYPE,

	/**
	 * @brief The IP address of a peer.
	 * @type fal_ip_address_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_PTP_PEER_IP_ADDRESS,

	/**
	 * @brief The MAC address of a peer.
	 * @type mac
	 * @flags
	 */
	FAL_PTP_PEER_MAC_ADDRESS,

	FAL_PTP_PEER_MAX
};

/**
 * @brief Create a PTP peer on a PTP port.
 *
 * @param[in]  attr_count Number of attributes
 * @param[in]  attr_list  Array of attributes
 * @param[out] peer       Object id for a PTP peer
 *
 * @return 0 on success, error code for failure
 */
int fal_plugin_create_ptp_peer(uint32_t attr_count,
			       struct fal_attribute_t *attr_list,
			       fal_object_t *peer);

/**
 * @brief Delete a PTP peer on a PTP port.
 *
 * @param[in] peer Object id for peer
 *
 * @return 0 on success, error code for failure
 */
int fal_plugin_delete_ptp_peer(fal_object_t peer);

/* Stuff for L3 ACLs */

/**
 * @brief Attribute data for FAL_ACL_TABLE_ATTR_STAGE
 */
enum fal_acl_stage_t {
	FAL_ACL_STAGE_INGRESS,
	FAL_ACL_STAGE_EGRESS,
};

/**
 * @brief ACL IP Type
 */
enum fal_acl_ip_type_t {
	FAL_ACL_IP_TYPE_ANY,		/* Don't care */
	FAL_ACL_IP_TYPE_IP,		/* IPv4 and IPv6 packets */
	FAL_ACL_IP_TYPE_IPV4ANY,	/* Any IPv4 packet */
	FAL_ACL_IP_TYPE_IPV6ANY,	/* Any IPv6 packet */
};

/**
 * @brief Attribute data for FAL_ACL_TABLE_ATTR_BIND_POINT
 */
enum fal_acl_bind_point_type_t {
	FAL_ACL_BIND_POINT_TYPE_ROUTER_INTERFACE,
};

/**
 * @brief ACL Action Type
 */
enum fal_acl_action_type_t {
	FAL_ACL_ACTION_TYPE_PACKET_ACTION,
	FAL_ACL_ACTION_TYPE_COUNTER,
};

/**
 * @brief ACL IP Fragment
 */
enum fal_acl_ip_frag_t {
	FAL_ACL_IP_FRAG_ANY,		/* Any Fragment */
	FAL_ACL_IP_FRAG_HEAD,		/* First Fragment */
	FAL_ACL_IP_FRAG_NON_HEAD,	/* Subsequent Fragment */
};

/**
 * @brief Field match mask
 */
union fal_acl_field_data_mask_t {
	uint16_t u16;
	uint8_t u8;
	uint8_t ip4[4];
	uint8_t ip6[16];
};

/**
 * @brief Field match data
 *
 * The s32 field is used for enum values.
 */
union fal_acl_field_data_data_t {
	int32_t s32;
	uint16_t u16;
	uint8_t u8;
	uint8_t ip4[4];
	uint8_t ip6[16];
};

/**
 * @brief Defines a single ACL filter
 *
 * When this references a data item (e.g. fal_acl_ip_frag_t)
 * the the mask is not defined.  Nor is it defined when
 * the enable field is false;
 *
 * @note IPv4 and IPv6 addresses in Network Byte Order
 */
struct fal_acl_field_data_t {
	union fal_acl_field_data_mask_t mask;
	union fal_acl_field_data_data_t data;
	bool enable;
};

/**
 * The value for an enabled ACL action
 */
union fal_acl_action_parameter_t {
	int32_t s32;		/* For enum values */
	fal_object_t objid;
};

/**
 * @brief Defines a single ACL action
 *
 * @note IPv4 and IPv6 Address expected in Network Byte Order
 */
struct fal_acl_action_data_t {
	/* true to set; false to delete */
	bool enable;

	/* Only valid if enable is true */
	union fal_acl_action_parameter_t parameter;
};

enum fal_acl_table_attr_t {
	/**
	 * @brief Ingress or Egress packets
	 * @type fal_acl_stage_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_ACL_TABLE_ATTR_STAGE,

	/**
	 * @brief The name of this table (group)
	 * The FAL layer should copy this string, not cache the pointer
	 * @type char const *
	 * @flags CREATE_ONLY
	 */
	FAL_ACL_TABLE_ATTR_NAME,

	/**
	 * @brief Type of IP packet, or eventually non IP packets
	 * If FAL_ACL_IP_TYPE_ANY, then entry may still specify
	 * @type fal_acl_ip_type_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_ACL_TABLE_ATTR_IP_TYPE,

	/**
	 * @brief Detailed result (error) status. Is zero for OK.
	 * @type uint32_t
	 * @flags READ_ONLY
	 */
	FAL_ACL_TABLE_ATTR_STATUS,

	/**
	 * @brief List of ACL bind points where this ACL can be applied
	 * @type fal_object_list_t fal_acl_bind_point_type_t
	 * @default empty
	 */
	FAL_ACL_TABLE_ATTR_BIND_POINT_TYPE_LIST,

	/**
	 * @brief List of actions used in this table
	 * @type fal_object_list_t fal_acl_action_type_t
	 */
	FAL_ACL_TABLE_ATTR_ACTION_TYPE_LIST,

	/*
	 * The following chunk has match fields; all bool, default to false
	 */

	/**
	 * @brief Source IPv4 address
	 * @type bool
	 */
	FAL_ACL_TABLE_ATTR_FIELD_SRC_IPV4,

	/**
	 * @brief Destination IPv4 address
	 * @type bool
	 */
	FAL_ACL_TABLE_ATTR_FIELD_DST_IPV4,

	/**
	 * @brief Source IPv6 address
	 * @type bool
	 */
	FAL_ACL_TABLE_ATTR_FIELD_SRC_IPV6,

	/**
	 * @brief Destination IPv6 address
	 * @type bool
	 */
	FAL_ACL_TABLE_ATTR_FIELD_DST_IPV6,

	/**
	 * @brief L4 Source port
	 * @type bool
	 */
	FAL_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT,

	/**
	 * @brief L4 Destination port
	 * @type bool
	 */
	FAL_ACL_TABLE_ATTR_FIELD_L4_DST_PORT,

	/**
	 * @brief L4 TCP flags
	 * @type bool
	 */
	FAL_ACL_TABLE_ATTR_FIELD_TCP_FLAGS,

	/**
	 * @brief Protocol field from IP(v4 or v6) header
	 * @type bool
	 */
	FAL_ACL_TABLE_ATTR_FIELD_IP_PROTO_BASE,

	/**
	 * @brief Protocol value of the final IP(v4 or v6) header
	 *
	 * This represents the terminal protocol in the chain,
	 * so [IPv4|AHP|TCP] would match as TCP; and [IPv6|HBH|UDP]
	 * would match as UDP.
	 *
	 * Note that [IPv4|HIP] or [IPv4|AHP|HIP] with the HIP
	 * 'next header' field being 50 (No next header) should
	 * match as 'HIP',  similarly for any IPv6 cases where
	 * the header chain terminates with a 'No next header'
	 * value.
	 *
	 * This is a generalisation of SAI_ACL_TABLE_ATTR_FIELD_IPV6_NEXT_HEADER
	 * and a given platform may not support it for the IPv4
	 * case.
	 *
	 * TBD - what happens if the base IP header has a protocol
	 * of 'No next header', or if we see [IPv6|DstOpt] and the
	 * 'next header' for 'DstOpt' is 'no next header'.
	 *
	 * @type bool
	 */
	FAL_ACL_TABLE_ATTR_FIELD_IP_PROTO_FINAL,

	/**
	 * @brief TTL field from IP(v4 or v6) header
	 * For IPv6, this is the 'Hop Count' field.
	 * @type bool
	 */
	FAL_ACL_TABLE_ATTR_FIELD_IP_TTL,

	/**
	 * @brief DSCP field from IP (either version) header
	 * @type bool
	 */
	FAL_ACL_TABLE_ATTR_FIELD_IP_DSCP,

	/**
	 * @brief IP fragment
	 * @type bool
	 */
	FAL_ACL_TABLE_ATTR_FIELD_IP_FRAG,

	/**
	 * @brief ICMP(v4) type
	 * @type bool
	 */
	FAL_ACL_TABLE_ATTR_FIELD_ICMP_TYPE,

	/**
	 * @brief ICMP(v4) code
	 * @type bool
	 */
	FAL_ACL_TABLE_ATTR_FIELD_ICMP_CODE,

	/**
	 * @brief ICMP(v6) type
	 * @type bool
	 */
	FAL_ACL_TABLE_ATTR_FIELD_ICMPV6_TYPE,

	/**
	 * @brief ICMP(v6) code
	 * @type bool
	 */
	FAL_ACL_TABLE_ATTR_FIELD_ICMPV6_CODE,
};

enum fal_acl_entry_attr_t {
	/**
	 * @brief The ACL table (named group) to associate this with
	 * @type fal_acl_table_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_ACL_ENTRY_ATTR_TABLE_ID,

	/**
	 * @brief Priority (Highest value has highest priority)
	 * @type uint16_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_ACL_ENTRY_ATTR_PRIORITY,

	/**
	 * @brief Admin state (false is disabled)
	 * @type bool
	 */
	FAL_ACL_ENTRY_ATTR_ADMIN_STATE,

	/**
	 * @brief Detailed result (error) status. Is zero for OK.
	 * @type uint32_t
	 * @flags READ_ONLY
	 */
	FAL_ACL_ENTRY_ATTR_STATUS,

	/*
	 * The following chunk has action fields
	 */

	/**
	 * @brief Packet Actions (e.g. Drop, Pass, etc)
	 *
	 * @type fal_acl_action_data_t fal_packet_action_t
	 * @flags CREATE_AND_SET
	 * @default disabled
	 */
	FAL_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION,

	/**
	 * @brief Attach/detach counter id to the entry
	 *
	 * @type fal_acl_action_data_t fal_object_id_t
	 * @flags CREATE_AND_SET
	 * @objects FAL_OBJECT_TYPE_ACL_COUNTER
	 * @default disabled
	 */
	FAL_ACL_ENTRY_ATTR_ACTION_COUNTER,

	/*
	 * The following chunk has match fields
	 */

	/**
	 * @brief Source IPv4 address
	 * @type fal_acl_field_data_t ip4
	 */
	FAL_ACL_ENTRY_ATTR_FIELD_SRC_IPV4,

	/**
	 * @brief Destination IPv4 address
	 * @type fal_acl_field_data_t ip4
	 */
	FAL_ACL_ENTRY_ATTR_FIELD_DST_IPV4,

	/**
	 * @brief Source IPv6 address
	 * @type fal_acl_field_data_t ip6
	 */
	FAL_ACL_ENTRY_ATTR_FIELD_SRC_IPV6,

	/**
	 * @brief Destination IPv6 address
	 * @type fal_acl_field_data_t ip6
	 */
	FAL_ACL_ENTRY_ATTR_FIELD_DST_IPV6,

	/**
	 * @brief L4 Source port
	 * @type fal_acl_field_data_t u16
	 */
	FAL_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT,

	/**
	 * @brief L4 Destination port
	 * @type fal_acl_field_data_t u16
	 */
	FAL_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT,

	/**
	 * @brief L4 TCP flags (12 bits)
	 * @type fal_acl_field_data_t u16
	 */
	FAL_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS,

	/**
	 * @brief Protocol field from IP(v4 or v6) header
	 * @type fal_acl_field_data_t u8
	 */
	FAL_ACL_ENTRY_ATTR_FIELD_IP_PROTO_BASE,

	/**
	 * @brief Protocol value of the final IP(v4 or v6) header
	 *
	 * This represents the terminal protocol in the chain,
	 * so [IPv4|AHP|TCP] would match as TCP; and [IPv6|HBH|UDP]
	 * would match as UDP.
	 *
	 * Note that [IPv4|HIP] or [IPv4|AHP|HIP] with the HIP
	 * 'next header' field being 50 (No next header) should
	 * match as 'HIP',  similarly for any IPv6 cases where
	 * the header chain terminates with a 'No next header'
	 * value.
	 *
	 * This is a generalisation of SAI_ACL_ENTRY_ATTR_FIELD_IPV6_NEXT_HEADER
	 * and a given platform may not support it for the IPv4
	 * case.
	 *
	 * TBD - what happens if the base IP header has a protocol
	 * of 'No next header', or if we see [IPv6|DstOpt] and the
	 * 'next header' for 'DstOpt' is 'no next header'.
	 *
	 * @type fal_acl_field_data_t u8
	 */
	FAL_ACL_ENTRY_ATTR_FIELD_IP_PROTO_FINAL,

	/**
	 * @brief TTL field from IP(v4 or v6) header
	 * For IPv6, this is the 'Hop Count' field.
	 * @type fal_acl_field_data_t u8
	 */
	FAL_ACL_ENTRY_ATTR_FIELD_IP_TTL,

	/**
	 * @brief DSCP field (6 bits) from IP(v4 or v6) header
	 * @type fal_acl_field_data_t
	 */
	FAL_ACL_ENTRY_ATTR_FIELD_IP_DSCP,

	/**
	 * @brief IP fragment
	 * @type fal_acl_ip_frag
	 */
	FAL_ACL_ENTRY_ATTR_FIELD_IP_FRAG,

	/**
	 * @brief ICMP(v4) type
	 * @type fal_acl_field_data_t u8
	 */
	FAL_ACL_ENTRY_ATTR_FIELD_ICMP_TYPE,

	/**
	 * @brief ICMP(v4) code
	 * @type fal_acl_field_data_t u8
	 */
	FAL_ACL_ENTRY_ATTR_FIELD_ICMP_CODE,

	/**
	 * @brief ICMP(v6) type
	 * @type fal_acl_field_data_t u8
	 */
	FAL_ACL_ENTRY_ATTR_FIELD_ICMPV6_TYPE,

	/**
	 * @brief ICMP(v6) code
	 * @type fal_acl_field_data_t u8
	 */
	FAL_ACL_ENTRY_ATTR_FIELD_ICMPV6_CODE,
};

enum fal_acl_counter_attr_t {
	/**
	 * @brief The ACL table (named group) to associate this with
	 * @type fal_acl_table_t
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_ACL_COUNTER_ATTR_TABLE_ID,

	/**
	 * @brief Detailed result (error) status. Is zero for OK.
	 * @type uint32_t
	 * @flags READ_ONLY
	 */
	FAL_ACL_COUNTER_ATTR_STATUS,

	/**
	 * @brief Enable/disable packet count
	 *
	 * @type bool
	 * @flags CREATE_ONLY
	 * @default false
	 */
	FAL_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT,

	/**
	 * @brief Enable/disable byte count
	 *
	 * @type bool
	 * @flags CREATE_ONLY
	 * @default false
	 */
	FAL_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT,

	/**
	 * @brief Get/set packet count
	 *
	 * @type uint64_t
	 * @flags CREATE_AND_SET
	 * @default 0
	 */
	FAL_ACL_COUNTER_ATTR_PACKETS,

	/**
	 * @brief Get/set byte count
	 *
	 * @type uint64_t
	 * @flags CREATE_AND_SET
	 * @default 0
	 */
	FAL_ACL_COUNTER_ATTR_BYTES,
};

/**
 * @brief Create a table for ACL entries/rules
 *
 * @param[in] attr_count Number of attributes
 * @param[in] attr List of attribute ids and values
 * @param[out] new_table_id Identifier for the table
 *
 * @return 0 on success or failure status.
 */
int fal_plugin_acl_create_table(uint32_t attr_count,
			 const struct fal_attribute_t *attr,
			 fal_object_t *new_table_id);

/**
 * @brief Delete a table of ACL entries/rules
 *
 * @param[in] table_id Identifier for the table
 *
 * @return 0 on success or failure status.
 */
int fal_plugin_acl_delete_table(fal_object_t table_id);

/**
 * @brief Set an attribute of a table
 *
 * @param[in] table_id Identifier for the table
 * @param[in] attr The attribute id and value to be set
 *
 * @return 0 on success or failure status.
 */
int fal_plugin_acl_set_table_attr(fal_object_t table_id,
			   const struct fal_attribute_t *attr);

/**
 * @brief Get a table attribute
 *
 * @param[in] table_id Identifier for the table
 * @param[in] attr_count The number of attributes to retrieve
 * @param[in/out] attr_list A list of attributes to be retrieved and
 *                          there values
 *
 * @return 0 on success or failure status.
 */
int fal_plugin_acl_get_table_attr(fal_object_t table_id,
			   uint32_t attr_count,
			   struct fal_attribute_t *attr_list);

/**
 * @brief Create an entry/rule
 *
 * @param[in] attr_count Number of attributes
 * @param[in] attr The attributes and values for the entry/rule
 * @param[out] new_entry_id Entry identifier
 *
 * @return 0 on success or failure status.
 */
int fal_plugin_acl_create_entry(uint32_t attr_count,
			 const struct fal_attribute_t *attr,
			 fal_object_t *new_entry_id);

/**
 * @brief Delete an entry/rule
 *
 * @param[in] entry_id Entry identifier
 *
 * @return 0 on success or failure status.
 */
int fal_plugin_acl_delete_entry(fal_object_t entry_id);

/**
 * @brief Set an entry/rule attribute
 *
 * @param[in] entry_id Entry identifier
 * @param[in] attr The attribute to change and the new value
 *
 * @return 0 on success or failure status.
 */
int fal_plugin_acl_set_entry_attr(fal_object_t entry_id,
			   const struct fal_attribute_t *attr);

/**
 * @brief Get an entry/rule
 *
 * @param[in] entry_id Entry identifier
 * @param[in] attr_count Number of attributes
 * @param[in/out] attr_list A list of the attributes and their
 *                          associated values
 *
 * @return 0 on success or failure status.
 */
int fal_plugin_acl_get_entry_attr(fal_object_t entry_id,
			   uint32_t attr_count,
			   struct fal_attribute_t *attr_list);

/**
 * @brief Create a counter for an entry/rule
 *
 * @param[in] attr_count Number of attributes
 * @param[in] attr A list of attributes and their associated values
 * @param[out] new_counter_id Entry identifier
 *
 * @return 0 on success or failure status.
 */
int fal_plugin_acl_create_counter(uint32_t attr_count,
			   const struct fal_attribute_t *attr,
			   fal_object_t *new_counter_id);
/**
 * @brief Delete a counter for an entry/rule
 *
 * @param[in] counter_id Entry identifier
 *
 * @return 0 on success or failure status.
 */
int fal_plugin_acl_delete_counter(fal_object_t counter_id);

/**
 * @brief Set a counter attribute for a entry/rule
 *
 * @param[in] counter_id Entry identifier
 * @param[in] attr An attribute identifier and its new value
 *
 * @return 0 on success or failure status.
 */
int fal_plugin_acl_set_counter_attr(fal_object_t counter_id,
			     const struct fal_attribute_t *attr);

/**
 * @brief Get a counter list of attributes for an entry/rule
 *
 * @param[in] counter_id Entry identifier
 * @param[in] attr_count Number of attributes
 * @param[in/out] attr_list A list of attributes and their associated
 *			    values
 *
 * @return 0 on success or failure status.
 */
int fal_plugin_acl_get_counter_attr(fal_object_t counter_id,
			     uint32_t attr_count,
			     struct fal_attribute_t *attr_list);
/* End of ACL Stuff */

/*
 * Packet capture (snooping) attributes & functions
 */

enum fal_capture_attr_t {
	/**
	 * @brief Capture copy (crop) size - how much of the frame to
	 * capture
	 * @flags CREATE_ONLY
	 * @type  uint32_t
	 * @default 0 (copy whole frame)
	 */
	FAL_CAPTURE_ATTR_COPY_LENGTH,

	/**
	 * @brief How much backplane bandwidth to be used by captured
	 * frames (Kbits/sec)
	 * @flags CREATE_ONLY
	 * @type uint32_t
	 * @default 0 (2000Kbps)
	 */
	FAL_CAPTURE_ATTR_BANDWIDTH,
};

int fal_plugin_capture_create(uint32_t attr_count,
			      const struct fal_attribute_t *attr_list,
			      fal_object_t *obj);
void fal_plugin_capture_delete(fal_object_t obj);

/* BFD Definitions */

/**
 * @brief FAL session type of BFD
 */
enum fal_bfd_session_type_t {
	/** Demand Active Mode */
	FAL_BFD_SESSION_TYPE_DEMAND_ACTIVE = 0,

	/** Demand Passive Mode */
	FAL_BFD_SESSION_TYPE_DEMAND_PASSIVE,

	/** Asynchronous Active Mode */
	FAL_BFD_SESSION_TYPE_ASYNC_ACTIVE,

	/** Asynchronous Passive Mode */
	FAL_BFD_SESSION_TYPE_ASYNC_PASSIVE,
};

/**
 * @brief FAL type of encapsulation tunnel for BFD
 */
enum fal_bfd_encapsulation_type_t {
	/**
	 * @brief IP in IP Encapsulation | L2 Ethernet header | IP header |
	 * Inner IP header | Original BFD packet
	 */
	FAL_BFD_ENCAPSULATION_TYPE_IP_IN_IP,

	/**
	 * @brief L3 GRE Tunnel Encapsulation | L2 Ethernet header | IP header |
	 * GRE header | Original BFD packet
	 */
	FAL_BFD_ENCAPSULATION_TYPE_L3_GRE_TUNNEL,
};

/**
 * @brief FAL BFD session state
 */
enum fal_bfd_session_state_t {
	/** BFD Session is in Admin down */
	FAL_BFD_SESSION_STATE_ADMIN_DOWN,

	/** BFD Session is Down */
	FAL_BFD_SESSION_STATE_DOWN,

	/** BFD Session is in Initialization */
	FAL_BFD_SESSION_STATE_INIT,

	/** BFD Session is Up */
	FAL_BFD_SESSION_STATE_UP,
};

/**
 * @brief FAL BFD session diagnostic
 */
enum fal_bfd_session_diag_t {
	/** No Diagnostic */
	FAL_BFD_DIAG_NONE,

	/** Control Detection Time Expired */
	FAL_BFD_DIAG_DETECT_EXPIRE,

	/** Echo Function Failed */
	FAL_BFD_DIAG_ECHO_FAIL,

	/** Neighbor Signaled Session Down */
	FAL_BFD_DIAG_NEIGH_DOWN,

	/** Forwarding Plane Reset */
	FAL_BFD_DIAG_FWD_RESET,

	/** Path Down */
	FAL_BFD_DIAG_PATH_DOWN,

	/** Concatenated Path Down */
	FAL_BFD_DIAG_CONCAT_DOWN,

	/** Administratively Down */
	FAL_BFD_DIAG_ADMIN_DOWN,

	/** Reverse Concatenated Path Down */
	FAL_BFD_DIAG_REV_CONCAT_DOWN,
};

/**
 * @ brief BFD PDU flags
 */
union fal_bfd_pdu_flags_t {
	struct {
		/** BFD PDU flags byte value */
		uint8_t flags;
		/** BFD Param changed, 0 - not changed, 1 - changed */
		uint8_t param_changed;
		uint8_t reserved1;
		uint8_t reserved2;
	};
	uint32_t val;
};

/**
 * @brief Defines the operational status of the BFD session
 */
struct fal_bfd_session_state_notification_t {
	/** BFD Session id */
	fal_object_t bfd_session_id;

	/** BFD session state */
	enum fal_bfd_session_state_t session_state;

	/** BFD remote session state */
	enum fal_bfd_session_state_t remote_state;

	/** BFD local session diagnostic */
	enum fal_bfd_session_diag_t local_diag;

	/** BFD remote session diagnostic */
	enum fal_bfd_session_diag_t remote_diag;

	/** BFD remote PDU flag bits */
	union fal_bfd_pdu_flags_t remote_pdu_flags;

	/** BFD remote discriminator */
	uint32_t remote_session_id;

	/** BFD rx interval received from remote peer */
	uint32_t remote_rx_required;

	/** BFD negotiated Tx interval max(local Tx, remote Rx) */
	uint32_t tx_negotiated;

	/** BFD negotiated Rx interval max(local Rx, remote Tx) */
	uint32_t rx_negotiated;

	/** BFD remote detect multiplier */
	uint32_t remote_detect_mult;
};

/**
 * @brief FAL attributes for BFD session
 */
enum fal_bfd_session_attr_t {
	/**
	 * @brief Start of attributes
	 */
	FAL_BFD_SESSION_ATTR_START,

	/**
	 * @brief BFD Session type DEMAND/ASYNCHRONOUS
	 *
	 * @type u8
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_BFD_SESSION_ATTR_TYPE = FAL_BFD_SESSION_ATTR_START,

	/**
	 * @brief Router interface ojbect
	 *
	 * @type fal_object_t
	 * @flags CREATE_AND_SET
	 */
	FAL_BFD_SESSION_ATTR_ROUTER_INTERFACE,

	/**
	 * @brief Local discriminator
	 *
	 * @type u32
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_BFD_SESSION_ATTR_LOCAL_DISCRIMINATOR,

	/**
	 * @brief Remote discriminator
	 *
	 * @type u32
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_BFD_SESSION_ATTR_REMOTE_DISCRIMINATOR,

	/**
	 * @brief UDP Source port
	 *
	 * @type u32
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_BFD_SESSION_ATTR_UDP_SRC_PORT,

	/**
	 * @brief Encapsulation type
	 *
	 * @type u8 fal_bfd_encapsulation_type_t
	 * @flags CREATE_ONLY
	 */
	FAL_BFD_SESSION_ATTR_BFD_ENCAPSULATION_TYPE,

	/**
	 * @brief IP header version
	 *
	 * @type u8
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_BFD_SESSION_ATTR_IPHDR_VERSION,

	/**
	 * @brief IP header TOS
	 *
	 * @type u8
	 * @flags CREATE_AND_SET
	 * @default 0
	 */
	FAL_BFD_SESSION_ATTR_TOS,

	/**
	 * @brief IP header TTL
	 *
	 * @type u8
	 * @flags CREATE_AND_SET
	 * @default 255
	 */
	FAL_BFD_SESSION_ATTR_TTL,

	/**
	 * @brief Source IP
	 *
	 * @type ipaddr
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_BFD_SESSION_ATTR_SRC_IP_ADDRESS,

	/**
	 * @brief Destination IP
	 *
	 * @type ipaddr
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 */
	FAL_BFD_SESSION_ATTR_DST_IP_ADDRESS,

	/**
	 * @brief Tunnel IP header TOS
	 *
	 * @type u8
	 * @flags CREATE_AND_SET
	 * @default 0
	 * @validonly FAL_BFD_SESSION_ATTR_BFD_ENCAPSULATION_TYPE ==
	 * FAL_BFD_ENCAPSULATION_TYPE_IP_IN_IP
	 */
	FAL_BFD_SESSION_ATTR_TUNNEL_TOS,

	/**
	 * @brief Tunnel IP header TTL
	 *
	 * @type u8
	 * @flags CREATE_AND_SET
	 * @default 255
	 * @validonly FAL_BFD_SESSION_ATTR_BFD_ENCAPSULATION_TYPE ==
	 * FAL_BFD_ENCAPSULATION_TYPE_IP_IN_IP
	 */
	FAL_BFD_SESSION_ATTR_TUNNEL_TTL,

	/**
	 * @brief Tunnel source IP
	 *
	 * @type ipaddr
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 * @condition FAL_BFD_SESSION_ATTR_BFD_ENCAPSULATION_TYPE ==
	 * FAL_BFD_ENCAPSULATION_TYPE_IP_IN_IP
	 */
	FAL_BFD_SESSION_ATTR_TUNNEL_SRC_IP_ADDRESS,

	/**
	 * @brief Tunnel destination IP
	 *
	 * @type ipaddr
	 * @flags MANDATORY_ON_CREATE | CREATE_ONLY
	 * @condition FAL_BFD_SESSION_ATTR_BFD_ENCAPSULATION_TYPE ==
	 * FAL_BFD_ENCAPSULATION_TYPE_IP_IN_IP
	 */
	FAL_BFD_SESSION_ATTR_TUNNEL_DST_IP_ADDRESS,

	/**
	 * @brief Multi hop BFD session
	 *
	 * @type bool
	 * @flags CREATE_ONLY
	 * @default false
	 */
	FAL_BFD_SESSION_ATTR_MULTIHOP,

	/**
	 * @brief Minimum Transmit interval in microseconds
	 *
	 * @type u32
	 * @flags MANDATORY_ON_CREATE | CREATE_AND_SET
	 */
	FAL_BFD_SESSION_ATTR_MIN_TX,

	/**
	 * @brief Negotiated Transmit interval in microseconds
	 *
	 * @type u32
	 * @flags MANDATORY_ON_CREATE | CREATE_AND_SET
	 */
	FAL_BFD_SESSION_ATTR_NEGOTIATED_TX,

	/**
	 * @brief Minimum Receive interval in microseconds
	 *
	 * @type u32
	 * @flags MANDATORY_ON_CREATE | CREATE_AND_SET
	 */
	FAL_BFD_SESSION_ATTR_MIN_RX,

	/**
	 * @brief Negotiated Receive interval in microseconds
	 *
	 * @type u32
	 * @flags MANDATORY_ON_CREATE | CREATE_AND_SET
	 */
	FAL_BFD_SESSION_ATTR_NEGOTIATED_RX,

	/**
	 * @brief Detection time Multiplier of local endpoint
	 *
	 * @type u8
	 * @flags MANDATORY_ON_CREATE | CREATE_AND_SET
	 */
	FAL_BFD_SESSION_ATTR_DETECT_MULT,

	/**
	 * @brief Minimum Remote Transmit interval in microseconds
	 *
	 * @type u32
	 * @flags READ_ONLY
	 */
	FAL_BFD_SESSION_ATTR_REMOTE_MIN_TX,

	/**
	 * @brief Minimum Remote Receive interval in microseconds
	 *
	 * @type u32
	 * @flags READ_ONLY
	 */
	FAL_BFD_SESSION_ATTR_REMOTE_MIN_RX,

	/**
	 * @brief Detection time Multiplier of remote endpoint
	 *
	 * @type u8
	 * @flags READ_ONLY
	 */
	FAL_BFD_SESSION_ATTR_REMOTE_DETECT_MULT,

	/**
	 * @brief BFD session detection time in microseconds
	 *
	 * @type u32
	 * @flags CREATE_AND_SET
	 */
	FAL_BFD_SESSION_ATTR_DETECTION_TIME,

	/**
	 * @brief BFD Session state
	 *
	 * @type u8 fal_bfd_session_state_t
	 * @flags READ_ONLY
	 */
	FAL_BFD_SESSION_ATTR_STATE,

	/**
	 * @brief BFD Remote Session state
	 *
	 * @type u8 fal_bfd_session_state_t
	 * @flags READ_ONLY
	 */
	FAL_BFD_SESSION_ATTR_REMOTE_STATE,

	/**
	 * @brief BFD Local diagnostic
	 *
	 * @type u8 fal_bfd_session_diag_t
	 * @flags READ_ONLY
	 */
	FAL_BFD_SESSION_ATTR_LOCAL_DIAG,

	/**
	 * @brief BFD Remote diagnostic
	 *
	 * @type u8 fal_bfd_session_diag_t
	 * @flags READ_ONLY
	 */
	FAL_BFD_SESSION_ATTR_REMOTE_DIAG,

	/**
	 * @brief Next hop for a multi hop BFD session
	 *
	 * @type ipaddr
	 * @flags CREATE_AND_SET
	 * @validonly FAL_BFD_SESSION_ATTR_MULTIHOP == true
	 */
	FAL_BFD_SESSION_ATTR_NEXTHOP,

	/**
	 * @brief BFD packet drop precedence in egress traffic,
	 *        BFD should use FAL_PACKET_COLOUR_GREEN
	 *
	 * @type  enum fal_packet_colour
	 * @flags MANDATORY_ON_CREATE | CREATE_AND_SET
	 */
	FAL_BFD_SESSION_ATTR_PKT_COLOUR,

	/**
	 * @brief BFD packet priority queue in egress traffic,
	 *        Value range: 0-7. BFD should be applied to highest prioirty
	 *
	 * @type u32
	 * @flags MANDATORY_ON_CREATE | CREATE_AND_SET
	 */
	FAL_BFD_SESSION_ATTR_PKT_DESIGNATOR,

	/**
	 * @brief BFD packet local flags
	 *
	 * @type u32
	 * @flags MANDATORY_ON_CREATE | CREATE_AND_SET
	 */
	FAL_BFD_SESSION_ATTR_POLL_BIT,

	/**
	 * @brief BFD packet local flags
	 *
	 * @type u32
	 * @flags MANDATORY_ON_CREATE | CREATE_AND_SET
	 */
	FAL_BFD_SESSION_ATTR_FINAL_BIT,

	/**
	 * @brief End of attributes
	 */
	FAL_BFD_SESSION_ATTR_END,

};

/**
 * @brief BFD Session counter IDs in fal_get_bfd_session_stats() call
 */
enum fal_bfd_session_stat_t {
	/** Ingress packet stat count */
	FAL_BFD_SESSION_STAT_IN_PACKETS,

	/** Egress packet stat count */
	FAL_BFD_SESSION_STAT_OUT_PACKETS,

	/** Packet Drop stat count */
	FAL_BFD_SESSION_STAT_DROP_PACKETS

};

/**
 * @brief HW mode of supporting BFD
 */
enum fal_bfd_hw_mode {
	/** Unknown running mode */
	FAL_BFD_HW_MODE_UNKNOWN,

	/*
	 * HW BFD does not maintain state machine in hardware resource.
	 * Session state transition, flags and parameter negotiation
	 * depend on Dataplane software.
	 */
	FAL_BFD_HW_MODE_CP_DEPENDENT,
	FAL_BFD_HW_MODE_DP_SW_DEPENDENT = FAL_BFD_HW_MODE_CP_DEPENDENT,

	/*
	 * HW BFD is Independent of the Dataplane software state.
	 * Full BFD state machine is maintained in hardware layer.
	 * HW session initial state cannot be set flexibly, but fixed
	 * to be DOWN
	 */
	FAL_BFD_HW_MODE_CP_INDEPENDENT,
	FAL_BFD_HW_MODE_DP_SW_INDEPENDENT = FAL_BFD_HW_MODE_CP_INDEPENDENT,
};

/**
 * @brief Create BFD session.
 *
 * @param[out] bfd_session_id BFD session id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Value of attributes
 *
 * @return 0 if operation is successful otherwise a different
 * error code is returned.
 */
int fal_plugin_bfd_create_session(fal_object_t *bfd_session_id,
				  uint32_t attr_count,
				  const struct fal_attribute_t *attr_list);

/**
 * @brief Delete BFD session.
 *
 * @param[in] bfd_session_id BFD session id
 *
 * @return 0 if operation is successful otherwise a different
 * error code is returned.
 */
int fal_plugin_bfd_delete_session(fal_object_t bfd_session_id);

/**
 * @brief Set BFD session attributes.
 *
 * @param[in] bfd_session_id BFD session id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Value of attributes
 *
 * @return 0 if operation is successful otherwise a different
 * error code is returned.
 */
int fal_plugin_bfd_set_session_attribute(fal_object_t bfd_session_id,
				  uint32_t attr_count,
				  const struct fal_attribute_t *attr_list);

/**
 * @brief Get BFD session attributes.
 *
 * @param[in] bfd_session_id BFD session id
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Value of attribute
 *
 * @return 0 if operation is successful otherwise a different
 * error code is returned.
 */
int fal_plugin_bfd_get_session_attribute(fal_object_t bfd_session_id,
				  uint32_t attr_count,
				  struct fal_attribute_t *attr_list);

/**
 * @brief Get BFD session statistics counters.
 *
 * @param[in] bfd_session_id BFD session id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 * @param[out] counters Array of resulting counter values.
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_bfd_get_session_stats(fal_object_t bfd_session_id,
			      uint32_t number_of_counters,
			      const enum fal_bfd_session_stat_t *counter_ids,
			      uint64_t *counters);

/**
 * @brief BFD session state change notification
 *
 * Passed as a parameter to FAL_SWITCH_ATTR_BFD_SESSION_STATE_NOTIFY
 *
 * @count data[count]
 *
 * @param[in] count Number of notifications
 * @param[in] data Array of BFD session state
 */
typedef void (*fal_bfd_session_state_change_notification_fn)(
	uint32_t count,
	struct fal_bfd_session_state_notification_t *data);

/* End of BFD Definitions */

#endif /* VYATTA_DATAPLANE_FAL_PLUGIN_H */
