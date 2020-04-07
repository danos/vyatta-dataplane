/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef VYATTA_DATAPLANE_PIPELINE_H
#define VYATTA_DATAPLANE_PIPELINE_H

#include <stdint.h>

/*
 * The pipeline is the part that of the feature plugin that interacts
 * with packets.  When a packet is received it enters the pipeline where
 * it makes its way through the nodes in a graph. Each node does its
 * specific processing before passing the packet on to the next node
 * Once the packet reaches an output node it is finished.
 *
 * The graph is constructed at dataplane start, using all the builtin nodes
 * plus any that are added by the feature plugins.
 *
 * NODES
 * =====
 *
 * Each node declares the set of possible next nodes in the graph, and when
 * a packet it being processed by a node it must transition to one of possible
 * next-nodes.  The next nodes are typically of the form: drop, consume,
 * accept. They specify what this node has decided to do with the packet.
 * They do not typically specify the overall order of the graph. That is done
 * by the features.
 *
 * A node has a type that defines the behaviour for that node.  Most nodes
 * that are added as part of plugins will be of type PL_PROC.
 *
 * A node has a domain and a name. The default domain for all builtin nodes
 * is 'vyatta' and this must not be used for nodes added by feature plugins.
 *
 * An example built in node (using the default domain 'vyatta') is:
 *
 * /----------------------\
 * |                      |  -> ACCEPT  (ipv4-route-lookup)
 * | vyatta:ipv4-validate |  -> DROP    (term-drop)
 * |                      |  -> CONSUME (term-finish)
 * \----------------------/
 *
 * An example feature-plugin could be of the form:
 *
 * /--------------\
 * |              |  -> ACCEPT  (term-noop)
 * | domain:feat1 |  -> CONSUME (term-finish)
 * |              |  -> DROP    (term-drop)
 * |              |  -> DROP    (domain1:drop-and-count)
 * \--------------/
 *
 * Where the feature will either decide to either:
 *  - accept the packet, and move to the next step of processing
 *  - consume the packet (its processing is now finished)
 *  - drop the given packet using the existing drop node.
 *  - drop the packet with a custom drop node (which is registered as another
 *    node)
 *
 * A node is registered using: pipeline_register_node()
 *
 *
 * FEATURES
 * ========
 *
 * A node can be declared to be a feature-point node. When this happens there
 * are some extra handler functions added and these allow features to be run
 * on packets at that feature-point node.
 *
 * A feature is a node that is run from a feature-point.
 *
 * When a node is declared as a feature-point it will run a sub-graph
 * of all the features for that feature-point, and after processing of that
 * sub graph it will call its next node (unless the subgraph has called an
 * output node).
 *
 * When the graph is built each feature point will sort the features
 * associated with it based on the ordering constraints specified at
 * feature registration.
 *
 * Feature nodes can be dynamically enabled/disabled, and during packet
 * processing only the ones that are enabled will be called.
 *
 * There are some well known feature-points that are in the builtin graph
 * and these are the ones that plugin features will be associated with.
 *
 * An example of this is the ipv4-validate node shown in the NODES section
 * above.
 *
 * If we register our example feature node from above with it the graph
 * for this part would become:
 *
 *
 * /----------------------\
 * |                      |  -> (feature_subgraph) -> ACCEPT (ipv4-route-lookup)
 * |                      |                        -> CONSUME
 * |                      |
 * | vyatta:ipv4-validate |  -> DROP
 * |                      |  -> CONSUME
 * \----------------------/
 *
 * And the feat1 node would be called if ipv4-validate does not drop or
 * consume. It would then be run (along with any other features at this
 * feature-point) and as long as they have a next node of ACCEPT (noop)
 * then the subsequent features would be run.
 *
 * /--------------\
 * |              |  -> ACCEPT  (term-noop)
 * | domain:feat1 |  -> CONSUME (term-finish)
 * |              |  -> DROP    (term-drop)
 * |              |  -> DROP    (domain1:drop-and-count)
 * \--------------/
 *
 * So in this case domain:feat1 would run if the ipv4_validate node
 * successfully validated the packet.  This feat1 node then does its
 * processing and returns on of the 4 next node values. If the return
 * is the ACCEPT then the ipv4-validate node will also return ACCEPT
 * and move onto the ipv4-route-lookup. If it is any of the others the
 * ipv4-validate node will return CONSUME (as the subgraph has consumed
 * the packet and any drop counters etc have already been incremented
 * by the subgraph.
 *
 * Once a feature is registered it is part of the graph, but it will only
 * be visited if that feature has been enabled.
 *
 * A feature is registered using: pipeline_register_feature()
 * A feature is enabled using: pipeline_enable_feature()
 *                             pipeline_enable_feature_by_inst()
 *
 * A feature is disabled using: pipeline_disable_feature()
 *                             pipeline_disable_feature_by_inst()
 */

/*
 * A pipeline node must have a type specified as part of the registration.
 */
enum pl_node_type {
	/*
	 * The most common node type. This is the type that gives standard
	 * processing through the graph, where the node does some work
	 * then moves onto the next node.
	 */
	PL_PROC = 0,
	/*
	 * A terminal node. When the graph walk reaches a node of this type
	 * the walk finishes. A node of this type has no next nodes registered.
	 */
	PL_OUTPUT,
	/*
	 * A special type of node for making transitions. A node of this
	 * type has no next nodes registered. A node of this type is
	 * typically used as a next node for a (feature) that wants processing
	 * to continue.
	 */
	PL_CONTINUE,
};

/*
 * The maximum number of storage entries on a pl_packet.
 */
#define PL_NODE_STORE_MAX 4

/*
 * These are carry over from existing
 * pipeline functionality but should be
 * refactored out of existence if possible.
 */
enum validation_flags {
	NEEDS_EMPTY     = 0x0,
	NEEDS_SLOWPATH  = 0x1,
};

/*
 * The structure that contains all the information about a packet. This is the
 * structure that will be passed to each pipeline node.
 */
struct pl_packet {
	/*
	 * A pointer to the mbuf that is being processed.
	 */
	struct rte_mbuf      *mbuf;
	/*
	 * A pointer to the Layer 3 header in the mbuf. This is set once
	 * the packet processing has got as as the L3 processing. It will
	 * be NULL until then.
	 */
	void                 *l3_hdr;
	/*
	 * the type of the packet, unicast, multicast, broadcast
	 */
	int                   l2_pkt_type;
	/*
	 * These will be refactored out soon.
	 */
	enum validation_flags val_flags;
	/*
	 * A pointer to a next hop. If a node makes a forwarding decision then
	 * this can be stored here, and this is the next hop that the packet
	 * will use when forwarded. Note that later features may overwrite this
	 * decision.
	 */
	union {
		struct next_hop *v4;
		struct next_hop_v6 *v6;
	} nxt;
	/*
	 * Pointer to the input interface for this packet
	 */
	struct ifnet         *in_ifp;
	/*
	 * Pointer to the output interface to use for this packet.
	 */
	struct ifnet         *out_ifp;
	/*
	 * The table to use for forwarding the packet. This can be either
	 * a PBR table or the main table from a different VRF.
	 */
	uint32_t              tblid;
	/*
	 * NPF feature state. This should not be modified by feature_plugins.
	 */
	uint16_t              npf_flags;
	/*
	 * The L2 protocol, for example ETH_P_IP. This is not always set.
	 */
	uint16_t              l2_proto;
	/*
	 * A count of how many of the data storage nodes have been used
	 * for this packet.
	 */
	int                   max_data_used;
	/*
	 * An array of pointers to store data. These can be used by nodes
	 * to store data that is (potentially) needed by a node later in
	 * the graph.
	 */
	void                 *data[PL_NODE_STORE_MAX];
} __rte_cache_aligned;

/*
 * A callback function for packet processing in a node.
 *
 * When registering a node a packet processing function of this type
 * is provided. This function is the one that does all the work of the
 * node.
 *
 * @param[in,out] packet The structure that contains the packet being
 *                processed and all the related state. The function
 *                can modify the contents to of the packet/state as
 *                required.
 *
 * @param[in, out] context Pointer to the context registered for this node
 *                 instance by the call to
 *                 dp_pipeline_register_node_instance_storage(). If no
 *                 context was registered then this will be NULL.
 *
 * @return The index of the next node. This is based on the set of next
 *         nodes provided at registration time.
 */
typedef unsigned int
(pl_proc) (struct pl_packet *packet, void *context);

/*
 * Register a new pipeline node. If called during the startup sequence of
 * the dataplane this node will be inserted into the graph. The graph will
 * be calculated and verified once all plugins are loaded.
 *
 * @param[in] name The name for this node. This is comprised of a domain and
 *            a name, separated by a colon. For example 'my_domain:feat1'
 * @param[in] num_next_nodes The number of next nodes that this node can have.
 * @param[in] next_nodes_names An array of strings of size num_next_nodes. Each
 *            entry in the array is the name of a possible next node. This next
 *            node name can optionally include a domain. If it does this is of
 *            the format <domain>:<name>. If it does not then the default
 *            domain (vyatta) will be used.
 * @param[in] node_type the type of this node.
 * @param[in] handler The function that does the processing for this node.
 *            It does any required processing and returns the index of the
 *            next node to use.
 *
 * @return 0 on success
 *         -EBUSY if the dataplane has finished initialisation
 *         -EINVAL if invalid arguments are provided.
 *
 * The combination of domain and name must be unique.
 *
 * This function may return success now but there is a further phase of
 * validation once all plugins are loaded. For example a node may have a next
 * node from a not yet loaded plugin. In this case the behaviour is to return
 * success now, and do a final graph validation at the stage where all the
 * plugins have been loaded. If at the verification stage the node can not
 * be installed properly due to missing next-nodes it will be removed from
 * the graph and an error will be logged.
 */
int dp_pipeline_register_node(const char *name,
			      int num_next_nodes,
			      const char **next_node_names,
			      enum pl_node_type node_type,
			      pl_proc handler);
/*
 * If storage for a node instance has been registered and the node
 * instance goes away then this callback can be used to cleanup
 * so that any memory for the instance is not leaked.
 *
 * @param[in] instance The instance that is being removed
 *
 * @param[in] context The context that was registered
 */
typedef void (dp_pipeline_inst_cleanup_cb)(const char *instance,
					   void *context);

struct dp_pipeline_feat_registration {
	/*
	 * The name of the plugin. This should be the same as
	 * the name returned in the dp_feature_plugin_init func.
	 */
	const char *plugin_name;
	/*
	 * The name for this feature. This is comprised of a domain and
	 * a name, separated by a colon. For example 'my_domain:feat1'
	 */
	const char *name;
	/*
	 * The name of the node being used by for this feature.
	 * This is comprised of a domain and a name, separated by a colon.
	 * For example 'my_domain:feat1'
	 */
	const char *node_name;
	/*
	 * feature_point The feature point this feature should use. This
	 * can optionally include a domain. If it does this is of
	 * the format <domain>:<name>. If it does not then the default
	 * domain (vyatta) will be used.
	 */
	const char *feature_point;
	/*
	 * visit_before An optional argument that indicates that this feature
	 * should be invoked before the named feature.  This can optionally
	 * include a domain. If it does this is of the format
	 * <domain>:<name>. If it does not then the default domain (vyatta)
	 * will be used.
	 */
	const char *visit_before;
	/*
	 * visit_after An optional argument that indicates that this feature
	 * should be invoked after the named feature. This can optionally
	 * include a domain. If it does this is of the format
	 * <domain>:<name>. If it does not then the default domain (vyatta)
	 * will be used.
	 */
	const char *visit_after;
	/*
	 * Only used for the case features. The case value to match
	 * on. Only features that have a matching value are executed, and
	 * there can only be one feature registering a given value.
	 */
	uint32_t value;
	/*
	 * If a feature registers node instance storage then it can provide
	 * a callback via this field so that the storage can be cleaned up
	 * if the instance goes away. This field can be NULL.
	 */
	dp_pipeline_inst_cleanup_cb *cleanup_cb;
};

/*
 * Register a new pipeline list feature. If called during the startup sequence
 * of the dataplane this feature will be created. The graph will be calculated
 * and verified once all plugins are loaded.
 *
 * @param[in] feat Structure containing all the information needed
 *            to register a feature.
 *
 * @return 0 on success
 *         -EBUSY if the dataplane has finished initialisation
 *         -EINVAL if invalid arguments are provided.
 *
 * The combination of domain and name that is being registered must be unique.
 * All other names that are referred to must exist once all nodes/features
 * are registered.
 *
 * This function may return success now but there is a further phase of
 * validation once all plugins are loaded. For example a feature may be
 * after another feature that is not yet loaded. In this case the
 * behaviour is to return success now, and do a final graph validation at
 * the stage where all the plugins have been loaded. If at the verification
 * stage there are missing nodes/features from the graph and an error will
 * be logged.
 * @return 0 on success
 *         -EBUSY if the dataplane has finished initialisation
 *         -EINVAL if invalid arguments are provided.
 */
int
dp_pipeline_register_list_feature(struct dp_pipeline_feat_registration *feat);
int
dp_pipeline_register_case_feature(struct dp_pipeline_feat_registration *feat);

/*
 * If a feature wants per instance storage then it can allocate it
 * with this API. This will be stored on a per instance basis, and
 * will be passed to the processing function in the 'context' parameter.
 *
 * A cleanup_callback can be registered as part of the feature registration
 * as the cleanup is per feature, not per feature per instance.
 *
 * Note that this must be called on the master thread.
 *
 * @param[in] name The name of the feature to allocate context for.
 *            This is comprised of a domain and a name, separated by
 *            a colon. For example 'my_domain:feat1'
 * @param[in] instance The instance to add the context to, for example
 *            'dp0s0p1'
 *
 * @param[in] context A pointer to the context for this node instance. This
 *            pointer to will be passed to the registred handler
 *            function for the node in the 'context' parameter.
 *            This param is optional.
 *
 * @return 0 on success
 *         -EINVAL if invalid arguments are provided.
 */
int dp_pipeline_register_inst_storage(const char *name,
				      const char *instance,
				      void *context);

/*
 * Unregister per node instance storage.
 *
 * Note that this must be called on the master thread.
 *
 * @param[in] name The name of the feature to deallocate storage for.
 *            This is comprised of a domain and a name, separated by
 *            a colon. For example 'my_domain:feat1'
 * @param[in] instance The instance to remove the context from, for example
 *            'dp0s0p1'
 *
 */
int dp_pipeline_unregister_inst_storage(const char *node_name,
					const char *instance);

/*
 * Get the per node instance storage that was previously registered.
 *
 * @param[in] name The name of the feature to retireve storage for.
 *            This is comprised of a domain and a name, separated by
 *            a colon. For example 'my_domain:feat1'
 * @param[in] instance The instance to retrieve the context from, for example
 *            'dp0s0p1'
 *
 * @return A pointer to the context that was registered.
 *         NULL if no context registered.
 */
void *dp_pipeline_get_inst_storage(const char *node_name,
				   const char *instance);

/*
 * Enable the given feature on the named instance. Instance names are currently
 * interface names.
 *
 * @param[in] name The name of the feature to enable. This is comprised of
 *            a domain and a name, separated by a colon. For example
 *            'my_domain:feat1'
 * @param[in] instance The instance to enable the feature on, for example
 *            'dp0s0p1'
 *
 * @return 0 on success
 *         -EINVAL if invalid arguments are provided.
 */
int dp_pipeline_enable_feature_by_inst(const char *name,
				       const char *instance);

/*
 * Disable the given feature on the named instance. Instance names are currently
 * interface names.
 *
 * @param[in] name The name of the feature to disable. This is comprised of
 *            a domain and a name, separated by a colon. For example
 *            'my_domain:feat1'
 * @param[in] instance The instance to disable the feature on, for example
 *            'dp0s0p1'
 *
 * @return 0 on success
 *         -EINVAL if invalid arguments are provided.
 */
int dp_pipeline_disable_feature_by_inst(const char *name,
					const char *instance);

/*
 * Enable the given feature globally.
 *
 * For list features it will enable the feature on all instances of the
 * type the feature uses. It will also be enabled on future instances
 * as they are created.
 *
 * For case features it will enable the feature on all instances of the
 * type the feature uses.
 *
 * @param[in] name The name of the feature to enable. This is comprised of
 *            a domain and a name, separated by a colon. For example
 *            'my_domain:feat1'
 * @return 0 on success
 *         -EINVAL if invalid arguments are provided.
 */
int dp_pipeline_enable_global_feature(const char *name);

/*
 * Disable the given feature globally.
 *
 * For list features it will disable the feature on all instances of the
 * type the feature uses.  If a feature was enabled per instance, then
 * globally, then turned off globally it will remove the feature from all
 * instances including the one that was initially enabled on a per instance
 * basis.
 *
 * For case features it will disable the feature on all instances of the
 * type the feature uses.
 *
 * @param[in] name The name of the feature to disable. This is comprised of
 *            a domain and a name, separated by a colon. For example
 *            'my_domain:feat1'
 * @return 0 on success
 *         -EINVAL if invalid arguments are provided.
 */
int dp_pipeline_disable_global_feature(const char *name);

#endif /* VYATTA_DATAPLANE_PIPELINE_H */
