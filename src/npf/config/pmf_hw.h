#include <stdbool.h>
#include <stdint.h>

struct pmf_group_ext;
struct pmf_cntr;
struct pmf_attrl;
struct pmf_rule;
struct ifnet;

bool pmf_hw_rule_add(struct pmf_attrl *earl, struct pmf_rule *rule);
void pmf_hw_rule_mod(struct pmf_attrl *earl, struct pmf_rule *rule);
void pmf_hw_rule_del(struct pmf_attrl *earl);
bool pmf_hw_group_attach(struct pmf_group_ext *earg, struct ifnet *ifp);
void pmf_hw_group_detach(struct pmf_group_ext *earg, struct ifnet *ifp);
bool pmf_hw_group_create(struct pmf_group_ext *earg);
void pmf_hw_group_mod(struct pmf_group_ext *earg, uint32_t new);
void pmf_hw_group_delete(struct pmf_group_ext *earg);
bool pmf_hw_counter_create(struct pmf_cntr *eark);
void pmf_hw_counter_delete(struct pmf_cntr *eark);
bool pmf_hw_counter_clear(struct pmf_cntr const *eark);
bool pmf_hw_counter_read(struct pmf_cntr const *eark,
			 uint64_t *pkts, uint64_t *bytes);
void pmf_hw_commit(void);
