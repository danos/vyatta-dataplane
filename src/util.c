/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2011-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 * Useful routines from FreeBSD
 */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/neighbour.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <urcu/list.h>
#include <linux/rtnetlink.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_spinlock.h>
#include <rte_timer.h>
#include <sys/capability.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <syscall.h>

#include "bitmask.h"
#include "urcu.h"
#include "util.h"
#include "vplane_log.h"

struct cds_lfht;

/* Use /dev/urandom to read a random seed */
void random_init(void)
{
	int fd;
	unsigned int seed;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		rte_log(RTE_LOG_NOTICE, RTE_LOGTYPE_USER1,
			"Can't open /dev/urandom: %s\n", strerror(errno));
		seed = rte_rdtsc();
	} else {
		if (read(fd, &seed, sizeof(seed)) != sizeof(seed))
			rte_panic("Can't read random seed: %s\n",
				  strerror(errno));
		close(fd);
	}
	srandom(seed);
}

/* Netlink message type to string */
const char *nlmsg_type(unsigned int type)
{
	static char buf[32];

	switch (type) {
	case RTM_NEWLINK:	return "RTM_NEWLINK";
	case RTM_DELLINK:	return "RTM_DELLINK";
	case RTM_GETLINK:	return "RTM_GETLINK";
	case RTM_SETLINK:	return "RTM_SETLINK";
	case RTM_NEWADDR:	return "RTM_NEWADDR";
	case RTM_DELADDR:	return "RTM_DELADDR";
	case RTM_GETADDR:	return "RTM_GETADDR";
	case RTM_NEWROUTE:	return "RTM_NEWROUTE";
	case RTM_DELROUTE:	return "RTM_DELROUTE";
	case RTM_GETROUTE:	return "RTM_GETROUTE";
	case RTM_NEWNEIGH:	return "RTM_NEWNEIGH";
	case RTM_DELNEIGH:	return "RTM_DELNEIGH";
	case RTM_GETNEIGH:	return "RTM_GETNEIGH";
	case RTM_NEWRULE:	return "RTM_NEWRULE";
	case RTM_DELRULE:	return "RTM_DELRULE";
	case RTM_GETRULE:	return "RTM_GETRULE";
	case RTM_NEWQDISC:	return "RTM_NEWQDISC";
	case RTM_DELQDISC:	return "RTM_DELQDISC";
	case RTM_GETQDISC:	return "RTM_GETQDISC";
	case RTM_NEWTCLASS:	return "RTM_NEWTCLASS";
	case RTM_DELTCLASS:	return "RTM_DELTCLASS";
	case RTM_GETTCLASS:	return "RTM_GETTCLASS";
	case RTM_NEWTFILTER:	return "RTM_NEWTFILTER";
	case RTM_DELTFILTER:	return "RTM_DELTFILTER";
	case RTM_GETTFILTER:	return "RTM_GETTFILTER";
	case RTM_NEWACTION:	return "RTM_NEWACTION";
	case RTM_DELACTION:	return "RTM_DELACTION";
	case RTM_GETACTION:	return "RTM_GETACTION";
	case RTM_NEWPREFIX:	return "RTM_NEWPREFIX";
	case RTM_GETMULTICAST:	return "RTM_GETMULTICAST";
	case RTM_GETANYCAST:	return "RTM_GETANYCAST";
	case RTM_NEWNEIGHTBL:	return "RTM_NEWNEIGHTBL";
	case RTM_GETNEIGHTBL:	return "RTM_GETNEIGHTBL";
	case RTM_SETNEIGHTBL:	return "RTM_SETNEIGHTBL";
	case RTM_NEWNDUSEROPT:	return "RTM_NEWNDUSEROPT";
	case RTM_NEWADDRLABEL:	return "RTM_NEWADDRLABEL";
	case RTM_DELADDRLABEL:	return "RTM_DELADDRLABEL";
	case RTM_GETADDRLABEL:	return "RTM_GETADDRLABEL";
	case RTM_GETDCB:	return "RTM_GETDCB";
	case RTM_SETDCB:	return "RTM_SETDCB";
	default:
		sprintf(buf, "%u", type);
		return buf;
	}
}

/* Netlink neighbour state to string */
const char *ndm_state(uint16_t nud_state)
{
	static char buf[32];

	switch (nud_state) {
	case NUD_INCOMPLETE: return "NUD_INCOMPLETE";
	case NUD_REACHABLE:  return "NUD_REACHABLE";
	case NUD_STALE:      return "NUD_STALE";
	case NUD_DELAY:      return "NUD_DELAY";
	case NUD_PROBE:      return "NUD_PROBE";
	case NUD_FAILED:     return "NUD_FAILED";
	case NUD_NOARP:      return "NUD_NOARP";
	case NUD_PERMANENT:  return "NUD_PERMANENT";
	default:
		sprintf(buf, "%u", nud_state);
		return buf;
	}
}

static int __net_ratelimit(uint64_t now)
{
	static uint64_t epoch;
	static unsigned int missed;
	static unsigned int printed;

	if (!epoch)
		epoch = now;

	if (now  - epoch > rte_get_timer_hz() * 5) {
		if (missed)
			rte_log(RTE_LOG_WARNING, RTE_LOGTYPE_USER1,
				"%u messages suppressed...\n", missed);
		missed = 0;
		printed = 0;
		epoch = 0;
		return 1;
	} else if (printed < 10) {
		++printed;
		return 1;
	} else {
		++missed;
		return 0;
	}
}


/* Simple function used to rate limit log messages
 * Allow no more than 10 messages every 5 seconds.
 */
int net_ratelimit(void)
{
	static rte_spinlock_t lock = RTE_SPINLOCK_INITIALIZER;

	/* Message already being printed? */
	if (!rte_spinlock_trylock(&lock))
		return 0;

	int ret =  __net_ratelimit(rte_get_timer_cycles());
	rte_spinlock_unlock(&lock);
	return ret;
}

/* Convert char from hex to number */
static unsigned int xdigit2val(unsigned char c)
{
	if (isdigit(c))
		return c - '0';
	else if (isupper(c))
		return c - 'A' + 10;
	else
		return c - 'a' + 10;
}


#if defined(__x86_64__) || defined(__i386__)

struct cpuid_regs {
	uint32_t eax;
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
};

static inline void get_cpuid(uint32_t eax, struct cpuid_regs *regs)
{
	asm volatile (
#if defined(__PIC__) && defined(__i386__)
		      "xchgl %%ebx, %%edi;"
		      "cpuid;"
		      "xchgl %%edi, %%ebx;"
		      : "=D" (regs->ebx),
#else
		      "cpuid;"
		      : "=b" (regs->ebx),
#endif
			"=a" (regs->eax),
			"=c" (regs->ecx),
			"=d" (regs->edx)
		      : "a" (eax), "c"(0));
}
#endif

/* Return hypervisor we are running on.
 * if not on a hypervisor, then returns NULL.
  */
const char *hypervisor_id(void)
{
#if defined(__x86_64__) || defined(__i386__)
	struct cpuid_regs regs;
	static uint32_t name[4];

	get_cpuid(1, &regs);

	/* is hypervisor present? */
	if (regs.ecx & (1u << 31)) {
		memset(&regs, 0, sizeof(regs));
		get_cpuid(0x40000000, &regs);

		name[0] = regs.ebx;
		name[1] = regs.ecx;
		name[2] = regs.edx;
		name[3] = 0;

		return (const char *) name;
	}
#endif
	return NULL;
}

/* Determine if this CPU is second child, called at initialization */
bool secondary_cpu(unsigned int core_id)
{
	char path[PATH_MAX];
	char thread_mask[1024];
	unsigned int idx = 0;
	size_t l;
	FILE *f;
	int i;

	snprintf(path, PATH_MAX,
		 "/sys/devices/system/cpu/cpu%u/topology/thread_siblings",
		 core_id);

	f = fopen(path, "r");
	if (f == NULL)
		rte_panic("%s: %s\n", path, strerror(errno));

	if (fgets(thread_mask, sizeof(thread_mask), f) == NULL)
		rte_panic("read %s failed\n", path);
	fclose(f);

	l = strlen(thread_mask);
	if (l < 2)
		rte_panic("bad data from sysfs '%s'\n", thread_mask);

	/* parse bitmap '11\n' in reverse */
	for (i = l - 2; i >= 0 && idx < core_id; i--) {
		char c = thread_mask[i];
		unsigned int j, val;

		if (c == ',')
			continue;

		if (!isxdigit(c))
			rte_panic("invalid char in thread mask '%s'\n",
				 thread_mask);

		val = xdigit2val(c);

		for (j = 0; j < 4 && idx < core_id; j++, idx++) {
			/* If this CPU has a sibling with lower id
			 * then it is secondary.
			 */
			if ((1 << j) & val)
				return true;
		}
	}

	return false;
}

/* Convert from argv set of strings to one long string separated
 * by spaces. Does not do quoting!.
 * Returns 0 on success, -1 if out of space.
 */
int str_unsplit(char *buf, size_t n, int argc, char **argv)
{
	int i;
	char *cp = buf;

	if (n < 1)
		return -1;	/* moron */

	for (i = 0; i < argc; i++) {
		const char *str = argv[i];
		size_t l = strlen(str);
		if (cp + l + 1 >= buf + n)
			return -1;	/* out of space */
		if (i != 0)
			*cp++ = ' ';

		strcpy(cp, str);
		cp += l;
	}
	*cp = '\0';

	return 0;
}

/* Like snprintf but concatinates to existing string */
size_t snprintfcat(char *buf, size_t size, const char *fmt, ...)
{
	size_t n, len = strnlen(buf, size);
	va_list args;

	va_start(args, fmt);
	n = vsnprintf(buf + len, size - len, fmt, args);
	va_end(args);

	return len + n;
}

/* convert string to unsigned value.
 * returns 0 on success, -errno on error
 */
int get_unsigned(const char *str, unsigned int *ptr)
{
	char *endp = NULL;
	unsigned long val;

	errno = 0;
	val = strtoul(str, &endp, 0);
	if (*str == '\0' || !endp || *endp)
		return -EINVAL;
	if (val == ULONG_MAX && errno == ERANGE)
		return -ERANGE;
	if (val > UINT_MAX)
		return -ERANGE;

	*ptr = val;
	return 0;
}

/* convert string to signed value.
 * returns 0 on success, -errno on error
 */
int get_signed(const char *str, int *ptr)
{
	char *endp = NULL;
	long val;

	errno = 0;
	val = strtol(str, &endp, 0);
	if (*str == '\0' || !endp || *endp)
		return -EINVAL;
	if ((val == LONG_MAX || val == LONG_MIN) && errno == ERANGE)
		return -ERANGE;
	if (val > INT_MAX || val < INT_MIN)
		return -ERANGE;

	*ptr = val;
	return 0;
}

/* convert string to unsigned short value.
 * returns 0 on success, -errno on error
 */
int get_unsigned_short(const char *str, unsigned short *ptr)
{
	int result;
	unsigned int val;

	result = get_unsigned(str, &val);
	if (result < 0)
		return result;

	if (val > USHRT_MAX)
		return -ERANGE;

	*ptr = val;
	return 0;
}

/* convert string to unsigned char value.
 * returns 0 on success, -errno on error
 */
int get_unsigned_char(const char *str, unsigned char *ptr)
{
	int result;
	unsigned int val;

	result = get_unsigned(str, &val);
	if (result < 0)
		return result;

	if (val > UCHAR_MAX)
		return -ERANGE;

	*ptr = val;
	return 0;
}

/* convert string to char value.
 * returns 0 on success, -errno on error
 */
int get_signed_char(const char *str, signed char *ptr)
{
	int result;
	int val;

	result = get_signed(str, &val);
	if (result < 0)
		return result;

	if (val > SCHAR_MAX || val < SCHAR_MIN)
		return -ERANGE;

	*ptr = val;
	return 0;
}

/* convert string to bool value.
 * accept true, false or an integer value
 * returns 0 on success, -errno on error
 */
int get_bool(const char *str, bool *ptr)
{
	int result;
	int val;

	if (streq(str, "true"))
		val = 1;
	else if (streq(str, "false"))
		val = 0;
	else {
		result = get_signed(str, &val);
		if (result < 0)
			return result;
	}

	*ptr = val;
	return 0;
}

/* convert string to float value.
 * returns 0 on success, -errno on error
 */
float get_float(const char *str, float *ptr)
{
	char *endp = NULL;
	float val;

	errno = 0;
	val = strtof(str, &endp);
	if (*str == '\0' || !endp || *endp)
		return -EINVAL;
	if (errno == ERANGE)
		return -ERANGE;

	*ptr = val;
	return 0;
}

static unsigned char xdigit(int c)
{
	if (isdigit(c))
		return c - '0';
	else if (isupper(c))
		return c - 'A' + 10;
	else
		return c - 'a' + 10;
}
/*
 * Parse bitmask expressed as hex
 * needs to handle up to RTE_MAX_LCORE and RTE_MAX_ETHPORTS bits (ie 128)
 *
 * NB: empty string == empty mask
 */
int bitmask_parse(bitmask_t *msk, const char *str)
{
	unsigned int offs;
	int i;

	bitmask_zero(msk);

	for (i = strlen(str) - 1, offs = 0; i >= 0; --i, ++offs) {
		char c = str[i];
		uint64_t val;

		if ((offs / (UINT64_BIT / 4)) >= BITMASK_SZ)
			return -1;	/* too many bits */

		if (!isxdigit(c))
			return -1;	/* invalid character */

		val = xdigit(c);

		val <<= (4 * (offs % (UINT64_BIT / 4)));

		msk->_bits[offs / (UINT64_BIT / 4)] |= val;
	}

	return 0;
}

/* Print out bitmask as long hex string. */
void bitmask_sprint(const bitmask_t *msk, char *buf, size_t sz)
{
	char *cp, tmp[BITMASK_STRSZ];
	int i;

	for (i = BITMASK_SZ - 1, cp = tmp; i >= 0; --i, cp += 16)
		sprintf(cp, "%016lx", msk->_bits[i]);

	/* skip leading zeros */
	for (i = 0; i < (int)strlen(tmp) - 1; i++)
		if (tmp[i] != '0')
			break;

	snprintf(buf, sz, "%s", tmp + i);
}

unsigned int get_lcore_max(void)
{
	unsigned int i;
	unsigned int max = 0;

	for (i = 0; i < RTE_MAX_LCORE; i++)
		if (rte_lcore_is_enabled(i))
			max = i;
	return max;
}

/* Allocate memory aligned on cache line boundary */
void *malloc_huge_aligned(size_t sz)
{
	void *ptr = NULL;

	ptr = mmap(NULL, sz, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (ptr == MAP_FAILED)
		return NULL;

	return ptr;
}

void free_huge(void *ptr, size_t sz)
{
	if (!ptr)
		return;

	munmap(ptr, sz);
}

static void free_huge_defer(void *ptr)
{
	struct free_huge_info *free_info = ptr;

	if (!free_info)
		return;

	free_huge(free_info->ptr, free_info->sz);
	free(free_info);
}

int defer_rcu_huge(void *ptr, size_t sz)
{
	struct free_huge_info *free_info;

	free_info = malloc(sizeof(*free_info));

	if (!free_info)
		return -1;

	free_info->ptr = ptr;
	free_info->sz = sz;
	defer_rcu(free_huge_defer, free_info);
	return 0;
}

void dp_ht_destroy_deferred(struct cds_lfht *table)
{
	cds_lfht_destroy(table, NULL);
}

static inline bool is_switch_driver(const char *driver_name)
{
	int drv_len = strlen(driver_name);

	if (!strncmp("net_sw_port", driver_name, drv_len) ||
		!strncmp("net_bcm", driver_name, drv_len))
		return true;
	return false;
}

bool get_switch_dev_info(const char *drv_name, const char *drv_dev_name,
						 int *switch_id, char *dev_name)
{
	const char *sw_start;
	int drv_len;

	if (!is_switch_driver(drv_name))
		return false;

	drv_len = strlen(drv_name);
	if (strncmp(drv_dev_name, drv_name, drv_len))
		return false;

	/* strip driver prefix + swX from name */
	sw_start = strstr(drv_dev_name + drv_len, "sw");
	if (!sw_start)
		return false;

	if (!dev_name) {
		if (sscanf(sw_start, "sw%d", switch_id) != 1)
			return false;
	} else {
		if (sscanf(sw_start, "sw%d%s", switch_id, dev_name) != 2)
			return false;
	}

	return true;
}

/*
 * Add or remove a flag from the effective capability set.
 * Note the flag must already be present in the permitted set.
 */
int
change_capability(cap_value_t capability, bool on)
{
	cap_t caps;
	cap_value_t cap_flag[1];
	int rc;

	if (!cap_valid(capability)) {
		RTE_LOG(ERR, DATAPLANE,
			"Invalid capability %d\n", capability);
		return -1;
	}

	caps = cap_get_proc();
	if (caps == NULL) {
		RTE_LOG(ERR, DATAPLANE,
			"Failed to get current capabilities\n");
		return -1;
	}

	cap_flag[0] = capability;
	rc = cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_flag,
			  on ? CAP_SET : CAP_CLEAR);
	if (rc < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"Failed to %s flag for capability %d\n",
			on ? "set" : "clear", capability);
		goto out;
	}

	rc = cap_set_proc(caps);
	if (rc < 0)
		RTE_LOG(ERR, DATAPLANE,
			"Failed to %s capability %d\n",
			on ? "enable" : "disable", capability);

out:
	cap_free(caps);
	return rc;
}

/*
 * There is no wrapper for this function. The value returned by
 * gettid is the thread id and this is not the same as the pid
 * or the POSIX thread id. It represents the value used by
 * the kernel's native thread implementation.
 */
static unsigned long gettid(void)
{
	return syscall(SYS_gettid);
}

/* Change the nice value of the current thread (not pthread) */
void renice(int value)
{
	int rc;

	if (change_capability(CAP_SYS_NICE, true) == 0) {
		rc = setpriority(PRIO_PROCESS, gettid(), value);
		if (rc < 0)
			RTE_LOG(ERR, DATAPLANE,
				"%s: failed to set thread priority: %s\n",
				__func__,  strerror(errno));
		change_capability(CAP_SYS_NICE, false);
	} else
		RTE_LOG(ERR, DATAPLANE,
			"%s: failed to set CAP_SYS_NICE: %s\n",
			__func__,  strerror(errno));
}
