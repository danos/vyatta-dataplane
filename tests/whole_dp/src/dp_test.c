/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <getopt.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#ifdef HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#else
#define VALGRIND_MAKE_MEM_UNDEFINED(addr, len)
#endif

#include <libmnl/libmnl.h>
#include <czmq.h>
#include "vplane_debug.h"
#include "master.h"
#include "if_llatbl.h"

#include "dp_test_controller.h"
#include "dp_test.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test/dp_test_cmd_check.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_console.h"
#include "dp_test/dp_test_macros.h"
#include "dp_test_route_broker.h"

/* DPDK debug level */
char rte_log_level[2];

/*
 * The way the tests look is:
 *
 * Dataplane:  majority of the dataplane files linked in to process, and the
 * threads created as per normal dataplane (no shadow).
 *
 * The dataplane startup state machine is as follows:
 *  - init eal
 *  - setup ZMQ connection with console
 *  - setup controller:
 *     - create ZMQ subscriber (controller is publisher)
 *     - register handlers for incoming pub messages
 *  - prepare master thread (master_loop)
 *    - create ZMQ dealer (connected to controller ROUTER)
 *
 *    - MASTER_SETUP:
 *        setup interfaces (build shadow state, tuntaps ...)
 *        send data to controller:
 *          "MYPORT" + 6 part with data in.
 *        wait for response:
 *          "OK" + seq + ifindex assigned for this port.
 *
 *    - MASTER_RESYNC:
 *        send "WHATSUP" on DEALER/ROUTER socket
 *        do loop polling for messages:
 *           process netlink/cmd messages
 *        until msg is THATSALLFOLKS
 *
 *    - MASTER_READY:
 *        do while not shutdown:
 *           - process incoming events.
 *
 *
 * test thread: Registers the far end of the 3 ZMQ pipes:
 *                - Netlink from  controller-> dataplane
 *                - Requests from dataplane -> controller
 *                - Show commands/replies from console -> dataplane
 *
 * Test thread does the init of the 3 ZMQs, then spawns a new ZMQ listener
 * thread to process incoming requests. This listener thread will receive
 * requests on the ZMQ pipe and process them, allowing the dataplane to
 * progress through the initial state machine and move itself to READY. Once
 * the dataplane transitions to READY it will start to poll for incoming
 * events, so will start pulling messages off the other 2 ZMQs, thus allowing
 * tests to be run.
 *
 * Once the test thread has spawned the ZMQ listener thread, it can progress
 * to running the tests.  As we are in the same process we can peek at the
 * state of some of the dataplane vars to find out what is going on, although
 * where possible we will not do that.  Running the tests involves looping
 * through each of the registered test files.  We simply call each of the test
 * funcs and if it returns success then we move on to the next one, aborting
 * as soon as we get any tests failing.
 *
 *-----------------------------------------------------------------------------
 *
 * The way that DPDK detects interfaces is that it runs the following steps
 * (there are other steps in between these doing other setup):
 * - init pci  -    builds a list of pci devices based on a scan of
 *                  /sys/bus/pci/devices
 * - init drivers - init the set of drivers that are registered - most of these
 *                  are registered by DPDK using the gcc
 *                   __attribute__ constructor
 *                  so are registered before we get into main.
 * - init devices - loop through the pci device list. For each device search the
 *                  driver list for a matching vendor/device ID. If found then
 *                  init the device using the registered driver init func.
 *
 * The init of the device is within eal, and then once eal has initialised,
 * dataplane gets the number of devices from DPDK, and then in main() we
 * create our representation of the interface with eth_port_init().
 *
 *-----------------------------------------------------------------------------
 *
 * A test can use the test library functions to add/remove routes/interfaces
 * etc, and to then inject packets, and check the forwarding behaviour.
 * Verification of routes can be done via the library functions too, and these
 * are typically based on doing show commands, and verifying the output of the
 * show commands. A test should always clean up after itself, returning the
 * system back to the 'initial' state, as much as is possible, so that
 * subsequent tests are always starting from a clean system.  This may involve
 * adding some extra functionality to the dataplane to allow clearing of some
 * state, but this will be added in such a way that it is not test specific.
 * Once a test has finished, the infra will verify the state is clean, and it
 * will poll for X seconds util it determines that the state is clean. If this
 * fails then we abort.  Once clean we can progress to the next test.
 */

/*
 * TODO
 *  - set timer for max run time so that we can abort if the initial
 *    sync with test thread goes wrong (to avoid builds that last forever)
 */

static void
dp_test_usage(int status) __attribute__((noreturn));
static void
dp_test_usage(int status)
{
	printf("%s\n"
	       "OPTIONS:\n"
	       " -d<n>, --debug<n>    Control debug\n"
	       "    -d0                   Minimal dataplane and eal debugs\n"
	       "    -d1                   Default dataplane and eal debugs\n"
	       "    -d2                   All dataplane and eal debugs\n"
	       " -u, --uplink         Run uplink tests (remote controller)\n"
	       " -h, --help           Display this help and exit\n"
	       " -p, --poison         Poison mbuf data before each test\n"
	       " -F --feat_plugin_dir Extra directory to check for feat plugins\n"
	       " -P  --plugin-directory Unit-Test plugin directory\n"
	       " -r, --routing-domain Use routing-domain VRF model\n"
	       " -E, --external       When being run from plugin code\n"
	       " -H, --platform       Specify the platform_conf file to use\n"
	       " -C, --cfg            Extra config that a caller wants to pass\n"
	       "                      into the tests. It represents a line in\n"
	       "                      the 'dataplane' section of the config\n"
	       "                      file.  It should be text based. As the\n"
	       "                      config typically represents socket\n"
	       "                      locations they should have the pid\n"
	       "                      in them. As the pid is not available\n"
	       "                      until the tests are run the strings\n"
	       "                      should contain %%d in places where the\n"
	       "                      pid is to be inserted. For example\n"
	       "                      val_1=aaa-%%d  If multiple lines are\n"
	       "                      needed then the option can be used\n"
	       "                      multiple times\n"
	       "ENV VARS:\n"
	       " CK_RUN_SUITE          Run a single suite\n"
	       " CK_RUN_CASE           Run a single test\n"
	       "  eg CK_RUN_CASE=bridge_unicast dp_test\n",
	       dp_test_pname);

	exit(status);
}

#define MAX_UT_PLUGIN_DIR_LEN 128

static char dp_ut_plugin_dir[MAX_UT_PLUGIN_DIR_LEN] = ".";
char dp_ut_dummyfs_dir[PATH_MAX] = "tests/whole_dp/dummyfs/";
static char drv_cfgfile[PATH_MAX] = "dataplane-drivers-default.conf";
static const char *dp_feat_plugin_dir = ".";
static const char *dp_test_platform_file = PLATFORM_FILE;

/*
 * Is the test being run from an external code tree, in which case a different
 * set of paths are used.
 */
bool from_external;

static void
dp_test_debug_default(void)
{
	/* Use dataplane / dpdk default debug levels */
	dp_debug = DP_DBG_DEFAULT;
#ifndef RTE_LOG_DP_LEVEL
#define RTE_LOG_DP_LEVEL RTE_LOG_LEVEL
#endif
	snprintf(rte_log_level, 2, "%d", RTE_LOG_DP_LEVEL);
}

int dp_test_debug;

int dp_test_debug_get(void)
{
	return dp_test_debug;
}

static void
dp_test_debug_arg(const char *optarg)
{
	if (!isdigit(*optarg)) {
		printf("%s: debug level '%s' must be a number\n", dp_test_pname,
		       optarg);
		dp_test_usage(1);
	}
	dp_test_debug = strtoul(optarg, NULL, 0);
	switch (dp_test_debug) {
	case 0:
		dp_debug = 0x0; /* Turn off all but emergency dataplane debug */
		 /* Turn off all dpdk debug */
		snprintf(rte_log_level, 2, "%d", RTE_LOG_EMERG);
		break;
	case 1:
		dp_test_debug_default();
		break;
	case 2:
		dp_debug = ~0ul; /* Turn on all dataplane debug */
		/* Turn on all dpdk debug */
		snprintf(rte_log_level, 2, "%d", RTE_LOG_DEBUG);
		break;
	default:
		printf("%s: debug level %i out of range\n", dp_test_pname,
		       dp_test_debug);
		dp_test_usage(1);
		break;
	}
	dp_test_controller_debug_set(dp_test_debug);
}

bool dp_test_poison;
uint32_t count = 1; /* The number of times to run each test */

static char *extra_cfg_buf;

static int
dp_test_parse_args(int argc, char **argv)
{
	int option_index;
	int opt;
	int ret;
	static const struct option lgopts[] = {
		{ "debug",    required_argument, NULL, 'd' },
		{ "uplink",   no_argument,       NULL, 'u' },
		{ "help",     no_argument,       NULL, 'h' },
		{ "poison",   no_argument,       NULL, 'p' },
		{ "count",    required_argument, NULL, 'c' },
		{ "routing-domain", no_argument, NULL, 'r' },
		{ "feat_plugin_dir", required_argument, NULL, 'F'},
		{ "plugin-directory", required_argument, NULL, 'P' },
		{ "platform", required_argument, NULL, 'H' },
		{ "external", no_argument, NULL, 'E' },
		{ "cfg", required_argument, NULL, 'C' },
		{ NULL, 0, NULL, 0}
	};

	while ((opt = getopt_long(argc, argv, "c:d:P:F:uhprEC:H:",
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		case 'd':
			dp_test_debug_arg(optarg);
			break;
		case 'u':
			printf("%s: Running in Uplink mode\n", dp_test_pname);
			break;
		case 'h':
			dp_test_usage(0);
			break;
		case 'p':
			dp_test_poison = true;
			break;
		case 'c':
			count = strtoul(optarg, NULL, 0);
			break;
		case 'F':
			dp_feat_plugin_dir = optarg;
			break;
		case 'H':
			dp_test_platform_file = optarg;
			break;
		case 'P':
			memcpy(dp_ut_plugin_dir, optarg,
			       strnlen(optarg, MAX_UT_PLUGIN_DIR_LEN));
			printf("%s: plug-in directory\n", dp_ut_plugin_dir);
			break;
		case 'E':
			from_external = true;
			printf("UTs being run from external repo, using paths from dev package\n");
			break;
		default:
			fprintf(stderr, "Unknown option %c\n", opt);
			dp_test_usage(1);
			break;
		}
	}

	ret = optind-1;
	optind = 0; /* reset getopt lib */

	return ret;
}

static SRunner *dp_test_runner;

Suite *
dp_test_get_suite(const char *filename)
{
	Suite *s;

	s = suite_create(filename);
	if (!s) {
		printf("%s: Failed to create test suite for %s\n",
		       dp_test_pname, filename);
		return NULL;
	}
	if (!dp_test_runner)
		dp_test_runner = srunner_create(s);
	else
		srunner_add_suite(dp_test_runner, s);
	return s;
}

static void
dp_test_pak_poison(struct rte_mbuf *test_pak)
{
	uint8_t *cursor;
	unsigned int i;

	cursor = (uint8_t *)test_pak->buf_addr;
	for (i = 0; i < test_pak->buf_len; i++) {
		if (i % 2)
			*(cursor + i) = 0xba;
		else
			*(cursor + i) = 0xab;
	}
}

static struct rte_mbuf *
dp_test_pktmbuf_alloc(struct rte_mempool *mp)
{
	struct rte_mbuf *m;

	m = pktmbuf_alloc(mp, VRF_DEFAULT_ID);
	if (!m)
		return NULL;

	if (dp_test_poison)
		dp_test_pak_poison(m);
	VALGRIND_MAKE_MEM_UNDEFINED(m->buf_addr, m->buf_len);

	return m;
}

static void
dp_test_thread_run(zsock_t *pipe, void *args)
{
	char *req_ipc;
	int dp_test_thread_internal_retval = 0;

	pthread_setname_np(pthread_self(), "dp_test_main");

	dp_test_controller_init(CONT_SRC_MAIN, &req_ipc);

	zsock_signal(pipe, 0);
	zstr_send(pipe, req_ipc);
	free(req_ipc);

	/*
	 * Wait for the vplaned-local ready state to be reached.
	 * For VR this is a no-op
	 */
	while (!dp_test_master_ready(CONT_SRC_UPLINK))
		sleep(1);

	json_object *intf_set;

	intf_set = dp_test_json_intf_set_create();

	/*
	 * Wait for the VR vplaned / vplaned-remote via uplink ready
	 * state to be reached
	 */
	while (!dp_test_master_ready(CONT_SRC_MAIN))
		sleep(1);
	dp_test_intf_create_default_set(intf_set);

	/*
	 * Initialise the code we use to build packets.
	 */
	dp_test_pktmbuf_set_mempool(mbuf_pool(0));
	dp_test_pktmbuf_set_alloc_fn(dp_test_pktmbuf_alloc);

	_dp_test_check_state_clean(__FILE__, __LINE__, false);

	/*
	 * The functions to send netlink data verify it has arrived
	 * before proceeding, therefore we can now move onto the
	 * tests without needing to worry about synchronisation.
	 */
	if (!dp_test_runner) {
		printf("\n%s: No tests registered aborting\n", dp_test_pname);
		dp_test_thread_internal_retval = -2;

	} else {
		int number_failed = 0;
		uint32_t i;

		srunner_set_fork_status(dp_test_runner, CK_NOFORK);
		for (i = 0; i < count; i++) {
			srunner_run_all(dp_test_runner, CK_ENV);
			number_failed += srunner_ntests_failed(dp_test_runner);
		}
		srunner_free(dp_test_runner);
		dp_test_runner = NULL;
		dp_test_thread_internal_retval = number_failed;
	}

	dp_test_controller_close(CONT_SRC_MAIN);

	/* SIGTERM will be caught by zmq, and then dataplane will be shutdown */
	kill(getpid(), SIGTERM);

	zsock_send(pipe, "i", dp_test_thread_internal_retval);
}

int stat(const char *path, struct stat *buf)
{
	return 0;
}

int dp_test_add_to_cfg_file(int argc, char **argv)
{
	int i;
	int size = 0;
	int remaining;
	char *ptr;

	if (argc > DP_MAX_EXTRA_CFG_LINES)
		return -EINVAL;

	for (i = 0; i < argc; i++)
		size += strlen(argv[i]);

	size += argc * 2;

	extra_cfg_buf = malloc(size);
	if (!extra_cfg_buf)
		return -ENOMEM;

	remaining = size;
	ptr = extra_cfg_buf;
	for (i = 0; i < argc; i++) {
		size = snprintf(ptr, remaining, "%s\n", argv[i]);
		remaining -= size;
		ptr += size;
	}

	return 0;
}

static char *get_conf_file_name(void)
{
	static char cfgfile[32];

	snprintf(cfgfile, sizeof(cfgfile), "dp_test-%d.conf", getpid());

	return cfgfile;
}

static void generate_conf_file(const char *cfgfile, const char *console_ep,
			       char *req_ipc, char *req_ipc_uplink,
			       const char *broker_ctrl_ep)
{
	char buf[1024];
	FILE *f;

	f = fopen(cfgfile, "w");
	if (!f) {
		perror("fopen");
		exit(2);
	}

	if (!extra_cfg_buf)
		extra_cfg_buf = (char *)"";

	const char *controller_ip_str, *dp_ip_str, *comment_str, *uplink_mac;
	const char *control_intf;
	uint16_t uuid;
	uint16_t dp_id;

	controller_ip_str = "127.0.0.1";
	comment_str = "# VR: dataplane id == 0";
	dp_ip_str = controller_ip_str;
	uuid = 0;
	dp_id = 0; /* is_local_controller-> true */
	uplink_mac = "00:00:00:00:00:00";
	control_intf = NULL;

	snprintf(buf, sizeof(buf),
		 "# %s test configuration\n"
		 "%s\n"
		 "[Controller]\n"
		 "ip=%s\n"
		 "request=%s\n"
		 "request_uplink=%s\n"
		 "\n"
		 "[Dataplane]\n"
		 "%s%s\n"  /* vr defines local ip */
		 "%s%s\n"  /* uplink uses dynamic address for local ip */
		 "control=%s\n"
		 "interface=lo\n"
		 "uuid=%i\n"
		 "dataplane-id=%i\n"
		 "uplink-mac=%s\n"
		 "%s\n"
		 "[RIB]\n"
		 "%s%s\n"  /* vr defines local ip */
		 "control=%s\n",
		 dp_test_pname,
		 comment_str,
		 controller_ip_str,
		 req_ipc ? req_ipc : "",
		 req_ipc_uplink ? req_ipc_uplink : "",
		 dp_ip_str ? "ip=" : "",
		 dp_ip_str ? dp_ip_str : "",
		 control_intf ? "control-interface=" : "",
		 control_intf ? control_intf : "",
		 console_ep,
		 uuid,
		 dp_id,
		 uplink_mac,
		 extra_cfg_buf,
		 dp_ip_str ? "ip=" : "",
		 dp_ip_str ? dp_ip_str : "",
		 broker_ctrl_ep);

	if (fwrite(buf, 1, strlen(buf) + 1, f) != strlen(buf) + 1) {
		fprintf(stderr, "Unable to write config\n");
		exit(2);
	}
	fclose(f);
}

static const char *get_rte_file_prefix(void)
{
	static char file_prefix[32];

	snprintf(file_prefix, sizeof(file_prefix),
		 "dp_test-%d", getpid());

	return file_prefix;
}

static void cleanup_temp_files(const char *cfgfile)
{
	if (unlink(cfgfile))
		perror("unlink dp config file");
}

static void unit_test_load_plugin(const char *buf)
{
	int (*unit_test_plugin_init)(const char **name);
	int rv;
	void *handle;
	const char *signature_buf;

	handle = dlopen(buf, RTLD_NOW);
	if (handle == NULL) {
		RTE_LOG(ERR, DATAPLANE,
			"failed to load unit_test plug-in: %s\n",
			dlerror());
		return;
	}

	/* Check it has an init func */
	unit_test_plugin_init = dlsym(handle, "dp_ut_plugin_init");
	if (!unit_test_plugin_init) {
		/* Not a unit_test plugin library */
		dlclose(handle);
		return;
	}

	RTE_LOG(INFO, DATAPLANE,
		"loaded unit-test plug-in: %s\n", buf);
	rv = unit_test_plugin_init(&signature_buf);
	if (rv) {
		RTE_LOG(INFO, DATAPLANE,
			"Failed to initialised unit-test plug-in: %s\n", buf);
		dlclose(handle);
		return;
	}

	RTE_LOG(INFO, DATAPLANE,
		"initialised unit plug-in: %s %s\n", buf, signature_buf);
}


static void unit_test_load_plugins(const char *directory)
{
	/*
	 * Iterate through directory loading pipeline plugins
	 */
	DIR *dp;
	struct dirent *ep;

	dp = opendir(directory);
	RTE_LOG(INFO, DATAPLANE, "Checking for unit-test plugins in %s\n",
		directory);

	if (dp != NULL)	{
		while ((ep = readdir(dp))) {
			/* restrict to .so files only */
			char *tmp = strrchr(ep->d_name, '.');

			if (!tmp)
				continue;
			if (strcmp(tmp, ".so") != 0)
				continue;

			char buf[1024];

			snprintf(buf, 1024, "%s/%s",
				 directory, ep->d_name);
			unit_test_load_plugin(buf);
		}
	} else {
		/*
		 * The directory not existing is normal so don't log
		 * an error in that case.
		 */
		if (errno != ENOENT)
			RTE_LOG(ERR, DATAPLANE,
				"error opening unit-test plug-in directory \"%s\": %s\n",
				directory, strerror(errno));
		return;
	}
	closedir(dp);
}



bool dp_test_fal_plugin_called;
uint32_t dp_test_fal_plugin_state;
void *dp_test_fal_plugin_ptr;

bool dp_test_abort_on_fail = true;

int __wrap_main(int argc, char **argv)
{
	char *cfgfile = get_conf_file_name();
	const char *console_ep = dp_test_console_set_endpoint(CONT_SRC_MAIN);
	char *broker_ctrl_ep;
	char *req_ipc, *req_ipc_uplink = NULL;
	const char *rte_file_prefix = get_rte_file_prefix();
	int ret;
	int dp_test_real_main_retval;
	int dp_test_thread_internal_retval;
	zactor_t *dp_test_actor;
	zactor_t *dp_test_broker_actor;

	/* Preserve name of myself. */
	dp_test_pname = strrchr(argv[0], '/');
	dp_test_pname = strdup(dp_test_pname ? dp_test_pname + 1 : argv[0]);

	if (getuid() == 0) {
		fprintf(stderr, "%s: Please run as normal user, not root\n",
			dp_test_pname);
		exit(1);
	}

	/* Because currently it's hard to clean up on failure */
	if (getenv("DP_TEST_DONT_ABORT_ON_FAIL"))
		dp_test_abort_on_fail = false;

	dp_test_debug_default();
	ret = dp_test_parse_args(argc, argv);
	if (ret < 0)
		return -1;

	if (from_external) {
		/* Setup paths if running from an external src tree */
		strncpy(dp_ut_dummyfs_dir,
			"/usr/share/vyatta-dataplane/tests/whole_dp/dummyfs/",
			PATH_MAX);
		strncpy(drv_cfgfile,
			"/usr/share/vyatta-dataplane/tests/dataplane-drivers-default.conf",
			PATH_MAX);
	}

	/* Load unit-test plugins if present */
	unit_test_load_plugins(dp_ut_plugin_dir);

	/* Start req and pub threads to emulate vplaned */
	dp_test_actor = zactor_new(dp_test_thread_run, NULL);
	if (!dp_test_actor) {
		fprintf(stderr, "%s: Failed to create test actor\n",
			dp_test_pname);
		exit(250);
	}
	req_ipc = zstr_recv(dp_test_actor);

	dp_test_broker_actor = zactor_new(dp_test_broker_thread_run, NULL);
	broker_ctrl_ep = zstr_recv(dp_test_broker_actor);

	generate_conf_file(cfgfile, console_ep, req_ipc,
			   req_ipc_uplink, broker_ctrl_ep);
	zstr_free(&broker_ctrl_ep);
	zstr_free(&req_ipc);
	if (req_ipc_uplink)
		zstr_free(&req_ipc_uplink);

	/*
	 * Disable the arp timer so that we don't get surprised
	 * by extra arp requests on slow systems.
	 */
	lltable_probe_timer_set_enabled(false);
	dp_test_intf_init();

	const char *dp_args[] = {
		"/usr/sbin/dataplane_test",
		"-f", cfgfile,
		"-c", drv_cfgfile,
		"-F", dp_feat_plugin_dir,
		"-C", console_ep,
		"-g", "root",
		"-P", dp_test_platform_file,
		"--",
		"-n", "1",
		"-c", "0x1",
		"--syslog", "local6",
		"--no-huge",
		"-m", "1024",
		"--file-prefix", rte_file_prefix,
		"--log-level",	rte_log_level,
	};

	dp_test_real_main_retval = __real_main(ARRAY_SIZE(dp_args),
					       (char **)dp_args);

	dp_test_fail_unless((dp_test_fal_plugin_called == true),
					"FAL plugin was not called");

	zsock_recv(dp_test_actor, "i", &dp_test_thread_internal_retval);
	zactor_destroy(&dp_test_actor);
	zactor_destroy(&dp_test_broker_actor);
	cleanup_temp_files(cfgfile);

	/*
	 * Since return code is see by shell as a uchar we effectively return -
	 *    0        = All OK
	 *    1- ~100  = Test Failures
	 * ~100- ~156  = Dataplane errors
	 * ~250-  255  = Test infra errors
	 *
	 * The ~ are because it depends on the range or dataplane and
	 * test infra error codes.
	 */
	if (dp_test_real_main_retval != 0)
		return dp_test_real_main_retval - 128;
	else
		return dp_test_thread_internal_retval;
}
