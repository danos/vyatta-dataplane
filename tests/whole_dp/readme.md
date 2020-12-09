# Dataplane Unit Test Framework


## Overview
This directory contains unit tests for vyatta-dataplane.  A test process which
includes the majority of the dataplane code is built. This process also includes
a test controller which provides state to the dataplane. Interfaces are faked.
Test APIs that allow the user to inject state from the test controller are defined,
along with APIs to allow the user to inject (receive) packets, which are then
processed. Further APIs allow checking that we got the expected behaviour from
packet processing.

## Building Test
Initially, it's recommended to do `dpkg-buildpackage -jauto -uc -us` to
configure the dataplane build environment, build the dataplane and
build and run the tests.

Setting `DEB_BUILD_OPTIONS="verbose"` `DH_VERBOSE=1` will generate detailed
test output.

Additional 'slow' tests can be optionally be enabled with either:

- If using the debian package build: `DEB_BUILD_OPTIONS="all_tests"`
- If using meson directly: `meson setup -Dall_tests=true <builddir> <sourcedir>`

It's often useful to disable Link Time Optimization to reduce rebuild times:

- If using the debian package build: `DEB_BUILD_OPTIONS="no_lto"`
- If using meson directly: `meson setup -Db_lto=false <builddir> <sourcedir>`

The tests are integrated into the [Meson Unit Test execution framework][1].
Use `meson test --help` for more information.

For rebuilds, you can simply do `meson test` from the build directory
(most likely `build`).

Detailed test output can also be generated with the following:
`meson test -v`

### Chroot Environment
Whilst the tests build and run via OBS and osc-buildpackage, for ease
and speed of development it's recommended to use a chroot
environment. After initially setting up the chroot environment
(e.g. using chrsetup), do the following:

1. `sudo mount --bind /proc /home/$USER/buildchroot/proc`
2. `sudo chroot /home/$USER/buildchroot su $USER`
3. `cd work/vyatta-dataplane/`

Then follow the instructions above to build and run the unit
tests. It's recommended to use an editor and git outside of the chroot
to avoid the need to ensure the settings in the chroot match those
outside. Note that binding `/proc` isn't necessary to build and run the
unit tests, but it avoids warnings if gdb is used on a running process.


## Running VR Tests
These are run automatically as part of `meson test` and the package build.

## Running Individual Tests
You can get a list of CK test suites with:
`meson test --list`

Indiviual CK test suites can be run with:
`meson test dp_test_bridge.c`

Run a single test using the `CK_RUN_CASE` environment variable:

`CK_RUN_CASE=bridge_unicast meson test dp_test_bridge.c`

or run directly after building only the test executable.

``` shell
ninja tests/whole_dp/dummyfs tests/whole_dp/fal_plugin_test.so tests/whole_dp/libsample_test.so src/pipeline/nodes/sample/sample_plugin.so
ninja tests/whole_dp/dataplane_test
cd tests/whole_dp
CK_RUN_CASE=bridge_unicast ./dataplane_test -d2 -F ../../src/pipeline/nodes/sample -P .
```

## Running test in GDB
The test binary can be executed in gdb:

`CK_RUN_CASE=bridge_unicast meson test --gdb -v dp_test_bridge.c`

or directly:

`CK_RUN_CASE=bridge_unicast gdb --args ./dataplane_test -f -d2`

 * `-d<n>` controls debugging logging

Use `./dataplane_test -h` for more help

## Adding tests via plugins
The dataplane supports adding features via plugins that live in different git repos.
To be able to test this there is support for adding UT plugins too. These can then
be used to test the feature plugins.

The vyatta-dataplane-dev package will install all the files needed to build the
feature plugins against the dataplane and also to build and run the unit tests.

To run the unit tests from outside the dataplane source tree you need to run in
'external' mode. This is done by passing in the -E flag. Doing this causes the
tests to use some different paths for files, pulling in the ones that are provided
by the dev package.

For example, the bfd dataplane plugin will run the tests as:
`/usr/bin/dataplane_test -d 0 -E`

When doing this the feat plugins will be picked up from:
`/usr/lib/*/vyatta-dataplane/pipeline/plugins/sample_plugin.so`

And the unit test plugins will be picked up from the directory that the test binary
is invoked from.


## Checking for memory leaks

It is good practice to ensure your code is not leaking memory. To that
end it is possible to run valgrind on the full unit-test module,
however it can take upwards of 1.5 hours to run. A more effcient
method is to run valgrind on individual test suites from within the
build root:

```
   CK_RUN_SUITE=dp_test_mstp_fwd.c \
   valgrind --suppressions=../tests/whole_dp/valgrind_suppressions \
   --trace-children=yes --tool=memcheck --leak-check=full \
   --show-reachable=no ./dataplane_test -d0
```

## Adding Tests
Tests are added either by adding further tests to an existing test file, or
by creating a new test file and adding it to the set of tests being run.

A test should always clean up after itself so that the state of the system
is as close as possible to the startup state.

## Code coverage
The module can be configured to add support for gcov based code coverage for
the whole_dp unit tests  using 'configure --enable-code-coverage'.
This will create a target 'make check-code-coverage' that will run the modules
test 'make check' and generate a code coverage report then print the URI for
the report.


## Test Architecture
The architecture of the tests tries to leave all the major aspects of the dataplane
in place, and then insert 'dummy' versions of the services that the dataplane uses.

This can be split into 2 parts, the dataplane code and the test code.

Dataplane:

  * dpdk - we link against the real dpdk, and use it for interfaces
  * core forwarding code used to forward packets
  * core zmq connections used to inject and query state:

    * pub/sub to controller
    * dealer/router to controller
    * console connection

Test code:

  * Wrapper functions (main and a version of random crypto uses)
  * Dummy controller providing the zmq connections and ability to use them
  * zmq console connection - send commands and get output
  * JSON parsing to allow us to parse command replies
  * netlink generation to inject state
  * dummy /proc /sys filesystems
  * Check UT infra  http://libcheck.github.io/check/
  * New 'main' which brings the tests up and runs them
  * stubs for dataplane code not included, shadow.c and a few other files

### How does it all hang together

On boot, the test version of the 'main' function runs. It spawns the test thread and
then it builds a set of arguments for the original dataplane 'main' function which it
then calls.

The dataplane code then goes through the normal init sequence.  It calls 'rte_eal_init'
to initialise dpdk.  The standard dpdk init queries the pci bus to find the set of
interfaces, and it queries the filesystem to get the number of cores. The test
environment fakes this up so that consistent results are returned irrespective of
where the tests are being run.  Arguments are passed into the dpdk init to stop it using
hugepages (we are not testing performance) and to provide a set of interfaces - each of
the interfaces we use is using the rte_eth_null driver, which is a standard PMD.

Once it has gone through the dpdk init, it proceeds through the rest of the init
as normal, and then the forwarding thread drops into the forwarding_loop, and the
main thread is in the main_loop.

To allow the dataplane to get through the init handshake the test thread has to provide
the controller/console ends of the zmq connections. It does this by spawning a further
thread to provide the controller request thread side.   This thread  will listen to the
MYPORT messages, and reply as required to allow init to proceed.  Meanwhile the test
thread (which is the zmq publisher) waits until the main loop is ready (i.e the
dataplane is ready).  It then creates the test interfaces (sends the default netlink
state) for each of them, and then is ready to start the tests.


### What does a test look like

A test starts with a clean system (as much as possible the default state). State can be
injected via netlink messages and verified via show commands along with JSON parsing.

Packets can be injected into the rx side of an interface with verification that what
was expected to happen did happen.

Each test cleans up the state it added, returning the system back to the clean state for
the next test.

### Why did we choose this model

We chose this model (as opposed to the per file tests) because we wanted to be able to
test the dataplane as a whole.  This approach gives the following benefits:

- test the dataplane from observable input/output
- dataplane not split into well defined 'units' for performance reasons, so stuff is tightly coupled
  and we want to test how those things work together.  For example, forwarding path and features.
- good correlation between test/real env, so if stuff works in tests it is very likely to work in real
  environment.
- this provides a development environment.
  code in the test harness.
- per file tests approach would have needed so much infra to let us test code properly, much less
  needed this way. For example, to test the forwarding of a packet in the 'per file' you would need
  to include multiple files, then provide lots of functional stubs (packets, lpm, ...)
 - minimal changes to real dataplane code needed.


## The Details


### Threading model

The threading model is important to understand as it drives some of the other test
behaviour.  Most tests want to do some variation of:

  * inject state
  * send and verify packets
  * clean

The state is injected to the dataplane via the zmq pub/sub socket, so we don't want to
send the packets until that state has been fully applied in the dataplane by the main
thread (in the standard way).  The forwarding thread (we pretend we are on a 2 core
system) is polling the interfaces rx queues to see if there are packets to forward.  They
are forwarded as soon as they are found, so we need to make sure we don't insert the
packets onto the interface rx queues until we know the state we want is applied.

The test thread sends the netlinks and injects the packets, so it needs to do the
verification. The standard way to do this is via a console request.  A new 'console'
connection is created, the console command is sent, it waits for the reply, and then
verifies the contents are as expected.  Once they are it can inject the packets and
the behaviour should be as expected.  The test netlink APIs typically do the verification
synchronously so when the func returns the state has been verified.

We have seen several races in the test due to the threading model when the verification
is not complete, the packets get sent but are not forwarded as expected due to the state
having not yet being fully applied. A couple of examples of this are:

  * bridge show command showing state before forwarding fully set up
  * gre show command not showing all fields, so change to tos not verified properly

Note also, that although the packet is injected by the test thread, it is forwarded by
the dataplane forwarding thread, so when debugging in gdb you need to look at multiple
threads to tie the forwarding code to test currently being run.

### How the interfaces work

As mentioned above, at init time the set of interfaces are provided in the args used when
we init dpdk.  This causes the dpdk to create all the interfaces, and the dataplane uses the
PMD to tx/rx packets.

Interfaces are named 'dpxTy' and we create 20 interfaces.

  * dp1T0..dp1T4
  * dp2T0..dp2T4
  * dp3T0..dp3T4
  * dp4T0..dp4T4

These interfaces get setup at init via the netlink APIs (see below).

Within the dpdk, each of these PMDs has an rx and a tx ring associated with it.  When the
PMD is queried to see if it has any packets, it returns the packets on the rx ring.  To
inject packets we simply add them to the ring on the receiving interface.

When we 'send' a packet out of an interface, that packet is placed on the 'tx' ring, where
the test code can query the ring to see what is there, and it can verify the contents of
any packets that are there.  The interface also maintains a count of how many times it
has been polled, and we can use this to determine that any packet in the system should
have completed processing.

Once the PMDs have been polled enough to ensure that all packets in the system are
processed the expected packets are compared against the received packets and anything that
is not as expected causes a test failure.

### Creating netlink messages

The forwarding state in the dataplane is built up by listening to netlink messages from
the controller. The test controller provides APIs to inject these netlink messages.  There
are multiple different types of netlink messages, new_link, new_route, ...

For all the netlink message types we currently care about we have APIs to generate a
message and sent it to the dataplane.  The arguments to the APIs depend on the netlink
message type, but I will talk about the routes here, as they are the most interesting.

A route can always be described by a string, for example
"10.73.2.0/24 nh 2.2.2.1 int:dp1T1"  There is a string parsing lib (dp_test_lib.h)
to turn this into a 'struct dp_test_route' This string is passed to the netlink API:

    dp_test_netlink_add_route("10.73.2.0/24 nh 2.2.2.1 int:dp1T1");

and this API will do the following (which is a standard pattern for the netlink APIs):

  * call the underlying func with line '__FILE__', '__func__', '__LINE__' to make identifying the
    line that failed easy
  * verify the state is currently as expected (i.e route is not yet there)
  * build the netlink message and send it
  * verify the new state is as expected (i.e the route is there).

The verification is done by running show commands and verifying that the output is as expected

There are complementary API to remove routes, and they follow the same pattern but with the
verification being the other way round

### JSON verification

Verifying with JSON follows this standard pattern:

 * given a string (for example a route) turn this into the set of 'expected JSON'
 * create the 'cmd' string
 * every millisec for 1 second:
 * send the cmd to dataplane via the console zmq
    * wait for the response
    * compare the expected JSON with the returned JSON. The comparisons can be
      EXACT, SUBSET, SUPERSET, i.e there is scope here to specify what you care about.
    * If match then break out of loop with PASS
 * If we didn't break out with PASS then FAIL

So, for example we would use this to verify that a route is there using the API:

    void
    _dp_test_wait_for_route(const char *route_string, bool match_nh,
    			const char *file, const char *func, int line)


### Naming conventions

There are some naming conventions worth mentioning here.  Core APIs that are typically used
by tests should try to take filename, func name and line number so that when a failure
happens perhaps several nested func calls deep, we can easily track down the originator.
We don't want to force the test writers to have to put these args into the API every time
they use them, so we adopt the following style for this case. Provide a macro version of the
API that calls the underlying func, inserting the required args.  The underlying func
typically has the same name, but with a leading underscore, for example:

    dp_test_netlink_route.h
    void _dp_test_netlink_add_route(const char *route_string, bool verify,
    				const char *file, const char *func,
    				int line);
    #define dp_test_netlink_add_route(route_string)			\
    	_dp_test_netlink_add_route(route_string, true,		\
    				   __FILE__, __func__, __LINE__)


In the above JSON verification example, the function to verify the route is gone starts
with a leading underscore as it is expecting the line etc to be passed in.  This is because
it is not a func expected to be called directly from the tests, but rather from a func to
add/remove a route via netlink.  The netlink func will pass the line etc through so that on
a failure the user knows what was being attempted when the failure happened.





### Creating a packet and the expectations for it


#### Interface Test name vs Real name

Tests are written using the distributed interface format
dp\<n\>T\<m\>, where \<n\> is the dataplane id and
\<m\> is the interface port number i.e. dp2T3.
We call these the test interface names.

The dataplane proper runs with:

  * VR format names when in VR mode i.e dpT23
  * Distributed format names when in distributed mode i.e. dp2T3

We call these the real interface names.

When running in VR mode, the test infra converts distributed test interface
names to VR interface names, so that we can write one test using the
distributed interface format and get the VR test for 'free'.
See `dp_test_lib_intf()`

dp\<n\>T4 is reserved for future use.

#### Generating the packets

The test model is to inject a test packet so the dataplane receives it.  Then
compare the packet(s) the dataplane transmits, with the packet(s) we expect.

The usual pattern for generating these packets is to:

  * Create the test packet to inject `dp_test_create_ipv4_pak()`
  * Create the packet we expect

    * Copy the packet we are going to inject `dp_test_exp_create()`

    * Modify the expected packet with the expected changes

      * L2 rewrite `dp_test_pktmbuf_eth_init()`
      * L3 update `dp_test_ipv4_decrement_ttl()`

The transmitted packet is compared to the expected packet `dp_test_pak_verify()`

#### Example Test

  * Receive on interface dp1T0
  * Transmit on interface dp2T1
  * Simulate IPv4 Unicast Host A to Host B

##### VR

Since we only have one vplane, the test interface names have been
transformed to be on the same vplane.

  * dp1T0 -> dpT10
  * dp2T1 -> dpT21


                      dataplane
                     +--------------+
     +------+        |              |        +------+
     |Host A|        |              |        |Host B|
     |      +---+--->|dpT10    dpT21+---+--->|      |
     |      |w  |   x|              |y  |   z|      |
     +------+   |    |              |   |    +------+
                |    +--------------+   |
                |                       |
      rx pak    |                       |    tx pak
     +----------+----------+          +-+-------------------+
     | L2  | L3  | Payload |          | L2  | L3  | Payload |
     |-----+-----+---------|      +-->|-----+-----+---------|
     | x w | A B | 1234    |      |   | z y | A B | 1234    |
     +---------------------+      |   +---------------------+
     dp_test_create_ipv4_pak()    |
     dp_test_pak_receive()        |
                                  |
                        dp_test_pak_verify()
                                  |
                                  |    dp_test_expected
                                  |   +---------------------+
                                  |   | L2  | L3  | Payload |
                                  +-->|-----+-----+---------|
                                      | z y | A B | 1234    |
                                      +---------------------+
                                      dp_test_exp_create()

####### Switch Ports

Two switch ports have been added to the system, "dp1sw_port_0_0" and
"dp1sw_port_0_7".  These interfaces are in addition to all the local
interfaces. Specific switch port tests have been added. The
switch ports are created with dp1T0 as their hardware switch backplane
interconnect. Specific tests use this interconnet to queue and receive
paths on, via the switch ports.


### Writing a test

Rather than copying a test here and letting it get out of date, a better option to see a
test is to look in the test files and find one that does something similar to what you need.

There are a wide range of APIs available to write set up what you need, and the most common
things needed are:

  * netlink routes, addresses, etc.
  * packets in and expected packets out
  * feature state.

For the simple tests, the style tends to be have a single test that does a single thing.
Within this test do:

  * create the netlink state
  * build a packet
  * build the expected packet/state
  * send the packet (and this calls the code to check if the packets are as expected)
  * cleanup

For example, see

    DP_START_TEST(ip_fwd_basic, if_fwd_basic)

The structure of this test is such that it
is reasonably easy to see what is being done, and what is being expected.

For the more complicated tests, for example some of the npf ones, the style is very
different. The npf ones have lots of wrappers to set up the state etc.  For example see

    DP_START_TEST(fw_ipv4, matching)

Here the test use wrappers to set up state, and so it is not as clear exactly what is
going on from a quick glance - usually there is more redirection needed.

As the 'best practices' for writing tests evolve we want to keep the following in mind:

  * It should be easy to look at the test and see what it is doing.  The more indirection
    there is the harder it can be.  But this has to be weighed against the cost of writing
    the same piece of code multiple times.
  * If using helper funcs to set up state try to make it obvious what those helper funcs
    are doing. For example write strings out in full or use string concatenation rather
    than building strings out of sprintf. Try to make sure these helper funcs identify
    the caller on failure so it is easy to see which test failed.
  * When injecting state, verify it is all there before sending packets.  If there is
    no way to verify the state, then consider adding a way.  If this is not possible
    you can at least verify that the processing should have finished by sending a further
    piece of state that you can verify, as messages should not be reordered if sent over
    the same zmq pipe.
  * We should aim to have a common set of APIs for building packets. Try not to make your
    packet builder func private to your tests. Add it to the lib of packet builder
    functions if appropriate.
  * Be aware of the races that can happen and try not to introduce tests that may be racy.
  * The tests are part of the build, so they must always work, and may have to be
    debugged by anyone if/when they fail.  Try to make your test as understandable as
    possible to any reader.


### TODO

These are some of the things on the todo list:

  * Allow testing to carry on after a fail.  Currently the testing ends on the first
    fail.  TO allow this we need a way to get back to a 'clean' state on a fail as
    otherwise we can't really tell if future tests have failed due to old state
    lying around or some other reason
  * Potential improvements to the way packets are displayed on failures.


[1]: https://mesonbuild.com/Unit-tests.html "Meson Unit Test Execution Framework"
