# QoS Dataplane Unit Test Framework

## Overview
The standard QoS unit-test topology has three-routers in a row, with the
UUT being the middle router.  The UUT has an ingress interface called dp1T0
that has an IP address of 1.1.1.1, and an egress interface called dp2T1 that
has an IP address of 2.2.2.2 to which the QoS configuration is attached.
The two neighbouring routers have IP addresses 1.1.1.11 and 2.2.2.11.

The basic design of each test consists of five stages:

1. test-setup - establishing the non-QoS configuration
2. attaching the QoS configuration to the egress interface
3. running some tests
4. removing the QoS configurartion from the egress interface
5. test-teardown - deleting the non-QoS configuration

If VIF/VLAN interfaces are required, they should be configured between steps
1 and 2, and deleted between steps 4 and 5.

The general goal of these test is to confirm that the QoS control plane is
working as expected.  While packet forwarding tests are possible, it is unlikely
that we will be able to have any rate-limiting or traffic-shaping unit-test due
to strict timing requirements, and the unusual way in which the DPDK's
librte_sched library handles time.

The principle of control-plane tests is to attach the relevant QoS configuration
to the egress interface, then check the JSON output returned by the "qos show"
vplsh command for the correct expected fields and value.

## QoS configuration
Since we only have access to the vyatta-dataplane, the QoS configuration has to
be given to the vyatta-dataplane in a form that it understand.  This means that
we need to generate a list of vyatta-dataplane QoS commands that are understood
by the vyatta-dataplane/src/qos_sched.c module.

The easiest way to generate these lists of vyatta-dataplane configuration
commands is to configure QoS on an VM using the standard vyatta QoS CLI
commands, then use a pair of scripts to produce a file containing a list of
the standard vyatta QoS CLI commands, and a list of the associated
vyatta-dataplane QoS commands.

The scripts are called qos-cli-to-dataplane-commands.sh and
qos-cli-to-dataplane-commands.py.  Both are available from the
vyatta-dataplane/tests/whole_dp/src directory.   Copy both scripts to a VM of
your choice, give the script execute permission, configured QoS, then run
./qos-cli-to-dataplane.sh.  The scripts are a bit clunky but they should
generate a file called qos_ut_test_cmds.txt.  Copy this file back to your
development environment as the seed for your new unit-test.

Please retain the comment section containing the standard vyatta QoS CLI
commands as they are much easier to understand than the list of
vyatta-dataplane QoS commands.


## Naming conventions
The dp_test_qos_get_json_... library functions use the following naming
convention.  The function name ends with the smallest suffix that uniquely
identify a node in the JSON tree returned by "qos show".   For example,
..._shaper because the "shaper" tag only appears one place in the JSON tree,
and ..._subports_tc and ..._pipes_tc because the "tc" tag appears in
two different locations in the tree, once under "subports" and once under
"pipes".


### Development and debugging hints
Add a temporary call dp_test_qos_show() to see what QoS thinks its op-mode state
is.

Each of the dp_test_qos_... library functions has a "debug" argument.  By
default all these arguments are linked to each test's debug variable (which
in turn is linked to the unit-test's command-line debug argument -d).
If a test is failing on a call to a particular dp_test_qos_... library
function, change its debug argument from "debug" to "true", rebuild and rerun
the test.  The library function should now provide additional information as
to why it is failing.

