# Public header files

## Overview
This directory contains header files that are for use by code outside
of the repository.

A few basic ground rules:
1. Don't include any private header files from these header files
2. Don't make changes that might break source code that worked fine
   against an earlier version.

Binary compatibility (source built against an earlier version of the
headers should work when run with a later version of the dataplane)
isn't a requirement at this stage, but it's best to also try to avoid
making changes that would break this.

# Feature Plugin

Feature plugins allow features to be added to the dataplane without having
to change the core code. A library is loaded at init time and this provides
a feature that plugs into the public APIs.

A typical feature requires some configuration which it uses to set up its
data structures etc. It will typically then do some packet processing using
those data structures and it will typically have some way of reporting state
back to the system.

[See feature_plugin.h for more details about the plugins](feature_plugin.h)

## Threading model

The dataplane process contains many threads, and certain types of work must
be done on the correct thread.

The dataplane uses the dpdk lcore infra. For each logical core in the system
a thread is created and that thread runs only on that core. The lowest core
number is used for control plane processing and is called the main thread.
All the other lcores are used for packet processing by default.

See lcore_sched.h for more details about the [lcores](lcore_sched.h)

To allow for efficient updates of control plane state without having to lock
the forwarding threads the dataplane uses RCU. This allows updates from a
single thread along with multiple concurrent readers.

### main thread
All of the control plane state processing (routes, interface state, etc) is
done in the main thread (main lcore, typically lcore 0). The main thread
receives events from multiple sources and processes them in an RCU safe way.

A feature plugin init function is always called on the main thread. For
features that register a command handler this handler will always be called
on the main thread.

If a feature then has a need to process further updates on the main thread
as they arrive from a socket it can use the [event api](events.h)

### console thread

For features that register a show commands handler this handler will always
be called on the console thread.

### forwarding threads

For features that are involved in forwarding of packets the forwarding may
happen on multiple different forwarding lcores, or sometimes on the main
core. As there may be multiple cores there can be processing of multiple
packets at the same time. Multiple threads can read read the RCU controlled
state with no performance penalty. However writing in parallel can cause
performance issues due to the need to take locks.  Where the features needs
to do writes per packet (for example counters) it is recommended to user per
lcore state so that there is only a single thread/core updating a given memory
location at a time.

### Other threads

Feature can create other threads as required, but this should  be done
from the main thread.  These threads will then inherit the cpu affinity
from the main thread and so will run on the main lcore only.
New threads that access memory used by other threads should be registered
with [rcu](urcu.h)

# Fal plugin
