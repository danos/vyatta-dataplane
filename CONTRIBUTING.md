# Code submission guidelines for the dataplane

Violating any of the below may result in a source submission
being rejected.

## Use Protobuf format messages

The dataplane has three general configuration message formats:

 1) Netlink
 2) String space delimited commands
 3) Protobuf formatted commands

(2) is being deprecated in favor of (3) for a number of reasons (security,
performance, message definition, etc.).

No new configuration messages should be implemented as (2). And any work
on existing commands are strongly encouraged to use (3).

## Never access pipeline node directly

The extensible packet processing pipeline is designed to be constructed
at build time through the use of the pl_gen_fused script. Individual nodes
are defined in the src/pipeline/nodes/* directory. At some point nodes may
be dynamically invoked in a runtime constructed graph.

Nodes should never be called directly (currently through their *_fused()
generated entry points).

## Whole dataplane unit tests

The unit tests are executed as part of the default package build and **must**
be kept passing with every commit.

You should consider adding unit tests for any new functionality being add.

The majority of the dataplane is built into a process and APIs are provided to
inject state/traffic and verify the processing of the state, using [libcheck][5].

See the [readme](tests/whole_dp/readme.md) for full details of the test code
architecuture, how to write new tests and how execute them.

## Coding Style

Code conforms to the [linux kernel coding style][1], and [checkpatch][2] can be
used to find common style issues.

`checkpatch.pl` should be in `$PATH` and `scripts/checkpatch_wrapper.sh` used
to set the correct options with something like:

`./scripts/checkpatch_wrapper.sh origin/master bugfix/foo`

Please fix any warnings it reports, or be prepared to justify the exception
during code review.

## Static Analysis

[clang-tidy][3] should be used to check the code for Static Analysis warnings.

``` shell
apt install clang-tidy clang
export CC=clang CXX=clang++
meson build && cd build && ninja clang-tidy
```

You **must not** introduce any new warnings.

[1]: https://www.kernel.org/doc/Documentation/CodingStyle "Linux Kernel Coding Style"
[2]: https://github.com/torvalds/linux/blob/master/scripts/checkpatch.pl "checkpatch script"
[3]: https://clang.llvm.org/extra/clang-tidy/ "Clang-Tidy Code Checker"
[5]: http://libcheck.github.io/check/ "Check Unit Test Framework"
