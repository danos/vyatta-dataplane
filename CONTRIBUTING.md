# Code submission guidelines for the dataplane

Violating any of the below may result in a source submission
being rejected.

## Developer Certificate of Origin

The project maintainers for DANOS will only accept contributions using the
[Developer’s Certificate of Origin 1.1][6] (“DCO”). The DCO is a legally binding
statement asserting that you are the creator of your contribution, or that you
otherwise have the authority to distribute the contribution, and that you are
intentionally making the contribution available under the license associated
with the given repository.

You can agree to the DCO in your contribution by using a “Signed-off-by” line
at the end of your commit message. You should only submit a contribution if you
are willing to agree to the DCO terms. If you are willing, just add a line to
the end of every git commit message:

```Signed-off-by: Jane Smith <jane.smith@email.com>```

You may type this line on your own when writing your commit messages. However,
Git makes it easy to add this line to your commit messages. If you set your
`user.name` and `user.email` as part of your git configuration, you can sign
your commit automatically with `git commit -s`.

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

## Unit Testing

Vyatta-dataplane unit tests are done in a harness that builds the whole
dataplane.

The unit tests are executed as part of the default package build and **must**
be kept passing with every commit.

You should consider adding unit tests for any new functionality being add.

### Whole dataplane tests

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

[Cppcheck][3] can be used to check the code for Static Analysis warnings.

`cppcheck` should be in `$PATH` and `scripts/cppcheck_wrapper.sh` used
to check the files modified by a set of changes with something like:

`./scripts/cppcheck_wrapper.sh origin/master bugfix/foo`

You **must not** introduce any new warnings.

[1]: https://www.kernel.org/doc/Documentation/CodingStyle "Linux Kernel Coding Style"
[2]: https://github.com/torvalds/linux/blob/master/scripts/checkpatch.pl "checkpatch script"
[3]: http://cppcheck.sourceforge.net/ "Cppcheck Static Analyser"
[4]: http://cpputest.github.io/ "Cpputest Unit Test Framework"
[5]: http://libcheck.github.io/check/ "Check Unit Test Framework"
[6]: https://developercertificate.org "Developer Certificate of Origin"
