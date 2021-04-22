# vRouter software dataplane

The dataplane provides routing, forwarding, firewall and QoS
fast path by use of the [Intel DPDK][0].

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details of coding requirements.

[0]: http://dpdk.org/ "Data Plane Development Kit"

## Package Maintenance

### Changelog Merging
When merging branches, particularly master -> master-next, conflicts can often be
generated due to differing changelog entries. The `dpkg-mergechangelogs` tool can
automatically resolve conflicts in debian/changelog and ensure consistent ordering
of changelog entries.

This repository is configured to use `dpkg-mergechangelogs` to resolve conflicts in
debian/changelog. However to make use of it, a maintainer must install the tool and
enable it. From `dpkg-mergechangelogs(1)`:

> INTEGRATION WITH GIT
>
> If  you  want  to use this program to merge Debian changelog files in a
> git repository, you have first  to  register  a  new  merge  driver  in
> .git/config or ~/.gitconfig:
>
>     [merge "dpkg-mergechangelogs"]
>         name = debian/changelog merge driver
>         driver = dpkg-mergechangelogs -m %O %A %B %A

## Source Structure

| Directory       | Description |
| --------------- | ----------- |
| include         | Header files which form part of the public API |
| protobuf        | Google Protocol Buffers message formats which form part of the public API |
| scripts         | Development and build scripts |
| src/crypto      | IPSec crypto processing |
| src/if/bridge   | Bridge/switch interface type implementation |
| src/if/dpdk-eth | DPDK ethernet interface type implementation |
| src/l2tp        | L2TP interface and processing |
| src/session     | L4 Session Manager |
| src/mpls        | MultiProtocol Label Switching processing |
| src/npf         | Firewall, NAT, QoS classification & L3 ACL features |
| src/netinet     | IPv4 protocol processing |
| src/netinet6    | IPv6 protocol processing |
| src/pathmonitor | Path monitoring feature |
| src/pipeline    | Forwarding pipeline infrastructure |
| src/portmonitor | Port monitoring feature (packet mirroring) |
| tests/whole_dp  | Grey-box testing of the dataplane as a unit |
| tools           | Scripts that are installed to help the dataplane service |
