# vRouter software dataplane

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/a182163af5bf41f9a667b67210546520)](https://app.codacy.com/gh/danos/vyatta-dataplane?utm_source=github.com&utm_medium=referral&utm_content=danos/vyatta-dataplane&utm_campaign=Badge_Grade_Settings)

The dataplane provides routing, forwarding, firewall and QoS
fast path by use of the [Intel DPDK][0].

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details of coding requirements.

[0]: http://dpdk.org/ "Data Plane Development Kit"

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
