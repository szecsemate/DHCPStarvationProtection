# Incident Report: DHCP Clients Falling Back to APIPA

**Incident date:** 2026-10-14  
**Environment:** Debian 13.7.0 VMs on Proxmox  
**Status:** Resolved

## Summary

Two Debian clients failed to obtain DHCP addresses and fell back to
IPv4 link-local (APIPA) addresses. The DHCP server was also running Debian
13.7.0 in a multi-interface VM. The clients and server could communicate when
configured with static addresses.

The server's DHCP UDP socket was bound to the specific unicast address
`10.0.0.1` on the client-facing interface. The clients' initial
`DHCPDISCOVER` messages are sent to the IPv4 broadcast address, not to
`10.0.0.1`. A packet capture (`tcpdump`) on the interface could see those
broadcast frames, but the application did not receive them through its socket.
As a result, the server did not process the requests or send offers.

## Impact

DHCP clients on the Proxmox network did not receive leases and assigned
themselves link-local addresses. Static addressing worked, and no firewall or
privilege issue was identified.

## Timeline and investigation

1. Clients showed APIPA addresses while the DHCP dashboard appeared to show
   leases. That display alone did not establish that an active client exchange
   had completed.
2. The server and clients were confirmed to be on the same Proxmox network;
   static-address communication worked.
3. The DHCP server had multiple network interfaces and used the client-facing
   unicast address `10.0.0.1` as its DHCP bind address.
4. The Proxmox VM NIC firewalls were tested disabled. The user also confirmed
   there were no host firewall rules and no other DHCP server on the network.
5. A packet capture showed incoming `DHCPDISCOVER` traffic. However, no
   corresponding Python application log or DHCP packet-log entry was observed.
   This distinguished visibility at the network interface from delivery to the
   server process.
6. The DHCP socket's unicast-only bind was identified as the likely cause:
   initial DHCP client packets target the subnet broadcast address.
7. The server was changed to listen on `0.0.0.0` and use Linux
   `SO_BINDTODEVICE` to restrict the socket to the client-facing NIC. The user
   confirmed that this configuration works.

## Root cause

The DHCP socket was bound to `10.0.0.1` instead of listening on the wildcard
IPv4 address while being restricted to the intended NIC. On a multi-interface
server, an incoming broadcast `DHCPDISCOVER` may be visible to an interface
packet capture without being delivered to a UDP socket bound only to a
specific unicast address.

This explains the key observed symptoms together: `tcpdump` saw client
broadcasts, but Python did not log or process them, so it did not produce
`DHCPOFFER` packets. This was not caused by the user permissions or firewall
rules examined during the investigation.

## Resolution

For a Linux server, bind the DHCP UDP socket to all IPv4 local addresses and
select the client-facing interface:

```sh
sudo python3 main.py \
  --server-ip 10.0.0.1 \
  --subnet-mask 255.255.255.0 \
  --pool-start 10.0.0.10 \
  --pool-end 10.0.0.100 \
  --bind-address 0.0.0.0 \
  --dhcp-interface <client-facing-interface>
```

Replace `<client-facing-interface>` with the actual Linux interface name (for
example, the name shown by `ip -br address`). `--dhcp-interface` uses Linux
`SO_BINDTODEVICE` to keep DHCP traffic on the chosen NIC while the wildcard
address bind accepts the broadcast destination. The interface option must be
paired with `--bind-address 0.0.0.0`.

The behavior is implemented in [server.py](../dhcp/server.py), configured by
the [CLI](../dhcp/cli.py), and described in the [run instructions](../README.md).

## Verification

After changing the bind configuration, the user confirmed DHCP worked. The
repository's unit tests also cover interface binding, broadcast-capable
wildcard binding, and rejection of a specific-IP bind combined with
`--dhcp-interface`.

## Operational notes

- On a multi-homed DHCP server, seeing a broadcast in `tcpdump` does not prove
  the application's UDP socket received it.
- The server log should show `Received DHCPDISCOVER`, followed by
  `Sending DHCPOFFER` and `Sent DHCPOFFER` when the application processes and
  sends a reply.
- A lease-allocation dashboard event alone is not proof that the client
  completed the DHCP exchange or received an address.
- Continue restricting DHCP to the intended client network/interface, and
  keep the unauthenticated HTTP dashboard/API on a trusted interface or behind
  appropriate network access controls.
