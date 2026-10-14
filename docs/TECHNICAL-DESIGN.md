# Technical Design and Internal Workings

This guide follows the implementation from process startup through DHCP
datagram handling, lease state changes, persistence, logging, and the HTTP/SIEM
service. It is intended for readers familiar with Python, IPv4, UDP, and DHCP.
The implementation is deliberately small and is not a complete or
production-grade DHCP server.

## 1. Runtime architecture

```text
main.py
  └─ dhcp.cli.main()
       ├─ DHCPServer
       │    ├─ UDP socket / DHCP message state machine
       │    └─ LeaseManager
       │         └─ dhcp_leases.json
       └─ SIEMService
            ├─ ThreadingHTTPServer ── dashboard.html + JSON API
            ├─ scheduler thread ───── event/pool rules
            ├─ siem_events.jsonl ──── lease lifecycle + alerts
            └─ dhcp_packets.jsonl ─── DHCP message metadata
```

`main()` is the composition root. `DHCPServer` owns protocol processing and
uses `LeaseManager` for address state. `SIEMService` attaches callbacks to the
server and lease manager; it does not own DHCP allocation policy. The DHCP
receive loop runs in the main thread. The HTTP server and rule scheduler run
in separate daemon threads.

## 2. Configuration and startup order

`dhcp.cli.parse_args()` defines the command-line interface. `main()` converts
reservation strings with `parse_reservation()`, constructs `DHCPServer`, then
constructs `SIEMService`, starts HTTP, and enters the DHCP receive loop. The
service constructor attaches callbacks before packet reception begins.

Important network parameters:

- `--server-ip` is the IPv4 address advertised in DHCP server replies and used
  as the server identifier. It also defines the network when combined with
  `--subnet-mask`.
- `--bind-address` is the local IPv4 address passed to the UDP socket's
  `bind()`. It is not necessarily the same concept as the DHCP server ID.
- `--dhcp-interface` is a Linux-only device restriction using
  `SO_BINDTODEVICE`. It must be combined with `--bind-address 0.0.0.0` so
  initial broadcast requests can reach the socket while DHCP remains scoped to
  the selected NIC.
- `--pool-start` and `--pool-end` define an inclusive dynamic range. Endpoints
  must be usable addresses in the server subnet, and the range must not
  contain the server address.
- `--router` defaults to `--server-ip` and must be in the server subnet.
- DHCP port defaults to UDP 67; HTTP defaults to TCP 8080.
- Lease, event, rules, and packet-log paths default to
  `dhcp_leases.json`, `siem_events.jsonl`, `siem_rules.json`, and
  `dhcp_packets.jsonl`. Relative paths are relative to the process working
  directory.

The HTTP listener has its own `--http-bind-address`, independent of the DHCP
socket. It defaults to all IPv4 interfaces and has no authentication, so
firewall or interface restrictions are important.

## 3. Wire representation and protocol helpers

`dhcp.protocol` is the shared low-level vocabulary:

- `BOOTREQUEST` is a `struct.Struct` describing the fixed 236-byte BOOTP
  header. Its name is retained for both BOOTP request and reply encoding.
- `MAGIC_COOKIE` is the four-byte DHCP cookie after the BOOTP header.
- DHCP message type option 53 is mapped by `DHCP_MESSAGE_TYPES` to readable
  names for message logging.
- `parse_options()` validates minimum packet size and cookie, walks options,
  handles PAD (0) and END (255), and rejects missing lengths/truncated values.
  Repeated options overwrite earlier occurrences.
- `encode_option()` writes an option tag, one-byte length, and value.
- `Lease` holds an IPv4 address and a monotonic expiry deadline.
- `parse_mac()` and `parse_reservation()` parse client IDs/reservation CLI
  values.

`DHCPServer.handle_packet()` performs further semantic validation after
option parsing: BOOTREQUEST operation, hardware address length, and required
one-byte message type. Ethernet hardware type requires a six-byte hardware
address. Invalid packets raise `ValueError` and are logged/ignored by the
receive loop.

## 4. DHCP socket and interface binding

`DHCPServer.serve_forever()` creates an IPv4 UDP socket. It enables
`SO_REUSEADDR` and `SO_BROADCAST`, optionally applies Linux
`SO_BINDTODEVICE`, and binds the configured address/port. It then waits in
`recvfrom(4096)`.

The DHCP socket and HTTP socket are distinct. The interface selector exists
because packet capture visibility on a NIC does not necessarily mean a UDP
socket bound only to a unicast local address will receive a broadcast
DHCPDISCOVER. For a multihomed Linux host, use the client's NIC with wildcard
bind, for example:

```sh
--bind-address 0.0.0.0 --dhcp-interface enp0s3
```

The server logs receive, intended response, and successful `sendto()` stages.
`OSError` during handling/send is logged; malformed packet `ValueError` or
`struct.error` is logged and the loop continues. Ctrl+C during `recvfrom()` is
handled as a normal stop.

## 5. Message state machine

All packet branches use the client hardware-address bytes from the BOOTP
header as the lease key. Lease operations are serialized with the manager's
reentrant lock.

### DHCPDISCOVER

1. Call `allocate_address(client)`.
2. `LeaseManager.allocate()` expires old state, reuses an existing client
   lease if present, otherwise selects the client's reservation or the first
   available address in the dynamic range.
3. The new lease is persisted and a `lease_allocated` SIEM event is emitted
   immediately, before the server sends an OFFER.
4. The server constructs a DHCPOFFER and sends it.

If the pool/reservation has no free address, the request is ignored and a pool
exhaustion warning is logged. Allocation at DISCOVER time means a dashboard
`lease_allocated` record is not proof an OFFER was delivered or an ACK
completed the exchange.

### DHCPREQUEST

- A malformed server identifier (option 54) or requested address (option 50)
  is rejected as a malformed packet.
- If option 54 identifies another DHCP server, this server ignores the
  request.
- The requested/current address must match this client's active lease in the
  SELECTING (server identifier present) or renewal cases handled by the code.
  In INIT-REBOOT (requested address present, no server identifier, zero
  `ciaddr`), the server validates and may assign a currently unused address
  from this client's allowed pool/reservation. Without option 50 or a nonzero
  `ciaddr`, the server uses the client's current lease if one exists.
- `LeaseManager.assign()` validates subnet, pool/reservation ownership,
  quarantine, server address exclusion, and conflicts with other clients.
- A valid request renews/persists the lease and produces DHCPACK; otherwise a
  DHCPNAK is built.

### DHCPDECLINE and DHCPRELEASE

- DECLINE accepts an omitted server ID, but ignores one naming another server.
  It quarantines only if the supplied/derived address matches the sender's
  active lease. A successful decline removes the lease and persists the
  quarantine deadline.
- RELEASE removes only that client's lease, and only if `ciaddr` agrees when
  it is present.
- These two message types do not receive a DHCP reply in this implementation.

Other message types are ignored. The implementation is IPv4-only and does not
implement the full set of DHCP options or all protocol edge cases.

## 6. Reply encoding and destination selection

`build_reply()` constructs a BOOTREPLY header while preserving relevant
request fields and client hardware address. It sets `yiaddr` to the offered/
assigned address (or zero for NAK), and `siaddr`/server-identifier option 54
to `--server-ip`.

Every reply contains message type option 53 and server identifier 54. OFFER
and ACK additionally advertise:

| Option | Value |
| --- | --- |
| 51 | Lease duration |
| 1 | Subnet mask |
| 3 | Router |
| 28 | Subnet broadcast address |
| 6 | Configured DNS server list, if any |
| 42 | Configured NTP server list, if any |
| 15 | Configured ASCII domain name, if any |

The options terminate with END (255). NAK resets `ciaddr` to zero and does not
include the OFFER/ACK configuration options.

`_response_destination()` chooses the UDP destination in this order:

1. Nonzero relay address `giaddr`: relay address, UDP 67.
2. NAK, broadcast flag set, or zero `ciaddr`: `255.255.255.255`, UDP 68.
3. Otherwise: `ciaddr`, UDP 68.

The socket has broadcast enabled before sending. The selected destination
reflects the code's policy; it is not proof that a packet traversed the host
network stack or reached a client.

## 7. Lease ownership, expiry, and persistence

`LeaseManager` owns two in-memory maps: client-to-`Lease`, and address-to-
quarantine-expiry. A reentrant lock protects mutation and related reads inside
this process. It does not coordinate multiple server processes sharing a
lease file.

### Address eligibility

- Network and broadcast addresses and the server address cannot be leased.
- Dynamic clients receive the first unused, non-reserved, non-quarantined
  address in the inclusive pool.
- A reservation may be outside the dynamic range but must be a usable address
  in the subnet. A reserved address is not available to dynamic clients.
- A client with a reservation cannot be given a different dynamic address.
- An address is unavailable while quarantined or held by another active lease.

`expire()` compares deadlines to `time.monotonic()`, removes elapsed leases and
quarantines, persists if anything changed, and emits `lease_expired` events.
Expiration is invoked as part of allocation, assignment, and management
operations; there is no separate lease-expiration thread.

### JSON state file

The lease file has a version and separate `leases` and `quarantined` arrays.
Each persisted expiry is wall-clock time. On load, remaining duration is
computed from wall time and converted to a monotonic deadline for runtime
comparisons. Expired entries are skipped. Invalid file structure/entries
raise errors; duplicate or currently invalid leases are ignored with
warnings.

Persistence writes a temporary file beside the target, serializes JSON,
flushes and `fsync`s it, then uses `os.replace()` for atomic replacement.
Temporary files are cleaned up in a `finally` block.

## 8. Logs and SIEM

The lease/SIEM event log and DHCP packet log are separate append-only JSONL
files, each managed by `JsonEventLog`. Each append adds a UTC ISO-8601
timestamp, writes one JSON object per line, flushes, and calls `fsync()`.
Corrupt JSON or non-object records produce `EventLogError` during searches.

### Lease/SIEM events

The lease log contains events such as `lease_allocated`, `lease_assigned`,
`lease_renewed`, `lease_extended`, `lease_released`, `lease_declined`,
`lease_expired`, and `siem_alert`. Fields vary by event; lease events include
client/address, while alerts include rule information and details.

### Packet metadata

The packet log records metadata, not raw packet bytes: timestamp, `event`
(`dhcp_packet`), direction, packet type, source IPv4, and destination IPv4.
`handle_packet()` logs a receive before full semantic processing, so malformed
datagrams can appear as `MALFORMED` or `UNKNOWN`. Sent entries are written only
after `sendto()` returns successfully. The current record does not contain
payload/options, client MAC, UDP ports, interface index, or a kernel-level
delivery confirmation. For outgoing entries, `source_address` is based on the
socket's local endpoint returned by `getsockname()`; with a wildcard bind, it
can therefore be `0.0.0.0` rather than the interface address selected by the
kernel for the datagram.

### SIEM rule processing

`SIEMService` loads a versioned rule file or creates default rules. Rule
validation supports:

- `event_rate`: event type, positive threshold, and positive time window.
- `pool_usage`: threshold from 1 through 100 percent.

A daemon scheduler waits `evaluation_interval` seconds between evaluations.
It reads lease events for event-rate rules and counts dynamic pool leases for
pool-usage rules. Triggered alerts are appended to the lease/SIEM event log.
`_last_triggered` suppresses repeated alerts for one evaluation interval while
a rule remains triggered. Rules are saved through a same-directory temporary
file and atomic replace. The built-in defaults trigger at 20 allocations in
60 seconds and at 80 percent pool utilization.

## 9. HTTP API and dashboard

`SIEMService.start_http()` uses Python's standard-library
`ThreadingHTTPServer`. It serves the package-local `dashboard.html` at `/` and
handles JSON routes. The dashboard is a static client and uses same-origin
`fetch()` calls.

| Route | Behavior |
| --- | --- |
| `GET /api/stats` | Active lease count, dynamic pool capacity/use, and quarantine count. |
| `GET /api/leases` | Search active leases by client, address, or free-text query. |
| `GET /api/leases/<mac>` | Read one lease. |
| `PUT /api/leases/<mac>` | Assign/renew an address from a JSON body. |
| `POST /api/leases/<mac>/renew` | Renew the current lease. |
| `POST /api/leases/<mac>/extend` | Extend expiry by a positive number of seconds. |
| `DELETE /api/leases/<mac>` | Release a lease. |
| `GET /api/logs` | Search lease/SIEM events. |
| `GET /api/packets` | Search packet metadata by `since`, `until`, `source`, `destination`, `type`, and `limit`. |
| `GET/POST /api/rules` | List or create detection rules. |
| `PATCH/PUT/DELETE /api/rules/<id>` | Update or delete a rule. |

Packet API time bounds are inclusive ISO-8601 timestamps; timezone-naive
values are treated as UTC. Source and destination filters are exact IPv4
matches, and packet type is validated against the supported DHCP names plus
`MALFORMED` and `UNKNOWN`. Invalid request values return HTTP 400. Log results
preserve append order, with a maximum number of matching records returned;
the dashboard reverses them for newest-first display.

Request bodies are limited to 1 MiB and must be JSON objects. Error handling
maps invalid values to 400, missing resources to 404, unsupported methods to
405, and storage/network failures to 500. The HTTP service has no
authentication/authorization and should only be exposed to trusted networks.

## 10. Diagnostics and implementation boundaries

For a failed client exchange, compare evidence from each layer:

1. `tcpdump` sees the frame at an interface; this alone does not establish
   delivery to the Python UDP socket.
2. `Received DHCPDISCOVER` in the application log establishes that
   `recvfrom()` returned a datagram and `handle_packet()` began processing it.
3. `lease_allocated` establishes that allocation/persistence ran, not that a
   client accepted an offer.
4. `Sending DHCPOFFER` precedes the `sendto()` call; `Sent DHCPOFFER` is logged
   only after that call returns successfully.
5. A client still needs to receive the OFFER, send REQUEST, and receive ACK.

On a multihomed Linux server, `--bind-address 0.0.0.0 --dhcp-interface
<client-nic>` is the supported broadcast-reception configuration. Refer to
the [incident report](INCIDENT-REPORT-2026-10-14-DHCP-BROADCAST.md) for the
observed Proxmox case and resolution.

Unit tests construct synthetic packets and fake sockets. They validate local
encoding, state transitions, callbacks, API filters, and configuration
contracts; they do not simulate Linux packet routing, Proxmox bridges, VLANs,
or client acceptance of a lease. Operational network behavior must be
verified on the target host/network.
