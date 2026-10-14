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
            ├─ scheduler thread ───── event/pool/expression rules
            ├─ backup thread ──────── periodic integrity-checked snapshots
            ├─ SessionAuth ────────── password, sessions, CSRF
            ├─ BackupManager ──────── snapshots and lease/rule rollback
            ├─ siem_events.jsonl ──── lease lifecycle + alerts
            └─ dhcp_packets.jsonl ─── DHCP message metadata
```

`main()` is the composition root. `DHCPServer` owns protocol processing and
uses `LeaseManager` for address state. `SIEMService` attaches callbacks to the
server and lease manager; it does not own DHCP allocation policy. The DHCP
receive loop runs in the main thread. The HTTP server and rule scheduler run
in separate daemon threads. `SIEMService` also starts its own snapshot scheduler;
it writes an initial checkpoint synchronously during service construction.

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
socket. It defaults to all IPv4 interfaces. Dashboard APIs require a single
user session; the default credentials are `root`/`root` for initial setup and
must be changed with `DHCP_DASHBOARD_PASSWORD`. The HTTP listener itself does
not provide TLS, so restrict access or put it behind a trusted TLS proxy.

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
- Request processing currently supports Ethernet BOOTP client identifiers only:
  `htype` must be Ethernet (1) and `hlen` must be six. Unsupported hardware
  address formats are rejected before lease state is touched.
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
- A client-originated RELEASE has no DHCP reply.
- The dashboard/API release operation is administrative: it removes the lease,
  quarantines the address until its former expiry to avoid reuse while a client
  may still be using it, then sends DHCPFORCERENEW. The resulting client
  DHCPREQUEST is NAKed because the lease has been revoked.

### Administrative lease changes

Dashboard/API renew and extend operations update server state and send a
unicast DHCPFORCERENEW to the client's current IPv4 address on UDP port 68.
When the client requests renewal, the server ACK includes the configured lease
duration, or the client's extended duration when one is set. DHCPFORCERENEW is an advisory protocol mechanism: clients must support and
accept it, and an unresponsive client may continue using its old address until
its original lease expires. This implementation does not add DHCP message
authentication, so use it only on a trusted client network. The server logs
its send attempt, not client receipt.

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
warnings. Per-client lease duration is also stored when an administrative
extension overrides the configured default; older records without that field
continue using the configured duration.

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
(`dhcp_packet`), direction, packet type, client MAC when an Ethernet BOOTP
header is available, source IPv4, and destination IPv4. `handle_packet()` logs
a receive before full semantic processing, so malformed datagrams can appear
as `MALFORMED` or `UNKNOWN`. Sent entries are written only after `sendto()`
returns successfully. The record does not contain payload/options, UDP ports,
interface index, or a kernel-level delivery confirmation. For outgoing
entries, `source_address` is based on the socket's local endpoint returned by
`getsockname()`; with a wildcard bind, it can therefore be `0.0.0.0` rather
than the interface address selected by the kernel for the datagram.

### SIEM rule processing

`SIEMService` loads a versioned rule file or creates default rules. Rule
validation supports:

- `event_rate`: event type, positive threshold, and positive time window.
- `pool_usage`: threshold from 1 through 100 percent.
- `expression`: a safe Boolean query over metrics or log records, evaluated
  no more frequently than its configured `interval_seconds`; `count_if()`
  can count matching records in a rolling time window.

A daemon scheduler waits `evaluation_interval` seconds between evaluations.
It reads lease events for event-rate rules and counts dynamic pool leases for
pool-usage rules. Triggered alerts are appended to the lease/SIEM event log.
`_last_triggered` suppresses repeated alerts for one evaluation interval while
a rule remains triggered. Rules are saved through a same-directory temporary
file and atomic replace. The built-in defaults trigger at 20 allocations in
60 seconds and at 80 percent pool utilization.

### Query expression language

`dhcp.query` parses expressions with Python's AST module but validates and
interprets an explicit subset; it never calls `eval()`. Supported syntax
includes nested dictionary paths (`nested.field`), constant dictionary/list
indexes (`record["field"]`), strings/numbers/booleans/null, `and`/`or`/`not`,
comparisons (`==`, `!=`, `<`, `<=`, `>`, `>=`, `in`, `not in`), and bounded
numeric `+`, `-`, `*`, `/`, `%`. `has("text")` searches the serialized record;
`contains(field, "text")` searches stringified field values or container
membership. Searches may select `all`, `events`, or `packets`.

For scheduled rules, `count_if("event == 'lease_allocated'", 60) >= 10`
compares the number of matching audit/packet records in the preceding 60
seconds. Expressions have length, AST-size, nesting, literal, arithmetic
result, and per-evaluation scan bounds. A search still scans the selected
JSONL file to find matches, so large log files affect query latency.

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
| `POST /api/leases/<mac>/renew` | Renew the current lease and prompt the client to renew. |
| `POST /api/leases/<mac>/extend` | Extend expiry and prompt the client to renew. |
| `DELETE /api/leases/<mac>` | Revoke a lease, protect its address until old expiry, and prompt the client to renew. |
| `GET /api/logs` | Search lease/SIEM events. |
| `GET /api/packets` | Search packet metadata by `since`, `until`, `source`, `destination`, `mac`, `type`, and `limit`. |
| `GET /api/search` | Evaluate a query expression over audit and/or packet records. |
| `POST /api/auth/login` | Authenticate and issue an HttpOnly session cookie and CSRF token. |
| `GET /api/auth/session`, `POST /api/auth/logout` | Inspect or end the current session. |
| `GET/POST /api/rules` | List or create detection rules. |
| `PATCH/PUT/DELETE /api/rules/<id>` | Update or delete a rule. |
| `GET/POST /api/backups` | List verified snapshot manifests or create a manual snapshot. |
| `POST /api/backups/<name>/restore` | Restore lease/rule state from a verified snapshot. |

Packet API time bounds are inclusive ISO-8601 timestamps; timezone-naive
values are treated as UTC. Source and destination filters are exact IPv4
matches, MAC addresses are normalized six-byte Ethernet addresses, and packet
type is validated against the supported DHCP names plus `MALFORMED` and
`UNKNOWN`. Invalid request values return HTTP 400. Log results
preserve append order, with a maximum number of matching records returned;
the dashboard reverses them for newest-first display.

Request bodies are limited to 1 MiB and must be JSON objects. All `/api/`
routes other than login and session inspection require an authenticated
session; non-GET methods additionally require its CSRF token. Sessions expire
after one hour and are held in memory, so restarting the process invalidates
them. Failed login attempts are throttled per remote address. Error handling
maps invalid values to 400, missing resources to 404, unsupported methods to
405, unauthenticated requests to 401, CSRF failures to 403, and storage/network
failures to 500. HTTP is still plaintext; authentication does not replace TLS.

## 10. Backups and rollback

`BackupManager` snapshots the lease state, rule file, audit log, and packet
log as a ZIP archive. It records source paths, presence/size metadata, and
SHA-256 digests in `manifest.json`. A checkpoint is written to a temporary
file, flushed, and atomically renamed; a startup snapshot is created
immediately, then the default interval is 1800 seconds and retention is 30
days. `--backup-dir`, `--backup-interval`, and `--backup-retention-days`
configure these values.

Restore verifies the manifest, paths, and file hashes, validates lease/rule
payloads before applying them, and creates a pre-rollback safety checkpoint.
Only lease and SIEM rule state are replaced; the current audit and packet logs
remain active. The in-memory lease/rule objects are reloaded after file
replacement. A snapshot is a local recovery mechanism, not off-host disaster
recovery or replication.

## 11. Diagnostics and implementation boundaries

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
