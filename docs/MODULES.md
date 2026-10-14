# Module and Function Connections

This document is a concise map of the repository and the main execution paths.
For packet formats, state transitions, persistence, logging, and API details,
see [TECHNICAL-DESIGN.md](TECHNICAL-DESIGN.md). For the resolved Proxmox
broadcast issue, see the
[incident report](INCIDENT-REPORT-2026-10-14-DHCP-BROADCAST.md).

Start the program from the repository root with `python3 main.py`.

## Module overview

```text
main.py                  root launcher
  └── dhcp/cli.py        parse configuration and coordinate services
        ├── dhcp/protocol.py
        ├── dhcp/server.py
        │     ├── dhcp/protocol.py
        │     └── dhcp/leases.py
        │           └── dhcp/protocol.py
        └── dhcp/siem.py
              ├── dhcp/auth.py
              ├── dhcp/backups.py
              ├── dhcp/query.py
              └── dhcp/protocol.py

dhcp/dashboard.html      browser client for the HTTP API

tests/
  ├── test_cli.py        CLI defaults and independent bind/log settings
  ├── test_server.py     DHCP packet and lease behavior
  └── test_siem.py       HTTP API, authentication, query, backups, and rules
```

| File | Responsibility |
| --- | --- |
| [main.py](../main.py) | Root launcher that calls `dhcp.cli.main()`. |
| [dhcp/cli.py](../dhcp/cli.py) | CLI options, object construction, service startup, and startup error reporting. |
| [dhcp/auth.py](../dhcp/auth.py) | Single-user password verification, expiring sessions, CSRF validation, and login throttling. |
| [dhcp/backups.py](../dhcp/backups.py) | Compressed integrity-checked snapshots, retention pruning, and protected state rollback. |
| [dhcp/protocol.py](../dhcp/protocol.py) | BOOTP/DHCP constants, message names, lease data type, option parsing/encoding, and MAC/reservation parsing. |
| [dhcp/query.py](../dhcp/query.py) | Bounded AST-based expression parsing and evaluation for log searches and rules; does not use Python `eval`. |
| [dhcp/server.py](../dhcp/server.py) | DHCP configuration validation, UDP receive loop, message processing, reply encoding/routing, and packet callback. |
| [dhcp/leases.py](../dhcp/leases.py) | Lease allocation/validation, reservations, release/decline/expiry, locking, and atomic JSON persistence. |
| [dhcp/siem.py](../dhcp/siem.py) | HTTP API/dashboard host, lease/SIEM event log, separate DHCP packet log, and scheduled rules. |
| [dhcp/dashboard.html](../dhcp/dashboard.html) | Browser UI for leases, lease/SIEM events, DHCP packet search, and rule administration. |
| [tests/test_cli.py](../tests/test_cli.py) | CLI defaults and configuration parsing. |
| [tests/test_server.py](../tests/test_server.py) | Synthetic DHCP packets and server/lease tests, including broadcast-interface binding. |
| [tests/test_siem.py](../tests/test_siem.py) | HTTP endpoints, authentication, log query, backups, and rules. |

## Startup and shutdown

1. `main.py` imports and calls `dhcp.cli.main()`.
2. `parse_args()` reads the server address, subnet, pool, bind settings, file
   paths, and optional DHCP configuration. Reservation arguments are parsed
   with `parse_reservation()`.
3. `main()` constructs `DHCPServer`; its constructor validates the IPv4
   network, pool, timers, and advertised options, then constructs
   `LeaseManager` and loads saved state.
4. `main()` constructs `SIEMService`. It creates the two JSON-lines logs,
   connects the lease and packet callbacks, loads/creates SIEM rules, creates
   an initial recovery snapshot, and starts the rule and backup scheduler
   threads.
5. `SIEMService.start_http()` starts the threaded HTTP server. The main thread
   then enters `DHCPServer.serve_forever()` and blocks in `recvfrom()`.
6. Ctrl+C during the DHCP receive loop is handled as normal shutdown. The
   `finally` block in `main()` closes the HTTP server and stops/joins the
   SIEM and backup schedulers.

## DHCP packet path

1. The UDP loop receives a datagram and its source endpoint. It calls
   `handle_packet()` with that source and the socket's local endpoint.
2. The server logs packet metadata, validates the fixed BOOTP header, and
   parses the DHCP magic cookie/options using `parse_options()`.
3. It dispatches DHCPDISCOVER, DHCPREQUEST, DHCPDECLINE, or DHCPRELEASE.
   Unsupported message types are ignored. DISCOVER allocates or reuses a
   lease, then builds an OFFER. REQUEST is checked against the current
   lease/requested address and produces an ACK or NAK. DECLINE quarantines a
   matching lease; RELEASE removes a matching lease. Neither produces a
   reply in the current implementation.
4. Replies encode a BOOTP reply header and DHCP options in `build_reply()`.
   `_response_destination()` selects the relay, client, or broadcast
   destination. `sendto()` sends the reply; successful sends are then recorded
   in the packet log.
5. Lease operations emit lease/SIEM audit events through the callback wired by
   `SIEMService`. Packet metadata, including the client MAC when available, is
   sent through a separate callback/log.

Dashboard/API lease renewal and extension send DHCPFORCERENEW to prompt the
client to renew. Administrative release revokes the server lease, holds its
address until its former expiry to avoid immediate reuse, then prompts the
client to renew; the server NAKs that client's renewal. Client support for
DHCPFORCERENEW is required, so it is not a guaranteed immediate disconnect.

`lease_allocated` means the server allocated/persisted state while handling
DISCOVER; by itself it does not prove that an OFFER reached the client or that
the DHCP exchange completed.

## State and HTTP/SIEM

- `LeaseManager` guards in-process lease/quarantine state with an `RLock`.
  Expiration is monotonic while running; JSON persistence converts expiry to
  wall-clock timestamps and atomically replaces the state file.
- `JsonEventLog` appends timestamped JSONL records with in-process
  synchronization and `fsync`. The lease/SIEM log and packet log are separate
  instances/files.
- `SessionAuth` verifies the configured single-user password using PBKDF2,
  issues expiring in-memory sessions, validates CSRF tokens, and throttles
  failed logins by remote address. The default `root`/`root` is for initial
  setup only; set `DHCP_DASHBOARD_PASSWORD`.
- `GET /api/packets` searches packet metadata by inclusive time bounds,
  source/destination IPv4, client MAC, and DHCP type. Authenticated `/api`
  routes also expose leases, logs, arbitrary-expression search, stats, rules,
  and snapshot management.
- `query.py` evaluates bounded Boolean, comparison, arithmetic, field-path,
  `has()`, and `contains()` expressions over JSON records. Scheduled
  expression rules also support rolling `count_if()` queries. This is a
  deliberately small DSL, not executable Python.
- `BackupManager` makes startup and periodic compressed snapshots of lease
  state, rules, and both logs, verifies member hashes before restore, and
  prunes archives by retention age. Manual restore replaces lease/rule state
  only, keeps active logs intact, and snapshots the pre-rollback state first.
- The SIEM scheduler evaluates event-rate, pool-usage, and expression rules,
  appending alerts to the lease/SIEM event log. SIEM rules detect but do not
  block or rate-limit DHCP clients.
- The dashboard is served from the package-local `dashboard.html` and calls
  the same-origin authenticated JSON API. HTTP itself is unencrypted; use a
  trusted network or TLS reverse proxy and restrict network exposure.

## Tests and dependencies

The project uses Python's standard library. Run tests from the repository root
with `python3 -m unittest`. Server tests use synthetic DHCP packets and a fake
socket; they do not require a live interface or prove delivery on a Proxmox
network.

The import direction is one-way: the CLI coordinates the protocol, server,
lease manager, and SIEM service; the server uses protocol utilities and lease
management; the lease manager uses protocol data/helpers. The dashboard is a
static HTTP resource and does not participate in server-side packet handling.
