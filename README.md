# DHCP Starvation Protection

A dependency-free IPv4 DHCP server written in Python. It provides dynamic
leases, static reservations, basic lease persistence, common network
configuration options, and a browser-based lease-management and SIEM console.

> **Scope:** This is a learning project, not a production-ready DHCP server.
> The SIEM rules provide basic detection and logging, not a replacement for
> network-level controls or a production security monitoring platform.

## Requirements

- Python 3.8 or newer
- Permission to bind to UDP port 67 (usually an elevated terminal)
- A network interface reachable by the DHCP clients and configured for the
  server address

The server uses only Python's standard library.

## Project structure

The code is organized into a [dhcp](dhcp) package, a [tests](tests) directory,
and a [docs](docs) directory. See [docs/MODULES.md](docs/MODULES.md) for the
module dependency diagram and connections between the main functions.

```text
DHCPStarvationProtection/
├── dhcp/                  server package
│   ├── cli.py             command-line configuration and startup
│   ├── leases.py          lease management and persistence
│   ├── protocol.py        DHCP packet constants and helpers
│   ├── server.py          DHCP message handling and UDP socket
│   └── siem.py            HTTP API, separate lease/packet logs, and SIEM rules
├── docs/
│   └── MODULES.md         module and function connections
├── tests/
│   ├── test_server.py     server and lease unit tests
│   └── test_siem.py       HTTP API and SIEM rule tests
├── main.py                root launcher
└── README.md
```

## Run

Choose a server address and address pool in the same subnet. The server address
must not be inside the dynamic pool.

```sh
python3 main.py --server-ip 192.168.1.1 --subnet-mask 255.255.255.0 --pool-start 192.168.1.100 --pool-end 192.168.1.200 --dns 1.1.1.1
```

By default, it listens on all IPv4 interfaces at UDP port 67 and saves leases
to `dhcp_leases.json` in the current directory. The HTTP API listens on all
IPv4 interfaces at port 8080 by default. Stop both services with Ctrl+C.

The DHCP and HTTP services have independent bind addresses. For example, on
Debian/Linux, set each to the address of its own interface (both addresses
must be configured on the machine):

```sh
sudo python3 main.py --server-ip 192.168.1.1 --subnet-mask 255.255.255.0 --pool-start 192.168.1.100 --pool-end 192.168.1.200 --bind-address 192.168.1.1 --http-bind-address 10.0.0.5
```

`--bind-address` selects the DHCP UDP listener address; `--http-bind-address`
selects the dashboard/API listener address. Use `0.0.0.0` for either option
to listen on all IPv4 interfaces, or specify an address assigned to the
desired interface. On Debian/Linux, Python 3 and no third-party packages are
required; binding DHCP's default UDP port 67 requires root or equivalent
network capabilities. On Windows, use an elevated terminal when needed.

### Options

| Option | Required | Default | Description |
| --- | --- | --- | --- |
| `--server-ip` | Yes | — | IPv4 address of this DHCP server |
| `--subnet-mask` | Yes | — | Subnet mask, such as `255.255.255.0` |
| `--pool-start` | Yes | — | First dynamic address in the pool |
| `--pool-end` | Yes | — | Last dynamic address in the pool |
| `--router` | No | Server address | Default gateway advertised to clients |
| `--dns` | No | None | DNS server to advertise; repeat for multiple servers |
| `--ntp` | No | None | NTP server to advertise; repeat for multiple servers |
| `--domain-name` | No | None | DNS domain name advertised to clients |
| `--reservation` | No | None | Static mapping in `MAC=IPv4` form; repeat as needed |
| `--lease-seconds` | No | `3600` | Lease duration |
| `--decline-hold-seconds` | No | `3600` | How long to quarantine a declined address |
| `--lease-file` | No | `dhcp_leases.json` | JSON file for persistent leases and quarantines |
| `--bind-address` | No | `0.0.0.0` | Local IPv4 address to bind |
| `--port` | No | `67` | UDP listening port |
| `--http-bind-address` | No | `0.0.0.0` | Dashboard HTTP IPv4 bind address; defaults to all interfaces |
| `--http-port` | No | `8080` | Dashboard HTTP port |
| `--siem-log-file` | No | `siem_events.jsonl` | JSON-lines audit log |
| `--dhcp-packet-log-file` | No | `dhcp_packets.jsonl` | Separate JSON-lines log of received and sent DHCP packets |
| `--siem-rules-file` | No | `siem_rules.json` | Persistent SIEM rules |
| `--siem-interval` | No | `10` | Rule evaluation interval in seconds |

For example, advertise a router, DNS and NTP servers, a domain, and reserve an
address for one Ethernet client:

```sh
python3 main.py --server-ip 192.168.1.2 --subnet-mask 255.255.255.0 --pool-start 192.168.1.100 --pool-end 192.168.1.200 --router 192.168.1.1 --dns 1.1.1.1 --dns 8.8.8.8 --ntp 192.168.1.10 --domain-name example.test --reservation 02:00:00:00:00:01=192.168.1.50
```

Use `python3 main.py --help` to see all command-line options.

Run the unit tests with:

```sh
python3 -m unittest
```

## Implemented behavior

- Handles the main IPv4 DHCP exchange: DISCOVER/OFFER and REQUEST/ACK or NAK.
- Supports address selection, client reboot requests, and lease renewal requests.
- Tracks addresses by client hardware address and serializes lease mutations
  within the server process.
- Persists leases and declined-address quarantine timestamps to a JSON file.
  State is written through a temporary file and replaced atomically. Expiry
  timestamps are saved as wall-clock times so they survive process restarts.
- Supports static Ethernet MAC reservations. A reserved address is excluded
  from dynamic assignments, and a reserved client cannot receive a different
  dynamic address.
- Processes RELEASE for the client's current lease. A DECLINE quarantines the
  address only when it matches that client's lease; the address is not offered
  again until the quarantine expires.
- Advertises lease duration, subnet mask, router, broadcast address, and any
  configured DNS, NTP, and domain-name options.
- Sends relayed client replies to the DHCP relay indicated by `giaddr`.
- Binds to a selected local IPv4 address with `--bind-address`; the default
  `0.0.0.0` listens on all IPv4 interfaces.
- Provides an HTTP JSON API for searching leases and audit events, managing
  leases, and configuring persistent SIEM rules.
- Logs lease allocations, assignments, renewals, extensions, releases,
  declines, expirations, and triggered alerts as JSON-lines events.
- Records received and sent DHCP message types, timestamps, source addresses,
  and destination addresses in a separate JSON-lines packet log.
- Evaluates configurable event-rate and pool-usage rules on a timer. Default
  rules alert on 20 allocations in 60 seconds and at least 80% pool use.

## Lease management and SIEM dashboard

Open `http://<http-interface-address>:8080/` in a browser while the server is
running (for example, `http://10.0.0.5:8080/` for the example above). The
dashboard provides an overview of active leases, pool utilization and alerts,
searchable lease management (assign, renew, extend, release), searchable audit
events, a separate searchable DHCP packet log, and SIEM rule creation,
enable/disable, and deletion. Packet search filters support a time range,
source IPv4 address, destination IPv4 address, and DHCP message type. The
dashboard refreshes automatically every 10 seconds. The HTTP service has no authentication and
binds to all IPv4 interfaces by default. Restrict access with a firewall or
bind it to a trusted interface/address; do not expose it to an untrusted
network.

The site uses these JSON endpoints internally:

| Method and path | Behavior |
| --- | --- |
| `GET /api/leases?client=<mac>&address=<ip>&q=<term>&limit=<n>` | Search active leases. |
| `GET /api/leases/<mac>` | Get one active lease. |
| `DELETE /api/leases/<mac>` | Release a client's active lease. |
| `PUT /api/leases/<mac>` with `{"address":"192.0.2.10"}` | Assign or renew a valid address. |
| `POST /api/leases/<mac>/renew` | Renew the active lease for the configured lease duration. |
| `POST /api/leases/<mac>/extend` with `{"seconds":3600}` | Extend its current expiry by the requested seconds. |
| `GET /api/logs?event=<type>&client=<mac>&address=<ip>&since=<ISO-8601>&q=<term>&limit=<n>` | Search JSON audit events. |
| `GET /api/packets?since=<ISO-8601>&until=<ISO-8601>&source=<ip>&destination=<ip>&type=<DHCP-type>&limit=<n>` | Search the separate DHCP packet log by inclusive time bounds, source/destination IPv4 address, and packet type. |
| `GET /api/rules` | List rules. |
| `POST /api/rules` | Create a rule. |
| `PATCH /api/rules/<id>` | Update a rule. |
| `DELETE /api/rules/<id>` | Delete a rule. |
| `GET /api/stats` | Get active lease count and address-pool utilization. |

The root (`/`) serves the dashboard page; the JSON endpoints remain available
for integrations.

Rules are either `event_rate` (`event_type`, `threshold`, and
`window_seconds`) or `pool_usage` (`threshold_percent`); both accept `name`
and `enabled`. For example, create an allocation-burst rule with:

```json
{
  "name": "Allocation burst",
  "type": "event_rate",
  "event_type": "lease_allocated",
  "threshold": 10,
  "window_seconds": 30,
  "enabled": true
}
```

The built-in starvation-oriented rules detect rapid allocations to many
clients and high address-pool utilization. Triggered rules append `siem_alert`
events to the searchable lease/SIEM JSON-lines log. Rule state is stored
separately from DHCP lease state; back up the lease file, SIEM rules, lease/SIEM
event log, and DHCP packet log.

## Limitations

- This is not a full implementation of every DHCP option or protocol edge case,
  and it does not support DHCPv6.
- It does not enforce per-client request rate limits or quotas. SIEM alerts
  are detection-only and do not block clients or mitigate starvation.
- The HTTP dashboard and management endpoints have no authentication or
  authorization. The listener binds to all IPv4 interfaces by default; restrict
  access with a firewall or bind to a trusted address.
- Lease updates are synchronized among threads in one process, but separate
  server processes must not share the same lease file.
- The JSON file is not a replicated database or a backup strategy. Keep it
  available and writable; malformed state files prevent startup so they can
  be repaired rather than silently discarded.
- It does not probe the network to detect addresses used by devices with
  manually configured IP addresses.
- It is intended for learning and controlled testing, not as a replacement for
  a maintained production DHCP service.

## Safety

Run the server only on an isolated test network or a network where you are
authorized to provide DHCP. Multiple DHCP servers on one network can issue
conflicting configuration to clients. Binding to UDP port 67 usually requires
root or the appropriate network capability on Debian/Linux, and an elevated
terminal on Windows.
