# DHCP Starvation Protection

A dependency-free IPv4 DHCP server written in Python. It provides dynamic
leases, static reservations, basic lease persistence, and common network
configuration options.

> **Scope:** This is a learning project, not a production-ready DHCP server.
> It deliberately does not implement security or starvation defenses such as
> client rate limits, abuse detection, or request quotas.

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
│   └── server.py          DHCP message handling and UDP socket
├── docs/
│   └── MODULES.md         module and function connections
├── tests/
│   └── test_server.py     server and lease unit tests
├── main.py                root launcher
└── README.md
```

## Run

Choose a server address and address pool in the same subnet. The server address
must not be inside the dynamic pool.

```powershell
python main.py --server-ip 192.168.1.1 --subnet-mask 255.255.255.0 --pool-start 192.168.1.100 --pool-end 192.168.1.200 --dns 1.1.1.1
```

By default, it listens on all IPv4 interfaces at UDP port 67 and saves leases
to `dhcp_leases.json` in the current directory. Stop it with Ctrl+C.

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

For example, advertise a router, DNS and NTP servers, a domain, and reserve an
address for one Ethernet client:

```powershell
python main.py --server-ip 192.168.1.2 --subnet-mask 255.255.255.0 --pool-start 192.168.1.100 --pool-end 192.168.1.200 --router 192.168.1.1 --dns 1.1.1.1 --dns 8.8.8.8 --ntp 192.168.1.10 --domain-name example.test --reservation 02:00:00:00:00:01=192.168.1.50
```

Use `python main.py --help` to see all command-line options.

Run the unit tests with:

```powershell
python -m unittest
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

## Limitations

- This is not a full implementation of every DHCP option or protocol edge case,
  and it does not support DHCPv6.
- It has no rate limiting, client quotas, starvation detection, or other
  abuse-prevention capability. The address pool bounds allocations but is not
  an anti-starvation defense.
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
conflicting configuration to clients. Binding to port 67 usually requires an
elevated PowerShell window on Windows.
