# DHCP Starvation Protection

A small, dependency-free IPv4 DHCP server written in Python. It implements the
basic DHCP client exchange and assigns addresses from a configured pool.

> **Status:** This is a barebones server, not a complete DHCP service or a
> starvation-protection system. Leases are kept in memory, and there are no
> rate limits, persistent storage, authentication, or advanced network
> configuration features.

## Requirements

- Python 3.7 or newer
- Permission to bind to UDP port 67 (typically an elevated terminal)
- A network interface with the configured server address

The server uses only the Python standard library; no package installation is
needed.

## Run

Choose a server address and an address pool that belong to the same subnet.
The server address must not be inside the pool.

```powershell
python main.py --server-ip 192.168.1.1 --subnet-mask 255.255.255.0 --pool-start 192.168.1.100 --pool-end 192.168.1.200 --dns 1.1.1.1
```

By default, the server listens on all IPv4 interfaces at UDP port 67. Stop it
with Ctrl+C.

### Options

| Option | Required | Default | Description |
| --- | --- | --- | --- |
| `--server-ip` | Yes | — | IPv4 address of the DHCP server |
| `--subnet-mask` | Yes | — | Subnet mask, such as `255.255.255.0` |
| `--pool-start` | Yes | — | First assignable address |
| `--pool-end` | Yes | — | Last assignable address |
| `--router` | No | Server address | Default gateway advertised to clients |
| `--dns` | No | None | DNS server to advertise; repeat the option for multiple servers |
| `--lease-seconds` | No | `3600` | Lease duration, in seconds |
| `--bind-address` | No | `0.0.0.0` | Local IPv4 address on which to listen |
| `--port` | No | `67` | UDP port on which to listen |

For example, to advertise a separate router and two DNS servers:

```powershell
python main.py --server-ip 192.168.1.2 --subnet-mask 255.255.255.0 --pool-start 192.168.1.100 --pool-end 192.168.1.200 --router 192.168.1.1 --dns 1.1.1.1 --dns 8.8.8.8
```

Use `python main.py --help` to see the command-line options.

## Behavior and limitations

- Handles DHCPDISCOVER with DHCPOFFER and DHCPREQUEST with DHCPACK or DHCPNAK.
- Includes subnet mask, router, broadcast address, lease duration, and optional
  DNS servers in successful replies.
- Tracks leases by client hardware address in memory. The first available
  address in the pool is assigned; expired leases are cleaned up when clients
  request or obtain addresses.
- Removes a client's lease on DHCPRELEASE or DHCPDECLINE.
- Does not persist leases across restarts. Restarting the process forgets all
  assignments.
- Has no starvation defenses beyond limiting assignments to the configured
  pool. It does not rate-limit clients or detect abusive behavior.
- Is not a general-purpose or production-ready DHCP server. DHCP features such
  as lease persistence, reservation policies, and robust recovery are outside
  its scope.

## Safety

Run the server only on an isolated test network or a network where you are
authorized to provide DHCP. Multiple DHCP servers on one network can issue
conflicting configuration to clients. Binding to port 67 usually requires an
elevated PowerShell window on Windows.
