# Module and Function Connections

This note describes how the Python files fit together and how a DHCP packet
travels through the code. Start the program from the repository root with
`python main.py`.

## Module overview

```text
main.py                  root launcher
  └── dhcp/cli.py        command-line setup
        ├── dhcp/protocol.py
        └── dhcp/server.py
              ├── dhcp/protocol.py
              └── dhcp/leases.py
                    └── dhcp/protocol.py

tests/test_server.py
  ├── dhcp/protocol.py
  └── dhcp/server.py
```

| File | Responsibility |
| --- | --- |
| [main.py](../main.py) | Small root launcher that keeps `python main.py` as the entry command. |
| [dhcp/cli.py](../dhcp/cli.py) | Command-line arguments, configuration parsing, server startup, and top-level error reporting. |
| [dhcp/protocol.py](../dhcp/protocol.py) | BOOTP/DHCP constants, lease data type, DHCP option parsing/encoding, and MAC/reservation parsing. |
| [dhcp/server.py](../dhcp/server.py) | Server configuration validation, DHCP message handling, reply construction, routing replies, and UDP socket loop. |
| [dhcp/leases.py](../dhcp/leases.py) | Address allocation, static reservation ownership, lease renew/release, DECLINE quarantine, expiry, and JSON persistence. |
| [tests/test_server.py](../tests/test_server.py) | Synthetic DHCP packets and unit tests for server and lease behavior. |

## Startup flow

1. Python runs the `if __name__ == "__main__"` block in [main.py](../main.py),
   which imports and calls `main()` from [dhcp/cli.py](../dhcp/cli.py).
2. `main()` calls `parse_args()` to read the network and lease settings.
3. `main()` uses `parse_reservation()` from [dhcp/protocol.py](../dhcp/protocol.py)
   to convert each `MAC=IPv4` argument to a client identifier and address.
4. `main()` constructs `DHCPServer` from [dhcp/server.py](../dhcp/server.py).
   Its constructor validates the subnet, pool, and advertised options, then
   creates a `LeaseManager`.
5. `LeaseManager` loads saved lease and quarantine state from the configured
   JSON file, if the file exists.
6. `main()` calls `DHCPServer.serve_forever()`, which binds the UDP socket and
   dispatches each received packet to `DHCPServer.handle_packet()`.

## DHCP packet flow

1. `DHCPServer.handle_packet()` checks the BOOTP header and invokes
   `parse_options()` from [dhcp/protocol.py](../dhcp/protocol.py).
2. For DISCOVER, it calls `DHCPServer.allocate_address()`, which delegates to
   `LeaseManager.allocate()`. The server then builds an OFFER with
   `DHCPServer.build_reply()`.
3. For REQUEST, the server determines the requested/current address and calls
   `DHCPServer.assign_address()`, delegating validation and lease renewal to
   `LeaseManager.assign()`. The server builds an ACK on success or a NAK when
   the request cannot be satisfied.
4. For DECLINE and RELEASE, `handle_packet()` asks `LeaseManager.decline()` or
   `LeaseManager.release()` to update state. Declined addresses are temporarily
   quarantined; released leases become available again.
5. Lease mutations and expiry call `LeaseManager._persist_state()`, which
   atomically updates the JSON state file.
6. For a reply, `DHCPServer._response_destination()` selects the relay,
   client, or broadcast destination, and `handle_packet()` sends the response.

## Function map

### `main.py` and `dhcp/cli.py`

- The root `main.py` imports and calls `dhcp.cli.main()` for a stable launch command.
- `parse_args()` in `dhcp/cli.py` defines and parses command-line options.
- `main()` parses reservation strings, constructs `DHCPServer`, starts its
  socket loop, and converts configuration/startup errors into command-line
  errors.

### `dhcp/protocol.py`

- `parse_options(packet)` validates the DHCP cookie and decodes packet options.
- `encode_option(code, value)` serializes one option for a server response.
- `parse_mac(value)` converts common textual MAC formats into six bytes.
- `parse_reservation(value)` splits a `MAC=IPv4` string and parses its fields.
- `Lease` stores an IPv4 address and a monotonic expiration time.
- The `BOOTREQUEST`, cookie, zero/broadcast IP, and DHCP message constants are
  shared by packet handling, lease state, and tests.

### `dhcp/server.py`

- `DHCPServer.__init__()` validates the network configuration and initializes
  `LeaseManager`.
- `allocate_address()` and `assign_address()` are small delegators to the lease
  manager, keeping packet handling separate from allocation policy.
- `build_reply()` encodes the BOOTP response header and configured DHCP options.
- `_response_destination()` chooses where the reply should be sent.
- `handle_packet()` dispatches DISCOVER, REQUEST, DECLINE, and RELEASE messages
  to the appropriate lease and reply methods.
- `serve_forever()` receives UDP datagrams, calls `handle_packet()`, and logs
  malformed packets or operational errors.
- `leases` and `quarantined` properties expose manager state for diagnostics
  and existing callers.

### `dhcp/leases.py`

- `LeaseManager.__init__()` validates and indexes MAC reservations and loads
  persisted state.
- `_address_is_valid()` checks whether a client is allowed to use an address.
- `_persist_state()` atomically serializes active leases and quarantine expiry.
- `load_state()` validates saved records and rebuilds monotonic expirations.
- `expire()` removes expired leases/quarantines and saves state if it changed.
- `allocate()` returns a reserved or first available dynamic address.
- `assign()` validates and renews a client lease.
- `release()` removes only the client's matching lease.
- `decline()` removes a matching lease and quarantines the address.

## Tests and dependencies

`tests/test_server.py` builds packets using the protocol constants and sends
them through `DHCPServer.handle_packet()` with an in-memory fake socket. This
exercises packet and lease behavior without binding to a real network
interface. Run the suite from the repository root with `python -m unittest`.

The import direction is one-way: `main.py` starts the CLI; `dhcp/cli.py` uses
the protocol helpers and server; `dhcp/server.py` uses protocol utilities and
lease management; `dhcp/leases.py` uses the protocol's `Lease` data class and
MAC parser. `dhcp/protocol.py` does not import the server or lease manager.
