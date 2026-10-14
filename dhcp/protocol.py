"""Constants and helpers for encoding and decoding DHCP packets."""

import ipaddress
import struct
from dataclasses import dataclass

# BOOTP's fixed 236-byte header; DHCP options follow its four-byte magic cookie.
BOOTREQUEST = struct.Struct("!BBBBIHH4s4s4s4s16s64s128s")
MAGIC_COOKIE = b"\x63\x82\x53\x63"
ZERO_IP = b"\0" * 4
BROADCAST_IP = ipaddress.IPv4Address("255.255.255.255")

DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_DECLINE = 4
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7
DHCP_MESSAGE_TYPES = {
    DHCP_DISCOVER: "DHCPDISCOVER",
    DHCP_OFFER: "DHCPOFFER",
    DHCP_REQUEST: "DHCPREQUEST",
    DHCP_DECLINE: "DHCPDECLINE",
    DHCP_ACK: "DHCPACK",
    DHCP_NAK: "DHCPNAK",
    DHCP_RELEASE: "DHCPRELEASE",
}


@dataclass
class Lease:
    """A client address and its monotonic expiry time."""

    address: ipaddress.IPv4Address
    expires_at: float


def parse_options(packet):
    """Decode DHCP options, rejecting malformed or truncated option data."""
    if len(packet) < BOOTREQUEST.size + len(MAGIC_COOKIE):
        raise ValueError("packet is shorter than the BOOTP header")
    if packet[BOOTREQUEST.size : BOOTREQUEST.size + 4] != MAGIC_COOKIE:
        raise ValueError("invalid DHCP magic cookie")

    options = {}
    offset = BOOTREQUEST.size + 4
    while offset < len(packet):
        code = packet[offset]
        offset += 1
        # PAD and END options have no length or payload field.
        if code == 0:
            continue
        if code == 255:
            break
        if offset >= len(packet):
            raise ValueError("missing DHCP option length")
        length = packet[offset]
        offset += 1
        if offset + length > len(packet):
            raise ValueError("truncated DHCP option")
        options[code] = packet[offset : offset + length]
        offset += length
    # Repeated option codes use the last value, matching the server's
    # single-value interpretation for the options it consumes.
    return options


def encode_option(code, value):
    """Encode a DHCP option's tag, one-byte length, and payload."""
    if len(value) > 255:
        raise ValueError("DHCP option value is too long")
    return bytes((code, len(value))) + value


def parse_mac(value):
    """Parse a colon-, hyphen-, dot-, or separator-free MAC address."""
    normalized = value.replace(":", "").replace("-", "").replace(".", "")
    try:
        address = bytes.fromhex(normalized)
    except ValueError as error:
        raise ValueError("invalid MAC address {!r}".format(value)) from error
    if len(address) != 6:
        raise ValueError("MAC address must contain exactly six bytes")
    return address


def parse_reservation(value):
    """Parse a command-line reservation in MAC=IPv4 form."""
    try:
        mac, address = value.split("=", 1)
    except ValueError as error:
        raise ValueError("reservation must use MAC=IPv4 format") from error
    return parse_mac(mac), ipaddress.IPv4Address(address)
