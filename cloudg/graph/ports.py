"""Numeric port ranges parsed from the ``port_range`` strings on graph edges.

The collectors write ``NetworkEdge.port_range`` in their provider's own
notation, and :class:`~cloudg.graph.builder.GraphBuilder` copies it onto the
graph edge as a string:

- AWS security groups: ``"22"`` or ``"from-to"`` such as ``"0-65535"``. A rule
  with protocol ``-1`` (all traffic) has no ports and is written as
  ``"0-65535"`` with protocol ``ALL``. For ICMP the two numbers are the ICMP
  type and code (``"8--1"``), not ports.
- Azure NSG rules: the destination port ranges joined with commas, for
  example ``"22,3389,8000-8100"``, or ``"*"`` for every port.
- GCP firewall rules: the ``ports`` list joined with commas. A protocol with
  no ports listed allows every port of that protocol.

Ports are matched as numbers. A substring test on the raw string would find
port 22 in ``"2200-2300"`` and miss it in ``"0-65535"``.

The module also holds the edge classification helpers shared by the graph
builder, the reachability analysis and the ontology: which edges are filter
rules, which rules are egress, which protocols carry ports and which
sources stand for the whole internet (:func:`is_internet_source`).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from cloudg.schema.models import EdgeType

MIN_PORT = 0
MAX_PORT = 65535

PortRange = tuple[int, int]
ALL_PORTS: tuple[PortRange, ...] = ((MIN_PORT, MAX_PORT),)

# ``port_range`` spelling of every port, as the AWS collector writes it
ALL_PORTS_RANGE = f"{MIN_PORT}-{MAX_PORT}"

# Protocol spellings that mean "every protocol": AWS ``-1`` (the collector
# writes ``ALL``), Azure ``*`` and ``Any``, GCP ``all``. Compared upper-case.
ALL_PROTOCOLS = frozenset({"ALL", "-1", "*", "ANY"})

# Protocols that carry ports, by name and by IANA number. An empty port list
# on a filter rule for one of these allows every port (GCP semantics).
PORTED_PROTOCOLS = frozenset({"TCP", "UDP", "SCTP", "6", "17", "132"})

# Port-less protocols, by name and by IANA number. AWS stores the ICMP type
# and code in the port fields.
PORTLESS_PROTOCOLS = frozenset(
    {"ICMP", "ICMPV6", "ESP", "AH", "GRE", "IPIP", "1", "58", "50", "51", "47", "4"}
)

# Filter rule edges: an empty port list on them means every port, and they
# are followed by the exposure walk unless they are egress rules. On other
# edges (for example a GCP ``INTERNET_EXPOSED`` edge for a public bucket) an
# empty ``port_range`` only means the collector had no port information.
FILTER_RULE_EDGES = frozenset({EdgeType.SECURITY_GROUP_RULE.value, EdgeType.NACL_RULE.value})

# CIDRs that stand for the whole internet
INTERNET_CIDRS = frozenset({"0.0.0.0/0", "::/0"})

# Every source spelling that stands for the whole internet, lower-cased: the
# CIDRs above plus the Azure NSG service tags ``Internet``, ``Any`` and ``*``.
INTERNET_SOURCES = INTERNET_CIDRS | {"*", "internet", "any"}

_RANGE_RE = re.compile(r"^(\d+)(?:-(\d+))?$")


def _normalise_protocol(protocol: str | None) -> str:
    return str(protocol or "").strip().upper()


def is_internet_source(value: str | None) -> bool:
    """Whether a rule source or CIDR stands for the whole internet.

    True for ``0.0.0.0/0``, ``::/0`` and the Azure NSG service tags
    ``Internet``, ``Any`` and ``*``, in any letter case and with surrounding
    blanks ignored. The exposure walk, the sensitive-port findings and the
    ontology's ``INTERNET_REACHABLE`` relation all use this one test.
    """
    return str(value or "").strip().lower() in INTERNET_SOURCES


def is_egress(edge_data: Mapping[str, Any]) -> bool:
    """Whether a graph edge (or edge attribute mapping) is an egress rule."""
    return str(edge_data.get("direction") or "").lower() == "egress"


def _parse_token(token: str) -> PortRange | None:
    """One ``"22"``, ``"1000-2000"`` or ``"*"`` token as a range, or None."""
    if token in ("*", "any", "all"):
        return ALL_PORTS[0]
    match = _RANGE_RE.match(token)
    if not match:
        return None
    low = int(match.group(1))
    high = int(match.group(2)) if match.group(2) is not None else low
    if low > high or high > MAX_PORT:
        return None
    return (low, high)


def parse_port_ranges(port_range: str | None, protocol: str | None = None) -> tuple[PortRange, ...]:
    """Parse a ``port_range`` string into inclusive ``(low, high)`` ranges.

    Args:
        port_range: The string as the collectors write it: ``"22"``,
            ``"0-65535"``, ``"22,3389,8000-8100"``, ``"*"`` or empty.
        protocol: The edge protocol (``TCP``, ``UDP``, ``ICMP``, ``ALL`` and
            the AWS / Azure / GCP spellings of those). Case does not matter.

    Returns:
        The ranges in the order written. Tokens that are not valid ports
        (``"-1"``, ``"70000"``, ``"30-20"``) are skipped. When nothing valid
        is left, an all-protocols rule (``ALL``, ``-1``, ``*``, ``Any``)
        returns every port, and so does an empty string for TCP, UDP or
        SCTP. Anything else returns ``()``, including a missing protocol.
        ICMP, ICMPv6, ESP, AH, GRE and IPIP rules always return ``()``: they
        have no ports, and the numbers AWS writes for ICMP are its type and
        code.

    Examples:
        >>> parse_port_ranges("0-65535", "ALL")
        ((0, 65535),)
        >>> parse_port_ranges("22,8000-8100", "Tcp")
        ((22, 22), (8000, 8100))
        >>> parse_port_ranges("", "TCP")
        ((0, 65535),)
        >>> parse_port_ranges("8--1", "ICMP")
        ()
    """
    proto = _normalise_protocol(protocol)
    if proto in PORTLESS_PROTOCOLS:
        return ()
    tokens = [t.strip().lower() for t in str(port_range or "").split(",")]
    ranges = tuple(r for r in (_parse_token(t) for t in tokens if t) if r is not None)
    if ranges:
        return ranges
    if proto in ALL_PROTOCOLS:
        return ALL_PORTS
    if proto in PORTED_PROTOCOLS and not any(tokens):
        return ALL_PORTS
    return ()


def edge_port_ranges(edge_data: Mapping[str, Any]) -> tuple[PortRange, ...]:
    """The ports a graph edge opens, from its ``port_range`` and ``protocol``.

    An edge with no ``port_range`` opens every port only when it is a
    security group or NACL rule. Any other edge type with an empty string
    returns ``()``, since there the collector simply had no ports to record.
    """
    port_range = str(edge_data.get("port_range") or "")
    if not port_range.strip() and edge_data.get("edge_type") not in FILTER_RULE_EDGES:
        return ()
    return parse_port_ranges(port_range, edge_data.get("protocol"))


def port_in_ranges(port: int, ranges: Iterable[PortRange]) -> bool:
    """Whether ``port`` falls inside any of the inclusive ``ranges``."""
    return any(low <= port <= high for low, high in ranges)


def covers_all_ports(ranges: Iterable[PortRange]) -> bool:
    """Whether the inclusive ``ranges`` together cover every port 0 to 65535."""
    reach = MIN_PORT - 1
    for low, high in sorted(ranges):
        if low > reach + 1:
            return False
        reach = max(reach, high)
    return reach >= MAX_PORT
