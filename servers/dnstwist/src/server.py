#!/usr/bin/env python3
"""dnstwist MCP server (axross-mcp-hub): domain permutations for typosquatting,
homograph and brand-impersonation checks, over MCP stdio.

Tools:
    - dnstwist_permutations: generate look-alike domains (offline, no DNS)
    - dnstwist_scan: generate them and resolve which are registered (DNS)
    - dnstwist_fuzzers: the permutation algorithms

dnstwist is used as a library (dnstwist.Fuzzer, dnstwist.run); nothing is run
through a shell. Every argument is validated first. Only DNS is used: no web
page fetching, WHOIS, GeoIP, banners or screenshots. dnstwist_scan needs the
network (axross: Full); with no network every domain reads as unregistered.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import re
import sys

import dnstwist
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
log = logging.getLogger("dnstwist-mcp")

FUZZERS = (
    "*original", "addition", "bitsquatting", "cyrillic", "homoglyph", "hyphenation",
    "insertion", "omission", "plural", "repetition", "replacement", "subdomain",
    "transposition", "vowel-swap", "dictionary", "tld-swap", "various",
)
MAX_RESULTS = 5000
MAX_THREADS = 32
# A domain name (or punycode); never starts with "-" or ".".
_DOMAIN = re.compile(r"^(?=.{4,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}\.)+[A-Za-z0-9-]{2,63}$")
_DOH = re.compile(r"^https://[a-z0-9.-]{4,253}/dns-query$")

mcp = FastMCP("dnstwist-mcp")


class ArgumentError(ValueError):
    """A tool argument that is not accepted; the text says why."""


def _domain(value) -> str:
    if not isinstance(value, str) or not _DOMAIN.match(value.strip().lower()):
        raise ArgumentError("domain: a domain name such as example.com (no scheme, no path)")
    return value.strip().lower()


def _fuzzers(value) -> list[str] | None:
    if value is None or value == []:
        return None
    if not isinstance(value, list) or not all(isinstance(v, str) and v in FUZZERS for v in value):
        raise ArgumentError(f"fuzzers: a list of {', '.join(FUZZERS)}")
    return list(dict.fromkeys(value))


def _nameservers(value) -> list[str] | None:
    if value is None or value == []:
        return None
    if not isinstance(value, list) or len(value) > 8:
        raise ArgumentError("nameservers: up to 8 IPv4 addresses or https://host/dns-query URLs")
    out = []
    for item in value:
        if isinstance(item, str) and _DOH.match(item):
            out.append(item)
            continue
        try:
            out.append(str(ipaddress.IPv4Address(item)))
        except (ipaddress.AddressValueError, TypeError, ValueError):
            raise ArgumentError(f"nameservers: {item!r} is not an IPv4 address or DoH URL") from None
    return out


def _int(value, name: str, low: int, high: int, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ArgumentError(f"{name}: an integer from {low} to {high}")
    return value


def _clean(rows: list[dict], limit: int) -> dict:
    rows = sorted(rows, key=lambda r: (r.get("fuzzer") != "*original", r.get("fuzzer", ""),
                                       r.get("domain", "")))
    return {"count": len(rows), "returned": min(len(rows), limit), "domains": rows[:limit]}


@mcp.tool()
def dnstwist_fuzzers() -> dict:
    """List the permutation algorithms dnstwist can use."""
    return {"fuzzers": list(FUZZERS)}


@mcp.tool()
def dnstwist_permutations(domain: str, fuzzers: list[str] | None = None,
                          max_results: int = 500) -> dict:
    """Generate look-alike domains of DOMAIN without any DNS lookup.

    fuzzers: limit to these algorithms (see dnstwist_fuzzers); max_results: 1-5000.
    """
    try:
        name = _domain(domain)
        chosen = _fuzzers(fuzzers)
        limit = _int(max_results, "max_results", 1, MAX_RESULTS, 500)
        url = dnstwist.UrlParser(name)
        fuzz = dnstwist.Fuzzer(url.domain)
        fuzz.generate(fuzzers=chosen or [])
        rows = [{"fuzzer": p.get("fuzzer"), "domain": p.get("domain")} for p in fuzz.domains]
        return _clean(rows, limit)
    except ArgumentError as exc:
        return {"error": str(exc)}


def _scan(name: str, chosen, servers, threads: int, registered_only: bool) -> list[dict]:
    kwargs = {"domain": name, "format": "null", "threads": threads,
              "registered": registered_only}
    if chosen:
        kwargs["fuzzers"] = ",".join(chosen)
    if servers:
        kwargs["nameservers"] = ",".join(servers)
    # stdout carries MCP: anything dnstwist prints goes to stderr instead.
    with contextlib.redirect_stdout(sys.stderr):
        return dnstwist.run(**kwargs) or []


@mcp.tool()
async def dnstwist_scan(domain: str, fuzzers: list[str] | None = None,
                        registered_only: bool = True, nameservers: list[str] | None = None,
                        threads: int = 8, max_results: int = 500) -> dict:
    """Generate look-alike domains of DOMAIN and resolve them (A, AAAA, NS, MX).

    registered_only: return only domains that resolve; nameservers: IPv4 resolvers or
    DoH URLs (default: the container's resolver); threads: 1-32; max_results: 1-5000.
    Needs network access (DNS).
    """
    try:
        name = _domain(domain)
        chosen = _fuzzers(fuzzers)
        servers = _nameservers(nameservers)
        workers = _int(threads, "threads", 1, MAX_THREADS, 8)
        limit = _int(max_results, "max_results", 1, MAX_RESULTS, 500)
    except ArgumentError as exc:
        return {"error": str(exc)}
    try:
        rows = await asyncio.to_thread(_scan, name, chosen, servers, workers,
                                       registered_only is not False)
    except Exception as exc:  # noqa: BLE001 - dnstwist reports bad input as Exception
        log.warning("dnstwist scan of %s failed: %s", name, exc)
        return {"error": f"dnstwist: {exc}"}
    return _clean([dict(r) for r in rows], limit)


if __name__ == "__main__":
    mcp.run("stdio")
