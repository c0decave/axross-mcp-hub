#!/usr/bin/env python3
"""crt.sh MCP server (axross-mcp-hub): subdomains and certificates of a domain from the
Certificate Transparency logs, through crt.sh.

Tools:
    - ct_search: certificates logged for a domain (and its subdomains), with the unique
      host names they name
    - ct_certificate: one certificate by its crt.sh ID (PEM)

Needs network access to crt.sh only: in axross choose the network "Allowlist" with
crt.sh:443 (requests go through axross's proxy; HTTPS_PROXY is honoured). Every argument is
validated; only https://crt.sh/ is ever requested, and answers are size-bounded.
"""

from __future__ import annotations

import json
import logging
import re
import sys

import httpx
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
log = logging.getLogger("crtsh-mcp")

BASE = "https://crt.sh/"
MAX_ANSWER = 32 << 20
TIMEOUT = 120.0
# A domain name; never starts with "-" or ".".
_DOMAIN = re.compile(r"^(?=.{4,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}\.)+[A-Za-z0-9-]{2,63}$")

mcp = FastMCP("crtsh-mcp")


class ArgumentError(ValueError):
    """A tool argument that is not accepted; the text says why."""


def _domain(value) -> str:
    if not isinstance(value, str) or not _DOMAIN.match(value.strip().lower()):
        raise ArgumentError("domain: a domain name such as example.com (no scheme, no path)")
    return value.strip().lower()


def _int(value, name: str, low: int, high: int, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ArgumentError(f"{name}: an integer from {low} to {high}")
    return value


async def _get(params: dict) -> bytes:
    """GET https://crt.sh/ with *params*: no redirects, bounded size, HTTPS_PROXY honoured."""
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False, trust_env=True,
                                 headers={"User-Agent": "axross-mcp-hub crtsh"}) as client:
        async with client.stream("GET", BASE, params=params) as response:
            if response.status_code != 200:
                raise ArgumentError(f"crt.sh answered HTTP {response.status_code}")
            body = b""
            async for chunk in response.aiter_bytes():
                body += chunk
                if len(body) > MAX_ANSWER:
                    raise ArgumentError("crt.sh's answer is larger than 32 MiB: narrow the query")
            return body


@mcp.tool()
async def ct_search(domain: str, include_subdomains: bool = True, exclude_expired: bool = False,
                    max_certificates: int = 200) -> dict:
    """Certificates in the CT logs for *domain* (with include_subdomains: also every
    subdomain, %.domain), the unique host names they cover, and the newest certificates
    (ID, issuer, names, validity). max_certificates 1-5000."""
    try:
        name = _domain(domain)
        limit = _int(max_certificates, "max_certificates", 1, 5000, 200)
        params = {"q": f"%.{name}" if include_subdomains is not False else name, "output": "json"}
        if exclude_expired is True:
            params["exclude"] = "expired"
        try:
            body = await _get(params)
            rows = json.loads(body) if body.strip() else []
        except httpx.HTTPError as exc:
            raise ArgumentError(f"crt.sh not reachable: {exc}") from None
        except ValueError:
            raise ArgumentError("crt.sh did not answer JSON (it is sometimes overloaded: retry)") from None
        if not isinstance(rows, list):
            raise ArgumentError("crt.sh answered something else than a list")
        names: set[str] = set()
        certs = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            covered = sorted({n.strip().lower() for n in str(row.get("name_value", "")).split("\n")
                              if n.strip()})
            names.update(covered)
            certs.append({"id": row.get("id"), "issuer": row.get("issuer_name"),
                          "names": covered, "not_before": row.get("not_before"),
                          "not_after": row.get("not_after"),
                          "serial": row.get("serial_number")})
        certs.sort(key=lambda c: str(c.get("not_before") or ""), reverse=True)
        host_names = sorted(n for n in names if n == name or n.endswith("." + name))
        return {"domain": name, "certificates": len(certs), "unique_names": len(host_names),
                "names": host_names, "newest": certs[:limit]}
    except ArgumentError as exc:
        return {"error": str(exc)}


@mcp.tool()
async def ct_certificate(certificate_id: int) -> dict:
    """One certificate from crt.sh by its ID (see ct_search), as PEM."""
    try:
        ident = _int(certificate_id, "certificate_id", 1, 10**13, 1)
        try:
            body = await _get({"d": str(ident)})
        except httpx.HTTPError as exc:
            raise ArgumentError(f"crt.sh not reachable: {exc}") from None
        text = body.decode("ascii", "replace")
        if "BEGIN CERTIFICATE" not in text:
            raise ArgumentError(f"crt.sh has no certificate {ident}")
        return {"id": ident, "pem": text[:65536]}
    except ArgumentError as exc:
        return {"error": str(exc)}


if __name__ == "__main__":
    mcp.run("stdio")
