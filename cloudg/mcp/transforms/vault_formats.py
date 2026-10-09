"""Token formats of the pseudonym vault (see :mod:`cloudg.mcp.transforms.vault`).

:class:`TokenFormats` is a mixin: every ``_fmt_*`` method turns one real
value into a candidate token of the same shape for a namespace and a
collision ``attempt``. :class:`~cloudg.mcp.transforms.vault.TokenVault`
supplies the keys (``_k_tok``, ``_k_bit``), the bit cache and
:meth:`tokenize` (used for nested components such as the account inside an
ARN).
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import ipaddress
import re
from typing import Any, Callable

_PRIVATE_BLOCKS_V4 = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")
]
_PRIVATE_BLOCKS_V6 = [ipaddress.ip_network("fc00::/7")]
_PUBLIC_V4_POOL = ipaddress.ip_network("198.18.0.0/15")
_WIDE_V4_POOL = ipaddress.ip_network("240.0.0.0/4")
_PUBLIC_V6_POOL = ipaddress.ip_network("2001:db8::/32")

_AWS_ID_RE = re.compile(r"^([a-z]{1,12})-([0-9a-f]{8,40})$")
_DIRS = r"(?:east|west|north|south|central|northeast|northwest|southeast|southwest)"
_REGION_RE = re.compile(
    rf"^(?:[a-z]{{2}}(?:-gov|-iso[a-z]?)?-{_DIRS}-\d|[a-z]+-{_DIRS}\d+(?:-[a-z])?|"
    rf"{_DIRS}[a-z]*\d?)$"
)
_SERVICE_LABELS = frozenset(
    "elb rds s3 ec2 compute compute-1 execute-api es cache cloudfront lambda-url on aws dkr "
    "ecr eks sqs sns blob file queue table web dfs vault database privatelink cloudapp c iam "
    "run cloudfunctions appspot core windows net azure googleapis internal azurewebsites "
    "scm documents redis servicebus azurecr postgres mysql mariadb sql s3-website api "
    "amazonaws com org io".split()
)
_CLOUD_SUFFIXES = tuple(
    sorted(
        (
            "amazonaws.com",
            "amazonaws.com.cn",
            "cloudfront.net",
            "awsapps.com",
            "azurewebsites.net",
            "cloudapp.azure.com",
            "cloudapp.net",
            "windows.net",
            "azure.com",
            "azurecr.io",
            "azure-api.net",
            "azureedge.net",
            "googleapis.com",
            "appspot.com",
            "run.app",
            "cloudfunctions.net",
            "internal",
            "compute.internal",
            "ec2.internal",
            "gserviceaccount.com",
        ),
        key=len,
        reverse=True,
    )
)
_GSA_RE = re.compile(
    r"^(?P<local>[^@]+)@(?P<proj>[a-z][a-z0-9\-]{4,28}[a-z0-9])"
    r"\.iam\.gserviceaccount\.com$"
)
_GSA_NUM_RE = re.compile(
    r"^(?P<prefix>service-|)(?P<num>\d{6,20})(?P<rest>-compute|)"
    r"@(?P<domain>[a-z0-9.\-]*gserviceaccount\.com)$"
)

#: Short prefixes for generic ``<prefix>-<hex>`` tokens.
_GENERIC_PREFIX = {
    "resource_name": "res",
    "dataset_name": "ds",
    "cloud_account": "acct",
    "url_username": "user",
    "azure_resource_group": "rg",
    "gcp_project_id": "proj",
    "tag_value": "tag",
    "person": "person",
    "hostname_label": "h",
    "email_domain": "d",
    "sensitive_field": "secret",  # nosec B105 - token prefix label, not a credential
    "secret_value": "secret",  # nosec B105 - token prefix label, not a credential
    "password": "secret",  # nosec B105 - token prefix label, not a credential
    "api_token": "secret",  # nosec B105 - token prefix label, not a credential
    "jwt": "secret",  # nosec B105 - token prefix label, not a credential
    "private_key": "secret",  # nosec B105 - token prefix label, not a credential
    "aws_secret_access_key": "secret",  # nosec B105 - token prefix label, not a credential
}

_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


class TokenFormats:
    """Format-preserving token builders (mixin of TokenVault)."""

    _k_tok: bytes
    _k_bit: bytes
    _bits: dict[tuple[Any, ...], int]

    #: Provided by TokenVault: returns the (possibly new) token of a value.
    tokenize: Callable[..., str]

    # ------------------------------------------------------------------
    # Token formats
    # ------------------------------------------------------------------

    def _digest(self, ns: str, entity: str, value: str, attempt: int) -> bytes:
        msg = f"{ns}\x1f{entity}\x1f{attempt}\x1f{value}".encode()
        return hmac.new(self._k_tok, msg, hashlib.sha256).digest()

    def _hex(self, ns: str, entity: str, value: str, attempt: int, n: int) -> str:
        h = self._digest(ns, entity, value, attempt).hex()
        while len(h) < n:
            h += self._digest(ns, entity, value + h, attempt).hex()
        return h[:n]

    def _build_formatters(self) -> dict[str, Callable[[str, str, int], str]]:
        ip = self._fmt_ip
        f: dict[str, Callable[[str, str, int], str]] = {
            "aws_account_id": self._fmt_digits("aws_account_id"),
            "gcp_project_number": self._fmt_digits("gcp_project_number"),
            "number": self._fmt_digits("number"),
            "azure_subscription_id": self._fmt_uuid("azure_subscription_id"),
            "azure_tenant_id": self._fmt_uuid("azure_tenant_id"),
            "uuid": self._fmt_uuid("uuid"),
            "gcp_project_id": self._fmt_project,
            "resource_name": self._fmt_resource_name,
            "aws_resource_id": self._fmt_resource_name,
            "email": self._fmt_email,
            "hostname": self._fmt_hostname,
            "aws_arn": self._fmt_arn,
            "azure_resource_id": self._fmt_azure_id,
            "gcp_resource_name": self._fmt_gcp_name,
            "mac_address": self._fmt_mac,
            "aws_access_key_id": self._fmt_akid,
            "aws_unique_id": self._fmt_akid,
            "cloudg_uri": self._fmt_cloudg_uri,
            "cloudg_iri": self._fmt_cloudg_iri,
            "rag_chunk_id": self._fmt_chunk_id,
            "aws_org_id": self._fmt_org_id,
            "aws_ou_id": self._fmt_org_id,
            "aws_root_id": self._fmt_org_id,
        }
        for name in (
            "ip_address",
            "private_ip",
            "public_ip",
            "special_ip",
            "cidr",
            "private_cidr",
            "public_cidr",
            "special_cidr",
        ):
            f[name] = ip
        return f

    def _fmt_generic(self, value: str, ns: str, attempt: int, entity: str | None = None) -> str:
        entity = entity or "generic"
        prefix = _GENERIC_PREFIX.get(entity) or (re.sub(r"[^a-z0-9]", "", entity)[:10] or "tok")
        return f"{prefix}-{self._hex(ns, entity, value, attempt, 10)}"

    def _generic_for(self, entity: str) -> Callable[[str, str, int], str]:
        return lambda v, ns, a: self._fmt_generic(v, ns, a, entity)

    def _fmt_digits(self, entity: str) -> Callable[[str, str, int], str]:
        def fmt(value: str, ns: str, attempt: int) -> str:
            if not value.isdigit():
                return self._fmt_generic(value, ns, attempt, entity)
            n = len(value)
            num = int.from_bytes(self._digest(ns, entity, value, attempt), "big") % (10**n)
            out = str(num).zfill(n)
            if n > 1 and out[0] == "0" and value[0] != "0":
                out = str(1 + int(out[0:1]) % 9) + out[1:]
            return out

        return fmt

    def _fmt_uuid(self, entity: str) -> Callable[[str, str, int], str]:
        def fmt(value: str, ns: str, attempt: int) -> str:
            h = list(self._hex(ns, entity, value.lower(), attempt, 32))
            h[12] = "8"  # RFC 9562 UUIDv8 (vendor-specific): well-formed, clearly synthetic
            h[16] = "89ab"[int(h[16], 16) % 4]
            s = "".join(h)
            out = f"{s[:8]}-{s[8:12]}-{s[12:16]}-{s[16:20]}-{s[20:]}"
            return out.upper() if value.isupper() else out

        return fmt

    def _fmt_project(self, value: str, ns: str, attempt: int) -> str:
        if value.isdigit():
            return self._fmt_digits("gcp_project_number")(value, ns, attempt)
        return f"proj-{self._hex(ns, 'gcp_project_id', value, attempt, 8)}"

    def _fmt_resource_name(self, value: str, ns: str, attempt: int) -> str:
        if value in ("*", "") or value.startswith("$"):
            return value
        m = _AWS_ID_RE.match(value)
        if m:
            return f"{m.group(1)}-{self._hex(ns, 'resource_name', value, attempt, len(m.group(2)))}"
        return f"res-{self._hex(ns, 'resource_name', value, attempt, 10)}"

    def _sub(self, value: str, entity: str, ns: str) -> str:
        return self.tokenize(value, entity, namespace=ns)

    def _fmt_email(self, value: str, ns: str, attempt: int) -> str:
        m = _GSA_RE.match(value)
        if m:
            proj = self._sub(m.group("proj"), "gcp_project_id", ns)
            local = f"sa-{self._hex(ns, 'email', value, attempt, 8)}"
            return f"{local}@{proj}.iam.gserviceaccount.com"
        m = _GSA_NUM_RE.match(value)
        if m:
            num = self._sub(m.group("num"), "gcp_project_number", ns)
            if attempt:
                num = self._fmt_digits("gcp_project_number")(m.group("num") + "x", ns, attempt)
            return f"{m.group('prefix')}{num}{m.group('rest')}@{m.group('domain')}"
        local, _, domain = value.rpartition("@")
        dom = self._sub(domain.lower(), "email_domain", ns) + ".example" if domain else "example"
        return f"user-{self._hex(ns, 'email', value, attempt, 8)}@{dom}"

    def _fmt_hostname(self, value: str, ns: str, attempt: int) -> str:
        host = value.rstrip(".")
        lower = host.lower()
        suffix = next((s for s in _CLOUD_SUFFIXES if lower == s or lower.endswith("." + s)), None)
        if suffix is None:
            return f"host-{self._hex(ns, 'hostname', lower, attempt, 8)}.example"
        left = host[: len(host) - len(suffix)].rstrip(".")
        if not left:
            return value
        labels = left.split(".")
        out = []
        changed = False
        for label in labels:
            ll = label.lower()
            if ll in _SERVICE_LABELS or _REGION_RE.match(ll):
                out.append(label)
            else:
                salt = label if attempt == 0 else f"{label}#{attempt}"
                out.append(self._sub(salt, "hostname_label", ns))
                changed = True
        if not changed:
            return value
        return ".".join(out) + "." + host[len(host) - len(suffix) :]

    def _fmt_arn(self, value: str, ns: str, attempt: int) -> str:
        parts = value.split(":", 5)
        if len(parts) < 6 or parts[0] != "arn":
            return self._fmt_generic(value, ns, attempt, "aws_arn")
        _, partition, service, region, account, resource = parts
        if account.isdigit() and len(account) == 12:
            account = self._sub(account, "aws_account_id", ns)
        rest = self._arn_resource(resource, service, ns)
        result = ":".join(["arn", partition, service, region, account, rest])
        if attempt:
            result += f"#{attempt}"
        return result

    def _arn_resource(self, resource: str, service: str, ns: str) -> str:
        """The resource part of an ARN: the resource type (first segment,
        except for S3 and single-segment resources), wildcards, variables
        and short numeric segments are kept; every other segment becomes a
        ``resource_name`` token."""
        segs = re.split(r"([/:])", resource)
        first_kept = not (service == "s3" or len(segs) == 1)
        out = []
        for i, seg in enumerate(segs):
            idx = i // 2
            keep = (
                i % 2 == 1  # separator
                or (idx == 0 and first_kept)
                or seg in ("", "*")
                or seg.startswith("$")
                or (seg.isdigit() and len(seg) <= 4 and idx > 0)
            )
            out.append(seg if keep else self._sub(seg, "resource_name", ns))
        return "".join(out)

    def _fmt_azure_id(self, value: str, ns: str, attempt: int) -> str:
        segs = value.split("/")
        out: list[str] = []
        prev = ""
        mode = ""  # "" | "type" | "name"
        for seg in segs:
            low = seg.lower()
            if not seg:
                out.append(seg)
            elif prev == "subscriptions":
                out.append(self._sub(seg, "azure_subscription_id", ns))
            elif prev == "tenants":
                out.append(self._sub(seg, "azure_tenant_id", ns))
            elif prev == "resourcegroups":
                out.append(self._sub(seg, "azure_resource_group", ns))
            elif low == "providers":
                out.append(seg)
                mode = "namespace"
            elif mode == "namespace":
                out.append(seg)
                mode = "type"
            elif mode == "type":
                out.append(seg)
                mode = "name"
            elif mode == "name":
                out.append(self._sub(seg, "resource_name", ns))
                mode = "type"
            else:
                out.append(seg)
            prev = low if seg else prev
        result = "/".join(out)
        return result + (f"#{attempt}" if attempt else "")

    def _fmt_gcp_name(self, value: str, ns: str, attempt: int) -> str:
        head = ""
        rest = value
        m = re.match(r"^(//[^/]+/)(.*)$", value)
        if m:
            head, rest = m.group(1), m.group(2)
        segs = rest.split("/")
        out = []
        for i, seg in enumerate(segs):
            if i % 2 == 0 or not seg:
                out.append(seg)
                continue
            coll = segs[i - 1].lower()
            if coll in ("zones", "regions", "locations") or seg == "-":
                out.append(seg)
            elif coll == "projects":
                out.append(
                    self._sub(seg, "gcp_project_number" if seg.isdigit() else "gcp_project_id", ns)
                )
            elif coll in ("organizations", "folders", "billingaccounts") and seg.isdigit():
                out.append(self._sub(seg, "number", ns))
            else:
                out.append(self._sub(seg, "resource_name", ns))
        result = head + "/".join(out)
        return result + (f"#{attempt}" if attempt else "")

    def _ref_entity(self, ref: str) -> str:
        from cloudg.mcp.transforms.detectors import classify_ip_text

        if ref.startswith("arn:"):
            return "aws_arn"
        if ref.lower().startswith("/subscriptions/"):
            return "azure_resource_id"
        if ref.startswith("//") or ref.startswith("projects/"):
            return "gcp_resource_name"
        refined = classify_ip_text(ref)
        if refined:
            return refined
        return "resource_name"

    def _fmt_cloudg_uri(self, value: str, ns: str, attempt: int) -> str:
        """``cloudg://assets/<ref>[/neighbors|/findings]`` and
        ``cloudg://datasets/<name>/...``: only the reference is replaced,
        typed like the same value elsewhere (an ARN stays an ARN pseudonym,
        a name gets the same ``res-...`` token as under ``name``)."""
        m = re.match(r"^(cloudg://assets/)(.+?)(/neighbors|/findings|/)?$", value)
        if m:
            ref = m.group(2)
            tok = self._ref_token(ref, ns)
            if tok == ref:
                return value
            out = f"{m.group(1)}{tok}{m.group(3) or ''}"
        else:
            m = re.match(r"^(cloudg://datasets/)([^/]+)(/.*)?$", value)
            if not m:
                return value
            out = f"{m.group(1)}{self._sub(m.group(2), 'dataset_name', ns)}{m.group(3) or ''}"
        return out + (f"#{attempt}" if attempt else "")

    def _fmt_org_id(self, value: str, ns: str, attempt: int) -> str:
        """``o-``, ``ou-`` and ``r-`` ids keep their prefix; every other
        hyphen-separated part becomes random hex of the same length."""
        prefix, _, rest = value.partition("-")
        if not rest:
            return self._fmt_generic(value, ns, attempt, "aws_org_id")
        h = self._hex(ns, "aws_org_id", value, attempt, max(len(rest), 8) + 8)
        parts, pos = [], 0
        for part in rest.split("-"):
            n = max(len(part), 4)
            parts.append(h[pos : pos + n])
            pos += n
        return f"{prefix}-{'-'.join(parts)}"

    def _ref_token(self, ref: str, ns: str) -> str:
        from cloudg.mcp.transforms.detectors import ref_entity

        structured = self._ref_entity(ref)
        if structured != "resource_name":  # ARN, Azure id, GCP name, IP
            return self._sub(ref, structured, ns)
        entity = ref_entity(ref)
        if entity == "uuid":
            return ref  # cloudg's own random ids are kept
        return self._sub(ref, entity, ns)

    def _fmt_cloudg_iri(self, value: str, ns: str, attempt: int) -> str:
        """Ontology resource IRIs (``cmr:<asset id>``, ``cmr:tag_<key>_<value>``):
        the identifier part gets the same token the plain value gets
        elsewhere; finding and compliance IRIs are kept."""
        from cloudg.mcp.transforms.detectors import PERSON_TAG_PATTERN, normalize_key
        from cloudg.mcp.transforms.redaction import DEFAULT_TAG_KEY_ALLOWLIST

        prefix = "cmr:" if value.startswith("cmr:") else "https://cloudg.io/resource/"
        local = value[len(prefix) :]
        if not local or local.startswith(("finding_", "compliance_")):
            return value
        if local.startswith("tag_"):
            rest = local[4:]
            key = next(
                (
                    k
                    for k in sorted(DEFAULT_TAG_KEY_ALLOWLIST, key=len, reverse=True)
                    if rest.lower().startswith(k + "_")
                ),
                None,
            )
            if key is not None:
                return value
            tkey, sep, tval = rest.partition("_")
            if not sep or not tval:
                return f"{prefix}tag_{self._sub(rest, 'tag_value', ns)}"
            person = re.search(PERSON_TAG_PATTERN, normalize_key(tkey))
            tok = self._sub(tval, "person" if person else "tag_value", ns)
            out = f"{prefix}tag_{tkey}_{tok}"
        else:
            out = prefix + self._ref_token(local, ns)
            if out == value:
                return value
        return out + (f"#{attempt}" if attempt else "")

    def _fmt_chunk_id(self, value: str, ns: str, attempt: int) -> str:
        """RAG chunk ids: ``entity::<asset id>`` gets the asset id's token;
        ``community::`` / ``relation_group::`` ids are kept."""
        kind, sep, ref = value.partition("::")
        if not sep or kind != "entity" or not ref:
            return value
        tok = self._ref_token(ref, ns)
        if tok == ref:
            return value
        return f"{kind}::{tok}" + (f"#{attempt}" if attempt else "")

    def _fmt_mac(self, value: str, ns: str, attempt: int) -> str:
        sep = "-" if "-" in value else ":"
        b = bytearray(self._digest(ns, "mac_address", value.lower(), attempt)[:6])
        b[0] = (b[0] | 0x02) & 0xFE  # locally administered, unicast
        out = sep.join(f"{x:02x}" for x in b)
        return out.upper() if value.isupper() else out

    def _fmt_akid(self, value: str, ns: str, attempt: int) -> str:
        prefix = value[:4]
        d = self._digest(ns, "aws_access_key_id", value, attempt)
        return prefix + "".join(_B32[x % 32] for x in d[:16])

    # -- IPs -------------------------------------------------------------

    def _pp_bits(self, ns: str, block: str, host: int, hbits: int) -> int:
        """Prefix-preserving keyed permutation of the low ``hbits`` bits
        (Crypto-PAn style): output bit i = input bit i XOR PRF(prefix)."""
        out = 0
        cache = self._bits
        if len(cache) > 500_000:
            cache.clear()
        for i in range(hbits):
            shift = hbits - i
            prefix = host >> shift
            ck = (ns, block, i, prefix)
            flip = cache.get(ck)
            if flip is None:
                flip = (
                    hashlib.blake2b(
                        f"{ns}|{block}|{i}|{prefix}".encode(), key=self._k_bit, digest_size=1
                    ).digest()[0]
                    & 1
                )
                cache[ck] = flip
            out = (out << 1) | (((host >> (shift - 1)) & 1) ^ flip)
        return out

    def _fmt_ip(self, value: str, ns: str, attempt: int) -> str:
        from cloudg.mcp.transforms.detectors import ip_class

        parsed = _parse_ip(value)
        if parsed is None:
            return self._fmt_generic(value, ns, attempt, "ip_address")
        addr, host_part, plen, is_net = parsed
        cls = ip_class(addr)
        if cls == "special" or (is_net and plen == 0):
            return value
        if cls == "private":
            fake = self._fake_private(addr, host_part, plen, (ns, value, attempt))
        else:
            seed = str(addr) if is_net else value
            fake = self._fake_public(addr, plen, (ns, seed, attempt))
        if fake is None:
            return value
        bits = addr.max_prefixlen
        cls_obj = ipaddress.IPv4Address if addr.version == 4 else ipaddress.IPv6Address
        if not is_net:
            return str(cls_obj(fake))
        netmask = ((1 << bits) - 1) ^ ((1 << (bits - plen)) - 1)
        host_bits = int(host_part) & ~netmask & ((1 << bits) - 1)
        if host_bits and cls == "private" and not attempt:
            # "10.0.1.5/24" style interface address: keep host consistent
            return f"{cls_obj(fake)}/{plen}"
        return f"{cls_obj(fake & netmask)}/{plen}"

    def _fake_private(
        self, addr: Any, host_part: Any, plen: int, seed: tuple[str, str, int]
    ) -> int | None:
        """Prefix-preserving replacement inside the same private block, or
        ``None`` when the network is the block itself (or wider)."""
        ns, value, attempt = seed
        blocks = _PRIVATE_BLOCKS_V4 if addr.version == 4 else _PRIVATE_BLOCKS_V6
        block = next(b for b in blocks if addr in b)
        if plen <= block.prefixlen:
            return None
        hbits = addr.max_prefixlen - block.prefixlen
        mask = (1 << hbits) - 1
        if attempt:  # collision fallback: non-prefix-preserving within block
            perm = int.from_bytes(self._digest(ns, "ip", value, attempt), "big") & mask
        else:
            perm = self._pp_bits(ns, str(block), int(host_part) & mask, hbits)
        return int(block.network_address) | perm

    def _fake_public(self, addr: Any, plen: int, seed: tuple[str, str, int]) -> int | None:
        """Random address in the benchmark / documentation pool, or ``None``
        when the network is wider than the pool."""
        ns, value, attempt = seed
        pool = _PUBLIC_V4_POOL if addr.version == 4 else _PUBLIC_V6_POOL
        if plen < pool.prefixlen:
            if not (addr.version == 4 and plen >= _WIDE_V4_POOL.prefixlen):
                return None
            pool = _WIDE_V4_POOL
        hbits = addr.max_prefixlen - pool.prefixlen
        rnd = int.from_bytes(self._digest(ns, "ip", value, attempt), "big")
        return int(pool.network_address) | (rnd & ((1 << hbits) - 1))


@functools.lru_cache(maxsize=65536)
def _parse_ip(value: str) -> tuple[Any, Any, int, bool] | None:
    """``(network or host address, host address, prefix length, is_net)``
    for an IP or CIDR string, ``None`` when invalid. Cached: the same
    addresses recur across a dataset."""
    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
            host_part = ipaddress.ip_address(value.split("/", 1)[0])
            return net.network_address, host_part, net.prefixlen, True
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    return addr, addr, addr.max_prefixlen, False
