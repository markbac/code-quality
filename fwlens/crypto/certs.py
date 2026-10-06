"""
Certificates and keys for the CBOM: files in the project (PEM, DER, keystores), PEM blocks and DER
byte arrays inside C source, with the certificate fields read from the DER itself (no third-party
parser), and the checks a reviewer would make: expiry, weak signature, small RSA key, and a
private key kept in the source tree.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

CERT_SUFFIXES = {".pem", ".crt", ".cer", ".der", ".key", ".csr", ".p7b", ".p7c", ".p12", ".pfx", ".jks", ".keystore"}
_KEYSTORE_SUFFIXES = {".p12", ".pfx", ".jks", ".keystore"}
MAX_FILE_BYTES = 2_000_000
MAX_FILES = 300
MAX_VISITED = 50_000            # files looked at, so a project root that is a whole drive does not stall the scan
PEM = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.DOTALL)
_CLEAN_BODY = re.compile(r'\\[nr]|["\s\\]')
_DER_ARRAY = re.compile(r"\b(\w+)\s*\[[^\]]*\]\s*=\s*\{([^{}]*)\}")
_HEX = re.compile(r"0[xX]([0-9a-fA-F]{1,2})\b")

_NAME_OIDS = {"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
              "2.5.4.5": "serialNumber", "1.2.840.113549.1.9.1": "emailAddress"}
_SIGNATURES = {
    "1.2.840.113549.1.1.4": ("md5WithRSAEncryption", "MD5 signature"),
    "1.2.840.113549.1.1.5": ("sha1WithRSAEncryption", "SHA-1 signature"),
    "1.2.840.113549.1.1.11": ("sha256WithRSAEncryption", ""), "1.2.840.113549.1.1.12": ("sha384WithRSAEncryption", ""),
    "1.2.840.113549.1.1.13": ("sha512WithRSAEncryption", ""), "1.2.840.113549.1.1.10": ("RSASSA-PSS", ""),
    "1.2.840.10045.4.1": ("ecdsa-with-SHA1", "SHA-1 signature"), "1.2.840.10045.4.3.1": ("ecdsa-with-SHA224", ""),
    "1.2.840.10045.4.3.2": ("ecdsa-with-SHA256", ""), "1.2.840.10045.4.3.3": ("ecdsa-with-SHA384", ""),
    "1.2.840.10045.4.3.4": ("ecdsa-with-SHA512", ""), "1.3.101.112": ("Ed25519", ""), "1.3.101.113": ("Ed448", ""),
}
_CURVES = {"1.2.840.10045.3.1.7": "secp256r1", "1.3.132.0.34": "secp384r1", "1.3.132.0.35": "secp521r1",
           "1.3.132.0.10": "secp256k1", "1.3.36.3.3.2.8.1.1.7": "brainpoolP256r1",
           "1.3.36.3.3.2.8.1.1.11": "brainpoolP384r1"}
_RSA = "1.2.840.113549.1.1.1"
_EC = "1.2.840.10045.2.1"


@dataclass
class Certificate:
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    signature: str
    signature_weak: str
    key: str                  # "RSA-2048", "EC secp256r1", "Ed25519"
    key_bits: int | None
    self_signed: bool


@dataclass
class Found:
    """One certificate, key or keystore, and where it was seen."""
    kind: str                 # certificate | private-key | public-key | csr | keystore | unknown-key
    where: str
    line: int | None
    source: str               # file | embedded
    name: str = ""
    certificate: Certificate | None = None
    problems: list[str] = field(default_factory=list)


# --- DER ---------------------------------------------------------------------------------------------------------

class _Der:
    def __init__(self, data: bytes):
        self.data = data

    def read(self, pos: int) -> tuple[int, int, int, int]:
        """(tag, start of content, end of content, end of element)"""
        if pos + 2 > len(self.data):
            raise ValueError("truncated")
        tag, first = self.data[pos], self.data[pos + 1]
        pos += 2
        if first < 0x80:
            length = first
        else:
            n = first & 0x7F
            if n == 0 or n > 4 or pos + n > len(self.data):
                raise ValueError("bad length")
            length = int.from_bytes(self.data[pos:pos + n], "big")
            pos += n
        end = pos + length
        if end > len(self.data):
            raise ValueError("truncated")
        return tag, pos, end, end

    def children(self, start: int, end: int) -> list[tuple[int, int, int]]:
        out, pos = [], start
        while pos < end:
            tag, s, e, nxt = self.read(pos)
            out.append((tag, s, e))
            pos = nxt
        return out


def _oid(data: bytes) -> str:
    if not data:
        return ""
    parts = [str(data[0] // 40), str(data[0] % 40)]
    value = 0
    for b in data[1:]:
        value = (value << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _time(tag: int, data: bytes) -> datetime:
    text = data.decode("ascii", errors="replace")
    if tag == 0x17:
        year = int(text[:2])
        text = ("19" if year >= 50 else "20") + text
    return datetime.strptime(text[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)


def _name(der: _Der, start: int, end: int) -> str:
    rdns = []
    for _, s, e in der.children(start, end):                           # each SET
        for _, s2, e2 in der.children(s, e):                           # each AttributeTypeAndValue
            items = der.children(s2, e2)
            if len(items) >= 2:
                key = _oid(der.data[items[0][1]:items[0][2]])
                value = der.data[items[1][1]:items[1][2]].decode("utf-8", errors="replace")
                rdns.append(f"{_NAME_OIDS.get(key, key)}={value}")
    return ", ".join(reversed(rdns))


def parse_certificate(data: bytes) -> Certificate:
    """Fields of an X.509 certificate in DER; raises ValueError when it is not one."""
    der = _Der(data)
    tag, s, e, _ = der.read(0)
    if tag != 0x30:
        raise ValueError("not a certificate")
    top = der.children(s, e)
    if len(top) < 3:
        raise ValueError("not a certificate")
    tbs = der.children(top[0][1], top[0][2])
    i = 1 if tbs and tbs[0][0] == 0xA0 else 0                           # skip the version
    if len(tbs) < i + 6:
        raise ValueError("not a certificate")
    sig_alg = der.children(tbs[i + 1][1], tbs[i + 1][2])
    sig_oid = _oid(der.data[sig_alg[0][1]:sig_alg[0][2]])
    sig_name, weak = _SIGNATURES.get(sig_oid, (sig_oid, ""))
    issuer_raw = der.data[tbs[i + 2][1]:tbs[i + 2][2]]
    subject_raw = der.data[tbs[i + 4][1]:tbs[i + 4][2]]
    validity = der.children(tbs[i + 3][1], tbs[i + 3][2])
    not_before = _time(validity[0][0], der.data[validity[0][1]:validity[0][2]])
    not_after = _time(validity[1][0], der.data[validity[1][1]:validity[1][2]])
    spki = der.children(tbs[i + 5][1], tbs[i + 5][2])
    alg = der.children(spki[0][1], spki[0][2])
    key_oid = _oid(der.data[alg[0][1]:alg[0][2]])
    bits: int | None = None
    if key_oid == _RSA:
        inner = _Der(der.data[spki[1][1] + 1:spki[1][2]])               # the BIT STRING's unused-bits byte comes first
        t, s2, e2, _ = inner.read(0)
        modulus = inner.children(s2, e2)[0]
        raw = inner.data[modulus[1]:modulus[2]].lstrip(b"\x00")
        bits = len(raw) * 8 - (8 - raw[0].bit_length()) if raw else None
        key = f"RSA-{bits}"
    elif key_oid == _EC:
        curve = _oid(der.data[alg[1][1]:alg[1][2]]) if len(alg) > 1 else ""
        key = f"EC {_CURVES.get(curve, curve)}"
    elif key_oid in ("1.3.101.112", "1.3.101.113"):
        key = _SIGNATURES[key_oid][0]
    else:
        key = key_oid
    return Certificate(_name(der, tbs[i + 4][1], tbs[i + 4][2]), _name(der, tbs[i + 2][1], tbs[i + 2][2]), not_before,
                       not_after, sig_name, weak, key, bits, issuer_raw == subject_raw)


def check_certificate(cert: Certificate, now: datetime, warn_days: int) -> list[str]:
    problems = []
    if cert.not_after < now:
        problems.append(f"certificate expired {cert.not_after.date().isoformat()}")
    elif cert.not_after < now + timedelta(days=warn_days):
        problems.append(f"certificate expires {cert.not_after.date().isoformat()}, within {warn_days} days")
    if cert.signature_weak:
        problems.append(f"{cert.signature_weak} ({cert.signature})")
    if cert.key_bits is not None and cert.key.startswith("RSA") and cert.key_bits < 2048:
        problems.append(f"{cert.key} key is below 2048 bits")
    return problems


# --- finding them ------------------------------------------------------------------------------------------------

def _decode_body(body: str) -> bytes | None:
    try:
        return base64.b64decode(_CLEAN_BODY.sub("", body), validate=False)
    except (binascii.Error, ValueError):
        return None


def _from_pem(label: str, body: str, where: str, line: int | None, source: str, now: datetime, warn_days: int) -> Found:
    label = label.upper()
    if "PRIVATE KEY" in label:
        found = Found("private-key", where, line, source, label.title())
        found.problems.append("a private key is stored in the source tree" if source == "file"
                              else "a private key is embedded in source code")
        return found
    if "PUBLIC KEY" in label:
        return Found("public-key", where, line, source, label.title())
    if "CERTIFICATE REQUEST" in label:
        return Found("csr", where, line, source, "Certificate request")
    if "CERTIFICATE" in label:
        found = Found("certificate", where, line, source)
        data = _decode_body(body)
        try:
            found.certificate = parse_certificate(data) if data else None
        except (ValueError, IndexError):
            found.certificate = None
        if found.certificate:
            found.name = found.certificate.subject
            found.problems = check_certificate(found.certificate, now, warn_days)
        else:
            found.name = "Certificate (unreadable)"
        return found
    return Found("unknown-key", where, line, source, label.title())


def scan_text(text: str, where: str, source: str, now: datetime, warn_days: int) -> list[Found]:
    """PEM blocks in a text file or C source, and DER certificates written as byte arrays."""
    out = []
    for m in PEM.finditer(text):
        out.append(_from_pem(m.group(1), m.group(2), where, text.count("\n", 0, m.start()) + 1, source, now, warn_days))
    if source == "embedded":
        for m in _DER_ARRAY.finditer(text):
            digits = _HEX.findall(m.group(2))
            if len(digits) < 150 or digits[0].lower() != "30":
                continue
            try:
                cert = parse_certificate(bytes(int(d, 16) for d in digits))
            except (ValueError, IndexError):
                continue
            found = Found("certificate", where, text.count("\n", 0, m.start()) + 1, source, cert.subject or m.group(1), cert)
            found.problems = check_certificate(cert, now, warn_days)
            out.append(found)
    return out


def scan_file(path: Path, where: str, now: datetime, warn_days: int) -> list[Found]:
    suffix = path.suffix.lower()
    try:
        data = path.read_bytes()
    except OSError:
        return []
    if suffix in _KEYSTORE_SUFFIXES:
        return [Found("keystore", where, None, "file", f"Keystore ({suffix[1:]})",
                      problems=["a keystore file is stored in the source tree"])]
    if b"-----BEGIN" in data:
        return scan_text(data.decode("utf-8", errors="replace"), where, "file", now, warn_days)
    if data[:1] == b"\x30":
        try:
            cert = parse_certificate(data)
        except (ValueError, IndexError):
            return [Found("unknown-key", where, None, "file", f"DER data ({suffix[1:]})")] if suffix == ".key" else []
        found = Found("certificate", where, None, "file", cert.subject or path.name, cert)
        found.problems = check_certificate(cert, now, warn_days)
        return [found]
    return []


def find_files(root: Path, skip_dirs: set[str], allowed) -> list[Path]:
    """Certificate-like files under the project root. `allowed(path)` drops files outside the scanned scopes."""
    found: list[Path] = []
    visited = 0
    for base, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in skip_dirs and not d.startswith("."))
        visited += len(files)
        if visited > MAX_VISITED:
            break
        for name in sorted(files):
            path = Path(base, name)
            if path.suffix.lower() in CERT_SUFFIXES and allowed(path):
                try:
                    if path.stat().st_size <= MAX_FILE_BYTES:
                        found.append(path)
                except OSError:
                    continue
            if len(found) >= MAX_FILES:
                return found
    return found
