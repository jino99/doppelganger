#!/usr/bin/env python3
"""
doppelganger — typosquat permutation scanner with TLS classification.

Generates algorithmic permutations of a domain (bitsquatting, homoglyphs,
omission, addition, replacement, repetition, transposition, vowel-swap,
hyphenation, combosquatting, subdomain insertion, country prefix, partial
and full leetspeak, dash removal, TLD swap, homoglyph+TLD-swap combo),
resolves each (A/AAAA/MX/SOA), probes :443, and classifies hits as
phishing, trusted TLS, untrusted TLS, active-no-HTTPS, mail-only,
registered, or self-subdomain (target-owned).

Zero external dependencies. Python 3.8+, standard library only.

Usage
  doppelganger example.com
  doppelganger example.com --json
  doppelganger example.com --only-suspicious
  doppelganger example.com -p
  doppelganger example.com -p --interval 900 -s state.json

Notes
  SOA rname is not cryptographically signed; a deliberate attacker who
  controls their own zone can set it to match the target. IP-subset and
  certificate-brand signals are not spoofable and remain authoritative.
  Some ISPs filter malicious domains at the resolver level — use
  `-r 1.1.1.1` or `-r 8.8.8.8` for unfiltered results.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import datetime as dt
import ipaddress
import json
import os
import re
import secrets
import signal
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time

EXAMPLES = """\
examples:
  doppelganger example.com
  doppelganger example.com --json
  doppelganger example.com --no-tls
  doppelganger example.com --only-suspicious
  doppelganger example.com -p
  doppelganger example.com -p --interval 900 -s doppelganger-example.com.json
  doppelganger example.com -r 1.1.1.1,8.8.8.8 --dns-timeout 2 --tls-timeout 8

persistent mode (-p):
  first cycle writes a baseline to the state file, nothing is printed;
  subsequent cycles print only NEW findings to stdout (human or JSONL
  with --json). The state file is written atomically each cycle.

exit codes:
  0 success   2 usage/config/state error   130 interrupted
"""

QUIET = False


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> dt.datetime:
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def log(msg: str) -> None:
    if not QUIET:
        sys.stderr.write(msg + "\n")
        sys.stderr.flush()


def log_error(msg: str) -> None:
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


# =============================================================================
# DNS client (RFC 1035 wire format, EDNS0 per RFC 6891, TCP fallback)
# =============================================================================
QTYPE = {"A": 1, "NS": 2, "SOA": 6, "MX": 15, "AAAA": 28}
QTYPE_REV = {v: k for k, v in QTYPE.items()}
RCODE_FORMERR, RCODE_SERVFAIL, RCODE_NXDOMAIN, RCODE_NOTIMP, RCODE_REFUSED = 1, 2, 3, 4, 5

Record = collections.namedtuple("Record", "name rtype ttl value")
Message = collections.namedtuple("Message", "id qr tc rcode questions answers")
Answer = collections.namedtuple("Answer", "rcode records")

FALLBACK_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


class DNSError(Exception):
    pass


def encode_name(name: str) -> bytes:
    out = bytearray()
    name = name.rstrip(".")
    if name:
        for label in name.split("."):
            try:
                raw = label.encode("ascii")
            except UnicodeEncodeError:
                raise DNSError("non-ASCII label: %r" % label)
            if not 0 < len(raw) <= 63:
                raise DNSError("invalid label length: %r" % label)
            out.append(len(raw))
            out += raw
    out.append(0)
    if len(out) > 255:
        raise DNSError("name too long")
    return bytes(out)


def build_query(name: str, qtype: int, qid: int, edns: bool = True) -> bytes:
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 1 if edns else 0)
    packet = header + encode_name(name) + struct.pack("!HH", qtype, 1)
    if edns:
        packet += struct.pack("!BHHIH", 0, 41, 1232, 0, 0)
    return packet


def read_name(msg: bytes, off: int):
    labels, end, hops = [], None, 0
    while True:
        if off >= len(msg):
            raise DNSError("name runs past end")
        ln = msg[off]
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                raise DNSError("truncated compression pointer")
            if end is None:
                end = off + 2
            off = ((ln & 0x3F) << 8) | msg[off + 1]
            hops += 1
            if hops > 40:
                raise DNSError("compression loop")
        elif ln == 0:
            if end is None:
                end = off + 1
            break
        elif ln & 0xC0:
            raise DNSError("unsupported label type")
        else:
            off += 1
            if off + ln > len(msg):
                raise DNSError("label overrun")
            labels.append(msg[off:off + ln].decode("latin-1"))
            off += ln
    return ".".join(labels).lower(), end


def _decode_rdata(msg: bytes, rtype: int, off: int, ln: int):
    if rtype == 1:
        return socket.inet_ntoa(msg[off:off + 4]) if ln == 4 else None
    if rtype == 28:
        return ipaddress.IPv6Address(msg[off:off + 16]).compressed if ln == 16 else None
    if rtype == 15:
        pref = struct.unpack_from("!H", msg, off)[0]
        host, _ = read_name(msg, off + 2)
        return "%d %s" % (pref, host)
    if rtype == 6:
        mname, p = read_name(msg, off)
        rname, _ = read_name(msg, p)
        return "%s %s" % (mname, rname)
    return None


def parse_message(data: bytes) -> Message:
    try:
        if len(data) < 12:
            raise DNSError("short message")
        mid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
        off, questions, answers = 12, [], []
        for _ in range(qd):
            name, off = read_name(data, off)
            qt, _qc = struct.unpack_from("!HH", data, off)
            off += 4
            questions.append((name, qt))
        for _ in range(an):
            name, off = read_name(data, off)
            rtype, _rc, ttl, rdlen = struct.unpack_from("!HHIH", data, off)
            off += 10
            if off + rdlen > len(data):
                raise DNSError("rdata overrun")
            val = _decode_rdata(data, rtype, off, rdlen)
            if val is not None and rtype in QTYPE_REV:
                answers.append(Record(name, QTYPE_REV[rtype], ttl, val))
            off += rdlen
        return Message(mid, bool(flags & 0x8000), bool(flags & 0x0200),
                       flags & 0xF, questions, answers)
    except (struct.error, IndexError, ValueError) as exc:
        raise DNSError("malformed DNS message: %s" % exc)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise DNSError("connection closed")
        buf += chunk
    return buf


class Resolver:
    """Thread-safe stub resolver talking to recursive resolvers over UDP/TCP."""

    def __init__(self, servers, timeout: float):
        self.servers = list(servers)
        self.timeout = timeout
        self._cache = {}
        self._lock = threading.Lock()
        self._rr = 0

    @staticmethod
    def _family(server: str):
        return socket.AF_INET6 if ":" in server else socket.AF_INET

    def _udp(self, server, packet, qid):
        s = socket.socket(self._family(server), socket.SOCK_DGRAM)
        try:
            s.settimeout(self.timeout)
            s.connect((server, 53))
            s.send(packet)
            deadline = time.monotonic() + self.timeout
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise socket.timeout("timed out")
                s.settimeout(left)
                msg = parse_message(s.recv(65535))
                if msg.id == qid and msg.qr:
                    return msg
        finally:
            s.close()

    def _tcp(self, server, packet, qid):
        with socket.socket(self._family(server), socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            s.connect((server, 53))
            s.sendall(struct.pack("!H", len(packet)) + packet)
            ln = struct.unpack("!H", _recv_exact(s, 2))[0]
            msg = parse_message(_recv_exact(s, ln))
        if msg.id != qid:
            raise DNSError("TCP response id mismatch")
        return msg

    def query(self, name: str, rtype: str) -> Answer:
        name = name.lower().rstrip(".")
        key = (name, rtype)
        with self._lock:
            hit = self._cache.get(key)
            start = self._rr
            self._rr += 1
        if hit is not None:
            return hit
        qtype, last, edns = QTYPE[rtype], None, True
        for attempt in range(max(3, len(self.servers))):
            server = self.servers[(start + attempt) % len(self.servers)]
            qid = secrets.randbits(16)
            packet = build_query(name, qtype, qid, edns)
            try:
                msg = self._udp(server, packet, qid)
                if msg.tc:
                    msg = self._tcp(server, packet, qid)
            except (OSError, DNSError) as exc:
                last = "%s: %s" % (server, exc)
                continue
            if msg.questions and msg.questions[0] != (name, qtype):
                last = "%s: question mismatch" % server
                continue
            if msg.rcode == RCODE_FORMERR and edns:
                edns = False
                last = "%s: FORMERR" % server
                continue
            if msg.rcode in (RCODE_SERVFAIL, RCODE_REFUSED, RCODE_NOTIMP, RCODE_FORMERR):
                last = "%s: rcode %d" % (server, msg.rcode)
                continue
            ans = Answer(msg.rcode, msg.answers)
            with self._lock:
                self._cache[key] = ans
            return ans
        raise DNSError("%s %s failed (%s)" % (name, rtype, last))

    def flush_cache(self):
        with self._lock:
            self._cache.clear()


def system_resolvers():
    found = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                p = line.split()
                if len(p) >= 2 and p[0] == "nameserver":
                    addr = p[1].split("%")[0]
                    try:
                        ipaddress.ip_address(addr)
                    except ValueError:
                        continue
                    if not addr.lower().startswith("fe80"):
                        found.append(addr)
    except OSError:
        pass
    return found or list(FALLBACK_RESOLVERS)


def lookup(resolver: Resolver, name: str, rtype: str):
    """Returns (status, values) where status is 'ok', 'nxdomain' or 'error'."""
    try:
        ans = resolver.query(name, rtype)
    except DNSError:
        return "error", []
    vals = [r.value for r in ans.records if r.rtype == rtype]
    return ("nxdomain" if ans.rcode == RCODE_NXDOMAIN else "ok"), vals


# =============================================================================
# Domain validation
# =============================================================================
LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def to_ascii_domain(domain: str) -> str:
    d = domain.strip().lower()
    if "://" in d:
        d = d.split("://", 1)[1]
    for sep in ("/", "?", "#"):
        if sep in d:
            d = d.split(sep, 1)[0]
    if ":" in d:
        d = d.split(":", 1)[0]
    d = d.rstrip(".")
    if not d:
        raise ValueError("empty domain")
    labels = []
    for lab in d.split("."):
        try:
            lab = lab.encode("idna").decode("ascii") if not lab.isascii() else lab
        except UnicodeError:
            raise ValueError("invalid domain: %r" % domain)
        labels.append(lab)
    if len(labels) < 2:
        raise ValueError("domain must have at least two labels (e.g. example.com)")
    if not all(LABEL_RE.match(x) for x in labels):
        raise ValueError("invalid domain: %r" % domain)
    if len(".".join(labels)) > 253:
        raise ValueError("domain too long: %r" % domain)
    return ".".join(labels)


# =============================================================================
# Permutation engine
# =============================================================================
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne",
                "go", "gob", "mil", "ltd", "plc", "sch", "gv"}

COMMON_TLDS = ["com", "net", "org", "co", "io", "info", "biz", "xyz", "app",
               "online", "site", "top", "cc", "cm", "om",
               "us", "uk", "de", "fr", "it", "nl", "se", "ru", "cn", "in",
               "me", "tv", "co.uk", "com.au", "co.jp", "com.br"]

# Only the most likely TLDs are used when combining homoglyphs with a TLD
# swap — using all COMMON_TLDS would blow up the permutation count.
COMBO_TLDS = ["com", "net", "org", "co", "io"]

COMBO_WORDS = ["app", "login", "portal", "mail", "secure", "support",
               "account", "online", "web", "my", "pay", "billing", "verify",
               "help", "service", "auth", "sso", "vpn", "admin",
               "www", "get", "go", "the", "official"]

SUBDOMAIN_INSERTION_WORDS = ["login", "secure", "auth", "account", "admin",
                             "portal", "mail", "sso", "signin", "webmail",
                             "support", "help", "verify", "pay", "billing",
                             "cloud", "office", "vpn", "remote", "docs"]

COUNTRY_PREFIXES = ["us", "uk", "de", "fr", "it", "eu", "ca", "au", "jp",
                    "cn", "ru"]

LEET_MAP = {"a": "4", "b": "8", "e": "3", "g": "9", "i": "1", "l": "1",
            "o": "0", "s": "5", "t": "7", "z": "2"}

FULL_HOMOGLYPH_MAP = {
    "a": "а", "c": "с", "e": "е", "h": "һ", "i": "і", "j": "ј",
    "k": "к", "l": "ӏ", "m": "м", "o": "о", "p": "р", "s": "ѕ",
    "x": "х", "y": "у",
}

_U = lambda *cps: [chr(c) for c in cps]  # noqa: E731
HOMOGLYPHS = {
    "o": ["0"] + _U(0x043E, 0x03BF, 0x00F3, 0x00F6, 0x00F2, 0x00F4, 0x0151),
    "l": ["1", "i"] + _U(0x04CF),
    "i": ["1", "l"] + _U(0x0456, 0x00ED, 0x00EF, 0x0131),
    "m": ["rn", "nn"], "w": ["vv"] + _U(0x051D, 0x0175),
    "d": ["cl"] + _U(0x0501, 0x010F),
    "rn": ["m"], "vv": ["w"], "cl": ["d"],
    "g": ["q"] + _U(0x0261, 0x0121), "q": ["g"] + _U(0x051B),
    "u": ["v"] + _U(0x00FC, 0x00FA, 0x03C5),
    "v": ["u"] + _U(0x03BD),
    "s": ["5"] + _U(0x0455, 0x015B, 0x0161), "b": ["6"],
    "z": ["2"] + _U(0x017A, 0x017C, 0x017E),
    "a": _U(0x0430, 0x00E0, 0x00E1, 0x00E2, 0x00E4, 0x0105, 0x0251),
    "c": _U(0x0441, 0x00E7, 0x0107, 0x010D),
    "e": ["3"] + _U(0x0435, 0x00E9, 0x00E8, 0x00EA, 0x00EB, 0x0119, 0x0117),
    "h": _U(0x04BB, 0x0125), "j": _U(0x0458), "k": _U(0x043A, 0x0137),
    "n": _U(0x00F1, 0x0144, 0x0578), "p": _U(0x0440), "t": ["7"] + _U(0x0165),
    "x": _U(0x0445), "y": _U(0x0443, 0x00FD, 0x00FF),
}

_KB_ROWS = ["1234567890-", "qwertyuiop", "asdfghjkl", "zxcvbnm"]


def _build_neighbors():
    nb = collections.defaultdict(set)
    for r, row in enumerate(_KB_ROWS):
        for c, ch in enumerate(row):
            if c > 0:
                nb[ch].add(row[c - 1])
            if c < len(row) - 1:
                nb[ch].add(row[c + 1])
            if r > 0:
                for cc in (c, c + 1):
                    if 0 <= cc < len(_KB_ROWS[r - 1]):
                        nb[ch].add(_KB_ROWS[r - 1][cc])
            if r < len(_KB_ROWS) - 1:
                for cc in (c - 1, c):
                    if 0 <= cc < len(_KB_ROWS[r + 1]):
                        nb[ch].add(_KB_ROWS[r + 1][cc])
    return {k: sorted(v) for k, v in nb.items()}


KB_NEIGHBORS = _build_neighbors()


def _split_domain(domain: str):
    labels = domain.split(".")
    n = 2 if (len(labels) >= 3 and len(labels[-1]) == 2
              and labels[-2] in SECOND_LEVEL) else 1
    return labels[:-n - 1], labels[-n - 1], labels[-n:]


def _valid_label(lab: str) -> bool:
    if not 0 < len(lab) <= 63 or lab.startswith("-") or lab.endswith("-"):
        return False
    return not (lab[2:4] == "--" and not lab.startswith("xn--"))


def _mixed_script(cand: str) -> bool:
    has_latin = any("a" <= c.lower() <= "z" for c in cand)
    has_nonascii = any(ord(c) > 127 for c in cand)
    return has_latin and has_nonascii


def generate_permutations(domain: str):
    """Return {ascii_domain: {"kinds": [...], "unicode": str|None,
    "mixed_script": bool}}."""
    prefix, label, suffix = _split_domain(domain)
    try:
        name = label.encode("ascii").decode("idna") if label.startswith("xn--") else label
    except UnicodeError:
        name = label

    found = {}

    def _store(full, kind, unicode_form=None, mixed=False):
        entry = found.setdefault(full, {"kinds": [], "unicode": None,
                                        "mixed_script": False})
        if kind not in entry["kinds"]:
            entry["kinds"].append(kind)
        if unicode_form:
            entry["unicode"] = unicode_form
        if mixed:
            entry["mixed_script"] = True

    def add(kind, cand, new_suffix=None, subdomain_prefix=None):
        if not cand:
            return
        if cand == name and new_suffix is None and subdomain_prefix is None:
            return
        try:
            ascii_label = cand if cand.isascii() else cand.encode("idna").decode("ascii")
        except UnicodeError:
            return
        if not _valid_label(ascii_label) or not LABEL_RE.match(ascii_label):
            return
        parts = list(prefix)
        if subdomain_prefix:
            if not _valid_label(subdomain_prefix):
                return
            parts.append(subdomain_prefix)
        parts.append(ascii_label)
        parts.extend(new_suffix or suffix)
        full = ".".join(parts)
        if full == domain or len(full) > 253:
            return

        unicode_form = None
        mixed = False
        if not cand.isascii():
            uparts = list(prefix)
            if subdomain_prefix:
                uparts.append(subdomain_prefix)
            uparts.append(cand)
            uparts.extend(new_suffix or suffix)
            unicode_form = ".".join(uparts)
            mixed = _mixed_script(cand)

        _store(full, kind, unicode_form, mixed)

        # Homoglyph combined with TLD swap (limited to top TLDs)
        if kind in ("homoglyph", "homoglyph-full") and new_suffix is None and not subdomain_prefix:
            for tld in COMBO_TLDS:
                if [tld] == suffix:
                    continue
                parts_tld = list(prefix) + [ascii_label] + [tld]
                full_tld = ".".join(parts_tld)
                if full_tld == domain or len(full_tld) > 253:
                    continue
                unicode_tld = None
                mixed_tld = False
                if not cand.isascii():
                    unicode_tld = ".".join(list(prefix) + [cand] + [tld])
                    mixed_tld = _mixed_script(cand)
                _store(full_tld, "homoglyph-tld-swap", unicode_tld, mixed_tld)

    n = len(name)
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-")

    for i, ch in enumerate(name):
        if ord(ch) < 128:
            for bit in range(8):
                flipped = chr(ord(ch) ^ (1 << bit))
                if flipped in allowed:
                    add("bitsquatting", name[:i] + flipped + name[i + 1:])

    for src, reps in HOMOGLYPHS.items():
        if len(src) != 1:
            continue
        start = name.find(src)
        while start != -1:
            for rep in reps:
                add("homoglyph", name[:start] + rep + name[start + len(src):])
            start = name.find(src, start + 1)

    for src in ("m", "w", "d", "rn", "vv", "cl"):
        for rep in HOMOGLYPHS.get(src, []):
            start = name.find(src)
            while start != -1:
                add("homoglyph", name[:start] + rep + name[start + len(src):])
                start = name.find(src, start + 1)

    for i in range(n):
        add("omission", name[:i] + name[i + 1:])
    for i, ch in enumerate(name):
        for nb in KB_NEIGHBORS.get(ch, []):
            add("addition", name[:i] + nb + name[i:])
            add("addition", name[:i + 1] + nb + name[i + 1:])
            add("replacement", name[:i] + nb + name[i + 1:])
    for i, ch in enumerate(name):
        add("repetition", name[:i] + ch + name[i:])
    for i in range(n - 1):
        if name[i] != name[i + 1]:
            add("transposition", name[:i] + name[i + 1] + name[i] + name[i + 2:])
    for i, ch in enumerate(name):
        if ch in "aeiou":
            for v in "aeiou":
                if v != ch:
                    add("vowel-swap", name[:i] + v + name[i + 1:])
    for i in range(1, n):
        add("hyphenation", name[:i] + "-" + name[i:])

    for w in COMBO_WORDS:
        for cand in (name + "-" + w, w + "-" + name, name + w, w + name):
            add("combosquatting", cand)

    for c in COUNTRY_PREFIXES:
        add("country-prefix", c + "-" + name)

    for i, ch in enumerate(name):
        if ch in LEET_MAP:
            add("partial-leetspeak", name[:i] + LEET_MAP[ch] + name[i + 1:])

    leet = "".join(LEET_MAP.get(ch, ch) for ch in name)
    if leet != name:
        add("leetspeak", leet)

    homo = "".join(FULL_HOMOGLYPH_MAP.get(ch, ch) for ch in name)
    if homo != name:
        add("homoglyph-full", homo)

    if "-" in name:
        add("dash-removal", name.replace("-", ""))
        for i, ch in enumerate(name):
            if ch == "-":
                add("dash-removal", name[:i] + name[i + 1:])

    for tld in COMMON_TLDS:
        tld_labels = tld.split(".")
        if tld_labels != suffix:
            add("tld-swap", name, tld_labels)

    if not prefix:
        for w in SUBDOMAIN_INSERTION_WORDS:
            add("subdomain-insert", name, subdomain_prefix=w)

    for entry in found.values():
        entry["kinds"].sort()
    return dict(sorted(found.items()))


# =============================================================================
# TLS probe
# =============================================================================
def _extract_names(cert: dict):
    sans = []
    for typ, val in cert.get("subjectAltName", ()):
        if typ == "DNS":
            sans.append(val.lower().rstrip("."))
    cn = None
    for rdn in cert.get("subject", ()):
        for k, v in rdn:
            if k == "commonName":
                cn = v
                break
        if cn:
            break
    issuer_cn = None
    for rdn in cert.get("issuer", ()):
        for k, v in rdn:
            if k == "commonName":
                issuer_cn = v
                break
        if issuer_cn:
            break
    return sans, cn, issuer_cn


def _cert_signal(sans, cn, original: str):
    orig = original.lower().rstrip(".")
    names = [n.lower().rstrip(".") for n in (list(sans) + ([cn] if cn else [])) if n]
    for n in names:
        if n == orig or n.endswith("." + orig):
            return "covers"
    orig_labels = orig.split(".")
    n_lbl = len(orig_labels)
    for n in names:
        labels = n.split(".")
        for i in range(len(labels) - n_lbl + 1):
            if labels[i:i + n_lbl] == orig_labels:
                return "mentions"
    return None


def _build_tls_info(cert: dict, original: str):
    sans, cn, issuer_cn = _extract_names(cert)
    return {
        "trusted": True,
        "cn": cn,
        "issuer_cn": issuer_cn,
        "not_after": cert.get("notAfter"),
        "sans": sans,
        "signal": _cert_signal(sans, cn, original),
    }


def quick_tls(host: str, ips, timeout: float, original: str):
    """Probe :443 with SNI=host. Returns dict or None."""
    untrusted_found = False
    for ip in ips[:3]:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((ip, 443), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    cert = tls.getpeercert()
            if not cert:
                continue
            return _build_tls_info(cert, original)
        except ssl.SSLCertVerificationError:
            untrusted_found = True
        except (ssl.SSLError, OSError, ValueError):
            pass
    if untrusted_found:
        return {"trusted": False}
    return None


# =============================================================================
# Probe
# =============================================================================
def probe(name: str, resolver: Resolver, original: str, do_tls: bool,
          tls_timeout: float, is_subdomain: bool = False):
    """Resolve a permutation. Returns (status, entry) or ('inactive'|'error', None)."""
    try:
        if not is_subdomain:
            s_ns, ns = lookup(resolver, name, "NS")
            if s_ns == "error":
                return "error", None
            if s_ns == "nxdomain":
                return "inactive", None
            if not ns:
                # NOERROR + empty NS on apex is unusual; confirm via A.
                s_a0, a0 = lookup(resolver, name, "A")
                if s_a0 == "error":
                    return "error", None
                if s_a0 == "nxdomain" or not a0:
                    return "inactive", None

        s_a, a = lookup(resolver, name, "A")
        s_aaaa, aaaa = lookup(resolver, name, "AAAA")
        s_mx, mx = lookup(resolver, name, "MX")
    except Exception:
        return "error", None
    if "error" in (s_a, s_aaaa, s_mx):
        return "error", None

    a = sorted(set(a))
    aaaa = sorted(set(aaaa))
    mx = sorted(set(mx))

    if not (a or aaaa or mx):
        return "inactive", None

    entry = {"a": a, "aaaa": aaaa, "mx": mx, "tls": None, "soa": None}

    # SOA ownership signal — apex only; the zone's SOA rname reveals whether
    # the zone lives under the target's administrative control.
    if not is_subdomain:
        try:
            s_soa, soa = lookup(resolver, name, "SOA")
            if s_soa == "ok" and soa:
                entry["soa"] = soa[0]
        except Exception:
            pass

    if do_tls and (a or aaaa):
        try:
            entry["tls"] = quick_tls(name, a + aaaa, tls_timeout, original)
        except Exception:
            entry["tls"] = None
    return "resolved", entry


def _soa_owned(soa_value, original: str) -> bool:
    """True when the zone's SOA rname is inside the target's zone."""
    if not soa_value:
        return False
    parts = soa_value.split(" ", 1)
    if len(parts) != 2:
        return False
    rname = parts[1].rstrip(".").lower()
    orig = original.lower().rstrip(".")
    return rname == orig or rname.endswith("." + orig)


def classify(entry: dict, kinds, target_ips, tls_checked: bool, original: str):
    if _soa_owned(entry.get("soa"), original):
        return "self_subdomain"

    if "subdomain-insert" in kinds and target_ips:
        perm_ips = set(entry.get("a", [])) | set(entry.get("aaaa", []))
        if perm_ips and perm_ips <= target_ips:
            return "self_subdomain"

    has_a = bool(entry.get("a") or entry.get("aaaa"))
    has_mx = bool(entry.get("mx"))
    tls = entry.get("tls")

    if has_a:
        if not tls_checked:
            return "active"
        if tls is None:
            return "active_no_https"
        if not tls.get("trusted"):
            return "untrusted_tls"
        if tls.get("signal"):
            # A trusted cert carrying the target's brand on a structural
            # permutation (subdomain-insert, tld-swap) is proof of ownership:
            # only the target can pass CA validation for those SANs.
            if "subdomain-insert" in kinds or "tld-swap" in kinds:
                return "self_subdomain"
            return "phishing"
        return "trusted_tls"
    if has_mx:
        return "mail_only"
    return "registered"


# =============================================================================
# Scan
# =============================================================================
def scan_once(domain: str, opts):
    perms = generate_permutations(domain)
    total = len(perms)
    findings = {}
    counts = collections.Counter()
    t0 = time.monotonic()

    target_ips = set()
    try:
        _, t_a = lookup(opts.resolver, domain, "A")
        _, t_aaaa = lookup(opts.resolver, domain, "AAAA")
        target_ips = set(t_a) | set(t_aaaa)
    except Exception:
        pass

    def work(item):
        name, meta = item
        is_sub = "subdomain-insert" in meta["kinds"]
        try:
            status, entry = probe(name, opts.resolver, domain, opts.tls,
                                  opts.tls_timeout, is_subdomain=is_sub)
        except Exception:
            return name, "error", None, meta
        return name, status, entry, meta

    with concurrent.futures.ThreadPoolExecutor(max_workers=opts.workers) as pool:
        for name, status, entry, meta in pool.map(work, perms.items()):
            if status == "error":
                counts["errors"] += 1
                continue
            if status != "resolved":
                counts["inactive"] += 1
                continue
            cls = classify(entry, meta["kinds"], target_ips, opts.tls, domain)
            entry["status"] = cls
            entry["kinds"] = meta["kinds"]
            if meta.get("unicode"):
                entry["unicode"] = meta["unicode"]
            if meta.get("mixed_script"):
                entry["mixed_script"] = True
            findings[name] = entry
            counts[cls] += 1

    counts["generated"] = total
    counts["duration_seconds"] = round(time.monotonic() - t0, 2)
    return findings, dict(counts)


def _log_diagnostics(stats):
    """Emit a hint on stderr when the error rate suggests network trouble."""
    errors = stats.get("errors", 0)
    total = stats.get("generated", 0)
    if total and errors > max(3, total * 0.05):
        pct = 100 * errors // total
        log("[!] %d/%d lookups failed (%d%%). Try --workers 8, "
            "--dns-timeout 2 --tls-timeout 8, or add resolvers with "
            "-r 1.1.1.1,8.8.8.8" % (errors, total, pct))


# =============================================================================
# Reporting
# =============================================================================
STATUS_LABELS = {
    "phishing":         "[!] PHISHING — trusted cert mentions target brand",
    "trusted_tls":      "[+] ACTIVE — trusted TLS",
    "untrusted_tls":    "[+] ACTIVE — untrusted TLS",
    "active":           "[+] ACTIVE — TLS not checked",
    "active_no_https":  "[+] ACTIVE — no HTTPS on :443",
    "mail_only":        "[~] MAIL ONLY (MX record)",
    "registered":       "[~] REGISTERED — no records",
    "self_subdomain":   "[i] SELF-SUBDOMAIN — resolves to your own infra",
}

STATUS_ORDER = ["phishing", "trusted_tls", "untrusted_tls", "active",
                "active_no_https", "mail_only", "registered", "self_subdomain"]

# Display order in --only-suspicious mode: critical untrusted-TLS typosquats
# (broken cert, likely active attack) are surfaced before trusted-TLS
# typosquats (valid cert, often parked/registered-for-sale).
SUSPICIOUS_ORDER = ["phishing", "untrusted_tls", "trusted_tls",
                    "active", "active_no_https", "mail_only"]

STATUS_DISPLAY = {
    "phishing": "phishing",
    "trusted_tls": "trusted-tls",
    "untrusted_tls": "untrusted-tls",
    "active": "active",
    "active_no_https": "active-no-https",
    "mail_only": "mail-only",
    "registered": "registered",
    "self_subdomain": "self-subdomain",
}

# Ranking used to sort the trusted/untrusted TLS buckets from
# "most likely targeted attack" to "most likely benign registration".
_KIND_SUSPICION = {
    "homoglyph": 0, "homoglyph-full": 0, "homoglyph-tld-swap": 0,
    "leetspeak": 1, "partial-leetspeak": 1,
    "bitsquatting": 2,
    "transposition": 3, "omission": 3, "addition": 3,
    "replacement": 3, "repetition": 3, "vowel-swap": 3,
    "combosquatting": 4,
    "hyphenation": 5, "dash-removal": 5,
    "country-prefix": 6,
    "tld-swap": 7, "subdomain-insert": 7,
}

# Kinds at or below this rank are "suspicious" for --only-suspicious:
# homoglyph, leet, bitsquat, and single-char typos.
SUSPICION_THRESHOLD = 3


def _rank(e: dict) -> int:
    kinds = e.get("kinds", [])
    return min((_KIND_SUSPICION.get(k, 50) for k in kinds), default=50)


def _sort_key(item):
    name, e = item
    return (_rank(e), name)


def _is_suspicious(e: dict) -> bool:
    status = e.get("status")
    if status in ("phishing", "untrusted_tls"):
        return True
    if status in ("self_subdomain", "registered"):
        return False
    return _rank(e) <= SUSPICION_THRESHOLD


def _tls_summary(tls):
    if not tls or not tls.get("trusted"):
        return "untrusted"
    parts = ["trusted"]
    if tls.get("issuer_cn"):
        parts.append("issuer=" + tls["issuer_cn"])
    sig = tls.get("signal")
    if sig == "covers":
        parts.append("COVERS-TARGET")
    elif sig == "mentions":
        parts.append("MENTIONS-TARGET")
    return " ".join(parts)


def _dns_summary(entry):
    bits = []
    if entry.get("a"):
        bits.append("a=" + ",".join(entry["a"]))
    if entry.get("aaaa"):
        bits.append("aaaa=" + ",".join(entry["aaaa"]))
    if entry.get("mx"):
        bits.append("mx=" + ",".join(entry["mx"]))
    return " ".join(bits)


def _badges(entry):
    badges = []
    if entry.get("mixed_script"):
        badges.append("MIXED-SCRIPT")
    if entry.get("unicode"):
        badges.append("IDN:" + entry["unicode"])
    return " [" + ",".join(badges) + "]" if badges else ""


def _format_line(name: str, e: dict) -> str:
    kinds = "/".join(e.get("kinds", [])) or "-"
    if e.get("status") in ("phishing", "trusted_tls", "untrusted_tls") and e.get("tls"):
        detail = _tls_summary(e["tls"])
    else:
        detail = _dns_summary(e)
    return "  %-42s %-18s %s%s" % (name, kinds, detail, _badges(e))


def render_human(domain: str, findings: dict, stats: dict,
                 only_suspicious: bool = False) -> str:
    resolved = stats["generated"] - stats.get("inactive", 0) - stats.get("errors", 0)
    note = " (showing only suspicious)" if only_suspicious else ""
    lines = [
        "doppelganger — permutation scan of %s" % domain,
        "[*] %d permutations generated, %d resolved in %.2fs%s" % (
            stats["generated"], resolved, stats.get("duration_seconds", 0.0), note),
        "",
    ]

    buckets = collections.defaultdict(list)
    for name, e in findings.items():
        if only_suspicious and not _is_suspicious(e):
            continue
        buckets[e.get("status", "registered")].append((name, e))

    order = SUSPICIOUS_ORDER if only_suspicious else STATUS_ORDER
    for status in order:
        items = buckets.get(status)
        if not items:
            continue
        lines.append("%s (%d)" % (STATUS_LABELS[status], len(items)))
        if status in ("trusted_tls", "untrusted_tls"):
            items.sort(key=_sort_key)
        else:
            items.sort(key=lambda x: x[0])
        for name, e in items:
            lines.append(_format_line(name, e))
        lines.append("")

    if not any(buckets.values()):
        if only_suspicious:
            lines.append("[-] no suspicious permutations found")
        else:
            lines.append("[-] no registered or active permutations found")
        lines.append("")

    summary_bits = ["%d generated" % stats["generated"]]
    for status in STATUS_ORDER:
        if status in stats:
            summary_bits.append("%d %s" % (stats[status], STATUS_DISPLAY[status]))
    summary_bits.append("%d inactive" % stats.get("inactive", 0))
    summary_bits.append("%d errors" % stats.get("errors", 0))
    lines.append("summary: " + ", ".join(summary_bits))
    return "\n".join(lines)


def _json_record(name: str, e: dict) -> dict:
    record = {
        "name": name,
        "kinds": e.get("kinds", []),
        "status": e.get("status"),
        "a": e.get("a", []),
        "aaaa": e.get("aaaa", []),
        "mx": e.get("mx", []),
    }
    tls = e.get("tls")
    if tls is not None:
        record["tls"] = {
            "trusted": tls.get("trusted", False),
            "cn": tls.get("cn"),
            "issuer_cn": tls.get("issuer_cn"),
            "not_after": tls.get("not_after"),
            "sans": tls.get("sans", []),
            "signal": tls.get("signal"),
        }
    if e.get("soa"):
        record["soa"] = e["soa"]
    if e.get("unicode"):
        record["unicode"] = e["unicode"]
    if e.get("mixed_script"):
        record["mixed_script"] = True
    return record


def render_json(domain: str, findings: dict, stats: dict,
                only_suspicious: bool = False) -> dict:
    if only_suspicious:
        visible = [_json_record(n, findings[n]) for n in sorted(findings)
                   if _is_suspicious(findings[n])]
    else:
        visible = [_json_record(n, findings[n]) for n in sorted(findings)]
    return {
        "tool": "doppelganger",
        "domain": domain,
        "generated_at": iso(utcnow()),
        "filter": "suspicious-only" if only_suspicious else None,
        "summary": stats,
        "findings": visible,
    }


# =============================================================================
# Persistent mode
# =============================================================================
def load_state(path: str, domain: str):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        log_error("doppelganger: cannot read state %s: %s" % (path, e))
        raise SystemExit(2)
    if not isinstance(data, dict) or not isinstance(data.get("findings"), dict):
        log_error("doppelganger: state %s has invalid structure" % path)
        raise SystemExit(2)
    if data.get("domain") != domain:
        log_error("doppelganger: state %s is for %r, not %r"
                  % (path, data.get("domain"), domain))
        raise SystemExit(2)
    for name, entry in data["findings"].items():
        if not isinstance(name, str) or not isinstance(entry, dict):
            log_error("doppelganger: state %s has a malformed finding %r"
                      % (path, name))
            raise SystemExit(2)
    return data


def save_state(path: str, state: dict):
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".doppelganger-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, sort_keys=True, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _sig_changed(prev: dict, cur: dict) -> bool:
    if prev.get("status") != cur.get("status"):
        return True
    if (prev.get("a") != cur.get("a")
            or prev.get("aaaa") != cur.get("aaaa")
            or prev.get("mx") != cur.get("mx")):
        return True
    ptls = prev.get("tls") or {}
    ctls = cur.get("tls") or {}
    for k in ("trusted", "cn", "issuer_cn", "signal"):
        if ptls.get(k) != ctls.get(k):
            return True
    return False


def _prune_state(state: dict, max_age_days: int, now: dt.datetime) -> int:
    """Remove findings whose last_seen is older than max_age_days. Returns count."""
    if max_age_days <= 0:
        return 0
    cutoff = now - dt.timedelta(days=max_age_days)
    stale = []
    for name, entry in state["findings"].items():
        last = entry.get("last_seen") or entry.get("first_seen")
        if not last:
            continue
        try:
            t = _parse_iso(last)
        except (ValueError, TypeError):
            continue
        if t < cutoff:
            stale.append(name)
    for name in stale:
        del state["findings"][name]
    return len(stale)


def _emit_new(ts: str, name: str, entry: dict, as_json: bool,
              only_suspicious: bool = False):
    if only_suspicious and not _is_suspicious(entry):
        return
    if as_json:
        record = _json_record(name, entry)
        record["ts"] = ts
        sys.stdout.write(json.dumps(record, ensure_ascii=False) + "\n")
    else:
        status = entry.get("status", "?")
        display = STATUS_DISPLAY.get(status, status)
        line = _format_line(name, entry).lstrip()
        sys.stdout.write("[%s] NEW %-16s %s\n" % (ts, display, line))
    sys.stdout.flush()


def run_persistent(domain: str, opts) -> int:
    state = load_state(opts.state, domain)
    baseline = state is None
    if baseline:
        state = {
            "tool": "doppelganger",
            "domain": domain,
            "created_at": iso(utcnow()),
            "last_scan": None,
            "cycles": 0,
            "findings": {},
        }

    stop = threading.Event()

    def on_signal(signum, frame):
        log("[%s] signal %d — finishing cycle" % (iso(utcnow()), signum))
        stop.set()

    old_int = signal.signal(signal.SIGINT, on_signal)
    old_term = signal.signal(signal.SIGTERM, on_signal)

    cycle = state.get("cycles", 0)
    try:
        while not stop.is_set():
            cycle += 1
            opts.resolver.flush_cache()
            log("[%s] cycle %d: scanning %s" % (iso(utcnow()), cycle, domain))
            try:
                findings, stats = scan_once(domain, opts)
            except Exception as e:
                log_error("[%s] cycle %d failed: %s" % (iso(utcnow()), cycle, e))
                if not stop.is_set():
                    stop.wait(opts.interval)
                continue

            now_iso = iso(utcnow())
            new_entries = {}
            for name, entry in findings.items():
                prev = state["findings"].get(name)
                if prev is None:
                    entry["first_seen"] = now_iso
                    entry["last_seen"] = now_iso
                    state["findings"][name] = entry
                    new_entries[name] = entry
                else:
                    prev["last_seen"] = now_iso
                    if _sig_changed(prev, entry):
                        prev.update({
                            "status": entry.get("status"),
                            "a": entry.get("a", []),
                            "aaaa": entry.get("aaaa", []),
                            "mx": entry.get("mx", []),
                            "tls": entry.get("tls"),
                            "soa": entry.get("soa"),
                            "kinds": entry.get("kinds", prev.get("kinds", [])),
                            "unicode": entry.get("unicode"),
                            "mixed_script": entry.get("mixed_script", False),
                        })
                        new_entries[name] = prev

            state["last_scan"] = now_iso
            state["cycles"] = cycle

            if opts.prune_after_days > 0:
                pruned = _prune_state(state, opts.prune_after_days, utcnow())
                if pruned:
                    log("[%s] pruned %d stale finding(s)" % (now_iso, pruned))

            try:
                save_state(opts.state, state)
            except OSError as e:
                log_error("[%s] cycle %d: cannot save state: %s"
                          % (iso(utcnow()), cycle, e))

            summary_parts = ["cycle %d: %d gen" % (cycle, stats.get("generated", 0))]
            for st in STATUS_ORDER:
                if st in stats:
                    summary_parts.append("%d %s" % (stats[st], STATUS_DISPLAY[st]))
            summary_parts.append("%d inactive" % stats.get("inactive", 0))
            summary_parts.append("%d errors" % stats.get("errors", 0))
            log("[%s] %s" % (now_iso, ", ".join(summary_parts)))
            _log_diagnostics(stats)

            if baseline:
                log("[%s] baseline: %d findings saved "
                    "(subsequent cycles emit deltas only)"
                    % (now_iso, len(state["findings"])))
                baseline = False
            else:
                for name in sorted(new_entries):
                    _emit_new(now_iso, name, new_entries[name], opts.json,
                              opts.only_suspicious)

            if not stop.is_set():
                stop.wait(opts.interval)
    finally:
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)
        log("[%s] doppelganger: stopped (cycles=%d)" % (iso(utcnow()), cycle))
    return 0


# =============================================================================
# CLI
# =============================================================================
def build_parser():
    p = argparse.ArgumentParser(
        prog="doppelganger",
        description="Typosquat permutation scanner: generates algorithmic "
                    "permutations of a domain, resolves them (A/AAAA/MX/SOA), "
                    "and probes :443 to classify each hit.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EXAMPLES,
    )
    p.add_argument("domain", nargs="?", help="target domain (e.g. example.com)")
    p.add_argument("-p", "--persistent", action="store_true",
                   help="daemon mode; emits only NEW findings (state file required)")
    p.add_argument("--interval", type=int, default=3600, metavar="SEC",
                   help="seconds between cycles in -p (default: 3600)")
    p.add_argument("--prune-after-days", type=int, default=0, metavar="N",
                   help="in persistent mode, remove entries not seen in N days "
                        "(default: 0 = never prune)")
    p.add_argument("-s", "--state", metavar="FILE",
                   help="state file (persistent mode); "
                        "default: doppelganger-<domain>.json")
    p.add_argument("-j", "--json", action="store_true",
                   help="JSON output (single-run) or JSONL new-findings (-p)")
    p.add_argument("--only-suspicious", action="store_true",
                   help="show only phishing, untrusted TLS, and active hosts "
                        "whose name is a targeted typosquat (homoglyph, leet, "
                        "bitsquat, single-char typo); hides combosquatting, "
                        "hyphenation, TLD-swap and self-owned domains. "
                        "Untrusted-TLS typosquats are listed before trusted ones.")
    p.add_argument("--no-tls", action="store_true",
                   help="skip TLS probing (DNS only; faster)")
    p.add_argument("--dns-timeout", type=int, default=3, metavar="SEC",
                   help="DNS query timeout in seconds (default: 3)")
    p.add_argument("--tls-timeout", type=int, default=5, metavar="SEC",
                   help="TLS handshake timeout in seconds (default: 5)")
    p.add_argument("--workers", type=int, default=16, metavar="N",
                   help="concurrent workers (default: 16)")
    p.add_argument("-r", "--resolver", action="append", metavar="IP",
                   help="DNS resolver IP (repeatable or comma-separated); "
                        "default: system. Use 1.1.1.1 or 8.8.8.8 if your ISP "
                        "filters malicious domains.")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress progress logs on stderr")
    return p


def main() -> int:
    global QUIET
    parser = build_parser()
    args = parser.parse_args()

    if not args.domain:
        parser.print_help()
        return 0

    QUIET = args.quiet

    try:
        domain = to_ascii_domain(args.domain)
    except ValueError as e:
        log_error("doppelganger: error: %s" % e)
        return 2

    if args.dns_timeout < 1 or args.tls_timeout < 1 or not 1 <= args.workers <= 256:
        log_error("doppelganger: error: timeouts >= 1, --workers in 1..256")
        return 2
    if args.interval < 1:
        log_error("doppelganger: error: --interval >= 1")
        return 2
    if args.prune_after_days < 0:
        log_error("doppelganger: error: --prune-after-days >= 0")
        return 2

    servers = []
    for item in args.resolver or []:
        for s in item.split(","):
            s = s.strip()
            if not s:
                continue
            try:
                ipaddress.ip_address(s)
            except ValueError:
                log_error("doppelganger: error: resolver must be an IP: %r" % s)
                return 2
            servers.append(s)

    resolver = Resolver(servers or system_resolvers(), args.dns_timeout)
    opts = argparse.Namespace(
        resolver=resolver,
        dns_timeout=args.dns_timeout,
        tls_timeout=args.tls_timeout,
        workers=args.workers,
        interval=args.interval,
        prune_after_days=args.prune_after_days,
        json=args.json,
        tls=not args.no_tls,
        only_suspicious=args.only_suspicious,
        state=args.state or ("doppelganger-%s.json" % domain),
    )

    if args.persistent:
        return run_persistent(domain, opts)

    log("[*] generating permutations of %s ..." % domain)
    log("[*] resolving with %d workers, dns-timeout=%ds, tls-timeout=%ds, tls=%s ..."
        % (opts.workers, opts.dns_timeout, opts.tls_timeout, "on" if opts.tls else "off"))
    try:
        findings, stats = scan_once(domain, opts)
    except Exception as e:
        log_error("doppelganger: error: scan failed: %s" % e)
        return 2

    _log_diagnostics(stats)

    if args.json:
        sys.stdout.write(json.dumps(render_json(domain, findings, stats,
                                                opts.only_suspicious),
                                    indent=2, ensure_ascii=False) + "\n")
    else:
        sys.stdout.write(render_human(domain, findings, stats,
                                      opts.only_suspicious) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        sys.exit(130)
    except BrokenPipeError:
        # Downstream consumer closed the pipe (e.g. `| head`); silence the
        # flush at interpreter shutdown and exit cleanly.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(0)