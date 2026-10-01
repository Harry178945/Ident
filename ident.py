#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDENT - Identificateur d'encodages, de bases numériques et de hashs (façon dcode.fr)

Aucune dépendance externe (bibliothèque standard uniquement, Python 3.8+).

Ce que fait l'outil
-------------------
* ENCODAGES / BASES : Base2 (binaire), Base8, Base10, Base16 (hex), Base32 (RFC4648,
  Base32hex, Crockford, z-base-32), Base36, Base45, Base58 (+ Base58Check), Base62,
  Base64 (standard, URL-safe, sans padding), Base85 (Ascii85, RFC1924, Z85), Base91,
  URL-encoding, entités HTML, Quoted-Printable, UUencode, séquences \\u / \\x, Morse,
  + force brute sur toutes les bases 2 à 62 (--brute).
* HASHS : MD5, SHA-1/2/3, RIPEMD, Whirlpool, BLAKE2, NTLM, LM, CRC32... (par longueur),
  formats à préfixe (bcrypt, $1$, $5$, $6$, phpass, Argon2, PBKDF2, MySQL, LDAP...),
  hash:sel, et digests encodés en Base64/Base32.
* FORMATS : JWT, UUID, PEM, adresse Ethereum, Base58Check (Bitcoin...).
* --deep    : décode récursivement les couches successives (base64 -> hex -> texte...).
* --check   : vérifie si un hash correspond à un texte connu (identifie l'algo exact).

Exemples
--------
    python ident.py "SGVsbG8gV29ybGQ="
    python ident.py 5d41402abc4b2a76b9719d911017c592
    python ident.py "NzQ2NTczNzQ=" --deep
    python ident.py 5d41402abc4b2a76b9719d911017c592 --check hello
    python ident.py -f liste.txt --json
    python ident.py                      # mode interactif
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import html
import json
import math
import quopri
import re
import struct
import sys
import urllib.parse
import zlib
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

__version__ = "1.0"

# --------------------------------------------------------------------------- #
#  Modèle de résultat
# --------------------------------------------------------------------------- #


@dataclass
class Candidate:
    category: str            # 'encodage' | 'hash' | 'format'
    name: str
    confidence: float        # 0..100
    details: str = ""
    decoded: Optional[bytes] = field(default=None, repr=False)
    preview: str = ""


# --------------------------------------------------------------------------- #
#  Outils d'analyse du contenu décodé
# --------------------------------------------------------------------------- #

MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "image PNG"), (b"\xff\xd8\xff", "image JPEG"),
    (b"GIF87a", "image GIF"), (b"GIF89a", "image GIF"), (b"%PDF", "document PDF"),
    (b"PK\x03\x04", "archive ZIP/DOCX/APK"), (b"\x1f\x8b", "données GZIP"),
    (b"BZh", "données BZIP2"), (b"7z\xbc\xaf\x27\x1c", "archive 7-Zip"),
    (b"Rar!\x1a\x07", "archive RAR"), (b"\x7fELF", "exécutable ELF"),
    (b"SQLite format 3\x00", "base SQLite"), (b"\xfd7zXZ\x00", "données XZ"),
    (b"RIFF", "conteneur RIFF (WAV/AVI/WEBP)"), (b"OggS", "audio/vidéo OGG"),
    (b"ID3", "audio MP3"), (b"-----BEGIN ", "bloc PEM"),
]


def sniff(b: bytes) -> Optional[str]:
    """Détecte un type de fichier connu à partir des premiers octets."""
    if len(b) < 4:
        return None
    for magic, name in MAGIC:
        if b.startswith(magic):
            return name
    if b[0] == 0x78 and ((b[0] << 8) | b[1]) % 31 == 0:
        try:
            zlib.decompress(b)
            return "données zlib (compressées)"
        except zlib.error:
            pass
    return None


def text_score(b: bytes) -> float:
    """0..1 : à quel point des octets ressemblent à du texte lisible."""
    if not b:
        return 0.0
    try:
        s = b.decode("utf-8")
        penalty = 1.0
        printable = sum(1 for c in s if c.isprintable() or c in "\n\r\t") / len(s)
    except UnicodeDecodeError:
        s = b.decode("latin-1")
        penalty = 0.45
        printable = sum(1 for c in s if (32 <= ord(c) < 127) or c in "\n\r\t") / len(s)
    n = len(s)
    common = sum(1 for c in s if c.isalnum() or c in " .,;:!?'\"-_/\\@#()[]{}\n\r\t") / n
    sc = 0.5 * printable + 0.5 * common
    if printable < 0.9:
        sc *= printable
    sc *= penalty
    if n < 3:
        sc *= 0.6
    return min(1.0, sc)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def preview(b: bytes, limit: int = 100) -> str:
    kind = sniff(b)
    if kind:
        return f"[{kind}, {len(b)} octets] hex: {b[:16].hex()}…"
    if text_score(b) > 0.6:
        try:
            s = b.decode("utf-8")
        except UnicodeDecodeError:
            s = b.decode("latin-1")
        s = s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
        return s if len(s) <= limit else s[:limit] + "…"
    h = b.hex()
    return f"(binaire, {len(b)} octets) hex: {h[:48]}{'…' if len(h) > 48 else ''}"


def int_to_bytes(n: int) -> bytes:
    return n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")


# --------------------------------------------------------------------------- #
#  Décodeurs d'encodages.  Chacun renvoie une liste de tuples :
#  (nom, octets_décodés, score_de_structure 0..1, détails, confiance_forcée|None)
# --------------------------------------------------------------------------- #

Result = Tuple[str, bytes, float, str, Optional[float]]
MAX_BIGINT = 4000


def _classes(t: str) -> int:
    return sum([bool(re.search("[A-Z]", t)), bool(re.search("[a-z]", t)),
                bool(re.search("[0-9]", t)), bool(re.search(r"[+/_\-]", t))])


# --- Base 2 / 8 / 10 / 16 -------------------------------------------------- #

def dec_binary(s: str) -> List[Result]:
    t = re.sub(r"[\s_]", "", s)
    if len(t) >= 8 and len(t) % 8 == 0 and re.fullmatch(r"[01]+", t):
        data = bytes(int(t[i:i + 8], 2) for i in range(0, len(t), 8))
        spaced = bool(re.fullmatch(r"(?:[01]{8}\s)+[01]{8}", s))
        return [("Base2 (binaire, 8 bits/octet)", data, 0.95 if spaced else 0.7, "", None)]
    return []


def dec_octal(s: str) -> List[Result]:
    if re.fullmatch(r"[0-7]{1,3}(?:[\s,;]+[0-7]{1,3})+", s):
        toks = re.split(r"[\s,;]+", s)
        vals = [int(x, 8) for x in toks]
        if all(v < 256 for v in vals):
            st = 0.85 if all(len(x) == 3 for x in toks) else 0.5
            return [("Base8 (octal, 1 octet/groupe)", bytes(vals), st, "", None)]
    return []


def dec_decimal(s: str) -> List[Result]:
    out: List[Result] = []
    if re.fullmatch(r"\d{1,3}(?:[\s,;]+\d{1,3})+", s):
        vals = [int(x) for x in re.split(r"[\s,;]+", s)]
        if all(v < 256 for v in vals):
            out.append(("Base10 (codes ASCII/octets décimaux)", bytes(vals), 0.85, "", None))
    if re.fullmatch(r"\d{6,}", s) and len(s) <= MAX_BIGINT:
        out.append(("Base10 (grand entier → octets)", int_to_bytes(int(s)), 0.3, "", None))
    return out


def dec_hex(s: str) -> List[Result]:
    explicit = bool(re.search(r"(?i)0x|\\x|[\s:,\-]", s))
    t = re.sub(r"(?i)0x|\\x|[\s:,\-]", "", s)
    if len(t) >= 2 and len(t) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", t):
        st = 0.9 if explicit else 0.8
        if not (re.search(r"[0-9]", t) and re.search(r"[a-fA-F]", t)):
            st -= 0.2
        return [("Base16 (hexadécimal)", bytes.fromhex(t), st, "", None)]
    return []


# --- Base 32 et variantes -------------------------------------------------- #

def _bitpack_decode(t: str, alphabet: str, bits: int) -> Optional[bytes]:
    acc = nb = 0
    out = bytearray()
    for ch in t:
        v = alphabet.find(ch)
        if v < 0:
            return None
        acc = (acc << bits) | v
        nb += bits
        if nb >= 8:
            nb -= 8
            out.append((acc >> nb) & 255)
            acc &= (1 << nb) - 1
    if acc != 0:          # bits de fin non nuls : encodage non canonique
        return None
    return bytes(out)


B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
B32HEX = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
ZBASE32 = "ybndrfg8ejkmcpqxot1uwisza345h769"


def dec_base32_family(s: str) -> List[Result]:
    out: List[Result] = []
    t = s.strip()
    if len(t) < 8:
        return out
    body = t.rstrip("=")
    pad_ok = (t.endswith("=") and len(t) % 8 == 0)
    if re.fullmatch(r"[A-Z2-7]+", body) and (not t.endswith("=") or pad_ok):
        data = _bitpack_decode(body, B32, 5)
        if data:
            st = 0.95 if pad_ok else (0.7 if len(t) % 8 == 0 else 0.45)
            out.append(("Base32 (RFC 4648)", data, st, "padding correct" if pad_ok else "", None))
    elif re.fullmatch(r"[a-z2-7]+", body) and len(body) % 8 in (0, 2, 4, 5, 7):
        data = _bitpack_decode(body.upper(), B32, 5)
        if data:
            out.append(("Base32 (minuscules)", data, 0.3, "", None))
    if re.fullmatch(r"[0-9A-V]+", body) and "=" not in body:
        data = _bitpack_decode(body, B32HEX, 5)
        if data:
            out.append(("Base32hex (RFC 4648)", data, 0.4 if not t.endswith("=") else 0.8, "", None))
    cl = t.upper().replace("-", "")
    if re.fullmatch(r"[0-9A-HJKMNP-TV-Z]+", cl):
        data = _bitpack_decode(cl, CROCKFORD, 5)
        if data:
            out.append(("Base32 Crockford", data, 0.4, "", None))
    if re.fullmatch(r"[ybndrfg8ejkmcpqxot1uwisza345h769]+", t):
        data = _bitpack_decode(t, ZBASE32, 5)
        if data:
            out.append(("z-base-32", data, 0.4, "", None))
    return out


# --- Base 36 / 58 / 62 (entiers en grande base) ---------------------------- #

def _bigint_decode(t: str, alphabet: str) -> Optional[int]:
    base = len(alphabet)
    n = 0
    for ch in t:
        i = alphabet.find(ch)
        if i < 0:
            return None
        n = n * base + i
    return n


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B62_A = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
B62_B = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
B36 = "0123456789abcdefghijklmnopqrstuvwxyz"


def dec_base58(s: str) -> List[Result]:
    t = s.strip()
    if len(t) < 6 or len(t) > MAX_BIGINT or not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]+", t):
        return []
    n = _bigint_decode(t, B58)
    data = b"\x00" * (len(t) - len(t.lstrip("1"))) + (int_to_bytes(n) if n else b"")
    if len(data) >= 5:
        payload, chk = data[:-4], data[-4:]
        if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == chk:
            ver = payload[0]
            hint = {0x00: "adresse Bitcoin P2PKH", 0x05: "adresse Bitcoin P2SH",
                    0x80: "clé privée Bitcoin (WIF)", 0x6F: "adresse Bitcoin testnet",
                    0x30: "adresse Litecoin", 0x1E: "adresse Dogecoin"}.get(ver, f"version 0x{ver:02x}")
            return [("Base58Check", payload[1:], 1.0, f"checksum valide → {hint}", 97.0)]
    return [("Base58 (Bitcoin)", data, 0.35, "", None)]


def dec_base36_62(s: str) -> List[Result]:
    t = s.strip()
    out: List[Result] = []
    if len(t) < 4 or len(t) > MAX_BIGINT or not re.fullmatch(r"[0-9A-Za-z]+", t):
        return out
    if t == t.lower() or t == t.upper():
        n = _bigint_decode(t.lower(), B36)
        out.append(("Base36 (entier → octets)", int_to_bytes(n), 0.3, "", None))
    if re.search("[A-Z]", t) and re.search("[a-z]", t):
        for label, alpha in (("0-9A-Za-z", B62_A), ("0-9a-zA-Z", B62_B)):
            n = _bigint_decode(t, alpha)
            out.append((f"Base62 (alphabet {label})", int_to_bytes(n), 0.3, "", None))
    return out


# --- Base 45 --------------------------------------------------------------- #

B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def dec_base45(s: str) -> List[Result]:
    t = s.strip("\r\n")
    if len(t) < 3 or len(t) % 3 == 1 or any(c not in B45 for c in t):
        return []
    out = bytearray()
    for i in range(0, len(t), 3):
        chunk = t[i:i + 3]
        vals = [B45.index(c) for c in chunk]
        if len(chunk) == 3:
            v = vals[0] + vals[1] * 45 + vals[2] * 2025
            if v > 0xFFFF:
                return []
            out += v.to_bytes(2, "big")
        else:
            v = vals[0] + vals[1] * 45
            if v > 0xFF:
                return []
            out.append(v)
    return [("Base45 (RFC 9285, QR / pass sanitaire)", bytes(out), 0.45, "", None)]


# --- Base 64 --------------------------------------------------------------- #

def dec_base64(s: str) -> List[Result]:
    t = re.sub(r"\s+", "", s)
    if len(t) < 4:
        return []
    out: List[Result] = []
    body = t.rstrip("=")
    padded = t != body
    if padded and (len(t) % 4 != 0 or len(t) - len(body) > 2):
        return []
    if len(body) % 4 == 1:
        return []

    def build(altchars: Optional[bytes], label: str):
        pad = body + "=" * (-len(body) % 4)
        try:
            data = base64.b64decode(pad, altchars=altchars, validate=True)
        except (binascii.Error, ValueError):
            return
        enc = base64.b64encode(data) if altchars is None else base64.urlsafe_b64encode(data)
        if enc.rstrip(b"=") != body.encode():
            return  # non canonique
        st = 0.25
        if len(t) % 4 == 0:
            st += 0.25
        if padded:
            st += 0.25
        cl = _classes(body)
        st += 0.25 if cl >= 3 else (0.1 if cl == 2 else 0)
        det = "" if (padded or len(t) % 4 == 0) else "sans padding"
        out.append((label, data, min(st, 1.0), det, None))

    if re.fullmatch(r"[A-Za-z0-9+/]+", body):
        build(None, "Base64")
    if re.fullmatch(r"[A-Za-z0-9_\-]+", body) and re.search(r"[_\-]", body):
        build(b"-_", "Base64 URL-safe")
    return out


# --- Base 85 / 91 ---------------------------------------------------------- #

Z85 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
B85_RFC1924 = ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
               "!#$%&()*+-;<=>?@^_`{|}~")


def dec_base85(s: str) -> List[Result]:
    t = s.strip()
    out: List[Result] = []
    if len(t) < 5:
        return out
    if t.startswith("<~") and t.endswith("~>"):
        try:
            out.append(("Ascii85 (Adobe <~ ~>)", base64.a85decode(t, adobe=True), 0.95, "", None))
        except ValueError:
            pass
    elif all(33 <= ord(c) <= 117 or c == "z" for c in t) and len(t) >= 5:
        try:
            out.append(("Ascii85 (btoa / PDF)", base64.a85decode(t), 0.3, "", None))
        except ValueError:
            pass
    if all(c in B85_RFC1924 for c in t):
        try:
            out.append(("Base85 (RFC 1924 / Git)", base64.b85decode(t), 0.3, "", None))
        except ValueError:
            pass
    if len(t) % 5 == 0 and all(c in Z85 for c in t):
        data = bytearray()
        ok = True
        for i in range(0, len(t), 5):
            v = 0
            for ch in t[i:i + 5]:
                v = v * 85 + Z85.index(ch)
            if v > 0xFFFFFFFF:
                ok = False
                break
            data += v.to_bytes(4, "big")
        if ok:
            out.append(("Z85 (ZeroMQ)", bytes(data), 0.35, "", None))
    return out


B91 = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
       "!#$%&()*+,./:;<=>?@[]^_`{|}~\"")
B91_DEC = {c: i for i, c in enumerate(B91)}


def dec_base91(s: str) -> List[Result]:
    t = s.strip()
    if len(t) < 5 or any(c not in B91_DEC for c in t):
        return []
    v, b, n = -1, 0, 0
    out = bytearray()
    for ch in t:
        c = B91_DEC[ch]
        if v < 0:
            v = c
        else:
            v += c * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while True:
                out.append(b & 255)
                b >>= 8
                n -= 8
                if n <= 7:
                    break
            v = -1
    if v + 1:
        out.append((b | v << n) & 255)
    return [("Base91 (basE91)", bytes(out), 0.3, "", None)]


# --- Autres encodages courants -------------------------------------------- #

def dec_url(s: str) -> List[Result]:
    if re.search(r"%[0-9A-Fa-f]{2}", s):
        data = urllib.parse.unquote_to_bytes(s)
        if data != s.encode():
            return [("URL-encoding (%XX)", data, 0.85, "", None)]
    return []


def dec_html(s: str) -> List[Result]:
    if re.search(r"&(?:#\d+|#[xX][0-9a-fA-F]+|[A-Za-z]{2,8});", s):
        r = html.unescape(s)
        if r != s:
            return [("Entités HTML", r.encode("utf-8"), 0.85, "", None)]
    return []


def dec_escapes(s: str) -> List[Result]:
    if re.search(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|\\[0-7]{3}", s):
        try:
            r = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)
            r = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), r)
            r = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), r)
            return [("Séquences d'échappement (\\u, \\x, \\NNN)", r.encode("utf-8", "replace"), 0.8, "", None)]
        except ValueError:
            pass
    return []


def dec_qp(s: str) -> List[Result]:
    if re.search(r"=[0-9A-F]{2}", s) or re.search(r"=\r?\n", s):
        data = quopri.decodestring(s.encode("latin-1", "replace"))
        if data != s.encode("latin-1", "replace"):
            return [("Quoted-Printable", data, 0.6, "", None)]
    return []


def dec_uu(s: str) -> List[Result]:
    lines = [ln for ln in s.splitlines() if ln.strip()]
    header = bool(lines) and lines[0].startswith("begin ")
    if header:
        lines = lines[1:]
        if lines and lines[-1].strip() == "end":
            lines = lines[:-1]
        if lines and lines[-1].strip() == "`":
            lines = lines[:-1]
    if not lines or (not header and len(lines) < 1):
        return []
    data = b""
    try:
        for ln in lines:
            data += binascii.a2b_uu(ln.encode("ascii"))
    except (binascii.Error, UnicodeEncodeError, ValueError):
        return []
    return [("UUencode", data, 0.95 if header else 0.3, "", None)] if data else []


MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F", "--.": "G",
    "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L", "--": "M", "-.": "N",
    "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T", "..-": "U",
    "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y", "--..": "Z", "-----": "0",
    ".----": "1", "..---": "2", "...--": "3", "....-": "4", ".....": "5", "-....": "6",
    "--...": "7", "---..": "8", "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?",
    "-.-.--": "!", "-..-.": "/", "---...": ":", "-....-": "-", ".----.": "'",
}


def dec_morse(s: str) -> List[Result]:
    if not re.fullmatch(r"[.\-/|\s]+", s) or not re.search(r"[.\-]", s):
        return []
    words = re.split(r"\s*[/|]\s*|\s{3,}", s.strip())
    res = []
    for w in words:
        letters = []
        for tok in w.split():
            if tok not in MORSE:
                return []
            letters.append(MORSE[tok])
        res.append("".join(letters))
    return [("Code Morse", " ".join(res).encode(), 0.85, "", None)]


DECODERS: List[Callable[[str], List[Result]]] = [
    dec_binary, dec_octal, dec_decimal, dec_hex, dec_base32_family, dec_base58,
    dec_base36_62, dec_base45, dec_base64, dec_base85, dec_base91, dec_url, dec_html,
    dec_escapes, dec_qp, dec_uu, dec_morse,
]


def brute_bases(s: str) -> List[Candidate]:
    """Teste chaque base de 2 à 62 en interprétant la chaîne comme un grand entier → octets."""
    t = s.strip()
    out: List[Candidate] = []
    if len(t) < 3 or len(t) > MAX_BIGINT or not re.fullmatch(r"[0-9A-Za-z]+", t):
        return out
    seen = set()
    for base in range(2, 37):
        try:
            n = int(t, base)
        except ValueError:
            continue
        seen.add((base, "std"))
        _add_brute(out, f"Base {base}", int_to_bytes(n))
    for base in range(37, 63):
        for label, alpha in (("0-9a-zA-Z", B62_B), ("0-9A-Za-z", B62_A)):
            n = _bigint_decode(t, alpha[:base])
            if n is not None:
                _add_brute(out, f"Base {base} (alphabet {label})", int_to_bytes(n))
    return out


def _add_brute(out: List[Candidate], name: str, data: bytes) -> None:
    ts = text_score(data)
    if len(data) >= 2 and ts >= 0.85:
        out.append(Candidate("encodage", f"{name} (entier → octets)", min(60.0, 55 * ts),
                             "force brute : possible faux positif", data, preview(data)))


# --------------------------------------------------------------------------- #
#  Identification des hashs
# --------------------------------------------------------------------------- #

# (regex complète, nom, mode hashcat)
PREFIXED = [
    (r"\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}", "bcrypt", "3200"),
    (r"\$1\$[^$]{0,8}\$[./0-9A-Za-z]{22}", "MD5-crypt (Unix, $1$)", "500"),
    (r"\$apr1\$[^$]{0,8}\$[./0-9A-Za-z]{22}", "Apache MD5 (apr1)", "1600"),
    (r"\$5\$(?:rounds=\d+\$)?[^$]{0,16}\$[./0-9A-Za-z]{43}", "SHA-256-crypt (Unix, $5$)", "7400"),
    (r"\$6\$(?:rounds=\d+\$)?[^$]{0,16}\$[./0-9A-Za-z]{86}", "SHA-512-crypt (Unix, $6$)", "1800"),
    (r"\$[PH]\$[./0-9A-Za-z]{31}", "phpass (WordPress / phpBB / Joomla)", "400"),
    (r"\$S\$[./0-9A-Za-z]{52}", "Drupal 7 (SHA-512 itéré)", "7900"),
    (r"\$argon2(?:id|i|d)\$.+", "Argon2", ""),
    (r"\$y\$.+", "yescrypt", ""),
    (r"\$7\$.+", "scrypt (crypt $7$)", ""),
    (r"\$scrypt\$.+", "scrypt (passlib)", ""),
    (r"\$sha1\$\d+\$.+", "SHA-1-crypt", ""),
    (r"\$pbkdf2-sha(?:1|256|512)\$.+", "PBKDF2 (passlib)", ""),
    (r"pbkdf2_sha(?:1|256)\$\d+\$[^$]+\$[A-Za-z0-9+/=]+", "PBKDF2-SHA (Django)", ""),
    (r"\*[0-9A-Fa-f]{40}", "MySQL 4.1+ (MySQL5)", "300"),
    (r"md5[0-9a-f]{32}", "PostgreSQL MD5", "12"),
    (r"\{SHA\}[A-Za-z0-9+/]{27}=", "LDAP SHA-1 ({SHA})", "101"),
    (r"\{SSHA\}[A-Za-z0-9+/=]{32,}", "LDAP SHA-1 salé ({SSHA})", "111"),
    (r"\{MD5\}[A-Za-z0-9+/]{22}==", "LDAP MD5 ({MD5})", ""),
    (r"0x0100[0-9A-Fa-f]{48}", "MSSQL 2005", "132"),
    (r"0x0100[0-9A-Fa-f]{88}", "MSSQL 2000", "131"),
    (r"S:[0-9A-F]{60}", "Oracle 11g", "112"),
]

# longueur hexa -> [(nom, poids, mode hashcat)]
HEX_HASHES = {
    8: [("CRC-32", 60, "11500"), ("Adler-32", 45, ""), ("FNV-1/1a 32 bits", 35, ""),
        ("MurmurHash3 32 bits", 25, ""), ("XXH32", 25, "")],
    16: [("MySQL323 (< 4.1)", 55, "200"), ("MD5 tronqué (16 car.)", 45, ""), ("CRC-64", 35, ""),
         ("FNV-64", 30, ""), ("XXH64", 30, ""), ("SipHash-2-4", 20, "")],
    32: [("MD5", 75, "0"), ("NTLM", 55, "1000"), ("MD4", 40, "900"), ("LM", 35, "3000"),
         ("MD5(MD5($pass)) / double MD5", 30, "2600"), ("Domain Cached Credentials (mscash)", 25, "1100"),
         ("RIPEMD-128", 22, ""), ("MD2", 20, ""), ("HAVAL-128", 15, ""), ("MurmurHash3 128", 15, ""),
         ("XXH128", 15, ""), ("Tiger-128", 12, ""), ("Snefru-128", 12, "")],
    40: [("SHA-1", 80, "100"), ("RIPEMD-160", 40, "6000"), ("MySQL5 (sans le *)", 30, "300"),
         ("SHA-1(SHA-1($pass))", 25, "4500"), ("Tiger-160", 15, ""), ("HAVAL-160", 15, "")],
    48: [("Tiger-192", 30, ""), ("HAVAL-192", 15, "")],
    56: [("SHA-224", 60, "1300"), ("SHA3-224", 40, "17300"), ("Keccak-224", 25, "17700"),
         ("SHA-512/224", 20, ""), ("HAVAL-224", 12, ""), ("BLAKE2s-224", 10, "")],
    64: [("SHA-256", 80, "1400"), ("SHA3-256", 45, "17400"), ("Keccak-256 (Ethereum)", 35, "17800"),
         ("BLAKE2s-256", 30, ""), ("BLAKE3 (256 bits)", 25, ""), ("SHA-256d (double SHA-256, Bitcoin)", 25, ""),
         ("SHA-512/256", 20, ""), ("GOST R 34.11-94", 20, "6900"), ("RIPEMD-256", 15, ""),
         ("Streebog-256", 15, "11700"), ("SM3", 15, "18300"), ("HAVAL-256", 12, ""),
         ("Snefru-256", 12, ""), ("Skein-256", 8, "")],
    80: [("RIPEMD-320", 40, "")],
    96: [("SHA-384", 75, "10800"), ("SHA3-384", 40, "17500"), ("Keccak-384", 25, "17900")],
    128: [("SHA-512", 80, "1700"), ("Whirlpool", 45, "6100"), ("SHA3-512", 40, "17600"),
          ("BLAKE2b-512", 40, "600"), ("Keccak-512", 30, "18000"), ("Streebog-512", 20, "11800"),
          ("Skein-512", 10, "")],
}
SALTED_NAMES = {32: "MD5", 40: "SHA-1", 56: "SHA-224", 64: "SHA-256", 96: "SHA-384", 128: "SHA-512"}


def identify_hashes(t: str) -> List[Candidate]:
    out: List[Candidate] = []
    for rx, name, mode in PREFIXED:
        if re.fullmatch(rx, t):
            d = f"hashcat -m {mode}" if mode else "format à préfixe reconnu"
            out.append(Candidate("hash", name, 96.0, d))
    if re.fullmatch(r"[0-9a-fA-F]+", t) and len(t) in HEX_HASHES:
        for name, w, mode in HEX_HASHES[len(t)]:
            d = f"{len(t)} car. hex ({len(t) * 4} bits)" + (f" · hashcat -m {mode}" if mode else "")
            out.append(Candidate("hash", name, float(w), d))
    m = re.fullmatch(r"([0-9a-fA-F]{32,128}):(.{1,128})", t)
    if m and len(m.group(1)) in SALTED_NAMES:
        out.append(Candidate("hash", f"{SALTED_NAMES[len(m.group(1))]} avec sel (hash:sel)", 70.0,
                             "attention à l'ordre du sel dans hashcat (ex. -m 10 / 20 pour MD5)"))
    if re.fullmatch(r"[./0-9A-Za-z]{13}", t):
        out.append(Candidate("hash", "DES-crypt (Unix traditionnel)", 35.0, "hashcat -m 1500"))
    if re.fullmatch(r"[0-9a-fA-F]+", t) and len(t) > 8 and len(t) not in HEX_HASHES and len(t) % 2 == 0:
        out.append(Candidate("hash", "Longueur hex inhabituelle : hash tronqué, salé ou HMAC ?", 15.0,
                             f"{len(t)} caractères"))
    return out


def identify_formats(t: str) -> List[Candidate]:
    out: List[Candidate] = []
    if re.fullmatch(r"eyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", t):
        det = ""
        try:
            h, p = t.split(".")[:2]
            fix = lambda x: base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)).decode()
            det = f"header={fix(h)}  payload={fix(p)[:120]}"
        except Exception:
            pass
        out.append(Candidate("format", "JWT (JSON Web Token)", 98.0, det))
    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-([0-9a-fA-F])[0-9a-fA-F]{3}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", t):
        out.append(Candidate("format", f"UUID (version {t[14]})", 95.0))
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", t):
        out.append(Candidate("format", "Adresse Ethereum / EVM", 90.0))
    if t.startswith("-----BEGIN "):
        label = re.match(r"-----BEGIN ([A-Z0-9 ]+)-----", t)
        body = re.sub(r"-----[^-]+-----|\s", "", t)
        data = None
        try:
            data = base64.b64decode(body, validate=True)
        except Exception:
            pass
        out.append(Candidate("format", f"PEM ({label.group(1) if label else '?'})", 97.0,
                             "corps en Base64", data, preview(data) if data else ""))
    return out


# --------------------------------------------------------------------------- #
#  Analyse principale
# --------------------------------------------------------------------------- #

def analyze(s: str, brute: bool = False, min_conf: float = 10.0) -> List[Candidate]:
    t = s.strip()
    cands: List[Candidate] = []
    if not t:
        return cands

    for dec in DECODERS:
        try:
            results = dec(t)
        except Exception:
            results = []
        for name, data, st, detail, force in results:
            kind = sniff(data)
            content = max(text_score(data), 0.95 if kind else 0.0)
            conf = force if force is not None else 100 * st * (0.15 + 0.85 * content)
            if kind:
                detail = (detail + " | " if detail else "") + f"fichier détecté : {kind}"
            cands.append(Candidate("encodage", name, conf, detail, data, preview(data)))

    if brute:
        cands += brute_bases(t)

    cands += identify_formats(t)
    hashes = identify_hashes(t)

    # Un « hash » hexa qui décode en texte lisible est en réalité du texte encodé en hexa.
    if re.fullmatch(r"[0-9a-fA-F]+", t) and len(t) % 2 == 0:
        ts = text_score(bytes.fromhex(t))
        for h in hashes:
            if h.confidence < 90:
                h.confidence *= (1 - 0.85 * ts)
    cands += hashes

    # Digests encodés en Base64 / Base32 (ex. SHA-1 en base64 = 28 car.)
    is_hex = bool(re.fullmatch(r"[0-9a-fA-F]+", t))
    for c in list(cands):
        if is_hex:
            break  # une chaîne purement hexa est presque sûrement un digest hexa, pas du Base64
        if c.category == "encodage" and c.decoded and c.name.startswith(("Base64", "Base32 (RFC")):
            if len(c.decoded) * 2 in HEX_HASHES and text_score(c.decoded) < 0.4 and not sniff(c.decoded):
                enc = "Base64" if c.name.startswith("Base64") else "Base32"
                for name, w, mode in HEX_HASHES[len(c.decoded) * 2][:4]:
                    if "(" in name:
                        continue
                    cands.append(Candidate("hash", f"{name} encodé en {enc}", w * 0.85,
                                           f"digest de {len(c.decoded)} octets"))

    # Dédoublonnage : même octets décodés -> on garde le meilleur
    best = {}
    final: List[Candidate] = []
    for c in sorted(cands, key=lambda x: -x.confidence):
        if c.category == "encodage" and c.decoded is not None:
            if c.decoded in best:
                continue
            best[c.decoded] = c
        final.append(c)
    return [c for c in final if c.confidence >= min_conf]


def deep_decode(s: str, max_depth: int = 10, min_conf: float = 45.0):
    """Décode récursivement. Renvoie la liste des couches [(nom, confiance, octets)]."""
    layers = []
    cur = s.strip()
    seen = {cur}
    for _ in range(max_depth):
        cands = [c for c in analyze(cur, min_conf=min_conf)
                 if c.category == "encodage" and c.decoded is not None]
        if not cands:
            break
        top = cands[0]
        layers.append((top.name, top.confidence, top.decoded))
        if sniff(top.decoded):
            break
        try:
            nxt = top.decoded.decode("utf-8").strip()
        except UnicodeDecodeError:
            break
        if not nxt or nxt in seen:
            break
        seen.add(nxt)
        cur = nxt
    return layers


# --------------------------------------------------------------------------- #
#  Vérification d'un hash contre un texte connu
# --------------------------------------------------------------------------- #

def _md4(data: bytes) -> bytes:
    """MD4 en Python pur (OpenSSL 3 le désactive souvent) - nécessaire pour NTLM."""
    M = 0xFFFFFFFF
    rotl = lambda x, n: ((x << n) | (x >> (32 - n))) & M
    msg = bytearray(data)
    ml = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", ml)
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for off in range(0, len(msg), 64):
        X = struct.unpack("<16I", bytes(msg[off:off + 64]))
        aa, bb, cc, dd = a, b, c, d
        for i in range(16):
            a = rotl((a + ((b & c) | (~b & d)) + X[i]) & M, (3, 7, 11, 19)[i % 4])
            a, b, c, d = d, a, b, c
        for i, k in enumerate([0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]):
            a = rotl((a + ((b & c) | (b & d) | (c & d)) + X[k] + 0x5A827999) & M, (3, 5, 9, 13)[i % 4])
            a, b, c, d = d, a, b, c
        for i, k in enumerate([0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]):
            a = rotl((a + (b ^ c ^ d) + X[k] + 0x6ED9EBA1) & M, (3, 9, 11, 15)[i % 4])
            a, b, c, d = d, a, b, c
        a, b, c, d = (a + aa) & M, (b + bb) & M, (c + cc) & M, (d + dd) & M
    return struct.pack("<4I", a, b, c, d)


def _hl(name: str, data: bytes) -> Optional[bytes]:
    try:
        return hashlib.new(name, data).digest()
    except Exception:
        return None


def all_digests(data: bytes) -> dict:
    out = {}
    for name in sorted(hashlib.algorithms_available):
        if name.startswith("shake"):
            continue
        d = _hl(name, data)
        if d:
            out[name] = d
    out.setdefault("md4", _md4(data))
    out["ntlm"] = _hl("md4", data.decode("latin-1").encode("utf-16le")) or _md4(
        data.decode("latin-1").encode("utf-16le"))
    out["crc32"] = zlib.crc32(data).to_bytes(4, "big")
    out["adler32"] = zlib.adler32(data).to_bytes(4, "big")
    out["md5(md5)"] = hashlib.md5(hashlib.md5(data).hexdigest().encode()).digest()
    out["sha1(sha1) [MySQL5]"] = hashlib.sha1(hashlib.sha1(data).digest()).digest()
    out["sha256d [Bitcoin]"] = hashlib.sha256(hashlib.sha256(data).digest()).digest()
    return out


def check_plaintext(target: str, plaintext: str) -> List[str]:
    """Renvoie la liste des algos dont le digest de `plaintext` égale `target`."""
    t = target.strip()
    t = re.sub(r"^(\*|0x|\{[A-Za-z0-9]+\})", "", t)
    wanted = set()
    if re.fullmatch(r"[0-9a-fA-F]+", t) and len(t) % 2 == 0:
        wanted.add(bytes.fromhex(t))
    try:
        wanted.add(base64.b64decode(t + "=" * (-len(t) % 4), validate=True))
    except Exception:
        pass
    found = []
    for label, variant in (("", plaintext), (" (+ \\n final)", plaintext + "\n"),
                           (" (+ \\r\\n final)", plaintext + "\r\n")):
        for name, dig in all_digests(variant.encode("utf-8")).items():
            if dig in wanted:
                found.append(name + label)
    return found


# --------------------------------------------------------------------------- #
#  Affichage
# --------------------------------------------------------------------------- #

USE_COLOR = sys.stdout.isatty()


def paint(txt: str, code: str) -> str:
    return f"\033[{code}m{txt}\033[0m" if USE_COLOR else txt


def bar(conf: float, width: int = 10) -> str:
    filled = round(conf / 100 * width)
    col = "92" if conf >= 70 else ("93" if conf >= 40 else "90")
    return paint("█" * filled + "░" * (width - filled), col)


def profile(s: str) -> str:
    t = s.strip()
    kinds = []
    if re.search("[a-z]", t): kinds.append("minuscules")
    if re.search("[A-Z]", t): kinds.append("MAJUSCULES")
    if re.search("[0-9]", t): kinds.append("chiffres")
    if re.search(r"\s", t): kinds.append("espaces")
    if re.search(r"[^\w\s]", t): kinds.append("symboles")
    return f"{len(t)} caractères · entropie {entropy(t):.2f} bits/car. · " + ", ".join(kinds)


def render(s: str, cands: List[Candidate], top: int, deep_layers=None) -> None:
    shown = s.strip().replace("\n", "\\n")
    print(paint("═" * 78, "36"))
    print(paint("Entrée : ", "1") + (shown if len(shown) < 90 else shown[:87] + "…"))
    print(paint("Profil : ", "1") + profile(s))
    print(paint("─" * 78, "36"))
    if not cands:
        print("Aucune piste sérieuse : texte brut, chiffrement, ou format non géré.")
    for i, c in enumerate(cands[:top], 1):
        tag = {"encodage": paint("ENCODAGE", "94"), "hash": paint("HASH    ", "95"),
               "format": paint("FORMAT  ", "96")}[c.category]
        print(f"{i:>2}. {tag} {c.name:<44.44} {bar(c.confidence)} {c.confidence:5.1f} %")
        if c.details:
            print(f"      {paint('ℹ', '90')} {c.details}")
        if c.preview:
            print(f"      {paint('→', '92')} {c.preview}")
    if len(cands) > top:
        print(paint(f"   … {len(cands) - top} autre(s) piste(s) (augmente --top)", "90"))
    if deep_layers:
        print(paint("─" * 78, "36"))
        print(paint("Décodage récursif (--deep) :", "1"))
        for i, (name, conf, data) in enumerate(deep_layers, 1):
            print(f"  couche {i}: {name} ({conf:.0f} %) → {preview(data, 70)}")
        last = deep_layers[-1][2]
        if text_score(last) > 0.6 and not sniff(last):
            print(paint("  RÉSULTAT FINAL : ", "1;92") + last.decode("utf-8", "replace"))
    print(paint("═" * 78, "36"))


def to_json(s: str, cands: List[Candidate], deep_layers=None) -> dict:
    d = {"input": s.strip(), "profile": profile(s), "candidates": [
        {"category": c.category, "name": c.name, "confidence": round(c.confidence, 1),
         "details": c.details, "decoded_preview": c.preview,
         "decoded_hex": c.decoded.hex() if c.decoded is not None else None} for c in cands]}
    if deep_layers:
        d["deep"] = [{"layer": n, "confidence": round(cf, 1), "preview": preview(b)} for n, cf, b in deep_layers]
    return d


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #

def main(argv=None) -> int:
    global USE_COLOR
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="Identifie encodages, bases et hashs (façon dcode.fr).")
    ap.add_argument("inputs", nargs="*", help="chaînes à analyser ('-' = stdin)")
    ap.add_argument("-f", "--file", help="fichier : une chaîne par ligne")
    ap.add_argument("-d", "--deep", action="store_true", help="décodage récursif multi-couches")
    ap.add_argument("-b", "--brute", action="store_true", help="force brute sur les bases 2 à 62")
    ap.add_argument("-c", "--check", metavar="TEXTE", help="vérifie si le hash correspond à ce texte")
    ap.add_argument("-n", "--top", type=int, default=8, help="nombre de pistes affichées (défaut 8)")
    ap.add_argument("-m", "--min-conf", type=float, default=10.0, help="confiance minimale (défaut 10)")
    ap.add_argument("-o", "--output", help="écrit les octets décodés de la 1re piste d'encodage")
    ap.add_argument("--json", action="store_true", help="sortie JSON")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--version", action="version", version=f"ident {__version__}")
    a = ap.parse_args(argv)
    if a.no_color:
        USE_COLOR = False

    items: List[str] = []
    for x in a.inputs:
        items.append(sys.stdin.read() if x == "-" else x)
    if a.file:
        with open(a.file, "r", encoding="utf-8", errors="replace") as fh:
            items += [ln.rstrip("\r\n") for ln in fh if ln.strip()]

    interactive = not items
    if interactive:
        print(paint(f"IDENT {__version__} — mode interactif (ligne vide ou 'q' pour quitter)", "1"))

    def handle(s: str) -> None:
        cands = analyze(s, brute=a.brute, min_conf=a.min_conf)
        layers = deep_decode(s) if a.deep else None
        if a.json:
            print(json.dumps(to_json(s, cands, layers), ensure_ascii=False, indent=2))
        else:
            render(s, cands, a.top, layers)
        if a.check is not None:
            m = check_plaintext(s, a.check)
            if m:
                print(paint(f"✔ Correspondance avec « {a.check} » : ", "1;92") + ", ".join(m))
            else:
                print(paint(f"✘ Aucun algorithme connu ne donne ce hash pour « {a.check} ».", "91"))
        if a.output:
            enc = [c for c in cands if c.category == "encodage" and c.decoded is not None]
            if enc:
                with open(a.output, "wb") as fh:
                    fh.write(enc[0].decoded)
                print(f"Octets décodés ({enc[0].name}) écrits dans {a.output}")

    if interactive:
        while True:
            try:
                s = input(paint("ident> ", "92"))
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not s.strip() or s.strip().lower() == "q":
                break
            handle(s)
    else:
        for s in items:
            handle(s)
    return 0


if __name__ == "__main__":
    sys.exit(main())
