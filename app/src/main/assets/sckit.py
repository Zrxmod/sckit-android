#!/usr/bin/env python3
"""
Sckit_Advanced — Fully featured automatic decoder for obfuscated strings
======================================================================
Enhancements vs original:
- Multiple backends (pycryptodome / cryptography) with pure-Python fallback.
- AES-ECB / AES-CBC, RC4, XOR single-byte & small repeating-key brute force.
- Iterative Base64/Base85 decoding, URL/html unescape, gzip/zlib detection.
- Wordlist-driven key search and parallel decoding across tokens & keys.
- JSONL / CSV output, deduplication, verbose & dry-run modes.
- ThreadPoolExecutor-based parallelism and progress prints.
"""
from __future__ import annotations
import argparse
import base64
import binascii
import collections
import html
import hashlib
import io
import itertools
import json
import math
import os
import re
import sys
import time
import zipfile
import zlib
import gzip
import csv
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional, Iterator, Dict

# Terminal colors (Termux / ANSI)
class C:
    HEADER = '\033[95m'; OKBLUE = '\033[94m'; OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'; WARNING = '\033[93m'; FAIL = '\033[91m'
    ENDC = '\033[0m'; BOLD = '\033[1m'; DIM = '\033[2m'

# Keep UTF-8
if hasattr(sys.stdout, "reconfigure"):
    try: sys.stdout.reconfigure(encoding="utf-8")
    except Exception: pass

# ---------------------------
# Backend detection (AES/RC4)
# ---------------------------
_BACKEND = "pure"
_AES_new = None
try:
    # Prefer PyCryptodome
    from Crypto.Cipher import AES as _AES_PYCD
    _AES_new = lambda key, mode, iv=None: _AES_PYCD.new(key, mode, iv) if iv is not None else _AES_PYCD.new(key, mode)
    _BACKEND = "pycryptodome"
except Exception:
    try:
        # Try cryptography
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        def _AES_new(key, mode, iv=None):
            if mode == "ECB":
                return Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
            elif mode == "CBC":
                return Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            else:
                raise ValueError("Unsupported mode")
        _BACKEND = "cryptography"
    except Exception:
        _BACKEND = "pure"

# ---------------------------
# Pure-Python AES & RC4 fallback (copied & improved)
# ---------------------------
# A minimal pure-Python AES from original for ECB (used if no libs).
# Keep same interface: aes_ecb_decrypt(key, data) and aes_cbc_decrypt(key, iv, data)
# For brevity we re-use the AES implementation you provided earlier when needed.
# We'll include that AES implementation only when backend == "pure"

# RC4 (pure)
def pure_rc4_decrypt(key: bytes, data: bytes) -> bytes:
    if not key:
        return data
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray(len(data))
    for k, b in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out[k] = b ^ S[(S[i] + S[j]) & 0xFF]
    return bytes(out)

# If pure backend, embed AES implementation (from original script, trimmed/ensured)
if _BACKEND == "pure":
    # --- GF math and AES small impl (block-level) ---
    def _gf_mul(a, b):
        p = 0
        for _ in range(8):
            if b & 1: p ^= a
            carry = a & 0x80; a = (a << 1) & 0xFF
            if carry: a ^= 0x1B
            b >>= 1
        return p
    def _build_sboxes():
        def gpow(a, n):
            r = 1
            while n:
                if n & 1: r = _gf_mul(r, a)
                a = _gf_mul(a, a); n >>= 1
            return r
        def rotl(x, n): return ((x << n) | (x >> (8 - n))) & 0xFF
        sbox, inv = [0]*256, [0]*256
        for i in range(256):
            x = 0 if i == 0 else gpow(i, 254)
            s = x ^ rotl(x, 1) ^ rotl(x, 2) ^ rotl(x, 3) ^ rotl(x, 4) ^ 0x63
            sbox[i] = s; inv[s] = i
        return sbox, inv
    _SBOX, _INV_SBOX = _build_sboxes()
    _RCON = (0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36)
    def _expand_key(key):
        ek = list(key); r = 0; i = len(ek)
        # assume 128-bit key (16 bytes)
        while i < 176:
            t = ek[i-4:i]
            if i % 16 == 0:
                t = [_SBOX[t[1]] ^ _RCON[r], _SBOX[t[2]], _SBOX[t[3]], _SBOX[t[0]]]; r += 1
            for b in t:
                ek.append(ek[i-16] ^ b)
            i += 1
        return ek
    def _inv_mix_columns(s):
        for c in range(4):
            i = 4*c; a0,a1,a2,a3 = s[i],s[i+1],s[i+2],s[i+3]
            s[i]   = _gf_mul(a0,14)^_gf_mul(a1,11)^_gf_mul(a2,13)^_gf_mul(a3,9)
            s[i+1] = _gf_mul(a0,9) ^_gf_mul(a1,14)^_gf_mul(a2,11)^_gf_mul(a3,13)
            s[i+2] = _gf_mul(a0,13)^_gf_mul(a1,9) ^_gf_mul(a2,14)^_gf_mul(a3,11)
            s[i+3] = _gf_mul(a0,11)^_gf_mul(a1,13)^_gf_mul(a2,9) ^_gf_mul(a3,14)
    def _pure_aes_decrypt_block(block, ek):
        s = list(block)
        def add_rk(rnd):
            for i in range(16): s[i] ^= ek[rnd*16+i]
        def inv_shift_rows():
            for r in range(1,4):
                row = [s[4*c+r] for c in range(4)]; row = row[-r:] + row[:-r]
                for c in range(4): s[4*c+r] = row[c]
        add_rk(10)
        for rnd in range(9,0,-1):
            inv_shift_rows()
            for i in range(16): s[i] = _INV_SBOX[s[i]]
            add_rk(rnd); _inv_mix_columns(s)
        inv_shift_rows()
        for i in range(16): s[i] = _INV_SBOX[s[i]]
        add_rk(0); return bytes(s)
    def _pure_aes_ecb_decrypt(key, data):
        ek = _expand_key(key)
        return b"".join(_pure_aes_decrypt_block(data[i:i+16], ek) for i in range(0, len(data), 16))
    def _pure_aes_cbc_decrypt(key, iv, data):
        ek = _expand_key(key)
        out = bytearray()
        prev = iv
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            dec = _pure_aes_decrypt_block(block, ek)
            out_block = bytes(a ^ b for a,b in zip(dec, prev))
            out.extend(out_block)
            prev = block
        return bytes(out)

# AES wrappers (ECB/CBC) that use available backend
def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    if _BACKEND == "pycryptodome":
        from Crypto.Cipher import AES as AES_C
        return AES_C.new(key, AES_C.MODE_ECB).decrypt(data)
    elif _BACKEND == "cryptography":
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=__import__('cryptography').hazmat.backends.default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()
    else:
        return _pure_aes_ecb_decrypt(key, data)

def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if _BACKEND == "pycryptodome":
        from Crypto.Cipher import AES as AES_C
        return AES_C.new(key, AES_C.MODE_CBC, iv).decrypt(data)
    elif _BACKEND == "cryptography":
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=__import__('cryptography').hazmat.backends.default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()
    else:
        return _pure_aes_cbc_decrypt(key, iv, data)

# ---------------------------
# Utilities & heuristics
# ---------------------------
def md5_key(s: str) -> bytes:
    # compatibility with original: md5 hex, take bytes of 8..24 hex -> 16 ascii hex chars -> bytes
    # Original returned ascii hex slice; preserve behaviour for compatibility
    hexdig = hashlib.md5(s.encode()).hexdigest()[8:24].lower()
    # Interpret hex string as hex bytes if possible, else use ascii bytes
    try:
        return bytes.fromhex(hexdig)
    except Exception:
        return hexdig.encode()[:16].ljust(16, b'\x00')

def pkcs7_unpad(data: bytes) -> bytes:
    if not data: raise ValueError("empty")
    pad = data[-1]
    if pad < 1 or pad > 16: raise ValueError("bad pad")
    if data[-pad:] != bytes([pad]) * pad: raise ValueError("bad pad bytes")
    return data[:-pad]

def calculate_entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = [0]*256
    for b in data: freq[b] += 1
    length = len(data); ent = 0.0
    for f in freq:
        if f:
            p = f/length; ent -= p * math.log2(p)
    return ent

_WORD_RE = re.compile(r"[a-zA-Z]{4,}")
_COMMON_TLD = re.compile(r"\.[a-z]{2,4}(?:/|\s|$)")
def readability_score(s: str) -> float:
    if not s or len(s) < 3: return 0.0
    try: enc = s.encode("utf-8")
    except Exception: return 0.0
    printable = sum(1 for ch in s if ch.isprintable() or ch in "\r\n\t")
    ratio = printable / len(s)
    ent = calculate_entropy(enc)
    ent_penalty = max(0.0, (ent - 5.0) / 3.0)
    bonus = 0.0
    if "http://" in s or "https://" in s: bonus += 0.35
    if _COMMON_TLD.search(s): bonus += 0.25
    if _WORD_RE.search(s): bonus += 0.12
    if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", s): bonus += 0.10
    score = max(0.0, min(1.0, ratio - ent_penalty + bonus))
    return score

# ---------------------------
# Candidate extraction
# ---------------------------
RE_SCKIT = re.compile(r"ScKit-[0-9a-fA-F]{8,}")
RE_HEX   = re.compile(r"\b[0-9a-fA-F]{32,}\b")
RE_BYTES = re.compile(r"\b\d{1,3}(?:\s*,\s*\d{1,3}){3,}\b")
RE_B64   = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])")
RE_B64U  = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{20,}={0,2}(?![A-Za-z0-9_=-])")
RE_ASC85 = re.compile(r"(?<!\S)[!<-~]{20,}(?!\S)")  # crude ascii85 candidate
RE_PCT   = re.compile(r"%[0-9A-Fa-f]{2}")
def extract_candidates(data: bytes, use_b64: bool) -> List[str]:
    text = data.decode("latin-1", errors="ignore")
    found = set()
    found.update(RE_SCKIT.findall(text))
    found.update(RE_HEX.findall(text))
    found.update(RE_BYTES.findall(text))
    found.update(RE_B64.findall(text))
    if use_b64:
        found.update(RE_B64U.findall(text))
        found.update(RE_ASC85.findall(text))
    # also pick up typical short tokens (>=12) for bruteforce attempts
    for m in re.findall(r"[A-Za-z0-9_\-+/=]{12,}", text):
        if len(m) >= 12: found.add(m)
    return list(found)

# ---------------------------
# Decoding helpers
# ---------------------------
def try_base64_variants(tok: str) -> List[bytes]:
    results = []
    # standard b64
    try:
        b = base64.b64decode(tok, validate=True)
        results.append(b)
    except Exception: pass
    # urlsafe
    try:
        padding = '=' * (-len(tok) % 4)
        b = base64.urlsafe_b64decode(tok + padding)
        results.append(b)
    except Exception: pass
    # ascii85 / base85
    try:
        b = base64.a85decode(tok)
        results.append(b)
    except Exception: pass
    try:
        b = base64.b85decode(tok)
        results.append(b)
    except Exception: pass
    return results

def try_unescape_layers(raw: bytes) -> List[bytes]:
    out = []
    # try zlib
    try:
        out.append(zlib.decompress(raw))
    except Exception: pass
    # try gzip
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
            out.append(gz.read())
    except Exception: pass
    return out

def try_text_decodes(data: bytes) -> List[str]:
    decs = []
    for enc in ("utf-8","latin-1","utf-16","ascii","cp1252"):
        try:
            decs.append(data.decode(enc))
        except Exception:
            pass
    return decs

# ---------------------------
# Core decode_token (multi-method)
# ---------------------------
def decode_token(token: str, keys: List[str], use_b64: bool, try_aes_cbc: bool, try_rc4: bool,
                 try_xor_bruteforce: bool, xor_max_keylen: int, verbose: bool=False) -> Optional[Tuple[float, str, str]]:
    candidates = []
    def add(method: str, plaintext: str):
        score = readability_score(plaintext)
        # small boost for verbose to capture more
        min_score = 0.60 if not verbose else 0.45
        if score >= min_score:
            candidates.append((score, method, plaintext))

    # quick raw text
    for t in try_text_decodes(token.encode("latin-1")):
        if any(ch.isalpha() for ch in t):
            add("RAW-TEXT", t)

    # ScKit / hex-aware AES & RC4 (original behavior)
    hexpart = None
    if token.startswith("ScKit-"):
        hexpart = token[6:]
    elif re.fullmatch(r"[0-9a-fA-F]+", token) and len(token) >= 32:
        hexpart = token
    if hexpart:
        try:
            raw = bytes.fromhex(hexpart if len(hexpart)%2==0 else "0"+hexpart)
            if len(raw) >= 16:
                # AES-ECB attempts
                if len(raw) % 16 == 0:
                    for key in keys:
                        try:
                            pt = pkcs7_unpad(aes_ecb_decrypt(md5_key(key), raw))
                            add(f"AES-ECB [{key}]", pt.decode("utf-8", errors="ignore"))
                        except Exception:
                            pass
                # AES-CBC attempts (if enabled) - assume IV + payload or try zero IV
                if try_aes_cbc and len(raw) >= 32:
                    iv = raw[:16]; payload = raw[16:]
                    for key in keys:
                        try:
                            pt = pkcs7_unpad(aes_cbc_decrypt(md5_key(key), iv, payload))
                            add(f"AES-CBC (IV-first) [{key}]", pt.decode("utf-8", errors="ignore"))
                        except Exception: pass
                        try:
                            pt = pkcs7_unpad(aes_cbc_decrypt(md5_key(key), b"\x00"*16, raw))
                            add(f"AES-CBC (zero-iv) [{key}]", pt.decode("utf-8", errors="ignore"))
                        except Exception: pass
                # RC4
                if try_rc4:
                    for key in keys:
                        try:
                            pt = pure_rc4_decrypt(md5_key(key), raw)
                            add(f"RC4 [{key}]", pt.decode("utf-8", errors="ignore"))
                        except Exception: pass
        except Exception:
            pass

    # Byte list XOR-Index (original)
    if re.fullmatch(r"\d{1,3}(?:\s*,\s*\d{1,3})+", token):
        try:
            data = bytes(int(x) for x in token.replace(" ", "").split(","))
            add("XOR-Index", bytes(b ^ (i & 0xFF) for i, b in enumerate(data)).decode("utf-8", errors="ignore"))
        except Exception: pass

    # Base64 and iterative layers
    if use_b64 and len(token) >= 8:
        b64_results = try_base64_variants(token)
        for raw in b64_results:
            # try direct text
            for t in try_text_decodes(raw):
                add("Base64", t)
            # try AES/RC4 over decoded raw
            for key in keys:
                try:
                    pt = pkcs7_unpad(aes_ecb_decrypt(md5_key(key), raw))
                    add(f"B64+AES-ECB [{key}]", pt.decode("utf-8", errors="ignore"))
                except Exception: pass
                if try_rc4:
                    try:
                        pt = pure_rc4_decrypt(md5_key(key), raw)
                        add(f"B64+RC4 [{key}]", pt.decode("utf-8", errors="ignore"))
                    except Exception: pass
            # try uncompress/unescape layers
            for decompressed in try_unescape_layers(raw):
                for t in try_text_decodes(decompressed):
                    add("Base64+DEFLATE/GZIP", t)
    # ASCII85 / base85-only attempt
    if use_b64 and RE_ASC85.fullmatch(token):
        try:
            raw = base64.a85decode(token)
            for t in try_text_decodes(raw): add("ASCII85", t)
        except Exception: pass

    # URL percent-decode & html unescape
    if "%" in token or "&amp;" in token or "&#" in token:
        try:
            pct = re.sub(r"\+", " ", token)
            pct = bytes(itertools.chain.from_iterable([[int(h,16)] if h else [] for h in re.findall(r"%([0-9A-Fa-f]{2})", pct)]))
            # if that produced bytes, try decode
            for t in try_text_decodes(pct): add("PCT-DECODE", t)
        except Exception: pass
        try:
            add("HTML-UNESCAPE", html.unescape(token))
        except Exception: pass

    # simple hex string -> text
    if re.fullmatch(r"[0-9a-fA-F]{8,}", token):
        try:
            raw = bytes.fromhex(token if len(token)%2==0 else "0"+token)
            for t in try_text_decodes(raw): add("HEX", t)
        except Exception: pass

    # XOR brute force (single-byte)
    if try_xor_bruteforce:
        data = None
        # prefer hex/base64 decoded payload if token looks like such
        if re.fullmatch(r"[0-9a-fA-F]+", token) and len(token) % 2 == 0:
            try: data = bytes.fromhex(token)
            except Exception: data = None
        else:
            try:
                data = token.encode("latin-1")
            except Exception: data = None
        if data:
            # single-byte XOR
            for k in range(256):
                pt = bytes(b ^ k for b in data)
                for t in try_text_decodes(pt):
                    add(f"XOR-1 [{k}]", t)
            # repeating-key small brute (length <= xor_max_keylen)
            maxk = min( xor_max_keylen, 3 )
            # use limited charset to avoid explosion
            charset = b"abcdefghijklmnopqrstuvwxyz0123456789_-.@"
            for L in range(2, maxk+1):
                # guard: avoid combinatorial explosion
                if len(charset) ** L > 50000:
                    break
                for key_bytes in itertools.islice(itertools.product(charset, repeat=L), 0, 50000):
                    key = bytes(key_bytes)
                    pt = bytes(b ^ key[i % len(key)] for i,b in enumerate(data))
                    for t in try_text_decodes(pt):
                        add(f"XOR-K [{key!r}]", t)

    # Wordlist keys (try AES/RC4) — limited attempts per token for performance
    # Already handled when hexpart existed; this will also try B64->AES with wordlist keys earlier via keys list.

    # Return highest scoring candidate
    if candidates:
        return max(candidates, key=lambda x: x[0])
    return None

# ---------------------------
# File iteration & scanning
# ---------------------------
def iter_inputs(path: str) -> Iterator[Tuple[str, bytes]]:
    file_size = os.path.getsize(path)
    if file_size > 200 * 1024 * 1024:
        print(f"{C.WARNING}[!] Large file ({file_size//(1024*1024)}MB); scanning may be slow{C.ENDC}")
    with open(path, "rb") as fh:
        blob = fh.read()
    if blob[:2] == b"PK":
        try:
            zf = zipfile.ZipFile(io.BytesIO(blob))
            names = [n for n in zf.namelist() if re.fullmatch(r"classes\d*\.dex", n)]
            if not names:
                names = [n for n in zf.namelist() if n.endswith((".dex",".smali",".txt",".json",".xml"))]
            for n in names:
                try:
                    yield n, zf.read(n)
                except Exception:
                    continue
        except Exception:
            # fallback: send whole APK bytes
            yield os.path.basename(path), blob
    else:
        yield os.path.basename(path), blob

def short(tok: str, n: int = 60) -> str:
    return tok if len(tok) <= n else tok[:max(20, n//2)] + "..." + tok[-(n//2 - 3):]

# ---------------------------
# Driver: decode_file & CLI
# ---------------------------
def decode_file(path: str, keys: List[str], use_b64: bool, out_path: str, out_jsonl: bool,
                workers: int, try_aes_cbc: bool, try_rc4: bool, try_xor_bruteforce: bool,
                xor_max_keylen: int, verbose: bool, dry_run: bool):
    start = time.time()
    hits = []
    total_candidates = 0
    lock = threading.Lock()
    seen_decoded = set()

    for name, blob in iter_inputs(path):
        print(f"{C.OKCYAN}[*] Scanning {name}: {C.BOLD}", end="")
        cands = extract_candidates(blob, use_b64)
        print(f"{len(cands)} candidates{C.ENDC}")
        total_candidates += len(cands)
        if not cands:
            continue

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(decode_token, tok, keys, use_b64, try_aes_cbc, try_rc4, try_xor_bruteforce, xor_max_keylen, verbose): tok for tok in cands}
            for future in as_completed(futures):
                tok = futures[future]
                try:
                    res = future.result()
                except Exception as e:
                    if verbose:
                        print(f"{C.WARNING}[!] token error {tok!r}: {e}{C.ENDC}")
                    continue
                if res:
                    score, method, pt = res
                    key = (name, pt)
                    with lock:
                        if key in seen_decoded:
                            continue
                        seen_decoded.add(key)
                        hits.append({"file": name, "encoded": tok, "method": method, "decoded": pt, "score": round(score, 3)})
                        if not dry_run:
                            print(f"  {C.OKGREEN}[✓]{C.ENDC} {short(tok)} {C.DIM}→{C.ENDC} {pt!r}   {C.OKCYAN}[{method} s={score:.2f}]{C.ENDC}")
                        else:
                            print(f"  {C.OKBLUE}[DRY]{C.ENDC} {short(tok)}  {C.OKCYAN}[{method} s={score:.2f}]{C.ENDC}")

    elapsed = time.time() - start
    print(f"\n{C.BOLD}[*] TOTAL: scanned {total_candidates} candidates, decoded {len(hits)} unique results in {elapsed:.2f}s{C.ENDC}")

    if dry_run:
        print(f"{C.DIM}[dry-run] no output saved{C.ENDC}")
        return hits

    # Save results
    if out_jsonl:
        with open(out_path, "w", encoding="utf-8") as fh:
            for item in hits:
                fh.write(json.dumps(item, ensure_ascii=False) + "\n")
    else:
        # CSV fallback
        with open(out_path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=["file","encoded","method","decoded","score"])
            writer.writeheader()
            for item in hits:
                writer.writerow(item)
    print(f"{C.OKGREEN}[*] Results saved → {out_path}{C.ENDC}")
    return hits

def decode_string(s: str, keys: List[str], use_b64: bool, try_aes_cbc: bool, try_rc4: bool,
                  try_xor_bruteforce: bool, xor_max_keylen: int, verbose: bool):
    res = decode_token(s, keys, use_b64, try_aes_cbc, try_rc4, try_xor_bruteforce, xor_max_keylen, verbose)
    if res:
        score, method, pt = res
        print(f"{C.OKGREEN}[✓]{C.ENDC} {method} → {pt!r}  (score={score:.2f})")
    else:
        print(f"{C.FAIL}[✗]{C.ENDC} No candidate decoded with current options.")

# ---------------------------
# CLI
# ---------------------------
def main():
    ap = argparse.ArgumentParser(description="Sckit_Advanced — automatic DEX/string decoder")
    ap.add_argument("-s","--string", help="Decode a single pasted string")
    ap.add_argument("-f","--file", help="Scan file (classes.dex / .apk / .smali / text)")
    ap.add_argument("-k","--key", action="append", default=[], help="Extra AES/RC4 key (repeatable)")
    ap.add_argument("-K","--keyfile", help="File with keys (1 per line)")
    ap.add_argument("--wordlist", help="Additional wordlist to try as keys (appended to keys)")
    ap.add_argument("--b64", action="store_true", help="Enable Base64/Base85 scanning")
    ap.add_argument("-o","--output", help="Output path (JSONL if -j, else CSV)", default="results.jsonl")
    ap.add_argument("-j","--jsonl", action="store_true", help="Save as JSONL (default). If not set, CSV is produced.")
    ap.add_argument("-w","--workers", type=int, default=(os.cpu_count() or 4), help="Parallel workers")
    ap.add_argument("--no-rc4", dest="rc4", action="store_false", help="Disable RC4 attempts")
    ap.add_argument("--no-aes-cbc", dest="aescbc", action="store_false", help="Disable AES-CBC attempts")
    ap.add_argument("--xor-brute", action="store_true", help="Enable XOR brute-force (slow)")
    ap.add_argument("--xor-max", type=int, default=2, help="Max repeating-key length for XOR brute force (default 2)")
    ap.add_argument("--verbose", "-v", action="store_true", help="Verbose / lower scoring threshold")
    ap.add_argument("--dry-run", action="store_true", help="Don't save output; just show candidates")
    args = ap.parse_args()

    keys = ["ScKit"] + (args.key or [])
    if args.keyfile:
        try:
            with open(args.keyfile, encoding="utf-8", errors="ignore") as fh:
                keys += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except Exception as e:
            print(f"{C.WARNING}[!] Could not read keyfile: {e}{C.ENDC}")
    if args.wordlist:
        try:
            with open(args.wordlist, encoding="utf-8", errors="ignore") as fh:
                keys += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except Exception as e:
            print(f"{C.WARNING}[!] Could not read wordlist: {e}{C.ENDC}")
    # dedup keys while preserving order
    seen = set(); dedup_keys = []
    for k in keys:
        if k not in seen:
            seen.add(k); dedup_keys.append(k)
    keys = dedup_keys

    print(f"{C.BOLD}{C.HEADER}=== Sckit_Advanced ==={C.ENDC}")
    print(f"{C.DIM}Backend: {_BACKEND} | Keys: {len(keys)} | Workers: {args.workers}{C.ENDC}\n")

    if args.string:
        decode_string(args.string, keys, args.b64, args.aescbc, args.rc4, args.xor_brute, args.xor_max, args.verbose)
    elif args.file:
        out_path = args.output
        decode_file(args.file, keys, args.b64, out_path, args.jsonl, args.workers, args.aescbc, args.rc4, args.xor_brute, args.xor_max, args.verbose, args.dry_run)
    else:
        ap.print_help()

if __name__ == "__main__":
    main()
