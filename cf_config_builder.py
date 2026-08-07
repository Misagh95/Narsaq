#!/usr/bin/env python3
"""
cf_config_builder.py — نسخه کامل
ساخت بهترین کانفیگ‌های Cloudflare از روی لیست آی‌پی و کانفیگ‌های کاربر

پشتیبانی کامل: VLESS, VMess, Trojan, Shadowsocks

استفاده:
    # حالت اسکنر (پیدا کردن آی‌پی تمیز Cloudflare بدون نیاز به VPN — مثل نسخه موبایل):
    python cf_config_builder.py --scan -c configs.txt
    python cf_config_builder.py --scan -c configs.txt --count 500 --v6 --ports 443,2053
    python cf_config_builder.py --scan --count 200 --save-ips clean_ips.txt

    # حالت قدیمی (تست لیست آی‌پی موجود):
    python cf_config_builder.py ips.txt -c configs.txt
    python cf_config_builder.py ips.txt -c configs.txt --top 30 --timeout 5
"""

import argparse
import base64
import glob
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import (
    parse_qs,
    quote,
    unquote,
    urlencode,
    urlparse,
    urlunparse,
)

VERSION = "1.0.0"

# ──────────────────────────────────────────────
#  آی‌پی
# ──────────────────────────────────────────────

def load_ips(path):
    """خواندن آی‌پی‌ها از فایل (IPv4 و IPv6)"""
    ips, seen = [], set()
    with open(path, "r", encoding="utf-8-sig") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # حذف پورت احتمالی
            token = line.split()[0]
            if token.startswith("["):
                token = token[1:].split("]")[0]
            else:
                # فقط برای IPv4 پورت بعد از : حذف شود
                if token.count(":") == 1:
                    token = token.split(":")[0]
            try:
                ip = str(ipaddress.ip_address(token))
            except ValueError:
                continue
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
    return ips


# ──────────────────────────────────────────────
#  رنج‌های Cloudflare و تولید آی‌پی (مثل نسخه موبایل)
# ──────────────────────────────────────────────

# رنج‌های منتشرشده Cloudflare (https://www.cloudflare.com/ips-v4/)
CLOUDFLARE_IPV4_CIDRS = [
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
]

# رنج‌های منتشرشده IPv6 (https://www.cloudflare.com/ips-v6/)
CLOUDFLARE_IPV6_CIDRS = [
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
]

# SNI‌های چرخشی — باعث می‌شود DPI نتواند اتصال را بلاک کند
SNI_HOSTNAMES = [
    "speed.cloudflare.com",
    "www.cloudflare.com",
    "cloudflare.com",
    "1.1.1.1.cdn.cloudflare.net",
]

def set_custom_snis(snis):
    """تنظیم SNI‌های سفارشی از سمت کاربر یا رابط گرافیکی برای تست TLS"""
    global SNI_HOSTNAMES
    if isinstance(snis, str):
        parts = [s.strip() for s in snis.replace(";", ",").split(",") if s.strip()]
        if parts:
            SNI_HOSTNAMES = parts
    elif isinstance(snis, (list, tuple)) and snis:
        SNI_HOSTNAMES = list(snis)

# اندازه نمونه‌ها (مثل نسخه موبایل)
DOWNLOAD_SAMPLE_BYTES = 64 * 1024      # پروب دانلود
SPEED_SAMPLE_BYTES = 512 * 1024        # تست سرعت
VERIFY_TOP_COUNT = 50                  # کاندیدهای TLS
VERIFY_SAMPLES = 3                     # نمونه تأیید
LOSS_TEST_SAMPLES = 10                 # نمونه تست افت
SPEED_TEST_COUNT = 10                  # کاندیدهای تست سرعت


def parse_cidr_v4(cidr):
    """تبدیل CIDR به (شروع, اندازه)"""
    ip_part, prefix = cidr.split("/")
    prefix = int(prefix)
    ip_int = int(ipaddress.IPv4Address(ip_part))
    size = 1 << (32 - prefix)
    base = ip_int & ~(size - 1)
    return base, size


def random_v4_in(base, size, rng):
    """آی‌پی تصادفی داخل بلوک (بدون آدرس شبکه و برودکست)"""
    if size <= 2:
        return base
    return base + rng.randrange(1, size - 1)


def random_v6_in(network, rng):
    """آی‌پی تصادفی داخل بلوک IPv6"""
    host_bits = 128 - network.prefixlen
    if host_bits <= 0:
        return str(network.network_address)
    return str(network.network_address + rng.getrandbits(host_bits))


def generate_random_ips(count):
    """تولید آی‌پی تصادفی IPv4 از رنج‌های Cloudflare (نمونه‌برداری وزنی)"""
    blocks = [parse_cidr_v4(c) for c in CLOUDFLARE_IPV4_CIDRS]
    total = sum(size for _, size in blocks)
    rng = random.Random()
    seen, attempts = set(), 0
    max_attempts = count * 8
    while len(seen) < count and attempts < max_attempts:
        attempts += 1
        r = rng.randrange(total)
        for base, size in blocks:
            if r < size:
                ip = random_v4_in(base, size, rng)
                seen.add(str(ipaddress.IPv4Address(ip)))
                break
            r -= size
    return list(seen)


def generate_random_ips_v6(count):
    """تولید آی‌پی تصادفی IPv6 از رنج‌های Cloudflare"""
    networks = []
    for cidr in CLOUDFLARE_IPV6_CIDRS:
        try:
            networks.append(ipaddress.IPv6Network(cidr))
        except ValueError:
            continue
    if not networks:
        return []
    total = sum(net.num_addresses for net in networks)
    rng = random.Random()
    seen, attempts = set(), 0
    max_attempts = count * 8
    while len(seen) < count and attempts < max_attempts:
        attempts += 1
        r = rng.randrange(total)
        for net in networks:
            if r < net.num_addresses:
                seen.add(random_v6_in(net, rng))
                break
            r -= net.num_addresses
    return list(seen)


def ip_to_int_v4(ip):
    """IPv4 به عدد صحیح"""
    try:
        return int(ipaddress.IPv4Address(ip))
    except ValueError:
        return None


def int_to_ip_v4(value):
    """عدد صحیح به IPv4"""
    return str(ipaddress.IPv4Address(value))


def neighbors_of(ip, count):
    """آی‌پی‌های همسایه داخل همان بلوک Cloudflare —
    آی‌پی‌های تمیز معمولاً خوشه‌ای‌اند (مثل نسخه موبایل)."""
    if count <= 0:
        return []
    value = ip_to_int_v4(ip)
    if value is None:
        return []
    block = None
    for cidr in CLOUDFLARE_IPV4_CIDRS:
        base, size = parse_cidr_v4(cidr)
        if base <= value < base + size:
            block = (base, size)
            break
    if block is None:
        return []
    base, size = block
    first_usable = base + 1
    last_usable = base + size - 2
    neighbors = []
    distance = 1
    while len(neighbors) < count and (
        value - distance >= first_usable or value + distance <= last_usable
    ):
        if value + distance <= last_usable:
            neighbors.append(int_to_ip_v4(value + distance))
        if len(neighbors) < count and value - distance >= first_usable:
            neighbors.append(int_to_ip_v4(value - distance))
        distance += 1
    return neighbors


def neighbors_of_multi(seeds, count):
    """همسایه‌های چند آی‌پی seed به صورت متناوب"""
    if not seeds or count <= 0:
        return []
    seen = []
    candidates = [neighbors_of(s, count) for s in list(dict.fromkeys(seeds))]
    for index in range(count):
        for neighbors in candidates:
            if index < len(neighbors) and neighbors[index] not in seen:
                seen.append(neighbors[index])
            if len(seen) == count:
                break
        if len(seen) == count:
            break
    return seen


def generate_from_custom_ranges(text, count):
    """تولید آی‌پی از رنج‌های دلخواه کاربر (IP خام، CIDR، ip:port)"""
    if not text.strip():
        return []
    networks = []
    direct = set()
    rng = random.Random()

    for raw_line in text.splitlines():
        line = raw_line.split("#")[0].strip()
        if not line:
            continue
        token = line.split()[0].strip()
        if not token:
            continue
        if token.startswith("["):
            close = token.find("]")
            if close < 0:
                continue
            addr = token[1:close].strip()
            try:
                direct.add(str(ipaddress.ip_address(addr)))
            except ValueError:
                pass
            continue
        if "/" in token:
            try:
                networks.append(ipaddress.ip_network(token, strict=False))
            except ValueError:
                pass
            continue
        if token.count(":") == 1:
            ip_part, port_part = token.rsplit(":", 1)
            if port_part.isdigit():
                token = ip_part
        try:
            ip = ipaddress.ip_address(token)
        except ValueError:
            continue
        if ip.version == 4:
            networks.append(ipaddress.ip_network(f"{ip}/32"))
        else:
            direct.add(str(ip))

    if not networks:
        return list(direct)[:count]

    total = sum(n.num_addresses for n in networks)
    seen = set(direct)
    attempts = 0
    max_attempts = count * 10 + len(direct) * 2
    while len(seen) < count and attempts < max_attempts:
        attempts += 1
        r = rng.randrange(total)
        for net in networks:
            if r < net.num_addresses:
                if net.version == 4:
                    base = int(net.network_address)
                    size = net.num_addresses
                    ip = random_v4_in(base, size, rng)
                    seen.add(str(ipaddress.IPv4Address(ip)))
                else:
                    seen.add(random_v6_in(net, rng))
                break
            r -= net.num_addresses
    return list(seen)[:count]


def generate_scan_scope(count, enable_v6, custom_ranges):
    """تولید لیست کامل آی‌پی برای اسکن"""
    scope = []
    if custom_ranges.strip():
        scope += generate_from_custom_ranges(
            custom_ranges, max(count // 2, 1)
        )
    scope += generate_random_ips(count)
    if enable_v6:
        scope += generate_random_ips_v6(min(count, max(count // 3, 50)))
    return list(dict.fromkeys(scope))


# ──────────────────────────────────────────────
#  پارسر کانفیگ‌ها
# ──────────────────────────────────────────────

def _b64_decode(data):
    """دیکد Base64 با پدینگ خودکار (standard + urlsafe)"""
    cleaned = data.replace("\n", "").replace("\r", "").strip()
    if not cleaned:
        return None
    rem = len(cleaned) % 4
    if rem:
        cleaned += "=" * (4 - rem)
    for use_urlsafe in (False, True):
        try:
            if use_urlsafe:
                raw = base64.urlsafe_b64decode(cleaned)
            else:
                raw = base64.b64decode(cleaned, validate=False)
            return raw.decode("utf-8", errors="replace")
        except Exception:
            continue
    return None


def _parse_vless(line):
    """پارس کانفیگ VLESS"""
    u = urlparse(line)
    if not u.hostname or not u.username:
        return None
    port = u.port or 443
    qs = parse_qs(u.query, keep_blank_values=True)
    return {
        "type": "vless",
        "uuid": u.username,
        "original_host": u.hostname,
        "port": port,
        "query_string": u.query,
        "query_params": qs,
        "fragment": unquote(u.fragment) if u.fragment else "",
        "raw": line,
        # برای تست
        "test_host": unquote(
            (qs.get("sni") or qs.get("host") or [u.hostname])[0]
        ),
        "test_path": unquote((qs.get("path") or ["/"])[0]),
        "test_tls": unquote(
            (qs.get("security") or ["none"])[0]
        ).lower() not in ("none", "reality", ""),
    }


def _parse_trojan(line):
    """پارس کانفیگ Trojan"""
    u = urlparse(line)
    if not u.hostname or not u.username:
        return None
    port = u.port or 443
    qs = parse_qs(u.query, keep_blank_values=True)
    return {
        "type": "trojan",
        "password": u.username,
        "original_host": u.hostname,
        "port": port,
        "query_string": u.query,
        "query_params": qs,
        "fragment": unquote(u.fragment) if u.fragment else "",
        "raw": line,
        "test_host": unquote(
            (qs.get("sni") or qs.get("host") or [u.hostname])[0]
        ),
        "test_path": unquote((qs.get("path") or ["/"])[0]),
        "test_tls": unquote(
            (qs.get("security") or ["tls"])[0]
        ).lower() not in ("none", ""),
    }


def _parse_vmess(line):
    """پارس کانفیگ VMess (base64 JSON)"""
    payload = line.split("://", 1)[1].split("#")[0].strip()
    decoded = _b64_decode(payload)
    if not decoded:
        return None
    try:
        obj = json.loads(decoded)
    except (json.JSONDecodeError, ValueError):
        return None

    host = str(obj.get("add", "")).strip()
    uuid_val = str(obj.get("id", "")).strip()
    if not host or not uuid_val:
        return None

    port = 443
    try:
        port = int(obj.get("port", 443))
    except (ValueError, TypeError):
        pass

    sni = str(obj.get("sni", "")).strip()
    ws_host = str(obj.get("host", "")).strip()
    path = str(obj.get("path", "")).strip()
    tls = str(obj.get("tls", "")).strip().lower()

    # fragment از بعد # اصلی
    frag = ""
    if "#" in line:
        frag = unquote(line.split("#", 1)[1])

    return {
        "type": "vmess",
        "vmess_obj": obj,
        "original_host": host,
        "port": port,
        "fragment": frag,
        "raw": line,
        "test_host": sni or ws_host or host,
        "test_path": path or "/",
        "test_tls": tls not in ("", "none"),
    }


def _parse_shadowsocks(line):
    """پارس کانفیگ Shadowsocks"""
    body = line.split("://", 1)[1]
    frag = ""
    if "#" in body:
        body, frag_raw = body.rsplit("#", 1)
        frag = unquote(frag_raw)

    query_string = ""
    if "?" in body:
        body, query_string = body.split("?", 1)

    # دو فرمت: method:pass@host:port یا base64@host:port
    if "@" in body:
        cred_part, server_part = body.rsplit("@", 1)
        # ممکنه cred_part خودش base64 باشه
        decoded_cred = _b64_decode(cred_part)
        if decoded_cred and ":" in decoded_cred:
            method_pass = decoded_cred
        elif ":" in cred_part:
            method_pass = unquote(cred_part)
        else:
            return None
    else:
        # همه‌اش base64 هست
        decoded = _b64_decode(body)
        if not decoded or "@" not in decoded:
            return None
        method_pass, server_part = decoded.rsplit("@", 1)

    # پارس host:port از server_part
    if server_part.startswith("["):
        # IPv6
        close = server_part.find("]")
        if close < 0:
            return None
        host = server_part[1:close]
        rest = server_part[close + 1:]
        port = 443
        if rest.startswith(":"):
            try:
                port = int(rest[1:])
            except ValueError:
                pass
    else:
        parts = server_part.rsplit(":", 1)
        host = parts[0]
        port = 443
        if len(parts) == 2:
            try:
                port = int(parts[1])
            except ValueError:
                pass

    if not host:
        return None

    return {
        "type": "shadowsocks",
        "method_pass": method_pass,
        "original_host": host,
        "port": port,
        "query_string": query_string,
        "fragment": frag,
        "raw": line,
        "test_host": host,
        "test_path": "/",
        "test_tls": False,
    }


def parse_config_line(line):
    """پارس یک خط کانفیگ — تشخیص خودکار نوع"""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    lower = line.lower()
    try:
        if lower.startswith("vless://"):
            return _parse_vless(line)
        if lower.startswith("trojan://"):
            return _parse_trojan(line)
        if lower.startswith("vmess://"):
            return _parse_vmess(line)
        if lower.startswith("ss://"):
            return _parse_shadowsocks(line)
    except Exception:
        pass
    return None


def load_configs(path):
    """خواندن تمام کانفیگ‌ها از فایل"""
    configs = []
    with open(path, "r", encoding="utf-8-sig") as fh:
        for line in fh:
            cfg = parse_config_line(line)
            if cfg:
                configs.append(cfg)
    return configs


# ──────────────────────────────────────────────
#  بازسازی کانفیگ با آی‌پی جدید
# ──────────────────────────────────────────────

FRAG_NUM_RE = re.compile(r"^(.*?)(\d+)(\s*-\s*.*)$")


def _make_fragment(original_frag, rank):
    """ساخت fragment با شماره رتبه"""
    m = FRAG_NUM_RE.match(original_frag)
    if m:
        prefix, suffix = m.group(1), m.group(3)
        return f"{prefix}{rank}{suffix}"
    prefix = (original_frag + " ") if original_frag else ""
    return f"{prefix}{rank}".strip()


def _format_ip(ip):
    """فرمت آی‌پی برای استفاده در URI"""
    if ":" in ip:
        return f"[{ip}]"
    return ip


def _normalize_fm(raw):
    """Convert fm to the NEW Xray FinalMask format (type + settings).

    Old cf-optimizor / PattNG 2.2.6-P2 format:
        {"tcp":[{"fragment":"tlshello","lengths":["5","94","1"],...}]}
    New PattNG (Xray core with FinalMask) requires:
        {"tcp":[{"type":"fragment","settings":{"packets":"tlshello",...}}]}
    Without "type" the core fails with "failed to build mask with type >
    unknown config id".  Old-format entries are converted, everything else
    is left untouched (minified).
    """
    if not raw:
        return raw
    try:
        obj = json.loads(raw)
    except Exception:
        return raw
    if not isinstance(obj, dict):
        return raw
    changed = False
    for key in ("tcp", "udp"):
        entries = obj.get(key)
        if not isinstance(entries, list):
            continue
        for i, entry in enumerate(entries):
            if not isinstance(entry, dict) or entry.get("type"):
                continue
            if "fragment" not in entry:
                continue
            settings = {}
            for fk in ("lengths", "delays", "maxSplit"):
                if fk in entry:
                    settings[fk] = entry[fk]
            if isinstance(entry.get("settings"), dict):
                settings.update(entry["settings"])
            entries[i] = {
                "type": "fragment",
                "settings": {"packets": entry["fragment"], **settings},
            }
            changed = True
    if not changed:
        return raw
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _normalize_fm_in_query(query):
    """Surgically rewrite only the fm= parameter inside a query string."""
    if not query or "fm=" not in query:
        return query

    def _repl(m):
        val = unquote(m.group(0).split("=", 1)[1])
        return "fm=" + quote(_normalize_fm(val), safe="")

    return re.sub(r"(^|&)fm=[^&]*", lambda m: m.group(1) + _repl(m), query, count=1)


def _config_identity(cfg):
    """Unique identity of a config: same endpoint + same credentials."""
    t = cfg.get("type")
    if t == "vless":
        cred = cfg.get("uuid", "")
    elif t == "trojan":
        cred = cfg.get("password", "")
    elif t == "shadowsocks":
        cred = cfg.get("method_pass", "")
    elif t == "vmess":
        obj = cfg.get("vmess_obj", {})
        cred = json.dumps(
            {k: v for k, v in obj.items() if k not in ("ps", "add")},
            sort_keys=True,
        )
    else:
        cred = cfg.get("raw", "")
    return (t, cfg.get("test_host", ""), cfg.get("port"), cred)

def rebuild_vless(cfg, ip, rank):
    """بازسازی کانفیگ VLESS با آی‌پی جدید"""
    addr = _format_ip(ip)
    name = _make_fragment(cfg["fragment"], rank)
    query = _normalize_fm_in_query(cfg["query_string"])
    q_part = f"?{query}" if query else ""
    f_part = f"#{quote(name, safe='')}" if name else ""
    return f"vless://{cfg['uuid']}@{addr}:{cfg['port']}{q_part}{f_part}"


def rebuild_trojan(cfg, ip, rank):
    """بازسازی کانفیگ Trojan با آی‌پی جدید"""
    addr = _format_ip(ip)
    name = _make_fragment(cfg["fragment"], rank)
    query = _normalize_fm_in_query(cfg["query_string"])
    q_part = f"?{query}" if query else ""
    f_part = f"#{quote(name, safe='')}" if name else ""
    return f"trojan://{cfg['password']}@{addr}:{cfg['port']}{q_part}{f_part}"


def rebuild_vmess(cfg, ip, rank):
    """بازسازی کانفیگ VMess با آی‌پی جدید"""
    obj = dict(cfg["vmess_obj"])  # کپی
    obj["add"] = ip  # فقط آدرس عوض می‌شود
    # ps (نام) را آپدیت می‌کنیم
    name = _make_fragment(cfg["fragment"], rank)
    obj["ps"] = name

    json_str = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    encoded = base64.b64encode(json_str.encode("utf-8")).decode("ascii")
    frag = f"#{quote(name, safe='')}" if name else ""
    return f"vmess://{encoded}{frag}"


def rebuild_shadowsocks(cfg, ip, rank):
    """بازسازی کانفیگ Shadowsocks با آی‌پی جدید"""
    addr = _format_ip(ip)
    name = _make_fragment(cfg["fragment"], rank)

    # method:pass را base64 می‌کنیم
    cred_b64 = base64.b64encode(
        cfg["method_pass"].encode("utf-8")
    ).decode("ascii").rstrip("=")

    q_part = f"?{cfg['query_string']}" if cfg.get("query_string") else ""
    f_part = f"#{quote(name, safe='')}" if name else ""
    return f"ss://{cred_b64}@{addr}:{cfg['port']}{q_part}{f_part}"


def rebuild_config(cfg, ip, rank):
    """بازسازی کانفیگ — تشخیص خودکار نوع"""
    t = cfg["type"]
    if t == "vless":
        return rebuild_vless(cfg, ip, rank)
    if t == "trojan":
        return rebuild_trojan(cfg, ip, rank)
    if t == "vmess":
        return rebuild_vmess(cfg, ip, rank)
    if t == "shadowsocks":
        return rebuild_shadowsocks(cfg, ip, rank)
    return None


# ──────────────────────────────────────────────
#  تست آی‌پی
# ──────────────────────────────────────────────

def test_ip(ip, host, port, path, use_tls, timeout):
    """تست اتصال TCP/TLS به یک آی‌پی و اندازه‌گیری تاخیر"""
    t0 = time.perf_counter()
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: CFConfigBuilder/2.0\r\n"
            "Connection: close\r\n\r\n"
        )
        sock.sendall(req.encode())
        data = sock.recv(1)
        if not data:
            return None
        return (time.perf_counter() - t0) * 1000.0
    except (OSError, ssl.SSLError, socket.timeout):
        return None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def run_test_phase(ips, host, port, path, use_tls, timeout, workers, label, samples=1, on_progress=None):
    """اجرای تست روی لیست آی‌پی‌ها"""
    results = {}
    total = len(ips)
    done = [0]

    def work(ip):
        latencies = []
        for _ in range(samples):
            r = test_ip(ip, host, port, path, use_tls, timeout)
            if r is not None:
                latencies.append(r)
        if latencies:
            latencies.sort()
            return ip, latencies[len(latencies) // 2]  # میانه
        return ip, None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(work, ip): ip for ip in ips}
        for fut in as_completed(futures):
            ip, lat = fut.result()
            if lat is not None:
                results[ip] = lat
            done[0] += 1
            pct = done[0] * 100 // total
            bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
            sys.stdout.write(f"\r  {label}: |{bar}| {done[0]}/{total} ({pct}%)")
            sys.stdout.flush()
            if on_progress:
                on_progress(done[0], total, label)
    sys.stdout.write("\n")
    return results


# ──────────────────────────────────────────────
#  اسکنر آی‌پی تمیز Cloudflare (مثل نسخه موبایل)
# ──────────────────────────────────────────────

def tls_trace_probe(ip, port, timeout):
    """TLS + SNI + GET /cdn-cgi/trace → بررسی colo=
    برمی‌گرداند (latency_ms, colo) یا None اگر آی‌پی معتبر نباشد.
    برای هر آی‌پی SNI‌های مختلف امتحان می‌شود (ضد DPI) — هر SNI با
    یک اتصال تازه (اتصال شکست‌خورده قابل استفاده مجدد نیست)."""
    ctx = ssl.create_default_context()
    for sni in SNI_HOSTNAMES:
        t_start = time.perf_counter()
        raw = None
        tls = None
        try:
            # بودجه زمانی: TCP 1/4، دست‌دهی TLS 1/2، HTTP باقی‌مانده
            dial_timeout = max(timeout / 4, min(2.0, timeout))
            handshake_timeout = max(timeout / 2, min(3.0, timeout))

            raw = socket.create_connection((ip, port), timeout=dial_timeout)
            raw.settimeout(handshake_timeout)

            # wrap_socket خودش handshake را انجام می‌دهد (do_handshake_on_connect)
            tls = ctx.wrap_socket(raw, server_hostname=sni)
            tls.settimeout(handshake_timeout)

            request = (
                f"GET /cdn-cgi/trace HTTP/1.1\r\n"
                f"Host: {sni}\r\n"
                "User-Agent: NarsaqDesktop/1.0\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n\r\n"
            )
            tls.sendall(request.encode("ascii"))

            remaining = max(timeout - (time.perf_counter() - t_start), 0.5)
            tls.settimeout(remaining)
            response = read_http_response(tls, 4096)
            colo = parse_colo(response)
            if colo:
                latency = (time.perf_counter() - t_start) * 1000.0
                # بررسی پایداری: اتصال باید چند لحظه زنده بماند
                # (زمان این پروب در تاخیر لحاظ نمی‌شود — فقط اتصال را راستی‌آزمایی می‌کند)
                # اگر روی این SNI ناپایدار بود، SNI بعدی را امتحان می‌کنیم
                if not tls_stability_probe(ip, port, timeout):
                    continue
                return latency, colo
        except (OSError, ssl.SSLError, socket.timeout):
            continue
        finally:
            try:
                if tls:
                    tls.close()
            except Exception:
                pass
            try:
                if raw:
                    raw.close()
            except Exception:
                pass
    return None


def tls_stability_probe(ip, port, timeout):
    """بررسی پایداری: DPI گاهی بعد از handshake اتصال را RST می‌کند.
    این پروب مطمئن می‌شود اتصال چند لحظه زنده می‌ماند."""
    raw = None
    tls = None
    try:
        dial_timeout = max(timeout / 4, min(2.0, timeout))
        handshake_timeout = max(timeout / 2, min(3.0, timeout))
        raw = socket.create_connection((ip, port), timeout=dial_timeout)
        raw.settimeout(handshake_timeout)
        ctx = ssl.create_default_context()
        sni = SNI_HOSTNAMES[0]
        tls = ctx.wrap_socket(raw, server_hostname=sni)
        tls.settimeout(handshake_timeout)

        idle_hold = min(1500, max(500, int(timeout * 1000 / 2)))
        tls.settimeout(idle_hold / 1000.0)
        try:
            # Timeout اینجا انتظار می‌رود (سرور در حالت idle داده نمی‌فرستد).
            # EOF (-1) یا هر خطایی یعنی اتصال کشته شده.
            data = tls.recv(1)
            return data != b""
        except socket.timeout:
            return True
    except Exception:
        return False
    finally:
        try:
            if tls:
                tls.close()
        except Exception:
            pass
        try:
            if raw:
                raw.close()
        except Exception:
            pass


def parse_colo(response):
    """استخراج کد colo از پاسخ /cdn-cgi/trace"""
    if not response:
        return None
    for line in response.splitlines():
        if line.startswith("colo="):
            value = line.split("=", 1)[1].strip()
            return value or None
    return None


def read_http_response(sock, max_bytes=4096):
    """خواندن پاسخ HTTP از سوکت — تا پیدا شدن colo= یا EOF ادامه می‌دهد
    (بدنه /cdn-cgi/trace حامل colo= است، پس نباید در انتهای هدر بایستیم)."""
    buf = bytearray()
    try:
        while len(buf) < max_bytes:
            chunk = sock.recv(512)
            if not chunk:
                break
            buf += chunk
            if b"colo=" in buf:
                break
    except (socket.timeout, OSError, ssl.SSLError):
        pass
    return bytes(buf).decode("iso-8859-1", errors="replace")


def tls_download_probe(ip, port, timeout, want_bytes):
    """دانلود نمونه داده از طریق آی‌پی — بررسی اینکه آی‌پی واقعاً
    می‌تواند ترافیک حمل کند (نه فقط trace). برمی‌گرداند True/False."""
    raw = None
    tls = None
    try:
        dial_timeout = max(timeout / 4, min(2.0, timeout))
        handshake_timeout = max(timeout / 2, min(3.0, timeout))
        sni = "speed.cloudflare.com"

        raw = socket.create_connection((ip, port), timeout=dial_timeout)
        raw.settimeout(handshake_timeout)
        ctx = ssl.create_default_context()
        tls = ctx.wrap_socket(raw, server_hostname=sni)
        tls.settimeout(handshake_timeout)

        request = (
            f"GET /__down?bytes={want_bytes} HTTP/1.1\r\n"
            f"Host: {sni}\r\n"
            "User-Agent: NarsaqDesktop/1.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        )
        tls.sendall(request.encode("ascii"))
        tls.settimeout(timeout)

        total = 0
        status_ok = False
        head = bytearray()
        header_done = False
        buf = bytearray()
        while total < want_bytes * 2:
            try:
                n = tls.recv(8192)
            except socket.timeout:
                break
            if not n:
                break
            buf += n
            if not header_done:
                head += n
                end = head.find(b"\r\n\r\n")
                if end >= 0:
                    header_done = True
                    status_line = bytes(head[:end]).split(b"\r\n", 1)[0]
                    if not (status_line.startswith(b"HTTP/1.1 200") or b" 200 " in status_line):
                        break
                    status_ok = True
                    total = len(buf) - (end + 4)
            else:
                total += len(n)
        return status_ok and total >= want_bytes
    except Exception:
        return False
    finally:
        try:
            if tls:
                tls.close()
        except Exception:
            pass
        try:
            if raw:
                raw.close()
        except Exception:
            pass


def tls_download_mbps(ip, port, timeout):
    """اندازه‌گیری سرعت دانلود واقعی (Mbps) از طریق آی‌پی."""
    raw = None
    tls = None
    try:
        dial_timeout = max(timeout / 4, min(2.0, timeout))
        handshake_timeout = max(timeout / 2, min(3.0, timeout))
        sni = "speed.cloudflare.com"

        raw = socket.create_connection((ip, port), timeout=dial_timeout)
        raw.settimeout(handshake_timeout)
        ctx = ssl.create_default_context()
        tls = ctx.wrap_socket(raw, server_hostname=sni)
        tls.settimeout(handshake_timeout)

        request = (
            f"GET /__down?bytes={SPEED_SAMPLE_BYTES} HTTP/1.1\r\n"
            f"Host: {sni}\r\n"
            "User-Agent: NarsaqDesktop/1.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        )
        tls.sendall(request.encode("ascii"))
        tls.settimeout(timeout)

        total = 0
        status_ok = False
        body_start = 0.0
        head = bytearray()
        header_done = False
        buf = bytearray()
        while total < SPEED_SAMPLE_BYTES * 2:
            try:
                n = tls.recv(8192)
            except socket.timeout:
                break
            if not n:
                break
            buf += n
            if not header_done:
                head += n
                end = head.find(b"\r\n\r\n")
                if end >= 0:
                    header_done = True
                    status_line = bytes(head[:end]).split(b"\r\n", 1)[0]
                    if not (status_line.startswith(b"HTTP/1.1 200") or b" 200 " in status_line):
                        break
                    status_ok = True
                    total = len(buf) - (end + 4)
                    body_start = time.perf_counter()
            else:
                total += len(n)

        if not status_ok or body_start <= 0:
            return None
        elapsed = time.perf_counter() - body_start
        if total < SPEED_SAMPLE_BYTES or elapsed <= 0:
            return None
        return (total * 8.0 / 1_000_000) / elapsed
    except Exception:
        return None
    finally:
        try:
            if tls:
                tls.close()
        except Exception:
            pass
        try:
            if raw:
                raw.close()
        except Exception:
            pass


def run_scan_pipeline(
    scope_ips,
    ports,
    timeout,
    workers,
    enable_tls,
    enable_verify,
    speed_test,
    on_phase=None,
    on_progress=None,
    neighbor_scan=False,
    stats=None,
):
    """پایپلاین ۵ مرحله‌ای اسکن (مثل نسخه موبایل):
    1. TCP pre-scan روی همه آی‌پی:پورت
    2. TLS + SNI + colo بررسی روی برترین‌ها
    3. تأیید چندنمونه + پروب دانلود
    4. تست افت بسته + جیتر
    5. تست سرعت Mbps روی بهترین‌ها
    """
    def progress(done, found, total, phase):
        pct = done * 100 // total if total else 0
        bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
        sys.stdout.write(f"\r  {phase}: |{bar}| {done}/{total} ({pct}%) | found: {found}")
        if on_progress:
            on_progress(done, found, total, phase)
        sys.stdout.flush()

    results = []  # dict: ip, port, tcp_ms, tls_ms, colo, verified, loss, jitter, mbps

    # ─── مرحله ۱: TCP pre-scan ───
    if on_phase:
        on_phase("TCP Test")
    pairs = [(ip, p) for ip in scope_ips for p in ports]
    total_pairs = len(pairs)
    phase1 = []
    done = [0]

    def tcp_work(pair):
        ip, port = pair
        t0 = time.perf_counter()
        try:
            s = socket.create_connection((ip, port), timeout=timeout)
            s.close()
            return pair, (time.perf_counter() - t0) * 1000.0
        except Exception:
            return pair, None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(tcp_work, p): p for p in pairs}
        for fut in as_completed(futures):
            pair, lat = fut.result()
            done[0] += 1
            if lat is not None:
                phase1.append({"ip": pair[0], "port": pair[1], "tcp_ms": lat})
            progress(done[0], len(phase1), total_pairs, "TCP Test")
    sys.stdout.write("\n")
    if not phase1:
        if stats is not None:
            stats.update({"tcp_found": 0, "tls_found": 0, "verify_found": 0, "failed_phase": "TCP Test"})
        return []

    if stats is not None:
        stats["tcp_found"] = len(phase1)

    # ─── مرحله ۱.۵: اسکن همسایگی (آی‌پی‌های تمیز خوشه‌ای‌اند) ───
    if neighbor_scan:
        known_ips = {r["ip"] for r in phase1}
        seeds = [r["ip"] for r in phase1[:5]]
        neighbor_ips = [
            ip for ip in neighbors_of_multi(seeds, min(len(phase1), 100))
            if ip not in known_ips
        ]
        if neighbor_ips:
            if on_phase:
                on_phase("Neighbor Test")
            n_done = [0]
            n_hits = []

            def n_work(pair):
                ip, port = pair
                t0 = time.perf_counter()
                try:
                    s = socket.create_connection((ip, port), timeout=timeout)
                    s.close()
                    return pair, (time.perf_counter() - t0) * 1000.0
                except Exception:
                    return pair, None

            n_pairs = [(ip, p) for ip in neighbor_ips for p in ports]
            with ThreadPoolExecutor(max_workers=min(workers, 60)) as pool:
                futures = {pool.submit(n_work, p): p for p in n_pairs}
                for fut in as_completed(futures):
                    pair, lat = fut.result()
                    n_done[0] += 1
                    if lat is not None:
                        n_hits.append({"ip": pair[0], "port": pair[1], "tcp_ms": lat})
                    progress(
                        n_done[0],
                        len(phase1) + len(n_hits),
                        total_pairs + len(n_pairs),
                        "Neighbor Test",
                    )
            sys.stdout.write("\n")
            phase1.extend(n_hits)
            phase1.sort(key=lambda r: r["tcp_ms"])

    phase1.sort(key=lambda r: r["tcp_ms"])

    # ─── مرحله ۲: TLS + SNI + colo ───
    if enable_tls:
        candidates2 = phase1[:VERIFY_TOP_COUNT]
        phase2 = []
        done[0] = 0

        def tls_work(item):
            r = tls_trace_probe(item["ip"], item["port"], timeout)
            if r:
                return item, r[0], r[1]
            return item, None, None

        with ThreadPoolExecutor(max_workers=min(workers, 30)) as pool:
            futures = {pool.submit(tls_work, c): c for c in candidates2}
            for fut in as_completed(futures):
                item, lat, colo = fut.result()
                done[0] += 1
                if lat is not None:
                    phase2.append({
                        **item, "tls_ms": lat, "colo": colo, "verified": True,
                    })
                progress(done[0], len(phase2), len(candidates2), "TLS Test")
        sys.stdout.write("\n")
        if not phase2:
            if stats is not None:
                stats["tls_found"] = 0
                stats["verify_found"] = 0
                stats["failed_phase"] = "TLS Test"
            return phase1
        phase2.sort(key=lambda r: r.get("tls_ms", 9e9))
        stage = phase2
        if stats is not None:
            stats["tls_found"] = len(phase2)
    else:
        stage = phase1
        if stats is not None:
            stats["tls_found"] = len(phase1)

    # ─── مرحله ۳: تأیید چندنمونه + دانلود ───
    if enable_tls and enable_verify:
        candidates3 = stage[:VERIFY_TOP_COUNT // 2]
        phase3 = []
        done[0] = 0

        def verify_work(item):
            latencies = []
            colo = ""
            for _ in range(VERIFY_SAMPLES):
                r = tls_trace_probe(item["ip"], item["port"], timeout)
                if r:
                    latencies.append(r[0])
                    colo = r[1] or colo
            if len(latencies) >= (VERIFY_SAMPLES + 1) // 2:
                download_ok = tls_download_probe(
                    item["ip"], item["port"], timeout, DOWNLOAD_SAMPLE_BYTES
                )
                if download_ok:
                    latencies.sort()
                    return item, latencies[len(latencies) // 2], colo
            return None

        with ThreadPoolExecutor(max_workers=min(workers, 20)) as pool:
            futures = {pool.submit(verify_work, c): c for c in candidates3}
            for fut in as_completed(futures):
                res = fut.result()
                done[0] += 1
                if res:
                    item, lat, colo = res
                    phase3.append({**item, "tls_ms": lat, "colo": colo, "verified": True})
                progress(done[0], len(phase3), len(candidates3), "Verify")
        sys.stdout.write("\n")
        if phase3:
            phase3.sort(key=lambda r: r.get("tls_ms", 9e9))
            stage = phase3
            if stats is not None:
                stats["verify_found"] = len(phase3)
                stats["failed_phase"] = ""
        else:
            if stats is not None:
                stats["verify_found"] = 0
                stats["failed_phase"] = "Verify"

    # ─── مرحله ۴: تست افت بسته + جیتر ───
    loss_candidates = stage[:25]
    phase4 = []
    done[0] = 0

    def loss_work(item):
        lost = 0
        samples = []
        for _ in range(LOSS_TEST_SAMPLES):
            t0 = time.perf_counter()
            try:
                s = socket.create_connection((item["ip"], item["port"]), timeout=max(timeout / 2, 0.5))
                s.close()
                samples.append((time.perf_counter() - t0) * 1000.0)
            except Exception:
                lost += 1
        if not samples:
            return None
        loss_rate = lost * 100.0 / (lost + len(samples))
        avg = sum(samples) / len(samples)
        variance = sum((x - avg) ** 2 for x in samples) / len(samples)
        jitter = variance ** 0.5
        return {**item, "loss": loss_rate, "jitter": jitter}

    with ThreadPoolExecutor(max_workers=min(workers, 15)) as pool:
        futures = {pool.submit(loss_work, c): c for c in loss_candidates}
        for fut in as_completed(futures):
            res = fut.result()
            done[0] += 1
            if res:
                phase4.append(res)
            progress(done[0], len(phase4), len(loss_candidates), "Loss Test")
    sys.stdout.write("\n")
    if phase4:
        stage = phase4

    # ─── مرحله ۵: تست سرعت Mbps ───
    if speed_test:
        speed_candidates = stage[:SPEED_TEST_COUNT]
        speed_map = {}
        done[0] = 0

        def speed_work(item):
            mbps = tls_download_mbps(item["ip"], item["port"], timeout)
            return item["ip"], item["port"], mbps

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = {pool.submit(speed_work, c): c for c in speed_candidates}
            for fut in as_completed(futures):
                ip, port, mbps = fut.result()
                done[0] += 1
                if mbps is not None:
                    speed_map[(ip, port)] = mbps
                progress(done[0], len(speed_map), len(speed_candidates), "Speed Test")
        sys.stdout.write("\n")
        for item in stage:
            if (item["ip"], item["port"]) in speed_map:
                item["mbps"] = speed_map[(item["ip"], item["port"])]

    # مرتب‌سازی نهایی بر اساس تاخیر کل
    stage.sort(key=lambda r: r.get("tls_ms") or r.get("tcp_ms") or 9e9)
    return stage


# ──────────────────────────────────────────────
#  اندپوینت یکتا برای هر کانفیگ
# ──────────────────────────────────────────────

def get_endpoint(cfg):
    """استخراج اندپوینت تست از کانفیگ"""
    return (
        cfg["test_host"],
        cfg["port"],
        cfg["test_path"],
        cfg["test_tls"],
    )


def unique_endpoints(configs):
    """لیست اندپوینت‌های یکتا"""
    seen = []
    for cfg in configs:
        ep = get_endpoint(cfg)
        if ep not in seen:
            seen.append(ep)
    return seen


# ──────────────────────────────────────────────
#  پیدا کردن فایل کانفیگ پیش‌فرض
# ──────────────────────────────────────────────

def find_config_file():
    """جستجوی خودکار فایل کانفیگ در پوشه فعلی"""
    # فقط فایل‌هایی که نامشان شامل config است (جلوگیری از انتخاب build_log.txt و امثال آن)
    for pattern in ("*config*.txt", "*Config*.txt", "*config*.conf"):
        files = glob.glob(pattern)
        files = [
            f for f in files
            if "ip" not in f.lower()
            and "best" not in f.lower()
            and "output" not in f.lower()
        ]
        if files:
            return max(files, key=os.path.getmtime)
    return None


# ──────────────────────────────────────────────
#  اصلی
# ──────────────────────────────────────────────


# ──────────────────────────────────────────────
#  کانفیگ ساز (مثل نسخه اندروید)
# ──────────────────────────────────────────────

def parse_configs_text(text):
    """پارس کانفیگ‌ها از متن (یک کانفیگ در هر خط)"""
    configs = []
    for line in text.splitlines():
        cfg = parse_config_line(line)
        if cfg:
            configs.append(cfg)
    return configs


def parse_ips_text(text):
    """پارس آی‌پی‌ها از متن (IPv4/IPv6, ip:port, [v6]:port)"""
    ips, seen = [], set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[0]
        if token.startswith("["):
            close = token.find("]")
            if close < 0:
                continue
            token = token[1:close]
        elif token.count(":") == 1:
            token = token.split(":")[0]
        try:
            ip = str(ipaddress.ip_address(token))
        except ValueError:
            continue
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return ips


def build_configs_from_text(
    config_text,
    ip_text,
    timeout,
    workers,
    top=10,
    on_phase=None,
    on_progress=None,
):
    """کانفیگ ساز: کانفیگ‌ها و آی‌پی‌ها را می‌گیرد، هر کانفیگ را با آی‌پی‌های
    داده‌شده تست می‌کند و با بهترین آی‌پی بازسازی می‌کند (مثل نسخه اندروید).
    برمی‌گرداند (results, stats):
      results: list of dict(rank, type, host, sni, best_ip, best_port, latency_ms, final_config)
    """
    configs = parse_configs_text(config_text)
    _input_cfg_count = len(configs)
    ips = parse_ips_text(ip_text)
    # drop exact duplicates (same endpoint + same credentials) so the same
    # IP is not repeated across identical configs
    _seen, _unique = set(), []
    for _cfg in configs:
        _k = _config_identity(_cfg)
        if _k in _seen:
            continue
        _seen.add(_k)
        _unique.append(_cfg)
    configs = _unique
    if not configs:
        return [], {"error": "هیچ کانفیگ معتبری پیدا نشد"}
    if not ips:
        return [], {"error": "هیچ آی‌پی معتبری پیدا نشد"}

    endpoints = unique_endpoints(configs)
    rankings = {}
    total_eps = len(endpoints)

    for ep_idx, ep in enumerate(endpoints, 1):
        host, port, path, use_tls = ep
        if on_phase:
            on_phase(f"تست {host}:{port}")
        passed = run_test_phase(
            ips, host, port, path, use_tls,
            timeout, workers, f"تست {host}",
            samples=1,
            on_progress=lambda d, t, label: (
                on_progress(d, t, f"تست کانفیگ: {label}") if on_progress else None
            ),
        )
        if passed:
            ranked = sorted(passed.items(), key=lambda x: x[1])
            rankings[ep] = ranked[:top]

    results = []
    for cfg in configs:
        ep = get_endpoint(cfg)
        best_ips = rankings.get(ep, [])
        for rank, (ip, lat) in enumerate(best_ips, 1):
            final_cfg = rebuild_config(cfg, ip, rank)
            if not final_cfg:
                continue
            results.append({
                "rank": rank,
                "type": cfg["type"],
                "host": cfg.get("original_host", ""),
                "sni": cfg.get("test_host", ""),
                "best_ip": ip,
                "best_port": cfg.get("port", 443),
                "latency_ms": lat,
                "final_config": final_cfg,
            })
    results.sort(key=lambda r: (r["host"], r["rank"]))
    stats = {
        "configs": _input_cfg_count,
        "unique_configs": len(configs),
        "ips": len(ips),
        "endpoints": total_eps,
        "built": len(results),
    }
    return results, stats


# ──────────────────────────────────────────────
#  پکیج خروجی‌ها (مثل ConfigPackager اندروید)
# ──────────────────────────────────────────────

def pack_plain_text(results):
    """متن ساده: یک کانفیگ در هر خط"""
    return "\n".join(r["final_config"] for r in results)


def pack_base64_subscription(results):
    """Base64 سابسکریپشن v2ray (NO_WRAP)"""
    lines = "\n".join(r["final_config"] for r in results)
    return base64.b64encode(lines.encode("utf-8")).decode("ascii")


def _qparams(final_config):
    """پارامترهای query کانفیگ بازسازی‌شده"""
    u = urlparse(final_config)
    return parse_qs(u.query, keep_blank_values=True)


def _q1(params, key, default=""):
    vals = params.get(key)
    if vals:
        v = vals[0]
        if v:
            return unquote(v)
    return default


def _tag_for(result):
    frag = result["final_config"].split("#", 1)[1] if "#" in result["final_config"] else ""
    decoded = unquote(frag) if frag else ""
    return decoded if decoded else f"narsaq-{result['rank']}-{result['best_ip']}"


def _transport_for(params):
    net = _q1(params, "type") or _q1(params, "net") or "tcp"
    if net == "ws":
        t = {"type": "ws"}
        path = _q1(params, "path")
        if path:
            t["path"] = path
        host = _q1(params, "host")
        if host:
            t["headers"] = {"Host": host}
        return t
    if net == "grpc":
        t = {"type": "grpc"}
        svc = _q1(params, "serviceName")
        if svc:
            t["service_name"] = svc
        return t
    if net in ("httpupgrade", "xhttp", "splithttp"):
        t = {"type": "httpupgrade"}
        path = _q1(params, "path")
        if path:
            t["path"] = path
        host = _q1(params, "host")
        if host:
            t["host"] = host
        return t
    return None


def _tls_for(params, fallback_sni):
    obj = {"enabled": False}
    security = _q1(params, "security")
    if security in ("tls", "reality"):
        obj["enabled"] = True
        sni = _q1(params, "sni") or _q1(params, "host") or fallback_sni or ""
        if sni:
            obj["server_name"] = sni
        fp = _q1(params, "fp")
        if fp:
            obj["utls"] = {"enabled": True, "fingerprint": fp}
        if security == "reality":
            reality = {"enabled": True}
            pbk = _q1(params, "pbk") or _q1(params, "publicKey") or _q1(params, "public_key")
            sid = _q1(params, "sid") or _q1(params, "shortId") or _q1(params, "short_id")
            if pbk:
                reality["public_key"] = pbk
            if sid:
                reality["short_id"] = sid
            spx = _q1(params, "spx")
            if spx:
                reality["spider_x"] = spx
            handshake = _q1(params, "handshake") or sni
            if handshake:
                reality["handshake"] = {"server": handshake, "server_port": 443}
            obj["reality"] = reality
    return obj


def _ss_plugin(params):
    raw = _q1(params, "plugin")
    if not raw:
        return None
    parts = raw.split(";")
    name = parts[0].strip()
    if not name:
        return None
    opts = {}
    for token in parts[1:]:
        token = token.strip()
        if not token:
            continue
        kv = token.split("=", 1)
        opts[kv[0]] = kv[1] if len(kv) == 2 else ""
    return {"name": name, "opts": opts}


def pack_singbox_json(results):
    """Sing-box JSON (outbounds) — مثل ConfigPackager اندروید"""
    outbounds = []
    for r in results:
        try:
            obj = _singbox_outbound(r)
            if obj:
                outbounds.append(obj)
        except Exception:
            continue
    return json.dumps({"outbounds": outbounds}, ensure_ascii=False, indent=2)


def _singbox_outbound(r):
    cfg_type = r["type"]
    params = _qparams(r["final_config"])
    tag = _tag_for(r)
    ip = r["best_ip"]
    port = r["best_port"]
    sni = r.get("sni") or ""

    if cfg_type == "vless":
        u = urlparse(r["final_config"])
        obj = {
            "type": "vless",
            "tag": tag,
            "server": ip,
            "server_port": port,
            "uuid": u.username or "",
        }
        flow = _q1(params, "flow")
        if flow:
            obj["flow"] = flow
        transport = _transport_for(params)
        if transport:
            obj["transport"] = transport
        obj["tls"] = _tls_for(params, sni)
        return obj

    if cfg_type == "trojan":
        u = urlparse(r["final_config"])
        obj = {
            "type": "trojan",
            "tag": tag,
            "server": ip,
            "server_port": port,
            "password": u.username or "",
        }
        flow = _q1(params, "flow")
        if flow:
            obj["flow"] = flow
        transport = _transport_for(params)
        if transport:
            obj["transport"] = transport
        obj["tls"] = _tls_for(params, sni)
        return obj

    if cfg_type == "vmess":
        raw = r["final_config"]
        payload = raw.split("://", 1)[1].split("#", 1)[0].strip()
        decoded = _b64_decode(payload)
        v = json.loads(decoded) if decoded else {}
        obj = {
            "type": "vmess",
            "tag": tag,
            "server": ip,
            "server_port": port,
            "uuid": v.get("id", ""),
            "security": v.get("scy", "auto"),
            "alter_id": int(v.get("aid", 0)),
        }
        net = v.get("net", "tcp")
        if net == "ws":
            t = {"type": "ws", "path": v.get("path", "")}
            host = v.get("host", "")
            if host:
                t["headers"] = {"Host": host}
            obj["transport"] = t
        elif net == "grpc":
            obj["transport"] = {"type": "grpc", "service_name": v.get("path", "")}
        tls = v.get("tls", "")
        if tls in ("tls", "reality"):
            tls_obj = {"enabled": True}
            sni_val = v.get("sni", "") or v.get("host", "")
            if sni_val:
                tls_obj["server_name"] = sni_val
            obj["tls"] = tls_obj
        return obj

    if cfg_type == "shadowsocks":
        u = urlparse(r["final_config"])
        user_info = u.username or ""
        decoded = _b64_decode(user_info) or user_info
        method = decoded.split(":", 1)[0] if ":" in decoded else "aes-128-gcm"
        password = decoded.split(":", 1)[1] if ":" in decoded else decoded
        obj = {
            "type": "shadowsocks",
            "tag": tag,
            "server": ip,
            "server_port": port,
            "method": method,
            "password": password,
        }
        plugin = _ss_plugin(params)
        if plugin:
            if plugin["name"] in ("obfs-local", "simple-obfs"):
                obj["plugin"] = "obfs"
                opts = ";".join(
                    f"{k}={v}" if v else k for k, v in plugin["opts"].items()
                )
                obj["plugin_opts"] = opts
            else:
                obj["plugin"] = plugin["name"]
                opts = ";".join(
                    f"{k}={v}" if v else k for k, v in plugin["opts"].items()
                )
                obj["plugin_opts"] = opts
        return obj
    return None


def pack_clash_yaml(results):
    """Clash YAML (proxies) — مثل ConfigPackager اندروید"""
    lines = ["proxies:"]
    for r in results:
        try:
            block = _clash_proxy(r)
            if block:
                for line in block.splitlines():
                    lines.append("  " + line)
        except Exception:
            continue
    return "\n".join(lines)


def _clash_proxy(r):
    cfg_type = r["type"]
    params = _qparams(r["final_config"])
    name = _tag_for(r)
    ip = r["best_ip"]
    port = r["best_port"]
    sni = r.get("sni") or ""
    net = _q1(params, "type") or "tcp"

    if cfg_type == "vless":
        u = urlparse(r["final_config"])
        sb = [f'- name: "{name}"', "  type: vless",
              f"  server: {ip}", f"  port: {port}",
              f"  uuid: {u.username or ''}", f"  network: {net}",
              f"  tls: {str(_q1(params, 'security') in ('tls', 'reality')).lower()}"]
        sni_v = _q1(params, "sni") or _q1(params, "host") or sni
        if sni_v:
            sb.append(f"  servername: {sni_v}")
        fp = _q1(params, "fp")
        if fp:
            sb.append(f"  client-fingerprint: {fp}")
        flow = _q1(params, "flow")
        if flow:
            sb.append(f"  flow: {flow}")
        sb.extend(_clash_transport_lines(params, net))
        sb.append("  udp: true")
        return "\n".join(sb)

    if cfg_type == "trojan":
        u = urlparse(r["final_config"])
        sb = [f'- name: "{name}"', "  type: trojan",
              f"  server: {ip}", f"  port: {port}",
              f"  password: {u.username or ''}", f"  network: {net}"]
        sni_v = _q1(params, "sni") or _q1(params, "host") or sni
        if sni_v:
            sb.append(f"  sni: {sni_v}")
        fp = _q1(params, "fp")
        if fp:
            sb.append(f"  client-fingerprint: {fp}")
        sb.extend(_clash_transport_lines(params, net))
        sb.append("  udp: true")
        return "\n".join(sb)

    if cfg_type == "vmess":
        raw = r["final_config"]
        payload = raw.split("://", 1)[1].split("#", 1)[0].strip()
        decoded = _b64_decode(payload)
        v = json.loads(decoded) if decoded else {}
        net = v.get("net", "tcp")
        tls = v.get("tls", "")
        sni_v = v.get("sni", "") or v.get("host", "")
        sb = [f'- name: "{name}"', "  type: vmess",
              f"  server: {ip}", f"  port: {port}",
              f"  uuid: {v.get('id', '')}", f"  alterId: {int(v.get('aid', 0))}",
              f"  cipher: {v.get('scy', 'auto')}", f"  network: {net}",
              f"  tls: {str(tls == 'tls').lower()}"]
        if sni_v:
            sb.append(f"  servername: {sni_v}")
        if net == "ws":
            sb.append("  ws-opts:")
            sb.append(f'    path: "{v.get("path", "/")}"')
            host = v.get("host", "")
            if host:
                sb.append("    headers:")
                sb.append(f"      Host: {host}")
        elif net == "grpc":
            sb.append("  grpc-opts:")
            sb.append(f'    grpc-service-name: "{v.get("path", "")}"')
        sb.append("  udp: true")
        return "\n".join(sb)

    if cfg_type == "shadowsocks":
        u = urlparse(r["final_config"])
        user_info = u.username or ""
        decoded = _b64_decode(user_info) or user_info
        method = decoded.split(":", 1)[0] if ":" in decoded else "aes-128-gcm"
        password = decoded.split(":", 1)[1] if ":" in decoded else decoded
        sb = [f'- name: "{name}"', "  type: ss",
              f"  server: {ip}", f"  port: {port}",
              f"  cipher: {method}", f'  password: "{password}"']
        plugin = _ss_plugin(params)
        if plugin:
            if plugin["name"] in ("obfs-local", "simple-obfs"):
                sb.append("  plugin: obfs")
                sb.append("  plugin-opts:")
                mode = plugin["opts"].get("obfs", "http")
                sb.append(f"    mode: {mode}")
                host = plugin["opts"].get("obfs-host")
                if host:
                    sb.append(f'    host: "{host}"')
            else:
                sb.append(f"  plugin: {plugin['name']}")
        sb.append("  udp: true")
        return "\n".join(sb)
    return None


def _clash_transport_lines(params, net):
    lines = []
    if net == "ws":
        path = _q1(params, "path") or "/"
        host = _q1(params, "host")
        lines.append("  ws-opts:")
        lines.append(f'    path: "{path}"')
        if host:
            lines.append("    headers:")
            lines.append(f"      Host: {host}")
    elif net == "grpc":
        svc = _q1(params, "serviceName")
        lines.append("  grpc-opts:")
        lines.append(f'    grpc-service-name: "{svc}"')
    return lines


def pack_all(results):
    """همه فرمت‌های خروجی را یکجا می‌سازد"""
    return {
        "plain": pack_plain_text(results),
        "base64": pack_base64_subscription(results),
        "singbox": pack_singbox_json(results),
        "clash": pack_clash_yaml(results),
    }



# ──────────────────────────────────────────────
#  بهینه‌ساز کانفیگ (مثل cf-optimizor — PattNG)
# ──────────────────────────────────────────────

OPTIMIZER_DEFAULTS = {
    "cdn_ip": "",  # empty = keep each config's original address
    "fp": "unsafe",
    "cs": (
        "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:"
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
    ),
    "fm": (
        '{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["5","94","1"],"delays":["0"],"maxSplit":"0"}},{"type":"fragment","settings":{"packets":"1-1","lengths":["109","1"],"delays":["1"],"maxSplit":"355"}}]}'
    ),
}

# ترتیب خروجی پارامترها (مثل cf-optimizor)
OPTIMIZER_PARAM_ORDER = [
    "cs", "path", "security", "alpn", "encryption", "fm",
    "insecure", "host", "fp", "type", "allowInsecure", "sni",
]


def _looks_like_base64(s):
    """آیا متن شبیه یک بلاک base64 است؟"""
    s = s.strip()
    return (
        len(s) > 50
        and not s.startswith(("vless://", "trojan://", "vmess://", "ss://",
                               "hysteria2://", "hysteria://", "tuic://", "wireguard://",
                               "ssh://", "http://", "https://"))
        and re.fullmatch(r"[A-Za-z0-9+/=\s]+", s) is not None
    )


def _fetch_subscription(url, timeout=15):
    """دانلود محتوای لینک سابسکریپشن (Base64 یا متن ساده)"""
    import urllib.request
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (NarsaqDesktop/1.0)",
        "Accept": "*/*",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
    # decode
    for enc in ("utf-8", "iso-8859-1"):
        try:
            text = data.decode(enc)
            break
        except Exception:
            continue
    else:
        text = data.decode("utf-8", errors="replace")
    # اگه کل محتوا base64 بود → دیکد کن
    if _looks_like_base64(text):
        try:
            decoded = _b64_decode(text.replace("\n", ""))
            if decoded and "://" in decoded:
                return decoded
        except Exception:
            pass
    return text


def _extract_configs_from_text(text, timeout=15):
    """استخراج کانفیگ‌ها از متن (خطوط، بلاک base64، یا لینک‌های ساب)

    timeout به دانلود لینک‌های ساب می‌رود.
    خطاهای دانلود با پیشوند !SUB در خط نگه داشته می‌شوند تا پیام واضح باشد.
    """
    lines = []
    b64_buf = []  # تجمع خطوط base64 چندخطی

    def _flush_b64():
        nonlocal b64_buf
        if not b64_buf:
            return
        joined = "".join(b64_buf)
        b64_buf = []
        try:
            decoded = _b64_decode(joined)
        except Exception:
            decoded = None
        if decoded and "://" in decoded:
            lines.extend(x.strip() for x in decoded.splitlines() if x.strip())
        else:
            # قابل دیکد نبود → همان خطوط خام
            for _l in joined.split("\n"):
                lines.append(_l.strip())

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("http://", "https://")):
            _flush_b64()
            try:
                sub = _fetch_subscription(line, timeout=timeout)
            except Exception as e:
                lines.append(f"!SUB {line} — {str(e)[:60]}")
                continue
            # محتوای ساب: ممکن است base64 باشد → دیکد شود
            if _looks_like_base64(sub):
                try:
                    sub = _b64_decode(sub.replace("\n", "")) or sub
                except Exception:
                    pass
            lines.extend(x.strip() for x in sub.splitlines() if x.strip())
        elif _looks_like_base64(line) or (
            b64_buf and re.fullmatch(r"[A-Za-z0-9+/=]+", line) and len(line) % 4 == 0
        ):
            # خط پایه‌۶۴ (حتی کوتاه‌تر از ۵۰) وقتی بافر فعال است — جمع می‌شود
            b64_buf.append(line)
        else:
            _flush_b64()
            lines.append(line)
    _flush_b64()
    return lines


def _parse_vless_opt(raw):
    """پارس VLESS برای بهینه‌ساز — بدون نیاز به validate سخت‌گیرانه"""
    u = urlparse(raw)
    if u.scheme != "vless":
        return None
    params = parse_qs(u.query, keep_blank_values=True)
    return {
        "uuid": u.username,
        "host": u.hostname,
        "port": u.port,
        "params": params,
        "fragment": u.fragment,
    }


def _opt_params(params, opts):
    """اعمال تغییرات: cdn_ip, fp, cs, fm — با حفظ بقیه پارامترها"""
    out = {}
    for key, vals in params.items():
        if vals:
            out[key] = vals[0]
    out["fp"] = opts.get("fp", OPTIMIZER_DEFAULTS["fp"])
    out["cs"] = opts.get("cs", OPTIMIZER_DEFAULTS["cs"])
    out["fm"] = _normalize_fm(opts.get("fm", OPTIMIZER_DEFAULTS["fm"])) or OPTIMIZER_DEFAULTS["fm"]
    # dedupe + drop empty
    result = {}
    for key in out:
        val = out[key]
        if val == "" and key not in ("host",):
            continue
        result[key] = val
    return result


def _rebuild_vless_opt(cfg, opts):
    """بازسازی VLESS با آدرس جدید و ترتیب ثابت پارامترها"""
    params = _opt_params(cfg["params"], opts)
    cdn_ip = (opts.get("cdn_ip") or OPTIMIZER_DEFAULTS["cdn_ip"] or "").strip()
    if not cdn_ip:
        cdn_ip = cfg["host"]  # keep original address

    # ترتیب ثابت + پارامترهای ناشناخته در انتها
    ordered = []
    seen = set()
    for key in OPTIMIZER_PARAM_ORDER:
        if key in params and key not in seen:
            ordered.append((key, params[key]))
            seen.add(key)
    for key, val in params.items():
        if key not in seen:
            ordered.append((key, val))
            seen.add(key)

    query = "&".join(f"{quote(key, safe='')}={quote(str(val), safe='')}" for key, val in ordered)
    addr = _format_ip(cdn_ip)
    frag = f"#{cfg['fragment']}" if cfg["fragment"] else ""
    return f"vless://{cfg['uuid']}@{addr}:{cfg['port']}?{query}{frag}", ordered


def _opt_changes(original_params, new_params, cdn_ip, old_host=None):
    """خلاصه تغییرات برای نمایش به کاربر"""
    def _first(v):
        return v[0] if isinstance(v, list) else v

    changes = []
    if old_host is None:
        old_host = _first(original_params.get("host", ""))
    if cdn_ip and old_host and old_host != cdn_ip:
        changes.append(f"Address: {old_host} → {cdn_ip}")
    fp_old = _first(original_params.get("fp", ""))
    if str(fp_old) != str(new_params.get("fp", "")):
        changes.append(f"fp: {fp_old or '—'} → {new_params.get('fp')}")
    cs_old = _first(original_params.get("cs", ""))
    if not cs_old:
        changes.append("cs (Cipher Suites) added")
    elif str(cs_old) != str(new_params.get("cs", "")):
        changes.append("cs (Cipher Suites) changed")
    fm_old = _first(original_params.get("fm", ""))
    if not fm_old:
        changes.append("fm (FinalMask) added")
    elif str(fm_old) != str(new_params.get("fm", "")):
        changes.append("fm (FinalMask) changed")
    return changes


def optimize_configs(text, opts=None, timeout=15):
    """بهینه‌ساز گروهی کانفیگ‌ها (مثل cf-optimizor):
    - VLESS: آدرس → CDN IP، fp/cs/fm ست می‌شود، بقیه حفظ می‌شود
    - Trojan: fm/cs/fp تزریق می‌شود (بدون تغییر آدرس)
    - VMess/SS: بدون تغییر پاس داده می‌شود
    - لینک سابسکریپشن: دانلود و استخراج می‌شود
    برمی‌گرداند (results, errors):
      results: list of dict(index, input, output, type, changes, error?)
    """
    if opts is None:
        opts = {}
    defaults = dict(OPTIMIZER_DEFAULTS)
    defaults.update(opts)
    opts = defaults

    lines = _extract_configs_from_text(text, timeout=timeout)
    results = []
    errors = []

    for idx, raw in enumerate(lines, 1):
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("!SUB "):
            errors.append({"index": idx, "line": stripped[5:80], "error": "Subscription download failed"})
            continue
        try:
            if stripped.startswith("vless://"):
                cfg = _parse_vless_opt(stripped)
                if not cfg or not cfg["uuid"] or not cfg["host"]:
                    errors.append({"index": idx, "line": stripped[:80], "error": "Invalid VLESS"})
                    continue
                output, ordered = _rebuild_vless_opt(cfg, opts)
                changes = _opt_changes(cfg["params"], dict(ordered), opts["cdn_ip"], old_host=cfg["host"])
                results.append({
                    "index": idx,
                    "type": "vless",
                    "input": stripped,
                    "output": output,
                    "changes": changes,
                })
            elif stripped.startswith("trojan://"):
                u = urlparse(stripped)
                if not u.username or not u.hostname:
                    errors.append({"index": idx, "line": stripped[:80], "error": "Invalid Trojan"})
                    continue
                params = parse_qs(u.query, keep_blank_values=True)
                orig = {k: v[0] for k, v in params.items() if v}
                orig["fp"] = opts["fp"]
                orig["cs"] = opts["cs"]
                orig["fm"] = _normalize_fm(opts["fm"]) or OPTIMIZER_DEFAULTS["fm"]
                new_params = {}
                for key in OPTIMIZER_PARAM_ORDER:
                    if key in orig:
                        new_params[key] = orig.pop(key)
                new_params.update(orig)
                query = "&".join(f"{quote(k, safe='')}={quote(str(v), safe='')}" for k, v in new_params.items())
                frag = f"#{u.fragment}" if u.fragment else ""
                output = f"trojan://{u.username}@{u.hostname}:{u.port or 443}?{query}{frag}"
                changes = _opt_changes(
                    {k: v[0] for k, v in params.items() if v},
                    new_params,
                    opts["cdn_ip"],
                )
                if not changes:
                    changes = ["fm/cs/fp injected"]
                results.append({
                    "index": idx,
                    "type": "trojan",
                    "input": stripped,
                    "output": output,
                    "changes": changes,
                })
            elif "://" in stripped:
                # سایر پروتکل‌ها (hysteria2/hysteria/tuic/wireguard/ssh/...): پاس‌ترو بدون تغییر
                scheme = stripped.split("://", 1)[0].lower()
                if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", scheme) or " " in stripped:
                    raise ValueError("Unknown format")
                results.append({
                    "index": idx,
                    "type": scheme,
                    "input": stripped,
                    "output": stripped,
                    "changes": ["Unchanged (pass-through)"],
                })
            else:
                errors.append({"index": idx, "line": stripped[:80], "error": "Unknown format"})
        except Exception as e:
            errors.append({"index": idx, "line": stripped[:80], "error": str(e)[:80]})

    return results, errors


def optimizer_join_results(results):
    """متن نهایی خروجی — فقط کانفیگ‌های بهینه‌شده/پاس‌ترو"""
    return "\n".join(r["output"] for r in results)


# ──────────────────────────────────────────────
#  تست End-to-End واقعی با Xray core
# ──────────────────────────────────────────────

def app_base_dir():
    """پوشه اصلی برنامه — کنار exe (frozen) یا کنار اسکریپت"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def find_xray_binary():
    """پیدا کردن xray.exe — متغیر XRAY_BIN، پوشه bin کنار اسکریپت، PATH، مسیرهای رایج"""
    import shutil
    cands = []
    env = os.environ.get("XRAY_BIN")
    if env:
        cands.append(env)
    base = app_base_dir()
    cands.append(os.path.join(base, "bin", "xray.exe"))
    cands.append(os.path.join(base, "xray.exe"))
    cands.append(r"C:\xray\xray.exe")
    cands.append(os.path.expanduser(r"~\xray\xray.exe"))
    cands.append(os.path.expanduser(r"~\v2rayN\xray\xray.exe"))
    cands.append(r"C:\v2rayN\xray\xray.exe")
    for c in cands:
        if c and os.path.isfile(c):
            return c
    w = shutil.which("xray")
    return w or None


def download_xray_core(dest_dir, on_progress=None):
    """دانلود xray-core ویندوز (آخرین ریلیز رسمی) و استخراج xray.exe در پوشه bin"""
    import shutil
    import urllib.request
    import zipfile
    os.makedirs(dest_dir, exist_ok=True)
    exe = os.path.join(dest_dir, "xray.exe")
    if os.path.isfile(exe):
        return exe
    lock_path = os.path.join(dest_dir, "_xray_dl.lock")
    if os.path.exists(lock_path):
        raise RuntimeError("Xray core is already being downloaded")
    try:
        with open(lock_path, "w") as lf:
            lf.write("1")
    except Exception:
        pass
    url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip"
    tmp = os.path.join(dest_dir, "_xray_dl.zip")
    req = urllib.request.Request(url, headers={"User-Agent": "NarsaqDesktop/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp, open(tmp, "wb") as fh:
            total = int(resp.headers.get("Content-Length") or 0)
            done = 0
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                fh.write(chunk)
                done += len(chunk)
                if on_progress and total:
                    on_progress(done / max(total, 1))
        with zipfile.ZipFile(tmp) as z:
            entry = next((n for n in z.namelist() if n.lower().endswith("xray.exe")), None)
            if not entry:
                raise RuntimeError("xray.exe not found in archive")
            with z.open(entry) as src, open(exe, "wb") as dst:
                shutil.copyfileobj(src, dst)
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass
        try:
            os.remove(lock_path)
        except Exception:
            pass
    return exe


def _q1v(q, key, default=""):
    """اولین مقدار پارامتر query (decode شده)"""
    vals = q.get(key)
    if vals:
        v = vals[0]
        if v:
            return unquote(v)
    return default


def _readn(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def _socks5_probe(port, target_host, target_port, timeout):
    """اتصال واقعی از طریق پراکسی SOCKS5 محلی (xray) به یک هدف معروف و اندازه‌گیری تاخیر"""
    t0 = time.perf_counter()
    sock = None
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        if _readn(sock, 2) != b"\x05\x00":
            raise ConnectionError("SOCKS5 handshake failed")
        host = target_host.encode()
        req = b"\x05\x01\x00\x03" + bytes([len(host)]) + host + target_port.to_bytes(2, "big")
        sock.sendall(req)
        rep = _readn(sock, 10)
        if len(rep) < 2 or rep[1] != 0:
            raise ConnectionError("SOCKS5 CONNECT refused")
        ctx = ssl.create_default_context()
        tls = ctx.wrap_socket(sock, server_hostname=target_host)
        tls.sendall(
            ("GET /generate_204 HTTP/1.1\r\nHost: %s\r\n"
             "User-Agent: NarsaqDesktop/1.0\r\nConnection: close\r\n\r\n" % target_host).encode()
        )
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = tls.recv(4096)
            if not chunk:
                break
            data += chunk
        line = data.split(b"\r\n", 1)[0]
        parts = line.split(b" ", 2)
        code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        ok = 200 <= code < 400
        return ok, (time.perf_counter() - t0) * 1000.0, ("" if ok else "HTTP %s" % code)
    except Exception as e:
        return False, (time.perf_counter() - t0) * 1000.0, str(e)[:90]
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _xray_stream_settings(q, default_sni):
    """ساخت streamSettings برای Xray از پارامترهای کانفیگ (بدون fm — fm فقط روی کلاینت خاص است)"""
    network = _q1v(q, "type", "tcp") or "tcp"
    security = (_q1v(q, "security", "none") or "none").lower()
    sni = _q1v(q, "sni") or _q1v(q, "host") or default_sni
    stream = {"network": network}

    ws = {}
    ws_path = _q1v(q, "path")
    ws_host = _q1v(q, "host")
    if ws_path:
        ws["path"] = ws_path
    if ws_host:
        ws["headers"] = {"Host": ws_host}
    if ws:
        stream["wsSettings"] = ws

    grpc = {}
    svc = _q1v(q, "serviceName")
    if svc:
        grpc["serviceName"] = svc
    if grpc:
        stream["grpcSettings"] = grpc

    hu = {}
    if ws_path:
        hu["path"] = ws_path
    if ws_host:
        hu["host"] = ws_host
    if hu:
        stream["httpupgradeSettings"] = hu

    xh = {}
    if ws_path:
        xh["path"] = ws_path
    if ws_host:
        xh["host"] = ws_host
    mode = _q1v(q, "mode")
    if mode:
        xh["mode"] = mode
    if xh:
        stream["xhttpSettings"] = xh

    fp = _q1v(q, "fp")
    if security == "tls":
        # NOTE: allowInsecure was removed in recent Xray (26.x) — use standard verification
        tls = {"serverName": sni}
        if fp:
            tls["fingerprint"] = fp
        cs = _q1v(q, "cs")
        if cs:
            tls["cipherSuites"] = cs
        alpn = _q1v(q, "alpn")
        if alpn:
            tls["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
        stream["security"] = "tls"
        stream["tlsSettings"] = tls
    elif security == "reality":
        # Xray 26.x: single serverName (string) — serverNames array was removed
        # Xray 26.x reality outbound: serverName (string), password (= pbk), shortId (string)
        rl = {"serverName": sni}
        if fp:
            rl["fingerprint"] = fp
        pbk = _q1v(q, "pbk")
        if pbk:
            rl["password"] = pbk
        sid = _q1v(q, "sid")
        if sid:
            rl["shortId"] = sid
        spx = _q1v(q, "spx")
        if spx:
            rl["spiderX"] = spx
        stream["security"] = "reality"
        stream["realitySettings"] = rl
    else:
        stream["security"] = "none"
    return stream


def build_xray_client_json(output_url, socks_port):
    """تبدیل کانفیگ خروجی (vless/trojan/vmess/ss) به کانفیگ کلاینت Xray با SOCKS inbound"""
    lower = output_url.lower()
    outbound = None
    if lower.startswith("vless://"):
        u = urlparse(output_url)
        if not u.hostname or not u.username:
            return None
        q = parse_qs(u.query, keep_blank_values=True)
        user = {"id": u.username, "encryption": _q1v(q, "encryption", "none") or "none"}
        flow = _q1v(q, "flow")
        if flow:
            user["flow"] = flow
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{"address": u.hostname, "port": u.port or 443, "users": [user]}]
            },
            "streamSettings": _xray_stream_settings(q, u.hostname),
        }
    elif lower.startswith("trojan://"):
        u = urlparse(output_url)
        if not u.hostname or not u.username:
            return None
        q = parse_qs(u.query, keep_blank_values=True)
        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [{"address": u.hostname, "port": u.port or 443, "password": u.username}]
            },
            "streamSettings": _xray_stream_settings(q, u.hostname),
        }
    elif lower.startswith("vmess://"):
        payload = output_url.split("://", 1)[1].split("#", 1)[0].strip()
        try:
            obj = json.loads(_b64_decode(payload) or "{}")
        except Exception:
            return None
        host = str(obj.get("add", "")).strip()
        vid = str(obj.get("id", "")).strip()
        if not host or not vid:
            return None
        q = {}
        net = str(obj.get("net", "tcp") or "tcp")
        sec = str(obj.get("tls", "") or "").lower()
        q["type"] = [net]
        if sec in ("tls", "reality"):
            q["security"] = [sec]
        q["sni"] = [str(obj.get("sni", "") or "")] if obj.get("sni") else []
        q["host"] = [str(obj.get("host", "") or "")] if obj.get("host") else []
        q["path"] = [str(obj.get("path", "") or "")] if obj.get("path") else []
        if obj.get("fp"):
            q["fp"] = [str(obj["fp"])]
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": int(obj.get("port", 443) or 443),
                    "users": [{
                        "id": vid,
                        "alterId": int(obj.get("aid", 0) or 0),
                        "security": "auto",
                    }],
                }]
            },
            "streamSettings": _xray_stream_settings(q, host),
        }
    elif lower.startswith("ss://"):
        body = output_url.split("://", 1)[1].split("#", 1)[0]
        u = urlparse("ss://" + body)
        cred = ""
        host = u.hostname
        if u.username:
            cred = u.username
            # base64(method:password) — decode if it is not plain text
            if ":" not in cred:
                try:
                    dec = base64.b64decode(cred + "==").decode("utf-8", "ignore")
                    if ":" in dec:
                        cred = dec
                except Exception:
                    pass
        else:
            try:
                decoded = base64.b64decode(body.split("@")[0] + "==").decode("utf-8", "ignore")
                if ":" in decoded and "@" in body:
                    cred = decoded
            except Exception:
                pass
        if not host:
            return None
        if ":" in cred:
            method, password = cred.split(":", 1)
        else:
            method, password = "", cred
        outbound = {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{"address": host, "port": u.port or 8388, "method": method, "password": password}]
            },
            "streamSettings": {"network": "tcp", "security": "none"},
        }
    else:
        return None
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [outbound],
    }


def test_config_with_xray(xray_bin, output_url, socks_port, timeout=12):
    """اجرای xray با کانفیگ خروجی و تست واقعی پراکسی → (ok, latency_ms, error)"""
    import subprocess
    import tempfile
    cfg = build_xray_client_json(output_url, socks_port)
    if cfg is None:
        return False, 0.0, "unsupported protocol"
    fd, cfg_path = tempfile.mkstemp(suffix=".json", prefix="narsaq_xray_")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh)
    proc = None
    try:
        if str(xray_bin).lower().endswith(".py"):
            # test hook: allow pointing XRAY_BIN at a python script
            cmd = [sys.executable, xray_bin, "run", "-c", cfg_path]
        else:
            cmd = [xray_bin, "run", "-c", cfg_path]
        creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=creationflags,
        )
        deadline = time.time() + 6
        ready = False
        while time.time() < deadline:
            if proc.poll() is not None:
                return False, 0.0, "xray exited early (code %s)" % proc.returncode
            s = None
            try:
                s = socket.create_connection(("127.0.0.1", socks_port), timeout=1)
                ready = True
                break
            except OSError:
                time.sleep(0.15)
            finally:
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass
        if not ready:
            return False, 0.0, "socks port not ready"
        return _socks5_probe(socks_port, "www.gstatic.com", 443, min(timeout, 8))
    except Exception as e:
        return False, 0.0, str(e)[:90]
    finally:
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                proc.wait(3)
            except Exception:
                pass
            if proc.poll() is None:
                try:
                    proc.kill()
                except Exception:
                    pass
        try:
            os.remove(cfg_path)
        except Exception:
            pass


def real_test_results(results, xray_bin=None, timeout=12, workers=4,
                      on_progress=None, should_cancel=None):
    """تست واقعی پراکسی روی خروجی هر کانفیگ با xray.exe (موازی).

    نتایج با فیلدهای test (ok/fail/skip/no-xray/cancelled)، latency_ms و test_error تکمیل می‌شوند.
    برمی‌گرداند (results, xray_bin).
    """
    if xray_bin is None:
        xray_bin = find_xray_binary()
    if not xray_bin:
        for r in results:
            r["test"] = "no-xray"
            r["latency_ms"] = None
            r["test_error"] = ""
        return results, None
    total = len(results)
    _lock = threading.Lock()
    _counter = [10800]
    done = [0]
    ok_count = [0]

    def _next_port():
        while True:
            with _lock:
                _counter[0] += 1
                port = 10800 + (_counter[0] % 49000)
            # skip ports already occupied (e.g. orphaned xray from a crashed run)
            sck = None
            try:
                sck = socket.create_connection(("127.0.0.1", port), timeout=0.4)
                sck.close()
                continue
            except OSError:
                return port
            finally:
                if sck:
                    try:
                        sck.close()
                    except Exception:
                        pass

    def work(r):
        try:
            if should_cancel and should_cancel():
                r.update(test="cancelled", latency_ms=None, test_error="")
                return r
            scheme = (r.get("output") or "").split("://", 1)[0].lower()
            if scheme not in ("vless", "trojan", "vmess", "ss"):
                r.update(test="skip", latency_ms=None, test_error="")
                with _lock:
                    done[0] += 1
                    if on_progress:
                        on_progress(done[0], total, ok_count[0])
                return r
            ok, lat, err = test_config_with_xray(xray_bin, r.get("output", ""), _next_port(), timeout)
            r["test"] = "ok" if ok else "fail"
            r["latency_ms"] = round(lat, 1) if lat is not None else None
            r["test_error"] = err or ""
            with _lock:
                done[0] += 1
                if ok:
                    ok_count[0] += 1
                if on_progress:
                    on_progress(done[0], total, ok_count[0])
        except Exception as e:
            r.update(test="fail", latency_ms=None, test_error=str(e)[:90])
            with _lock:
                done[0] += 1
                if on_progress:
                    on_progress(done[0], total, ok_count[0])

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(work, results))
    return results, xray_bin


def main():
    # تنظیم encoding خروجی
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

    ap = argparse.ArgumentParser(
        description="ساخت بهترین کانفیگ‌های Cloudflare — اسکنر آی‌پی تمیز + تست کانفیگ",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
نمونه استفاده:
  # حالت اسکنر (بدون نیاز به VPN — آی‌پی تمیز پیدا می‌کند):
  python cf_config_builder.py --scan -c my_configs.txt
  python cf_config_builder.py --scan -c my_configs.txt --count 500 --v6 --ports 443,2053
  python cf_config_builder.py --scan --count 200 --save-ips clean_ips.txt

  # حالت قدیمی (تست لیست آی‌پی موجود):
  python cf_config_builder.py ips.txt -c my_configs.txt
  python cf_config_builder.py ips.txt -c my_configs.txt --top 30 --timeout 5
  python cf_config_builder.py ips.txt -c my_configs.txt --workers 100 --no-verify

فرمت فایل آی‌پی (ips.txt):
  یک آی‌پی در هر خط (IPv4 یا IPv6)

فرمت فایل کانفیگ (configs.txt):
  یک کانفیگ در هر خط — پشتیبانی از:
  vless://...
  vmess://...
  trojan://...
  ss://...
        """,
    )
    ap.add_argument("--version", action="version", version="Narsaq Desktop %s" % VERSION)
    ap.add_argument("ips", nargs="?", help="مسیر فایل آی‌پی‌ها (در حالت اسکنر اختیاری)")
    ap.add_argument("-c", "--configs", help="مسیر فایل کانفیگ‌ها")
    ap.add_argument("-o", "--output", help="مسیر فایل خروجی")

    ap.add_argument(
        "--scan", action="store_true",
        help="حالت اسکنر: تولید آی‌پی از رنج‌های Cloudflare و پیدا کردن آی‌پی‌های تمیز "
             "(بدون نیاز به VPN — مثل نسخه موبایل)"
    )
    ap.add_argument(
        "--count", type=int, default=300,
        help="تعداد آی‌پی برای اسکن (پیش‌فرض: 300)"
    )
    ap.add_argument(
        "--ports", type=str, default="443",
        help="پورت‌های اسکن، جدا شده با کاما (پیش‌فرض: 443)"
    )
    ap.add_argument(
        "--v6", action="store_true",
        help="اسکن IPv6 هم انجام بده (رنج‌های Cloudflare v6)"
    )
    ap.add_argument(
        "--custom-ranges", type=str, default="",
        help="رنج‌های دلخواه — متن مستقیم یا مسیر فایل (هر خط یک CIDR یا IP)"
    )
    ap.add_argument(
        "--save-ips", type=str, default="",
        help="ذخیره آی‌پی‌های تمیز در فایل (پیش‌فرض: clean_ips_<timestamp>.txt)"
    )
    ap.add_argument(
        "--no-speed", action="store_true",
        help="غیرفعال کردن تست سرعت Mbps"
    )

    ap.add_argument(
        "--neighbor-scan", action="store_true",
        help="اسکن همسایگی آی‌پی‌های پیدا شده (آی‌پی‌های تمیز معمولاً خوشه‌ای‌اند — مثل موبایل)"
    )
    ap.add_argument(
        "--top", type=int, default=50,
        help="حداکثر تعداد کانفیگ برتر برای هر اندپوینت (پیش‌فرض: 50)"
    )
    ap.add_argument(
        "--timeout", type=float, default=3.0,
        help="تایم‌اوت هر تست به ثانیه (پیش‌فرض: 3)"
    )
    ap.add_argument(
        "--workers", type=int, default=64,
        help="تعداد اتصال‌های همزمان (پیش‌فرض: 64)"
    )
    ap.add_argument(
        "--no-verify", action="store_true",
        help="حذف مرحله تأیید (تست دوم با ۳ نمونه)"
    )
    ap.add_argument(
        "--snis", type=str, default="",
        help="SNI‌های سفارشی با کاما (مثال: speed.cloudflare.com,custom.example.com)"
    )
    args = ap.parse_args()

    if hasattr(args, "snis") and args.snis:
        set_custom_snis(args.snis)

    # ─── حالت اسکنر: تولید و اسکن آی‌پی‌ها ───
    if args.scan:
        ports = []
        for p in args.ports.replace(";", ",").split(","):
            try:
                ports.append(int(p.strip()))
            except ValueError:
                continue
        if not ports:
            ports = [443]

        custom = args.custom_ranges
        if custom and os.path.exists(custom):
            with open(custom, "r", encoding="utf-8-sig") as fh:
                custom = fh.read()

        print("=" * 60)
        print("  Narsaq Cloudflare Clean-IP Scanner")
        print("=" * 60)
        print(f"  تولید آی‌پی:       {args.count} عدد (IPv4{' + IPv6' if args.v6 else ''})")
        print(f"  پورت‌ها:           {', '.join(map(str, ports))}")
        print(f"  تایم‌اوت:          {args.timeout}s")
        print(f"  همزمانی:           {args.workers}")
        print("=" * 60)

        print(f"\n  → تولید آی‌پی از رنج‌های Cloudflare...")
        scope_ips = generate_scan_scope(args.count, args.v6, custom)
        print(f"  ✓ {len(scope_ips)} آی‌پی تولید شد")

        stats = {}
        results = run_scan_pipeline(
            scope_ips,
            ports,
            args.timeout,
            args.workers,
            enable_tls=True,
            enable_verify=not args.no_verify,
            speed_test=not args.no_speed,
            neighbor_scan=args.neighbor_scan,
            stats=stats,
        )

        if not results:
            tcp_f = stats.get("tcp_found", 0)
            tls_f = stats.get("tls_found", 0)
            phase_failed = stats.get("failed_phase", "")
            if phase_failed == "TCP Test" or tcp_f == 0:
                hint = (
                    "اتصال TCP به آی‌پی‌های Cloudflare روی این شبکه مسدود است.\n"
                    "  1. پورت‌های جایگزین را امتحان کنید: --ports 2053,2083,2087,2096,8443\n"
                    "  2. با VPN روشن اسکن کنید\n"
                    "  3. تایم‌اوت را بیشتر کنید: --timeout 5"
                )
            elif phase_failed == "TLS Test" or tls_f == 0:
                hint = "TCP وصل شد ولی بررسی TLS/colo پاس نشد — تایم‌اوت را بیشتر کنید (--timeout 5)."
            else:
                hint = "مرحله تأیید شکست خورد — تایم‌اوت را بیشتر کنید یا --no-verify بزنید."
            sys.exit(f"\n⛔ هیچ آی‌پی تمیزی پیدا نشد!\n   دیاگنوز: {phase_failed or 'نامشخص'} | TCP: {tcp_f} | TLS: {tls_f} | Verify: {stats.get('verify_found', 0)}\n\n{hint}")

        # ذخیره آی‌پی‌های تمیز
        stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        save_path = args.save_ips or f"clean_ips_{stamp}.txt"
        with open(save_path, "w", encoding="utf-8") as fh:
            for r in results:
                ip = f"[{r['ip']}]" if ":" in r["ip"] else r["ip"]
                fh.write(f"{ip}:{r['port']}\n")

        print(f"\n{'=' * 60}")
        print(f"  ✅ {len(results)} آی‌پی تمیز پیدا شد")
        print(f"  📄 ذخیره شد در: {save_path}")
        print(f"{'=' * 60}")

        # نمایش برترین‌ها
        print(f"\n  برترین آی‌پی‌ها:")
        for i, r in enumerate(results[:15], 1):
            ip = f"[{r['ip']}]" if ":" in r["ip"] else r["ip"]
            total = r.get("tls_ms") or r["tcp_ms"]
            parts = [f"{total:.0f}ms"]
            if r.get("colo"):
                parts.append(f"Colo: {r['colo']}")
            if r.get("loss") is not None:
                parts.append(f"Loss: {r['loss']:.0f}%")
            if r.get("jitter") is not None:
                parts.append(f"Jitter: ±{r['jitter']:.0f}ms")
            if r.get("mbps"):
                parts.append(f"{r['mbps']:.1f} Mbps")
            print(f"  {i:>2}. {ip}:{r['port']} | {' | '.join(parts)}")

        # یکتاسازی: اگر چند پورت پاس شده باشد، هر آی‌پی فقط یک بار تست شود
        ips = list(dict.fromkeys(r["ip"] for r in results))

        # اگر کانفیگ داده شده، از آی‌پی‌های تمیز کانفیگ بساز
        if args.configs:
            cfg_file = args.configs
        else:
            cfg_file = find_config_file()
        if not cfg_file or not os.path.exists(cfg_file):
            print(
                "\n(فایل کانفیگ پیدا نشد — فقط آی‌پی‌های تمیز ذخیره شدند. "
                "برای ساخت کانفیگ از -c استفاده کنید)"
            )
            return
        configs = load_configs(cfg_file)
        if not configs:
            print(f"\n⚠ هیچ کانفیگ معتبری در '{cfg_file}' پیدا نشد.")
            return
        print(f"\n  → ساخت کانفیگ از {len(configs)} کانفیگ ورودی با آی‌پی‌های تمیز...")

    else:
        # ─── حالت قدیمی: تست لیست آی‌پی موجود ───
        if not args.ips:
            sys.exit(
                "خطا: یا فایل آی‌پی بدهید یا از --scan استفاده کنید.\n"
                "مثال: python cf_config_builder.py ips.txt -c configs.txt\n"
                "یا:   python cf_config_builder.py --scan -c configs.txt"
            )
        if not os.path.exists(args.ips):
            sys.exit(f"خطا: فایل آی‌پی '{args.ips}' پیدا نشد.")
        ips = load_ips(args.ips)
        if not ips:
            sys.exit("خطا: هیچ آی‌پی معتبری در فایل ورودی نیست.")

        cfg_file = args.configs or find_config_file()
        if not cfg_file or not os.path.exists(cfg_file):
            sys.exit(
                "خطا: فایل کانفیگ پیدا نشد.\n"
                "لطفاً با -c مسیر فایل کانفیگ را مشخص کنید.\n"
                "مثال: python cf_config_builder.py ips.txt -c my_configs.txt"
            )
        configs = load_configs(cfg_file)
        if not configs:
            sys.exit(
                f"خطا: هیچ کانفیگ معتبری در '{cfg_file}' پیدا نشد.\n"
                "مطمئن شوید فایل شامل کانفیگ‌های vless://, vmess://, trojan:// یا ss:// باشد."
            )

    # ─── نمایش خلاصه ───

    endpoints = unique_endpoints(configs)
    type_counts = {}
    for c in configs:
        type_counts[c["type"]] = type_counts.get(c["type"], 0) + 1
    type_str = " | ".join(f"{t}: {n}" for t, n in sorted(type_counts.items()))

    print("=" * 60)
    print("  CF Config Builder v2.1 (Desktop)")
    print("=" * 60)
    print(f"  آی‌پی‌ها:        {len(ips)} عدد")
    print(f"  کانفیگ‌ها:       {len(configs)} عدد ({type_str})")
    print(f"  اندپوینت‌ها:     {len(endpoints)} عدد")
    print(f"  حداکثر خروجی:   {args.top} عدد برای هر اندپوینت")
    print(f"  تایم‌اوت:        {args.timeout}s")
    print(f"  همزمانی:         {args.workers}")
    print("=" * 60)

    # ─── تست آی‌پی‌ها برای هر اندپوینت ───

    rankings = {}

    for ep_idx, ep in enumerate(endpoints, 1):
        host, port, path, use_tls = ep
        proto = "TLS" if use_tls else "TCP"
        print(f"\n{'─' * 50}")
        print(f"  اندپوینت {ep_idx}/{len(endpoints)}: {host}:{port} ({proto})")
        print(f"{'─' * 50}")

        # مرحله ۱: تست اولیه
        passed = run_test_phase(
            ips, host, port, path, use_tls,
            args.timeout, args.workers,
            f"تست اولیه",
            samples=1,
        )

        if not passed:
            print(f"  ⚠ هیچ آی‌پی‌ای پاسخ نداد!")
            rankings[ep] = []
            continue

        ranked = sorted(passed.items(), key=lambda x: x[1])
        print(
            f"  ✓ پاس شده: {len(ranked)}/{len(ips)}"
            f" | بهترین: {ranked[0][0]} ({ranked[0][1]:.0f}ms)"
            f" | بدترین: {ranked[-1][0]} ({ranked[-1][1]:.0f}ms)"
        )

        # مرحله ۲: تأیید (اختیاری)
        if not args.no_verify and len(ranked) > 1:
            candidates = [ip for ip, _ in ranked[:min(len(ranked), args.top * 3, 150)]]
            print(f"  → مرحله تأیید: {len(candidates)} آی‌پی برتر با ۳ نمونه...")
            verified = run_test_phase(
                candidates, host, port, path, use_tls,
                args.timeout, args.workers,
                f"تست تأیید",
                samples=3,
            )
            if verified:
                ranked = sorted(verified.items(), key=lambda x: x[1])
                print(
                    f"  ✓ تأیید شده: {len(ranked)}"
                    f" | بهترین: {ranked[0][0]} ({ranked[0][1]:.0f}ms)"
                )
            else:
                print("  ⚠ هیچ آی‌پی‌ای در مرحله تأیید پاس نشد!")
                ranked = sorted(passed.items(), key=lambda x: x[1])

        rankings[ep] = ranked[:args.top]

    # ─── بررسی نتایج ───

    if not any(rankings.values()):
        sys.exit(
            "\n⛔ هیچ آی‌پی سالمی پیدا نشد!\n"
            "پیشنهادها:\n"
            "  1. تایم‌اوت را بیشتر کنید: --timeout 5\n"
            "  2. آی‌پی‌ها را بررسی کنید\n"
            "  3. اتصال اینترنت را چک کنید"
        )

    # ─── ساخت کانفیگ‌های نهایی ───

    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    out_path = args.output or f"best_configs_{stamp}.txt"

    total_configs = 0
    output_lines = [
        f"# CF Config Builder v2.1 (Desktop)",
        f"# تاریخ: {stamp}",
        f"# آی‌پی تست شده: {len(ips)} | کانفیگ ورودی: {len(configs)}",
        f"#",
    ]

    print(f"\n{'=' * 60}")
    print("  نتایج نهایی")
    print(f"{'=' * 60}")

    for cfg in configs:
        ep = get_endpoint(cfg)
        best_ips = rankings.get(ep, [])
        if not best_ips:
            continue

        proto = cfg["type"].upper()
        host, port, path, use_tls = ep
        print(f"\n  [{proto}] {host}:{port} — {len(best_ips)} کانفیگ")
        print(f"  {'─' * 45}")

        output_lines.append(f"# --- {proto} | {host}:{port} ---")

        for rank, (ip, lat) in enumerate(best_ips, 1):
            final_cfg = rebuild_config(cfg, ip, rank)
            if not final_cfg:
                continue
            output_lines.append(final_cfg)
            total_configs += 1

            # نمایش ۵ تای اول + آخری
            if rank <= 5:
                print(f"  {rank:>3}. {lat:6.0f}ms | {final_cfg[:100]}...")
            elif rank == 6 and len(best_ips) > 6:
                print(f"  {'...':>5} ({len(best_ips) - 5} مورد دیگر)")

    # ─── ذخیره فایل خروجی ───

    output_lines.append(f"#")
    output_lines.append(f"# مجموع: {total_configs} کانفیگ")

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(output_lines) + "\n")

    print(f"\n{'=' * 60}")
    print(f"  ✅ {total_configs} کانفیگ ذخیره شد")
    print(f"  📄 فایل خروجی: {out_path}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
