#!/usr/bin/env python3
"""
cf_config_builder.py — نسخه کامل
ساخت بهترین کانفیگ‌های Cloudflare از روی لیست آی‌پی و کانفیگ‌های کاربر

پشتیبانی کامل: VLESS, VMess, Trojan, Shadowsocks

استفاده:
    python cf_config_builder.py ips.txt -c configs.txt
    python cf_config_builder.py ips.txt -c configs.txt --top 30 --timeout 5
"""

import argparse
import base64
import glob
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
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
    for altchars in (None, b"-_"):
        try:
            if altchars:
                raw = base64.b64decode(cleaned.translate(
                    str.maketrans("-_", "+/")), validate=False)
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


def rebuild_vless(cfg, ip, rank):
    """بازسازی کانفیگ VLESS با آی‌پی جدید"""
    addr = _format_ip(ip)
    name = _make_fragment(cfg["fragment"], rank)
    query = cfg["query_string"]
    q_part = f"?{query}" if query else ""
    f_part = f"#{quote(name, safe='')}" if name else ""
    return f"vless://{cfg['uuid']}@{addr}:{cfg['port']}{q_part}{f_part}"


def rebuild_trojan(cfg, ip, rank):
    """بازسازی کانفیگ Trojan با آی‌پی جدید"""
    addr = _format_ip(ip)
    name = _make_fragment(cfg["fragment"], rank)
    query = cfg["query_string"]
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


def run_test_phase(ips, host, port, path, use_tls, timeout, workers, label, samples=1):
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
    sys.stdout.write("\n")
    return results


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
    for pattern in ("*config*.txt", "*Config*.txt", "*.txt"):
        files = glob.glob(pattern)
        # فایل‌هایی که ip یا best در نامشان هست حذف شوند
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

def main():
    # تنظیم encoding خروجی
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

    ap = argparse.ArgumentParser(
        description="ساخت بهترین کانفیگ‌های Cloudflare از روی لیست آی‌پی و کانفیگ کاربر",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
نمونه استفاده:
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
    ap.add_argument("ips", help="مسیر فایل آی‌پی‌ها")
    ap.add_argument("-c", "--configs", help="مسیر فایل کانفیگ‌ها")
    ap.add_argument("-o", "--output", help="مسیر فایل خروجی")
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
    args = ap.parse_args()

    # ─── بارگذاری فایل‌ها ───

    # فایل آی‌پی
    if not os.path.exists(args.ips):
        sys.exit(f"خطا: فایل آی‌پی '{args.ips}' پیدا نشد.")
    ips = load_ips(args.ips)
    if not ips:
        sys.exit("خطا: هیچ آی‌پی معتبری در فایل ورودی نیست.")

    # فایل کانفیگ
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
    print("  CF Config Builder v2.0")
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
        f"# CF Config Builder v2.0",
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