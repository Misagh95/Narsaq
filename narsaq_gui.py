#!/usr/bin/env python3
"""
narsaq_gui.py — رابط گرافیکی وب برای اسکنر Narsaq
پیدا کردن آی‌پی‌های تمیز Cloudflare با پیشرفت زنده — بدون نیاز به VPN

استفاده:
    python narsaq_gui.py
    python narsaq_gui.py --port 8787
    python narsaq_gui.py --no-browser

بعد از اجرا، مرورگر به صورت خودکار باز می‌شود:
    http://127.0.0.1:8787

همه‌چیز فقط با کتابخانه استاندارد Python ساخته شده (بدون نصب چیزی).
"""

import argparse
import json
import os
import queue
import socket
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime
from urllib.parse import urlparse, parse_qs

# فایل اسکنر اصلی — همان منطق cf_config_builder
import cf_config_builder as cfb

# ──────────────────────────────────────────────
#  وضعیت اسکن (مشترک بین رشته‌ها)
# ──────────────────────────────────────────────

STATE = {
    "running": False,
    "cancelled": False,
    "phase": "idle",
    "done": 0,
    "found": 0,
    "total": 0,
    "results": [],          # dict های نهایی (ip, port, tcp_ms, tls_ms, colo, loss, jitter, mbps)
    "clean_ips_file": "",
    "configs_file": "",
    "best_file": "",
    "error": "",
    "started_at": "",
}
LOCK = threading.Lock()
BROADCAST = []  # لیست queue های متصل برای SSE
SSE_LOCK = threading.Lock()


def set_state(**kw):
    with LOCK:
        STATE.update(kw)


def get_state():
    with LOCK:
        return dict(STATE)


VERSION = "1.0.0"


def broadcast(event, data):
    """ارسال رویداد SSE به همه کلاینت‌های متصل"""
    payload = f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
    with SSE_LOCK:
        for q in list(BROADCAST):
            try:
                q.put_nowait(payload)
            except queue.Full:
                pass


# ──────────────────────────────────────────────
#  کارگر اسکن (رشته پس‌زمینه)
# ──────────────────────────────────────────────

def _emit_phase(done, found, total, phase):
    set_state(done=done, found=found, total=total, phase=phase)
    broadcast("progress", {"done": done, "found": found, "total": total, "phase": phase})


def _run_scan(params):
    """اجرای کامل اسکن + ساخت کانفیگ در رشته پس‌زمینه"""
    try:
        count = int(params.get("count", 300))
        ports = [int(p) for p in str(params.get("ports", "443")).replace(";", ",").split(",") if p.strip().isdigit()] or [443]
        timeout = float(params.get("timeout", 3.0))
        workers = int(params.get("workers", 64))
        enable_v6 = bool(params.get("v6", False))
        speed_test = bool(params.get("speed_test", True))
        enable_verify = bool(params.get("verify", True))
        neighbor_scan = bool(params.get("neighbor_scan", True))
        custom = params.get("custom_ranges", "") or ""
        config_file = params.get("config_file", "") or ""

        if custom and os.path.exists(custom):
            with open(custom, "r", encoding="utf-8-sig") as fh:
                custom = fh.read()

        set_state(running=True, cancelled=False, error="", phase="Generating IPs",
                  done=0, found=0, total=count, results=[],
                  clean_ips_file="", configs_file=params.get("config_file", ""), best_file="",
                  started_at=datetime.now().strftime("%H:%M:%S"))
        broadcast("status", {"message": "شروع اسکن...", "state": "started"})

        # ─── ۱. تولید آی‌پی ───
        broadcast("phase", {"phase": "Generating IPs from Cloudflare ranges"})
        scope_ips = cfb.generate_scan_scope(count, enable_v6, custom)
        set_state(total=len(scope_ips) * len(ports), done=0)
        broadcast("progress", {"done": 0, "found": 0, "total": len(scope_ips) * len(ports), "phase": "Ready to scan"})

        # ─── ۲. پایپلاین ۵ مرحله‌ای ───
        stats = {}
        results = cfb.run_scan_pipeline(
            scope_ips,
            ports,
            timeout,
            workers,
            enable_tls=True,
            enable_verify=enable_verify,
            speed_test=speed_test,
            on_progress=_emit_phase,
            neighbor_scan=neighbor_scan,
            stats=stats,
        )

        if STATE["cancelled"]:
            set_state(running=False, phase="Cancelled")
            broadcast("done", {"state": "cancelled", "message": "Scan cancelled"})
            return

        if not results:
            tcp_f = stats.get("tcp_found", 0)
            tls_f = stats.get("tls_found", 0)
            phase_failed = stats.get("failed_phase", "")
            if phase_failed == "TCP Test" or tcp_f == 0:
                hint = (
                    "TCP connections to Cloudflare IPs are blocked on this network. "
                    "Try alternative ports (2053,2083,2087,2096,8443) or scan with a VPN."
                )
            elif phase_failed == "TLS Test" or tls_f == 0:
                hint = "TCP connected but TLS/colo check failed — increase the timeout."
            else:
                hint = "Verification phase failed — increase the timeout or disable multi-step verification."
            msg = f"No clean IPs found! (Phase: {phase_failed or 'unknown'} | TCP: {tcp_f} | TLS: {tls_f} | Verify: {stats.get('verify_found', 0)}) — {hint}"
            set_state(running=False, phase="پایان", error=msg)
            broadcast("done", {"state": "error", "message": msg})
            return

        # ─── ۳. ذخیره آی‌پی‌های تمیز ───
        stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        save_path = params.get("save_ips") or f"clean_ips_{stamp}.txt"
        with open(save_path, "w", encoding="utf-8") as fh:
            for r in results:
                ip = f"[{r['ip']}]" if ":" in r["ip"] else r["ip"]
                fh.write(f"{ip}:{r['port']}\n")

        set_state(results=results, clean_ips_file=save_path, phase="Saved")
        broadcast("results", {"results": results, "clean_ips_file": save_path})

        # ─── ۴. ساخت کانفیگ از کانفیگ‌های کاربر ───
        ips = list(dict.fromkeys(r["ip"] for r in results))
        if config_file and os.path.exists(config_file):
            configs = cfb.load_configs(config_file)
            if configs:
                broadcast("phase", {"phase": "تست کانفیگ‌ها روی آی‌پی‌های تمیز"})
                out_path = params.get("output") or f"best_configs_{stamp}.txt"
                total_configs = _build_configs(configs, ips, config_file, timeout, workers, out_path, stamp)
                set_state(best_file=out_path)
                broadcast("configs", {"file": out_path, "count": total_configs})

        set_state(running=False, phase="Done")
        broadcast("done", {"state": "done", "message": "اسکن کامل شد", "clean_ips_file": save_path, "best_file": STATE["best_file"]})

    except Exception as e:
        import traceback
        traceback.print_exc()
        set_state(running=False, phase="Error", error=str(e))
        broadcast("done", {"state": "error", "message": str(e)})


def _build_configs(configs, ips, config_file, timeout, workers, out_path, stamp=None):
    """تست آی‌پی‌های تمیز روی اندپوینت‌های کانفیگ‌ها و ساخت فایل نهایی"""
    endpoints = cfb.unique_endpoints(configs)
    rankings = {}
    for ep_idx, ep in enumerate(endpoints, 1):
        host, port, path, use_tls = ep
        broadcast("phase", {"phase": f"Endpoint {ep_idx}/{len(endpoints)}: {host}:{port}"})
        passed = cfb.run_test_phase(
            ips, host, port, path, use_tls,
            timeout, workers, f"تست {host}",
            samples=1,
        )
        if passed:
            ranked = sorted(passed.items(), key=lambda x: x[1])
            rankings[ep] = ranked[:50]

    if stamp is None:
        stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    if not os.path.dirname(out_path):
        out_path = f"best_configs_{stamp}.txt"

    total_configs = 0
    output_lines = [f"# CF Config Builder v2.1 (Desktop GUI)", f"# تاریخ: {stamp}", f"#"]
    for cfg in configs:
        ep = cfb.get_endpoint(cfg)
        best_ips = rankings.get(ep, [])
        if not best_ips:
            continue
        output_lines.append(f"# --- {cfg['type'].upper()} | {ep[0]}:{ep[1]} ---")
        for rank, (ip, lat) in enumerate(best_ips, 1):
            final_cfg = cfb.rebuild_config(cfg, ip, rank)
            if not final_cfg:
                continue
            output_lines.append(final_cfg)
            total_configs += 1

    output_lines.append(f"#")
    output_lines.append(f"# مجموع: {total_configs} کانفیگ")
    with open(out_path, "w", encoding="utf-8") as fh:
        content = "\n".join(output_lines) + "\n"
        fh.write("\n".join(output_lines) + "\n")
        with LOCK:
            LAST_CONFIGS["content"] = content
    return total_configs


def _start_scan_thread(params):
    if STATE["running"]:
        return False
    t = threading.Thread(target=_run_scan, args=(params,), daemon=True)
    t.start()
    return True


# ──────────────────────────────────────────────
#  کانفیگ ساز (مثل نسخه اندروید)
# ──────────────────────────────────────────────

BUILD_STATE = {
    "running": False,
    "phase": "idle",
    "done": 0,
    "total": 0,
    "error": "",
}
LAST_BUILD = {
    "results": [],
    "stats": {},
    "outputs": {"plain": "", "base64": "", "singbox": "", "clash": ""},
    "finished_at": "",
}


def _emit_build_phase(done, total, phase):
    with LOCK:
        BUILD_STATE.update(done=done, total=total, phase=phase, error="")
    broadcast("build-progress", {"done": done, "total": total, "phase": phase})


def _run_build(params):
    """ساخت کانفیگ از متن کانفیگ‌ها + آی‌پی‌ها در رشته پس‌زمینه"""
    try:
        config_text = params.get("configs", "") or ""
        ip_text = params.get("ips", "") or ""
        timeout = float(params.get("timeout", 3.0))
        workers = int(params.get("workers", 64))
        top = int(params.get("top", 10))

        with LOCK:
            BUILD_STATE.update(running=True, phase="Start", done=0, total=0, error="")

        results, stats = cfb.build_configs_from_text(
            config_text,
            ip_text,
            timeout,
            workers,
            top=top,
            on_phase=lambda p: _emit_build_phase(0, 0, p),
            on_progress=lambda d, t, phase: _emit_build_phase(d, t, phase),
        )

        with LOCK:
            BUILD_STATE.update(running=False, phase="Done")
        broadcast("build-phase", {"phase": "Building outputs..."})

        if not results:
            err = stats.get("error", "هیچ کانفیگی ساخته نشد")
            with LOCK:
                BUILD_STATE.update(error=err)
            broadcast("build-done", {"state": "error", "message": err})
            return

        outputs = cfb.pack_all(results)
        with LOCK:
            LAST_BUILD.update(
                results=results,
                stats=stats,
                outputs=outputs,
                finished_at=datetime.now().strftime("%H:%M:%S"),
            )
            BUILD_STATE.update(running=False, phase="Done", error="")
        broadcast("build-done", {
            "state": "done",
            "count": len(results),
            "stats": stats,
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        with LOCK:
            BUILD_STATE.update(running=False, phase="Error", error=str(e))
        broadcast("build-done", {"state": "error", "message": str(e)})


def _start_build_thread(params):
    with LOCK:
        if BUILD_STATE["running"]:
            return False
        BUILD_STATE["running"] = True
    t = threading.Thread(target=_run_build, args=(params,), daemon=True)
    t.start()
    return True


# ──────────────────────────────────────────────
#  بهینه‌ساز کانفیگ (مثل cf-optimizor — PattNG)
# ──────────────────────────────────────────────

OPT_STATE = {
    "running": False,
    "phase": "idle",
    "done": 0,
    "total": 0,
    "error": "",
    "found": 0,
    "passed": 0,
}
LAST_OPT = {
    "results": [],
    "errors": [],
    "output": "",
    "finished_at": "",
}


def _emit_opt(done, total, phase, found=0, passed=0):
    with LOCK:
        OPT_STATE.update(done=done, total=total, phase=phase, found=found, passed=passed, error="")
    broadcast("opt-progress", {"done": done, "total": total, "phase": phase, "found": found, "passed": passed})


def _run_opt(params):
    """بهینه‌سازی گروهی کانفیگ‌ها در رشته پس‌زمینه"""
    try:
        text = params.get("text", "") or ""
        opts = params.get("opts", {}) or {}
        timeout = float(params.get("timeout", 15.0))

        with LOCK:
            OPT_STATE.update(running=True, phase="Start", done=0, total=0, error="", found=0, passed=0)

        # به‌روزرسانی تنظیمات از فرم (فقط مقادیر پر)
        clean = {}
        if opts.get("cdn_ip"):
            clean["cdn_ip"] = opts["cdn_ip"]
        if opts.get("fp"):
            clean["fp"] = opts["fp"]
        if opts.get("cs"):
            clean["cs"] = opts["cs"]
        if opts.get("fm"):
            clean["fm"] = opts["fm"]

        _emit_opt(0, 1, "Extracting configs...")
        results, errors = cfb.optimize_configs(text, opts=clean, timeout=timeout)

        if params.get("real_test") and results:
            xray_bin = cfb.find_xray_binary()
            if not xray_bin:
                _emit_opt(0, len(results), "Xray core not found - use the download button")
                for r in results:
                    r["test"] = "no-xray"
                    r["latency_ms"] = None
                    r["test_error"] = ""
            else:
                _emit_opt(0, len(results), "Real proxy test (Xray core)...")
                results, _ = cfb.real_test_results(
                    results,
                    xray_bin=xray_bin,
                    timeout=max(float(timeout), 10.0),
                    workers=4,
                    on_progress=lambda d, t, p: _emit_opt(
                        d, t, "Testing %d/%d..." % (d, t), found=p, passed=p
                    ),
                    should_cancel=lambda: not OPT_STATE["running"],
                )
                if not OPT_STATE["running"]:
                    _emit_opt(0, len(results), "Cancelled")

        output = cfb.optimizer_join_results(results)
        with LOCK:
            _tested = any(r.get("test") in ("ok", "fail") for r in results)
            _passed = (
                sum(1 for r in results if r.get("test") == "ok")
                if _tested
                else len(results)
            )
            _phase = "Done" if OPT_STATE["running"] else "Cancelled"
            OPT_STATE.update(running=False, phase=_phase, done=len(results),
                             total=len(results) + len(errors), found=len(results), passed=_passed)
            LAST_OPT.update(
                results=results,
                errors=errors,
                output=output,
                finished_at=datetime.now().strftime("%H:%M:%S"),
            )
        broadcast("opt-done", {
            "state": "done",
            "count": len(results),
            "errors": len(errors),
            "output": output,
            "results": results,
            "error_list": errors,
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        with LOCK:
            OPT_STATE.update(running=False, phase="Error", error=str(e))
        broadcast("opt-done", {"state": "error", "message": str(e)})


_XRAY_DL_ACTIVE = [False]


def _xray_download_worker():
    """دانلود xray-core در پوشه bin کنار اسکریپت — با گزارش پیشرفت SSE"""
    with LOCK:
        if _XRAY_DL_ACTIVE[0]:
            return
        _XRAY_DL_ACTIVE[0] = True
    try:
        dest = os.path.join(cfb.app_base_dir(), "bin")
        cfb.download_xray_core(dest, on_progress=lambda p: broadcast("xray-dl", {"progress": p}))
        broadcast("xray-dl", {"message": "done"})
    except Exception as e:
        broadcast("xray-dl", {"error": "Xray download failed: %s" % str(e)[:90]})
    finally:
        with LOCK:
            _XRAY_DL_ACTIVE[0] = False


def _start_opt_thread(params):
    with LOCK:
        if OPT_STATE["running"]:
            return False
        OPT_STATE["running"] = True
    t = threading.Thread(target=_run_opt, args=(params,), daemon=True)
    t.start()
    return True


# ──────────────────────────────────────────────
#  HTML داشبورد (تعبیه‌شده)
# ──────────────────────────────────────────────

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title data-i="title">Narsaq — Cloudflare Clean IP Scanner</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect width='24' height='24' rx='5' fill='%23f6821f'/%3E%3Ctext x='12' y='16.5' font-size='13' font-family='Arial' font-weight='bold' text-anchor='middle' fill='white'%3EN%3C/text%3E%3C/svg%3E">
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap');
  :root {
    --orange: #f6821f;
    --orange-dark: #d96f0d;
    --orange-light: #ffab5e;
    --orange-glow: rgba(246,130,31,.35);
    --ok: #22c55e;
    --warn: #f59e0b;
    --err: #ef4444;
  }
  [data-theme="dark"] {
    --bg: #0b1017;
    --bg2: #131b26;
    --card: #16202d;
    --card2: #1d2a3a;
    --line: #2a3a4e;
    --text: #e8eef4;
    --muted: #8fa3b5;
    --accent: var(--orange);
    --accent-dark: var(--orange-dark);
    --accent-soft: rgba(246,130,31,.13);
    --accent-text: var(--orange-light);
    --btn-text: #1a0e00;
  }
  [data-theme="light"] {
    --bg: #f6f4f1;
    --bg2: #ffffff;
    --card: #ffffff;
    --card2: #fbf3ea;
    --line: #e5d9cc;
    --text: #1c2330;
    --muted: #6b7787;
    --accent: #f6821f;
    --accent-dark: #e0710c;
    --accent-soft: rgba(246,130,31,.1);
    --accent-text: #c25e00;
    --btn-text: #fff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background:
      radial-gradient(1000px 500px at 85% -10%, var(--orange-glow), transparent 60%),
      radial-gradient(800px 400px at -10% 110%, rgba(246,130,31,.12), transparent 60%),
      var(--bg);
    color: var(--text);
    font-family: 'Inter', system-ui, sans-serif;
    min-height: 100vh;
    padding: 24px;
    transition: background .3s, color .3s;
  }
  .wrap { max-width: 1000px; margin: 0 auto; }
  header { display: flex; align-items: center; gap: 14px; margin-bottom: 20px; }
  .logo {
    width: 46px; height: 46px; border-radius: 14px;
    background: linear-gradient(135deg, #c75d00, var(--orange), #ffb066);
    display: flex; align-items: center; justify-content: center;
    font-size: 22px; font-weight: 800; color: #fff;
    box-shadow: 0 8px 24px var(--orange-glow);
    letter-spacing: -.5px;
  }
  h1 { font-size: 22px; font-weight: 800; letter-spacing: .3px; }
  .sub { color: var(--muted); font-size: 13px; margin-top: 2px; }
  .pill {
    background: var(--accent-soft); color: var(--accent-text);
    border: 1px solid rgba(246,130,31,.35);
    padding: 3px 10px; border-radius: 99px; font-size: 11px; font-weight: 600;
  }
  .theme-toggle {
    margin-right: auto;
    display: flex; align-items: center; gap: 8px;
  }
  .theme-toggle button {
    background: var(--card); color: var(--text);
    border: 1px solid var(--line); border-radius: 99px;
    padding: 6px 14px; font-size: 13px; cursor: pointer;
    font-family: inherit; font-weight: 600;
    transition: border-color .2s, transform .15s;
  }
  .theme-toggle button:hover { border-color: var(--orange); }
  .theme-toggle button:active { transform: scale(.95); }

  .card {
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 18px;
    padding: 20px;
    margin-bottom: 16px;
    transition: background .3s, border-color .3s;
  }
  .card h2 { font-size: 15px; font-weight: 700; margin-bottom: 14px; color: var(--accent-text); display: flex; align-items: center; gap: 8px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
  .field label { display: block; font-size: 12px; color: var(--muted); margin-bottom: 6px; }
  .field input, .field select {
    width: 100%; background: var(--bg2); color: var(--text);
    border: 1px solid var(--line); border-radius: 10px;
    padding: 9px 12px; font-family: inherit; font-size: 13px;
    transition: border-color .2s;
  }
  .field input:focus { outline: none; border-color: var(--orange); }
  .switch-row { display: flex; align-items: center; gap: 10px; padding: 8px 0; }
  .switch-row label { font-size: 13px; color: var(--text); cursor: pointer; }
  .switch { position: relative; width: 42px; height: 24px; flex-shrink: 0; }
  .switch input { opacity: 0; width: 0; height: 0; }
  .slider {
    position: absolute; inset: 0; border-radius: 99px;
    background: var(--line); transition: .25s; cursor: pointer;
  }
  .slider::before {
    content: ''; position: absolute; width: 18px; height: 18px;
    border-radius: 50%; background: #fff; top: 3px; right: 3px; transition: .25s;
  }
  .switch input:checked + .slider { background: var(--orange); }
  .switch input:checked + .slider::before { transform: translateX(-18px); }
  textarea {
    width: 100%; background: var(--bg2); color: var(--text);
    border: 1px solid var(--line); border-radius: 10px;
    padding: 10px 12px; font-family: 'Consolas', 'Courier New', monospace; font-size: 12px;
    min-height: 60px; resize: vertical;
  }
  textarea:focus { outline: none; border-color: var(--orange); }

  .actions { display: flex; gap: 10px; margin-top: 16px; flex-wrap: wrap; }
  button {
    font-family: inherit; border: none; border-radius: 12px;
    padding: 12px 26px; font-size: 14px; font-weight: 700; cursor: pointer;
    transition: transform .15s, box-shadow .2s, opacity .2s;
  }
  button:active { transform: scale(.96); }
  #btnStart {
    background: linear-gradient(135deg, var(--orange-dark), var(--orange));
    color: var(--btn-text); flex: 1; min-width: 160px;
    box-shadow: 0 6px 20px var(--orange-glow);
  }
  #btnStart:hover { box-shadow: 0 8px 28px rgba(246,130,31,.5); }
  #btnStart:disabled { opacity: .5; cursor: not-allowed; }
  #btnCancel { background: var(--card2); color: var(--text); border: 1px solid var(--line); }
  .ghost {
    background: transparent; color: var(--muted); border: 1px solid var(--line);
    padding: 8px 14px; font-size: 12px; border-radius: 10px;
  }
  .ghost:hover { color: var(--accent-text); border-color: var(--orange); }

  .progress-card { display: none; }
  .progress-card.active { display: block; }
  .phase-label { font-size: 13px; color: var(--accent-text); font-weight: 600; margin-bottom: 8px; }
  .bar-wrap { height: 14px; background: var(--bg2); border-radius: 99px; overflow: hidden; border: 1px solid var(--line); }
  .bar { height: 100%; width: 0%; border-radius: 99px;
    background: linear-gradient(90deg, var(--orange-dark), var(--orange));
    transition: width .3s ease; }
  .stats { display: flex; gap: 24px; margin-top: 12px; font-size: 13px; color: var(--muted); }
  .stats b { color: var(--text); font-size: 16px; display: block; }

  .results-card { display: none; }
  .results-card.active { display: block; }
  .results-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-wrap: wrap; gap: 8px; }
  .results-head h2 { margin: 0; }
  .table-wrap { max-height: 380px; overflow-y: auto; border-radius: 12px; border: 1px solid var(--line); }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  thead { position: sticky; top: 0; background: var(--card2); z-index: 1; }
  th { padding: 10px 12px; text-align: left; color: var(--muted); font-weight: 600; font-size: 11.5px; }
  td { padding: 9px 12px; border-top: 1px solid var(--line); }
  tr:hover td { background: var(--accent-soft); }
  .rank { color: var(--muted); font-weight: 600; }
  .ip { font-family: 'Consolas', monospace; font-size: 12px; }
  .colo-chip {
    background: var(--accent-soft); color: var(--accent-text);
    border-radius: 6px; padding: 2px 8px; font-size: 11px; font-weight: 700;
  }
  .ok { color: var(--ok); } .warn { color: var(--warn); }
  .err { color: var(--err); }
  .muted { color: var(--muted); }

  .toast {
    position: fixed; bottom: 24px; left: 24px; background: var(--card2);
    border: 1px solid var(--orange); color: var(--text); border-radius: 12px;
    padding: 12px 20px; font-size: 13px; box-shadow: 0 10px 30px rgba(0,0,0,.35);
    transform: translateY(120%); transition: transform .3s ease; z-index: 99;
  }
  .toast.show { transform: translateY(0); }
  .toast.err { border-color: var(--err); }

  .file-line { background: var(--bg2); border: 1px dashed var(--line); border-radius: 10px; padding: 10px 14px; font-family: monospace; font-size: 12px; margin: 8px 0; word-break: break-all; }
  .hidden { display: none !important; }
  footer { text-align: center; color: var(--muted); font-size: 12px; margin-top: 20px; }
  a { color: var(--orange); }
  .pattng-note {
    display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
    background: var(--accent-soft); border: 1px dashed rgba(246,130,31,.4);
    border-radius: 10px; padding: 10px 14px; font-size: 12px; margin-top: 12px;
  }
  .pattng-note a { font-weight: 700; text-decoration: none; }
  .pattng-note a:hover { text-decoration: underline; }
  @media (max-width: 640px) { body { padding: 14px; } .stats { flex-wrap: wrap; gap: 12px; } }
  body[dir="rtl"] { direction: rtl; text-align: right; }
  body[dir="rtl"] .stats, body[dir="rtl"] .results-head, body[dir="rtl"] .actions, 
  body[dir="rtl"] header { direction: rtl; }
  body[dir="rtl"] th { text-align: right; }
  body[dir="rtl"] .theme-toggle { margin-right: 0; margin-left: auto; }
</style>
</head>
<body data-theme="dark">
<div class="wrap">
  <header>
    <div style="display:flex;align-items:center;gap:10px">
      <div class="logo">N</div>
      <svg width="34" height="34" viewBox="0 0 24 24" fill="none" aria-label="Cloudflare" title="Cloudflare">
        <g fill="%23f6821f">
          <path d="M13.5 3.5c-1.6 0-3 .9-3.8 2.2a4.6 4.6 0 0 0-1-.1C6 5.6 3.8 7.8 3.8 10.5c0 .5.1 1 .2 1.5C1.9 12.6.8 14 .8 15.6c0 2 1.6 3.6 3.6 3.6h9.1c2.5 0 4.5-2 4.5-4.5a4.5 4.5 0 0 0-3.6-4.4A5 5 0 0 0 13.5 3.5z"/>
        </g>
      </svg>
    </div>
    <div>
      <h1 data-i="scanner_name">Narsaq Scanner</h1>
      <div class="sub" data-i="scanner_sub">Cloudflare clean IP finder &amp; config optimizer</div>
    </div>
    <div class="theme-toggle" style="display:flex;align-items:center;gap:6px">
      <button id="btnTheme">☀️ Light</button>
      <button id="btnLang" class="ghost" style="padding:6px 10px;font-size:12px;min-width:74px">فارسی</button>
    </div>
    <div class="pill" id="connPill">Connecting…</div>
  </header>

  <div class="card">
    <h2 data-i="scan_settings">⚙️ Scan Settings</h2>
    <div class="grid">
      <div class="field"><label data-i="num_ips">Number of IPs</label><input id="count" type="number" value="300" min="10" max="2000"></div>
      <div class="field"><label data-i="ports">Ports (comma separated)</label><input id="ports" value="443"><button class="ghost" id="btnAltPorts" style="margin-top:6px;width:100%" data-i="alt_ports">🔀 Cloudflare alt ports</button></div>
      <div class="field"><label data-i="timeout">Timeout (s)</label><input id="timeout" type="number" value="3" min="1" max="15" step="0.5"></div>
      <div class="field"><label data-i="concurrency">Concurrency</label><input id="workers" type="number" value="64" min="4" max="300"></div>
    </div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:4px;margin-top:8px">
      <div class="switch-row"><label class="switch"><input type="checkbox" id="v6"><span class="slider"></span></label><label for="v6" data-i="scan_ipv6">Scan IPv6</label></div>
      <div class="switch-row"><label class="switch"><input type="checkbox" id="nscan" checked><span class="slider"></span></label><label for="nscan" data-i="neighbor_scan">Neighbor scan</label></div>
      <div class="switch-row"><label class="switch"><input type="checkbox" id="verify" checked><span class="slider"></span></label><label for="verify" data-i="multi_verify">Multi-step verify</label></div>
      <div class="switch-row"><label class="switch"><input type="checkbox" id="speed" checked><span class="slider"></span></label><label for="speed" data-i="speed_test">Speed test (Mbps)</label></div>
    </div>
    <div style="margin-top:14px">
      <label style="font-size:12px;color:var(--muted);display:block;margin-bottom:6px" data-i="custom_ranges">Custom ranges (optional — one CIDR or IP per line)</label>
      <textarea id="customRanges" placeholder="e.g.&#10;104.16.0.0/13&#10;1.2.3.4"></textarea>
    </div>
    <div style="margin-top:14px">
      <label style="font-size:12px;color:var(--muted);display:block;margin-bottom:6px" data-i="config_file">Config file (optional — for building final configs)</label>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <input id="configFile" placeholder="e.g. configs.txt" style="flex:1;min-width:220px">
        <button class="ghost" id="btnBrowse" data-i="choose_file">📂 Choose file</button>
      </div>
    </div>
    <div class="actions">
      <button id="btnStart" data-i="start_scan">🚀 Start Scan</button>
      <button id="btnCancel" class="hidden" data-i="cancel">⛔ Cancel</button>
    </div>
  </div>

  <div class="card progress-card" id="progressCard">
    <h2 data-i="scan_progress">📡 Scan Progress</h2>
    <div class="phase-label" id="phaseLabel" data-i="waiting_start">Waiting to start…</div>
    <div class="bar-wrap"><div class="bar" id="bar"></div></div>
    <div class="stats">
      <div data-i="done_label">Done<b id="stDone">0</b></div>
      <div data-i="found_label">Found<b id="stFound">0</b></div>
      <div data-i="total_label">Total<b id="stTotal">0</b></div>
    </div>
  </div>

  <div class="card results-card" id="resultsCard">
    <div class="results-head">
      <h2 data-i="clean_ips">🏆 Clean IPs</h2>
      <div style="display:flex;gap:8px">
        <button class="ghost" id="btnCopyIps" data-i="copy_ips">📋 Copy IPs</button>
        <button class="ghost" id="btnCopyCfg" data-i="copy_configs">📋 Copy configs</button>
      </div>
    </div>
    <div class="file-line hidden" id="cleanFile"></div>
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>#</th><th data-i="ip_col">IP</th><th data-i="latency_col">Latency</th><th data-i="colo_col">Colo</th><th data-i="loss_col">Loss</th><th data-i="jitter_col">Jitter</th><th data-i="speed_col">Speed</th>
        </tr></thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
    <div id="cfgResult" style="margin-top:12px"></div>
  </div>

  <div class="card" id="builderCard">
    <h2 data-i="config_builder">🔨 Config Builder</h2>
    <div class="sub" style="margin-bottom:14px" data-i="builder_sub">Paste configs and IPs — each config is tested against all IPs and rebuilt with the best one</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px" id="builderGrid">
      <div>
        <label style="font-size:12px;color:var(--muted);display:block;margin-bottom:6px" data-i="configs_label">Configs (one per line)</label>
        <textarea id="cfgText" style="min-height:150px" data-i-plh="configs_label" placeholder="vless://...&#10;vmess://...&#10;trojan://...&#10;ss://..."></textarea>
        <div style="display:flex;gap:8px;margin-top:8px">
          <button class="ghost" id="btnPasteCfg" data-i="paste_btn">📋 Paste</button>
          <button class="ghost" id="btnClearCfg" data-i="clear_btn">🗑 Clear</button>
          <span class="muted" id="cfgCount" style="font-size:12px;align-self:center"><span class="cnum">0</span> <span class="clabel" data-i="configs">configs</span></span>
        </div>
      </div>
      <div>
        <label style="font-size:12px;color:var(--muted);display:block;margin-bottom:6px" data-i="ips_label">IPs (one per line)</label>
        <textarea id="ipsText" style="min-height:150px" data-i-plh="ips_label" placeholder="104.16.0.1&#10;1.2.3.4:443&#10;[2606:4700::1]"></textarea>
        <div style="display:flex;gap:8px;margin-top:8px">
          <button class="ghost" id="btnPasteIps" data-i="paste_btn">📋 Paste</button>
          <button class="ghost" id="btnUseScanIps" data-i="use_scan">📥 From scan results</button>
          <button class="ghost" id="btnClearIps" data-i="clear_btn">🗑 Clear</button>
          <span class="muted" id="ipsCount" style="font-size:12px;align-self:center"><span class="cnum">0</span> <span class="clabel" data-i="ips_label">IPs</span></span>
        </div>
      </div>
    </div>
    <div class="actions">
      <button id="btnBuild" data-i="build_configs">🔨 Build Configs</button>
      <button id="btnBuildCancel" class="hidden" data-i="cancel">⛔ Cancel</button>
    </div>
    <div class="progress-card" id="buildProgress" style="margin-top:14px">
      <div class="phase-label" id="buildPhaseLabel" data-i="waiting">Waiting…</div>
      <div class="bar-wrap"><div class="bar" id="buildBar"></div></div>
      <div class="stats">
        <div data-i="done_label">Done<b id="buildDone">0</b></div>
        <div data-i="total_label">Total<b id="buildTotal">0</b></div>
      </div>
    </div>
    <div class="results-card" id="buildResults" style="margin-top:16px">
      <div class="results-head">
        <h2><span data-i="built_configs">🏆 Built Configs</span> <span class="muted" id="buildCount"></span></h2>
        <div style="display:flex;gap:6px;flex-wrap:wrap">
          <button class="ghost" id="btnOutPlain" data-i="copy_plain">📋 Copy plain</button>
          <button class="ghost" id="btnOutBase64" data-i="copy_base64">📋 Copy Base64</button>
          <button class="ghost" id="btnOutSingbox" data-i="copy_singbox">📋 Copy Sing-box</button>
          <button class="ghost" id="btnOutClash" data-i="copy_clash">📋 Copy Clash</button>
        </div>
      </div>
      <div class="table-wrap" style="max-height:260px">
        <table>
          <thead><tr>
            <th>#</th><th data-i="type_col">Type</th><th data-i="host_col">Host</th><th data-i="ip_col">IP</th><th>Port</th><th data-i="latency_col">Latency</th>
          </tr></thead>
          <tbody id="buildTbody"></tbody>
        </table>
      </div>
      <div style="margin-top:12px">
        <div style="display:flex;gap:6px;align-items:center;margin-bottom:6px">
          <span style="font-size:12px;color:var(--muted)" id="outLabel" data-i="output_label">Output</span>
          <button class="ghost" id="btnOutShow" data-i="show_btn">👁 Show</button>
          <button class="ghost" id="btnOutDownload" data-i="download_btn">⬇ Download</button>
        </div>
        <textarea id="outText" style="min-height:140px;font-size:11px" readonly></textarea>
      </div>
    </div>
  </div>

  <div class="card" id="optCard">
    <h2><span data-i="config_optimizer">⚡ Config Optimizer</span> <span class="muted" style="font-weight:400" data-i="optimizer_sub_title">(PattNG — bypass Cloudflare disruption)</span></h2>
    <div class="sub" style="margin-bottom:14px" data-i="optimizer_desc">Paste VLESS/Trojan configs or a subscription link — fp/unsafe, Cipher Suites (cs) and FinalMask (fm) are injected automatically. VMess/SS pass through unchanged.</div>
    <div>
      <label style="font-size:12px;color:var(--muted);display:block;margin-bottom:6px" data-i="opt_configs_label">Configs / subscription link (one per line, or a base64 blob)</label>
      <textarea id="optText" style="min-height:150px;font-size:11px" data-i-plh="opt_input_placeholder" placeholder="vless://...&#10;trojan://...&#10;https://sub.example.com/link&#10;(base64 blobs accepted too)"></textarea>
      <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
        <button class="ghost" id="btnOptPaste" data-i="paste_btn">📋 Paste</button>
        <button class="ghost" id="btnOptClear" data-i="clear_btn">🗑 Clear</button>
        <button class="ghost" id="btnOptSample" data-i="sample_btn">🧪 Sample</button>
        <span class="muted" id="optCount" style="font-size:12px;align-self:center"><span class="cnum">0</span> <span class="clabel" data-i="configs">configs</span></span>
      </div>
    </div>
    <div style="margin-top:14px">
      <div class="sub" style="margin-bottom:8px" data-i="advanced_opts">⚙️ Advanced (IP empty = keep each config’s address · fp/cs/fm empty = default)</div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px">
        <div>
          <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:4px" data-i="clean_ip_addr">Clean IP (Address)</label>
          <input id="optIp" placeholder="e.g. 188.114.97.6">
        </div>
        <div>
          <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:4px" data-i="fingerprint">Fingerprint (fp)</label>
          <input id="optFp" placeholder="unsafe">
        </div>
        <div>
          <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:4px" data-i="cipher_suites">Cipher Suites (cs)</label>
          <input id="optCs" placeholder="13 cipher suites (default)">
        </div>
        <div>
          <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:4px" data-i="finalmask">FinalMask (fm)</label>
          <input id="optFm" placeholder="JSON FinalMask (default)">
        </div>
      </div>
    </div>
    <div style="margin-top:12px;display:flex;align-items:center;gap:12px;flex-wrap:wrap">
      <div class="switch-row" style="margin:0"><label class="switch"><input type="checkbox" id="optRealTest"><span class="slider"></span></label><label for="optRealTest" data-i="real_test">🔌 Real proxy test (Xray core)</label></div>
      <span class="muted" id="xrayStatus" style="font-size:11px" data-i="checking_xray">checking…</span>
      <button class="ghost hidden" id="btnXrayDl" style="font-size:11px" data-i="dl_xray">⬇ Download Xray core</button>
    </div>
    <div style="margin-top:6px"><span class="muted" style="font-size:11px" data-i="xray_note">Note: the test uses standard TLS verification (Xray 26+); configs whose outer TLS cert doesn't validate may show ❌ even when they work in PattNG. The bundled/downloaded core is expected.</span></div>
    <div class="actions" style="margin-top:14px">
      <button id="btnOpt" data-i="optimize_btn">⚡ Optimize</button>
      <button id="btnOptCancel" class="hidden" data-i="cancel">⛔ Cancel</button>
    </div>
    <div class="pattng-note">
      <span><span data-i="pattng_note">⚡ This trick only works on this v2rayNG fork — download</span> <b>PattNG</b>:</span>
      <a href="https://github.com/patterniha/PattNG/releases" target="_blank" rel="noopener" data-i="pattng_link">github.com/patterniha/PattNG/releases ↗</a>
    </div>
    <div class="progress-card" id="optProgress" style="margin-top:14px">
      <div class="phase-label" id="optPhaseLabel" data-i="waiting">Waiting…</div>
      <div class="bar-wrap"><div class="bar" id="optBar"></div></div>
      <div class="stats">
        <div data-i="configs">Configs<b id="optDone">0</b></div>
        <div data-i="errors_col">Errors<b id="optErrors">0</b></div>
      </div>
    </div>
    <div class="results-card" id="optResults" style="margin-top:16px">
      <div class="results-head">
        <h2><span data-i="optimize_results">⚡ Optimization Results</span> <span class="muted" id="optCountLabel"></span></h2>
        <div style="display:flex;gap:6px;flex-wrap:wrap">
          <button class="ghost" id="btnOptCopy" data-i="copy_all">📋 Copy all</button>
          <button class="ghost" id="btnOptDownload" data-i="download_btn">⬇ Download</button>
        </div>
      </div>
      <div class="table-wrap" style="max-height:220px">
        <table>
          <thead><tr><th>#</th><th data-i="type_col">Type</th><th data-i="status_col">Status</th><th data-i="test_col">Test</th><th data-i="changes_col">Changes</th></tr></thead>
          <tbody id="optTbody"></tbody>
        </table>
      </div>
      <div id="optErrorsBox" style="margin-top:10px;display:none">
        <div class="sub" style="color:var(--err);margin-bottom:4px" data-i="opt_errors">⚠️ Errors</div>
        <textarea id="optErrorsText" style="min-height:70px;font-size:11px" readonly></textarea>
      </div>
      <div style="margin-top:12px">
        <label style="font-size:12px;color:var(--muted);display:block;margin-bottom:6px" data-i="opt_output">Output — ready for PattNG</label>
        <textarea id="optOut" style="min-height:180px;font-size:11px" readonly></textarea>
      </div>
    </div>
  </div>

  <footer data-i="footer">Narsaq v1.0.0</footer>
</div>

<div class="toast" id="toast"></div>

<script>
const $ = id => document.getElementById(id);
let es = null;
let results = [];
let cleanIpsText = '';
let configsText = '';
let optResults = [];
let optOut = '';

// ─── theme toggle ───
function applyTheme(t) {
  document.body.dataset.theme = t;
  $('btnTheme').textContent = t === 'dark' ? '☀️ Light' : '🌙 Dark';
  try { localStorage.setItem('narsaq-theme', t); } catch (e) {}
}
(function () {
  let t = 'dark';
  try { t = localStorage.getItem('narsaq-theme') || 'dark'; } catch (e) {}
  applyTheme(t);
})();
$('btnTheme').onclick = () => {
  applyTheme(document.body.dataset.theme === 'dark' ? 'light' : 'dark');
};

// ─── i18n: Persian / English ───
const I18N = {
  en: {
    title:'Narsaq \u2014 Cloudflare Clean IP Scanner',scanner_name:'Narsaq Scanner',scanner_sub:'Cloudflare clean IP finder & config optimizer',
    theme_light:'☀️ Light',theme_dark:'🌙 Dark',lang_en:'English',lang_fa:'فارسی',
    connecting:'Connecting…',connected:'● Connected',disconnected:'○ Disconnected',
    scan_settings:'⚙️ Scan Settings',num_ips:'Number of IPs',ports:'Ports (comma separated)',
    alt_ports:'🔀 Cloudflare alt ports',timeout:'Timeout (s)',concurrency:'Concurrency',
    scan_ipv6:'Scan IPv6',neighbor_scan:'Neighbor scan',
    multi_verify:'Multi-step verify',speed_test:'Speed test (Mbps)',
    custom_ranges:'Custom ranges (optional — one CIDR or IP per line)',
    config_file:'Config file (optional — for building final configs)',
    choose_file:'📂 Choose file',start_scan:'🚀 Start Scan',
    scanning:'⏳ Scanning…',cancel:'⛔ Cancel',
    scan_progress:'📡 Scan Progress',waiting_start:'Waiting to start…',
    done_label:'Done',found_label:'Found',total_label:'Total',
    clean_ips:'🏆 Clean IPs',copy_ips:'📋 Copy IPs',copy_configs:'📋 Copy configs',
    type_col:'Type',ip_col:'IP',latency_col:'Latency',colo_col:'Colo',
    loss_col:'Loss',jitter_col:'Jitter',speed_col:'Speed',
    status_col:'Status',changes_col:'Changes',test_col:'Test',host_col:'Host',
    config_builder:'🔨 Config Builder',
    builder_sub:'Paste configs and IPs — each config is tested against all IPs and rebuilt with the best one',
    configs_label:'Configs (one per line)',ips_label:'IPs (one per line)',
    paste_btn:'📋 Paste',clear_btn:'🗑 Clear',use_scan:'📥 From scan results',
    build_configs:'🔨 Build Configs',built_configs:'🏆 Built Configs',
    copy_plain:'📋 Copy plain',copy_base64:'📋 Copy Base64',
    copy_singbox:'📋 Copy Sing-box',copy_clash:'📋 Copy Clash',
    output_label:'Output',show_btn:'👁 Show',download_btn:'⬇ Download',
    config_optimizer:'⚡ Config Optimizer',
    optimizer_sub_title:'(PattNG — bypass Cloudflare disruption)',
    optimizer_desc:'Paste VLESS/Trojan configs or a subscription link — fp/unsafe, Cipher Suites (cs) and FinalMask (fm) are injected automatically. VMess/SS pass through unchanged.',
    opt_configs_label:'Configs / subscription link (one per line, or a base64 blob)',
    opt_input_placeholder:'vless://...\ntrojan://...\nhttps://sub.example.com/link\n(base64 blobs accepted too)',
    sample_btn:'🧪 Sample',
    advanced_opts:"⚙️ Advanced (IP empty = keep each config's address \u00b7 fp/cs/fm empty = default)",
    clean_ip_addr:'Clean IP (Address)',fingerprint:'Fingerprint (fp)',
    cipher_suites:'Cipher Suites (cs)',finalmask:'FinalMask (fm)',
    real_test:'🔌 Real proxy test (Xray core)',checking_xray:'checking…',
    dl_xray:'⬇ Download Xray core',
    xray_note:"Note: the test uses standard TLS verification (Xray 26+); configs whose outer TLS cert doesn't validate may show \u274c even when they work in PattNG.",
    optimize_btn:'⚡ Optimize',
    pattng_note:'⚡ This trick only works on this v2rayNG fork — download',
    pattng_link:'github.com/patterniha/PattNG/releases \u2197',
    optimize_results:'⚡ Optimization Results',copy_all:'📋 Copy all',
    opt_errors:'⚠️ Errors',opt_output:'Output — ready for PattNG',
    errors_col:'Errors',optimized:'Optimized',passthrough:'Pass-through',
    no_xray:'⏭ no Xray',waiting:'Waiting…',
    status_ok:'✅ Scan complete',status_cancelled:'⛔ Cancelled',
    configs:'Configs',footer:'Narsaq v1.0.0',
    clean_ips_found:'clean IPs found',clean_ips_prev:'clean IPs (previous scan)',
    error_prefix:'\u274c ',progress_prefix:'\ud83d\udd04 ',done_prefix:'\u2705 ',
    building_outputs:'Building outputs...',extracting_configs:'Extracting configs...',
    built_short:'built',optimized_short:'optimized',start_failed:'Failed to start scan',fetch_error:'Error fetching output',dl_xray_progress:'⏳ Downloading Xray…',
  },
  fa: {
    title:'\u0646\u0631\u0633\u0627\u0642 \u2014 \u0627\u0633\u06a9\u0646\u0631 \u0622\u06cc\u200c\u067e\u06cc \u062a\u0645\u06cc\u0632 \u06a9\u0644\u0627\u062f\u0641\u0644\u0631',scanner_name:'Narsaq Scanner',scanner_sub:'\u06cc\u0627\u0641\u062a\u0646 \u0622\u06cc\u200c\u067e\u06cc \u062a\u0645\u06cc\u0632 \u06a9\u0644\u0627\u062f\u0641\u0644\u0631 \u0648 \u0628\u0647\u06cc\u0646\u0647\u200c\u0633\u0627\u0632 \u06a9\u0627\u0646\u0641\u06cc\u06af',
    theme_light:'☀️ روشن',theme_dark:'🌙 تیره',lang_fa:'فارسی',lang_en:'English',
    connecting:'در حال اتصال…',connected:'● متصل',disconnected:'○ قطع',
    scan_settings:'⚙️ تنظیمات اسکن',num_ips:'تعداد آی‌پی',ports:'پورت‌ها (با کاما جدا)',
    alt_ports:'🔀 پورت‌های جایگزین کلادفلر',timeout:'مهلت (ثانیه)',concurrency:'همزمانی',
    scan_ipv6:'اسکن IPv6',neighbor_scan:'اسکن همسایه',
    multi_verify:'تأیید چندمرحله‌ای',speed_test:'تست سرعت (Mbps)',
    custom_ranges:'محدوده سفارشی (اختیاری — هر خط یک CIDR یا آی‌پی)',
    config_file:'فایل کانفیگ (اختیاری — برای ساخت کانفیگ نهایی)',
    choose_file:'📂 انتخاب فایل',start_scan:'🚀 شروع اسکن',
    scanning:'⏳ در حال اسکن…',cancel:'⛔ لغو',
    scan_progress:'📡 پیشرفت اسکن',waiting_start:'منتظر شروع…',
    done_label:'انجام',found_label:'پیدا',total_label:'مجموع',
    clean_ips:'🏆 آی‌پی‌های تمیز',copy_ips:'📋 کپی آی‌پی‌ها',copy_configs:'📋 کپی کانفیگ‌ها',
    type_col:'نوع',ip_col:'آی‌پی',latency_col:'تاخیر',colo_col:'موقعیت',
    loss_col:'افت',jitter_col:'نوسان',speed_col:'سرعت',
    status_col:'وضعیت',changes_col:'تغییرات',test_col:'تست',host_col:'هاست',
    config_builder:'🔨 سازنده کانفیگ',
    builder_sub:'کانفیگ‌ها و آی‌پی‌ها را جایگذین کنید — هر کانفیگ روی همه آی‌پی‌ها تست و با بهترین‌شان ساخته می‌شود',
    configs_label:'کانفیگ‌ها (هر خط یکی)',ips_label:'آی‌پی‌ها (هر خط یکی)',
    paste_btn:'📋 چسباندن',clear_btn:'🗑 پاک کردن',use_scan:'📥 از نتایج اسکن',
    build_configs:'🔨 ساخت کانفیگ',built_configs:'🏆 کانفیگ‌های ساخته شده',
    copy_plain:'📋 کپی ساده',copy_base64:'📋 کپی Base64',
    copy_singbox:'📋 کپی Sing-box',copy_clash:'📋 کپی Clash',
    output_label:'خروجی',show_btn:'👁 نمایش',download_btn:'⬇ دانلود',
    config_optimizer:'⚡ بهینه‌ساز کانفیگ',
    optimizer_sub_title:'(PattNG — عبور از اختلال کلادفلر)',
    optimizer_desc:'کانفیگ‌های VLESS/Trojan یا لینک ساب رو بذار — fp/unsafe، Cipher Suites (cs) و FinalMask (fm) خودکار تزریق می‌شن. کانفیگ‌های VMess/SS بدون تغییر عبور می‌کنن.',
    opt_configs_label:'کانفیگ‌ها / لینک ساب (هر خط یکی، یا متن base64)',
    opt_input_placeholder:'vless://...\ntrojan://...\nhttps://sub.example.com/link\n(متن base64 هم قبوله)',
    sample_btn:'🧪 نمونه',
    advanced_opts:"⚙️ پیشرفته (آی‌پی خالی = آدرس خود کانفیگ حفظ می‌شه \u00b7 fp/cs/fm خالی = پیش‌فرض)",
    clean_ip_addr:'آی‌پی تمیز (آدرس)',fingerprint:'اثر انگشت (fp)',
    cipher_suites:'مجموعه رمز (cs)',finalmask:'ماسک نهایی (fm)',
    real_test:'🔌 تست واقعی پراکسی (هسته Xray)',
    checking_xray:'در حال بررسی…',dl_xray:'⬇ دانلود هسته Xray',
    xray_note:'توجه: تست از تأیید استاندارد TLS استفاده می‌کنه (Xray 26+)؛ کانفیگ‌هایی که گواهی TLS خارجی ندارن ممکنه ❌ نشون بدن حتی توی PattNG کار کنن.',
    optimize_btn:'⚡ بهینه‌سازی',
    pattng_note:'⚡ این ترفند فقط روی این fork ویتوری جواب میده — دانلود',
    pattng_link:'github.com/patterniha/PattNG/releases \u2197',
    optimize_results:'⚡ نتایج بهینه‌سازی',
    copy_all:'📋 کپی همه',opt_errors:'⚠️ خطاها',opt_output:'خروجی — آماده برای PattNG',
    errors_col:'خطاها',optimized:'بهینه شده',passthrough:'بدون تغییر',
    no_xray:'⏭ بدون Xray',waiting:'منتظر…',
    status_ok:'✅ اسکن کامل شد',status_cancelled:'⛔ لغو شد',
    configs:'کانفیگ‌ها',footer:'نرساق نسخه ۱.۰.۰',
    clean_ips_found:'آی‌پی تمیز پیدا شد',clean_ips_prev:'آی‌پی تمیز (اسکن قبلی)',
    error_prefix:'❌ ',progress_prefix:'🔄 ',done_prefix:'✅ ',
    building_outputs:'در حال ساخت خروجی...',extracting_configs:'در حال استخراج کانفیگ‌ها...',
    built_short:'ساخته شد',optimized_short:'بهینه شد',start_failed:'شروع اسکن ناموفق بود',fetch_error:'خطا در دریافت خروجی',dl_xray_progress:'⏳ در حال دانلود Xray…',
  }
};
let _cl = 'en';
try{_cl=localStorage.getItem('narsaq-lang')||'en'}catch(e){}
function t(k){const o=I18N[_cl]||I18N.en;return o[k]!=null?o[k]:k;}
const PHASES={
  'Generating IPs':['تولید آی‌پی','Generating IPs'],
  'Generating IPs from Cloudflare ranges':['تولید آی‌پی از محدوده کلادفلر','Generating IPs from Cloudflare ranges'],
  'Ready to scan':['آماده اسکن','Ready to scan'],
  'Scan cancelled':['اسکن لغو شد','Scan cancelled'],
  'Scan complete':['اسکن کامل شد','Scan complete'],
  'Done':['پایان','Done'],
  'Cancelled':['لغو شد','Cancelled'],
  'Error':['خطا','Error'],
  'Building outputs...':['در حال ساخت خروجی...','Building outputs...'],
  'Extracting configs...':['در حال استخراج کانفیگ‌ها...','Extracting configs...'],
  'Real proxy test (Xray core)...':['تست واقعی پراکسی (هسته Xray)...','Real proxy test (Xray core)...'],
  'Xray core not found - use the download button':['هسته Xray پیدا نشد - از دکمه دانلود استفاده کنید','Xray core not found - use the download button'],
  'Saved':['ذخیره شد','Saved'],
  'Started':['شروع شد','Started'],
};
function tp(ph){
  const v=PHASES[ph];if(!v)return ph;
  return _cl==='fa'?v[0]:v[1];
}
function translateUI(){
  document.querySelectorAll('[data-i]').forEach(e=>{
    if(e.hasAttribute('data-i-plh')){e.placeholder=t(e.getAttribute('data-i-plh'));return;}
    if(e.children.length===0){e.textContent=t(e.getAttribute('data-i'));}
  });
  const ti=document.querySelector('title');if(ti&&ti.hasAttribute('data-i'))ti.textContent=t(ti.getAttribute('data-i'));
  document.body.dir=_cl==='fa'?'rtl':'ltr';
  const th=document.body.dataset.theme;$('btnTheme').textContent=th==='dark'?t('theme_light'):t('theme_dark');
  $('btnLang').textContent=_cl==='fa'?'English':'فارسی';
  $('btnLang').addEventListener('click',()=>{_cl=_cl==='en'?'fa':'en';try{localStorage.setItem('narsaq-lang',_cl)}catch(e){}translateUI();})
}

function toast(msg, isErr) {
  const t = $('toast');
  t.textContent = msg;
  t.className = 'toast show' + (isErr ? ' err' : '');
  clearTimeout(t._h);
  t._h = setTimeout(() => t.className = 'toast', 3500);
}

function renderOptResults() {
  const tb = $('optTbody');
  tb.innerHTML = '';
  optResults.forEach(r => {
    const tr = document.createElement('tr');
    let status, changes;
    if (r.error) { status = '<span style="color:var(--err)">Error</span>'; changes = r.error; }
    else if (r.changes && (r.changes.some(c => c.includes('→')) || r.changes.some(c => /cs|fm|fp|Cipher|FinalMask|injected/i.test(c)))) { status = '<span style="color:var(--ok)">Optimized</span>'; changes = r.changes.join(' • '); }
    else { status = '<span style="color:var(--muted)">Pass-through</span>'; changes = (r.changes || []).join(' • '); }
    let testCell;
    if (r.test === 'ok') testCell = `<td style="font-size:11px;color:var(--ok);white-space:nowrap">✅ ${r.latency_ms != null ? Math.round(r.latency_ms) : ''} ms</td>`;
    else if (r.test === 'fail') testCell = `<td style="font-size:11px;color:var(--err)" title="${(r.test_error || '').replace(/"/g, '&quot;')}">❌</td>`;
    else if (r.test === 'no-xray') testCell = '<td style="font-size:11px;color:var(--muted)">⏭ no Xray</td>';
    else if (r.test === 'skip') testCell = '<td style="font-size:11px;color:var(--muted)" title="Not testable with Xray">⏭</td>';
    else if (r.test === 'cancelled') testCell = '<td style="font-size:11px;color:var(--muted)">⛔</td>';
    else testCell = '<td style="font-size:11px;color:var(--muted)">—</td>';
    tr.innerHTML = `<td>${r.index}</td><td>${r.type}</td><td>${status}</td>${testCell}<td style="font-size:11px">${changes}</td>`;
    tb.appendChild(tr);
  });
  $('optCountLabel').textContent = `(${optResults.length} ${t('configs')})`;
  $('optOut').value = optOut;
}

function optCount() {
  const t = $('optText').value.trim();
  const n = t ? t.split(/\n+/).filter(l => l.trim() && !l.trim().startsWith('#')).length : 0;
  try{const e=$('optCount'),n=e?e.querySelector('.cnum'):null;if(n)n.textContent=n;}catch(e){}
}

function connectSSE() {
  if (es) es.close();
  (function(){try{window._narsaqLang=localStorage.getItem('narsaq-lang')||'en'}catch(e){window._narsaqLang='en'}})();
  es = new EventSource('/events?lang='+window._narsaqLang);
  es.onopen = () => { $('connPill').textContent = t('connected'); $('connPill').style.color = 'var(--ok)'; };
  es.addEventListener('opt-progress', e => {
    const d = JSON.parse(e.data);
    $('optProgress').classList.add('active');
    $('optPhaseLabel').textContent = tp(d.phase || '...');
    const bar = $('optBar');
    if (d.total > 0) bar.style.width = Math.min(100, (d.done / d.total) * 100) + '%';
    $('optDone').textContent = d.found || d.done || 0;
    $('optErrors').textContent = Math.max(0, (d.total || 0) - (d.done || 0));
  });
  es.addEventListener('xray-dl', e => {
    const d = JSON.parse(e.data);
    if (d.progress != null) { $('xrayStatus').textContent = t('dl_xray_progress') + ' ' + Math.round(d.progress * 100) + '%'; }
    else {
      const dl = $('btnXrayDl');
      dl.disabled = false;
      dl.textContent = t('dl_xray');
      if (d.error) toast(d.error, true);
      refreshXrayStatus();
    }
  });
  es.addEventListener('opt-done', e => {
    const d = JSON.parse(e.data);
    $('optProgress').classList.remove('active');
    $('btnOpt').classList.remove('hidden');
    $('btnOptCancel').classList.add('hidden');
    if (d.state === 'error') {
      $('optPhaseLabel').textContent = t('error_prefix') + (d.message || 'Error');
      toast(d.message || 'Error', true);
      return;
    }
    $('optPhaseLabel').textContent = t('done_prefix') + 'Done';
    if (d.results && d.results.length) {
      optResults = d.results;
      optOut = d.output || '';
    } else {
      const lines = (d.output || '').split('\n').filter(l => l.trim());
      optResults = lines.map((o, i) => ({index: i + 1, type: '?', output: o, changes: []}));
      optOut = d.output || '';
    }
    if (d.error_list && d.error_list.length) {
      $('optErrorsText').value = d.error_list.map(e => `#${e.index} ${e.error}`).join('\n');
    } else {
      $('optErrorsText').value = '';
    }
    const hasErr = (d.error_list && d.error_list.length) || optResults.some(r => r.error);
    $('optErrorsBox').style.display = hasErr ? 'block' : 'none';
    $('optResults').classList.add('active');
    renderOptResults();
    if (d.count) toast('⚡ ' + d.count + ' ' + t('configs') + ' ' + t('optimized_short') + (d.errors ? ` (${d.errors} errors)` : ''));
  });
  es.onerror = () => { $('connPill').textContent = t('disconnected'); $('connPill').style.color = 'var(--err)'; };

  es.addEventListener('hello', e => {
    const d = JSON.parse(e.data);
    if (d.running) {
      $('progressCard').classList.add('active');
      $('phaseLabel').textContent = t('progress_prefix') + tp(d.phase);
      $('btnStart').disabled = true;
      $('btnStart').textContent = t('scanning');
      $('btnCancel').classList.remove('hidden');
    }
    if (d.results && d.results.length) {
      results = d.results;
      $('resultsCard').classList.add('active');
      $('progressCard').classList.add('active');
      $('phaseLabel').textContent = t('done_prefix') + results.length + ' ' + t('clean_ips_prev');
      $('bar').style.width = '100%';
      $('stFound').textContent = results.length;
      cleanIpsText = results.map(r => {
        const ip = r.ip.includes(':') ? '[' + r.ip + ']' : r.ip;
        return ip + ':' + r.port;
      }).join('\n');
      renderTable(results);
    }
  });
  es.addEventListener('progress', e => {
    const d = JSON.parse(e.data);
    $('progressCard').classList.add('active');
    $('phaseLabel').textContent = t('progress_prefix') + tp(d.phase);
    $('stDone').textContent = d.done;
    $('stFound').textContent = d.found;
    $('stTotal').textContent = d.total;
    const pct = d.total ? Math.round(d.done * 100 / d.total) : 0;
    $('bar').style.width = Math.min(pct, 100) + '%';
  });
  es.addEventListener('phase', e => {
    const d = JSON.parse(e.data);
    $('progressCard').classList.add('active');
    $('phaseLabel').textContent = '🔄 ' + d.phase;
  });
  es.addEventListener('results', e => {
    const d = JSON.parse(e.data);
    results = d.results || [];
    $('resultsCard').classList.add('active');
    $('progressCard').classList.add('active');
    $('phaseLabel').textContent = t('done_prefix') + results.length + ' ' + t('clean_ips_found');
    $('bar').style.width = '100%';
    $('stFound').textContent = results.length;
    cleanIpsText = results.map(r => {
      const ip = r.ip.includes(':') ? '[' + r.ip + ']' : r.ip;
      return ip + ':' + r.port;
    }).join('\n');
    if (d.clean_ips_file) {
      $('cleanFile').textContent = '📄 ' + d.clean_ips_file;
      $('cleanFile').classList.remove('hidden');
    }
    renderTable(results);
  });
  es.addEventListener('configs', e => {
    const d = JSON.parse(e.data);
    $('cfgResult').innerHTML =
      '<div class="file-line">📄 ' + d.file + ' — ' + d.count + ' ' + t('configs') + '</div>';
    toast(t('done_prefix') + d.count + ' ' + t('configs') + ' ' + t('built_short'));
  });
  es.addEventListener('done', e => {
    const d = JSON.parse(e.data);
    $('btnStart').disabled = false;
    $('btnStart').textContent = t('start_scan');
    $('btnCancel').classList.add('hidden');
    if (d.state === 'done') {
      $('phaseLabel').textContent = t('status_ok');
      toast('✅ ' + d.message);
    } else if (d.state === 'cancelled') {
      $('phaseLabel').textContent = t('status_cancelled');
      toast(t('status_cancelled'), true);
    } else {
      $('phaseLabel').textContent = t('error_prefix') + (d.message || 'Error');
      toast(d.message || 'Error', true);
    }
  });
  es.addEventListener('build-progress', e => {
    const d = JSON.parse(e.data);
    $('buildProgress').classList.add('active');
    $('buildPhaseLabel').textContent = t('progress_prefix') + tp(d.phase);
    $('buildDone').textContent = d.done;
    $('buildTotal').textContent = d.total;
    const pct = d.total ? Math.round(d.done * 100 / d.total) : 0;
    $('buildBar').style.width = Math.min(pct, 100) + '%';
  });
  es.addEventListener('build-phase', e => {
    const d = JSON.parse(e.data);
    $('buildProgress').classList.add('active');
    $('buildPhaseLabel').textContent = '🔄 ' + d.phase;
  });
  es.addEventListener('build-done', async e => {
    const d = JSON.parse(e.data);
    $('btnBuild').disabled = false;
    $('btnBuild').textContent = t('build_configs');
    $('btnBuildCancel').classList.add('hidden');
    if (d.state === 'done') {
      try {
        const resp = await fetch('/api/build-outputs');
        const j = await resp.json();
        buildResults = j.results || [];
        buildOutputs = j.outputs || buildOutputs;
        $('buildCount').textContent = '— ' + buildResults.length + ' ' + t('configs');
        $('buildResults').classList.add('active');
        $('buildProgress').classList.add('active');
        $('buildPhaseLabel').textContent = t('done_prefix') + buildResults.length + ' ' + t('configs') + ' ' + t('built_short');
        $('buildBar').style.width = '100%';
        renderBuildTable();
        setOutText();
        toast(t('done_prefix') + buildResults.length + ' ' + t('configs') + ' ' + t('built_short'));
      } catch (err) {
        toast(t('fetch_error'), true);
      }
    } else {
      $('buildPhaseLabel').textContent = t('error_prefix') + (d.message || 'Error');
      toast(d.message || 'Error', true);
    }
  });
}

function renderTable(rows) {
  const tb = $('tbody');
  tb.innerHTML = '';
  rows.slice(0, 100).forEach((r, i) => {
    const total = r.tls_ms || r.tcp_ms || '—';
    const tr = document.createElement('tr');
    tr.innerHTML =
      '<td class="rank">' + (i + 1) + '</td>' +
      '<td class="ip">' + (r.ip.includes(':') ? '[' + r.ip + ']' : r.ip) + ':' + r.port + '</td>' +
      '<td>' + (typeof total === 'number' ? Math.round(total) + ' ms' : total) + '</td>' +
      '<td>' + (r.colo ? '<span class="colo-chip">' + r.colo + '</span>' : '<span class="muted">—</span>') + '</td>' +
      '<td>' + (r.loss !== undefined ? '<span class="' + (r.loss < 10 ? 'ok' : 'warn') + '">' + r.loss.toFixed(0) + '%</span>' : '<span class="muted">—</span>') + '</td>' +
      '<td>' + (r.jitter !== undefined ? '±' + Math.round(r.jitter) + ' ms' : '<span class="muted">—</span>') + '</td>' +
      '<td>' + (r.mbps ? '<b class="ok">' + r.mbps.toFixed(1) + ' Mbps</b>' : '<span class="muted">—</span>') + '</td>';
    tb.appendChild(tr);
  });
}

$('btnStart').onclick = async () => {
  const body = {
    count: parseInt($('count').value) || 300,
    ports: $('ports').value || '443',
    timeout: parseFloat($('timeout').value) || 3,
    workers: parseInt($('workers').value) || 64,
    v6: $('v6').checked,
    neighbor_scan: $('nscan').checked,
    verify: $('verify').checked,
    speed_test: $('speed').checked,
    custom_ranges: $('customRanges').value,
    config_file: $('configFile').value.trim(),
  };
  $('btnStart').disabled = true;
  $('btnStart').textContent = t('scanning');
  $('btnCancel').classList.remove('hidden');
  $('resultsCard').classList.remove('active');
  $('cfgResult').innerHTML = '';
  $('cleanFile').classList.add('hidden');
  $('tbody').innerHTML = '';
  try {
    const resp = await fetch('/api/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const j = await resp.json();
    if (!j.ok) toast(j.message || 'A scan is already running', true);
  } catch (err) {
    toast(t('start_failed'), true);
    $('btnStart').disabled = false;
    $('btnStart').textContent = t('start_scan');
  }
};

$('btnCancel').onclick = async () => {
  try { await fetch('/api/cancel', { method: 'POST' }); } catch (e) {}
};

$('btnBrowse').onclick = () => {
  const inp = document.createElement('input');
  inp.type = 'file';
  inp.accept = '.txt,.conf';
  inp.onchange = () => { if (inp.files[0]) $('configFile').value = inp.files[0].name; };
  inp.click();
};

$('btnCopyIps').onclick = async () => {
  if (!cleanIpsText) { toast('No IPs found yet', true); return; }
  try {
    await navigator.clipboard.writeText(cleanIpsText);
    toast('📋 IPs copied');
  } catch (e) { toast('Copy failed', true); }
};

$('btnCopyCfg').onclick = async () => {
  if (!configsText) { toast('No configs built yet', true); return; }
  try {
    await navigator.clipboard.writeText(configsText);
    toast('📋 Configs copied');
  } catch (e) { toast('Copy failed', true); }
};

setInterval(async () => {
  if (!configsText && $('cfgResult').textContent.includes('configs')) {
    try {
      const resp = await fetch('/api/last-configs');
      const j = await resp.json();
      if (j.content) configsText = j.content;
    } catch (e) {}
  }
}, 2000);

$('btnAltPorts').onclick = () => { $('ports').value = '2053,2083,2087,2096,8443'; toast('🔀 Alternative ports set — rescan'); };

function optRun() {
  const text = $('optText').value.trim();
  if (!text) { toast('Enter configs or a subscription link first', true); return; }
  const opts = {};
  if ($('optIp').value.trim()) opts.cdn_ip = $('optIp').value.trim();
  if ($('optFp').value.trim()) opts.fp = $('optFp').value.trim();
  if ($('optCs').value.trim()) opts.cs = $('optCs').value.trim();
  if ($('optFm').value.trim()) opts.fm = $('optFm').value.trim();
  $('btnOpt').classList.add('hidden');
  $('btnOptCancel').classList.remove('hidden');
  $('optResults').classList.remove('active');
  $('optProgress').classList.add('active');
  $('optPhaseLabel').textContent = 'Starting…';
  $('optBar').style.width = '0%';
  fetch('/api/opt-optimize', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ text, opts, real_test: $('optRealTest').checked })
  }).then(r => r.json()).then(j => {
    if (!j.ok) toast(j.message || 'Failed to start optimization', true);
  }).catch(() => toast('Failed to start optimization', true));
}
$('btnOpt').onclick = optRun;
$('btnOptCancel').onclick = () => { try { fetch('/api/opt-cancel', {method: 'POST'}); } catch (e) {} };
$('btnOptPaste').onclick = () => {
  navigator.clipboard.readText().then(t => { $('optText').value = t; optCount(); toast('📋 Pasted'); })
    .catch(() => toast('Clipboard is empty', true));
};
$('btnOptClear').onclick = () => { $('optText').value = ''; optCount(); $('optResults').classList.remove('active'); };
$('btnOptSample').onclick = () => {
  $('optText').value = 'vless://6f4b5e2a-3c9d-4f1e-8a7b-2c3d4e5f6a7b@example.com:443?encryption=none&security=reality&sni=yahoo.com&fp=chrome&pbk=test&sid=abcd&type=tcp&flow=xtls-rprx-vision#Test';
  optCount(); toast('🧪 Sample loaded — press ⚡ Optimize');
};
$('btnOptCopy').onclick = () => {
  if (!optOut) { toast('No output yet', true); return; }
  navigator.clipboard.writeText(optOut).then(() => toast('📋 Output copied'))
    .catch(() => toast('Copy failed', true));
};
function refreshXrayStatus() {
  fetch('/api/xray-status').then(r => r.json()).then(j => {
    const st = $('xrayStatus'), dl = $('btnXrayDl');
    if (j.path) {
      st.textContent = '✅ Xray core: ' + j.path.split(/[\\/]/).slice(-2).join('/');
      st.style.color = 'var(--ok)';
      dl.classList.add('hidden');
    } else {
      st.textContent = '❌ Xray core not found — real test needs it';
      st.style.color = 'var(--err)';
      dl.classList.remove('hidden');
    }
  }).catch(() => {});
}
refreshXrayStatus();
setInterval(refreshXrayStatus, 8000);
$('btnXrayDl').onclick = () => {
  const dl = $('btnXrayDl'), st = $('xrayStatus');
  dl.disabled = true;
  dl.textContent = '⏳ Downloading…';
  st.textContent = '⏳ Downloading Xray core…';
  fetch('/api/xray-download', {method: 'POST'}).then(r => r.json()).then(j => {
    if (!j.ok) { toast(j.message || 'Download failed', true); dl.disabled = false; dl.textContent = '⬇ Download Xray core'; }
  }).catch(() => { dl.disabled = false; dl.textContent = '⬇ Download Xray core'; });
};
$('btnOptDownload').onclick = () => {
  if (!optOut) { toast('No output yet', true); return; }
  const blob = new Blob([optOut], {type: 'text/plain;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'optimized_configs.txt';
  a.click();
  URL.revokeObjectURL(a.href);
  toast('⬇ File downloaded');
};
$('optText').addEventListener('input', optCount);

// ─── config builder ───
let buildResults = [];
let buildOutputs = { plain: '', base64: '', singbox: '', clash: '' };
let buildOutKey = 'plain';

function countLines(id) {
  const v = $(id).value;
  return v.split('\n').filter(l => l.trim()).length;
}
function refreshCounts() {
  try{const e=$('cfgCount'),n=e?e.querySelector('.cnum'):null;if(n)n.textContent=countLines('cfgText');}catch(e){}
  try{const e=$('ipsCount'),n=e?e.querySelector('.cnum'):null;if(n)n.textContent=countLines('ipsText');}catch(e){}
}

$('btnPasteCfg').onclick = async () => {
  try {
    const t = await navigator.clipboard.readText();
    $('cfgText').value = t; refreshCounts(); toast('📋 Configs pasted');
  } catch (e) { toast('Clipboard is empty', true); }
};
$('btnPasteIps').onclick = async () => {
  try {
    const t = await navigator.clipboard.readText();
    $('ipsText').value = t; refreshCounts(); toast('📋 IPs pasted');
  } catch (e) { toast('Clipboard is empty', true); }
};
$('btnUseScanIps').onclick = () => {
  if (!cleanIpsText) { toast('Run a scan first to have clean IPs', true); return; }
  $('ipsText').value = cleanIpsText; refreshCounts();
  toast('📥 Scan results IPs loaded');
};
$('btnClearCfg').onclick = () => { $('cfgText').value = ''; refreshCounts(); };
$('btnClearIps').onclick = () => { $('ipsText').value = ''; refreshCounts(); };
$('cfgText').addEventListener('input', refreshCounts);
$('ipsText').addEventListener('input', refreshCounts);

function renderBuildTable() {
  const tb = $('buildTbody');
  tb.innerHTML = '';
  buildResults.slice(0, 100).forEach((r, i) => {
    const tr = document.createElement('tr');
    tr.innerHTML =
      '<td class="rank">' + (i + 1) + '</td>' +
      '<td><span class="colo-chip">' + r.type + '</span></td>' +
      '<td class="ip">' + r.host + '</td>' +
      '<td class="ip">' + r.best_ip + '</td>' +
      '<td>' + r.best_port + '</td>' +
      '<td>' + Math.round(r.latency_ms) + ' ms</td>';
    tb.appendChild(tr);
  });
}

function setOutText() {
  $('outLabel').textContent = {
    plain: 'Output: plain text',
    base64: 'Output: Base64 subscription',
    singbox: 'Output: Sing-box JSON',
    clash: 'Output: Clash YAML',
  }[buildOutKey] || 'Output';
  $('outText').value = buildOutputs[buildOutKey] || '';
}

$('btnOutPlain').onclick = async () => {
  if (!buildOutputs.plain) { toast('No configs built yet', true); return; }
  try {
    await navigator.clipboard.writeText(buildOutputs.plain);
    toast('📋 Configs (plain) copied');
  } catch (e) { toast('Copy failed', true); }
};
$('btnOutBase64').onclick = async () => {
  if (!buildOutputs.base64) { toast('No configs built yet', true); return; }
  try {
    await navigator.clipboard.writeText(buildOutputs.base64);
    toast('📋 Base64 subscription copied');
  } catch (e) { toast('Copy failed', true); }
};
$('btnOutSingbox').onclick = async () => {
  if (!buildOutputs.singbox) { toast('No configs built yet', true); return; }
  try {
    await navigator.clipboard.writeText(buildOutputs.singbox);
    toast('📋 Sing-box JSON copied');
  } catch (e) { toast('Copy failed', true); }
};
$('btnOutClash').onclick = async () => {
  if (!buildOutputs.clash) { toast('No configs built yet', true); return; }
  try {
    await navigator.clipboard.writeText(buildOutputs.clash);
    toast('📋 Clash YAML copied');
  } catch (e) { toast('Copy failed', true); }
};
$('btnOutShow').onclick = () => {
  const keys = ['plain', 'base64', 'singbox', 'clash'];
  const idx = keys.indexOf(buildOutKey);
  buildOutKey = keys[(idx + 1) % keys.length];
  setOutText();
};
$('btnOutDownload').onclick = () => {
  const ext = { plain: 'txt', base64: 'txt', singbox: 'json', clash: 'yaml' }[buildOutKey] || 'txt';
  const blob = new Blob([buildOutputs[buildOutKey] || ''], { type: 'text/plain;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'narsaq_configs.' + ext;
  a.click();
  URL.revokeObjectURL(a.href);
  toast('⬇ File downloaded');
};

$('btnBuild').onclick = async () => {
  const configs = $('cfgText').value;
  const ips = $('ipsText').value;
  if (!configs.trim()) { toast('Enter configs first', true); return; }
  if (!ips.trim()) { toast('Enter IPs first', true); return; }
  $('btnBuild').disabled = true;
  $('btnBuild').textContent = '⏳ Building…';
  $('btnBuildCancel').classList.remove('hidden');
  $('buildResults').classList.remove('active');
  $('buildProgress').classList.add('active');
  $('buildPhaseLabel').textContent = '🔄 Starting…';
  $('buildBar').style.width = '0%';
  try {
    const resp = await fetch('/api/build-configs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        configs, ips,
        timeout: parseFloat($('timeout').value) || 3,
        workers: parseInt($('workers').value) || 64,
        top: 10,
      }),
    });
    const j = await resp.json();
    if (!j.ok) toast(j.message || 'Another build is running', true);
  } catch (err) {
    toast('Failed to start build', true);
    $('btnBuild').disabled = false;
    $('btnBuild').textContent = '🔨 Build Configs';
  }
};
$('btnBuildCancel').onclick = async () => {
  try { await fetch('/api/build-cancel', { method: 'POST' }); } catch (e) {}
};


connectSSE();
translateUI();

</script>
</body>
</html>
"""


# ──────────────────────────────────────────────
#  HTTP هندلر
# ──────────────────────────────────────────────

LAST_CONFIGS = {"content": ""}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stdout.write(f"[gui] {fmt % args}\n")

    def _send_json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urlparse(self.path)
        path = url.path
        if path == "/" or path == "/index.html":
            data = DASHBOARD_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
        elif path == "/events":
            self._handle_sse()
        elif path == "/api/state":
            self._send_json(get_state())
        elif path == "/api/last-configs":
            self._send_json(LAST_CONFIGS)
        elif path == "/api/build-state":
            self._send_json(BUILD_STATE)
        elif path == "/api/build-outputs":
            self._send_json(LAST_BUILD)
        elif path == "/api/health":
            self._send_json({"ok": True})
        elif path == "/api/opt-state":
            self._send_json(OPT_STATE)
        elif path == "/api/xray-status":
            self._send_json({"path": cfb.find_xray_binary() or ""})
        elif path == "/api/opt-outputs":
            self._send_json(LAST_OPT)
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        url = urlparse(self.path)
        path = url.path
        if path == "/api/start":
            length = int(self.headers.get("Content-Length", 0))
            try:
                params = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
            except Exception:
                params = {}
            ok = _start_scan_thread(params)
            self._send_json({"ok": ok, "message": "" if ok else "اسکن دیگری در حال اجراست"})
        elif path == "/api/cancel":
            set_state(cancelled=True)
            self._send_json({"ok": True})
        elif path == "/api/build-configs":
            length = int(self.headers.get("Content-Length", 0))
            try:
                params = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
            except Exception:
                params = {}
            ok = _start_build_thread(params)
            self._send_json({"ok": ok, "message": "" if ok else "ساخت دیگری در حال اجراست"})
        elif path == "/api/build-cancel":
            with LOCK:
                BUILD_STATE["running"] = False
                BUILD_STATE["phase"] = "Cancelled"
            self._send_json({"ok": True})
        elif path == "/api/opt-optimize":
            length = int(self.headers.get("Content-Length", 0))
            try:
                params = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
            except Exception:
                params = {}
            ok = _start_opt_thread(params)
            self._send_json({"ok": ok, "message": "" if ok else "بهینه‌سازی دیگری در حال اجراست"})
        elif path == "/api/opt-cancel":
            with LOCK:
                OPT_STATE["running"] = False
                OPT_STATE["phase"] = "Cancelled"
            self._send_json({"ok": True})
        elif path == "/api/xray-download":
            self._send_json({"ok": True})
            threading.Thread(target=_xray_download_worker, daemon=True).start()
        else:
            self._send_json({"error": "not found"}, 404)

    def _handle_sse(self):
        # Parse lang from URL for Persian support
        _url = urlparse(self.path)
        _qp = parse_qs(_url.query)
        _sse_lang = _qp.get("lang", ["en"])[0]
        if _sse_lang not in ("en", "fa"):
            _sse_lang = "en"
        setattr(self, "_sse_lang", _sse_lang)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        q = queue.Queue(maxsize=200)
        with SSE_LOCK:
            BROADCAST.append(q)
        try:
            # اولین پیام: وضعیت فعلی
            st = get_state()
            hello = {
                "running": st["running"],
                "phase": st["phase"],
                "done": st["done"],
                "found": st["found"],
                "total": st["total"],
                "results": st["results"],
            }
            self.wfile.write(f"event: hello\ndata: {json.dumps(hello, ensure_ascii=False)}\n\n".encode("utf-8"))
            self.wfile.flush()
            while True:
                try:
                    msg = q.get(timeout=15)
                    self.wfile.write(msg.encode("utf-8"))
                    self.wfile.flush()
                except queue.Empty:
                    # heartbeat تا اتصال زنده بماند
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with SSE_LOCK:
                try:
                    BROADCAST.remove(q)
                except ValueError:
                    pass


def pick_port(preferred):
    """انتخاب پورت آزاد"""
    for port in ([preferred] if preferred else []) + [8787, 8788, 8789, 8790, 8791, 0]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", port))
            s.close()
            return port if port else s.getsockname()[1]
        except OSError:
            continue
    return 0


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    ap = argparse.ArgumentParser(description="Narsaq Scanner — رابط گرافیکی وب")
    ap.add_argument("--port", type=int, default=8787, help="پورت سرور (پیش‌فرض: 8787)")
    ap.add_argument("--no-browser", action="store_true", help="مرورگر را خودکار باز نکن")
    args = ap.parse_args()

    port = pick_port(args.port)
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}"

    print("=" * 56)
    print("  Narsaq Scanner v%s — رابط گرافیکی" % VERSION)
    print("=" * 56)
    print(f"  آدرس: {url}")
    print("  برای توقف: Ctrl+C")
    print("=" * 56)

    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nخداحافظ!")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
