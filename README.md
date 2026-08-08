# Narsaq Desktop

Cloudflare clean-IP finder, config builder & config optimizer — a fully local,
standalone Windows desktop tool. Self-contained with zero required external dependencies.

> 📱 **Looking for the Android app?** Check out the official Android version: **[Narsaq for Android](https://github.com/Misagh95/Narsaq)**

> 🔒 **All processing happens locally on your machine. Nothing is uploaded anywhere.**

---

## 🚀 Quick Start (Windows / Desktop)

**The installed/portable app runs in its own native desktop window**
(no browser tab needed — powered by pywebview + WebView2, which ships
with Windows 10/11).

1. Install Python 3.10+ (https://www.python.org/downloads/) — check
   **"Add python.exe to PATH"** during install.
2. Double-click **start_gui.bat** (or run `python narsaq_gui.py`).
3. The app opens in a native desktop window. If `pywebview` isn't
   installed, it falls back to opening your browser at
   **http://127.0.0.1:8787** instead.

To run on a different port, or force a specific window mode:

```bash
python narsaq_gui.py --port 9000       # run on custom port
python narsaq_gui.py --browser         # force system web browser
python narsaq_gui.py --no-browser      # server only (no desktop window / headless)
```

---

## ✨ Features

- **🧹 Clean IP Scanner** — finds clean Cloudflare IPs on your network: TCP → TLS → HTTP multi-step verification, speed test (Mbps), IPv6 & neighbor scan support.
- **🔗 Local Subscription Server (`/sub`)** *(NEW)* — hosts a live local subscription endpoint for your client apps (`v2rayN`, `Nekobox`, `Sing-box`, `Clash`). Automatically serves the latest optimized or built configs with `Profile-Title: Narsaq-Desktop` and standard subscription traffic headers.
  - `http://127.0.0.1:8787/sub` (Base64 subscription)
  - `http://127.0.0.1:8787/sub?fmt=singbox` (Sing-box JSON outbounds)
  - `http://127.0.0.1:8787/sub?fmt=clash` (Clash YAML proxies)
  - `http://127.0.0.1:8787/sub?fmt=plain` (Plain text URIs)
- **🛡️ Custom SNI / DPI Bypass (`--snis`)** *(NEW)* — define custom clean hostnames/SNIs (e.g. `speed.cloudflare.com, www.cloudflare.com, custom-cdn.example.com`) directly in the GUI or CLI to rotate SNIs during TLS handshake and bypass ISP throttling/DPI censorship.
- **⚡ Fast Retest Saved IPs** *(NEW)* — instantly re-test and optimize your configs against previously saved clean IPs (`clean_ips_*.txt`) with a single click, without waiting for a full network scan.
- **🔨 Config Builder** — paste your configs + clean IPs; every endpoint is tested and rebuilt with the best (lowest-latency) IPs. Duplicate configs are deduplicated so each output gets a distinct IP.
- **⚡ Config Optimizer (PattNG Trick)** — injects `fp=unsafe`, 13-suite `cs`, and FinalMask `fm=` into VLESS/Trojan configs to bypass Cloudflare upload disruption. VMess/SS and other protocols pass through cleanly.
- **🔌 Real Proxy Test (Xray)** — after optimizing, each output config is launched through the real `xray.exe` and actually connected to `www.gstatic.com` through the proxy; the results table shows ✅ connected + real latency or ❌ failed.
- **🌐 English / فارسی** — switch the UI language with the button in the top-right corner. Persian layout switches to RTL automatically.

> ⚠️ **Important Compatibility Note:** The optimized configs (`fm=`, `cs=`, `fp=unsafe`) require an Xray core that supports FinalMask. Use the **PattNG** v2rayNG fork on Android ([https://github.com/patterniha/PattNG/releases](https://github.com/patterniha/PattNG/releases)), or update your Xray core in `v2rayN`/`Nekobox` on Windows.

---

## 📂 What's Inside

| File | Purpose |
| --- | --- |
| `narsaq_gui.py` | The web UI (runs a local server, handles `/sub` subscription, auto-opens the browser/window) |
| `cf_config_builder.py` | Engine: clean-IP scanner, custom SNI rotator, config builder, optimizer, Xray E2E tester, CLI (`--help`) |
| `bin/xray.exe` | Xray-core (used for the real proxy test; auto-downloaded if missing on Windows) |
| `clean_ips_*.txt`, `best_configs_*.txt` | Scan output files (saved next to the scripts) |

---

## 💻 CLI (Scripting)

```bash
# Clean IP scanner with custom SNIs for DPI bypass:
python cf_config_builder.py --scan -c configs.txt --count 500 --snis "speed.cloudflare.com,www.cloudflare.com" --save-ips clean_ips.txt

# Test existing IP list against configs:
python cf_config_builder.py ips.txt -c configs.txt --top 30 --timeout 5
```

---

## 📦 Building the Desktop Release

### Locally (Windows)

```bash
pip install pyinstaller pillow pywebview
python build_release.py
```

This produces, inside `releases/`:
- `NarsaqDesktop-v<ver>.exe` — standalone executable (no Python installation needed)
- `Narsaq-Desktop-v<ver>-portable.zip` — portable package (`exe` + `start_gui.bat` + README + `bin/xray.exe`)
- `NarsaqDesktop-Setup-<ver>.exe` — Windows Installer (Inno Setup) with Start-menu shortcuts and uninstaller
- `SHA256SUMS.txt` — SHA-256 checksums for all release files

### On GitHub Actions (Automated CI/CD)

The repository includes a GitHub Actions workflow (`.github/workflows/build-release.yml`) that automatically compiles Windows executables and installers on any version tag:

```bash
git tag v1.0.0 && git push origin v1.0.0
```

---

## 🦁☀️ راهنمای فارسی (Persian Guide)

<p align="right">
  <img src="https://upload.wikimedia.org/wikipedia/commons/f/fd/State_flag_of_Iran_%281964%E2%80%931980%29.svg" width="70" alt="پرچم شیر و خورشید ایران - Lion and Sun Flag of Iran">
</p>

> 📱 **نسخه موبایل (اندروید):** این مخزن مربوط به نسخه دسکتاپ و ویندوز است. برای دریافت و استفاده از اپلیکیشن اندروید به مخزن رسمی اندروید مراجعه کنید:  
> 🔗 **[Narsaq for Android (نسخه اندروید)](https://github.com/Misagh95/Narsaq)**

### ویژگی‌های کلیدی Narsaq Desktop:
1. **اسکنر آی‌پی تمیز کلودفلر:** پیدا کردن آی‌پی‌های تمیز با ۴ مرحله وریفای (TCP ➔ TLS ➔ HTTP ➔ تست سرعت Mbps) و پشتیبانی از اسکن همسایه‌ها.
2. **سرور اشتراک محلی زنده (`/sub`):** امکان اضافه کردن آدرس `http://127.0.0.1:8787/sub` به عنوان Subscription در برنامه‌های **v2rayN**، **Nekobox**، **Sing-box** و **v2rayNG** جهت آپدیت خودکار کانفیگ‌ها.
3. **عبور از فیلترینگ با SNI دلخواه:** امکان تعریف دامنه‌های تمیز دلخواه برای جلوگیری از بلاک شدن توسط DPI اپراتورها.
4. **تست سریع کانفیگ‌های ذخیره‌شده (`Fast Retest Saved IPs`):** ساخت و تست آنی کانفیگ‌ها با استفاده از فایل‌های آی‌پی قبلی بدون معطلی اسکن جدید.
5. **بهینه‌ساز ضد‌اختلال آپلود (تکنیک PattNG):** تزریق خودکار پارامترهای `fm=`، `cs=` و `fp=unsafe` به کانفیگ‌های VLESS و Trojan.
