# 🦁☀️ Narsaq-Go (High Performance Cloudflare Engine)

<p align="left">
  <img src="https://upload.wikimedia.org/wikipedia/commons/f/fd/State_flag_of_Iran_%281964%E2%80%931980%29.svg" width="90" alt="Lion and Sun Flag of Iran">
</p>

An ultra-fast, lightweight Cloudflare Clean-IP Scanner, Config Builder, and **Live Local Subscription Server (`/sub`)** written entirely in **Go (Golang)**.

> ⚡ **10x Faster Scanning:** Scans and verifies thousands of Cloudflare Edge IPs concurrently using light Go goroutines.
> 💾 **Zero Python Needed:** Runs as a single, lightweight binary (~5 MB) with less than 10 MB RAM usage!
> 📱 **Android Termux Ready:** Runs native ARM64 Linux binaries instantly on Android phones.

---

## 🚀 Quick Start

### 1. Run Web Dashboard & Live Subscription Server (`/sub`)

Download the release binary for your platform (`windows-amd64.exe`, `linux-amd64`, `linux-arm64`, or `darwin-arm64`) and execute it:

```bash
# On Linux / Android Termux / macOS:
chmod +x narsaq-go-linux-arm64
./narsaq-go-linux-arm64 --port 8787

# On Windows:
narsaq-go-windows-amd64.exe -port 8787
```

- Open your browser at **`http://127.0.0.1:8787`** for the dashboard.
- Add **`http://127.0.0.1:8787/sub`** as a Subscription URL in **v2rayN**, **Nekobox**, **Sing-box**, or **Clash**!
  - `http://127.0.0.1:8787/sub` (Base64 subscription)
  - `http://127.0.0.1:8787/sub?fmt=singbox` (Sing-box JSON outbounds)
  - `http://127.0.0.1:8787/sub?fmt=clash` (Clash YAML proxies)
  - `http://127.0.0.1:8787/sub?fmt=plain` (Plain text URIs)

### 2. Fast CLI Scanner Mode

```bash
# Scan 500 IPs with custom SNI for DPI bypass:
./narsaq-go-linux-amd64 --scan --count 500 --snis "speed.cloudflare.com,www.cloudflare.com"
```

---

## 🦁☀️ راهنمای فارسی (Persian Guide)

<p align="right">
  <img src="https://upload.wikimedia.org/wikipedia/commons/f/fd/State_flag_of_Iran_%281964%E2%80%931980%29.svg" width="80" alt="پرچم شیر و خورشید ایران">
</p>

**Narsaq-Go** نسخه فوق‌سریع و بازنویسی‌شده پروژه به زبان قدرتمند **Go (Golang)** است.

### مزایای نسخه Go نسبت به نسخه پایتون:
1. **سرعت اسکن تا ۱۰ برابر بیشتر:** اسکن و تست هم‌زمان هزاران آی‌پی با استفاده از Goroutineهای سبک بدون سربار پردازنده.
2. **یک فایل تک بدون نیاز به نصب پایتون (Single Binary):** کل برنامه (سرور وب، اسکنر و اشتراک محلی) داخل یک فایل ۵ مگابایتی است.
3. **اجرای آنی در اندروید (Termux):** فایل `narsaq-go-linux-arm64` روی گوشی‌های اندروید در کسری از ثانیه اجرا می‌شود.
4. **سرور اشتراک محلی زنده (`/sub`):** تولید خروجی‌های Base64، Sing-box، و Clash با هدر رسمی `Profile-Title: Narsaq-Go`.

### اجرای سریع در Termux (اندروید):
```bash
chmod +x narsaq-go-linux-arm64
./narsaq-go-linux-arm64 --port 8787
```
سپس آدرس `http://127.0.0.1:8787` را در مرورگر گوشی باز کنید یا آدرس `http://127.0.0.1:8787/sub` را در v2rayNG وارد کنید!
