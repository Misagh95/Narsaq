<p align="center">
  <img src="docs/logo.png" width="96" height="96" alt="Narsaq" />
  <h1 align="center">Narsaq</h1>
  <p align="center"><b>Config Endpoint Tester</b> — paste your proxy configs, rank responsive endpoints by TCP latency.</p>
  <p align="center">
    <a href="https://github.com/Misagh95/Narsaq/releases/download/v1.0.2/Narsaq-v1.0.2.apk"><img src="https://img.shields.io/badge/Download-v1.0.2-4F46E5?style=for-the-badge" /></a>
    <a href="https://github.com/Misagh95/Narsaq"><img src="https://img.shields.io/badge/Open%20on-GitHub-181717?style=for-the-badge&logo=github" /></a>
  </p>
</p>

---

**Narsaq** is a lightweight Material 3 Android app that takes `vless://`, `vmess://`, `ss://`, `trojan://` configs or raw `host:port` lines, checks TCP reachability in parallel, and ranks the responsive endpoints by connect latency — then exports a clean text report.

### ✨ Features
- 📥 Paste, file import, or sample configs
- 🔎 **IP scanner** — scan Cloudflare ranges and pick the fastest endpoints (new in v1.0.1)
- 🔀 Parallel testing — never blocks the UI
- 🏆 Ranked results with Passed / Failed filters
- 🛡️ Built-in **anti-filter preset** (Fragment + Unsafe FP + custom CipherSuites)
- 📤 Export, copy, and share reports
- 🌐 English & فارسی (RTL) — instant language switch

### 🛡️ Anti-Filter for v2rayNG

The anti-filter preset inside Narsaq is tuned for the **patterniha v2rayNG** fork — one of the most reliable clients for filtered networks.

#### Setup Guide

**۱. Install PattNG first:**
https://github.com/patterniha/v2rayNG/releases
(PattNG is fully compatible with v2rayNG and adds the extra features needed for anti-filter.)

**۲. Open your config in the app and tap Edit (✏️).**

**۳. In the Address field, enter a clean Cloudflare IP** (e.g. `188.114.97.6` or any healthy IP from the scan results).

**۴. In the Final Mask field, paste the following:**
```
{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["5","94", "1"], "delays": ["0"], "maxSplit": "0"}},{"type": "fragment", "settings": {"packets": "1-1", "lengths": ["109", "1"], "delays": ["1"], "maxSplit": "355"}}]}
```

**۵. Set Fingerprint to `unsafe`.**

**۶. In the Cipher Suites field, paste:**
```
TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
```

**۷. Save and done.**

👉 **Channel:** https://t.me/patt_channel_x/91

### 📦 Download
Grab the latest signed APK from the **[Releases](https://github.com/Misagh95/Narsaq/releases)** page — or download **[v1.0.2](https://github.com/Misagh95/Narsaq/releases/download/v1.0.2/Narsaq-v1.0.2.apk)** directly.

### 📄 License
MIT
