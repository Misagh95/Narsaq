<p align="center">
  <img src="docs/logo.png" width="96" height="96" alt="Narsaq" />
  <h1 align="center">Narsaq</h1>
  <p align="center"><b>Config Endpoint Tester</b> — paste your proxy configs, scan Cloudflare ranges, and rank endpoints by TCP latency.</p>
  <p align="center">
    <a href="https://github.com/Misagh95/Narsaq/releases"><img src="https://img.shields.io/badge/Download-latest-4F46E5?style=for-the-badge" /></a>
    <a href="https://github.com/Misagh95/Narsaq"><img src="https://img.shields.io/badge/Open%20on-GitHub-181717?style=for-the-badge&logo=github" /></a>
  </p>
</p>

---

**Narsaq** is a lightweight Material 3 Android app that takes `vless://`, `vmess://`, `ss://`, `trojan://` configs or raw `host:port` lines, checks TCP reachability in parallel, and ranks the responsive endpoints by connect latency.

### ✨ Features
- 📥 Paste, file import, or sample configs
- 🔎 **IP scanner** — scan Cloudflare ranges and pick the fastest endpoints
- 🧭 **Neighbor scan** (optional) — also probe the closest IPs around each healthy one
- 📶 **Loss rate** — every result is re-probed with repeated TCP samples for a quality score
- 🏷️ **ASN / ISP lookup** — identifies the provider of each endpoint, with optional filtering of domestic ISPs
- 📤 Export reports as **Sing-box JSON**, **Clash YAML**, **Base64 subscription**, or plain text
- 🔀 Parallel testing — never blocks the UI
- 🏆 Ranked results with Passed / Failed filters
- 🌐 English & فارسی (RTL) — instant language switch

### 📦 Download
Grab the latest signed APK from the **[Releases](https://github.com/Misagh95/Narsaq/releases)** page.

### 📄 License
MIT
