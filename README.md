<p align="center">
  <img src="docs/logo.png" width="96" height="96" alt="Narsaq" />
  <h1 align="center">Narsaq</h1>
  <p align="center"><b>Config Endpoint Tester</b> — paste your proxy configs, scan Cloudflare ranges, and rank the best endpoints by latency and real throughput.</p>
  <p align="center">
    <a href="https://github.com/Misagh95/Narsaq/releases"><img src="https://img.shields.io/badge/Download-latest-087B72?style=for-the-badge" /></a>
    <a href="https://github.com/Misagh95/Narsaq"><img src="https://img.shields.io/badge/Open%20on-GitHub-181717?style=for-the-badge&logo=github" /></a>
  </p>
</p>

---

**Narsaq** is a lightweight Material 3 Android app that takes `vless://`, `vmess://`, `ss://`, `trojan://` configs or raw `host:port` lines, tests them against Cloudflare-scanned endpoints, and ranks the results by connection quality — so you can pick the fastest, most stable server for your setup.

### ✨ Features

- 📥 **Paste, file import, or sample configs** — one line per config, any protocol
- 🔎 **IP scanner** — scan Cloudflare ranges (IPv4 + IPv6) and keep only clean endpoints
- 🧩 **Custom ranges** — add your own CIDR blocks or `ip:port` lines on top of the Cloudflare pool
- 📶 **Multi-sample verification** — every endpoint is re-probed for a stable latency & loss score
- ⚡ **Real speed test** — downloads from the top endpoints and reports actual Mbps
- 🛡️ **End-to-end validation** — real VLESS / Trojan + TLS / WebSocket handshakes through each candidate, with TTFB & throughput scores
- 🏷️ **ASN / ISP lookup** — identifies the provider behind every IP
- 📤 **Export** — reports as TXT, Base64 subscription, Sing-box JSON, or Clash YAML, plus one-tap copy & share
- 🧭 **PattNG anti-filter guide** — ready-made FinalMask and CipherSuites for filtered networks
- 🔀 **Parallel testing** — never blocks the UI
- 🏆 **Ranked results** with Passed / Failed filters and quality insights
- 🌐 **English & فارسی (RTL)** — instant language switch

### 🚀 How it works

1. **Scan** — the built-in scanner probes Cloudflare ranges (or your custom ranges) and returns only the clean, fast endpoints.
2. **Build** — paste your configs and the scanned IPs, then run the test. Narsaq checks TCP reachability in parallel, then runs a real protocol handshake through the top candidates.
3. **Results** — copy or export the rebuilt configs with the best IPs, sorted by latency, E2E status, and speed.

### 📦 Download

Grab the latest signed APK from the **[Releases](https://github.com/Misagh95/Narsaq/releases)** page.

### 🛠️ Requirements

- Android 8.0+ (API 26)
- No root required

### 📄 License

MIT
