# Narsaq Desktop

Cloudflare clean-IP finder, config builder & config optimizer — a fully local,
standalone desktop tool. No Android project files here; this folder is
self-contained.

> All processing happens on your machine. Nothing is uploaded anywhere.

## Quick start

1. Install Python 3.10+ (https://www.python.org/downloads/) — check
   "Add python.exe to PATH" during install.
2. Double-click **start_gui.bat** (or run `python narsaq_gui.py`).
3. Your browser opens at **http://127.0.0.1:8791** — that's the app.

To run on a different port:

```
python narsaq_gui.py --port 9000
```

## What's inside

| File | Purpose |
| --- | --- |
| `narsaq_gui.py` | The web UI (runs a local server + auto-opens the browser) |
| `cf_config_builder.py` | Engine: clean-IP scanner, config builder, optimizer, Xray E2E tester, CLI (`--help`) |
| `bin/xray.exe` | Xray-core (used for the real proxy test; auto-downloaded if missing) |
| `clean_ips_*.txt`, `best_configs_*.txt` | Scan output files (saved next to the scripts) |

## Features

- **🧹 Clean IP scanner** — finds clean Cloudflare IPs on your network without
  a VPN: TCP → TLS → HTTP multi-step verification, speed test (Mbps),
  IPv6 & neighbor scan support.
- **🔨 Config builder** — paste your configs + clean IPs; every endpoint is
  tested and rebuilt with the best (lowest-latency) IPs. Duplicate configs are
  deduplicated so each output gets a distinct IP. Outputs: plain text,
  Base64 subscription, Sing-box JSON, Clash YAML.
- **⚡ Config optimizer** — the PattNG trick: injects `fp=unsafe`,
  13-suite `cs` and FinalMask `fm` into VLESS/Trojan configs to bypass
  Cloudflare upload disruption. VMess/SS and other protocols pass through.
  Accepts configs, subscription links and base64 blobs.
- **🔌 Real proxy test (Xray)** — after optimizing, each output config is
  launched through the real `xray.exe` and actually connected to
  `www.gstatic.com` through the proxy; the results table shows
  ✅ connected + real latency or ❌ failed.
- **🌐 English / فارسی** — switch the UI language with the button in the
  top-right corner (next to the theme toggle). Your choice is remembered;
  Persian layout switches to RTL automatically.

> ⚠️ The optimized configs (fm/cs/fp) only work in the **PattNG** v2rayNG
> fork: https://github.com/patterniha/PattNG/releases

## CLI (scripting)

```
python cf_config_builder.py --scan -c configs.txt --count 500 --save-ips clean_ips.txt
python cf_config_builder.py ips.txt -c configs.txt --top 30 --timeout 5
```

## Requirements

- Python 3.10+ (standard library only — no pip packages needed)
- Xray-core (`bin/xray.exe`, ~36 MB) for the real proxy test — click
  "⬇ Download Xray core" in the UI if it's missing

## 📦 Building the desktop release

### Locally (Windows)

```
pip install pyinstaller
python build_release.py
```

This produces, inside `releases/`:

- `NarsaqDesktop-v<ver>.exe` — standalone exe (no Python needed to run)
- `Narsaq-Desktop-v<ver>-portable.zip` — exe + `start_gui.bat` + README + `bin/xray.exe`
- `SHA256SUMS.txt` — checksums for both files

> The exe auto-downloads `xray.exe` into its own `bin/` folder on first use
> (or via the "⬇ Download Xray core" button), so even the bare exe works.
> Output files (`clean_ips_*.txt`, `best_configs_*.txt`) are saved next to the exe.

### On GitHub (no local machine needed)

The repo includes a CI workflow (`.github/workflows/build-release.yml`) that
builds the release on GitHub's Windows runner and uploads it:

1. Push this folder to a GitHub repository.
2. **Manual:** Actions → *Build Desktop Release* → **Run workflow**, then grab
   the artifacts from the run. Or **automatic:** create a tag and push it:

```
git tag v1.0.0 && git push origin v1.0.0
```

On a `v*` tag the workflow also creates a **GitHub Release** with the exe,
portable zip and checksums attached, ready for people to download.

> ℹ️ Artifacts are named after the version in `cf_config_builder.py`
> (`VERSION`). Bump that constant before tagging so the tag and the files
> match (e.g. `VERSION = "1.1.0"` → `git tag v1.1.0`).
