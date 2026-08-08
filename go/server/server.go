package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Misagh95/Narsaq/go/config"
	"github.com/Misagh95/Narsaq/go/scanner"
)

type ServerState struct {
	Running   bool                  `json:"running"`
	Phase     string                `json:"phase"`
	Done      int                   `json:"done"`
	Total     int                   `json:"total"`
	Message   string                `json:"message"`
	CleanIPs  []scanner.ScanResult  `json:"clean_ips"`
	Configs   []config.RebuiltConfig `json:"configs"`
	UpdatedAt string                `json:"updated_at"`
}

var (
	mu          sync.Mutex
	state       ServerState
	customSNIs  []string
)

const DashboardHTML = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Narsaq-Go (Fast Engine)</title>
  <style>
    :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #238636; }
    body { font-family: Tahoma, Arial, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; }
    .container { max-width: 900px; margin: 0 auto; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px; }
    h1, h2 { color: #58a6ff; margin-top: 0; }
    button { background: var(--accent); color: #fff; border: none; padding: 10px 18px; border-radius: 6px; cursor: pointer; font-weight: bold; }
    button:hover { opacity: 0.9; }
    .sub-link { background: #0d1117; padding: 10px; border-radius: 6px; border: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; font-family: monospace; direction: ltr; }
    .badge { background: #1f6feb; color: #fff; font-size: 11px; padding: 2px 8px; border-radius: 12px; }
    input, textarea { width: 100%; background: #0d1117; color: #c9d1d9; border: 1px solid var(--border); border-radius: 6px; padding: 8px; box-sizing: border-box; }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <h1>🦁☀️ Narsaq-Go (موتور فوق‌سریع Go)</h1>
        <span class="badge">v1.0.0 Go</span>
      </div>
      <p>اسکنر آی‌پی تمیز و بهینه‌ساز کانفیگ کلودفلر — نوشته شده به زبان Go با ۱۰ برابری سرعت و بدون مصرف رم بالا.</p>
      <div style="margin-top:14px;">
        <label>SNIهای سفارشی (با کاما):</label>
        <input id="snis" placeholder="speed.cloudflare.com, www.cloudflare.com">
      </div>
      <div style="margin-top:14px;">
        <button onclick="startScan()">🚀 شروع اسکن سریع (Goroutines)</button>
        <span id="statusText" style="margin-right:15px;color:#8b949e;">آماده به کار</span>
      </div>
    </div>

    <div class="card">
      <h2>🔗 سرور اشتراک محلی زنده (/sub)</h2>
      <p style="font-size:13px;color:#8b949e;">لینک اشتراک زیر را در کلاینت (v2rayN، Nekobox، Sing-box، Clash) قرار دهید تا همیشه آخرین آی‌پی‌ها را دریافت کنید:</p>
      <div class="sub-link">
        <span>http://127.0.0.1:8787/sub</span>
        <button onclick="copyLink('http://127.0.0.1:8787/sub')" style="background:#30363d;padding:4px 10px;">📋 کپی Base64</button>
      </div>
      <div class="sub-link">
        <span>http://127.0.0.1:8787/sub?fmt=singbox</span>
        <button onclick="copyLink('http://127.0.0.1:8787/sub?fmt=singbox')" style="background:#30363d;padding:4px 10px;">📋 کپی Sing-box</button>
      </div>
      <div class="sub-link">
        <span>http://127.0.0.1:8787/sub?fmt=clash</span>
        <button onclick="copyLink('http://127.0.0.1:8787/sub?fmt=clash')" style="background:#30363d;padding:4px 10px;">📋 کپی Clash</button>
      </div>
    </div>
  </div>
  <script>
    async function startScan() {
      document.getElementById('statusText').textContent = '📡 در حال اسکن...';
      const snis = document.getElementById('snis').value;
      const resp = await fetch('/api/start?count=100&snis=' + encodeURIComponent(snis), { method: 'POST' });
      const data = await resp.json();
      document.getElementById('statusText').textContent = '✅ اسکن کامل شد! (' + (data.clean_ips ? data.clean_ips.length : 0) + ' آی‌پی تمیز)';
    }
    function copyLink(url) {
      navigator.clipboard.writeText(url);
      alert('لینک کپی شد!');
    }
  </script>
</body>
</html>`

func StartServer(port int) error {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	http.HandleFunc("/", handleDashboard)
	http.HandleFunc("/sub", handleSub)
	http.HandleFunc("/api/start", handleStartScan)
	http.HandleFunc("/api/state", handleState)

	fmt.Printf("[Narsaq-Go] Live UI & Subscription Server listening on http://%s\n", addr)
	return http.ListenAndServe(addr, nil)
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(DashboardHTML))
}

func handleSub(w http.ResponseWriter, r *http.Request) {
	fmtParam := r.URL.Query().Get("fmt")
	if fmtParam == "" {
		fmtParam = "base64"
	}

	mu.Lock()
	cfgs := state.Configs
	if len(cfgs) == 0 {
		// generate sample config with latest scan IPs if exists
		for i, ip := range state.CleanIPs {
			cfgs = append(cfgs, config.RebuiltConfig{
				Type:        "vless",
				FinalConfig: fmt.Sprintf("vless://00000000-0000-0000-0000-000000000000@%s:%d?encryption=none&security=tls&sni=speed.cloudflare.com&fp=unsafe#NarsaqGo-%d", ip.IP, ip.Port, i+1),
				BestIP:      ip.IP,
				BestPort:    ip.Port,
				SNI:         "speed.cloudflare.com",
				Tag:         fmt.Sprintf("NarsaqGo-%d", i+1),
			})
		}
	}
	mu.Unlock()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Profile-Update-Interval", "6")
	w.Header().Set("Subscription-Userinfo", "upload=0; download=0; total=107374182400; expire=253402300799")
	w.Header().Set("Profile-Title", "Narsaq-Go")

	switch strings.ToLower(fmtParam) {
	case "plain":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(config.PackPlainText(cfgs)))
	case "singbox":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write([]byte(config.PackSingboxJSON(cfgs)))
	case "clash":
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		w.Write([]byte(config.PackClashYAML(cfgs)))
	default:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(config.PackBase64Subscription(cfgs)))
	}
}

func handleStartScan(w http.ResponseWriter, r *http.Request) {
	count, _ := strconv.Atoi(r.URL.Query().Get("count"))
	if count <= 0 {
		count = 100
	}
	snisStr := r.URL.Query().Get("snis")
	var snis []string
	if snisStr != "" {
		for _, s := range strings.Split(snisStr, ",") {
			if strings.TrimSpace(s) != "" {
				snis = append(snis, strings.TrimSpace(s))
			}
		}
	}

	mu.Lock()
	state.Running = true
	state.Phase = "Scanning"
	mu.Unlock()

	ips := scanner.GenerateRandomIPs(count, false)
	res := scanner.RunScan(ips, []int{443, 2053}, snis, 3.0, 64, nil)

	mu.Lock()
	state.Running = false
	state.Phase = "Done"
	state.CleanIPs = res
	state.UpdatedAt = time.Now().Format("15:04:05")
	mu.Unlock()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(state)
}

func handleState(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(state)
}
