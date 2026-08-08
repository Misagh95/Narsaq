package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/Misagh95/Narsaq/go/scanner"
	"github.com/Misagh95/Narsaq/go/server"
)

const Version = "1.0.0-go"

func main() {
	port := flag.Int("port", 8787, "Port for web UI and subscription server")
	noBrowser := flag.Bool("no-browser", false, "Do not auto-open desktop app window")
	scanMode := flag.Bool("scan", false, "Run in fast CLI scanner mode")
	count := flag.Int("count", 200, "Number of Cloudflare IPs to scan")
	snisFlag := flag.String("snis", "", "Comma-separated custom SNIs for DPI bypass")
	v6 := flag.Bool("v6", false, "Include IPv6 scan")
	showVer := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVer {
		fmt.Printf("Narsaq-Go v%s (High Performance Engine)\n", Version)
		os.Exit(0)
	}

	var snis []string
	if *snisFlag != "" {
		for _, s := range strings.Split(*snisFlag, ",") {
			if strings.TrimSpace(s) != "" {
				snis = append(snis, strings.TrimSpace(s))
			}
		}
	}

	if *scanMode {
		fmt.Println("==================================================")
		fmt.Println("  🦁☀️ Narsaq-Go High Performance IP Scanner")
		fmt.Println("==================================================")
		fmt.Printf("  Target IPs:  %d (IPv6: %v)\n", *count, *v6)
		if len(snis) > 0 {
			fmt.Printf("  Custom SNIs: %v\n", snis)
		}
		fmt.Println("--------------------------------------------------")

		ips := scanner.GenerateRandomIPs(*count, *v6)
		res := scanner.RunScan(ips, []int{443, 2053, 2083}, snis, 3.0, 100, func(done, total int, phase string) {
			fmt.Printf("\r  [%s] %d/%d IPs tested...", phase, done, total)
		})
		fmt.Println("\n==================================================")
		fmt.Printf("  ✓ Found %d clean edge IPs!\n", len(res))
		for i, r := range res {
			if i >= 15 {
				break
			}
			fmt.Printf("   %-15s :%-5d | Latency: %6.1f ms | Colo: %s\n", r.IP, r.Port, r.LatencyMs, r.Colo)
		}
		return
	}

	go openAppWindow(fmt.Sprintf("http://127.0.0.1:%d", *port), *noBrowser)

	if err := server.StartServer(*port); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting Narsaq-Go server: %v\n", err)
		os.Exit(1)
	}
}

func openAppWindow(url string, noBrowser bool) {
	if noBrowser {
		return
	}
	time.Sleep(300 * time.Millisecond)

	switch runtime.GOOS {
	case "windows":
		// ۱. تلاش برای اجرای پنجره مستقل دسکتاپ با Edge (بدون تب و نوار آدرس - حالت Native App)
		if err := exec.Command("cmd", "/c", "start", "msedge", "--app="+url).Start(); err == nil {
			return
		}
		// ۲. تلاش با Chrome در حالت App
		if err := exec.Command("cmd", "/c", "start", "chrome", "--app="+url).Start(); err == nil {
			return
		}
		// ۳. فال‌بک به باز کردن در مرورگر پیش‌فرض
		exec.Command("cmd", "/c", "start", url).Start()
	case "darwin":
		exec.Command("open", url).Start()
	case "linux":
		exec.Command("xdg-open", url).Start()
	}
}
