package scanner

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Cloudflare IPv4 CIDRs
var CloudflareIPv4CIDRs = []string{
	"103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
	"131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
	"172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
	"190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
}

// Cloudflare IPv6 CIDRs
var CloudflareIPv6CIDRs = []string{
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
	"2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
	"2c0f:f248::/32",
}

var DefaultSNIs = []string{
	"speed.cloudflare.com",
	"www.cloudflare.com",
	"cloudflare.com",
	"1.1.1.1.cdn.cloudflare.net",
}

type ScanResult struct {
	IP        string  `json:"ip"`
	Port      int     `json:"port"`
	LatencyMs float64 `json:"latency_ms"`
	SpeedMbps float64 `json:"speed_mbps"`
	Colo      string  `json:"colo"`
}

type ProgressCallback func(done, total int, phase string)

// GenerateRandomIPs generates count random IPs from Cloudflare CIDRs
func GenerateRandomIPs(count int, enableV6 bool) []string {
	var ips []string
	seen := make(map[string]bool)

	cidrs := CloudflareIPv4CIDRs
	if enableV6 {
		cidrs = append(cidrs, CloudflareIPv6CIDRs...)
	}

	attempts := 0
	maxAttempts := count * 10
	for len(seen) < count && attempts < maxAttempts {
		attempts++
		cidr := cidrs[attempts%len(cidrs)]
		ip, _, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		// simple randomized host variation in subnet
		randOffset, _ := rand.Int(rand.Reader, big.NewInt(250))
		ip4 := ip.To4()
		if ip4 != nil {
			ip4[3] = byte((int(ip4[3]) + int(randOffset.Int64())) % 254 + 1)
			ipStr := ip4.String()
			if !seen[ipStr] {
				seen[ipStr] = true
				ips = append(ips, ipStr)
			}
		}
	}
	return ips
}

// TestIP checks TCP connection, TLS handshake with custom SNI, and HTTP trace
func TestIP(ip string, port int, snis []string, timeout time.Duration) (*ScanResult, error) {
	if len(snis) == 0 {
		snis = DefaultSNIs
	}
	target := fmt.Sprintf("%s:%d", ip, port)

	t0 := time.Now()
	conn, err := net.DialTimeout("tcp", target, timeout/2)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Pick SNI for rotation
	sni := snis[0]
	tlsConf := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}

	tlsConn := tls.Client(conn, tlsConf)
	if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	reqStr := fmt.Sprintf("GET /cdn-cgi/trace HTTP/1.1\r\nHost: %s\r\nUser-Agent: Narsaq-Go/1.0\r\nConnection: close\r\n\r\n", sni)
	if _, err := tlsConn.Write([]byte(reqStr)); err != nil {
		return nil, err
	}

	reader := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	latMs := float64(time.Since(t0).Microseconds()) / 1000.0
	colo := "EDGE"
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "colo=") {
			colo = strings.TrimPrefix(line, "colo=")
			break
		}
	}

	return &ScanResult{
		IP:        ip,
		Port:      port,
		LatencyMs: latMs,
		Colo:      colo,
	}, nil
}

// RunScan runs concurrent clean IP scan over scope IPs and ports
func RunScan(ips []string, ports []int, snis []string, timeoutSec float64, workers int, cb ProgressCallback) []ScanResult {
	timeout := time.Duration(timeoutSec * float64(time.Second))
	if workers <= 0 {
		workers = 64
	}

	type job struct {
		ip   string
		port int
	}

	var jobs []job
	for _, ip := range ips {
		for _, p := range ports {
			jobs = append(jobs, job{ip: ip, port: p})
		}
	}

	jobCh := make(chan job, len(jobs))
	for _, j := range jobs {
		jobCh <- j
	}
	close(jobCh)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []ScanResult
	doneCount := 0
	total := len(jobs)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobCh {
				res, err := TestIP(j.ip, j.port, snis, timeout)
				mu.Lock()
				doneCount++
				if err == nil && res != nil {
					results = append(results, *res)
				}
				if cb != nil && doneCount%5 == 0 {
					cb(doneCount, total, "Scanning IPs...")
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if cb != nil {
		cb(total, total, "Completed")
	}
	return results
}
