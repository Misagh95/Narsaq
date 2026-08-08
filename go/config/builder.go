package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

type RebuiltConfig struct {
	Type        string `json:"type"`
	FinalConfig string `json:"final_config"`
	BestIP      string `json:"best_ip"`
	BestPort    int    `json:"best_port"`
	SNI         string `json:"sni"`
	Tag         string `json:"tag"`
}

var DefaultCS = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"

// RebuildConfig replaces IP and port in vless/trojan URI and injects PattNG optimizer params
func RebuildConfig(rawCfg string, newIP string, newPort int, rank int, fp string, cs string) string {
	rawCfg = strings.TrimSpace(rawCfg)
	u, err := url.Parse(rawCfg)
	if err != nil {
		return rawCfg
	}

	addr := newIP
	if strings.Contains(addr, ":") && !strings.HasPrefix(addr, "[") {
		addr = "[" + addr + "]"
	}

	u.Host = fmt.Sprintf("%s:%d", addr, newPort)
	q := u.Query()
	if fp != "" {
		q.Set("fp", fp)
	}
	if cs != "" {
		q.Set("cs", cs)
	}
	u.RawQuery = q.Encode()

	frag := u.Fragment
	if frag == "" {
		frag = fmt.Sprintf("CleanIP-%d", rank)
	} else {
		frag = fmt.Sprintf("%s-%d", frag, rank)
	}
	u.Fragment = frag

	return u.String()
}

// PackPlainText joins config URIs with newline
func PackPlainText(cfgs []RebuiltConfig) string {
	var lines []string
	for _, c := range cfgs {
		lines = append(lines, c.FinalConfig)
	}
	return strings.Join(lines, "\n")
}

// PackBase64Subscription encodes plain text as Base64 for v2ray subscription
func PackBase64Subscription(cfgs []RebuiltConfig) string {
	plain := PackPlainText(cfgs)
	return base64.StdEncoding.EncodeToString([]byte(plain))
}

// PackSingboxJSON formats configs as Sing-box outbounds JSON
func PackSingboxJSON(cfgs []RebuiltConfig) string {
	var outbounds []map[string]interface{}
	for i, c := range cfgs {
		tag := c.Tag
		if tag == "" {
			tag = fmt.Sprintf("proxy-%d", i+1)
		}
		u, _ := url.Parse(c.FinalConfig)
		q := u.Query()
		sni := q.Get("sni")
		if sni == "" {
			sni = c.SNI
		}
		item := map[string]interface{}{
			"type":        c.Type,
			"tag":         tag,
			"server":      c.BestIP,
			"server_port": c.BestPort,
		}
		if c.Type == "vless" && u != nil {
			item["uuid"] = u.User.Username()
			item["tls"] = map[string]interface{}{
				"enabled":     true,
				"server_name": sni,
				"insecure":    true,
			}
		}
		outbounds = append(outbounds, item)
	}
	wrapped := map[string]interface{}{"outbounds": outbounds}
	data, _ := json.MarshalIndent(wrapped, "", "  ")
	return string(data)
}

// PackClashYAML formats configs as Clash YAML proxies
func PackClashYAML(cfgs []RebuiltConfig) string {
	var lines []string
	lines = append(lines, "proxies:")
	for i, c := range cfgs {
		tag := c.Tag
		if tag == "" {
			tag = fmt.Sprintf("proxy-%d", i+1)
		}
		u, _ := url.Parse(c.FinalConfig)
		if c.Type == "vless" && u != nil {
			lines = append(lines, fmt.Sprintf("  - name: \"%s\"", tag))
			lines = append(lines, "    type: vless")
			lines = append(lines, fmt.Sprintf("    server: %s", c.BestIP))
			lines = append(lines, fmt.Sprintf("    port: %d", c.BestPort))
			lines = append(lines, fmt.Sprintf("    uuid: %s", u.User.Username()))
			lines = append(lines, "    tls: true")
			lines = append(lines, "    udp: true")
		}
	}
	return strings.Join(lines, "\n")
}
