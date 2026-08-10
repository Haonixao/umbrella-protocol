package bypass

import (
	"net"
	"strings"
)

// ShouldBypass returns true if the host should be connected to directly.
// Supports domains (including all subdomains) and IP CIDR ranges (e.g. "192.168.1.0/24").
func ShouldBypass(host string, gBypass []string) bool {
	if len(gBypass) == 0 {
		return false
	}

	host = strings.ToLower(host)
	hostIP := net.ParseIP(host)

	for _, rule := range gBypass {
		rule = strings.ToLower(rule)
		if rule == "" {
			continue
		}

		// 1. Try as CIDR (e.g. "192.168.1.0/24")
		if hostIP != nil {
			if _, ipnet, err := net.ParseCIDR(rule); err == nil {
				if ipnet.Contains(hostIP) {
					return true
				}
				continue
			}
		}

		// 2. Exact match (works for both IPs and domains)
		if host == rule {
			return true
		}

		// 3. Domain suffix match (only if host is not an IP)
		if hostIP == nil && strings.HasSuffix(host, "."+rule) {
			return true
		}
	}
	return false
}

