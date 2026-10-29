package ip

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// CheckIp queries public IP services sequentially and returns the first successful IP.
func CheckIp() (string, error) {
	services := []string{
		"https://api64.ipify.org",
		"https://a.ident.me",
		"https://ifconfig.me/ip",
		"https://api.2ip.io",
	}

	client := &http.Client{Timeout: 5 * time.Second}

	for _, url := range services {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		ipStr := strings.TrimSpace(string(body))
		if strings.HasPrefix(url, "https://api.2ip.io") {
			var data struct {
				IP string `json:"ip"`
			}
			if jsonErr := json.Unmarshal(body, &data); jsonErr != nil {
				continue
			}
			ipStr = strings.TrimSpace(data.IP)
		}

		if ipStr != "" && (strings.Contains(ipStr, ".") || strings.Contains(ipStr, ":")) {
			return ipStr, nil
		}
	}
	return "", errors.New("unable to obtain public IP from all services")
}
