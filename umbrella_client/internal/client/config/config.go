package config

import (
	"fmt"
	"os"

	"github.com/stretchr/testify/assert/yaml"
)

type Config struct {
	Protocol     string `yaml:"protocol"`
	Server       string `yaml:"server"`
	SNI          string `yaml:"sni"`
	ListenAddr   string `yaml:"listen"`
	UDPEnabled   bool   `yaml:"udp"`
	DecoyTraffic bool   `yaml:"decoy-traffic"`

	Shaper     bool   `yaml:"shaper"`
	PhasesFile string `yaml:"phases-file"`
	PhasesData []byte `yaml:"-"` // For embedded data

	Xtls struct {
		PublicKey          string `yaml:"public-key"`
		ShortId            string `yaml:"short-id"`
		ConnectionsTimeOut int    `yaml:"connections-time-out"`
		SessionsNum        int    `yaml:"sessions-num"`
	} `yaml:"xtls"`

	Xhttp struct {
		AuthKey string `yaml:"auth-key"`
		Quic    bool   `yaml:"quic"`
		Path    string `yaml:"path"`
		Mode    string `yaml:"mode"` // stream-one, stream-up, packet-up
	} `yaml:"xhttp"`

	Hysteria struct {
		AuthKey      string `yaml:"auth-key"`
		AuthPassword string `yaml:"auth-password"`
		ConnsNum     int    `yaml:"conns-num"`
	} `yaml:"hysteria"`

	Torrent struct {
		AuthKey            string `yaml:"auth-key"`
		InfoHash           string `yaml:"info-hash"`
		SessionsNum        int    `yaml:"sessions-num"`
		ConnectionsTimeOut int    `yaml:"connections-time-out"`
	} `yaml:"torrent"`

	Bypass []string `yaml:"bypass"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(data)
}

func ParseConfig(data []byte) (*Config, error) {
	cfg := &Config{}

	cfg.SNI = "github.com"
	cfg.ListenAddr = "0.0.0.0:1080"
	cfg.UDPEnabled = true
	cfg.DecoyTraffic = false

	cfg.Shaper = false
	cfg.PhasesFile = "phases.yml"

	cfg.Xtls.ConnectionsTimeOut = 70
	cfg.Xtls.SessionsNum = 2

	cfg.Hysteria.ConnsNum = 2

	cfg.Torrent.SessionsNum = 2
	cfg.Torrent.ConnectionsTimeOut = 70

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	if cfg.Server == "" {
		return nil, fmt.Errorf("server is required in config")
	}

	switch cfg.Protocol {
	case "xtls":
		if cfg.Xtls.PublicKey == "" {
			return nil, fmt.Errorf("public-key is required in config")
		}
		if cfg.Xtls.ShortId == "" {
			return nil, fmt.Errorf("short-id is required in config")
		}
	}

	return cfg, nil
}
