package config

import (
	"os"

	"github.com/stretchr/testify/assert/yaml"
)

type Config struct {
	// Client side data
	ClientActivationKey string   `yaml:"client_activation_key"`
	ListenAddr          string   `yaml:"listen"`
	UDPEnabled          bool     `yaml:"udp"`
	DecoyTraffic        bool     `yaml:"decoy-traffic"`
	Bypass              []string `yaml:"bypass"`
	Shaper              bool     `yaml:"shaper"`
	PhasesFile          string   `yaml:"phases-file"`
	PhasesData          []byte   `yaml:"-"` // For embedded data

	Imap struct {
		Gmail struct {
			Login    string `yaml:"login"`
			Password string `yaml:"password"`
		} `yaml:"gmail"`
	} `yaml:"imap"`

	// Server side data
	Protocol string `yaml:"protocol"`
	Server   string `yaml:"server"`
	SNI      string `yaml:"sni"`

	Xhttp struct {
		Quic bool   `yaml:"quic"`
		Path string `yaml:"path"`
		Mode string `yaml:"mode"` // stream-one, stream-up, packet-up
	} `yaml:"xhttp"`

	Hysteria struct {
		AuthPassword string `yaml:"auth-password"`
		ConnsNum     int    `yaml:"conns-num"`
	} `yaml:"hysteria"`

	Torrent struct {
		AuthKey            string `yaml:"auth-key"`
		InfoHash           string `yaml:"info-hash"`
		SessionsNum        int    `yaml:"sessions-num"`
		ConnectionsTimeOut int    `yaml:"connections-time-out"`
	} `yaml:"torrent"`
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

	cfg.ListenAddr = "0.0.0.0:1080"
	cfg.UDPEnabled = true
	cfg.DecoyTraffic = false

	cfg.Shaper = false
	cfg.PhasesFile = "phases.yml"

	cfg.Hysteria.ConnsNum = 2

	cfg.Torrent.SessionsNum = 2
	cfg.Torrent.ConnectionsTimeOut = 70

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
