package config

import (
	importRand "crypto/rand"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Protocol string `yaml:"protocol"`
	Port     string `yaml:"port"`
	Dest     string `yaml:"dest"`
	Debug    bool   `yaml:"debug"`

	Imap struct {
		Gmail struct {
			Login    string `yaml:"login"`
			Password string `yaml:"password"`
		} `yaml:"gmail"`
	} `yaml:"imap"`

	Xhttp struct {
		Path string `yaml:"path"`
	} `yaml:"xhttp"`

	Hysteria struct {
		AuthPassword string `yaml:"auth-password"`
	} `yaml:"hysteria"`

	Torrent struct {
		AuthKey  string `yaml:"auth-key"`
		InfoHash string `yaml:"info-hash"`
	} `yaml:"torrent"`
}

type ClientConfig struct {
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
	} `yaml:"hysteria"`

	Torrent struct {
		AuthKey  string `yaml:"auth-key"`
		InfoHash string `yaml:"info-hash"`
	} `yaml:"torrent"`
}

func LoadConfig(path string) (*Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return createDefaultConfig(path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func createDefaultConfig(path string) (*Config, error) {
	// Генерация ключей для дефолтного конфига
	privKey := make([]byte, 32)
	importRand.Read(privKey)

	shortId := make([]byte, 8)
	importRand.Read(shortId)

	cfg := &Config{
		Protocol: "xhttp",
		Port:     "443",
		Dest:     "github.com:443",
		Xhttp: struct {
			Path string "yaml:\"path\""
		}{
			Path: "/8f9e0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f/data",
		},
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return nil, err
	}

	return cfg, nil
}
