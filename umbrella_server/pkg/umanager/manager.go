package umanager

import (
	"fmt"
	"os"
	"sync"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

type yamlKey struct {
	Value       string `yaml:"value"`
	IsActivated bool   `yaml:"is_activated"`
}

type yamlKeysFile struct {
	Keys []yamlKey `yaml:"keys"`
}

type KeyInfo struct {
	IsActivated bool
	IP          string
}

type Umanager struct {
	keys    map[string]KeyInfo
	fastIps map[string]bool
	rwLock  sync.RWMutex
}

func (m *Umanager) SetupManager() error {
	m.rwLock.Lock()
	defer m.rwLock.Unlock()

	const keysFile = "keys.yaml"

	m.keys = make(map[string]KeyInfo)
	m.fastIps = make(map[string]bool)

	// Check if keys.yaml exists
	if info, err := os.Stat(keysFile); err == nil && !info.IsDir() {
		// File exists, load it
		data, err := os.ReadFile(keysFile)
		if err != nil {
			return fmt.Errorf("failed to read keys.yaml: %w", err)
		}

		var ykf yamlKeysFile
		if err := yaml.Unmarshal(data, &ykf); err != nil {
			return fmt.Errorf("failed to parse keys.yaml: %w", err)
		}

		for _, k := range ykf.Keys {
			m.keys[k.Value] = KeyInfo{
				IsActivated: k.IsActivated,
				IP:          "",
			}
		}
	} else if os.IsNotExist(err) {
		// File doesn't exist, create empty one
		emptyYAML := yamlKeysFile{Keys: []yamlKey{}}
		data, err := yaml.Marshal(emptyYAML)
		if err != nil {
			return fmt.Errorf("failed to marshal empty keys.yaml: %w", err)
		}
		if err := os.WriteFile(keysFile, data, 0o644); err != nil {
			return fmt.Errorf("failed to create keys.yaml: %w", err)
		}
	} else {
		return fmt.Errorf("failed to check keys.yaml: %w", err)
	}

	// Count inactive keys
	inactiveCount := 0
	for _, info := range m.keys {
		if !info.IsActivated {
			inactiveCount++
		}
	}

	// Generate 100 additional keys if inactive < 50
	if inactiveCount < 50 {
		for range 100 {
			m.keys[uuid.NewString()] = KeyInfo{
				IsActivated: false,
				IP:          "",
			}
		}
		if err := m.flushKeys(); err != nil {
			return fmt.Errorf("failed to flush keys: %w", err)
		}
	}

	return nil
}

func (m *Umanager) flushKeys() error {
	const keysFile = "keys.yaml"

	ykf := yamlKeysFile{Keys: make([]yamlKey, 0, len(m.keys))}
	for id, info := range m.keys {
		ykf.Keys = append(ykf.Keys, yamlKey{
			Value:       id,
			IsActivated: info.IsActivated,
		})
	}

	data, err := yaml.Marshal(ykf)
	if err != nil {
		return fmt.Errorf("failed to marshal keys.yaml: %w", err)
	}

	if err := os.WriteFile(keysFile, data, 0o644); err != nil {
		return fmt.Errorf("failed to write keys.yaml: %w", err)
	}

	return nil
}

func (m *Umanager) IsIpActivated(ip string) bool {
	if ip == "127.0.0.1" {
		return true
	}
	m.rwLock.RLock()
	defer m.rwLock.RUnlock()
	return m.fastIps[ip]
}

func (m *Umanager) ActivateIp(key string, ip string) error {
	m.rwLock.Lock()
	defer m.rwLock.Unlock()

	info, ok := m.keys[key]
	if !ok {
		return fmt.Errorf("key not found: %s", key)
	}

	if info.IP != "" {
		m.fastIps[info.IP] = false
	}

	m.fastIps[ip] = true

	info.IP = ip
	info.IsActivated = true
	m.keys[key] = info

	if err := m.flushKeys(); err != nil {
		return fmt.Errorf("failed to flush keys: %w", err)
	}

	return nil
}
