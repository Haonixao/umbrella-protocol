package activator

import (
	"fmt"
	"log"
	"time"
	"umbrella_server/internal/config"
	"umbrella_server/pkg/imap/gmail"
	"umbrella_server/pkg/umanager"

	"gopkg.in/yaml.v3"
)

type Activator struct {
	gmailImap *gmail.GmailImap
	umanager  *umanager.Umanager
}

func (a *Activator) setupMeta(clientCfg config.ClientConfig) error {
	metaYaml, err := yaml.Marshal(clientCfg)
	if err != nil {
		return fmt.Errorf("failed to marshal client config to YAML: %w", err)
	}

	return a.gmailImap.SetUmbrellaMeta(string(metaYaml))
}

func (a *Activator) processUmbrellaRequests() {
	c, err := a.gmailImap.SetupImapClient()
	if err != nil {
		log.Printf("[ERR] Failed to get imap client: %v", err)
	}

	const interval = 5 * time.Second
	for {
		c.Noop()

		requests, err := a.gmailImap.GetUmbrellaRequests(c)
		if err != nil {
			log.Printf("[ERR] Failed to get umbrella requests: %v", err)
			c.Logout()
			c, err = a.gmailImap.SetupImapClient()
			if err != nil {
				log.Printf("[ERR] Failed to get imap client: %v", err)
			}
		}

		for _, req := range requests {
			var data struct {
				IP                  string `yaml:"ip"`
				ClientActivationKey string `yaml:"client_activation_key"`
			}
			if err := yaml.Unmarshal([]byte(req), &data); err != nil {
				log.Printf("[ERR] Failed to parse activation request: %v", err)
				continue
			}

			if data.IP == "" || data.ClientActivationKey == "" {
				log.Printf("[ERR] Activation request missing IP or key: %v", req)
				continue
			}

			if err := a.umanager.ActivateIp(data.ClientActivationKey, data.IP); err != nil {
				log.Printf("[ERR] Activation failed for IP %s with key %s: %v", data.IP, data.ClientActivationKey, err)
				continue
			}

			if err := a.gmailImap.PostUmbrellaResponse(c, data.IP); err != nil {
				log.Printf("[ERR] Failed to send activation response for IP %s: %v", data.IP, err)
				continue
			}

			log.Printf("[INFO] Success activation for IP %s", data.IP)
		}

		time.Sleep(interval)
	}
}

func (a *Activator) IsIpActivated(ip string) bool {
	return a.umanager.IsIpActivated(ip)
}

func SetupActivator(cfg config.Config, clientCfg config.ClientConfig) (*Activator, error) {
	gmailImap := gmail.GmailImap{
		Login:    cfg.Imap.Gmail.Login,
		Password: cfg.Imap.Gmail.Password,
	}

	um := umanager.Umanager{}
	if err := um.SetupManager(); err != nil {
		return nil, fmt.Errorf("failed to load keys: %w", err)
	}

	activator := &Activator{
		gmailImap: &gmailImap,
		umanager:  &um,
	}

	if err := activator.setupMeta(clientCfg); err != nil {
		log.Printf("[ERR] setupMeta failed: %v", err)
	}

	go activator.processUmbrellaRequests()

	return activator, nil
}
