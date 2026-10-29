package app

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"umbrella_client/internal/client/config"
	"umbrella_client/internal/client/decoy"
	"umbrella_client/internal/client/hysteria"
	"umbrella_client/internal/client/torrent"
	"umbrella_client/internal/client/xhttp"
	"umbrella_client/internal/logging"
	"umbrella_client/internal/settings"
	"umbrella_client/internal/storage"
	"umbrella_client/internal/tunnel"
	"umbrella_client/pkg/imap/gmail"
	"umbrella_client/pkg/ip"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/data/binding"
	"go.yaml.in/yaml/v3"
)

func loadConfig(appSettings *settings.AppSettings, l *logging.LogsContainer, appRef fyne.App) (*config.Config, error) {
	configData, err := storage.LoadConfig(appSettings.AppFilesDir, appRef)
	if err != nil {
		l.AppendLog("[ERR] Cannot read config.yaml: " + err.Error())
		return nil, err
	}

	var userCfg *config.Config
	if userCfg, err = config.ParseConfig(configData); err != nil {
		l.AppendLog("[ERR] Raw config parse failed: " + err.Error())
		return nil, err
	}

	// Fetch server-side config via IMAP
	imapClient := &gmail.GmailImap{
		Login:    userCfg.Imap.Gmail.Login,
		Password: userCfg.Imap.Gmail.Password,
	}

	serverCfgStr, err := imapClient.GetUmbrellaMeta()
	if err != nil {
		l.AppendLog("[ERR] Failed to get server config via IMAP: " + err.Error())
		return nil, err
	}

	// Parse server config (applies defaults + validation)
	serverCfg, err := config.ParseConfig([]byte(serverCfgStr))
	if err != nil {
		l.AppendLog("[ERR] Failed to parse server config: " + err.Error())
		return nil, err
	}

	// Merge: for Server side data fields, use server value if user didn't explicitly set it
	if userCfg.Protocol == "" {
		userCfg.Protocol = serverCfg.Protocol
	}
	if userCfg.Server == "" {
		userCfg.Server = serverCfg.Server
	}
	if userCfg.SNI == "" {
		userCfg.SNI = serverCfg.SNI
	}

	// Xhttp
	if userCfg.Xhttp.Mode == "" {
		userCfg.Xhttp.Mode = serverCfg.Xhttp.Mode
	}
	if userCfg.Xhttp.Path == "" {
		userCfg.Xhttp.Path = serverCfg.Xhttp.Path
	}
	userCfg.Xhttp.Quic = userCfg.Xhttp.Quic || serverCfg.Xhttp.Quic

	// Hysteria
	if userCfg.Hysteria.AuthPassword == "" {
		userCfg.Hysteria.AuthPassword = serverCfg.Hysteria.AuthPassword
	}
	if userCfg.Hysteria.ConnsNum == 0 {
		userCfg.Hysteria.ConnsNum = serverCfg.Hysteria.ConnsNum
	}

	// Torrent
	if userCfg.Torrent.AuthKey == "" {
		userCfg.Torrent.AuthKey = serverCfg.Torrent.AuthKey
	}
	if userCfg.Torrent.InfoHash == "" {
		userCfg.Torrent.InfoHash = serverCfg.Torrent.InfoHash
	}
	if userCfg.Torrent.SessionsNum == 0 {
		userCfg.Torrent.SessionsNum = serverCfg.Torrent.SessionsNum
	}
	if userCfg.Torrent.ConnectionsTimeOut == 0 {
		userCfg.Torrent.ConnectionsTimeOut = serverCfg.Torrent.ConnectionsTimeOut
	}

	cfg, err := yaml.Marshal(*userCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal client config to YAML: %w", err)
	}

	l.AppendLog("[INFO] Config: " + string(cfg))

	return userCfg, nil
}

func clientActivate(ctx context.Context, cfg *config.Config) error {
	// Get public IP
	publicIP, err := ip.CheckIp()
	if err != nil {
		return fmt.Errorf("activation: failed to get public IP: %w", err)
	}

	// Build YAML string for server
	requestStr := fmt.Sprintf("ip: %s\nclient_activation_key: %s\n", publicIP, cfg.ClientActivationKey)

	// Send activation request via IMAP
	imapClient := &gmail.GmailImap{
		Login:    cfg.Imap.Gmail.Login,
		Password: cfg.Imap.Gmail.Password,
	}

	if err := imapClient.PostUmbrellaRequest(requestStr); err != nil {
		return fmt.Errorf("activation: failed to post request: %w", err)
	}

	// Wait for server response
	found, err := imapClient.GetUmbrellaResponse(publicIP)
	if err != nil {
		return fmt.Errorf("activation: response error: %w", err)
	}
	if !found {
		return fmt.Errorf("activation: activation response not found")
	}

	return nil
}

func initAndStart(appSettings *settings.AppSettings, l *logging.LogsContainer, appRef fyne.App, isRunning *bool, ctx context.Context, startEnabled, stopEnabled binding.Bool, onceLog *sync.Once) {
	// Set up logging first to capture all output
	onceLog.Do(func() {
		log.SetOutput(&logging.LogWriter{LogsContainer: l})
		log.SetFlags(0)
	})
	err := os.MkdirAll(appSettings.AppFilesDir, 0o755)
	if err != nil {
		l.AppendLog("[ERR] Failed to create directory: " + err.Error())
		finish("Status: Directory Error", isRunning, l, startEnabled, stopEnabled)
		return
	}

	l.AppendLog("[INFO] Loading configuration...")
	cfg, err := loadConfig(appSettings, l, appRef)
	if err != nil {
		l.AppendLog("[ERR] Config parse failed: " + err.Error())
		finish("Status: Config Error", isRunning, l, startEnabled, stopEnabled)
		return
	}

	// Load phases data from storage/disk (required)
	phasesData, err := storage.LoadPhases(appSettings.AppFilesDir, appRef)
	if err != nil {
		l.AppendLog("[ERR] Cannot read phases.yml: " + err.Error())
		finish("Status: Phases Error", isRunning, l, startEnabled, stopEnabled)
		return
	}
	cfg.PhasesData = phasesData

	// Log what will be started
	l.AppendLog(fmt.Sprintf("[INFO] Starting client on %s", cfg.ListenAddr))

	if cfg.Shaper {
		l.AppendLog("[INFO] Traffic shaping: enabled")
	}
	if cfg.DecoyTraffic {
		l.AppendLog("[INFO] Decoy traffic: enabled")
		go decoy.StartGlobalDecoy(ctx)
	}

	// Start tunnel core if configured
	var pr *os.Process
	if appSettings.TunnelCorePath != "" {
		if pr, err = tunnel.StartTunnelCore(appSettings.TunnelCorePath, appSettings.TunnelCoreArgs, l); err != nil {
			l.AppendLog("[ERR] Failed to start tunnel core: " + err.Error())
			finish("Status: Tunnel Core Error", isRunning, l, startEnabled, stopEnabled)
			return
		}
	}

	// Run client in a goroutine
	go func() {
		defer func() {
			// Ensure we always call finish and handle panics
			if r := recover(); r != nil {
				l.AppendLog(fmt.Sprintf("[ERR] Client crashed: %v", r))
				finish("Status: Crashed", isRunning, l, startEnabled, stopEnabled)
			} else if *isRunning {
				// Normal exit
				l.AppendLog("[INFO] Client stopped, updating status")
				finish("Status: Stopped", isRunning, l, startEnabled, stopEnabled)
			}
			if appSettings.TunnelCorePath != "" {
				if err := tunnel.StopTunnelCore(pr); err == nil {
					l.AppendLog("[INFO] Tunnel core stopped")
				} else {
					l.AppendLog("[ERR] Tunnel core not stopped. Need a manual stop process. " + err.Error())
				}
			}
		}()

		l.AppendLog("[INFO] Activating...")
		err := clientActivate(ctx, cfg)
		if err != nil {
			l.AppendLog("[ERR] Client failed to activate: " + err.Error())
			finish("Status: Failed", isRunning, l, startEnabled, stopEnabled)
			return
		}
		l.AppendLog("[INFO] Client activated")

		var start func(cfg *config.Config, ctx context.Context, appFilesDir string) error
		switch cfg.Protocol {
		case "hysteria":
			start = hysteria.Start
		case "torrent":
			start = torrent.Start
		case "xhttp":
			start = xhttp.Start
		default:
			l.AppendLog("[ERR] Client failed to start: not valid protocol")
			finish("Status: Failed", isRunning, l, startEnabled, stopEnabled)
		}
		err = start(cfg, ctx, appSettings.AppFilesDir)
		if err != nil {
			if strings.Contains(err.Error(), "failed to listen on "+cfg.ListenAddr) {
				if runtime.GOOS != "android" {
					switch runtime.GOOS {
					case "windows":
						errR := exec.Command("net", "stop", "winnat").Run()
						if errR == nil {
							errR = exec.Command("net", "start", "winnat").Run()
						}
						if errR != nil {
							l.AppendLog("[ERR] Failed net command: " + errR.Error())
							finish("Status: Failed net command", isRunning, l, startEnabled, stopEnabled)
							return
						}
					case "linux":
						if errR := exec.Command("sh", "-c", "fuser -k 1080/tcp").Run(); errR != nil {
							l.AppendLog("[ERR] Failed net sh: " + errR.Error())
							finish("Status: Failed net sh", isRunning, l, startEnabled, stopEnabled)
							return
						}
					}
					err = start(cfg, ctx, appSettings.AppFilesDir)
				}
			}

			l.AppendLog(fmt.Sprintf("[ERR] Client failed to start: %v", err))
			if runtime.GOOS != "android" {
				var comm string
				switch runtime.GOOS {
				case "windows":
					comm = "net stop winnat && net start winnat"
				case "linux":
					comm = "sudo sh -c fuser -k 1080/tcp"
				}
				l.AppendLog(fmt.Sprintf("[ERR] If port problem try this command in terminal: '%s'", comm))
			}
			finish("Status: Failed", isRunning, l, startEnabled, stopEnabled)
		} else {
			l.AppendLog("[INFO] Client stopped gracefully")
			// Only call finish if we're still running (not already stopped)
			if *isRunning {
				finish("Status: Stopped", isRunning, l, startEnabled, stopEnabled)
			}
		}
	}()
}

func finish(status string, isRunning *bool, l *logging.LogsContainer, startEnabled, stopEnabled binding.Bool) {
	*isRunning = false
	l.StatusBind.Set(status)
	startEnabled.Set(true)
	stopEnabled.Set(false)
	l.AppendLog(fmt.Sprintf("[INFO] Client status: %s", strings.TrimPrefix(status, "Status: ")))
}
