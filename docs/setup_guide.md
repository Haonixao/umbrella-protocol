# Umbrella Build and Deployment Guide

## 🛠️ Building Components

### 1. Umbrella Server (Linux)

Building for Linux x64 architecture:

```bash
cd umbrella_server
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o umbrella_server ./cmd/server
```



```bash
cd umbrella_server
go build -o umbrella_server ./cmd/server
```

### 2. Umbrella Client (Windows | Linux)

```bash
cd umbrella_client
go build -ldflags="-H windowsgui" -o umbrella-client.exe ./cmd/ui
```



```bash
cd umbrella_client
fyne-cross windows -env GOTOOLCHAIN=auto -app-id com.umbrella.client ./cmd/ui
```



```bash
cd umbrella_client
go build -o umbrella-client ./cmd/ui
```

### 3. Umbrella Client (Android)

Building for Android requires `fyne-cross` installed:

```bash
fyne-cross android -env GOTOOLCHAIN=auto -app-id com.umbrella.client ./cmd/ui
```

 *Note:* See. [android_fix.md](./android_fix.md) for correct background operation.

---

## 🚀 Deployment

### Server (VPS)

1. Copy the `umbrella_server` binary to your server.
2. Run it for the first time to automatically generate the configuration file and keys:
   

```bash
   chmod +x umbrella_server
   ./umbrella_server
   ```

3. The server will output the generated `Private Key`,  `Public Key` and `Short ID` to the log. Save them!

4. Edit the created `config.yaml` to select the desired protocol and insert your keys.

### Client (Windows)

1. Launch `umbrella-client`.
2. Go to **Settings -> Config** .
3. Fill in the server parameters using the data obtained during the server startup
4. Select the desired operating mode.

---

## ⚙️ Configuration

Configuration parameters depend on the chosen masking protocol. A detailed description of all fields for each mode can be found in the corresponding documentation files:

* **XTLS** : [Details in xtls.md](./protocols/xtls.md)
* **Hysteria 2** : [Details in hysteria.md](./protocols/hysteria.md)
* **Torrent** : [Details in torrent.md](./protocols/torrent.md)

---

## 📚 Configuration Reference

Full schemas of all parameters are available:
* **[Client Configuration Schema](./client_config.md)** 
* **[Server Configuration Schema](./server_config.md)** 
