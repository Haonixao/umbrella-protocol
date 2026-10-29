# Umbrella Server Configuration Parameters Reference

The Umbrella server is managed via the `config.yaml` file, which is automatically generated on the first run with default settings for the XHTTP protocol. Below is a detailed description of all available parameters, reflecting the current architecture with out-of-band (IMAP) activation.

---

### protocol:

```yaml
protocol: "xhttp"
```

Defines the active obfuscation protocol on the server.
* **Allowed values**: `"xhttp"`, `"hysteria"`, `"torrent"`.

### port:

```yaml
port: "443" # or "50000-50100" for torrent
```

The port the server will listen on.
* **For Torrent**: You can specify a port range (e.g., `"50000-50100"`) to enable Port Hopping.
* **Default**: `"443"`.

### dest:

```yaml
dest: "samsung.com:443"
```

Fallback address. All incoming connections from unactivated IPs will be transparently redirected to this address. This simulates the behavior of a real service (Reality-like fallback).
* **Default**: `"samsung.com:443"`.

### debug:

```yaml
debug: false
```

Enables verbose logging for troubleshooting.

---

## IMAP Section (Control Plane)

This section configures the out-of-band channel used for client activation and dynamic configuration delivery.

### imap.gmail.login:

```yaml
imap:
  gmail:
    login: "your_email@gmail.com"
```

The Gmail account used to read activation requests and publish the server configuration.

### imap.gmail.password:

```yaml
imap:
  gmail:
    password: "your_app_password"
```

The App Password for the Gmail account (not your regular password). Required for IMAP authentication.

---

## XHTTP Section (HTTP/2 & HTTP/3 Tunnel)

### xhttp.path:

```yaml
xhttp:
  path: "/api/v1/update"
```

The HTTP path used for the tunnel. Requests to other paths will be handled according to the `dest` fallback logic (returning 404/403 as appropriate).
* **Note**: `auth-key` has been removed from XHTTP configuration. Authentication is now handled exclusively via IP whitelisting through the IMAP Control Plane.

---

## Hysteria Section (Hysteria 2)

### hysteria.auth-password:

```yaml
hysteria:
  auth-password: "your_password"
```

The password for standard Hysteria 2 protocol authentication. This is verified by the internal Hysteria core *after* the frontend wrapper has validated the client's IP via the Control Plane.
* **Note**: `auth-key` and `quic-port` have been removed from the configuration. The internal port is fixed (e.g., `8443`), and handshake cryptography is no longer used for initial filtering.

---

## Torrent Section (Torrent Stealth)

### torrent.auth-key:

```yaml
torrent:
  auth-key: "hex_string_32_bytes"
```

The shared secret used to derive the AES-CTR session encryption key. 
* **Note**: This is no longer used for HMAC PeerID verification in the handshake. The handshake is now 100% vanilla. This key is only used for encrypting the payload after the IP has been whitelisted.

### torrent.info-hash:

```yaml
torrent:
  info-hash: "40_hex_chars"
```

The info-hash of the torrent distribution. If left empty, the server will generate a random hash at startup.
* **Recommendation**: Specify a real hash (e.g., a popular Linux distribution) so the server appears as a legitimate peer for that distribution during Decoy Mode.
