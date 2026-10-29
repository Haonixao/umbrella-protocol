# Umbrella Client Configuration Parameters Reference

In the Umbrella GUI client, all settings are defined in internal editors (**Settings -> Config Editor** and **Phase Editor**). 

**Important Note on Zero-Touch Provisioning:** Most "Server side data" parameters (Protocol, Server, SNI, XHTTP Path, Hysteria Auth-Password, Torrent Auth-Key/Info-Hash) are automatically fetched from the Control Plane (IMAP) upon activation. Manual configuration of these is only required for initial setup, debugging, or offline mode.

---

## Client Side Data & Control Plane

### client_activation_key:

```yaml
client_activation_key: "your_pre_shared_key"
```

The pre-shared key used to authenticate the client's IP address with the server via the Control Plane (IMAP). This is the only mandatory credential required to establish a connection.

### imap.gmail.login & imap.gmail.password:

```yaml
imap:
  gmail:
    login: "your_email@gmail.com"
    password: "your_app_password"
```

Credentials for the Gmail account used to communicate with the server's Control Plane. The client uses this to send activation requests and fetch the latest server configuration.

### listen:

```yaml
listen: "0.0.0.0:1080"
```

Local address and port where the client will start the SOCKS5 proxy server.
* **Default**: `"0.0.0.0:1080"`.

### udp:

```yaml
udp: true
```

Enables `UDP ASSOCIATE` support. Required for voice calls, games, and some messengers to work through the proxy.
* **Default**: `true`.

### decoy-traffic:

```yaml
decoy-traffic: false
```

Enables the global obfuscation module. The client will simulate regular user activity by performing rare requests to legitimate global resources (Bing, Apple, etc.) directly, blurring IP connection statistics and hiding the fact of connecting to only one server.
* **Default**: `false`.

### shaper:

```yaml
shaper: false
```

Activates the Traffic Shaping system. Allows simulating data transfer patterns of various applications. Requires phase configuration in the **Phase Editor**.
* **Default**: `false`.

### phases-file:

```yaml
phases-file: "phases.yml"
```

Path to the file containing shaper phase descriptions. In the GUI client, it is edited via the **Phase Editor**.
* **Default**: `"phases.yml"`.

### bypass:

```yaml
bypass:
  - "192.168.1.0/24"
  - "gosuslugi.ru"
```

List of IP networks (in CIDR format) or domain names for which connections should go directly through the local provider, bypassing the secure tunnel.

---

## Server Side Data (Auto-fetched via Control Plane)

*Note: These parameters are typically populated automatically after successful IMAP activation. Manual overrides are possible.*

### protocol:

```yaml
protocol: "xhttp"
```

Defines the main traffic obfuscation protocol.
* **Allowed values**: `"xhttp"`, `"hysteria"`, `"torrent"`.

### server:

```yaml
server: "1.2.3.4:443" # or 1.2.3.4:50000-50100 for torrent
```

Address and port of your remote Umbrella VPS server.
* **For Torrent**: You can specify a port range (e.g., `50000-50100`) if Port Hopping is enabled.

### sni:

```yaml
sni: "google.com"
```

Server Name Indication. The domain that the connection will masquerade as.
* **Default**: `"github.com"`.

---

## XHTTP Section (HTTP/2 & HTTP/3 Tunnel)

### xhttp.quic:

```yaml
xhttp:
  quic: false
```

Enables HTTP/3 (QUIC) instead of HTTP/2 as the underlying transport.
* **Default**: `false`.

### xhttp.path:

```yaml
xhttp:
  path: "/api/v1/update"
```

The HTTP path used for establishing the tunnel.

### xhttp.mode:

```yaml
xhttp:
  mode: "stream-one"
```

Defines the tunneling mode:
* **stream-one**: A single long-lived POST request for both uplink and downlink.
* **stream-up**: Uses a GET request for downlink and a separate long-lived POST for uplink.
* **packet-up**: Uses a GET request for downlink and splits uplink data into multiple small POST requests (useful for bypassing CDN or firewall restrictions).
* **Default**: `"stream-one"`.

---

## Hysteria Section (Hysteria 2)

### hysteria.auth-password:

```yaml
hysteria:
  auth-password: "your_password"
```

Password for standard Hysteria 2 protocol authentication. Verified by the internal Hysteria core *after* the frontend wrapper has validated the client's IP via the Control Plane.

### hysteria.conns-num:

```yaml
hysteria:
  conns-num: 2
```

Number of independent UDP clients (sessions). Helps bypass some provider restrictions on traffic volume or packet count within a single UDP stream.
* **Default**: `2`.

---

## Torrent Section (Torrent Stealth)

### torrent.auth-key:

```yaml
torrent:
  auth-key: "hex_string_32_bytes"
```

Shared secret used to derive the AES-CTR session encryption key. 
* **Note**: This is **no longer** used for HMAC PeerID verification in the handshake (the handshake is now 100% vanilla). It is strictly used for encrypting the payload after the IP has been whitelisted.

### torrent.info-hash:

```yaml
torrent:
  info-hash: "40_hex_chars"
```

Info-hash of the torrent distribution that the traffic masquerades as.
* **Recommendation**: Use a real hash of popular distributions (e.g., Linux distros) so that masquerading as "White Noise" (tracker requests) looks as plausible as possible.

### torrent.sessions-num:

```yaml
torrent:
  sessions-num: 2
```

Number of uTP sessions in the Yamux multiplexing pool.
* **Default**: `2`.

### torrent.connections-time-out:

```yaml
torrent:
  connections-time-out: 70
```

Torrent connection rotation period in seconds. Allows changing ports and PeerID to improve obfuscation.
* **Default**: `70`.
