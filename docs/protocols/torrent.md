# Torrent Stealth (Umbrella variant)

Torrent Stealth is a unique Umbrella protocol designed for maximum survivability in environments where all known VPN protocols are blocked. It masks proxy traffic as legitimate BitTorrent communication while maintaining 100% vanilla handshakes.

## Configuration

To activate this mode, use `protocol: torrent` in your configuration files.

### Server (config.yaml)

```yaml
protocol: "torrent"
port: "50000-50100"         # Range for Port Hopping

torrent:
  auth-key: "..."      # Shared secret for session encryption (hex, 32 bytes)
  info-hash: "..."     # Info hash (40 hex chars). If empty, generated randomly.
```

### Client (config.yaml)

**Note:** The client receives the actual connection configuration (server IP, port, SNI, auth-key, info-hash) automatically from the Control Plane (see [Activation](../activation.md)). Manual configuration is only required for initial setup or debugging.

```yaml
protocol: "torrent"
server: "your_vps_ip:50000-50100" # Must match the server range
listen: "0.0.0.0:1080"

torrent:
  auth-key: "..."      # Must match the server
  info-hash: "..."     # For better masking, use the hash of a real torrent (e.g., Ubuntu)
```

## How It Works

### 1. Control Plane Activation

Before any data exchange, the client activates its IP address through an out-of-band channel (e.g., Gmail IMAP). The server publishes the current `ClientConfig` (IP, port, auth-key, info-hash) to a draft message. The client sends an activation request with its IP and pre-shared key. Upon validation, the server adds the client's IP to a fast-lookup whitelist.

See [Activation via Alternative Channel](../activation.md) for details.

### 2. 100% Vanilla BitTorrent Handshake

Unlike traditional stealth proxies, Umbrella Torrent does not embed custom cryptographic signatures into the BitTorrent handshake:
* **Standard PeerID**: Both client and server use vanilla BitTorrent client identifiers (e.g., `-TR4000-` for Transmission 4.0.0). No HMAC, no time-drift masks, no custom byte structures.
* **Reality-Like Fallback**: If an unactivated IP connects, the server responds with a valid, standard BitTorrent handshake and enters **Decoy Mode** (see below). To an external observer, this is indistinguishable from a legitimate torrent peer.

### 3. Decoy Mode (Anti-Probing Protection)

If an external scanner or a real torrent client (with unactivated IP) accesses the server port:
*   The server pretends to be a normal seed (Peer).
*   It accepts `request` messages to download file pieces.
*   In response, the server sends **`piece` messages containing random data**. To an external observer, this looks like the transmission of encrypted fragments of a real file.

### 4. Session Encryption (AES-CTR)

After the handshake, all traffic is encrypted using AES-256-CTR:
* **Key Derivation**: `SHA256(auth-key)`
* **IV Derivation**: `SHA256(auth-key + clientPeerID + serverPeerID)`

This ensures that even if the same `auth-key` is reused, each session has a unique IV, preventing replay attacks.

### 5. Piece Framing + Padding

All your data (TCP/UDP/DNS) is encapsulated into standard BitTorrent `piece` messages (ID 7).

* **Random Padding:** Between 0 and 255 bytes of random "junk" are added to each message.
*   This makes the length of every packet unique and unpredictable, breaking any statistical packet length signatures.

### 6. Port Hopping & Rotation

The client selects a random port from the specified range for every new session. Additionally, each session is automatically rotated after a random interval. This makes blocking a specific port ineffective and simulates the natural behavior of switching between different peers in a torrent network.

## Advantages

1. **Zero-Touch Provisioning**: Clients automatically fetch the latest configuration from the Control Plane. No manual updates required when server parameters change.
2. **Traffic Analysis Resistance**: 100% vanilla handshakes prevent detection via DPI, JA3/JA4 fingerprinting, or entropy analysis.
3. **Plausible Deniability**: Unactivated connections receive standard BitTorrent responses, making the server indistinguishable from a legitimate torrent seed.
4. **Agnostic Control Plane**: Can be adapted to any legitimate messaging service with an API (Gmail, Yandex Mail, Mail.ru, etc.).
The client selects a random port from the specified range for every new session. Additionally, each session is automatically rotated after a random interval. This makes blocking a specific port ineffective and simulates the natural behavior of switching between different peers in a torrent network.
