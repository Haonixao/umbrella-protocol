# Torrent Stealth (Umbrella variant)

Torrent Stealth is a unique Umbrella protocol designed for maximum survivability in environments where all known VPN protocols are blocked.

## Configuration

To activate this mode, use `protocol: torrent` in your configuration files.

### Server (config.yaml)

```yaml
protocol: "torrent"
port: "50000-50100"         # Range for Port Hopping

torrent:
  auth-key: "..."      # HMAC key for authentication (hex, 32 bytes)
  info-hash: "..."     # Info hash (40 hex chars). If empty, generated randomly.
```

### Client (config.yaml)

```yaml
protocol: "torrent"
server: "your_vps_ip:50000-50100" # Must match the server range
listen: "0.0.0.0:1080"

torrent:
  auth-key: "..."      # Must match the server
  info-hash: "..."     # For better masking, use the hash of a real torrent (e.g., Ubuntu)
```

## Why It Works

### 1. Unique Authentication

Unlike standard proxies, Umbrella Torrent validates the client during the BitTorrent handshake stage:
* **HMAC PeerID** : The client generates its `PeerID` using a Nonce and an HMAC signature. The server verifies this signature using the secret `auth-key`.
* **Stealth**: If the signature is invalid, the server does not drop the connection; instead, it switches to **Decoy Mode** .

### 2. Decoy Mode (Anti-Probing Protection)

If an external scanner or a real torrent client accesses the server port:
*   The server pretends to be a normal seed (Peer).
*   It accepts `request` messages to download file pieces.
*   In response, the server sends **`piece` messages containing random data** . To an external observer, this looks like the transmission of encrypted fragments of a real file.

### 3. Piece Framing + Padding

All your data (TCP/UDP/DNS) is encapsulated into standard BitTorrent `piece` messages (ID 7).

* **Random Padding:** Between 0 and 255 bytes of random "junk" are added to each message.
*   This makes the length of every packet unique and unpredictable, breaking any statistical packet length signatures.

### 5. Port Hopping & Rotation

The client selects a random port from the specified range for every new session. Additionally, each session is automatically rotated after a random interval. This makes blocking a specific port ineffective and simulates the natural behavior of switching between different peers in a torrent network.
