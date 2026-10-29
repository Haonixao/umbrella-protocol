# Client Activation via Alternative Channel (Control Plane)

This document describes the Umbrella protocol's activation mechanism, which strictly separates the **Control Plane** (authentication and configuration) from the **Data Plane** (traffic routing).

## Mechanism

1. **Server Initialization**: The server determines its public IP and generates a `ClientConfig` (IP, port, SNI, protocol keys).
2. **OOB Publication**: The server publishes this config to a legitimate messaging service (e.g., Gmail IMAP Draft with subject `[Umbrella meta]`).
3. **Client Request**: The client sends an activation request to the same channel (e.g., IMAP Draft `[Umbrella request]` containing its public IP and pre-shared activation key in YAML).
4. **Validation**: The server's background process polls the channel, validates the key against its local registry (`keys.yaml`), and binds the client's IP to it.
5. **Response**: The server posts a confirmation (e.g., IMAP Draft `[Umbrella response]`).
6. **Data Plane Access**: The client's IP is added to a fast-lookup whitelist. Subsequent traffic from this IP is routed directly to the backend.

## Key Advantages

### 1. 100% Vanilla Handshakes
Eliminates custom byte structures (HMAC, time-drift masks) from protocol headers (TLS `SessionID`, QUIC `SCID`, BitTorrent `peer_id`). Prevents detection via DPI, entropy analysis, or JA3/JA4 fingerprinting.

### 2. Zero-Touch Provisioning
Clients dynamically fetch the actual `ClientConfig` from the Control Plane. No manual config updates are required when server parameters change; a simple reconnect suffices.

### 3. Simplified Data Plane
Complex cryptographic validation is removed from the packet processing path. Routing relies solely on a highly efficient whitelist check (`IsIpActivated`), eliminating silent failures from clock drift or parsing errors and reducing CPU overhead.

### 4. Reality-Like Fallback
Unactivated connections are not dropped or met with cryptographic errors. The server emulates legitimate target behavior:
- **XHTTP**: Forwards to a standard web destination.
- **Hysteria**: Responds with standard QUIC behavior.
- **BitTorrent**: Replies with a valid, standard handshake (e.g., `-TR4000-` client ID) and random peer ID, mimicking a legitimate peer.

### 5. Agnostic Control Plane
Gmail IMAP is a reference implementation. The mechanism can be adapted to any legitimate messaging service with an API (e.g., Yandex Mail, Mail.ru), ensuring resilience against platform-specific blocking.
