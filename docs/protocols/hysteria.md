# Hysteria 2 (Umbrella Variant)

Hysteria 2 is a high-performance protocol based on QUIC (UDP), optimized for operation in networks with high packet loss and unstable latency.

## Configuration

To activate this mode, use `protocol: hysteria` in the configuration files.

### Server (config.yaml)

```yaml
protocol: "hysteria"
port: "443"             # Main port (masquerade)
dest: "samsung.com:443" # Fallback site for "outsiders"

hysteria:
  auth-key: "..."      # HMAC key for authentication (hex, 32 bytes)
  auth-password: "..." # Password for QUIC authentication
```

### Client (config.yaml)

```yaml
protocol: "hysteria"
server: "your_vps_ip:443"
sni: "samsung.com"
listen: "0.0.0.0:1080"

hysteria:
  auth-key: "..."      # Must match the server
  auth-password: "..." # Must match the server
```

## Implementation Features in Umbrella

Unlike classic Hysteria, the Umbrella Protocol implementation includes a custom enhancement (Flawless Masquerade) and packet-level Random padding to ensure maximum stealth ( **due to this, Salamander mode is not supported** ):

### 1. Two-level Authentication and Masquerade (Flawless Masquerade)

Umbrella implements a unique mechanism for verifying clients even before the QUIC handshake begins:
* **HMAC Connection ID** : The client embeds an HMAC signature into the `Source Connection ID` of the first packet (`Initial`). The server verifies this signature using the `auth-key`.
* **Transparent Proxying (Fallback)** : If the signature is invalid or missing (a request from a scanner or an "outsider"), the server behaves as a transparent UDP proxy. It redirects traffic to `dest` (e.g., samsung.com), fully imitating the behavior of a legitimate service.
* **Active Probing Protection** : The ISP or censor cannot detect Hysteria by simple scanning, as the server only responds to its own clients. For "outsiders" transparent proxying of the QUIC connection to `dest` is performed.

### 3. Padding

* **Random Padding:** Between 0 and 255 bytes of random "junk" are added to each message.
*   This makes the length of every packet unique and unpredictable, breaking any statistical packet length signatures.

### 4. Dynamic Rotation

The system automatically rotates UDP clients in the pool, generating new Connection IDs with unique HMAC signatures for each new session. This prevents tracking users via static network identifiers.
