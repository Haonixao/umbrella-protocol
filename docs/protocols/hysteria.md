# Hysteria 2 (Umbrella Variant)

Hysteria 2 is a high-performance protocol based on QUIC (UDP), optimized for operation in networks with high packet loss and unstable latency. The Umbrella variant enhances it with out-of-band activation and reality-like fallback.

## Configuration

To activate this mode, use `protocol: hysteria` in your configuration files.

### Server (config.yaml)

```yaml
protocol: "hysteria"
port: "443"             # Main port (masquerade)
dest: "samsung.com:443" # Fallback site for unactivated connections

hysteria:
  auth-password: "..." # Standard Hysteria password authentication
```

### Client (config.yaml)

**Note:** The client receives the actual connection configuration (server IP, port, SNI, auth-password) automatically from the Control Plane (see [Activation](../activation.md)). Manual configuration is only required for initial setup or debugging.

```yaml
protocol: "hysteria"
server: "your_vps_ip:443"
sni: "samsung.com"
listen: "0.0.0.0:1080"

hysteria:
  auth-password: "..." # Must match the server
```

## How It Works

### 1. Control Plane Activation

Before any data exchange, the client activates its IP address through an out-of-band channel (e.g., Gmail IMAP). The server publishes the current `ClientConfig` to a draft message. The client sends an activation request with its IP and pre-shared key. Upon validation, the server adds the client's IP to a fast-lookup whitelist.

See [Activation via Alternative Channel](../activation.md) for details.

### 2. 100% Vanilla QUIC Handshakes

Unlike previous iterations of stealth proxies, Umbrella Hysteria **does not** embed custom cryptographic signatures (such as HMAC) into the QUIC `Source Connection ID` (SCID) or any other handshake fields.
* **Standard QUIC:** The initial packets are indistinguishable from legitimate QUIC traffic.
* **No Custom Parsing:** The frontend wrapper no longer inspects or modifies QUIC Initial packets, eliminating the risk of detection via entropy analysis or custom fingerprinting.

### 3. Reality-Like Fallback

If an unactivated IP attempts to connect:
* The server does not drop the connection or return cryptographic errors.
* Instead, it acts as a transparent UDP proxy, forwarding the traffic directly to the configured `dest` (e.g., `samsung.com:443`).
* To an external observer or active probing scanner, the server behaves exactly like a legitimate service or an open UDP relay.

### 4. Standard Hysteria Core Processing

Once the client's IP is validated by the frontend whitelist, the traffic is seamlessly forwarded to the internal Hysteria backend (e.g., `127.0.0.1:8443`).
* Authentication is handled by the standard Hysteria `auth-password` mechanism.
* Advanced features like BBR congestion control (`bbr.ProfileAggressive`) operate natively without custom wrapper interference.

### 5. Custom Padding

* **Random Padding:** Between 0 and 255 bytes of random "junk" are added to each message by the Umbrella wrapper.
* This makes the length of every packet unique and unpredictable, breaking any statistical packet length signatures. This is a custom enhancement absent in the official Hysteria library.

### 6. Dynamic Rotation

The system automatically rotates UDP clients in the pool. While it no longer relies on unique cryptographic signatures in the Connection ID for initial authentication, it still generates new session parameters and rotates connections for each new session. This prevents long-term tracking of users via static network identifiers.

## Advantages

1. **Zero-Touch Provisioning**: Clients automatically fetch the latest configuration from the Control Plane. No manual updates required when server parameters change.
2. **Traffic Analysis Resistance**: 100% vanilla QUIC handshakes prevent detection via DPI, JA3/JA4 fingerprinting, or SCID entropy analysis.
3. **Plausible Deniability**: Unactivated connections are forwarded to a legitimate destination, making the server indistinguishable from a standard proxy or the target service itself.
4. **Agnostic Control Plane**: Can be adapted to any legitimate messaging service with an API (Gmail, Yandex Mail, Mail.ru, etc.).
