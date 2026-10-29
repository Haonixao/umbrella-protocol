# XHTTP (Umbrella variant)

XHTTP is the most advanced stealth protocol in the Umbrella suite. It encapsulates SOCKS5 traffic within HTTP/2 or HTTP/3 streams, mimicking modern web applications (like API calls or real-time streams). Combined with the Umbrella Control Plane, it ensures 100% vanilla handshakes while providing robust traffic obfuscation.

## Configuration

To activate this mode, use `protocol: xhttp` in the configuration files.

### Server (config.yaml)

```yaml
protocol: "xhttp"
port: "443"
dest: "samsung.com:443" # Donor site for certificate and fallback

xhttp:
  path: "/web/v1/api"  # Secret path for tunnel requests
```

### Client (config.yaml)

**Note:** The client receives the actual connection configuration (server IP, port, SNI, path) automatically from the Control Plane (see [Activation](../activation.md)). Manual configuration is only required for initial setup or debugging.

```yaml
protocol: "xhttp"
server: "your_vps_ip:443"
sni: "samsung.com"
listen: "0.0.0.0:1080"

xhttp:
  path: "/web/v1/api"  # Must match the server
  mode: "stream-one"   # Modes: stream-one, stream-up, packet-up
  quic: true           # Use H3 transport
```

## How It Works

### 1. Control Plane Activation

Before any HTTP traffic exchange, the client activates its IP address through an out-of-band channel (e.g., Gmail IMAP). The server publishes the current `ClientConfig` to a draft message. The client sends an activation request with its IP and pre-shared key. Upon validation, the server adds the client's IP to a fast-lookup whitelist.

See [Activation via Alternative Channel](../activation.md) for details.

### 2. 100% Vanilla Handshakes

Unlike previous stealth mechanisms, Umbrella XHTTP **does not** embed any custom signatures, time-drift masks, or HMACs into the TLS `SessionID` or QUIC `Source Connection ID`.
* **Standard H2/H3:** The client performs a completely standard TLS or QUIC handshake. There are no "magic" bytes or custom fingerprints required to open the connection.
* **Traffic Analysis Resistance:** By relying on IP whitelisting rather than handshake cryptography, the protocol eliminates the risk of detection via JA3/JA4 fingerprinting or SCID entropy analysis.

### 3. Multi-Layer Padding

To break statistical traffic analysis (DPI) during the actual data transfer, XHTTP applies padding at two levels:

* **Header Padding:** Every HTTP request and response includes an `X-Padding` header with a random hex string (32–512 characters), masking the exact size of the L7 headers.
* **Payload Padding:** All data is wrapped in frames: `[2: DataLen][2: PaddingLen][Data][Random Noise]`. Each frame includes 32–512 bytes of random noise, making packet lengths unpredictable.
* **L7 Noise:** In `stream-up` mode, the server periodically sends dummy 'X' characters in the POST response body to keep the connection alive and further obfuscate the traffic pattern.

### 4. Transport Modes

* **stream-one:** Uses a single persistent `POST` request for both uploading and downloading data.
* **stream-up:** Uses a `GET` request for the downlink and a separate persistent `POST` for the uplink, linked by a `X-Session-ID`.
* **packet-up:** Uses a `GET` for the downlink and multiple short-lived `POST` requests for the uplink. Each packet has a `X-Seq` header to ensure correct reassembly. This mode mimics erratic API-like behavior.

### 5. Advanced Masquerading

* **Reality-Like Fallback:** If an unauthorized IP or a scanner accesses the server, the `ipFilterListener` (TCP) or `quicFrontend` (UDP) transparently proxies the traffic to the `dest` (donor site). The server never returns cryptographic errors or drops connections silently.
* **HTTP Camouflage:** The server responds with `404 Not Found` if the secret path is incorrect and `403 Forbidden` if the `Umbrella-Client` header is missing, even for whitelisted IPs.
* **In-Memory Certs:** The server generates self-signed certificates on-the-fly that match the donor site's SNI, avoiding the need for complex file-based management.

## Advantages

* **Anti-Active Probing:** Scanners only see the donor site. There is no way to trigger a "proxy-like" response without prior IP activation via the Control Plane.
* **Zero-Touch Provisioning:** Clients automatically fetch the latest configuration (SNI, path, transport) from the Control Plane.
* **No Fingerprints:** By using standard H2/H3 transports and vanilla handshakes, the traffic is indistinguishable from a regular browser or API client.
* **Resilience:** The protocol handles both TCP and UDP, allowing it to bypass environments where one of them is throttled or blocked.
