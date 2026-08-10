# XHTTP (Umbrella variant)

XHTTP is the most advanced stealth protocol in the Umbrella suite. It encapsulates SOCKS5 traffic within HTTP/2 or HTTP/3 streams, mimicking modern web applications (like API calls or real-time streams) while using a sophisticated pre-authentication mechanism to hide the server from scanners.

## Configuration

To activate this mode, use `protocol: xhttp` in the configuration files.

### Server (config.yaml)

```yaml
protocol: "xhttp"
port: "443"
dest: "samsung.com:443" # Donor site for certificate and fallback

xhttp:
  auth-key: "..."      # HMAC key for authentication (hex, 32 bytes)
  path: "/web/v1/api"  # Secret path for tunnel requests
```

### Client (config.yaml)

```yaml
protocol: "xhttp"
server: "your_vps_ip:443"
sni: "samsung.com"
listen: "0.0.0.0:1080"

xhttp:
  auth-key: "..."      # Must match the server
  path: "/web/v1/api"  # Must match the server
  mode: "stream-one"   # Modes: stream-one, stream-up, packet-up
  quic: true           # Use H3 transport
```

## Technical Features

### 1. Silent IP Activation (The "Knock")

Umbrella XHTTP uses a unique "Silent Activation" mechanism. The server acts as a "Black Hole" or a transparent proxy to a donor site ( `dest` ) for any IP not in its whitelist.

* **The Mechanism:** Before sending any HTTP requests, the client performs a "Knock" during the handshake:
    - **H2 (TCP):** The client (using `uTLS` with a Chrome fingerprint) embeds a magic 32-byte `SessionID` in the TLS ClientHello.
    - **H3 (UDP):** The client embeds a magic 20-byte `Source Connection ID` in the QUIC Initial packet.
* **The Payload:** The magic field contains `[Random:5][XORed Time:3][HMAC Signature]`. The time is verified within a ±2.5-minute window to prevent replay attacks.
* **The Result:** If the "Knock" is valid, the server whitelists the client's IP. All subsequent connections from this IP use standard handshakes and headers without any signatures, ensuring maximum stealth.

### 2. Multi-Layer Padding

To break statistical traffic analysis (DPI), XHTTP applies padding at two levels:

* **Header Padding:** Every HTTP request and response includes an `X-Padding` header with a random hex string (32–512 characters), masking the exact size of the L7 headers.
* **Payload Padding:** All data is wrapped in frames: `[2: DataLen][2: PaddingLen][Data][Random Noise]`. Each frame includes 32–512 bytes of random noise, making packet lengths unpredictable.
* **L7 Noise:** In `stream-up` mode, the server periodically sends dummy 'X' characters in the POST response body to keep the connection alive and further obfuscate the traffic pattern.

### 3. Transport Modes

* **stream-one:** Uses a single persistent `POST` request for both uploading and downloading data.
* **stream-up:** Uses a `GET` request for the downlink and a separate persistent `POST` for the uplink, linked by a `X-Session-ID`.
* **packet-up:** Uses a `GET` for the downlink and multiple short-lived `POST` requests for the uplink. Each packet has a `X-Seq` header to ensure correct reassembly. This mode mimics erratic API-like behavior.

### 4. Advanced Masquerading

* **Transparent Fallback:** If an unauthorized IP or a scanner accesses the server, the `ipFilterListener` (TCP) or `quicFrontend` (UDP) transparently proxies the traffic to the `dest` (donor site).
* **HTTP Camouflage:** The server responds with `404 Not Found` if the secret path is incorrect and `403 Forbidden` if the `Umbrella-Client` header is missing, even for whitelisted IPs.
* **In-Memory Certs:** The server generates self-signed certificates on-the-fly that match the donor site's SNI, avoiding the need for complex file-based management.

## Advantages

* **Anti-Active Probing:** Scanners only see the donor site. There is no way to trigger a "proxy-like" response without knowing the `auth-key` and the magic handshake format.
* **No Fingerprints:** By using `uTLS` (Chrome fingerprint) and standard H2/H3 ALPNs, the traffic is indistinguishable from a regular browser.
* **Resilience:** The protocol handles both TCP and UDP, allowing it to bypass environments where one of them is throttled or blocked.
