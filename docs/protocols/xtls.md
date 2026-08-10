# XTLS Reality + Vision (Umbrella variant)

XTLS is an evolution of the VLESS protocol, offering what is currently the best masquerading as standard HTTPS traffic (TCP).

This implementation is a SOCKS5 proxy over TCP with a [Reality](https://github.com/XTLS/REALITY) handshake and yamux multiplexing.

## Configuration

To activate this mode, use `protocol: xtls` in the configuration files.

### Server (config.yaml)

```yaml
protocol: "xtls"
port: "443"             # Listening port
dest: "samsung.com:443" # Donor site for Reality (where to redirect "unauthorized" traffic)

xtls:
  private-key: "..."    # x25519 private key (base64, 32 bytes)
  short-id: "..."       # Reality Short ID (hex, up to 16 characters)
  server-names: "..."   # Allowed SNIs separated by commas (if empty, taken from dest)
```

### Client (config.yaml)

```yaml
protocol: "xtls"
server: "your_vps_ip:443"
sni: "samsung.com"      # Must match one of the server's SNIs
listen: "0.0.0.0:1080"             # UDP ASSOCIATE support
decoy-traffic: true     # Global masking (external HEAD requests)

xtls:
  public-key: "..."     # Server's public key (base64)
  short-id: "..."       # Server's Short ID (hex)
```

## Masking Technologies

### 1. Reality (Handshake Stealth)

Reality technology allows your server to "steal the identity" of any popular foreign website (e.g., `samsung.com` or `microsoft.com` ).
* **How it works:** When someone tries to access your server via port 443, it proxies the TLS handshake from the actual chosen site. 
* **Result:** The ISP sees a valid certificate and legitimate TLS fingerprints. Your Umbrella server does not reveal itself until the client sends a secret key in the `SessionID`field.

---

Authentication is built into the TLS ClientHello rather than application data:

1. The client executes `BuildHandshakeState()` — a ClientHello is built in memory without being sent.
2. The client extracts an ephemeral x25519 key from the KeyShare and calculates `sharedSecret = X25519(clientEphPriv, serverStaticPub)`.
3. `authKey = HKDF-SHA256(ikm=sharedSecret, salt=random[:20], info="REALITY")`.
4. Plaintext (16 байт) `[ver=0 | zeros | unix_time(4) | shortId(8)]` is encrypted with `AES-256-GCM(authKey, nonce=random[20:32])`, and the result (32 bytes) is written into the `SessionId`field.
5. `MarshalClientHello()` → `Handshake()`.

The server ( `xtls/reality` ) performs the same steps independently: if the `SessionId` decryption is valid, the connection is authenticated. Otherwise, it acts as a transparent proxy to `dest` (e.g., github.com). The server never shows its own certificate.

### 2. Umbrella Vision

 **Task.** 

When an application opens an HTTPS connection through a tunnel, its TLS ClientHello and the entire inner handshake pass in encrypted form through the outer Reality TLS. DPI cannot read the content, but it sees the **statistical pattern of the sizes of the first TLS records** (inner ClientHello ≈ 300–500 bytes, followed by a characteristic sequence of records) — this is a detectable sign of TLS-in-TLS.

In general, all application packets can have statistical length signatures.

 **Solution.** 

All connections are wrapped in a Vision stream, and all packets into Vision frames
  + A fake TLS header is generated.
  + Real TLS headers and application data are packed into the payload.
  + **Random Padding:** Between 0 and 255 bytes of random "junk" are added to each message.
  + This makes the length of every packet unique and unpredictable, breaking any statistical packet length signatures.
  + Thanks to these solutions, the tunnel correctly passes non-standard protocols on port 443 (e.g., Telegram's MTProto) while continuing to mask TLS headers and main data using Random Padding. No additional configuration is required. Everything happens transparently.

### 3. Multiplexing (yamux)

All SOCKS5 streams travel within a single TLS connection via `yamux` . This prevents an avalanche of individual TLS handshakes during multi-threaded downloads

### 4. Session Rotation

The client rotates the TLS connection randomly ( `crypto/rand` ). Active `yamux` streams wait for their natural termination. The next SOCKS5 request transparently opens a new connection with a fresh handshake.

## Advantages and Disadvantages compared to Xray (VLESS+REALITY+XTLS)

The original XTLS aims for maximum performance (removing the wrapper) and strict routing, sacrificing flexibility. Umbrella takes a different approach, focusing on zero-configuration and reliability.

 **Advantages of Umbrella:** 

1. **Universality (Breaks nothing):** The client applies Vision to all traffic while correctly wrapping and processing data streams of non-standard protocols on port 443 (e.g., Telegram's MTProto) without disabling masking for them. An Xray client with `xtls-rprx-vision` would require complex routing rules; otherwise, non-TLS traffic on the configured port would be dropped to protect against active probing.
2. **Zero-config:** Neither the administrator nor the user needs to worry about `flow` directives. The protocol adapts itself for every new stream on the fly.
3. **Multiplexing Security:** Hundreds of internal SOCKS5 requests pass through a single external TCP tunnel (Reality) within `yamux`. DPI cannot determine the number of open connections. В In the original Xray, each spliced stream generates a separate external connection.
4. **Random Padding:** Continues to break statistical packet length signatures for all traffic, not just for the TLS ClientHello.

 **Disadvantages of Umbrella:** 

1. **CPU Overhead (Double Encryption):** Xray XTLS performs "splicing" — it disables the VLESS layer at the Application Data stage and sends internal traffic out "as is" (since it is already encrypted by the internal HTTPS). Due to `yamux`, Umbrella is forced to always encrypt traffic with a second layer (the outer Reality server). This creates a small (1-2%) extra load on the VPS/client CPU, which might be noticeable at gigabit router speeds but is negligible in daily use.
