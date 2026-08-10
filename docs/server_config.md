# Umbrella Server Configuration Parameters Reference

The Umbrella server is managed via the `config.yaml` file, which is automatically generated on the first run with default settings for the XTLS protocol. Below is a detailed description of all available parameters.

---

### protocol:

```yaml
protocol: "xtls"
```

Defines the active obfuscation protocol on the server.
* **Allowed values** : `"xtls"`,   `"hysteria"`,   `"torrent"`,   `"xhttp"`.
* **Default** : `"xtls"`.

### port:

```yaml
port: "443" # or "50000-50100" for torrent
```

The port the server will listen on.
* **For Torrent** : You can specify a port range (e.g.,   `"50000-50100"`) if Port Hopping is enabled.
* **Default** : `"443"`.

### dest:

```yaml
dest: "samsung.com:443"
```

Fallback address. All incoming connections that fail authorization (without a valid Connection ID, Short ID, or PeerID) will be transparently redirected to this address. This simulates the behavior of a real service.
* **Default** : `"samsung.com:443"`.

### debug:

```yaml
debug: false
```

Enables extended logging of all events and errors to the server console.
* **Default** : `false`.

---

## XHTTP Section (HTTP/2 & HTTP/3 Tunnel)

### xhttp.auth-key:

```yaml
xhttp:
  auth-key: "hex_string_32_bytes"
```

Secret key for HMAC authentication between client and server. If the client provides an invalid authentication token, the server redirects the request to the `dest` address.

### xhttp.path:

```yaml
xhttp:
  path: "/api/v1/update"
```

The HTTP path used for the tunnel. Requests to other paths will be handled according to the `dest` fallback logic.

---

## XTLS Section (Reality + Vision)

### xtls.private-key:

```yaml
xtls:
  private-key: "YOUR_PRIVATE_KEY"
```

The x25519 private key for Reality technology. Generated automatically on the first run.

### xtls.short-id:

```yaml
xtls:
  short-id: "hex_string"
```

The allowed Short ID. Must match the client settings. Generated automatically on the first run.

### xtls.server-names:

```yaml
xtls:
  server-names: "samsung.com,google.com"
```

A list of domains (SNI) for which the server will issue Reality certificates. By default, it is taken from the `dest` parameter.

---

## Hysteria Section (Hysteria 2)

### hysteria.quic-port:

```yaml
hysteria:
  quic-port: "8443"
```

The internal UDP port where the Hysteria core operates. The external port is defined by the global `port` parameter.
* **Default** : `"8443"`.

### hysteria.auth-key:

```yaml
hysteria:
  auth-key: "hex_string_32_bytes"
```

The key for HMAC Connection ID verification. If a client sends an invalid ID, the server redirects the traffic to `dest` .

### hysteria.auth-password:

```yaml
hysteria:
  auth-password: "your_password"
```

The password for standard Hysteria 2 protocol authentication.

---

## Torrent Section (Torrent Stealth)

### torrent.auth-key:

```yaml
torrent:
  auth-key: "hex_string_32_bytes"
```

The key for HMAC PeerID verification. Allows distinguishing "authorized" clients from random scanners or real torrent network participants.

### torrent.info-hash:

```yaml
torrent:
  info-hash: "40_hex_chars"
```

The info-hash of the torrent distribution. If left empty, the server will generate a random hash at startup.
* **Recommendation** : Specify a real hash (e.g., a Linux distribution) so the server appears as a legitimate peer for that distribution.
