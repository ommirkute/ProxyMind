# Capture modes: SOCKS5, transparent mode and upstream chains

ProxyMind can take traffic in three ways besides a browser's HTTP proxy setting, and can send what it forwards through
other proxies, chosen per host.

| You have | Use |
| --- | --- |
| A tool or app that speaks SOCKS5 (curl, a browser, an Android SOCKS app) | a **SOCKS5 listener** |
| A device or program that cannot be given proxy settings (Linux traffic you can redirect with iptables or nftables) | a **transparent listener** (Linux) |
| A target that is only reachable through another proxy (a corporate proxy, Tor, a jump host) | **upstream rules** |

All three are set in the web UI (Setup, "3. Proxy listeners", and Settings, Network), through the API
(`PUT /api/v1/proxy/listeners`, `PUT /api/v1/network`) or with `proxymind network set`. Web traffic that arrives by any
of them is recorded, rewritten, held and hooked exactly like traffic from the HTTP proxy listener.

## SOCKS5 listener

Add a listener on Setup, "3. Proxy listeners": choose type **SOCKS5**, an address (`127.0.0.1:1080`, or `0.0.0.0:1080`
for other machines), and optionally a username and password. Or in the API:

```json
{"listeners": [{"bind": "127.0.0.1:1080", "kind": "socks5", "username": "scout", "password": "s3cret"}]}
```

What it speaks (RFC 1928, login per RFC 1929):

- `CONNECT` with IPv4, IPv6 and domain-name addresses. `BIND` and `UDP ASSOCIATE` are refused with reply code 7
  (command not supported), unknown address types with code 8. UDP (DNS over SOCKS, QUIC) is not carried.
- No login, or username and password when you set them. A client that cannot log in gets "no acceptable method"; a
  wrong login is refused. Usernames and passwords are at most 255 bytes (the protocol's limit). Passwords are stored in
  the project like other secrets, shown as `********` and never logged. There is no lockout: do not expose a SOCKS5
  listener to networks you do not trust.
- The client has 10 seconds to finish the handshake.

After the handshake the connection is treated like a `CONNECT` tunnel to `host:port`:

- **TLS** is intercepted with ProxyMind's CA (HTTP/1.1 and HTTP/2), **plain HTTP** is read and recorded (WebSockets
  too), hosts on the TLS pass-through list are tunnelled untouched, and `http://proxymind.setup/` shows the setup page.
  Match-and-replace rules, plugin hooks and the intercept queue apply.
- A client that resolves names itself (curl `--socks5`, not `--socks5-hostname`) sends an IP address. ProxyMind still
  names the target by the TLS server name or the Host header, and connects to that IP address.
- **Other protocols** (SSH, databases, mail, anything that is not HTTP or TLS) are relayed byte for byte and
  **recorded as raw streams** (see below). A protocol where the server speaks
  first works too: after half a second of silence ProxyMind connects to the target, and if the server speaks first the
  stream is relayed. A client that stays silent and then speaks first (a browser's idle pre-connection) is still read as
  HTTP or TLS.
- A protocol that runs inside TLS but is not HTTP (IMAPS, MQTT over TLS) is intercepted with ProxyMind's CA and
  recorded as a TLS raw stream (see below). Put its host on the TLS pass-through list (Network) to relay it untouched
  and unrecorded, for example when the client pins the certificate.

### Client examples

```bash
# curl: --socks5-hostname lets ProxyMind see the name (socks5h); --socks5 resolves it locally
curl --socks5-hostname 127.0.0.1:1080 -o ca.pem http://proxymind.setup/ca.pem     # fetch the CA (setup page)
curl --socks5-hostname 127.0.0.1:1080 --cacert ca.pem https://shop.test/
curl --socks5-hostname 127.0.0.1:1080 --proxy-user scout:s3cret http://shop.test/  # with a login

# Chromium / Chrome (resolves names remotely; it cannot send a SOCKS login, so use a listener without one);
# Firefox: Settings, Network, Manual proxy, SOCKS v5 (it can log in), "Proxy DNS when using SOCKS v5"
chromium --proxy-server="socks5://127.0.0.1:1080" --user-data-dir=/tmp/pm-profile

# Any program, with proxychains (set `socks5 127.0.0.1 1080` in proxychains.conf)
proxychains4 -q git ls-remote https://example.com/repo.git
```

**Android apps.** Install an app that forwards the phone's traffic to a SOCKS5 server (for example Postern or Drony),
point it at `<this computer's address>:1080` (use a listener on `0.0.0.0` and the address from the Setup page's phone
section), and install ProxyMind's CA as in [mobile.md](mobile.md). Apps that ignore user certificates still cannot be
intercepted; add their hosts to TLS pass-through if they break.

## Transparent mode (Linux)

A **transparent** listener takes connections the operating system redirected to it, from clients that have no proxy
settings, and sends each one where the client was really going. Turn it on for an HTTP listener
(`{"bind": "0.0.0.0:8081", "transparent": true}`, or the "transparent" box in the UI; the box is greyed out on systems
that cannot do it).

How it works:

- ProxyMind asks Linux for the original destination of each connection: `SO_ORIGINAL_DST` for iptables and nftables
  `REDIRECT`, or the connection's own local address for `TPROXY`. It uses the `nix` crate (0.32, MIT) for that, so
  ProxyMind itself contains no `unsafe` code.
- **TLS** is intercepted for the server name (SNI) in the ClientHello, with a certificate from ProxyMind's CA; without
  an SNI the original address names the host. **Plain HTTP** is named by its Host header (the original address if there
  is none), recorded under that name, with the original port.
- ProxyMind **connects to the original address**, not to what the name resolves to now, and still refuses to connect to
  itself. The upstream rules are applied by name as for any traffic.
- A request that names its own target (a client that does speak proxy protocol: absolute-form or `CONNECT`) goes to
  the target it names. Connections that were not redirected (a client connecting straight to the listener) behave like
  ordinary "invisible" clients, routed by Host header or SNI.
- Other protocols are relayed unchanged and recorded as raw streams, as with SOCKS5.

Not supported yet: **macOS** (`pf` needs `DIOCNATLOOK`, and no safe crate exposes it) and **Windows**. On those systems
use a proxy or SOCKS5 listener, or run ProxyMind on a Linux gateway. QUIC (HTTP/3) is UDP and is not handled: block UDP
port 443 on the redirected path so clients fall back to HTTPS over TCP.

### Redirecting traffic

> **Warning: keep ProxyMind's own outbound traffic out of the redirect.** If the rule also catches the connections
> ProxyMind makes to the target, they loop back into the listener. ProxyMind refuses a connection that would reach its
> own listener, but a redirect that catches its outbound traffic will still break everything. Run ProxyMind as its own
> user and exclude that user (`-m owner ! --uid-owner`, `meta skuid`), or exclude by interface, destination or mark.
> Only redirect traffic you are authorized to test.

On the machine that runs ProxyMind (a listener on `127.0.0.1:8081`, ProxyMind running as the user `proxymind`):

```bash
# iptables
sudo iptables -t nat -N PROXYMIND
sudo iptables -t nat -A PROXYMIND -d 127.0.0.0/8 -j RETURN
sudo iptables -t nat -A PROXYMIND -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 8081
sudo iptables -t nat -A OUTPUT -m owner ! --uid-owner proxymind -j PROXYMIND

# remove it again
sudo iptables -t nat -D OUTPUT -m owner ! --uid-owner proxymind -j PROXYMIND
sudo iptables -t nat -F PROXYMIND && sudo iptables -t nat -X PROXYMIND
```

```bash
# nftables (the same, in one file: sudo nft -f proxymind.nft; remove with: sudo nft delete table ip proxymind)
table ip proxymind {
  chain out {
    type nat hook output priority -100;
    meta skuid "proxymind" return
    ip daddr 127.0.0.0/8 return
    tcp dport { 80, 443 } redirect to :8081
  }
}
```

On a gateway that forwards a LAN's traffic (a Linux box acting as the Wi-Fi access point or router; the listener on
`0.0.0.0:8081`, `wlan0` the device-facing interface). The gateway's own traffic is not caught by `PREROUTING`, so there is
no loop:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A PREROUTING -i wlan0 -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 8081
sudo iptables -t nat -A PREROUTING -i wlan0 -p udp --dport 443 -j REJECT        # push QUIC back to TCP
# nftables:  table ip proxymind { chain pre { type nat hook prerouting priority -100;
#              iifname "wlan0" tcp dport { 80, 443 } redirect to :8081 } }
```

IPv6 needs the same with `ip6tables` or an `ip6` table. `TPROXY` keeps the destination address without NAT (needs
`CAP_NET_ADMIN` for the listener's `IP_TRANSPARENT` option, which ProxyMind sets when it can):

```bash
sudo iptables -t mangle -A PREROUTING -i wlan0 -p tcp -m multiport --dports 80,443 \
     -j TPROXY --on-port 8081 --tproxy-mark 0x1/0x1
sudo ip rule add fwmark 1 lookup 100 && sudo ip route add local 0.0.0.0/0 dev lo table 100
```

To check it: from the redirected client run `curl -v http://example.test/` (or open any site) and look for the exchange
in History. The Host or SNI name is recorded; the connection went to the address the client dialled.

The automated tests use a fake original-destination provider. One more test redirects real connections with iptables
and needs root: `PROXYMIND_TEST_TRANSPARENT=1 cargo test -p pm-proxy --test transparent_mode -- real_redirect`.

### HTTP/3 (QUIC) and interception

A browser that uses ProxyMind as its HTTP or SOCKS5 proxy never uses HTTP/3: CONNECT and SOCKS5 carry TCP, so it
falls back to HTTP/2 or HTTP/1.1. A client that is **redirected** (transparent mode, a gateway) is different. When a
server it talks to through ProxyMind says `Alt-Svc: h3=":443"`, the client may open a QUIC connection (UDP/443) to the
target next time, and if UDP reaches the target that traffic goes around ProxyMind. ProxyMind has no QUIC listener yet
(ADR-0021), so keep UDP/443 from reaching the target:

- **Block it** at the same place that redirects TCP, so the client falls back to TCP at once (this is what the gateway
  example above does with `-p udp --dport 443 -j REJECT`). On the machine that runs ProxyMind itself, for a client that is
  another user or container: `sudo iptables -A OUTPUT -m owner ! --uid-owner proxymind -p udp --dport 443 -j REJECT`
  (remove it with `-D`). A client that already holds an `Alt-Svc` alternative keeps trying QUIC until it expires
  (`ma`, up to a day or more) and then falls back, so block UDP first.
- **Remove the advertisement** with the **Remove HTTP/3 advertisements (Alt-Svc h3)** preset (Proxy, Rules, "Add a
  preset…"). It drops only the `h3` alternatives from `Alt-Svc` headers of in-scope responses; other alternatives stay.
  It is off until you add it (nothing changes traffic by itself), and History keeps the server's original response
  under **Delivered response**. It cannot reach a cached alternative or an HTTPS DNS record, so it complements the block.

To *test* an HTTP/3 target, write `HTTP/3` in the request line in Replay (or pick it in the Protocol selector). That
needs an `https` target and a direct route: a host that an upstream rule sends through an HTTP or SOCKS5 proxy is
refused for HTTP/3, because those proxies carry TCP only.

## Raw TCP and TLS streams

Traffic that is not HTTP is recorded as a **stream**, whichever way it reached ProxyMind (a CONNECT tunnel from an HTTP
listener, SOCKS5 or a transparent listener). Open **Proxy, Streams** in the web UI, or use `GET /api/v1/streams`.

**How a stream is recognised.** After the tunnel opens, ProxyMind waits for the client's first bytes. A TLS handshake is
intercepted, an HTTP/1.x request line is read as HTTP, anything else is a raw stream. If the client says nothing for
half a second, ProxyMind connects to the target and, when the target speaks first (SMTP, SSH, IMAP, databases), relays
the stream from there. Inside intercepted TLS the same idea applies to the decrypted bytes: if the client offered ALPN
values other than `h2` and `http/1.1`, they are passed to the target (it picks one, ProxyMind offers that one back) and
the stream is raw; with no such ALPN, the first decrypted bytes decide, and a client that stays silent for half a second
is checked for a server that speaks first. HTTP, HTTP/2 and WebSockets behave exactly as before. The bytes on the wire
are never changed: the recorder gets a copy of each chunk after it was passed on.

**What is stored.** One row per connection (target host and port, client address, start and end time, bytes each way,
plain or TLS with the server name and ALPN, how it ended: `client_closed`, `server_closed` or `error`) and its chunks in
order, each as read from one side, with direction, time and length. Chunk bytes are stored compressed like other
bodies. At most 16 MB and 50 000 chunks are kept per stream; past that the bytes are relayed and counted, and the stream
is marked cut. For TLS streams the chunks are the decrypted bytes.

**What is recorded.** The recording settings apply as for HTTP: with "record only in-scope traffic", a stream is kept when
its target is in scope (a plain stream is matched as `http://host:port/`, a TLS stream as `https://host:port/`, so a scope
entry needs the port, or `:*`); with "record only these devices", when the client is one of them. Every stream is relayed
whatever the scope, as HTTP is. TLS pass-through tunnels are not recorded.

**Replay.** `POST /api/v1/streams/{id}/replay` (or "Replay stream…" on the page, or the MCP tool `stream_replay`) opens a
new connection to the same target (TLS with the same server name and ALPN when the original was TLS), sends the client's
chunks in order (replace them with `chunks` as base64 or `text_chunks`), waits `delay_ms` between chunks, reads the
server's answer until it is quiet for `read_ms` (or `max_response_bytes`, or 60 s) and records the result as a new
stream. A server that spoke first is waited for before the first chunk. Replay goes through the policy gate like a request
replay: the target must be in scope, only connecting and listening is active-safe, sending bytes is active-intrusive
(more when they look destructive), agents need approval (the approval covers exactly these chunks), and it is audited.

## Upstream rules and chains

`upstream_rules` in the network settings is an ordered list. For every outgoing connection ProxyMind makes (browser
traffic through any listener, Replay, the scanner, the Fuzzer, crawls, proofs and agents), the **first rule whose
`match` covers the target host** decides how to reach it. A host that matches no rule is reached directly.

```yaml
upstream_rules:
  - match: [localhost, 127.0.0.1, "*.internal.example", 10.0.0.0/8]
    via: direct
  - match: ["*.onion"]
    via: socks5://127.0.0.1:9050        # Tor
    remote_dns: true
  - match: ["*.corp.example"]
    via: http://proxy.corp.example:3128
    username: svc-pentest
    password: "…"                       # stored in the project, shown as ********, never logged
  - via: socks5://jump.example:1080     # no match: every other host (must be the last rule)
```

| Field | Meaning |
| --- | --- |
| `match` | Host names (`api.example.com` exact; `*.example.com` also covers `example.com`; `*` and `?` work inside names, `*` is everything) and CIDR ranges (`10.0.0.0/8`, `fd00::/8`). A range covers targets given as an IP address, not names that resolve into it. Empty: every host (last rule only). |
| `via` | `direct`, `http://host:port` (CONNECT for HTTPS) or `socks5://host:port`. No login in the URL. |
| `username`, `password` | Optional login for the proxy (Basic or SOCKS5 username/password). |
| `remote_dns` | Let the proxy resolve names (`socks5h`; CONNECT by name). Off by default. |

Apply with `proxymind network set rules.yaml`, the Network page or `PUT /api/v1/network`. Running proxies pick the change
up within seconds. The older single `upstream` form (with `bypass`) still loads and becomes the equivalent rules. On the
Network page, "Which rule matches?" (and `POST /api/v1/network/upstream/resolve {"host": "a.corp.example"}`, which also
accepts a draft in `rules`) shows which rule a host would use without sending anything.

**DNS rebinding protection.** ProxyMind checks the addresses a name resolves to against the denied networks before it
connects. To keep that check meaningful, with `direct` and with proxies that do not have `remote_dns`, ProxyMind
connects (or asks the proxy to connect) to **the address it checked**, not to the name: SOCKS5 gets the IP address, an
HTTP proxy gets `CONNECT <ip>:<port>`, and TLS inside still uses the name. With `remote_dns: true` the proxy resolves the
name itself, so ProxyMind cannot check the address; use it only for proxies that need it (Tor's `.onion`, proxies that
only allow named hosts). Plain `http://` requests through an HTTP proxy always go by name, because the proxy takes the
host from the request.

Chains of proxies: point a rule at another tool's proxy listener (an HTTP or SOCKS5 proxy that itself forwards further),
for example a second inspection tool or a VPN client's SOCKS port. Hosts that must not take that detour get a `direct`
rule above it.
