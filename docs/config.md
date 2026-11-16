# Config reference

The file is YAML. Unknown keys are rejected at startup. Paths below are inside the container. A missing file is replaced with [config.default.yml](../config.default.yml).

## listen

```yaml
listen:
  - bind: 0.0.0.0:636
    mode: ldaps       # ldaps | starttls
  - bind: 0.0.0.0:389
    mode: starttls
```

`ldaps` expects a TLS ClientHello as the first bytes. `starttls` expects an LDAP StartTLS extended operation (OID `1.3.6.1.4.1.1466.20037`), answers it, then reads the ClientHello.

The default, when `listen` is omitted, is both of the listeners above.

## Routing

```yaml
requireSni: true
blockIpSni: true
unmatched: reject     # or "10.0.0.9:636"
```

| Key | Default | Meaning |
|---|---|---|
| `requireSni` | `true` | Drop connections that send no server name. |
| `blockIpSni` | `true` | Drop a server name that is an IP address. |
| `unmatched` | `reject` | What to do when the name matches no route. `reject`, or one `host:port`. |

Host patterns, first match wins:

| Pattern | Matches |
|---|---|
| `ldap.example.com` | that name only, case-insensitive, trailing dot ignored |
| `*.ldap.example.com` | one label, captured as `$1` |
| `**.example.com` | the rest of the name, captured as `$1` |
| `*` | any name, captured as `$1` |

`$1`, `$2`, `${sni}`, and `${host}` are substituted into backend addresses.

## routes

```yaml
routes:
  - name: main
    host: ldap.example.com          # string or list
    backend: "10.0.0.90:636"        # host:port, a list, or a servers: name
    strategy: first                 # first | round-robin | random | least-connections
    mode: ldaps                     # ldaps | starttls; omit to match the listener
```

`backend` cannot mix `host:port` values with server names. Several addresses are tried in `strategy` order. A failed TCP connect moves to the next address.

## servers

```yaml
servers:
  replicas:
    addresses:
      - 10.0.0.91:636
      - 10.0.0.92:636
    strategy: round-robin
    mode: ldaps
```

A route then uses `backend: replicas`. A string value is shorthand for one address: `directory: "10.0.0.90:636"`.

## log, limits, timeouts, health

```yaml
log:
  level: info          # debug | info | warn | error
  format: text         # text | json

limits:
  maxConnections: 2000

timeouts:
  connect: 5s          # TCP connect to a backend
  handshake: 10s       # ClientHello or StartTLS
  idle: 0s             # 0 turns the idle timer off

health:
  enabled: true
  bind: 127.0.0.1:8081
```

Durations are `500ms`, `5s`, or `1m`. `GET /health` returns `{"ok":true,"connections":N,"routes":N}`.

## What the proxy does not do

It does not bind as a user, and it does not read the LDAP operations after the handshake. OpenLDAP still does authentication, access control, and certificates. The proxy only chooses the server from the hostname.
