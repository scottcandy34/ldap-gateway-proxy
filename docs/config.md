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
    mode: plain                     # plain | ldaps | starttls; omit to match the listener
```

`plain` is plaintext LDAP. The proxy terminates the client TLS and does not ask the directory for StartTLS or a certificate. `ldaps` and `starttls` are the encrypted backends. A `plain` route always terminates TLS, so it needs `tls.cert` and `tls.key` (the certificate clients see). `ca` and `rejectUnauthorized` are only used for `ldaps` and `starttls` backends.

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

## Firewall, cache, and bind maps

These are the parts borrowed from [kanidm/ldap-proxy](https://github.com/kanidm/ldap-proxy). They only run on a route that terminates TLS. A route terminates TLS when it has a `binds` map, or when `intercept: true` is set. Other routes stay a byte-for-byte SNI splice and do not see binds or searches.

```yaml
firewall:
  allowAllBinds: false       # false: only DNs listed in binds may bind
  maxIncomingBytes: 8388608  # largest client LDAP message
  maxBackendBytes: 8388608   # largest backend LDAP message
  cache:
    maxBytes: 134217728      # 0 turns the cache off
    ttl: 1800s

routes:
  - name: main
    host: ldap.example.com
    backend: "10.0.0.90:636"
    mode: ldaps
    tls:
      cert: /config/certs/ldap.example.com.pem   # presented to the client
      key: /config/certs/ldap.example.com.key
      ca: /config/certs/backend-ca.pem           # optional, verifies the backend
      rejectUnauthorized: true
    binds:
      "":                                        # anonymous
        mapToDn: "uid=reader,dc=example,dc=com"
        mapToSecret: "replace-me"
        allowedQueries:
          - ["dc=example,dc=com", "subtree", "(objectClass=*)"]
      "cn=admin,dc=example,dc=com": {}           # every search is allowed
```

| Behavior | What happens |
|---|---|
| Bind DN not listed, `allowAllBinds: false` | operations error `unable to bind`. The backend is not contacted. |
| `allowedQueries` omitted | that DN may run any search |
| `allowedQueries` set | the base DN, scope (`base`, `one`, `subtree`), and filter must match exactly. Anything else returns a successful search with no entries. |
| `mapToDn` / `mapToSecret` | the backend bind uses those credentials. The client still sees its own DN, including from Who Am I. |
| Search cache | successful searches are remembered per bind DN, base, scope, and filter. A second identical search does not hit OpenLDAP. Controls are never cached. |
| Who Am I | answered locally (`1.3.6.1.4.1.4203.1.11.3`). |
| Add, modify, delete, compare, rename | forwarded after a successful bind. They are not filtered. |
| SASL binds | rejected. Simple binds only. |

Bind DNs are compared case-insensitively, ignoring spaces around `=` and `,`. Filters are compared in a canonical form, so `(objectClass=*)` and `(objectclass=*)` are the same rule.

The certificate in `tls.cert` is the one the client validates. It has to match the hostname the client used. `tls.ca` is only for checking the OpenLDAP server.

[npm-cert-share](https://github.com/scottcandy34/npm-cert-share) writes one folder per domain from Nginx Proxy Manager. Mount that directory at `/certs` and set `cert: /certs/ldap.example.com/fullchain.pem` and `key: /certs/ldap.example.com/privkey.pem`. A wildcard name is the folder `_.example.com`. This is only for a route that terminates TLS (`mode: plain`, `binds`, or `intercept: true`). A splice route never reads these files. The process reads them at startup, so recreate the container after a renewal. pg-gateway-proxy is different: it always terminates, and its certificate list lives under a top-level `tls` block rather than on the route.

