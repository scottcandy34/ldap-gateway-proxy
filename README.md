# ldap-gateway-proxy

One public port for many OpenLDAP servers. The client connects to `ldap.example.com`. The proxy reads that name from TLS SNI and forwards the connection to the matching server. A raw IP, or any name you did not list, is dropped.

This is the LDAP version of [pg-gateway-proxy](https://github.com/scottcandy34/pg-gateway-proxy). With `mode: ldaps` or `mode: starttls` the proxy splices the TLS stream and the certificate stays on OpenLDAP. With `mode: plain` the proxy holds the certificate, terminates TLS, and talks ordinary LDAP to a directory that has no certificate of its own.

Port 389 is StartTLS. The proxy answers the StartTLS request, reads the same SNI name, then forwards the TLS stream. Port 636 is LDAPS and is forwarded as-is.

## Image

| | |
|---|---|
| Image | `ghcr.io/scottcandy34/ldap-gateway-proxy` |
| This release | `v0.2.1` |
| Also tagged | `0.2.1`, `v0.2`, `0.2`, `latest` |

```bash
docker pull ghcr.io/scottcandy34/ldap-gateway-proxy:v0.2.1
```

`latest` moves when a newer version is published. `v0.2.1` does not. Pin the version.

The image version is the `version` in [package.json](package.json). Major stays `0` until a breaking change. Bump it before a change you want published:

```bash
npm version patch    # v0.1.0 -> v0.1.1
npm version minor    # v0.1.0 -> v0.2.1
```

Commit the version bump and push `main`. The workflow builds that version and does not overwrite an older tag.

## Run

```bash
mkdir -p config
docker compose up -d
```

[docker-compose.yml](docker-compose.yml) already points at `ghcr.io/scottcandy34/ldap-gateway-proxy:v0.2.1`. The first start writes `config/config.yml` if the file is missing. Edit it and recreate the container. An empty `./config` mount is enough. Pulling a new image does not overwrite a config you have edited.

Or without compose:

```bash
docker run -d --name ldap-gateway \
  -p 389:389 -p 636:636 \
  -v "$PWD/config:/config" \
  ghcr.io/scottcandy34/ldap-gateway-proxy:v0.2.1
```

Health checks inside the container use `http://127.0.0.1:8081/health`. That port is not published.

## Config

```yaml
listen:
  - bind: 0.0.0.0:636
    mode: ldaps
  - bind: 0.0.0.0:389
    mode: starttls

requireSni: true
blockIpSni: true
unmatched: reject

routes:
  - name: main
    host: ldap.example.com
    backend: "10.0.0.90:636"
    mode: ldaps

  - name: tenant
    host: "*.ldap.example.com"
    backend: "$1.ldap.internal:636"
    mode: ldaps
```

`mode` is how the **backend** expects the connection:

| mode | Backend sees |
|---|---|
| `plain` | Plain LDAP, no TLS. The proxy presents the certificate and the directory does not need one. |
| `ldaps` | TLS immediately. Use this when slapd is listening on 636. |
| `starttls` | An LDAP StartTLS request, then TLS. Use this when slapd is listening on 389 and has its own certificate. |

If you omit `mode`, the backend is spoken to the same way the client connected. A client on 389 can still be forwarded to a backend on 636: set `mode: ldaps`.

`host` is an exact name, `*.example.com` (one label), `**.example.com`, or `*`. `$1` and `${sni}` are substituted into the backend address. First match wins.

Quoted `host:port` values are required. YAML will not accept a bare `10.0.0.90:636`.

Every route key is documented in [docs/config.md](docs/config.md).

## Clients

The host has to be the name, not the IP. The name is what gets routed, and it is the name on the OpenLDAP certificate.

```bash
ldapsearch -H ldaps://ldap.example.com -x -b dc=example,dc=com -D "cn=admin,dc=example,dc=com" -W
```

StartTLS on 389:

```bash
ldapsearch -H ldap://ldap.example.com -ZZ -x -b dc=example,dc=com
```

`LDAPTLS_REQCERT=demand` works when the certificate the proxy (or, for a splice route, the backend) presents is publicly trusted for that hostname.

## Firewall

A route with a `binds` map terminates TLS and applies the same kind of limits as [kanidm/ldap-proxy](https://github.com/kanidm/ldap-proxy): which DNs may bind, which searches each DN may run, an anonymous bind rewritten to a service account, an in-memory search cache, and a maximum LDAP message size. The full table is in [docs/config.md](docs/config.md).

```yaml
routes:
  - name: main
    host: ldap.example.com
    backend: "10.0.0.90:636"
    tls:
      cert: /config/certs/ldap.example.com.pem
      key: /config/certs/ldap.example.com.key
    binds:
      "cn=admin,dc=example,dc=com": {}
      "":
        mapToDn: "uid=reader,dc=example,dc=com"
        mapToSecret: "replace-me"
        allowedQueries:
          - ["dc=example,dc=com", "subtree", "(objectClass=*)"]
```

Without `binds`, nothing changes: the connection is spliced and the certificate stays on OpenLDAP.

## Build the image yourself

```bash
docker build -t ldap-gateway-proxy .
docker run --rm -p 636:636 -v "$PWD/config:/config" ldap-gateway-proxy
```

The image is `node:22-alpine` plus `tini`. It runs as root so the first start can write the seed config into the mounted volume.
