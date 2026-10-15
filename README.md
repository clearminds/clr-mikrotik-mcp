# clr-mikrotik-mcp

MikroTik RouterOS management via REST API and SSH

## Install

```bash
pip install clr-mikrotik-mcp
# or
uvx clr-mikrotik-mcp
```

## Configuration

**Preferred:** Configuration file at `~/.config/mikrotik/credentials.json` (chmod 600):

```json
{
  "username": "admin",
  "password": "your-password",
  "ssh_key": "/path/to/id_rsa"
}
```

**Note:** Either password or ssh_key is required, not both.

**Alternative:** Environment variables are also supported:

| Variable | Description | Example |
|----------|-------------|---------|
| `MIKROTIK_USERNAME` | MikroTik username | `admin` |
| `MIKROTIK_PASSWORD` | MikroTik password | `your-password` |
| `MIKROTIK_SSH_KEY` | SSH key path | `/path/to/id_rsa` |

Optional:

| Variable | Description | Default |
|----------|-------------|---------|
| `MIKROTIK_READ_ONLY` | Run in read-only mode | `false` |
| `MIKROTIK_TRANSPORT` | Transport protocol (`stdio` or `http`) | `stdio` |
| `MIKROTIK_LOG_LEVEL` | Log level | `INFO` |
| `MIKROTIK_CA_BUNDLE` | PEM CA file used to verify the routers' HTTPS certificate (see below) | empty (no verification) |
| `MIKROTIK_TLS_NAMES` | JSON object mapping a host/IP to the DNS name on its certificate | `{}` |

## Verified HTTPS

The REST API is reached on `https://<host>` (port 443). By default the
certificate is **not** verified and, if 443 is closed, plain `http://<host>`
(port 80) is used instead. A warning is logged once at the first REST call
while running like this.

Set `MIKROTIK_CA_BUNDLE` to a CA file to turn verification on. With a CA
bundle configured:

- The certificate must chain to that CA and match the router's DNS name
  (hostname checking is on).
- There is **no fallback to http:80**: if 443 is unreachable the call fails
  rather than downgrading to cleartext.
- Calls addressed by **DNS name** need nothing else.
- Calls addressed by **IP** need the name the certificate was issued for,
  from `MIKROTIK_TLS_NAMES` or a per-device `tls_name` (the per-device value
  wins). An IP with no known name is refused with an error that says so;
  verification is never silently skipped.

How an IP is verified: the client still **connects to the IP** the caller
gave, but sends the mapped name as TLS SNI and as the HTTP `Host` header and
verifies the certificate against that name (httpx's `sni_hostname` request
extension). This was chosen over rewriting the URL to the name because it
does not depend on DNS: it keeps working when the internal resolvers are
unreachable, and it always talks to exactly the address the caller asked for.

Per-device names live next to per-device credentials in
`credentials.json`:

```json
{
  "username": "admin",
  "password": "your-password",
  "devices": {
    "10.199.0.40": {"tls_name": "sto-gar-ar2-1.lo.int.clearminds.se"}
  }
}
```

### Deploying (Docker)

Mount the CA read-only and set both variables, e.g. for the Clearminds
FreeIPA CA (`/etc/ipa/ca.crt` on the Docker host):

```yaml
services:
  mikrotik:
    image: ghcr.io/clearminds/clr-mikrotik-mcp:latest
    volumes:
      - /etc/ipa/ca.crt:/etc/ipa/ca.crt:ro
    environment:
      MIKROTIK_CA_BUNDLE: /etc/ipa/ca.crt
      MIKROTIK_TLS_NAMES: >-
        {"10.199.0.1": "sto-gar-ar1.lo.int.clearminds.se",
         "10.199.0.10": "sto-gar-edge1.lo.int.clearminds.se",
         "10.199.0.11": "sto-gar-edge2.lo.int.clearminds.se",
         "10.199.0.20": "oob-sto-gar.int.clearminds.se",
         "10.199.0.30": "sto-gar-mgmtsw1.int.clearminds.se",
         "10.199.0.40": "sto-gar-ar2-1.lo.int.clearminds.se",
         "10.199.0.41": "sto-gar-ar2-2.lo.int.clearminds.se",
         "10.199.0.50": "sto-gar-sw1.int.clearminds.se",
         "192.168.144.1": "sto-alv-rt01.lo.int.clearminds.se"}
```

A missing or unreadable CA file stops the server at startup. A router whose
certificate does not match its name, or that is not signed by the CA, fails
with a certificate verification error.

See `--help` for additional options:

```bash
clr-mikrotik-mcp --help
```

## Development

```bash
git clone https://github.com/clearminds/clr-mikrotik-mcp.git
cd clr-mikrotik-mcp
uv sync
uv run clr-mikrotik-mcp
```

## License

MIT
