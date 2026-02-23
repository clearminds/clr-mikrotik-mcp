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
