# mikrotik-mcp-server

MikroTik RouterOS management via REST API and SSH

## Install

```bash
pip install mikrotik-mcp-server
# or
uvx mikrotik-mcp-server
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

See `--help` for additional options:

```bash
mikrotik-mcp-server --help
```

## Development

```bash
git clone https://github.com/clearminds/mikrotik-mcp-server.git
cd mikrotik-mcp-server
uv sync
uv run mikrotik-mcp-server
```

## License

MIT
