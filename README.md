# mikrotik-mcp-server

MikroTik RouterOS management via REST API and SSH

## Install

```bash
pip install mikrotik-mcp-server
# or
uvx mikrotik-mcp-server
```

## Configuration

Configuration via environment variables. See `--help` for all options:

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
