"""Configuration for MikroTik MCP Server."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Settings loaded from environment variables."""

    mikrotik_username: str = ""
    mikrotik_password: str = ""
    mikrotik_ssh_key: str = ""  # Path to SSH private key (optional)
    mikrotik_transport: str = "stdio"
    mikrotik_log_level: str = "INFO"
