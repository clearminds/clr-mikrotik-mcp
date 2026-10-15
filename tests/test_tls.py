"""Tests for verified HTTPS to RouterOS (MIKROTIK_CA_BUNDLE / MIKROTIK_TLS_NAMES).

The unit tests pin the client kwargs; the end-to-end tests run a real TLS
server on 127.0.0.1 with a certificate for a DNS name, proving that "connect
to the IP, verify against the mapped name" actually verifies (and rejects a
wrong name) rather than merely setting a header.
"""

from __future__ import annotations

import datetime
import http.server
import json
import logging
import ssl
import threading
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from clr_mikrotik_mcp.config import Settings
from clr_mikrotik_mcp.routeros_client import RouterOSClient

ROUTER_NAME = "router.test.clearminds.se"


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """A throwaway CA plus a server certificate for ROUTER_NAME."""
    d = tmp_path_factory.mktemp("pki")
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ROUTER_NAME)]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(ROUTER_NAME)]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    paths = {"ca": d / "ca.crt", "cert": d / "server.crt", "key": d / "server.key"}
    paths["ca"].write_bytes(_pem(ca))
    paths["cert"].write_bytes(_pem(cert))
    paths["key"].write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return paths


@pytest.fixture
def tls_server(pki: dict[str, Path]) -> Iterator[dict[str, object]]:
    """HTTPS server on 127.0.0.1 that records the Host header it receives."""
    seen: dict[str, object] = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            seen["host"] = self.headers.get("Host")
            body = json.dumps([{"name": "ok"}]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pki["cert"], pki["key"])
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"port": httpd.server_address[1], "seen": seen}
    finally:
        httpd.shutdown()
        httpd.server_close()


def _always_open(monkeypatch: pytest.MonkeyPatch, open_ports: set[int]) -> None:
    monkeypatch.setattr(
        RouterOSClient,
        "_port_open",
        lambda self, host, port, timeout=2.0: port in open_ports,
    )


# --- unit: client kwargs -------------------------------------------------------


def test_ca_set_with_dns_name_host_uses_verifying_context(
    pki: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    _always_open(monkeypatch, {443})
    client = RouterOSClient(username="u", password="p", ca_bundle=str(pki["ca"]))
    kw = client._client_kwargs(ROUTER_NAME)

    assert isinstance(kw["verify"], ssl.SSLContext)
    assert kw["verify"].check_hostname is True
    assert kw["verify"].verify_mode == ssl.CERT_REQUIRED
    assert kw["base_url"] == f"https://{ROUTER_NAME}"
    # Connecting by name: nothing to override.
    assert "headers" not in kw
    assert "event_hooks" not in kw


@pytest.mark.parametrize("source", ["settings", "device"])
def test_ca_set_with_mapped_ip_sets_sni_and_host(
    pki: dict[str, Path], monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    _always_open(monkeypatch, {443})
    ip = "10.199.0.40"
    if source == "settings":
        client = RouterOSClient(ca_bundle=str(pki["ca"]), tls_names={ip: ROUTER_NAME})
    else:
        client = RouterOSClient(ca_bundle=str(pki["ca"]), devices={ip: {"tls_name": ROUTER_NAME}})
    kw = client._client_kwargs(ip)

    assert kw["base_url"] == f"https://{ip}"  # connect to the IP ...
    assert kw["headers"] == {"Host": ROUTER_NAME}  # ... but speak to the name
    request = httpx.Request("GET", f"https://{ip}/rest/system/identity")
    for hook in kw["event_hooks"]["request"]:
        hook(request)
    assert request.extensions["sni_hostname"] == ROUTER_NAME


def test_device_tls_name_beats_global_map(pki: dict[str, Path]) -> None:
    client = RouterOSClient(
        ca_bundle=str(pki["ca"]),
        tls_names={"10.0.0.1": "global.example"},
        devices={"10.0.0.1": {"tls_name": "device.example"}},
    )
    assert client._tls_name("10.0.0.1") == "device.example"


def test_ca_set_with_unmapped_ip_fails_clearly(
    pki: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    probed: list[int] = []
    monkeypatch.setattr(
        RouterOSClient,
        "_port_open",
        lambda self, host, port, timeout=2.0: probed.append(port) or True,
    )
    client = RouterOSClient(ca_bundle=str(pki["ca"]), tls_names={"10.0.0.2": "x.example"})
    with pytest.raises(ConnectionError, match="no known TLS name.*MIKROTIK_TLS_NAMES"):
        client._client_kwargs("10.0.0.1")
    with pytest.raises(ConnectionError, match="no known TLS name"):
        client.rest_get("10.0.0.1", "/system/identity")
    assert probed == []  # refused before touching the network


def test_no_ca_keeps_legacy_behaviour_and_warns_once(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _always_open(monkeypatch, {80})
    client = RouterOSClient(username="u", password="p")
    with caplog.at_level(logging.WARNING, logger="clr_mikrotik_mcp.routeros_client"):
        kw = client._client_kwargs("10.0.0.1")
        client._client_kwargs("10.0.0.1")

    assert kw["verify"] is False
    assert kw["base_url"] == "http://10.0.0.1"  # http fallback still allowed
    assert kw["auth"] == ("u", "p")
    warnings = [r for r in caplog.records if "NOT verified" in r.getMessage()]
    assert len(warnings) == 1


def test_no_http_downgrade_when_ca_set(
    pki: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    _always_open(monkeypatch, {80})  # only plain HTTP reachable
    client = RouterOSClient(ca_bundle=str(pki["ca"]))
    with pytest.raises(ConnectionError, match="not falling back to plain HTTP"):
        client._client_kwargs(ROUTER_NAME)


def test_missing_ca_bundle_fails_at_construction(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        RouterOSClient(ca_bundle=str(tmp_path / "nope.crt"))


def test_no_verify_false_left_in_client() -> None:
    import clr_mikrotik_mcp.routeros_client as mod

    source = Path(mod.__file__).read_text()
    assert source.count('"verify": False') == 1  # only the legacy branch of the helper
    assert "verify=False" not in source


# --- settings ------------------------------------------------------------------


def test_settings_parse_tls_names_and_ca(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIKROTIK_CA_BUNDLE", "/etc/ipa/ca.crt")
    monkeypatch.setenv("MIKROTIK_TLS_NAMES", json.dumps({"10.199.0.40": ROUTER_NAME}))
    s = Settings()
    assert s.mikrotik_ca_bundle == "/etc/ipa/ca.crt"
    assert s.mikrotik_tls_names == {"10.199.0.40": ROUTER_NAME}


def test_settings_defaults_and_empty_tls_names(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MIKROTIK_CA_BUNDLE", raising=False)
    monkeypatch.setenv("MIKROTIK_TLS_NAMES", "")
    s = Settings()
    assert s.mikrotik_ca_bundle == ""
    assert s.mikrotik_tls_names == {}


def test_settings_reject_non_object_tls_names(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIKROTIK_TLS_NAMES", '["10.0.0.1"]')
    with pytest.raises(ValueError, match="JSON object"):
        Settings()


# --- end-to-end against a real TLS server ----------------------------------------


def _point_at(monkeypatch: pytest.MonkeyPatch, port: int) -> None:
    monkeypatch.setattr(
        RouterOSClient, "_get_base_url", lambda self, host: f"https://{host}:{port}"
    )


def test_e2e_ip_with_mapped_name_verifies(
    pki: dict[str, Path], tls_server: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    _point_at(monkeypatch, tls_server["port"])  # type: ignore[arg-type]
    client = RouterOSClient(ca_bundle=str(pki["ca"]), tls_names={"127.0.0.1": ROUTER_NAME})
    assert client.rest_get("127.0.0.1", "/system/identity") == [{"name": "ok"}]
    assert tls_server["seen"]["host"] == ROUTER_NAME  # type: ignore[index]


def test_e2e_wrong_name_is_rejected(
    pki: dict[str, Path], tls_server: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    _point_at(monkeypatch, tls_server["port"])  # type: ignore[arg-type]
    client = RouterOSClient(
        ca_bundle=str(pki["ca"]), tls_names={"127.0.0.1": "other.clearminds.se"}
    )
    with pytest.raises(httpx.ConnectError, match="(?i)hostname mismatch|certificate verify"):
        client.rest_get("127.0.0.1", "/system/identity")


def test_e2e_untrusted_ca_is_rejected(
    pki: dict[str, Path],
    tls_server: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    other_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Other CA")])
    other_ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(other_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(other_key, hashes.SHA256())
    )
    bundle = tmp_path / "other.crt"
    bundle.write_bytes(_pem(other_ca))
    _point_at(monkeypatch, tls_server["port"])  # type: ignore[arg-type]
    client = RouterOSClient(ca_bundle=str(bundle), tls_names={"127.0.0.1": ROUTER_NAME})
    with pytest.raises(httpx.ConnectError, match="(?i)certificate verify"):
        client.rest_get("127.0.0.1", "/system/identity")
