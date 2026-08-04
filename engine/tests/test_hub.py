"""Phase 9 — the mTLS fleet hub.

The end-to-end tests use a real TLS socket with real certificates from the
project's own CA script. Mocking the handshake would test that the code calls
`wrap_socket`; a socket tests that an unauthenticated client is actually turned
away, which is the only claim that matters.

The tests that earn their keep are the negative ones: no certificate, a
certificate from the wrong CA, and a revoked certificate must all fail — and
crucially, revoking one probe must not disturb any other.
"""

from __future__ import annotations

import json
import shutil
import ssl
import subprocess
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from sentinel.config import Settings
from sentinel.hub import (
    FleetHub,
    RevocationList,
    build_ssl_context,
    make_hub_server,
    peer_identity,
)

CA_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "sentinel-ca.sh"
pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not available")


@pytest.fixture(scope="module")
def pki(tmp_path_factory) -> dict[str, Path]:
    """A real CA with a server certificate and two client certificates.

    Module-scoped: RSA keygen is slow, and every test wants the same fleet.
    """
    root = tmp_path_factory.mktemp("pki")
    env = {"SENTINEL_CA_DIR": str(root), "SENTINEL_KEY_BITS": "2048", "PATH": "/usr/bin:/bin"}

    def ca(*args: str) -> None:
        subprocess.run(["bash", str(CA_SCRIPT), *args], env=env, check=True,
                       capture_output=True, timeout=180)

    ca("init")
    ca("server", "sentinel-hub.lan", "127.0.0.1", "localhost")
    ca("client", "probe-01")
    ca("client", "probe-02")
    return {
        "dir": root,
        "ca": root / "ca.crt",
        "server_cert": root / "certs" / "sentinel-hub.lan.crt",
        "server_key": root / "private" / "sentinel-hub.lan.key",
        "p1_cert": root / "certs" / "probe-01.crt",
        "p1_key": root / "private" / "probe-01.key",
        "p2_cert": root / "certs" / "probe-02.crt",
        "p2_key": root / "private" / "probe-02.key",
        "revoked": root / "revoked.json",
    }


def hub_settings(settings: Settings, pki: dict[str, Path], **overrides) -> Settings:
    fields = {
        "hub_cert": str(pki["server_cert"]),
        "hub_key": str(pki["server_key"]),
        "hub_ca": str(pki["ca"]),
        "hub_revocation_list": str(pki["revoked"]),
        "hub_host": "127.0.0.1",
        "hub_port": 0,
    }
    fields.update(overrides)
    return replace(settings, **fields)


class TestRevocationList:
    def test_absent_path_revokes_nothing(self):
        assert RevocationList(None).is_revoked(name="probe-01") is False

    def test_missing_file_revokes_nothing(self, tmp_path):
        assert RevocationList(tmp_path / "nope.json").is_revoked(name="probe-01") is False

    def test_revokes_by_name_and_fingerprint(self, tmp_path):
        path = tmp_path / "r.json"
        path.write_text(json.dumps({"revoked": [
            {"name": "probe-04", "fingerprint": "AA:BB:CC"},
        ]}), encoding="utf-8")
        rl = RevocationList(path)
        assert rl.is_revoked(name="probe-04") is True
        assert rl.is_revoked(fingerprint="aabbcc") is True
        assert rl.is_revoked(name="probe-01") is False

    def test_hot_reloads_on_change(self, tmp_path):
        path = tmp_path / "r.json"
        path.write_text('{"revoked": []}', encoding="utf-8")
        rl = RevocationList(path)
        assert rl.is_revoked(name="probe-04") is False

        import os
        import time

        path.write_text(json.dumps({"revoked": [{"name": "probe-04"}]}), encoding="utf-8")
        os.utime(path, (time.time() + 1, time.time() + 1))
        assert rl.is_revoked(name="probe-04") is True, "revocation must take effect without a restart"

    def test_malformed_file_does_not_fail_open(self, tmp_path):
        # A corrupted write must not silently re-admit a revoked probe.
        import os
        import time

        path = tmp_path / "r.json"
        path.write_text(json.dumps({"revoked": [{"name": "probe-04"}]}), encoding="utf-8")
        rl = RevocationList(path)
        assert rl.is_revoked(name="probe-04") is True

        path.write_text("{ this is not json", encoding="utf-8")
        os.utime(path, (time.time() + 1, time.time() + 1))
        assert rl.is_revoked(name="probe-04") is True, "corrupt list must keep the previous entries"


class TestAuthorisation:
    def _hub(self, settings, tmp_path, **overrides) -> FleetHub:
        cfg = replace(settings, events_path=tmp_path / "events.jsonl",
                      hub_revocation_list="", **overrides)
        return FleetHub(cfg)

    def test_accepts_a_named_probe(self, settings, tmp_path):
        assert self._hub(settings, tmp_path).authorise("probe-01", "ff")[0] is True

    def test_rejects_a_certificate_with_no_common_name(self, settings, tmp_path):
        allowed, reason = self._hub(settings, tmp_path).authorise("", "ff")
        assert allowed is False and "Common Name" in reason

    def test_allowlist_is_a_second_gate(self, settings, tmp_path):
        hub = self._hub(settings, tmp_path, hub_allowed_probes=["probe-01"])
        assert hub.authorise("probe-01", "ff")[0] is True
        allowed, reason = hub.authorise("probe-09", "ff")
        assert allowed is False and "ALLOWED_PROBES" in reason

    def test_revoked_probe_is_refused(self, settings, tmp_path):
        revoked = tmp_path / "r.json"
        revoked.write_text(json.dumps({"revoked": [{"name": "probe-04"}]}), encoding="utf-8")
        hub = self._hub(settings, tmp_path)
        hub.revocations = RevocationList(revoked)
        assert hub.authorise("probe-04", "ff")[0] is False
        assert hub.authorise("probe-01", "ff")[0] is True, "revoking one probe must not affect another"


class TestHostPinning:
    def _hub(self, settings, tmp_path, **overrides) -> FleetHub:
        return FleetHub(replace(settings, events_path=tmp_path / "events.jsonl",
                                hub_revocation_list="", **overrides))

    def _stored(self, tmp_path) -> list[dict]:
        path = tmp_path / "events.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]

    def test_host_is_overwritten_with_the_certificate_identity(self, settings, tmp_path):
        hub = self._hub(settings, tmp_path)
        assert hub.accept_line("probe-01", json.dumps({"host": "whatever", "message": "x"}))[0]
        assert self._stored(tmp_path)[0]["host"] == "probe-01"

    def test_the_claim_is_preserved_for_forensics(self, settings, tmp_path):
        hub = self._hub(settings, tmp_path)
        hub.accept_line("probe-01", json.dumps({"host": "probe-07", "message": "x"}))
        assert self._stored(tmp_path)[0]["_claimed_host"] == "probe-07"

    def test_impersonation_is_neutralised_not_dropped(self, settings, tmp_path):
        # Rejecting would let anyone who can change a hostname silence a probe
        # entirely, which is worse than the impersonation it prevents.
        hub = self._hub(settings, tmp_path)
        ok, _ = hub.accept_line("probe-01", json.dumps({"host": "probe-07", "message": "quiet"}))
        assert ok is True
        stored = self._stored(tmp_path)[0]
        assert stored["host"] == "probe-01"
        assert hub.status()["host_mismatches"]["probe-01"] == 1

    def test_strict_mode_rejects_instead(self, settings, tmp_path):
        hub = self._hub(settings, tmp_path, hub_reject_host_mismatch=True)
        ok, reason = hub.accept_line("probe-01", json.dumps({"host": "probe-07"}))
        assert ok is False and "certificate says" in reason
        assert self._stored(tmp_path) == []

    def test_probe_identity_is_stamped(self, settings, tmp_path):
        hub = self._hub(settings, tmp_path)
        hub.accept_line("probe-01", json.dumps({"message": "x"}))
        stored = self._stored(tmp_path)[0]
        assert stored["_probe"] == "probe-01" and stored["_received_at"]

    def test_malformed_input_is_rejected(self, settings, tmp_path):
        hub = self._hub(settings, tmp_path)
        assert hub.accept_line("probe-01", "not json")[0] is False
        assert hub.accept_line("probe-01", "[1,2,3]")[0] is False
        assert self._stored(tmp_path) == []


class TestSSLContext:
    def test_requires_mutual_authentication(self, settings, pki):
        context = build_ssl_context(hub_settings(settings, pki))
        assert context.verify_mode == ssl.CERT_REQUIRED, "without this it is one-way TLS"
        assert context.minimum_version >= ssl.TLSVersion.TLSv1_3

    @pytest.mark.parametrize("missing", ["hub_cert", "hub_key", "hub_ca"])
    def test_missing_material_is_a_startup_error(self, settings, pki, missing):
        with pytest.raises(ValueError, match="SENTINEL_HUB_"):
            build_ssl_context(hub_settings(settings, pki, **{missing: ""}))

    def test_nonexistent_file_is_a_startup_error(self, settings, pki):
        with pytest.raises(FileNotFoundError):
            build_ssl_context(hub_settings(settings, pki, hub_ca="/nonexistent/ca.crt"))


class TestEndToEnd:
    """A real TLS listener, exercised with real client certificates."""

    @pytest.fixture
    def running_hub(self, settings, pki, tmp_path):
        cfg = hub_settings(settings, pki, events_path=tmp_path / "events.jsonl")
        server = make_hub_server(cfg)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield server, server.server_address[1], tmp_path
        server.shutdown()
        server.server_close()

    def _client_context(self, pki, cert=None, key=None) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cafile=str(pki["ca"]))
        if cert:
            ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
        return ctx

    def _post(self, port, ctx, body: str) -> tuple[int, str]:
        import http.client

        conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=15)
        conn.request("POST", "/ingest", body=body.encode("utf-8"),
                     headers={"Content-Type": "application/x-ndjson"})
        resp = conn.getresponse()
        payload = resp.read().decode()
        conn.close()
        return resp.status, payload

    def test_authenticated_probe_can_ship(self, running_hub, pki):
        _server, port, tmp_path = running_hub
        ctx = self._client_context(pki, pki["p1_cert"], pki["p1_key"])
        status, payload = self._post(port, ctx, json.dumps({"host": "x", "message": "hello"}) + "\n")
        assert status == 200
        assert json.loads(payload)["accepted"] == 1
        stored = json.loads((tmp_path / "events.jsonl").read_text().splitlines()[0])
        assert stored["host"] == "probe-01"

    def test_a_client_with_no_certificate_is_refused(self, running_hub, pki):
        _server, port, _tmp = running_hub
        ctx = self._client_context(pki)  # no client cert
        with pytest.raises((ssl.SSLError, OSError)):
            self._post(port, ctx, "{}\n")

    def test_a_certificate_from_another_ca_is_refused(self, running_hub, pki, tmp_path):
        _server, port, _tmp = running_hub
        rogue_cert, rogue_key = tmp_path / "rogue.crt", tmp_path / "rogue.key"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(rogue_key), "-out", str(rogue_cert),
            "-days", "1", "-subj", "/CN=probe-01",
        ], check=True, capture_output=True, timeout=120)

        ctx = self._client_context(pki, rogue_cert, rogue_key)
        with pytest.raises((ssl.SSLError, OSError)):
            self._post(port, ctx, "{}\n")

    def test_a_revoked_probe_is_refused_and_others_are_not(self, running_hub, pki):
        import os
        import time

        server, port, _tmp = running_hub
        p1 = self._client_context(pki, pki["p1_cert"], pki["p1_key"])
        p2 = self._client_context(pki, pki["p2_cert"], pki["p2_key"])
        assert self._post(port, p1, "{}\n")[0] == 200
        assert self._post(port, p2, "{}\n")[0] == 200

        revoked = Path(pki["revoked"])
        revoked.write_text(json.dumps({"revoked": [{"name": "probe-02"}]}), encoding="utf-8")
        os.utime(revoked, (time.time() + 1, time.time() + 1))

        status, payload = self._post(port, p2, "{}\n")
        assert status == 403 and "revoked" in payload
        # The whole point of the question: one probe out, the fleet unaffected.
        assert self._post(port, p1, "{}\n")[0] == 200

        revoked.write_text('{"revoked": []}', encoding="utf-8")
        os.utime(revoked, (time.time() + 2, time.time() + 2))

    def test_rejection_closes_the_connection(self, running_hub, pki):
        # Answering 403 without draining the body leaves unread bytes in the
        # socket; on a keep-alive connection the next request is then parsed from
        # the middle of the previous body. Found by running it.
        import http.client
        import os
        import time

        _server, port, _tmp = running_hub
        revoked = Path(pki["revoked"])
        revoked.write_text(json.dumps({"revoked": [{"name": "probe-02"}]}), encoding="utf-8")
        os.utime(revoked, (time.time() + 1, time.time() + 1))

        ctx = self._client_context(pki, pki["p2_cert"], pki["p2_key"])
        conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=15)
        big = "".join(json.dumps({"n": i}) + "\n" for i in range(500))
        conn.request("POST", "/ingest", body=big.encode(),
                     headers={"Content-Type": "application/x-ndjson"})
        resp = conn.getresponse()
        assert resp.status == 403
        assert resp.getheader("Connection", "").lower() == "close"
        resp.read()
        conn.close()

        revoked.write_text('{"revoked": []}', encoding="utf-8")
        os.utime(revoked, (time.time() + 2, time.time() + 2))

    def test_status_reports_the_fleet(self, running_hub, pki):
        import http.client

        _server, port, _tmp = running_hub
        ctx = self._client_context(pki, pki["p1_cert"], pki["p1_key"])
        self._post(port, ctx, json.dumps({"message": "x"}) + "\n")

        conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=15)
        conn.request("GET", "/status")
        payload = json.loads(conn.getresponse().read())
        conn.close()
        assert any(p["name"] == "probe-01" for p in payload["probes"])
        assert payload["host_pinning"] is True


class TestPeerIdentity:
    def test_extracts_the_common_name(self):
        cert = {"subject": ((("countryName", "JP"),), (("commonName", "probe-07"),))}
        assert peer_identity(cert) == "probe-07"

    def test_missing_certificate_is_empty(self):
        assert peer_identity(None) == ""
        assert peer_identity({}) == ""
