import json

import httpx
import pytest
from click.testing import CliRunner

from saltrouter_cli import cli as cli_mod
from saltrouter_cli.client import XmoClient

from .conftest import PASSWORD


@pytest.fixture
def run(router, tmp_path, monkeypatch):
    real_init = XmoClient.__init__

    def init(self, *a, **kw):
        kw.update(transport=httpx.MockTransport(router), cache_dir=tmp_path)
        real_init(self, *a, **kw)

    monkeypatch.setattr(XmoClient, "__init__", init)
    monkeypatch.setattr(cli_mod, "load_env_files", lambda *a: None)
    monkeypatch.setenv("SALTROUTER_PASSWORD", PASSWORD)

    def invoke(*args):
        res = CliRunner().invoke(cli_mod.cli, list(args))
        return res.exit_code, res.stdout, res.stderr

    return invoke


def test_get_scalar(run):
    code, out, _ = run("get", "Device/DeviceInfo/UpTime")
    assert code == 0 and out.strip() == "100"


def test_hosts_active_only_and_fields(run):
    code, out, _ = run("hosts", "-f", "uid,name,link")
    assert code == 0
    assert json.loads(out) == [{"uid": 2, "name": "Laptop", "link": "WiFi:PRIV1"}]


def test_where_and_tsv(run):
    code, out, _ = run("hosts", "--all", "-w", "active=false", "-o", "tsv", "-f", "uid,ip")
    assert code == 0
    assert out.splitlines() == ["uid\tip", "1\t192.168.1.10", "3\t192.168.1.12"]


def test_host_resolution_prefers_active(run):
    code, out, _ = run("host", "rename", "laptop", "Work", "--dry-run")
    assert code == 0
    assert '@uid=\\"2\\"' in out


def test_dry_run_sends_nothing(run, router):
    code, out, _ = run("set", "Device/Firewall/Config", "HIGH", "--dry-run")
    assert code == 0 and json.loads(out)["dry_run"] is True
    assert router.requests == []


def test_destructive_needs_yes(run, router):
    code, _, err = run("system", "reboot")
    assert code == 6 and json.loads(err)["error"]["type"] == "confirmation_required"
    assert router.requests == []
    code, out, _ = run("system", "reboot", "--yes")
    assert code == 0 and json.loads(out)["ok"] is True
    assert router.requests[-1]["actions"][0]["method"] == "reboot"


def test_router_error_exit_code(run):
    code, out, err = run("get", "Device/Nope")
    assert code == 4 and out == ""
    assert json.loads(err)["error"]["message"] == "XMO_UNKNOWN_PATH_ERR"


def test_auth_error_exit_code(run, monkeypatch):
    monkeypatch.setenv("SALTROUTER_PASSWORD", "wrong")
    code, _, err = run("get", "Device/DeviceInfo/UpTime")
    assert code == 3 and json.loads(err)["error"]["type"] == "auth"


def test_describe(run):
    code, out, _ = run("describe", "Device/Firewall/Config")
    d = json.loads(out)
    assert code == 0 and d["writable"] is True and d["enum"] == ["LOW", "HIGH"] and d["type"] == "int32"


def test_commands_lists_everything(run):
    _, out, _ = run("commands")
    cmds = {c["cmd"] for c in json.loads(out)}
    assert {"status", "wifi set", "portfw add", "system reboot", "get", "batch"} <= cmds


def test_paths_catalog_search(run):
    code, out, _ = run("paths", "portmappings", "-n", "2")
    rows = json.loads(out)
    assert code == 0 and len(rows) == 2 and all("PortMapping" in r["xpath"] for r in rows)


def test_secrets_redacted(run, monkeypatch):
    monkeypatch.setattr(
        cli_mod,
        "_wifi_raw",
        lambda: {
            "ssids": [{"Alias": "S", "SSID": "net", "LowerLayers": "Device/WiFi/Radios/Radio[R]"}],
            "aps": [
                {"Alias": "A", "SSIDReference": "Device/WiFi/SSIDs/SSID[S]", "Security": {"KeyPassphrase": "hunter22"}}
            ],
            "radios": [{"Alias": "R"}],
        },
    )
    _, out, _ = run("wifi", "show", "S", "-f", "password")
    assert json.loads(out) == {"password": "***"}
    _, out, _ = run("wifi", "show", "S", "-f", "password", "--show-secrets")
    assert json.loads(out) == {"password": "hunter22"}
