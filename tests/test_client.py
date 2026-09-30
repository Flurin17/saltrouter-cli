import pytest

from saltrouter_cli.client import AuthError, XmoError, parse_json, unwrap_value

from .conftest import NONCE, SESSION_ID


def test_login_and_get(make_client, router):
    c = make_client()
    assert c.get("Device/DeviceInfo/ModelName") == "NJJ Fibre Box"
    assert router.logins == 1
    assert c.session.session_id == SESSION_ID and c.session.nonce == NONCE


def test_bad_password_raises_auth_error(make_client):
    with pytest.raises(AuthError):
        make_client(password="wrong").get("Device/DeviceInfo/UpTime")


def test_session_is_cached_between_clients(make_client, router):
    make_client().get("Device/DeviceInfo/UpTime")
    make_client().get("Device/DeviceInfo/UpTime")
    assert router.logins == 1


def test_expired_session_relogs_in(make_client, router):
    c = make_client()
    c.get("Device/DeviceInfo/UpTime")
    c.session.session_id = 1  # router will answer XMO_INVALID_SESSION_ERR
    assert c.get("Device/DeviceInfo/UpTime") == 100
    assert router.logins == 2


def test_request_ids_increment(make_client, router):
    c = make_client(cache_session=False)
    c.get("Device/DeviceInfo/UpTime")
    c.get("Device/DeviceInfo/UpTime")
    assert [r["id"] for r in router.requests] == [0, 1, 2]


def test_multi_match_predicate_returns_list(make_client):
    vals = make_client().get('Device/Hosts/Hosts/Host[Active="true"]/HostName')
    assert vals == ["laptop", "laptop"]


def test_get_many_tolerates_errors(make_client):
    res = make_client().get_many({"m": "Device/DeviceInfo/ModelName", "x": "Device/Nope"})
    assert res == {"m": "NJJ Fibre Box", "x": None}


def test_unknown_path_raises(make_client):
    with pytest.raises(XmoError) as e:
        make_client().get("Device/Nope")
    assert e.value.xpath == "Device/Nope"


def test_capability_is_returned(make_client):
    r = make_client().request([{"method": "getValue", "xpath": "Device/Firewall/Config"}])[0]
    assert r["capability"]["restrictions"]["enum-values"][0]["name"] == "LOW"


def test_rpc_reboot_forces_gui_source(make_client, router):
    make_client().rpc("Device", "reboot", {"x": 1})
    assert router.requests[-1]["actions"][0]["parameters"] == {"source": "GUI"}


def test_unwrap_and_lenient_json():
    assert unwrap_value({"UpTime": 5}) == 5
    assert unwrap_value({"a": 1, "b": 2}) == {"a": 1, "b": 2}
    assert parse_json('{"a": [1, 2,], "b": {"c": 1,},}') == {"a": [1, 2], "b": {"c": 1}}
