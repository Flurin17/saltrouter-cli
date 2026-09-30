"""A fake XMO router that validates the auth digest and serves a tiny data model."""

import json
import urllib.parse

import httpx
import pytest

from saltrouter_cli.client import XmoClient, sha512

USER, PASSWORD = "admin", "secret"
SESSION_ID, NONCE = 4242, "1234567"

TREE = {
    "Device/DeviceInfo/ModelName": "NJJ Fibre Box",
    "Device/DeviceInfo/UpTime": 100,
    "Device/Hosts/Hosts": [
        {
            "uid": 1,
            "PhysAddress": "aa:bb:cc:dd:ee:01",
            "IPAddress": "192.168.1.10",
            "HostName": "old",
            "UserFriendlyName": "aa:bb:cc:dd:ee:01",
            "Active": False,
            "InterfaceType": "Ethernet",
        },
        {
            "uid": 2,
            "PhysAddress": "aa:bb:cc:dd:ee:02",
            "IPAddress": "192.168.1.11",
            "HostName": "laptop",
            "UserFriendlyName": "Laptop",
            "Active": True,
            "InterfaceType": "WiFi",
            "AssociatedDevice": "Device/WiFi/AccessPoints/AccessPoint[Alias='PRIV1']/AssociatedDevices/x",
        },
        {
            "uid": 3,
            "PhysAddress": "aa:bb:cc:dd:ee:03",
            "IPAddress": "192.168.1.12",
            "HostName": "laptop",
            "UserFriendlyName": "",
            "Active": False,
            "InterfaceType": "WiFi",
        },
    ],
    "Device/Firewall/Config": "Advanced",
}
CAPS = {
    "Device/Firewall/Config": {
        "type": "fw:Firewall:Config xmo:int32 xmo:number xmo:value",
        "flags": {"value": True, "config": True},
        "restrictions": {"enum-values": [{"name": "LOW"}, {"name": "HIGH"}]},
    }
}


class FakeRouter:
    def __init__(self):
        self.requests: list[dict] = []
        self.logins = 0

    def check_auth(self, req: dict, nonce: str) -> bool:
        ha1 = sha512(f"{USER}:{nonce}:{sha512(PASSWORD)}")
        expect = sha512(f"{ha1}:{req['id']}:{req['cnonce']}:JSON:/cgi/json-req")
        return req["auth-key"] == expect

    def reply(self, rid: int, code: int, desc: str, actions: list | None = None) -> httpx.Response:
        body = {
            "reply": {
                "uid": 0,
                "id": rid,
                "error": {"code": code, "description": desc},
                "actions": actions or [],
                "events": [],
            }
        }
        # Real firmware sometimes emits trailing commas; make sure we cope.
        return httpx.Response(200, text=json.dumps(body)[:-2] + ",}}" if rid % 2 else json.dumps(body))

    def __call__(self, request: httpx.Request) -> httpx.Response:
        form = urllib.parse.parse_qs(request.content.decode())
        req = json.loads(form["req"][0])["request"]
        self.requests.append(req)
        actions = req["actions"]
        if actions and actions[0]["method"] == "logIn":
            if not self.check_auth(req, ""):
                return self.reply(
                    req["id"],
                    16777216,
                    "XMO_REQUEST_NO_ERR",
                    [{"id": 0, "error": {"code": 16777223, "description": "XMO_AUTHENTICATION_ERR"}}],
                )
            self.logins += 1
            return self.reply(
                req["id"],
                16777216,
                "XMO_REQUEST_NO_ERR",
                [
                    {
                        "id": 0,
                        "error": {"code": 16777238, "description": "XMO_NO_ERR"},
                        "callbacks": [{"parameters": {"id": SESSION_ID, "nonce": NONCE}}],
                    }
                ],
            )
        if req["session-id"] != SESSION_ID or not self.check_auth(req, NONCE):
            return self.reply(req["id"], 16777219, "XMO_INVALID_SESSION_ERR")
        out = []
        for a in actions:
            ok = {"code": 16777238, "description": "XMO_NO_ERR"}
            if a["method"] == "getValue":
                x = a["xpath"]
                if x == 'Device/Hosts/Hosts/Host[Active="true"]/HostName':
                    cbs = [{"parameters": {"value": h["HostName"]}} for h in TREE["Device/Hosts/Hosts"] if h["Active"]]
                    cbs *= 2
                    out.append({"id": a["id"], "error": ok, "callbacks": cbs})
                elif x in TREE:
                    leaf = x.rsplit("/", 1)[-1]
                    params = {"value": {leaf: TREE[x]}}
                    if x in CAPS:
                        params["capability"] = CAPS[x]
                    out.append({"id": a["id"], "error": ok, "callbacks": [{"parameters": params}]})
                else:
                    out.append({"id": a["id"], "error": {"code": 16777242, "description": "XMO_UNKNOWN_PATH_ERR"}})
            else:
                out.append({"id": a["id"], "error": ok, "callbacks": [{"parameters": {"echo": a["method"]}}]})
        return self.reply(req["id"], 16777216, "XMO_REQUEST_NO_ERR", out)


@pytest.fixture
def router():
    return FakeRouter()


@pytest.fixture
def make_client(router, tmp_path):
    def make(password: str = PASSWORD, **kw) -> XmoClient:
        return XmoClient("192.168.1.1", USER, password, cache_dir=tmp_path, transport=httpx.MockTransport(router), **kw)

    return make
