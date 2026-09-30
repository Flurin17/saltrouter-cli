"""Client for the Sagemcom XMO JSON API used by Salt Fiber Box routers.

Reverse-engineered from the router web GUI (js/gui-api.js, js/xmo.js):

* Every call is a POST to ``/cgi/json-req`` with form field ``req`` holding a
  JSON envelope ``{"request": {id, session-id, priority, actions, cnonce, auth-key}}``.
* Auth is a digest scheme using SHA-512:
    pass_hash = sha512(password)
    ha1       = sha512(f"{user}:{nonce}:{pass_hash}")      # nonce is "" before login
    auth_key  = sha512(f"{ha1}:{request_id}:{cnonce}:JSON:/cgi/json-req")
* ``logIn`` returns a session id and a server nonce used for subsequent requests.
* Actions: getValue, setValue, addChild, deleteChild, logIn, logOut and RPC
  methods called on an xpath (reboot, ping, traceRoute, nslookup, ...).
"""

import hashlib
import json
import os
import random
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Self

import httpx

ENDPOINT = "/cgi/json-req"
UINT_MAX = 4294967295

XMO_REQUEST_NO_ERR = 16777216
XMO_INVALID_SESSION_ERR = 16777219
XMO_SESSION_TIMEOUT_ERR = 16777220
XMO_SESSION_LOGOUT_ERR = 16777221
XMO_AUTHENTICATION_ERR = 16777223
XMO_LOGIN_RETRY_ERR = 16777224
XMO_MAX_SESSION_COUNT_ERR = 16777225
XMO_REQUEST_ID_ERR = 16777233
XMO_REQUEST_ACTION_ERR = 16777236
XMO_NO_ERR = 16777238
XMO_ACTION_CALLBACK_ERR = 16777248

SESSION_ERRORS = {
    XMO_INVALID_SESSION_ERR,
    XMO_SESSION_TIMEOUT_ERR,
    XMO_SESSION_LOGOUT_ERR,
    XMO_REQUEST_ID_ERR,
}

SESSION_OPTIONS = {
    "nss": [{"name": "gtw", "uri": "http://sagemcom.com/gateway-data"}],
    "language": "ident",
    "context-flags": {"get-content-name": True, "local-time": True},
    "capability-depth": 2,
    "capability-flags": {
        "name": True,
        "default-value": False,
        "restriction": True,
        "description": False,
    },
    "time-format": "ISO_8601",
    "write-only-string": "_XMO_WRITE_ONLY_",
    "undefined-write-only-string": "_XMO_UNDEFINED_WRITE_ONLY_",
}


class XmoError(Exception):
    """Error returned by the router for a request or an action."""

    def __init__(self, code: int, description: str, xpath: str | None = None):
        self.code = code
        self.description = description
        self.xpath = xpath
        msg = f"{description} ({code})"
        if xpath:
            msg += f" at {xpath}"
        super().__init__(msg)


class AuthError(XmoError):
    """Login failed or session could not be established."""


def sha512(text: str) -> str:
    return hashlib.sha512(text.encode()).hexdigest()


def action(method: str, xpath: str | None = None, parameters: dict | None = None, **extra: Any) -> dict:
    """Build a single XMO action dict (id is assigned when the request is sent)."""
    a: dict[str, Any] = {"method": method}
    if xpath is not None:
        a["xpath"] = xpath
    if parameters is not None:
        a["parameters"] = parameters
    a.update(extra)
    return a


def get_action(xpath: str) -> dict:
    return action("getValue", xpath)


def set_action(xpath: str, value: Any) -> dict:
    return action("setValue", xpath, {"value": value})


def add_action(xpath: str, value: Any, uid: int | None = None) -> dict:
    params: dict[str, Any] = {"value": value}
    if uid is not None:
        params["uid"] = uid
    return action("addChild", xpath, params)


def delete_action(xpath: str) -> dict:
    return action("deleteChild", xpath)


def default_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(Path.home(), ".cache")
    return Path(base) / "saltrouter"


@dataclass
class Session:
    session_id: int = 0
    nonce: str = ""
    request_id: int = 0
    created: float = field(default_factory=time.time)


class XmoClient:
    """Minimal synchronous XMO client.

    Sessions are cached on disk (per host+user) so consecutive CLI invocations
    reuse one router session instead of logging in each time.
    """

    def __init__(
        self,
        host: str = "192.168.1.1",
        username: str = "admin",
        password: str = "",
        *,
        timeout: float = 30.0,
        cache_session: bool = True,
        cache_dir: Path | None = None,
        transport: httpx.BaseTransport | None = None,
    ):
        self.base_url = host if host.startswith("http") else f"http://{host}"
        self.username = username
        self._pass_hash = sha512(password)
        self.cache_session = cache_session
        self._cache_file = (cache_dir or default_cache_dir()) / (
            sha512(f"{self.base_url}|{username}|{self._pass_hash}")[:16] + ".json"
        )
        self.session = Session()
        self._http = httpx.Client(base_url=self.base_url, timeout=timeout, transport=transport)
        if cache_session:
            self._load_session()

    # -- session cache -------------------------------------------------
    def _load_session(self) -> None:
        try:
            data = json.loads(self._cache_file.read_text())
            self.session = Session(**data)
        except OSError, ValueError, TypeError:
            self.session = Session()

    def _save_session(self) -> None:
        if not self.cache_session:
            return
        try:
            self._cache_file.parent.mkdir(parents=True, exist_ok=True)
            self._cache_file.write_text(json.dumps(self.session.__dict__))
            os.chmod(self._cache_file, 0o600)
        except OSError:
            pass

    def _clear_session(self) -> None:
        self.session = Session()
        try:
            self._cache_file.unlink()
        except OSError:
            pass

    @property
    def logged_in(self) -> bool:
        return self.session.session_id != 0

    # -- transport -----------------------------------------------------
    def _post(self, actions: list[dict]) -> dict:
        s = self.session
        req_id = s.request_id
        s.request_id = 1 if s.request_id + 1 > UINT_MAX else s.request_id + 1
        cnonce = random.randint(0, UINT_MAX)
        ha1 = sha512(f"{self.username}:{s.nonce}:{self._pass_hash}")
        auth_key = sha512(f"{ha1}:{req_id}:{cnonce}:JSON:{ENDPOINT}")
        body = {
            "request": {
                "id": req_id,
                "session-id": s.session_id,
                "priority": False,
                "actions": [dict(a, id=i) for i, a in enumerate(actions)],
                "cnonce": cnonce,
                "auth-key": auth_key,
            }
        }
        resp = self._http.post(ENDPOINT, data={"req": json.dumps(body, separators=(",", ":"))})
        resp.raise_for_status()
        self._save_session()
        return parse_json(resp.text)["reply"]

    def login(self) -> Session:
        self.session = Session()
        reply = self._post(
            [
                action(
                    "logIn",
                    parameters={
                        "user": self.username,
                        "persistent": "true",
                        "session-options": SESSION_OPTIONS,
                    },
                )
            ]
        )
        err = reply["error"]
        act = (reply.get("actions") or [{}])[0]
        if err["code"] != XMO_REQUEST_NO_ERR or act.get("error", {}).get("code") != XMO_NO_ERR:
            e = act.get("error") or err
            raise AuthError(e["code"], e["description"])
        params = act["callbacks"][0]["parameters"]
        self.session = Session(session_id=params["id"], nonce=str(params["nonce"]), request_id=1)
        self._save_session()
        return self.session

    def logout(self) -> None:
        if self.logged_in:
            try:
                self._post([action("logOut")])
            except httpx.HTTPError, KeyError, ValueError:
                pass
        self._clear_session()

    def request(self, actions: list[dict], *, raise_on_error: bool = True) -> list[dict]:
        """Send actions in one request; returns per-action results.

        Each result: ``{"xpath", "method", "ok", "value" | "parameters" | "error"}``.
        Transparently logs in (or re-logs in on an expired session).
        """
        if not actions:
            return []
        if not self.logged_in:
            self.login()
        reply = self._post(actions)
        if reply["error"]["code"] in SESSION_ERRORS:
            self.login()
            reply = self._post(actions)
        code = reply["error"]["code"]
        if code not in (XMO_REQUEST_NO_ERR, XMO_REQUEST_ACTION_ERR):
            if code in SESSION_ERRORS or code == XMO_AUTHENTICATION_ERR:
                self._clear_session()
                raise AuthError(code, reply["error"]["description"])
            raise XmoError(code, reply["error"]["description"])
        results = []
        for sent, got in zip(actions, reply.get("actions", [])):
            results.append(self._parse_action(sent, got))
        if raise_on_error:
            for r in results:
                if not r["ok"]:
                    raise XmoError(r["error"]["code"], r["error"]["description"], r.get("xpath"))
        return results

    @staticmethod
    def _parse_action(sent: dict, got: dict) -> dict:
        xpath = sent.get("xpath")
        res: dict[str, Any] = {"method": sent["method"], "xpath": xpath}
        err = got.get("error", {})
        callbacks = got.get("callbacks") or []
        if err.get("code") not in (XMO_NO_ERR, None):
            # Callback-level errors carry the more specific description.
            for cb in callbacks:
                r = cb.get("result", {})
                if r.get("code") not in (XMO_NO_ERR, None):
                    err = r
                    break
            res.update(ok=False, error={"code": err.get("code"), "description": err.get("description")})
            return res
        res["ok"] = True
        params = callbacks[0].get("parameters", {}) if callbacks else {}
        if sent["method"] == "getValue":
            # A predicate matching several nodes yields one callback per match.
            values = [unwrap_value(cb.get("parameters", {}).get("value")) for cb in callbacks]
            res["value"] = values if len(values) > 1 else (values[0] if values else None)
            if "capability" in params:
                res["capability"] = params["capability"]
        else:
            res["parameters"] = params
        return res

    # -- convenience ---------------------------------------------------
    def get(self, xpath: str) -> Any:
        return self.request([get_action(xpath)])[0]["value"]

    def get_many(self, xpaths: dict[str, str], *, raise_on_error: bool = False) -> dict[str, Any]:
        """Batch getValue for a {name: xpath} mapping (one HTTP round-trip per 90)."""
        names = list(xpaths)
        out: dict[str, Any] = {}
        for i in range(0, len(names), 90):
            chunk = names[i : i + 90]
            results = self.request([get_action(xpaths[n]) for n in chunk], raise_on_error=raise_on_error)
            for n, r in zip(chunk, results):
                out[n] = r["value"] if r["ok"] else None
        return out

    def set(self, xpath: str, value: Any) -> dict:
        return self.request([set_action(xpath, value)])[0]

    def set_many(self, values: dict[str, Any]) -> list[dict]:
        return self.request([set_action(k, v) for k, v in values.items()])

    def add_child(self, xpath: str, value: Any, uid: int | None = None) -> dict:
        return self.request([add_action(xpath, value, uid)])[0]

    def delete_child(self, xpath: str) -> dict:
        return self.request([delete_action(xpath)])[0]

    def rpc(self, xpath: str, method: str, parameters: dict | None = None) -> dict:
        if method == "reboot":
            parameters = {"source": "GUI"}
        return self.request([action(method, xpath, parameters if parameters is not None else {})])[0]

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def unwrap_value(value: Any) -> Any:
    """getValue wraps the result in ``{<LeafName>: ...}``; strip that single key."""
    if isinstance(value, dict) and len(value) == 1:
        return next(iter(value.values()))
    return value


_TRAILING_COMMA = re.compile(r",\s*([}\]])")


def parse_json(text: str) -> Any:
    """Parse router JSON; some firmware emits trailing commas, so retry leniently."""
    try:
        return json.loads(text)
    except ValueError:
        return json.loads(_TRAILING_COMMA.sub(r"\1", text))
