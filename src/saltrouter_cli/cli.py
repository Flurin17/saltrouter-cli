"""saltrouter: agent-first CLI for Salt Fiber Box (Sagemcom XMO) routers.

Conventions (see AGENTS.md):
  * stdout is data only: compact JSON by default (-o pretty|jsonl|tsv|raw).
  * Trim output with -f/--fields, -w/--where, -n/--limit. Secrets are redacted
    unless --show-secrets.
  * Every write supports --dry-run (prints the XMO actions, sends nothing).
    Deletes and disruptive actions (reboot, reset) also require --yes.
  * Errors go to stderr as JSON with a stable exit code:
    1 unexpected, 2 usage, 3 auth, 4 router error, 5 network, 6 needs --yes, 7 not found.
"""

import json
import os
import re
import sys
from importlib import resources
from typing import Any

import click
import httpx

from . import __version__
from .client import (
    AuthError,
    XmoClient,
    XmoError,
    action,
    add_action,
    delete_action,
    get_action,
    set_action,
)
from .config import env_password, load_env_files
from .output import emit, emit_error, parse_where, summarize

EXIT_UNEXPECTED, EXIT_USAGE, EXIT_AUTH, EXIT_ROUTER, EXIT_NETWORK, EXIT_CONFIRM, EXIT_NOT_FOUND = 1, 2, 3, 4, 5, 6, 7


class CliError(Exception):
    def __init__(self, kind: str, message: str, code: int, **extra: Any):
        super().__init__(message)
        self.kind, self.code, self.extra = kind, code, extra


def not_found(what: str, ident: str, **extra: Any) -> CliError:
    return CliError("not_found", f"no {what} matching {ident!r}", EXIT_NOT_FOUND, **extra)


# ---------------------------------------------------------------- plumbing


def _set_opt(ctx: click.Context, param: click.Parameter, value: Any) -> Any:
    if value not in (None, (), False):
        ctx.find_root().obj[param.name] = value
    return value


def output_options(f):
    """Output flags accepted on every command (and globally), so agents can append them anywhere."""
    opts = [
        click.option(
            "-o",
            "--output",
            "fmt",
            type=click.Choice(["json", "pretty", "jsonl", "tsv", "raw"]),
            expose_value=False,
            callback=_set_opt,
            help="Output format (default: compact json).",
        ),
        click.option(
            "-f",
            "--fields",
            expose_value=False,
            callback=_set_opt,
            help="Comma-separated fields to keep (dotted paths ok, e.g. Security.ModeEnabled).",
        ),
        click.option(
            "-w",
            "--where",
            multiple=True,
            expose_value=False,
            callback=_set_opt,
            help="Filter list rows: key=val, key!=val, key~substr, key>n, key<n. Repeatable (AND).",
        ),
        click.option("-n", "--limit", type=int, expose_value=False, callback=_set_opt, help="Max list rows."),
        click.option(
            "--show-secrets", is_flag=True, expose_value=False, callback=_set_opt, help="Do not redact passwords/keys."
        ),
    ]
    for o in reversed(opts):
        f = o(f)
    return f


def write_options(f):
    return click.option("--dry-run", is_flag=True, help="Print the XMO actions instead of sending them.")(f)


def confirm_option(f):
    return click.option("--yes", "-y", is_flag=True, help="Required for deletes and disruptive actions.")(f)


def out(obj: Any) -> None:
    o = click.get_current_context().find_root().obj
    fields = [x.strip() for x in o["fields"].split(",")] if o.get("fields") else None
    emit(
        obj,
        fmt=o.get("fmt") or "json",
        fields=fields,
        where=parse_where(list(o.get("where") or [])),
        limit=o.get("limit"),
        show_secrets=bool(o.get("show_secrets")),
    )


def client() -> XmoClient:
    o = click.get_current_context().find_root().obj
    if o.get("client") is None:
        password = o.get("password") or env_password()
        if not password:
            raise CliError(
                "auth", "no password: set SALTROUTER_PASSWORD (or SALTROUTER_PW), a .env file, or --password", EXIT_AUTH
            )
        o["client"] = XmoClient(o["host"], o["user"], password, timeout=o["timeout"], cache_session=not o["no_cache"])
    return o["client"]


def run_write(actions: list[dict], dry_run: bool, *, yes: bool | None = None, what: str = "") -> None:
    """Send write actions (or print them). ``yes`` is None for non-destructive writes."""
    if dry_run:
        out({"dry_run": True, "actions": actions})
        return
    if yes is False:
        raise CliError(
            "confirmation_required",
            f"{what or 'this action'} is destructive; re-run with --yes (or --dry-run to preview)",
            EXIT_CONFIRM,
            actions=actions,
        )
    results = client().request(actions)
    payload: dict[str, Any] = {"ok": True}
    extra = [r.get("parameters") for r in results if r.get("parameters")]
    if extra:
        payload["result"] = extra[0] if len(extra) == 1 else extra
    out(payload)


def ref(path: str) -> str:
    """'Device/WiFi/Radios/Radio[RADIO5G]' -> 'RADIO5G'."""
    m = re.search(r"\[(?:Alias=)?['\"]?([^'\"\]]+)['\"]?\]$", path or "")
    return m.group(1) if m else ""


def q(value: str) -> str:
    """Quote a value for an xpath predicate."""
    return '"' + value.replace('"', "") + '"'


def as_list(v: Any) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def scalars(d: dict) -> dict:
    return {k: v for k, v in d.items() if not isinstance(v, (dict, list))}


def parse_value(raw: str, kind: str) -> Any:
    match kind:
        case "str":
            return raw
        case "int":
            return int(raw)
        case "bool":
            if raw.lower() in ("1", "true", "yes", "on"):
                return True
            if raw.lower() in ("0", "false", "no", "off"):
                return False
            raise click.BadParameter(f"not a boolean: {raw}")
        case "json":
            return json.loads(raw)
    # auto: JSON literal if it parses (true, 5, {"a":1}), else plain string
    try:
        return json.loads(raw)
    except ValueError:
        return raw


def parse_kv(pairs: tuple[str, ...]) -> dict:
    params = {}
    for p in pairs:
        if "=" not in p:
            raise click.BadParameter(f"expected key=value, got {p!r}")
        k, _, v = p.partition("=")
        params[k] = parse_value(v, "auto")
    return params


def mac_norm(mac: str) -> str:
    return mac.strip().lower().replace("-", ":")


MAC_RE = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.IGNORECASE)


class AgentGroup(click.Group):
    def invoke(self, ctx: click.Context) -> Any:
        try:
            return super().invoke(ctx)
        except CliError as e:
            emit_error(e.kind, str(e), **e.extra)
            ctx.exit(e.code)
        except AuthError as e:
            emit_error("auth", str(e), code=e.code)
            ctx.exit(EXIT_AUTH)
        except XmoError as e:
            emit_error("router", e.description, code=e.code, xpath=e.xpath)
            ctx.exit(EXIT_ROUTER)
        except httpx.HTTPError as e:
            emit_error("network", f"{type(e).__name__}: {e}")
            ctx.exit(EXIT_NETWORK)
        except (ValueError, json.JSONDecodeError) as e:
            emit_error("usage", str(e))
            ctx.exit(EXIT_USAGE)
        finally:
            c = (ctx.obj or {}).get("client")
            if c is not None:
                c.close()


# ---------------------------------------------------------------- root


@click.group(cls=AgentGroup, context_settings={"help_option_names": ["-h", "--help"], "max_content_width": 110})
@click.option("--host", envvar="SALTROUTER_HOST", default="192.168.1.1", show_default=True, help="Router address.")
@click.option("--user", "-u", envvar="SALTROUTER_USER", default="admin", show_default=True, help="GUI username.")
@click.option("--password", "-p", help="GUI password (prefer env SALTROUTER_PASSWORD / SALTROUTER_PW or .env).")
@click.option("--env-file", type=click.Path(dir_okay=False), help="Extra .env file to load.")
@click.option("--timeout", type=float, default=30.0, show_default=True, help="HTTP timeout in seconds.")
@click.option("--no-cache", is_flag=True, help="Do not reuse the cached router session.")
@output_options
@click.version_option(__version__, "-V", "--version")
@click.pass_context
def cli(ctx: click.Context, host, user, password, env_file, timeout, no_cache):
    """Control a Salt Fiber Box (Sagemcom F@st / XMO API) router. Agent-first: JSON out, flags anywhere.

    \b
    Start here:  saltrouter status | saltrouter commands | saltrouter paths wifi
    Raw access:  get / tree / describe / set / add / delete / rpc / batch
    """
    if env_file:
        load_env_files(env_file)
        src = click.core.ParameterSource.DEFAULT
        if ctx.get_parameter_source("host") == src:
            host = os.environ.get("SALTROUTER_HOST", host)
        if ctx.get_parameter_source("user") == src:
            user = os.environ.get("SALTROUTER_USER", user)
    ctx.ensure_object(dict)
    ctx.obj.update(host=host, user=user, password=password, timeout=timeout, no_cache=no_cache, client=None)


# ---------------------------------------------------------------- discovery


@cli.command("commands")
@output_options
def commands_cmd():
    """Machine-readable list of every command with its arguments and options."""

    def walk(cmd: click.Command, prefix: str) -> list[dict]:
        if isinstance(cmd, click.Group):
            rows = []
            for name in cmd.list_commands(click.get_current_context()):
                rows += walk(cmd.get_command(click.get_current_context(), name), f"{prefix} {name}".strip())
            return rows
        args, opts = [], []
        for p in cmd.params:
            if p.name in ("fmt", "fields", "where", "limit", "show_secrets"):
                continue
            if isinstance(p, click.Argument):
                args.append(p.name.upper() + ("..." if p.nargs == -1 else "") + ("" if p.required else "?"))
            else:
                o = "/".join(p.opts + p.secondary_opts)
                if isinstance(p.type, click.Choice):
                    o += "=" + "|".join(map(str, p.type.choices))
                elif not getattr(p, "is_flag", False):
                    o += "=" + p.type.name.upper()
                opts.append(o)
        return [{"cmd": prefix, "args": args, "opts": opts, "help": (cmd.help or "").strip().split("\n")[0]}]

    out(walk(cli, ""))


def _catalog() -> dict[str, str]:
    return json.loads(resources.files("saltrouter_cli").joinpath("data/gui_xpaths.json").read_text())


@cli.command("paths")
@click.argument("terms", nargs=-1)
@output_options
def paths_cmd(terms):
    """Search the xpath catalog extracted from the router web GUI (~3.4k named xpaths).

    All TERMS must match (case-insensitive) the catalog name or the xpath. '#', '#X#' and '$' in
    xpaths are placeholders the GUI fills in (usually a uid or Alias).
    """
    terms = [t.lower() for t in terms]
    rows = [
        {"name": k, "xpath": v} for k, v in _catalog().items() if all(t in k.lower() or t in v.lower() for t in terms)
    ]
    out(rows)


# ---------------------------------------------------------------- raw XMO access


@cli.command("get")
@click.argument("xpaths", nargs=-1, required=True)
@output_options
def get_cmd(xpaths):
    """Read one or more xpaths in a single request (e.g. Device/DeviceInfo/UpTime).

    Predicates work: 'Device/Hosts/Hosts/Host[Active="true"]/HostName' returns a list.
    With several XPATHS the result is {xpath: value}.
    """
    results = client().request([get_action(x) for x in xpaths], raise_on_error=len(xpaths) == 1)
    if len(xpaths) == 1:
        out(results[0]["value"])
    else:
        out({r["xpath"]: (r["value"] if r["ok"] else {"error": r["error"]["description"]}) for r in results})


@cli.command("tree")
@click.argument("xpath", default="Device")
@click.option("-d", "--depth", type=int, default=1, show_default=True, help="Levels to expand.")
@output_options
def tree_cmd(xpath, depth):
    """Shape of a subtree: scalars inline, containers collapsed (cheap way to explore the data model)."""
    out(summarize(client().get(xpath), depth))


@cli.command("describe")
@click.argument("xpaths", nargs=-1, required=True)
@output_options
def describe_cmd(xpaths):
    """Value + type, writability and allowed enum values for leaf xpaths (use before `set`)."""
    rows = []
    for r in client().request([get_action(x) for x in xpaths], raise_on_error=False):
        if not r["ok"]:
            rows.append({"xpath": r["xpath"], "error": r["error"]["description"]})
            continue
        cap = r.get("capability") or {}
        flags = cap.get("flags", {})
        types = [t.removeprefix("xmo:") for t in cap.get("type", "").split() if t.startswith("xmo:")]
        row = {
            "xpath": r["xpath"],
            "value": r["value"] if not isinstance(r["value"], (dict, list)) else "<node>",
            "type": types[0] if types else None,
            "writable": bool(flags.get("config")) and not flags.get("read-only"),
            "kind": next((k for k in ("statistic", "key", "config") if flags.get(k)), None),
        }
        enum = (cap.get("restrictions") or {}).get("enum-values")
        if enum:
            row["enum"] = [e["name"] for e in enum]
        for k in ("min-value", "max-value", "min-length", "max-length", "pattern"):
            if k in (cap.get("restrictions") or {}):
                row[k] = cap["restrictions"][k]
        if "default-value" in cap:
            row["default"] = cap["default-value"]
        rows.append(row)
    out(rows[0] if len(rows) == 1 else rows)


@cli.command("set")
@click.argument("xpath")
@click.argument("value")
@click.option(
    "-t",
    "--type",
    "kind",
    type=click.Choice(["auto", "str", "int", "bool", "json"]),
    default="auto",
    show_default=True,
    help="How to parse VALUE (auto = JSON literal if valid, else string).",
)
@write_options
@output_options
def set_cmd(xpath, value, kind, dry_run):
    """Set a leaf value (setValue). Check `describe XPATH` for type/enum first."""
    run_write([set_action(xpath, parse_value(value, kind))], dry_run)


@cli.command("add")
@click.argument("xpath")
@click.argument("value_json")
@click.option("--uid", type=int, help="Explicit uid for the new child.")
@write_options
@output_options
def add_cmd(xpath, value_json, uid, dry_run):
    """Add a child to a list (addChild). VALUE_JSON is wrapped by type, e.g. '{"PortMapping":{...}}'."""
    run_write([add_action(xpath, json.loads(value_json), uid)], dry_run)


@cli.command("delete")
@click.argument("xpath")
@write_options
@confirm_option
@output_options
def delete_cmd(xpath, dry_run, yes):
    """Delete a list element (deleteChild), e.g. 'Device/NAT/PortMappings/PortMapping[@uid="3"]'."""
    run_write([delete_action(xpath)], dry_run, yes=yes, what="delete")


@cli.command("rpc")
@click.argument("xpath")
@click.argument("method")
@click.argument("params", nargs=-1)
@click.option("--json", "params_json", help="Parameters as a JSON object (instead of key=value args).")
@write_options
@confirm_option
@output_options
def rpc_cmd(xpath, method, params, params_json, dry_run, yes):
    """Call an RPC method on an xpath, e.g. `rpc Device nslookup Host=example.com`.

    Known methods: reboot, reinitialize, ping, pingCancel, traceRoute, nslookup, arping, scanWifi,
    DhcpServerList, restoreNodes, tcpdump, startWPS, generatePinCode, changeClearPassword,
    getVendorLogDownloadURI, speedTestClient, SpeedTestGetServersList, restartConnection, testPhones.
    reboot/reinitialize require --yes.
    """
    p = json.loads(params_json) if params_json else parse_kv(params)
    destructive = method in ("reboot", "reinitialize")
    run_write(
        [action(method, xpath, {"source": "GUI"} if method == "reboot" else p)],
        dry_run,
        yes=yes if destructive else None,
        what=method,
    )


@cli.command("batch")
@click.argument("file", type=click.File("r"), default="-")
@write_options
@confirm_option
@output_options
def batch_cmd(file, dry_run, yes):
    """Send a JSON array of actions in one request (from FILE or stdin).

    Each action: {"method": "getValue|setValue|addChild|deleteChild|<rpc>", "xpath": "...", "parameters": {...}}.
    Returns per-action results. Batches containing deleteChild/reboot/reinitialize need --yes.
    """
    actions = json.load(file)
    if not isinstance(actions, list):
        raise click.BadParameter("batch input must be a JSON array of actions")
    if dry_run:
        out({"dry_run": True, "actions": actions})
        return
    if any(a.get("method") in ("deleteChild", "reboot", "reinitialize") for a in actions) and not yes:
        raise CliError("confirmation_required", "batch contains destructive actions; re-run with --yes", EXIT_CONFIRM)
    res = client().request(actions, raise_on_error=False)
    out([{k: v for k, v in r.items() if k != "capability"} for r in res])


# ---------------------------------------------------------------- session


@cli.command("login")
@output_options
def login_cmd():
    """Verify credentials and open (and cache) a session."""
    c = client()
    s = c.login()
    out({"ok": True, "host": c.base_url, "user": c.username, "session_id": s.session_id})


@cli.command("logout")
@output_options
def logout_cmd():
    """Close the cached router session."""
    client().logout()
    out({"ok": True})


# ---------------------------------------------------------------- overview


def _hosts_raw() -> list[dict]:
    return as_list(client().get("Device/Hosts/Hosts"))


def host_name(h: dict) -> str:
    ufn = h.get("UserFriendlyName") or ""
    if ufn and not MAC_RE.match(ufn):
        return ufn
    return h.get("HostName") or h.get("UserHostName") or ufn or h.get("PhysAddress", "")


def host_row(h: dict) -> dict:
    link = h.get("InterfaceType", "")
    ap = ref(h.get("AssociatedDevice", "").split("/AssociatedDevices")[0]) if h.get("AssociatedDevice") else ""
    return {
        "uid": h.get("uid"),
        "name": host_name(h),
        "ip": h.get("IPAddress"),
        "mac": h.get("PhysAddress"),
        "active": h.get("Active"),
        "link": f"{link}:{ap}" if ap else link,
        "src": h.get("AddressSource"),
        "type": h.get("UserDeviceType") or h.get("DetectedDeviceType"),
        "lease_s": h.get("LeaseTimeRemaining"),
    }


@cli.command("status")
@output_options
def status_cmd():
    """One-shot health summary: device, uptime, WAN, fiber signal, Wi-Fi, clients, CPU/memory."""
    v = client().get_many(
        {
            "info": "Device/DeviceInfo",
            "wan": 'Device/IP/Interfaces/Interface[Alias="IP_DATA"]',
            "optical": 'Device/Optical/Interfaces/Interface[@uid="1"]',
            "ssids": "Device/WiFi/SSIDs",
            "hosts": "Device/Hosts/Hosts",
        }
    )
    info, wan, opt = v["info"] or {}, v["wan"] or {}, v["optical"] or {}
    v4 = (wan.get("IPv4Addresses") or [{}])[0]
    pfx = [p.get("Prefix") for p in wan.get("IPv6Prefixes", []) if p.get("Prefix")]
    mem = info.get("MemoryStatus", {})
    hosts = as_list(v["hosts"])
    out(
        {
            "model": info.get("ModelName"),
            "fw": info.get("SoftwareVersion"),
            "serial": info.get("SerialNumber"),
            "uptime_s": info.get("UpTime"),
            "reboots": info.get("RebootCount"),
            "cpu_pct": info.get("ProcessStatus", {}).get("CPUUsage"),
            "mem_used_pct": round(100 * (1 - mem.get("Available", 0) / mem["Total"]), 1) if mem.get("Total") else None,
            "temp_c": (info.get("TemperatureStatus", {}).get("TemperatureSensors") or [{}])[0].get("Value"),
            "wan": {
                "status": wan.get("Status"),
                "ipv4": v4.get("IPAddress"),
                "gw": v4.get("IPGateway"),
                "dns": v4.get("Dns"),
                "ipv6_prefix": pfx,
            },
            "fiber": {
                "status": opt.get("Status"),
                "rx_dbm": _milli(opt.get("OpticalSignalLevel")),
                "tx_dbm": _milli(opt.get("TransmitOpticalLevel")),
                "alarm": opt.get("Alarm"),
            },
            "wifi": [
                {"alias": s.get("Alias"), "ssid": s.get("SSID"), "on": s.get("Enable"), "status": s.get("Status")}
                for s in as_list(v["ssids"])
            ],
            "hosts_active": sum(1 for h in hosts if h.get("Active")),
            "hosts_known": len(hosts),
        }
    )


def _milli(x: Any, digits: int = 2) -> float | None:
    return round(x / 1000, digits) if isinstance(x, (int, float)) else None


@cli.command("info")
@click.option("--processes", is_flag=True, help="Include the process table.")
@output_options
def info_cmd(processes):
    """Device identity, firmware, uptime, memory and temperatures."""
    info = client().get("Device/DeviceInfo")
    row = scalars(info)
    row["MemoryStatus"] = info.get("MemoryStatus")
    row["CPUUsage"] = info.get("ProcessStatus", {}).get("CPUUsage")
    row["Temperatures"] = [s.get("Value") for s in info.get("TemperatureStatus", {}).get("TemperatureSensors", [])]
    if processes:
        row["Processes"] = [
            {k: p.get(k) for k in ("PID", "Command", "Size", "CPUTime", "State")}
            for p in info.get("ProcessStatus", {}).get("Processes", [])
        ]
    out(row)


# ---------------------------------------------------------------- hosts


@cli.command("hosts")
@click.option("-a", "--all", "show_all", is_flag=True, help="Include inactive/remembered hosts.")
@click.option("--raw", is_flag=True, help="Full router objects instead of the compact rows.")
@output_options
def hosts_cmd(show_all, raw):
    """Connected devices (active only unless --all)."""
    hosts = [h for h in _hosts_raw() if show_all or h.get("Active")]
    out(hosts if raw else [host_row(h) for h in hosts])


def resolve_host(ident: str) -> dict:
    hosts = _hosts_raw()
    i = ident.strip()
    for pred in (
        lambda h: i.isdigit() and str(h.get("uid")) == i,
        lambda h: mac_norm(h.get("PhysAddress", "")) == mac_norm(i),
        lambda h: h.get("IPAddress") == i,
        lambda h: host_name(h).lower() == i.lower(),
        lambda h: (h.get("HostName") or "").lower() == i.lower(),
    ):
        found = sorted((h for h in hosts if pred(h)), key=lambda h: not h.get("Active"))
        if found:
            return found[0]
    raise not_found("host", ident)


@cli.group("host")
def host_grp():
    """Inspect or modify one host (ID = uid, MAC, IP or name)."""


@host_grp.command("show")
@click.argument("ident")
@output_options
def host_show(ident):
    """Full details for one host."""
    out(resolve_host(ident))


@host_grp.command("rename")
@click.argument("ident")
@click.argument("name")
@write_options
@output_options
def host_rename(ident, name, dry_run):
    """Set the friendly name shown in the GUI."""
    h = resolve_host(ident)
    run_write([set_action(f'Device/Hosts/Hosts/Host[@uid="{h["uid"]}"]/UserFriendlyName', name)], dry_run)


@host_grp.command("set-type")
@click.argument("ident")
@click.argument("device_type")
@write_options
@output_options
def host_set_type(ident, device_type, dry_run):
    """Set the device type/icon (e.g. COMPUTER, SMARTPHONE, TV, PRINTER, MISCELLANEOUS)."""
    h = resolve_host(ident)
    run_write([set_action(f'Device/Hosts/Hosts/Host[@uid="{h["uid"]}"]/UserDeviceType', device_type)], dry_run)


@host_grp.command("forget")
@click.argument("ident")
@write_options
@confirm_option
@output_options
def host_forget(ident, dry_run, yes):
    """Remove a (usually inactive) host from the device list."""
    h = resolve_host(ident)
    run_write([delete_action(f'Device/Hosts/Hosts/Host[@uid="{h["uid"]}"]')], dry_run, yes=yes, what="host forget")


# ---------------------------------------------------------------- wifi


def _wifi_raw() -> dict:
    return client().get_many(
        {"ssids": "Device/WiFi/SSIDs", "aps": "Device/WiFi/AccessPoints", "radios": "Device/WiFi/Radios"},
        raise_on_error=True,
    )


def _wifi_rows(raw: dict) -> list[dict]:
    radios = {r.get("Alias"): r for r in as_list(raw["radios"])}
    aps = {ref(a.get("SSIDReference", "")): a for a in as_list(raw["aps"])}
    rows = []
    for s in as_list(raw["ssids"]):
        ap = aps.get(s.get("Alias"), {})
        radio = radios.get(ref(s.get("LowerLayers", "")), {})
        sec = ap.get("Security", {})
        rows.append(
            {
                "alias": s.get("Alias"),
                "ap": ap.get("Alias"),
                "radio": radio.get("Alias"),
                "band": radio.get("OperatingFrequencyBand"),
                "ssid": s.get("SSID"),
                "enabled": s.get("Enable"),
                "status": s.get("Status"),
                "hidden": not ap.get("SSIDAdvertisementEnabled", True),
                "security": sec.get("ModeEnabled"),
                "password": sec.get("KeyPassphrase"),
                "channel": radio.get("Channel"),
                "bandwidth": radio.get("OperatingChannelBandwidth"),
                "clients": sum(1 for d in ap.get("AssociatedDevices", []) if d.get("Active")),
                "bssid": s.get("BSSID"),
            }
        )
    return rows


def resolve_wifi(ident: str, rows: list[dict]) -> dict:
    for r in rows:
        if ident.lower() in {str(r["alias"]).lower(), str(r["ap"]).lower(), str(r["ssid"]).lower()}:
            return r
    raise not_found("wifi network", ident, known=[r["alias"] for r in rows])


@cli.group("wifi")
def wifi_grp():
    """Wi-Fi networks (SSID/access point), radios, clients, WPS, neighbor scan."""


@wifi_grp.command("list")
@output_options
def wifi_list():
    """All SSIDs joined with their access point and radio settings."""
    out(_wifi_rows(_wifi_raw()))


@wifi_grp.command("show")
@click.argument("ident")
@output_options
def wifi_show(ident):
    """One network by SSID alias (WL_PRIV_5G), AP alias (PRIV1) or SSID name."""
    out(resolve_wifi(ident, _wifi_rows(_wifi_raw())))


@wifi_grp.command("set")
@click.argument("ident")
@click.option("--ssid", help="New network name.")
@click.option("--password", "passphrase", help="New WPA passphrase.")
@click.option("--security", help="Security mode, e.g. WPA2_PERSONAL, WPA2_WPA3_PERSONAL, WPA3_PERSONAL, NONE.")
@click.option("--enable/--disable", default=None, help="Turn the network on/off.")
@click.option("--hidden/--visible", default=None, help="Hide/broadcast the SSID.")
@click.option("--isolation/--no-isolation", default=None, help="Client isolation.")
@click.option("--wps/--no-wps", default=None, help="Allow WPS.")
@write_options
@output_options
def wifi_set(ident, ssid, passphrase, security, enable, hidden, isolation, wps, dry_run):
    """Change SSID, password, security, visibility or on/off state of one network."""
    r = resolve_wifi(ident, _wifi_rows(_wifi_raw()))
    s = f"Device/WiFi/SSIDs/SSID[Alias={q(r['alias'])}]"
    a = f"Device/WiFi/AccessPoints/AccessPoint[Alias={q(r['ap'])}]"
    acts = []
    if ssid is not None:
        acts.append(set_action(f"{s}/SSID", ssid))
    if passphrase is not None:
        acts.append(set_action(f"{a}/Security/KeyPassphrase", passphrase))
    if security is not None:
        acts.append(set_action(f"{a}/Security/ModeEnabled", security.upper()))
    if enable is not None:
        acts.append(set_action(f"{s}/Enable", enable))
    if hidden is not None:
        acts.append(set_action(f"{a}/SSIDAdvertisementEnabled", not hidden))
    if isolation is not None:
        acts.append(set_action(f"{a}/IsolationEnable", isolation))
    if wps is not None:
        acts.append(set_action(f"{a}/WPS/Enable", wps))
    if not acts:
        raise click.UsageError("nothing to change; pass at least one option")
    run_write(acts, dry_run)


@wifi_grp.command("radios")
@output_options
def wifi_radios():
    """Radio settings (band, channel, bandwidth, standards, power)."""
    keys = (
        "Alias",
        "Enable",
        "Status",
        "OperatingFrequencyBand",
        "OperatingStandards",
        "Channel",
        "AutoChannelEnable",
        "OperatingChannelBandwidth",
        "CurrentOperatingChannelBandwidth",
        "ChannelsInUse",
        "PossibleChannels",
        "TransmitPower",
        "MaxBitRate",
        "RegulatoryDomain",
    )
    out([{k: r.get(k) for k in keys if k in r} for r in as_list(client().get("Device/WiFi/Radios"))])


@wifi_grp.command("radio-set")
@click.argument("radio")
@click.option("--channel", help="Channel number or 'auto'.")
@click.option("--bandwidth", help="20MHZ | 40MHZ | 80MHZ | 160MHZ | AUTO.")
@click.option("--enable/--disable", default=None, help="Turn the whole radio on/off.")
@click.option("--power", type=int, help="Transmit power percent (-1 = auto).")
@write_options
@output_options
def wifi_radio_set(radio, channel, bandwidth, enable, power, dry_run):
    """Change a radio (RADIO2G4 / RADIO5G): channel, bandwidth, power, on/off."""
    x = f"Device/WiFi/Radios/Radio[Alias={q(radio)}]"
    acts = []
    if channel is not None:
        if channel.lower() == "auto":
            acts.append(set_action(f"{x}/AutoChannelEnable", True))
        else:
            acts += [set_action(f"{x}/AutoChannelEnable", False), set_action(f"{x}/Channel", int(channel))]
    if bandwidth is not None:
        acts.append(set_action(f"{x}/OperatingChannelBandwidth", bandwidth.upper()))
    if enable is not None:
        acts.append(set_action(f"{x}/Enable", enable))
    if power is not None:
        acts.append(set_action(f"{x}/TransmitPower", power))
    if not acts:
        raise click.UsageError("nothing to change; pass at least one option")
    run_write(acts, dry_run)


@wifi_grp.command("clients")
@click.option("-a", "--all", "show_all", is_flag=True, help="Include inactive associations.")
@output_options
def wifi_clients(show_all):
    """Wireless clients with signal, rates and resolved host names."""
    v = client().get_many(
        {"aps": "Device/WiFi/AccessPoints", "hosts": "Device/Hosts/Hosts", "ssids": "Device/WiFi/SSIDs"},
        raise_on_error=True,
    )
    names = {mac_norm(h.get("PhysAddress", "")): host_name(h) for h in as_list(v["hosts"])}
    ips = {mac_norm(h.get("PhysAddress", "")): h.get("IPAddress") for h in as_list(v["hosts"])}
    ssid_by_alias = {s.get("Alias"): s.get("SSID") for s in as_list(v["ssids"])}
    rows = []
    for ap in as_list(v["aps"]):
        for d in ap.get("AssociatedDevices", []):
            if not (show_all or d.get("Active")):
                continue
            mac = mac_norm(d.get("MACAddress", ""))
            rows.append(
                {
                    "name": names.get(mac, ""),
                    "mac": mac,
                    "ip": d.get("IPAddress") or ips.get(mac),
                    "ap": ap.get("Alias"),
                    "ssid": ssid_by_alias.get(ref(ap.get("SSIDReference", ""))),
                    "signal_dbm": d.get("SignalStrength"),
                    "down_kbps": d.get("LastDataDownlinkRate"),
                    "up_kbps": d.get("LastDataUplinkRate"),
                    "std": d.get("OperatingStandard"),
                    "active": d.get("Active"),
                }
            )
    out(rows)


@wifi_grp.command("wps")
@click.argument("ident")
@write_options
@output_options
def wifi_wps(ident, dry_run):
    """Start WPS push-button pairing on a network."""
    r = resolve_wifi(ident, _wifi_rows(_wifi_raw()))
    run_write([action("startWPS", f"Device/WiFi/AccessPoints/AccessPoint[Alias={q(r['ap'])}]", {})], dry_run)


@wifi_grp.command("scan")
@click.argument("radio", default="RADIO2G4")
@write_options
@output_options
def wifi_scan(radio, dry_run):
    """Trigger a neighbor AP scan on a radio (briefly disturbs Wi-Fi); read results with `wifi neighbors`."""
    run_write([action("scanWifi", "Device", {"Radio": radio})], dry_run)


@wifi_grp.command("neighbors")
@output_options
def wifi_neighbors():
    """Results of the last neighbor scan."""
    out(client().get("Device/WiFi/NeighboringWiFiDiagnostic"))


# ---------------------------------------------------------------- wan / fiber / lan


@cli.command("wan")
@click.option("--raw", is_flag=True, help="Full IP_DATA interface object.")
@output_options
def wan_cmd(raw):
    """Internet interface: addresses, gateway, DNS, IPv6 prefix, traffic counters."""
    w = client().get('Device/IP/Interfaces/Interface[Alias="IP_DATA"]')
    if raw:
        out(w)
        return
    v4 = [scalars(a) for a in w.get("IPv4Addresses", [])]
    out(
        {
            "status": w.get("Status"),
            "ifname": w.get("IfcName"),
            "link_up_s": w.get("LastChange"),
            "ipv4": [
                {k: a.get(k) for k in ("IPAddress", "SubnetMask", "IPGateway", "Dns", "AddressingType", "Status")}
                for a in v4
            ],
            "ipv6": [
                {k: a.get(k) for k in ("IPAddress", "Origin", "IPAddressStatus")} for a in w.get("IPv6Addresses", [])
            ],
            "ipv6_prefixes": [
                {k: p.get(k) for k in ("Prefix", "Origin", "PrefixStatus")} for p in w.get("IPv6Prefixes", [])
            ],
            "stats": {
                k: w.get("Stats", {}).get(k)
                for k in (
                    "BytesSent",
                    "BytesReceived",
                    "ErrorsSent",
                    "ErrorsReceived",
                    "DiscardPacketsSent",
                    "DiscardPacketsReceived",
                )
            },
        }
    )


@cli.command("fiber")
@output_options
def fiber_cmd():
    """Optical (GPON/XGS-PON) module: rx/tx power in dBm, temperature, voltage, bias, alarms."""
    v = client().get_many({"o": 'Device/Optical/Interfaces/Interface[@uid="1"]', "g": "Device/Optical/G988"})
    o, g = v["o"] or {}, v["g"] or {}
    em = g.get("EquipmentManagement", {})
    out(
        {
            "status": o.get("Status"),
            "alarm": o.get("Alarm"),
            "rx_dbm": _milli(o.get("OpticalSignalLevel"), 3),
            "tx_dbm": _milli(o.get("TransmitOpticalLevel"), 3),
            "temp_c": _milli(o.get("Temperature"), 1),
            "voltage_v": round(o["Voltage"] / 1e6, 3) if isinstance(o.get("Voltage"), int) else None,
            "bias_ma": _milli(o.get("BIASCurrent"), 2),
            "vendor": o.get("OpticalVendorName"),
            "part": o.get("OpticalPartNumber"),
            "last_change_s": o.get("LastChange"),
            "onu_state": g.get("GponState"),
            "onu_mode": g.get("OnuMode"),
            "olt_vendor": _hexstr(g.get("General", {}).get("OltG", {}).get("OltVendorId")),
            "onu_serial": em.get("OnuG", {}).get("SerialNumber"),
            "images": [
                {"version": _hexstr(i.get("Version")), "active": i.get("IsActive"), "committed": i.get("IsCommitted")}
                for i in em.get("SoftwareImages", [])
            ],
        }
    )


def _hexstr(v: Any) -> Any:
    """G.988 fields are hex-encoded ASCII (e.g. '414c434c' -> 'ALCL')."""
    try:
        return bytes.fromhex(v).decode("ascii").strip() if isinstance(v, str) and v else v
    except ValueError:
        return v


POOL = 'Device/DHCPv4/Server/Pools/Pool[Alias="DEFAULT_POOL"]'
POOL_KEYS = (
    "Enable",
    "Status",
    "IPInterface",
    "MinAddress",
    "MaxAddress",
    "SubnetMask",
    "IPRouters",
    "DNSServers",
    "DomainName",
    "LeaseTime",
)


@cli.command("lan")
@output_options
def lan_cmd():
    """LAN address and DHCP server configuration."""
    v = client().get_many(
        {
            "lan": 'Device/IP/Interfaces/Interface[Alias="IP_BR_LAN"]/IPv4Addresses',
            "pool": POOL,
            "dhcp": "Device/DHCPv4/Server/Enable",
        },
        raise_on_error=True,
    )
    pool = v["pool"] or {}
    out(
        {
            "ipv4": [{k: a.get(k) for k in ("IPAddress", "SubnetMask", "AddressingType")} for a in as_list(v["lan"])],
            "dhcp_server": v["dhcp"],
            "pool": {k: pool.get(k) for k in POOL_KEYS},
        }
    )


# ---------------------------------------------------------------- dhcp


@cli.group("dhcp")
def dhcp_grp():
    """DHCP leases, static reservations and pool settings."""


@dhcp_grp.command("leases")
@click.option("-a", "--all", "show_all", is_flag=True, help="Include expired leases.")
@output_options
def dhcp_leases(show_all):
    """Current DHCP leases with host names."""
    v = client().get_many({"clients": f"{POOL}/Clients", "hosts": "Device/Hosts/Hosts"}, raise_on_error=True)
    hosts = {mac_norm(h.get("PhysAddress", "")): h for h in as_list(v["hosts"])}
    rows = []
    for c in as_list(v["clients"]):
        if not (show_all or c.get("Active")):
            continue
        addr = (c.get("IPv4Addresses") or [{}])[0]
        mac = mac_norm(c.get("Chaddr", ""))
        h = hosts.get(mac, {})
        rows.append(
            {
                "name": host_name(h) if h else "",
                "ip": addr.get("IPAddress"),
                "mac": mac,
                "lease_s": h.get("LeaseTimeRemaining"),
                "active": c.get("Active"),
            }
        )
    out(rows)


def _reservations() -> list[dict]:
    return as_list(client().get(f"{POOL}/StaticAddresses"))


@dhcp_grp.command("reservations")
@output_options
def dhcp_reservations():
    """Static IP reservations (MAC -> IP)."""
    out(
        [
            {"alias": r.get("Alias"), "mac": r.get("Chaddr"), "ip": r.get("Yiaddr"), "enabled": r.get("Enable")}
            for r in _reservations()
        ]
    )


@dhcp_grp.command("reserve")
@click.argument("mac")
@click.argument("ip")
@write_options
@output_options
def dhcp_reserve(mac, ip, dry_run):
    """Reserve IP for MAC (MAC may also be a host name/IP known to the router)."""
    if not MAC_RE.match(mac):
        mac = resolve_host(mac)["PhysAddress"]
    run_write(
        [
            add_action(
                f"{POOL}/StaticAddresses",
                {"StaticAddress": {"Enable": True, "Yiaddr": ip, "Chaddr": mac.upper().replace("-", ":")}},
            )
        ],
        dry_run,
    )


@dhcp_grp.command("unreserve")
@click.argument("ident")
@write_options
@confirm_option
@output_options
def dhcp_unreserve(ident, dry_run, yes):
    """Delete a reservation by alias, MAC or IP."""
    for r in _reservations():
        if ident in (r.get("Alias"), r.get("Yiaddr")) or mac_norm(r.get("Chaddr", "")) == mac_norm(ident):
            run_write(
                [delete_action(f"{POOL}/StaticAddresses/StaticAddress[Alias={q(r['Alias'])}]")],
                dry_run,
                yes=yes,
                what="dhcp unreserve",
            )
            return
    raise not_found("reservation", ident)


@dhcp_grp.command("set")
@click.option("--enable/--disable", default=None, help="DHCP server on/off.")
@click.option("--start", help="First address of the pool.")
@click.option("--end", help="Last address of the pool.")
@click.option("--lease-time", type=int, help="Lease time in seconds.")
@click.option("--dns", help="DNS servers handed out (comma-separated).")
@click.option("--domain", help="Domain name handed out.")
@write_options
@output_options
def dhcp_set(enable, start, end, lease_time, dns, domain, dry_run):
    """Change DHCP server/pool settings."""
    acts = []
    if enable is not None:
        acts.append(set_action("Device/DHCPv4/Server/Enable", enable))
    for key, val in (
        ("MinAddress", start),
        ("MaxAddress", end),
        ("LeaseTime", lease_time),
        ("DNSServers", dns),
        ("DomainName", domain),
    ):
        if val is not None:
            acts.append(set_action(f"{POOL}/{key}", val))
    if not acts:
        raise click.UsageError("nothing to change; pass at least one option")
    run_write(acts, dry_run)


# ---------------------------------------------------------------- nat / port forwarding / dmz

PM = "Device/NAT/PortMappings"
WAN_IF = "Device/IP/Interfaces/Interface[IP_DATA]"


def _mappings() -> list[dict]:
    return as_list(client().get(PM))


def pm_row(m: dict) -> dict:
    ext = str(m.get("ExternalPort"))
    if m.get("ExternalPortEndRange") and m.get("ExternalPortEndRange") != m.get("ExternalPort"):
        ext += f"-{m['ExternalPortEndRange']}"
    return {
        "uid": m.get("uid"),
        "alias": m.get("Alias"),
        "desc": m.get("Description"),
        "enabled": m.get("Enable"),
        "status": m.get("Status"),
        "proto": m.get("Protocol"),
        "ext_port": ext,
        "int_port": m.get("InternalPort"),
        "ip": m.get("InternalClient"),
        "remote": m.get("RemoteHost") or None,
        "service": m.get("Service"),
        "creator": m.get("Creator"),
    }


@cli.group("portfw")
def portfw_grp():
    """IPv4 port forwarding rules (NAT port mappings)."""


@portfw_grp.command("list")
@click.option("-a", "--all", "show_all", is_flag=True, help="Include DMZ and UPnP-created mappings.")
@output_options
def portfw_list(show_all):
    """Port forwarding rules."""
    rows = [
        pm_row(m)
        for m in _mappings()
        if show_all or (m.get("Service") != "DMZ" and m.get("Creator") not in ("UPNP", "HIDDEN"))
    ]
    out(rows)


def _port_range(spec: str) -> tuple[int, int]:
    a, _, b = spec.partition("-")
    return int(a), int(b or a)


@portfw_grp.command("add")
@click.option("--ip", required=True, help="LAN target (IP, or host name/MAC known to the router).")
@click.option("--ext-port", required=True, help="External port or range, e.g. 443 or 5000-5010.")
@click.option("--int-port", type=int, help="Internal (start) port; defaults to the external start port.")
@click.option(
    "--proto", type=click.Choice(["TCP", "UDP", "BOTH"], case_sensitive=False), default="BOTH", show_default=True
)
@click.option("--desc", default="", help="Description / service name.")
@click.option("--remote-host", default="", help="Only allow this source IP.")
@click.option("--disabled", is_flag=True, help="Create the rule disabled.")
@write_options
@output_options
def portfw_add(ip, ext_port, int_port, proto, desc, remote_host, disabled, dry_run):
    """Create a port forwarding rule."""
    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        ip = resolve_host(ip).get("IPAddress")
    start, end = _port_range(ext_port)
    nums = [int(m.group(1)) for x in _mappings() if (m := re.match(r"PORTFW_RULE_(\d+)$", x.get("Alias", "")))]
    rule = {
        "Enable": not disabled,
        "Service": desc,
        "Protocol": proto.upper(),
        "Description": desc,
        "RemoteHost": remote_host,
        "InternalClient": ip,
        "ExternalPort": start,
        "ExternalPortEndRange": end,
        "InternalPort": int_port or start,
        "ExternalInterface": WAN_IF,
        "Alias": f"PORTFW_RULE_{max(nums, default=0) + 1}",
    }
    if not desc:
        del rule["Description"]
    run_write([add_action(PM, {"PortMapping": rule})], dry_run)


def _pm_xpath(uid: int) -> str:
    return f'{PM}/PortMapping[@uid="{uid}"]'


@portfw_grp.command("rm")
@click.argument("uids", nargs=-1, type=int, required=True)
@write_options
@confirm_option
@output_options
def portfw_rm(uids, dry_run, yes):
    """Delete rules by uid (see `portfw list`)."""
    run_write([delete_action(_pm_xpath(u)) for u in uids], dry_run, yes=yes, what="portfw rm")


@portfw_grp.command("enable")
@click.argument("uids", nargs=-1, type=int, required=True)
@write_options
@output_options
def portfw_enable(uids, dry_run):
    """Enable rules by uid."""
    run_write([set_action(f"{_pm_xpath(u)}/Enable", True) for u in uids], dry_run)


@portfw_grp.command("disable")
@click.argument("uids", nargs=-1, type=int, required=True)
@write_options
@output_options
def portfw_disable(uids, dry_run):
    """Disable rules by uid."""
    run_write([set_action(f"{_pm_xpath(u)}/Enable", False) for u in uids], dry_run)


DMZ = f'{PM}/PortMapping[Service="DMZ"]'


@cli.group("dmz")
def dmz_grp():
    """Exposed host (DMZ)."""


@dmz_grp.command("show")
@output_options
def dmz_show():
    """Current DMZ state."""
    m = client().get(DMZ)
    out(
        {
            "enabled": m.get("Enable"),
            "status": m.get("Status"),
            "ip": m.get("InternalClient") or None,
            "mac": m.get("InternalMACAddress") or None,
        }
    )


@dmz_grp.command("set")
@click.argument("target")
@write_options
@output_options
def dmz_set(target, dry_run):
    """Expose TARGET (IP, or host name/MAC known to the router) and enable DMZ."""
    ip = target if re.match(r"^\d+\.\d+\.\d+\.\d+$", target) else resolve_host(target).get("IPAddress")
    run_write([set_action(f"{DMZ}/InternalClient", ip), set_action(f"{DMZ}/Enable", True)], dry_run)


@dmz_grp.command("off")
@write_options
@output_options
def dmz_off(dry_run):
    """Disable DMZ."""
    run_write([set_action(f"{DMZ}/Enable", False)], dry_run)


# ---------------------------------------------------------------- firewall / dns / upnp / time


@cli.group("firewall")
def firewall_grp():
    """Firewall level and per-interface ping settings."""


@firewall_grp.command("show")
@output_options
def firewall_show():
    """Firewall level, config and per-interface ICMP settings."""
    fw = client().get("Device/Firewall")
    out(
        {
            **{
                k: fw.get(k)
                for k in ("Enable", "Config", "AdvancedLevel", "Type", "PortScanDetection", "BlockFragmentedIPPackets")
            },
            "levels": [lv.get("Name") for lv in fw.get("Levels", [])],
            "interfaces": [
                {
                    "uid": i.get("uid"),
                    "iface": ref(i.get("Interface", "")),
                    **{k: i.get(k) for k in ("RespondToPing4", "RespondToPing6", "EnableIpSourceCheck")},
                }
                for i in fw.get("Interfaces", [])
            ],
        }
    )


@firewall_grp.command("level")
@click.argument(
    "level", type=click.Choice(["OFF", "LOW", "MEDIUM", "HIGH", "Advanced", "CUSTOM", "BLOCKED"], case_sensitive=False)
)
@write_options
@output_options
def firewall_level(level, dry_run):
    """Set the firewall level (Device/Firewall/Config)."""
    canonical = {"advanced": "Advanced"}.get(level.lower(), level.upper())
    run_write([set_action("Device/Firewall/Config", canonical)], dry_run)


@firewall_grp.command("ping")
@click.argument("state", type=click.Choice(["on", "off"]))
@click.option("--iface", default="IP_DATA", show_default=True, help="Interface alias.")
@click.option("--v6", is_flag=True, help="IPv6 (RespondToPing6) instead of IPv4.")
@write_options
@output_options
def firewall_ping(state, iface, v6, dry_run):
    """Answer (on) or drop (off) ICMP echo on an interface (default: WAN)."""
    fw_ifaces = as_list(client().get("Device/Firewall/Interfaces"))
    match = [i for i in fw_ifaces if ref(i.get("Interface", "")) == iface]
    if not match:
        raise not_found("firewall interface", iface, known=[ref(i.get("Interface", "")) for i in fw_ifaces])
    key = "RespondToPing6" if v6 else "RespondToPing4"
    run_write(
        [set_action(f'Device/Firewall/Interfaces/Interface[@uid="{match[0]["uid"]}"]/{key}', state == "on")], dry_run
    )


@cli.command("dns")
@output_options
def dns_cmd():
    """DNS client servers, local host names and relay settings."""
    d = client().get("Device/DNS")
    cl = d.get("Client", {})
    out(
        {
            "hostnames": cl.get("HostName"),
            "local_domains": cl.get("LocalDomains"),
            "servers": [
                {k: s.get(k) for k in ("Alias", "Enable", "Status", "DNSServer", "Type")} for s in cl.get("Servers", [])
            ],
            "relay": scalars(d.get("Relay", {})),
        }
    )


@cli.group("ddns")
def ddns_grp():
    """Dynamic DNS."""


@ddns_grp.command("show")
@output_options
def ddns_show():
    """Dynamic DNS clients and available providers."""
    d = client().get("Device/Services/DynamicDNS")
    out(
        {
            "clients": [
                {**scalars(c), "hostnames": [h.get("Name") for h in c.get("Hostnames", [])]}
                for c in d.get("Clients", [])
            ],
            "services": [s.get("Name") for s in d.get("Services", [])],
        }
    )


@ddns_grp.command("set")
@click.option("--enable/--disable", default=None)
@click.option("--service", help="Provider name (see `ddns show`).")
@click.option("--username")
@click.option("--password", "pw")
@click.option("--hostname")
@write_options
@output_options
def ddns_set(enable, service, username, pw, hostname, dry_run):
    """Configure the (first) dynamic DNS client."""
    x = 'Device/Services/DynamicDNS/Clients/Client[@uid="1"]'
    acts = []
    if service is not None:
        acts.append(
            set_action(f"{x}/ServiceReference", f"Device/Services/DynamicDNS/Services/Service[Name='{service}']")
        )
    if username is not None:
        acts.append(set_action(f"{x}/Username", username))
    if pw is not None:
        acts.append(set_action(f"{x}/Password", pw))
    if hostname is not None:
        acts.append(set_action(f'{x}/Hostnames/Hostname[@uid="1"]/Name', hostname))
    if enable is not None:
        acts.append(set_action(f"{x}/Enable", enable))
    if not acts:
        raise click.UsageError("nothing to change; pass at least one option")
    run_write(acts, dry_run)


@cli.group("upnp")
def upnp_grp():
    """UPnP IGD (automatic port mappings)."""


@upnp_grp.command("show")
@output_options
def upnp_show():
    """UPnP state and mappings created through it."""
    v = client().get_many({"dev": "Device/UPnP/Device", "maps": f"{PM}"})
    dev = v["dev"] or {}
    out(
        {
            "enabled": dev.get("Enable"),
            "igd": dev.get("UPnPIGD"),
            "mappings": [pm_row(m) for m in as_list(v["maps"]) if m.get("Creator") == "UPNP"],
        }
    )


@upnp_grp.command("on")
@write_options
@output_options
def upnp_on(dry_run):
    """Enable UPnP IGD."""
    run_write([set_action("Device/UPnP/Device/Enable", True), set_action("Device/UPnP/Device/UPnPIGD", True)], dry_run)


@upnp_grp.command("off")
@write_options
@output_options
def upnp_off(dry_run):
    """Disable UPnP IGD."""
    run_write(
        [set_action("Device/UPnP/Device/UPnPIGD", False), set_action("Device/UPnP/Device/Enable", False)], dry_run
    )


@cli.command("time")
@output_options
def time_cmd():
    """Clock, time zone and NTP state."""
    out(scalars(client().get("Device/Time")))


@cli.command("voice")
@output_options
def voice_cmd():
    """Telephony: phone ports and SIP line status."""
    vs = as_list(client().get("Device/Services/VoiceServices"))
    lines, phones = [], []
    for s in vs:
        for p in s.get("VoiceProfiles", []):
            for ln in p.get("Lines", []):
                lines.append(
                    {k: ln.get(k) for k in ("uid", "Enable", "Status", "DirectoryNumber", "CallState") if k in ln}
                )
        phones += [
            {k: ph.get(k) for k in ("Alias", "PhyInterfaceType", "Status", "Description")}
            for ph in s.get("PhyInterfaces", [])
        ]
    out({"lines": lines, "ports": phones})


@cli.command("usb")
@output_options
def usb_cmd():
    """USB ports and attached devices."""
    out(client().get("Device/USB"))


@cli.command("leds")
@click.argument("mode", required=False, type=click.Choice(["on", "off"]))
@write_options
@output_options
def leds_cmd(mode, dry_run):
    """Show LED power-saving state, or set it (off = LEDs dimmed/power saving on)."""
    if mode is None:
        out(
            client().get_many(
                {
                    "power_saving": "Device/Managers/Led/LedPowerSaving",
                    "mode": "Device/Managers/Led/LedPowerSavingMode",
                },
                raise_on_error=True,
            )
        )
        return
    run_write([set_action("Device/Managers/Led/LedPowerSaving", mode == "off")], dry_run)


# ---------------------------------------------------------------- diagnostics


def _iface_ref(alias: str) -> str:
    uid = client().get(f"Device/IP/Interfaces/Interface[Alias={q(alias)}]/@uid")
    return f"Device.IP.Interface.{uid}"


@cli.group("diag")
def diag_grp():
    """Network diagnostics run on the router (ping, traceroute, nslookup, speedtest, ...)."""


@diag_grp.command("ping")
@click.argument("host")
@click.option("-c", "--count", type=int, default=4, show_default=True)
@click.option("--iface", default="IP_DATA", show_default=True, help="Source interface alias.")
@write_options
@output_options
def diag_ping(host, count, iface, dry_run):
    """Ping HOST from the router."""
    run_write(
        [
            action(
                "ping",
                "Device",
                {
                    "Host": host,
                    "Count": count,
                    "Protocol": "AUTO",
                    "Interface": _iface_ref(iface) if not dry_run else f"<{iface}>",
                },
            )
        ],
        dry_run,
    )


@diag_grp.command("traceroute")
@click.argument("host")
@click.option("-c", "--count", type=int, default=3, show_default=True, help="Probes per hop.")
@click.option("--iface", default="IP_DATA", show_default=True, help="Source interface alias.")
@write_options
@output_options
def diag_traceroute(host, count, iface, dry_run):
    """Traceroute to HOST from the router."""
    run_write(
        [
            action(
                "traceRoute",
                "Device",
                {
                    "Host": host,
                    "Protocol": "AUTO",
                    "Count": count,
                    "Interface": _iface_ref(iface) if not dry_run else f"<{iface}>",
                },
            )
        ],
        dry_run,
    )


@diag_grp.command("nslookup")
@click.argument("host")
@write_options
@output_options
def diag_nslookup(host, dry_run):
    """Resolve HOST using the router's resolver."""
    run_write([action("nslookup", "Device", {"Host": host})], dry_run)


@diag_grp.command("arping")
@write_options
@output_options
def diag_arping(dry_run):
    """ARP-scan the LAN from the router."""
    run_write([action("arping", "Device", {})], dry_run)


@diag_grp.command("dhcp-servers")
@write_options
@output_options
def diag_dhcp_servers(dry_run):
    """Detect other DHCP servers on the LAN."""
    run_write([action("DhcpServerList", "Device", {})], dry_run)


@diag_grp.command("arp")
@output_options
def diag_arp():
    """ARP table (read-only)."""
    rows = []
    for t in as_list(client().get("Device/ARP/ArpTables")):
        rows.append(scalars(t))
    out(rows)


@diag_grp.command("speedtest")
@click.option("--servers", "list_servers", is_flag=True, help="List speedtest servers instead of running a test.")
@write_options
@output_options
def diag_speedtest(list_servers, dry_run):
    """Start a router-side speedtest (results: `diag speedtest-results`)."""
    method = "SpeedTestGetServersList" if list_servers else "speedTestClient"
    run_write([action(method, "Device/IP/Diagnostics/SpeedTest", {})], dry_run)


@diag_grp.command("speedtest-results")
@output_options
def diag_speedtest_results():
    """Last speedtest status and history (read-only)."""
    out(client().get("Device/IP/Diagnostics/SpeedTest"))


# ---------------------------------------------------------------- system


@cli.group("system")
def system_grp():
    """Reboot, factory reset, password, logs."""


@system_grp.command("reboot")
@write_options
@confirm_option
@output_options
def system_reboot(dry_run, yes):
    """Reboot the router (needs --yes)."""
    run_write([action("reboot", "Device", {"source": "GUI"})], dry_run, yes=yes, what="reboot")


@system_grp.command("factory-reset")
@click.option("--mode", help="Optional RestoreMode passed to reinitialize.")
@write_options
@confirm_option
@output_options
def system_factory_reset(mode, dry_run, yes):
    """Factory reset (reinitialize). Wipes all settings; needs --yes."""
    run_write(
        [action("reinitialize", "Device", {"RestoreMode": mode} if mode else {})],
        dry_run,
        yes=yes,
        what="factory reset",
    )


@system_grp.command("password")
@click.option("--old", "old", envvar="SALTROUTER_PASSWORD", help="Current password (default: configured one).")
@click.option("--new", "new", required=True, help="New password.")
@write_options
@confirm_option
@output_options
def system_password(old, new, dry_run, yes):
    """Change the GUI password of the logged-in user (needs --yes; update your .env afterwards)."""
    o = click.get_current_context().find_root().obj
    old = old or o.get("password") or env_password()
    run_write(
        [
            action(
                "changeClearPassword",
                f"Device/UserAccounts/Users/User[Login={q(o['user'])}]",
                {"OldPassword": old, "NewPassword": new},
            )
        ],
        dry_run,
        yes=yes,
        what="password change",
    )


@system_grp.command("logs")
@click.option("--save", type=click.Path(dir_okay=False), help="Write the log file here instead of stdout.")
@click.option("--tail", type=int, help="Only the last N lines.")
def system_logs(save, tail):
    """Download the router's system log (asks the router for a one-time URI, then fetches it)."""
    c = client()
    res = c.rpc(
        'Device/DeviceInfo/VendorLogFiles/VendorLogFile[@uid="1"]',
        "getVendorLogDownloadURI",
        {"FileName": "utilsLogFile"},
    )
    uri = (res.get("parameters") or {}).get("uri")
    if not uri:
        raise CliError("router", "router did not return a log URI", EXIT_ROUTER, result=res.get("parameters"))
    text = c._http.get(uri if uri.startswith("/") else f"/{uri}").text
    if tail:
        text = "\n".join(text.splitlines()[-tail:])
    if save:
        with open(save, "w") as fh:
            fh.write(text)
        out({"ok": True, "path": save, "bytes": len(text)})
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")


@system_grp.command("accounts")
@output_options
def system_accounts():
    """User account profiles and their permissions summary."""
    ua = client().get("Device/UserAccounts")
    out(
        [
            {
                "name": p.get("Name"),
                "write": sorted(f["Name"] for f in p.get("Functionalities", []) if f.get("WriteAccess") == "ENABLED"),
                "read_only": sorted(
                    f["Name"]
                    for f in p.get("Functionalities", [])
                    if f.get("ReadAccess") == "ENABLED" and f.get("WriteAccess") != "ENABLED"
                ),
            }
            for p in ua.get("Profiles", [])
        ]
    )


def main() -> None:
    load_env_files()  # before click reads SALTROUTER_* env vars
    cli(prog_name="saltrouter")
