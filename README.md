# saltrouter-cli

Agent-first command-line tool and Python client for **Salt Fiber Box** routers
(Sagemcom F@st / "NJJ Fibre Box", firmware with the XMO JSON API at `/cgi/json-req`).

It speaks the router's own web-GUI protocol, reverse-engineered from the GUI JavaScript,
so everything the web UI can do is reachable: named commands cover the common tasks,
and the raw `get`/`set`/`add`/`delete`/`rpc`/`batch` commands cover everything else.

```bash
uvx saltrouter-cli status          # one-off run without installing
uv tool install saltrouter-cli     # or install the `saltrouter` command
```

Requires Python ≥ 3.14.

## Configure

The CLI reads credentials from flags, then environment variables, then `.env` files
(`./.env` and `~/.config/saltrouter/.env`):

```bash
SALTROUTER_PASSWORD=...        # GUI admin password (SALTROUTER_PW also accepted)
SALTROUTER_HOST=192.168.1.1    # optional
SALTROUTER_USER=admin          # optional
```

Sessions are cached in `~/.cache/saltrouter/` (mode 600), so consecutive commands don't log in
again. Use `--no-cache` to turn caching off, or `saltrouter logout` to close the session.

## Commands

| Area | Commands |
|---|---|
| Overview | `status`, `info [--processes]`, `wan`, `fiber`, `lan`, `time`, `voice`, `usb` |
| Devices | `hosts [--all]`, `host show\|rename\|set-type\|forget ID` (ID = uid, MAC, IP or name) |
| Wi-Fi | `wifi list\|show\|set\|radios\|radio-set\|clients\|wps\|scan\|neighbors` |
| DHCP | `dhcp leases\|reservations\|reserve\|unreserve\|set` |
| NAT | `portfw list\|add\|rm\|enable\|disable`, `dmz show\|set\|off`, `upnp show\|on\|off` |
| Security | `firewall show\|level\|ping`, `dns`, `ddns show\|set` |
| Diagnostics | `diag ping\|traceroute\|nslookup\|arping\|arp\|dhcp-servers\|speedtest\|speedtest-results` |
| System | `system reboot\|factory-reset\|password\|logs\|accounts`, `leds` |
| Raw API | `get`, `tree`, `describe`, `set`, `add`, `delete`, `rpc`, `batch` |
| Discovery | `commands` (machine-readable spec), `paths TERMS…` (≈3.4k xpaths from the web GUI) |

Examples:

```bash
saltrouter hosts -o tsv
saltrouter wifi clients -f name,ip,signal_dbm
saltrouter wifi set PRIV1 --ssid MyNet --password 'new-passphrase'
saltrouter portfw add --ip nas --ext-port 443 --int-port 8443 --proto TCP --desc https
saltrouter dhcp reserve laptop 192.168.1.50
saltrouter get 'Device/Hosts/Hosts/Host[Active="true"]/HostName'
saltrouter describe Device/Firewall/Config        # type, writable, enum values
saltrouter tree Device/WiFi -d 2                   # data-model shape without the bulk
saltrouter paths dmz                               # find the xpath the GUI uses
saltrouter system reboot --yes
```

## Designed for agents

* **stdout is data only**: compact JSON by default; `-o pretty|jsonl|tsv|raw`.
* **Trim output server- and client-side**: xpath predicates (`Host[Active="true"]`),
  `-f/--fields a,b.c`, `-w/--where key=val|key!=val|key~sub|key>n|key<n`, `-n/--limit`.
  Output flags work before or after the subcommand.
* **Secrets are redacted** (`***`) unless `--show-secrets`.
* **Safe writes**: every write accepts `--dry-run` and prints the exact XMO actions without
  sending. Deletes, reboot and factory reset also need `--yes`. The CLI never prompts.
* **Errors** go to stderr as `{"error":{"type","message",...}}` with stable exit codes:

  | code | meaning |
  |---|---|
  | 0 | ok |
  | 2 | usage error |
  | 3 | authentication failed / no password |
  | 4 | router rejected the request (e.g. `XMO_UNKNOWN_PATH_ERR`) |
  | 5 | network error |
  | 6 | destructive action needs `--yes` |
  | 7 | named object not found (lists known ids when possible) |

* **Self-describing**: `saltrouter commands` lists every command, argument and option as JSON;
  `describe XPATH` returns type, writability and allowed enum values before you `set`.

See [AGENTS.md](AGENTS.md) for a compact playbook.

## Python API

```python
from saltrouter_cli.client import XmoClient

with XmoClient("192.168.1.1", "admin", "password") as r:
    print(r.get("Device/DeviceInfo/ModelName"))
    print(r.get_many({"up": "Device/DeviceInfo/UpTime", "fw": "Device/DeviceInfo/SoftwareVersion"}))
    r.set("Device/WiFi/SSIDs/SSID[Alias=\"WL_GUEST_5G\"]/Enable", False)
    r.rpc("Device", "nslookup", {"Host": "example.com"})
```

## Protocol notes

`POST /cgi/json-req` with form field `req` =
`{"request":{"id","session-id","priority","actions":[…],"cnonce","auth-key"}}`.

```
pass_hash = sha512(password)
ha1       = sha512(f"{user}:{nonce}:{pass_hash}")          # nonce = "" for logIn
auth_key  = sha512(f"{ha1}:{request_id}:{cnonce}:JSON:/cgi/json-req")
```

`logIn` returns the session id and nonce. Actions are `getValue`, `setValue`, `addChild`,
`deleteChild`, `logOut`, and RPC methods called on an xpath (`reboot`, `ping`, `traceRoute`, …).
A predicate that matches several nodes returns one callback per match.

## Development

```bash
uv sync
uv run pytest          # offline tests against a fake router
uv run ruff check .
uv build
```

Not affiliated with Salt Mobile SA or Sagemcom.
