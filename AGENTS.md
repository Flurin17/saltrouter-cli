# AGENTS.md

## Using the `saltrouter` CLI

- Credentials come from `SALTROUTER_PASSWORD` (or `SALTROUTER_PW`) or a `.env` file; never pass them on argv.
- Start with `saltrouter status` (a single request that returns a small summary). `saltrouter commands` gives the
  full command spec as JSON.
- Keep output small: `-f name,ip`, `-w active=true`, `-n 5`, `-o tsv` for tables. Prefer named commands
  (`hosts`, `wifi list`) over raw `get Device/...`, which can return hundreds of KB.
- To explore the data model, use `tree XPATH -d N` (shape only). Before dumping anything, check
  `paths TERMS` for the xpath the web GUI uses.
- Before you `set`, run `describe XPATH` to see the type, whether it is writable, and the allowed enum values.
- Writes: run with `--dry-run` first and review the actions, then run for real. Deletes, `reboot` and
  `factory-reset` exit with code 6 unless `--yes` is given. Ask the user before disruptive changes, such as
  Wi-Fi password or SSID, reboot, reset or firewall changes.
- Exit codes: 3 auth, 4 router error (see `error.message`, e.g. `XMO_UNKNOWN_PATH_ERR`), 5 network, 7 not found.
- Xpath syntax: `Device/WiFi/SSIDs/SSID[Alias="WL_PRIV_5G"]/SSID`, `...[@uid="3"]`, `...[Active="true"]`.
  When a predicate matches several nodes, the result is a list.

## Working on this repo

- `uv sync`, `uv run pytest` (offline; `tests/conftest.py` has a fake router), `uv run ruff check . && uv run ruff format .`
- `src/saltrouter_cli/client.py` handles transport, auth and the session cache. `cli.py` holds the commands, and
  `output.py` handles formatting, filtering and redaction.
- `data/gui_xpaths.json` is the flattened `$.xpaths` object from the router GUI's `js/scripts.js`.
- To test against a real router, use read commands or `--dry-run` only, unless the owner asks for a write.
