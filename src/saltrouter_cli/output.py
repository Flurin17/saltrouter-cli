"""Token-efficient output: compact JSON by default, projection, filtering, redaction."""

import json
import re
import sys
from typing import Any

SECRET_KEY = re.compile(r"(pass(word|phrase)|secret|presharedkey|wepkey|pin|token)$", re.IGNORECASE)
REDACTED = "***"
WRITE_ONLY = {"", "_XMO_WRITE_ONLY_", "_XMO_UNDEFINED_WRITE_ONLY_"}


def redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {
            k: (REDACTED if SECRET_KEY.search(k) and isinstance(v, str) and v not in WRITE_ONLY else redact(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def get_path(obj: Any, path: str) -> Any:
    """Dotted lookup; list indexes allowed (``Security.ModeEnabled``, ``Servers.0``)."""
    for part in path.split("."):
        if isinstance(obj, dict):
            obj = obj.get(part)
        elif isinstance(obj, list) and part.lstrip("-").isdigit():
            i = int(part)
            obj = obj[i] if -len(obj) <= i < len(obj) else None
        else:
            return None
    return obj


def project(obj: Any, fields: list[str]) -> Any:
    if not fields:
        return obj
    if isinstance(obj, list):
        return [project(o, fields) for o in obj]
    if isinstance(obj, dict):
        return {f: get_path(obj, f) for f in fields}
    return obj


_WHERE = re.compile(r"^([\w.@-]+?)(!=|~|=|>|<)(.*)$")


def parse_where(exprs: list[str]) -> list[tuple[str, str, str]]:
    out = []
    for e in exprs:
        m = _WHERE.match(e)
        if not m:
            raise ValueError(f"bad --where expression {e!r}; use key=val, key!=val, key~substr, key>n, key<n")
        out.append(m.groups())
    return out


def _match(item: Any, key: str, op: str, want: str) -> bool:
    val = get_path(item, key)
    sval = json.dumps(val) if isinstance(val, (bool, type(None))) else str(val)
    match op:
        case "=":
            return sval.lower() == want.lower()
        case "!=":
            return sval.lower() != want.lower()
        case "~":
            return want.lower() in sval.lower()
        case ">" | "<":
            try:
                a, b = float(val), float(want)
            except TypeError, ValueError:
                return False
            return a > b if op == ">" else a < b
    return False


def filter_rows(obj: Any, where: list[tuple[str, str, str]]) -> Any:
    if not where or not isinstance(obj, list):
        return obj
    return [o for o in obj if all(_match(o, *w) for w in where)]


def _cell(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (dict, list)):
        return json.dumps(v, separators=(",", ":"), ensure_ascii=False)
    return str(v).replace("\t", " ").replace("\n", " ")


def render(obj: Any, fmt: str) -> str:
    match fmt:
        case "pretty":
            return json.dumps(obj, indent=2, ensure_ascii=False)
        case "jsonl":
            rows = obj if isinstance(obj, list) else [obj]
            return "\n".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False) for r in rows)
        case "tsv":
            if isinstance(obj, list) and obj and all(isinstance(r, dict) for r in obj):
                cols: list[str] = []
                for r in obj:
                    cols += [k for k in r if k not in cols]
                lines = ["\t".join(cols)]
                lines += ["\t".join(_cell(r.get(c)) for c in cols) for r in obj]
                return "\n".join(lines)
            if isinstance(obj, dict):
                return "\n".join(f"{k}\t{_cell(v)}" for k, v in obj.items())
            if isinstance(obj, list):
                return "\n".join(_cell(v) for v in obj)
            return _cell(obj)
        case "raw":
            return obj if isinstance(obj, str) else _cell(obj)
        case _:
            return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def emit(
    obj: Any,
    *,
    fmt: str = "json",
    fields: list[str] | None = None,
    where=None,
    limit: int | None = None,
    show_secrets: bool = False,
) -> None:
    if not show_secrets:
        obj = redact(obj)
    obj = filter_rows(obj, where or [])
    if isinstance(obj, list) and limit is not None:
        obj = obj[:limit]
    obj = project(obj, fields or [])
    text = render(obj, fmt)
    if text != "":
        sys.stdout.write(text + "\n")


def emit_error(kind: str, message: str, **extra: Any) -> None:
    sys.stderr.write(json.dumps({"error": {"type": kind, "message": message, **extra}}, separators=(",", ":")) + "\n")


def summarize(obj: Any, depth: int) -> Any:
    """Shape-only view of a subtree: scalars kept, containers collapsed below ``depth``."""
    if isinstance(obj, dict):
        if depth <= 0:
            return f"{{{len(obj)} keys}}"
        return {k: summarize(v, depth - 1) for k, v in obj.items()}
    if isinstance(obj, list):
        if depth <= 0 or not obj:
            return f"[{len(obj)} items]"
        first = obj[0]
        key = next((k for k in ("Alias", "Name", "uid") if isinstance(first, dict) and k in first), None)
        ids = [o.get(key) for o in obj if isinstance(o, dict)] if key else []
        return (
            {"_len": len(obj), "_ids": ids[:50], "_item": summarize(first, depth - 1)}
            if key
            else {"_len": len(obj), "_item": summarize(first, depth - 1)}
        )
    return obj
