#!/usr/bin/env python3
"""Local-only tools for authorized macOS WeChat database inspection."""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import os
import platform
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path


APP_ROOT = Path.home() / "Library" / "Application Support" / "AmantWeChatVault"
KEY_STORE = APP_ROOT / "private" / "keys.json"
DEFAULT_VAULT = APP_ROOT / "vault"
ORIGINAL_APP = Path("/Applications/WeChat.app")
APP_COPY = APP_ROOT / "apps" / "WeChatVault.app"


class AuthorizationError(RuntimeError):
    pass


def require_authorized(authorized: bool) -> None:
    if not authorized:
        raise AuthorizationError(
            "Refusing to access private WeChat data. Re-run with --authorized only for your own or explicitly authorized account."
        )


def fingerprint(value: str | bytes) -> str:
    raw = value if isinstance(value, bytes) else value.encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:12]


def write_private_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def load_captured_key(path: Path, key_fingerprint: str | None = None) -> str:
    if path.is_symlink():
        raise PermissionError("Refusing to read a symbolic-link key store")
    metadata = path.stat()
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise PermissionError("Key store must be readable only by its owner (mode 0600)")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise PermissionError("Key store must be owned by the current user")
    payload = json.loads(path.read_text(encoding="utf-8"))
    candidates = payload.get("candidates") if isinstance(payload, dict) else None
    if not isinstance(candidates, list):
        raise ValueError("Key store must contain a candidates list")
    keys = [
        item["derived_key"]
        for item in candidates
        if isinstance(item, dict)
        and isinstance(item.get("derived_key"), str)
        and re.fullmatch(r"[0-9a-f]{64}", item["derived_key"])
    ]
    if key_fingerprint is not None:
        keys = [key for key in keys if fingerprint(key) == key_fingerprint]
        if not keys:
            raise ValueError("No captured key matches --key-fingerprint")
    if len(keys) != 1:
        raise ValueError("Key store has multiple valid candidates; select one with --key-fingerprint")
    return keys[0]


def build_frida_script() -> str:
    return r"""
'use strict';
const CHANNEL = 'amant-wechat-vault';
const SYMBOL = 'CCKeyDerivationPBKDF';
const address = Module.findGlobalExportByName(SYMBOL);
if (address === null) throw new Error(`${SYMBOL} export not found`);

function encodePointer(pointer, length, maximum) {
  if (pointer.isNull() || length <= 0 || length > maximum) return null;
  const view = new Uint8Array(pointer.readByteArray(length));
  let result = '';
  for (const value of view) result += value.toString(16).padStart(2, '0');
  return result;
}

const activeCalls = new Map();
Interceptor.attach(address, {
  onEnter(args) {
    const callId = `${this.threadId}:${this.depth}`;
    this.amantCallId = callId;
    activeCalls.set(callId, {
      saltPointer: args[3],
      saltLength: args[4].toInt32(),
      rounds: args[6].toInt32(),
      outputPointer: args[7],
      outputLength: args[8].toInt32()
    });
  },
  onLeave(status) {
    const call = activeCalls.get(this.amantCallId);
    activeCalls.delete(this.amantCallId);
    if (!call || status.toInt32() !== 0) return;
    const keyHex = encodePointer(call.outputPointer, call.outputLength, 128);
    const saltHex = encodePointer(call.saltPointer, call.saltLength, 64);
    if (keyHex === null || saltHex === null) return;
    send({
      channel: CHANNEL,
      kind: 'pbkdf-result',
      material: { keyHex, saltHex, rounds: call.rounds }
    });
  }
});
send({channel: CHANNEL, kind: 'ready', symbol: SYMBOL});
""".strip()


def parse_capture_message(message: dict) -> dict | None:
    if message.get("type") != "send":
        return None
    payload = message.get("payload")
    if not isinstance(payload, dict) or payload.get("channel") != "amant-wechat-vault":
        return None
    if payload.get("kind") != "pbkdf-result":
        return None
    material = payload.get("material")
    if not isinstance(material, dict):
        return None
    key_hex = material.get("keyHex")
    salt_hex = material.get("saltHex")
    rounds = material.get("rounds")
    if not isinstance(key_hex, str) or not isinstance(salt_hex, str) or not isinstance(rounds, int):
        return None
    if not re.fullmatch(r"[0-9a-f]+", key_hex) or not re.fullmatch(r"[0-9a-f]+", salt_hex):
        return None
    if len(key_hex) % 2 or not 16 <= len(key_hex) // 2 <= 128:
        return None
    if len(salt_hex) % 2 or not 1 <= len(salt_hex) // 2 <= 64:
        return None
    return {"derived_key": key_hex, "salt": salt_hex, "rounds": rounds}


def prepare_app_copy(refresh: bool = False) -> Path:
    if not ORIGINAL_APP.is_dir():
        raise FileNotFoundError("WeChat.app was not found in /Applications.")
    if APP_COPY.exists() and refresh:
        shutil.rmtree(APP_COPY)
    if not APP_COPY.exists():
        APP_COPY.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(ORIGINAL_APP, APP_COPY, symlinks=True)
        subprocess.run(
            ["codesign", "--force", "--deep", "--sign", "-", str(APP_COPY)],
            check=True,
            capture_output=True,
            text=True,
        )
    return APP_COPY / "Contents" / "MacOS" / "WeChat"


def capture_keys(*, dry_run: bool, launch_copy: bool, duration: int) -> list[dict]:
    plan = {
        "mode": "launch-copy" if launch_copy else "attach",
        "source_app": str(ORIGINAL_APP),
        "app_copy": str(APP_COPY),
        "key_store": str(KEY_STORE),
        "duration_seconds": duration,
    }
    if dry_run:
        print(json.dumps({"status": "dry-run", "plan": plan}, ensure_ascii=False, indent=2))
        return []
    try:
        import frida
    except ImportError as exc:
        raise RuntimeError("Frida is missing. Install requirements.txt in the skill virtual environment.") from exc

    device = frida.get_local_device()
    pid = None
    if launch_copy:
        executable = prepare_app_copy()
        pid = device.spawn([str(executable)])
        session = device.attach(pid)
    else:
        session = device.attach("WeChat")

    captured: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def on_message(message, _data):
        candidate = parse_capture_message(message)
        if candidate is None:
            return
        pair = (candidate["derived_key"], candidate["salt"])
        if not pair[0] or pair in seen:
            return
        seen.add(pair)
        captured.append({
            "derived_key": pair[0],
            "salt": pair[1],
            "rounds": candidate["rounds"],
            "captured_at": int(time.time()),
        })
        print(json.dumps({
            "event": "key-candidate",
            "key_fingerprint": fingerprint(pair[0]),
            "salt_fingerprint": fingerprint(pair[1]),
            "rounds": candidate["rounds"],
        }, ensure_ascii=False))

    script = session.create_script(build_frida_script())
    script.on("message", on_message)
    script.load()
    if pid is not None:
        device.resume(pid)
    try:
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            time.sleep(0.25)
    finally:
        script.unload()
        session.detach()
    write_private_json(KEY_STORE, {"candidates": captured})
    print(json.dumps({"status": "ok", "candidate_count": len(captured), "key_store": str(KEY_STORE)}, ensure_ascii=False))
    return captured


def _page_keys(key_hex: str, salt: bytes, hmac_key_hex: str | None) -> tuple[bytes, bytes]:
    encryption_key = bytes.fromhex(key_hex)
    if len(encryption_key) != 32:
        raise ValueError("--key-hex must contain a 32-byte derived key")
    if hmac_key_hex:
        hmac_key = bytes.fromhex(hmac_key_hex)
    else:
        hmac_salt = bytes(byte ^ 0x3A for byte in salt)
        hmac_key = hashlib.pbkdf2_hmac("sha512", encryption_key, hmac_salt, 2, 32)
    return encryption_key, hmac_key


def ensure_distinct_paths(source: Path, output: Path) -> None:
    if source.resolve() == output.resolve():
        raise ValueError("Source and output must not be the same file")
    if output.exists() and os.path.samefile(source, output):
        raise ValueError("Source and output must not be the same file")


def private_temp_output(output: Path, overwrite: bool) -> tuple[int, Path]:
    if output.exists() and not overwrite:
        raise FileExistsError(f"Output already exists; pass --overwrite to replace it: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.",
        suffix=".tmp",
        dir=output.parent,
    )
    temporary = Path(temporary_name)
    os.chmod(temporary, 0o600)
    return fd, temporary


def decrypt_sqlcipher_database(
    source: Path,
    output: Path,
    key_hex: str,
    hmac_key_hex: str | None = None,
    page_size: int = 4096,
    overwrite: bool = False,
) -> dict:
    ensure_distinct_paths(source, output)
    if output.exists() and not overwrite:
        raise FileExistsError(f"Output already exists; pass --overwrite to replace it: {output}")
    try:
        from Crypto.Cipher import AES
    except ImportError as exc:
        raise RuntimeError("PyCryptodome is missing. Install requirements.txt.") from exc
    raw = source.read_bytes()
    if len(raw) < page_size or len(raw) % page_size:
        raise ValueError("Encrypted database size is not a whole number of pages")
    salt = raw[:16]
    encryption_key, hmac_key = _page_keys(key_hex, salt, hmac_key_hex)
    fd, temporary = private_temp_output(output, overwrite)
    pages = len(raw) // page_size
    try:
        with os.fdopen(fd, "wb") as handle:
            for page_number in range(1, pages + 1):
                page = raw[(page_number - 1) * page_size:page_number * page_size]
                offset = 16 if page_number == 1 else 0
                cipher_text = page[offset:page_size - 80]
                iv = page[page_size - 80:page_size - 64]
                stored_hmac = page[page_size - 64:page_size]
                page_bytes = page_number.to_bytes(4, "little")
                calculated = hmac.new(hmac_key, cipher_text + iv + page_bytes, hashlib.sha512).digest()
                if not hmac.compare_digest(stored_hmac, calculated):
                    raise ValueError(f"HMAC verification failed on page {page_number}; key or format is wrong")
                plain = AES.new(encryption_key, AES.MODE_CBC, iv).decrypt(cipher_text)
                if page_number == 1:
                    handle.write(b"SQLite format 3\x00")
                handle.write(plain)
                handle.write(b"\x00" * 80)
        os.replace(temporary, output)
        os.chmod(output, 0o600)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return {"status": "ok", "pages": pages, "output": str(output), "key_fingerprint": fingerprint(key_hex)}


def _text_columns(connection: sqlite3.Connection, table: str) -> list[str]:
    safe_table = table.replace('"', '""')
    rows = connection.execute(f'PRAGMA table_info("{safe_table}")').fetchall()
    return [row[1] for row in rows if not row[2] or any(token in row[2].upper() for token in ("TEXT", "CHAR", "CLOB"))]


def search_database(database: Path, query: str, limit: int = 20) -> list[dict]:
    if not query:
        raise ValueError("query must not be empty")
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        tables = [row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )]
        results: list[dict] = []
        for table in tables:
            safe_table = table.replace('"', '""')
            for column in _text_columns(connection, table):
                safe_column = column.replace('"', '""')
                sql = f'SELECT rowid, "{safe_column}" FROM "{safe_table}" WHERE "{safe_column}" LIKE ? LIMIT ?'
                for rowid, value in connection.execute(sql, (f"%{query}%", limit - len(results))):
                    results.append({"table": table, "rowid": rowid, "column": column, "value": value})
                    if len(results) >= limit:
                        return results
        return results
    finally:
        connection.close()


def browse_tables(database: Path, name_hints: list[str], limit: int = 20) -> list[dict]:
    """Return rows from tables whose names match a public feature hint."""
    lowered = [hint.lower() for hint in name_hints]
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        names = [row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )]
        matches = [name for name in names if any(hint in name.lower() for hint in lowered)]
        results: list[dict] = []
        for table in matches:
            safe = table.replace('"', '""')
            for row in connection.execute(f'SELECT * FROM "{safe}" LIMIT ?', (limit - len(results),)):
                values = {}
                for key in row.keys():
                    value = row[key]
                    values[key] = f"<blob:{len(value)}>" if isinstance(value, bytes) else value
                results.append({"table": table, "values": values})
                if len(results) >= limit:
                    return results
        return results
    finally:
        connection.close()


def database_digest(database: Path) -> dict:
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        tables = []
        for (name,) in rows:
            safe = name.replace('"', '""')
            count = connection.execute(f'SELECT COUNT(*) FROM "{safe}"').fetchone()[0]
            tables.append({"table": name, "rows": count})
        return {"database": str(database), "table_count": len(tables), "tables": tables}
    finally:
        connection.close()


def export_results(results: list[dict], output: Path, fmt: str, overwrite: bool = False) -> None:
    fd, temporary = private_temp_output(output, overwrite)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            if fmt == "jsonl":
                for row in results:
                    handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            else:
                writer = csv.DictWriter(handle, fieldnames=["table", "rowid", "column", "value"])
                writer.writeheader()
                writer.writerows(results)
        os.replace(temporary, output)
        os.chmod(output, 0o600)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def doctor() -> dict:
    checks = {
        "macos": platform.system() == "Darwin",
        "wechat_app": ORIGINAL_APP.is_dir(),
        "codesign": shutil.which("codesign") is not None,
        "python_3_10_plus": sys.version_info >= (3, 10),
        "frida": False,
        "pycryptodome": False,
        "zstandard": False,
    }
    for module, key in (("frida", "frida"), ("Crypto", "pycryptodome"), ("zstandard", "zstandard")):
        try:
            __import__(module)
            checks[key] = True
        except ImportError:
            pass
    return {"ok": all(checks.values()), "checks": checks, "app_root": str(APP_ROOT)}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor")

    capture = sub.add_parser("capture-keys")
    capture.add_argument("--authorized", action="store_true")
    capture.add_argument("--dry-run", action="store_true")
    capture.add_argument("--launch-copy", action="store_true")
    capture.add_argument("--duration", type=int, default=30)

    decrypt = sub.add_parser("decrypt")
    decrypt.add_argument("--authorized", action="store_true")
    decrypt.add_argument("--source-db", required=True, type=Path)
    decrypt.add_argument("--output", required=True, type=Path)
    decrypt.add_argument("--key-file", type=Path, default=KEY_STORE)
    decrypt.add_argument("--key-fingerprint")
    decrypt.add_argument("--overwrite", action="store_true")

    search = sub.add_parser("search")
    search.add_argument("--authorized", action="store_true")
    search.add_argument("query")
    search.add_argument("--db", required=True, type=Path)
    search.add_argument("--limit", type=int, default=20)
    search.add_argument("--show-content", action="store_true")

    export = sub.add_parser("export")
    export.add_argument("--authorized", action="store_true")
    export.add_argument("--db", required=True, type=Path)
    export.add_argument("--query", required=True)
    export.add_argument("--output", required=True, type=Path)
    export.add_argument("--format", choices=("jsonl", "csv"), default="jsonl")
    export.add_argument("--limit", type=int, default=1000)
    export.add_argument("--overwrite", action="store_true")

    for name in ("contacts", "moments", "favorites"):
        command = sub.add_parser(name)
        command.add_argument("--authorized", action="store_true")
        command.add_argument("--db", required=True, type=Path)
        command.add_argument("--limit", type=int, default=20)
        command.add_argument("--show-content", action="store_true")

    digest = sub.add_parser("digest")
    digest.add_argument("--authorized", action="store_true")
    digest.add_argument("--db", required=True, type=Path)
    return parser.parse_args(argv)


def main() -> int:
    args = parse_args()
    try:
        if args.command == "doctor":
            report = doctor()
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 0 if report["ok"] else 1
        require_authorized(args.authorized)
        if args.command == "capture-keys":
            capture_keys(dry_run=args.dry_run, launch_copy=args.launch_copy, duration=args.duration)
            return 0
        if args.command == "decrypt":
            key_hex = load_captured_key(args.key_file, args.key_fingerprint)
            report = decrypt_sqlcipher_database(args.source_db, args.output, key_hex, overwrite=args.overwrite)
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 0
        if args.command == "digest":
            print(json.dumps(database_digest(args.db), ensure_ascii=False, indent=2))
            return 0
        if args.command in {"contacts", "moments", "favorites"}:
            hints = {
                "contacts": ["contact", "friend", "user"],
                "moments": ["sns", "moment", "timeline"],
                "favorites": ["favorite", "fav", "collection"],
            }[args.command]
            results = browse_tables(args.db, hints, args.limit)
        else:
            results = search_database(args.db, args.query, args.limit)
        if args.command == "export":
            ensure_distinct_paths(args.db, args.output)
            export_results(results, args.output, args.format, overwrite=args.overwrite)
            print(json.dumps({"status": "ok", "rows": len(results), "output": str(args.output)}, ensure_ascii=False))
            return 0
        if args.show_content:
            output = results
        elif args.command in {"contacts", "moments", "favorites"}:
            output = [{"table": row["table"], "values": {
                key: f"<redacted:{fingerprint(str(value))}>" for key, value in row["values"].items()
            }} for row in results]
        else:
            output = [{**row, "value": f"<redacted:{fingerprint(str(row['value']))}>"} for row in results]
        print(json.dumps({"status": "ok", "matches": output}, ensure_ascii=False, indent=2))
        return 0
    except (AuthorizationError, OSError, RuntimeError, ValueError, json.JSONDecodeError, sqlite3.Error) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
