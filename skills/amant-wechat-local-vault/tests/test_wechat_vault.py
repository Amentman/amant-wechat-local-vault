import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from scripts.wechat_vault import (
    AuthorizationError,
    browse_tables,
    build_frida_script,
    fingerprint,
    parse_args,
    parse_capture_message,
    require_authorized,
    search_database,
    write_private_json,
)


class WeChatVaultTests(unittest.TestCase):
    def test_authorization_is_required_for_private_data(self):
        with self.assertRaises(AuthorizationError):
            require_authorized(False)

    def test_fingerprint_never_returns_the_secret(self):
        secret = "ab" * 32
        shown = fingerprint(secret)
        self.assertNotEqual(shown, secret)
        self.assertEqual(len(shown), 12)

    def test_frida_script_emits_key_and_salt_candidates(self):
        script = build_frida_script()
        self.assertIn("CCKeyDerivationPBKDF", script)
        self.assertIn("pbkdf-result", script)
        self.assertIn("keyHex", script)
        self.assertIn("Interceptor.attach", script)

    def test_capture_message_accepts_only_the_namespaced_event_contract(self):
        message = {
            "type": "send",
            "payload": {
                "channel": "amant-wechat-vault",
                "kind": "pbkdf-result",
                "material": {
                    "keyHex": "ab" * 32,
                    "saltHex": "cd" * 16,
                    "rounds": 256000,
                },
            },
        }
        self.assertEqual(parse_capture_message(message), {
            "derived_key": "ab" * 32,
            "salt": "cd" * 16,
            "rounds": 256000,
        })
        self.assertIsNone(parse_capture_message({"type": "error", "payload": message["payload"]}))
        self.assertIsNone(parse_capture_message({"type": "send", "payload": {"kind": "pbkdf-result"}}))

    def test_readme_command_shapes_parse_with_all_required_arguments(self):
        decrypt = parse_args([
            "decrypt", "--authorized", "--source-db", "/tmp/source.db",
            "--output", "/tmp/plain.db", "--key-hex", "ab" * 32,
        ])
        self.assertEqual(decrypt.command, "decrypt")
        search = parse_args(["search", "产品反馈", "--db", "/tmp/plain.db", "--limit", "20"])
        self.assertEqual(search.command, "search")
        export = parse_args([
            "export", "--db", "/tmp/plain.db", "--query", "产品反馈",
            "--format", "jsonl", "--output", "/tmp/result.jsonl",
        ])
        self.assertEqual(export.command, "export")

    def test_private_json_uses_owner_only_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "keys.json"
            write_private_json(target, {"key": "01"})
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(target.read_text()), {"key": "01"})

    def test_search_database_finds_text_without_schema_assumptions(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "synthetic.db"
            connection = sqlite3.connect(database)
            connection.execute("CREATE TABLE messages(sender TEXT, content TEXT, created_at INTEGER)")
            connection.execute("INSERT INTO messages VALUES (?, ?, ?)", ("示例联系人", "讨论产品反馈", 1700000000))
            connection.execute("INSERT INTO messages VALUES (?, ?, ?)", ("另一联系人", "普通消息", 1700000001))
            connection.commit()
            connection.close()

            results = search_database(database, "产品反馈", limit=10)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["table"], "messages")
            self.assertEqual(results[0]["column"], "content")
            self.assertEqual(results[0]["value"], "讨论产品反馈")

    def test_browse_tables_selects_matching_schema_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "synthetic.db"
            connection = sqlite3.connect(database)
            connection.execute("CREATE TABLE Contact(user_name TEXT, nick_name TEXT)")
            connection.execute("INSERT INTO Contact VALUES (?, ?)", ("wxid_demo", "示例联系人"))
            connection.commit()
            connection.close()

            results = browse_tables(database, ["contact"], limit=10)
            self.assertEqual(results[0]["table"], "Contact")
            self.assertEqual(results[0]["values"]["nick_name"], "示例联系人")


if __name__ == "__main__":
    unittest.main()
