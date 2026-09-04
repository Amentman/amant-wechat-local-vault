import importlib.util
import io
import json
import sqlite3
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from scripts.wechat_vault import (
    AuthorizationError,
    browse_tables,
    build_frida_script,
    capture_keys,
    decrypt_sqlcipher_database,
    export_results,
    fingerprint,
    load_captured_key,
    main,
    parse_args,
    parse_capture_message,
    persist_captured_candidates,
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
            "--output", "/tmp/plain.db", "--key-file", "/tmp/keys.json",
            "--key-fingerprint", "abc123def456",
        ])
        self.assertEqual(decrypt.command, "decrypt")
        self.assertFalse(hasattr(decrypt, "key_hex"))
        search = parse_args(["search", "产品反馈", "--authorized", "--db", "/tmp/plain.db", "--limit", "20"])
        self.assertEqual(search.command, "search")
        export = parse_args([
            "export", "--authorized", "--db", "/tmp/plain.db", "--query", "产品反馈",
            "--format", "jsonl", "--output", "/tmp/result.jsonl",
        ])
        self.assertEqual(export.command, "export")

    def test_every_private_database_command_accepts_and_records_authorization(self):
        commands = [
            ["digest", "--authorized", "--db", "/tmp/plain.db"],
            ["search", "产品反馈", "--authorized", "--db", "/tmp/plain.db"],
            ["export", "--authorized", "--db", "/tmp/plain.db", "--query", "产品反馈", "--output", "/tmp/result.jsonl"],
            ["contacts", "--authorized", "--db", "/tmp/plain.db"],
            ["moments", "--authorized", "--db", "/tmp/plain.db"],
            ["favorites", "--authorized", "--db", "/tmp/plain.db"],
        ]
        for argv in commands:
            with self.subTest(command=argv[0]):
                self.assertTrue(parse_args(argv).authorized)

    def test_private_database_command_rejects_missing_authorization(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "synthetic.db"
            connection = sqlite3.connect(database)
            connection.execute("CREATE TABLE messages(content TEXT)")
            connection.commit()
            connection.close()
            script = Path(__file__).resolve().parents[1] / "scripts" / "wechat_vault.py"
            result = subprocess.run(
                [sys.executable, str(script), "digest", "--db", str(database)],
                text=True,
                capture_output=True,
            )
            self.assertEqual(2, result.returncode)
            self.assertIn("--authorized", result.stderr)

    def test_private_json_uses_owner_only_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "keys.json"
            write_private_json(target, {"key": "01"})
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(target.read_text()), {"key": "01"})

    def test_load_captured_key_uses_owner_only_store_and_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "keys.json"
            first = "ab" * 32
            second = "cd" * 32
            write_private_json(target, {"candidates": [
                {"derived_key": first},
                {"derived_key": second},
            ]})
            self.assertEqual(second, load_captured_key(target, fingerprint(second)))
            with self.assertRaisesRegex(ValueError, "multiple"):
                load_captured_key(target)

    def test_load_captured_key_rejects_permissive_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "keys.json"
            write_private_json(target, {"candidates": [{"derived_key": "ab" * 32}]})
            target.chmod(0o644)
            with self.assertRaises(PermissionError):
                load_captured_key(target)

    def test_zero_candidate_capture_preserves_existing_key_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "keys.json"
            existing = {
                "candidates": [{
                    "derived_key": "ab" * 32,
                    "salt": "cd" * 16,
                    "rounds": 256000,
                    "captured_at": 1700000000,
                }]
            }
            write_private_json(target, existing)
            original = target.read_bytes()

            report = persist_captured_candidates(target, [])

            self.assertEqual("no-candidates", report["status"])
            self.assertEqual(0, report["candidate_count"])
            self.assertEqual(1, report["total_candidate_count"])
            self.assertEqual(original, target.read_bytes())

    def test_zero_candidate_frida_session_reports_no_candidates_and_preserves_store(self):
        class FakeScript:
            def on(self, _event, _callback):
                pass

            def load(self):
                pass

            def unload(self):
                pass

        class FakeSession:
            def create_script(self, _source):
                return FakeScript()

            def detach(self):
                pass

        class FakeDevice:
            def attach(self, process):
                self.attached_process = process
                return FakeSession()

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "keys.json"
            existing = {"candidates": [{
                "derived_key": "ab" * 32,
                "salt": "cd" * 16,
                "rounds": 256000,
                "captured_at": 1700000000,
            }]}
            write_private_json(target, existing)
            original = target.read_bytes()
            fake_frida = types.SimpleNamespace(get_local_device=lambda: FakeDevice())
            output = io.StringIO()

            with patch.dict(sys.modules, {"frida": fake_frida}), \
                    patch("scripts.wechat_vault.KEY_STORE", target), \
                    redirect_stdout(output):
                captured = capture_keys(dry_run=False, launch_copy=False, duration=0)

            report = json.loads(output.getvalue().strip().splitlines()[-1])
            self.assertEqual([], captured)
            self.assertEqual("no-candidates", report["status"])
            self.assertEqual(1, report["total_candidate_count"])
            self.assertEqual(original, target.read_bytes())

    def test_main_returns_three_when_real_capture_has_no_candidates(self):
        args = types.SimpleNamespace(
            command="capture-keys",
            authorized=True,
            dry_run=False,
            launch_copy=False,
            duration=0,
        )
        with patch("scripts.wechat_vault.parse_args", return_value=args), \
                patch("scripts.wechat_vault.capture_keys", return_value=[]):
            self.assertEqual(3, main())

    def test_new_capture_merges_with_existing_candidates_without_duplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "keys.json"
            first = {
                "derived_key": "ab" * 32,
                "salt": "cd" * 16,
                "rounds": 256000,
                "captured_at": 1700000000,
            }
            second = {
                "derived_key": "ef" * 32,
                "salt": "12" * 16,
                "rounds": 256000,
                "captured_at": 1700000100,
            }
            write_private_json(target, {"candidates": [first]})

            report = persist_captured_candidates(target, [dict(first), second])

            payload = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual("ok", report["status"])
            self.assertEqual(2, report["candidate_count"])
            self.assertEqual(1, report["added_candidate_count"])
            self.assertEqual(2, report["total_candidate_count"])
            self.assertEqual([first, second], payload["candidates"])

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

    def test_decrypt_refuses_same_source_and_output_without_damage(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.db"
            original = b"\x00" * 4096
            source.write_bytes(original)
            with self.assertRaisesRegex(ValueError, "same file"):
                decrypt_sqlcipher_database(source, source, "ab" * 32)
            self.assertEqual(original, source.read_bytes())

    @unittest.skipUnless(importlib.util.find_spec("Crypto"), "PyCryptodome is installed by bootstrap")
    def test_decrypt_failure_leaves_no_partial_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.db"
            output = Path(tmp) / "plain.db"
            source.write_bytes(b"\x00" * 4096)
            with self.assertRaisesRegex(ValueError, "HMAC verification failed"):
                decrypt_sqlcipher_database(source, output, "ab" * 32)
            self.assertFalse(output.exists())

    @unittest.skipUnless(importlib.util.find_spec("Crypto"), "PyCryptodome is installed by bootstrap")
    def test_decrypt_requires_overwrite_and_preserves_old_output_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.db"
            output = Path(tmp) / "plain.db"
            source.write_bytes(b"\x00" * 4096)
            output.write_bytes(b"existing")
            with self.assertRaises(FileExistsError):
                decrypt_sqlcipher_database(source, output, "ab" * 32)
            with self.assertRaisesRegex(ValueError, "HMAC verification failed"):
                decrypt_sqlcipher_database(source, output, "ab" * 32, overwrite=True)
            self.assertEqual(b"existing", output.read_bytes())

    def test_export_requires_explicit_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "result.jsonl"
            output.write_text("existing", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                export_results([], output, "jsonl")
            export_results([], output, "jsonl", overwrite=True)
            self.assertEqual("", output.read_text(encoding="utf-8"))

    def test_export_refuses_to_replace_its_source_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "source.db"
            connection = sqlite3.connect(database)
            connection.execute("CREATE TABLE messages(content TEXT)")
            connection.execute("INSERT INTO messages VALUES ('keep me')")
            connection.commit()
            connection.close()
            original = database.read_bytes()
            script = Path(__file__).resolve().parents[1] / "scripts" / "wechat_vault.py"
            result = subprocess.run(
                [
                    sys.executable, str(script), "export", "--authorized",
                    "--db", str(database), "--query", "keep",
                    "--output", str(database), "--overwrite",
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(2, result.returncode)
            self.assertIn("same file", result.stderr)
            self.assertEqual(original, database.read_bytes())

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
