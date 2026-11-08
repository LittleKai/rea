#!/usr/bin/env python3
"""Unit tests for REA repo-local reverse-engineering skills.

Covers:
1. rea-js-reverse-lab:
   - scripts/opaque_token_inspect.py
   - scripts/experiment_ledger.py
   - scripts/project_baseline.py
2. rea-android-kotlin-recovery:
   - scripts/kotlin_apk_inspector.py
3. rea-case-review:
   - scripts/review_case.py
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import struct
import sys
import tempfile
import types
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest import mock

SKILLS_ROOT = Path(__file__).resolve().parents[1]
JS_LAB_SCRIPTS = SKILLS_ROOT / "rea-js-reverse-lab" / "scripts"
ANDROID_SCRIPTS = SKILLS_ROOT / "rea-android-kotlin-recovery" / "scripts"
CASE_REVIEW_SCRIPTS = SKILLS_ROOT / "rea-case-review" / "scripts"

OPAQUE_TOKEN_SCRIPT = JS_LAB_SCRIPTS / "opaque_token_inspect.py"
EXPERIMENT_LEDGER_SCRIPT = JS_LAB_SCRIPTS / "experiment_ledger.py"
PROJECT_BASELINE_SCRIPT = JS_LAB_SCRIPTS / "project_baseline.py"
KOTLIN_INSPECTOR_SCRIPT = ANDROID_SCRIPTS / "kotlin_apk_inspector.py"
REVIEW_CASE_SCRIPT = CASE_REVIEW_SCRIPTS / "review_case.py"

_MODULE_CACHE: dict[Path, types.ModuleType] = {}


def _load_script_module(script: Path) -> types.ModuleType:
    resolved = script.resolve()
    if resolved not in _MODULE_CACHE:
        spec = importlib.util.spec_from_file_location(resolved.stem, resolved)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Unable to load module spec for {resolved}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _MODULE_CACHE[resolved] = mod
    return _MODULE_CACHE[resolved]


def run_cli(script: Path, *args: str, cwd: Path | None = None) -> types.SimpleNamespace:
    mod = _load_script_module(script)
    out_buf = io.StringIO()
    err_buf = io.StringIO()
    prev_cwd = Path.cwd()
    rc = 0
    try:
        if cwd is not None:
            os.chdir(cwd)
        with (
            mock.patch.object(sys, "argv", [str(script), *args]),
            contextlib.redirect_stdout(out_buf),
            contextlib.redirect_stderr(err_buf),
        ):
            try:
                res = mod.main()
                rc = int(res) if isinstance(res, int) else 0
            except SystemExit as exc:
                if exc.code is None:
                    rc = 0
                elif isinstance(exc.code, int):
                    rc = exc.code
                else:
                    err_buf.write(f"{exc.code}\n")
                    rc = 1
    finally:
        if cwd is not None:
            os.chdir(prev_cwd)
    return types.SimpleNamespace(
        returncode=rc,
        stdout=out_buf.getvalue(),
        stderr=err_buf.getvalue(),
    )


class TestOpaqueTokenInspect(unittest.TestCase):
    def test_help_and_version(self) -> None:
        res_help = run_cli(OPAQUE_TOKEN_SCRIPT, "--help")
        self.assertEqual(res_help.returncode, 0, res_help.stderr)
        self.assertIn("--encoding", res_help.stdout)

        res_ver = run_cli(OPAQUE_TOKEN_SCRIPT, "--version")
        self.assertEqual(res_ver.returncode, 0, res_ver.stderr)
        self.assertTrue(res_ver.stdout.strip())

    def test_token_batch_xor_and_crc32_tail(self) -> None:
        key = 0x5A
        raw_samples: list[bytes] = []
        tokens: list[str] = []
        for idx, body in enumerate([b"user=101&ts=1700001", b"user=101&ts=1700099&extra=1"]):
            payload = bytes([0x01, 0x02, len(body)]) + body
            crc = zlib.crc32(payload) ^ key
            full = payload + struct.pack("<I", crc)
            raw_samples.append(full)
            tokens.append(base64.urlsafe_b64encode(full).decode("ascii").rstrip("="))

        res = run_cli(
            OPAQUE_TOKEN_SCRIPT,
            *tokens,
            "--encoding",
            "base64url",
            "--xor-align",
            "--checksum",
            "crc32",
            "--checksum-at",
            "tail",
            "--endian",
            "little",
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        data = json.loads(res.stdout)
        self.assertEqual(data["count"], 2)
        self.assertEqual(data["encoding"], "base64url")
        self.assertIn(0, data["head_stable_positions"])
        self.assertIn(1, data["head_stable_positions"])
        self.assertTrue(data["xor_alignment"])
        self.assertIn("head", data["xor_alignment"][0])
        self.assertIn("tail", data["xor_alignment"][0])
        self.assertIn("0x0000005a", data["checksum_key_candidates"])

    def test_custom_alphabet_and_invalid_alphabet_rejection(self) -> None:
        custom_alpha = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/"
        std_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        raw = b"\x10\x20\x30\x40\x50\x60"
        std_b64 = base64.b64encode(raw).decode("ascii")
        custom_b64 = std_b64.translate(str.maketrans(std_alpha, custom_alpha))

        res_ok = run_cli(
            OPAQUE_TOKEN_SCRIPT,
            custom_b64,
            "--encoding",
            "custom",
            "--alphabet",
            custom_alpha,
        )
        self.assertEqual(res_ok.returncode, 0, res_ok.stderr)
        parsed = json.loads(res_ok.stdout)
        self.assertEqual(parsed["samples"][0]["hex"], raw.hex())

        res_bad = run_cli(
            OPAQUE_TOKEN_SCRIPT,
            custom_b64,
            "--encoding",
            "custom",
            "--alphabet",
            "SHORT_ALPHABET",
        )
        self.assertNotEqual(res_bad.returncode, 0)

    def test_query_param_extraction(self) -> None:
        tok = base64.urlsafe_b64encode(b"\xaa\xbb\xcc\xdd\xee").decode("ascii").rstrip("=")
        url = f"https://app.internal/api?foo=1&sign={tok}&bar=2"
        res = run_cli(OPAQUE_TOKEN_SCRIPT, url, "--param", "sign", "--encoding", "base64url")
        self.assertEqual(res.returncode, 0, res.stderr)
        parsed = json.loads(res.stdout)
        self.assertEqual(parsed["samples"][0]["hex"], "aabbccddee")


class TestExperimentLedger(unittest.TestCase):
    def test_help_and_version(self) -> None:
        res_help = run_cli(EXPERIMENT_LEDGER_SCRIPT, "--help")
        self.assertEqual(res_help.returncode, 0, res_help.stderr)
        res_ver = run_cli(EXPERIMENT_LEDGER_SCRIPT, "--version")
        self.assertEqual(res_ver.returncode, 0, res_ver.stderr)

    def test_record_gate_summary_and_audit_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ledger = tmp_path / "ledger.jsonl"

            r1 = run_cli(
                EXPERIMENT_LEDGER_SCRIPT,
                "record",
                "--ledger",
                str(ledger),
                "--batch",
                "b1",
                "--variant",
                "v1",
                "--outcome",
                "transport_error",
            )
            self.assertEqual(r1.returncode, 0, r1.stderr)

            g1 = run_cli(
                EXPERIMENT_LEDGER_SCRIPT,
                "gate",
                "--ledger",
                str(ledger),
                "--batch",
                "b1",
                "--budget",
                "1",
            )
            self.assertEqual(g1.returncode, 0, g1.stderr)
            self.assertTrue(json.loads(g1.stdout)["allowed"])

            r2 = run_cli(
                EXPERIMENT_LEDGER_SCRIPT,
                "record",
                "--ledger",
                str(ledger),
                "--batch",
                "b1",
                "--variant",
                "v2",
                "--outcome",
                "rejected",
            )
            self.assertEqual(r2.returncode, 0, r2.stderr)

            g2 = run_cli(
                EXPERIMENT_LEDGER_SCRIPT,
                "gate",
                "--ledger",
                str(ledger),
                "--batch",
                "b1",
                "--budget",
                "5",
            )
            self.assertEqual(g2.returncode, 2)
            self.assertEqual(json.loads(g2.stdout)["reason"], "server_rejection_recorded")

            base_req = tmp_path / "base.json"
            cand_req = tmp_path / "cand.json"
            secret_a = "SUPER_SECRET_TOKEN_VALUE_ALPHA"
            secret_b = "SUPER_SECRET_TOKEN_VALUE_BETA"
            base_req.write_text(
                json.dumps(
                    {
                        "method": "POST",
                        "url": "https://service.local/api/v1/check?b=2&a=1",
                        "headers": {"X-Sign": secret_a, "User-Agent": "Test/1.0"},
                        "cookies": "c2=v2; c1=v1",
                        "body": "{\"k\":1}",
                    }
                ),
                encoding="utf-8",
            )
            cand_req.write_text(
                json.dumps(
                    {
                        "method": "POST",
                        "url": "https://service.local/api/v1/check?a=1&b=2",
                        "headers": {"x-sign": secret_b, "user-agent": "Test/1.0"},
                        "cookies": {"c1": "v1", "c2": "v2"},
                        "body": "{\"k\":1}",
                    }
                ),
                encoding="utf-8",
            )

            audit = run_cli(
                EXPERIMENT_LEDGER_SCRIPT,
                "audit",
                "--base",
                str(base_req),
                "--candidate",
                str(cand_req),
                "--allow",
                "header:x-sign",
                "--must-change",
                "header:x-sign",
            )
            self.assertEqual(audit.returncode, 0, audit.stderr)
            self.assertNotIn(secret_a, audit.stdout)
            self.assertNotIn(secret_b, audit.stdout)
            audit_json = json.loads(audit.stdout)
            self.assertTrue(audit_json["single_variable_confirmed"])
            self.assertEqual(audit_json["changed_fields"], ["header:x-sign"])
            self.assertEqual(
                audit_json["diffs"][0]["base"]["sha256"],
                hashlib.sha256(secret_a.encode("utf-8")).hexdigest()[:16],
            )


class TestProjectBaseline(unittest.TestCase):
    def test_create_and_check_with_windows_case_normalization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "bundle" / "signer.js"
            sample.parent.mkdir(parents=True, exist_ok=True)
            sample.write_text("function sign(x) { return x; }\n", encoding="utf-8")

            c_res = run_cli(
                PROJECT_BASELINE_SCRIPT,
                "create",
                "--root",
                str(root),
                "--manifest",
                "baseline.json",
                "--files",
                "bundle/signer.js",
                "--identity",
                "sdk_public=2.1.0",
            )
            self.assertEqual(c_res.returncode, 0, c_res.stderr)

            root_swapped_drive = str(root)
            if len(root_swapped_drive) >= 2 and root_swapped_drive[1] == ":":
                drive = root_swapped_drive[0]
                swapped = drive.lower() if drive.isupper() else drive.upper()
                root_swapped_drive = swapped + root_swapped_drive[1:]

            chk_ok = run_cli(
                PROJECT_BASELINE_SCRIPT,
                "check",
                "--root",
                root_swapped_drive,
                "--manifest",
                "baseline.json",
            )
            self.assertEqual(chk_ok.returncode, 0, chk_ok.stderr)
            chk_data = json.loads(chk_ok.stdout)
            self.assertEqual(chk_data["status"], "unchanged")
            self.assertEqual(chk_data["versions"]["skill"], "1.0.0")
            self.assertEqual(chk_data["identities"]["sdk_public"], "2.1.0")

            sample.write_text("function sign(x) { return x + 1; }\n", encoding="utf-8")
            chk_changed = run_cli(
                PROJECT_BASELINE_SCRIPT,
                "check",
                "--root",
                str(root),
                "--manifest",
                "baseline.json",
            )
            self.assertEqual(chk_changed.returncode, 1)
            self.assertEqual(json.loads(chk_changed.stdout)["status"], "changed")


class TestKotlinApkInspector(unittest.TestCase):
    def test_fingerprint_recover_lookup_and_find_api(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            apk_path = tmp_path / "sample.apk"
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("AndroidManifest.xml", "<manifest/>")
                zf.writestr("classes.dex", b"dex\n035\x00...Lkotlin/Metadata;...Lokhttp3/OkHttpClient;")
                zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF")
                zf.writestr("kotlin/kotlin.kotlin_builtins", b"kotlin")

            fp = run_cli(KOTLIN_INSPECTOR_SCRIPT, "fingerprint", str(apk_path), "--json")
            self.assertEqual(fp.returncode, 0, fp.stderr)
            fp_data = json.loads(fp.stdout)
            self.assertEqual(fp_data["container_type"], "apk")
            self.assertTrue(fp_data["has_kotlin_metadata"])
            self.assertEqual(fp_data["dex_count"], 1)
            self.assertIn("arm64-v8a", fp_data["abis"])

            src_dir = tmp_path / "sources"
            obf_file = src_dir / "a" / "b" / "c.java"
            obf_file.parent.mkdir(parents=True, exist_ok=True)
            obf_file.write_text(
                """package a.b;
import kotlin.Metadata;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import retrofit2.http.POST;
import okhttp3.CertificatePinner;

@Metadata(
    d1 = {"\\u0000\\n"},
    d2 = {"Lcom/example/auth/TokenSigner;", "", "signPayload", "(Ljava/lang/String;)Ljava/lang/String;"},
    k = 1,
    mv = {1, 9, 0}
)
@DebugMetadata(c = "com.example.auth.TokenSigner", f = "TokenSigner.kt", l = {42}, m = "signPayload")
public final class c {
    @POST("/v1/auth/sign")
    public String signPayload(String body) {
        CertificatePinner pinner = new CertificatePinner.Builder().build();
        return "https://api-gw.internal.corp/v1/auth/sign";
    }
}
""",
                encoding="utf-8",
            )

            out_dir = tmp_path / "kotlin_map"
            rec = run_cli(KOTLIN_INSPECTOR_SCRIPT, "recover-kotlin", str(src_dir), str(out_dir))
            self.assertEqual(rec.returncode, 0, rec.stderr)
            rec_data = json.loads(rec.stdout)
            self.assertGreaterEqual(rec_data["recovered_classes"], 1)
            mapping = json.loads((out_dir / "mapping.json").read_text(encoding="utf-8"))
            self.assertEqual(mapping.get("a.b.c"), "com.example.auth.TokenSigner")

            lk_obf = run_cli(KOTLIN_INSPECTOR_SCRIPT, "lookup", str(out_dir), "-o", "a.b.c")
            self.assertEqual(lk_obf.returncode, 0, lk_obf.stderr)
            self.assertIn("com.example.auth.TokenSigner", lk_obf.stdout)

            lk_grep = run_cli(
                KOTLIN_INSPECTOR_SCRIPT,
                "lookup",
                str(out_dir),
                "--grep",
                "signPayload",
                "--sources",
                str(src_dir),
            )
            self.assertEqual(lk_grep.returncode, 0, lk_grep.stderr)
            self.assertIn("com.example.auth.TokenSigner", lk_grep.stdout)

            api_res = run_cli(KOTLIN_INSPECTOR_SCRIPT, "find-api", str(src_dir), "--all", "--json")
            self.assertEqual(api_res.returncode, 0, api_res.stderr)
            api_data = json.loads(api_res.stdout)
            self.assertTrue(api_data["retrofit"])
            self.assertTrue(api_data["okhttp"])
            self.assertTrue(api_data["urls"])


class TestReviewCase(unittest.TestCase):
    def test_valid_and_invalid_case_review_with_windows_drive_casing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            case_root = Path(tmp)
            (case_root / "artifacts").mkdir()
            (case_root / "evidence").mkdir()
            (case_root / "report").mkdir()

            artifact = case_root / "artifacts" / "sample.bin"
            artifact_bytes = b"MZ_SAMPLE_BINARY_PAYLOAD"
            artifact.write_bytes(artifact_bytes)
            sha256_hex = hashlib.sha256(artifact_bytes).hexdigest()

            artifact_str = str(artifact)
            if len(artifact_str) >= 2 and artifact_str[1] == ":":
                d = artifact_str[0]
                artifact_str = (d.lower() if d.isupper() else d.upper()) + artifact_str[1:]

            (case_root / "scope.md").write_text(
                "# Scope\n- Target: sample.bin\n- Authorization: local\n- Goal: verify\n",
                encoding="utf-8",
            )
            (case_root / "workitems.md").write_text(
                "# Workitems\n- [x] W-001 Inspect sample.bin\n",
                encoding="utf-8",
            )
            (case_root / "timeline.md").write_text(
                "# Timeline\n- 2026-11-07T20:00:00Z Collected E-001\n",
                encoding="utf-8",
            )
            (case_root / "evidence" / "E-001.md").write_text(
                f"""# E-001
- id: E-001
- type: static
- source: {artifact_str}
- locator: 0x00401000
- sha256: {sha256_hex}
- reproduced: true
- summary: Verified entry point
""",
                encoding="utf-8",
            )
            (case_root / "report" / "REPORT.md").write_text(
                """# Case Report
### F-001
- id: F-001
- status: confirmed
- confidence: high
- evidence: E-001
- summary: Entry point verified

### P-001
- id: P-001
- status: verified
- findings: F-001
- evidence: E-001
- next: done
""",
                encoding="utf-8",
            )

            res_pass = run_cli(
                REVIEW_CASE_SCRIPT,
                str(case_root),
                "--format",
                "json",
                "--verify-hashes",
                "--strict",
            )
            self.assertEqual(res_pass.returncode, 0, res_pass.stderr)
            report = json.loads(res_pass.stdout)
            self.assertEqual(report["status"], "PASS", json.dumps(report, indent=2))
            outside_codes = [
                f["code"] for f in report.get("findings", []) if f["code"] == "artifact.outside_case"
            ]
            self.assertEqual(outside_codes, [])

            (case_root / "evidence" / "E-001.md").write_text(
                f"""# E-001
- id: E-001
- type: static
- source: {artifact_str}
- locator: 0x00401000
- sha256: {"0" * 64}
- reproduced: true
- summary: Tampered hash
""",
                encoding="utf-8",
            )
            res_fail = run_cli(
                REVIEW_CASE_SCRIPT,
                str(case_root),
                "--format",
                "json",
                "--verify-hashes",
            )
            self.assertEqual(res_fail.returncode, 1)
            self.assertEqual(json.loads(res_fail.stdout)["status"], "FAIL")


class TestClaudeSkillsParity(unittest.TestCase):
    def test_claude_skills_mirror_agents_skills_byte_for_byte(self) -> None:
        repo_root = SKILLS_ROOT.parent.parent
        claude_skills = repo_root / ".claude" / "skills"
        for skill_name in (
            "rea-js-reverse-lab",
            "rea-android-kotlin-recovery",
            "rea-case-review",
        ):
            src_dir = SKILLS_ROOT / skill_name
            dst_dir = claude_skills / skill_name
            self.assertTrue(src_dir.is_dir(), f"Missing .agents/skills/{skill_name}")
            self.assertTrue(dst_dir.is_dir(), f"Missing .claude/skills/{skill_name}")

            src_files = {
                p.relative_to(src_dir).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in src_dir.rglob("*")
                if p.is_file() and "__pycache__" not in p.parts and not p.name.endswith(".pyc")
            }
            dst_files = {
                p.relative_to(dst_dir).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in dst_dir.rglob("*")
                if p.is_file() and "__pycache__" not in p.parts and not p.name.endswith(".pyc")
            }
            self.assertEqual(
                src_files,
                dst_files,
                f"Drift detected between .agents/skills/{skill_name} and .claude/skills/{skill_name}",
            )


if __name__ == "__main__":
    unittest.main()
