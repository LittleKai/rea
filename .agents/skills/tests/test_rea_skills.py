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
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import types
import unittest
import urllib.error
import zipfile
import zlib
from pathlib import Path
from unittest import mock

SKILLS_ROOT = Path(__file__).resolve().parents[1]
JS_LAB_SCRIPTS = SKILLS_ROOT / "rea-js-reverse-lab" / "scripts"
ANDROID_SCRIPTS = SKILLS_ROOT / "rea-android-kotlin-recovery" / "scripts"
CASE_REVIEW_SCRIPTS = SKILLS_ROOT / "rea-case-review" / "scripts"
ANTI_REA_SCRIPTS = SKILLS_ROOT / "anti-rea" / "scripts"

OPAQUE_TOKEN_SCRIPT = JS_LAB_SCRIPTS / "opaque_token_inspect.py"
EXPERIMENT_LEDGER_SCRIPT = JS_LAB_SCRIPTS / "experiment_ledger.py"
PROJECT_BASELINE_SCRIPT = JS_LAB_SCRIPTS / "project_baseline.py"
KOTLIN_INSPECTOR_SCRIPT = ANDROID_SCRIPTS / "kotlin_apk_inspector.py"
REVIEW_CASE_SCRIPT = CASE_REVIEW_SCRIPTS / "review_case.py"
ANTI_REA_SCRIPT = ANTI_REA_SCRIPTS / "audit_anti_rea.py"

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


class TestAntiReaAuditor(unittest.TestCase):
    def test_help_and_version(self) -> None:
        res_help = run_cli(ANTI_REA_SCRIPT, "--help")
        self.assertEqual(res_help.returncode, 0, res_help.stderr)
        self.assertIn("audit-dir", res_help.stdout)
        self.assertIn("check-url", res_help.stdout)

        res_ver = run_cli(ANTI_REA_SCRIPT, "--version")
        self.assertEqual(res_ver.returncode, 0, res_ver.stderr)
        self.assertTrue(res_ver.stdout.strip())

    def test_audit_dir_detects_exposures_and_passes_clean_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pub = root / "public"
            (pub / "js").mkdir(parents=True)
            (pub / "assets" / "pilot").mkdir(parents=True)

            # Build 25 XOR-encoded plain identifier entries matching 0x45d9f3b schedule
            entries: list[str] = []
            for idx in range(25):
                raw = f"coreSymbolFunc{idx}".encode("utf-8")
                key = ((idx + 1) * 0x45D9F3B) & 0xFF or 0x5A
                enc = bytes(b ^ ((key + ((i * 17) & 0xFF)) & 0xFF) for i, b in enumerate(raw))
                entries.append(base64.b64encode(enc).decode("ascii"))

            bundle_js = (
                f'const tbl={json.dumps(entries)};'
                'const p="file:"===loc.protocol||"localhost"===loc.hostname;'
                'if(!p){el.textContent="Unauthorized domain";return;}'
                'const passthrough=new Set(["window","document","customCharacterPacks"]);'
                'const glsl="uniform mat4 uVP; in vec3 aPosition; out vec3 outPos;";'
                'function check(hasToken){if(!hasToken)return false;return !obj.isProActive||!obj.isPro||!obj.shouldWatermarkExport;}'
                'function u(s){s^=s<<13;s^=s>>>17;s^=s<<5;return s;}'
            )
            (pub / "js" / "app.min.js").write_text(bundle_js, encoding="utf-8")
            (pub / "js" / "app.min.js.map").write_text('{"version":3,"mappings":"AAAA"}', encoding="utf-8")
            (pub / "assets" / "pilot" / "prop.asset.json").write_text(
                json.dumps({"source": "design-mcp/blender/.pjs/stage", "glb_sha256": "a" * 64}),
                encoding="utf-8",
            )
            (pub / "assets" / "pilot" / "prop.glb").write_bytes(b"LUMI18\x01\x00\x11\x22\x33\x44payload")

            res = run_cli(ANTI_REA_SCRIPT, "audit-dir", str(pub), "--strict")
            self.assertEqual(res.returncode, 1)
            report = json.loads(res.stdout)
            codes = {f["code"] for f in report["findings"]}
            self.assertIn("F-SOURCEMAP-FILE", codes)
            self.assertIn("F-SIDECAR-METADATA", codes)
            self.assertIn("F-VAULT-SYMBOL-TABLE", codes)
            self.assertIn("F-GLSL-PLAINTEXT", codes)
            self.assertIn("F-UNMANGLED-COMMERCIAL-PROPS", codes)
            self.assertIn("F-PERMISSIVE-DOMAIN-LOCK", codes)
            self.assertIn("F-FAILOPEN-WATERMARK", codes)
            self.assertIn("F-INLINE-ASSET-SEED", codes)
            self.assertIn("F-WINDOW-PASSTHROUGH", codes)

            # Verify a clean hardened directory passes --strict with exit 0
            clean_dir = root / "clean_public"
            (clean_dir / "js").mkdir(parents=True)
            (clean_dir / "js" / "app.min.js").write_text(
                '(function(){const slot=[1,2,3];if(location.hostname!=="app.example.com")return;})();',
                encoding="utf-8",
            )
            res_clean = run_cli(ANTI_REA_SCRIPT, "audit-dir", str(clean_dir), "--strict")
            self.assertEqual(res_clean.returncode, 0, res_clean.stderr)
            self.assertEqual(json.loads(res_clean.stdout)["finding_count"], 0)

    def test_check_url_requires_allow_live_and_detects_secfetch_and_cache_bugs(self) -> None:
        denied = run_cli(ANTI_REA_SCRIPT, "check-url", "https://app.example.com/studio/tool")
        self.assertEqual(denied.returncode, 2)
        self.assertIn("--allow-live", denied.stderr)

        mod = _load_script_module(ANTI_REA_SCRIPT)
        spa_bytes = b"<!doctype html><html><body>SPA SHELL</body></html>"
        spa_hash_prefix = hashlib.sha256(spa_bytes).hexdigest()[:16]

        def fake_passive_get(url: str, headers: dict[str, str], timeout: float) -> dict[str, object]:
            if url.endswith("/robots.txt"):
                return {
                    "url": url,
                    "final_url": url,
                    "status": 200,
                    "sampled_bytes": 24,
                    "body_sha256_prefix": "1111222233334444",
                    "headers": {"content-type": "text/plain"},
                    "body_head": "User-agent: *\nAllow: /\n",
                }
            if url.endswith("/tool/app.min.js"):
                if headers.get("Sec-Fetch-Site") == "cross-site":
                    return {
                        "url": url,
                        "final_url": url,
                        "status": 403,
                        "sampled_bytes": 0,
                        "body_sha256_prefix": None,
                        "headers": {},
                        "body_head": "",
                    }
                return {
                    "url": url,
                    "final_url": url,
                    "status": 200,
                    "sampled_bytes": 128,
                    "body_sha256_prefix": "aaaa1111bbbb2222",
                    "headers": {"content-type": "application/javascript"},
                    "body_head": "console.log(1);",
                }
            if url.endswith("/tool/missing.js"):
                return {
                    "url": url,
                    "final_url": url,
                    "status": 200,
                    "sampled_bytes": len(spa_bytes),
                    "body_sha256_prefix": spa_hash_prefix,
                    "headers": {
                        "content-type": "text/html; charset=utf-8",
                        "cache-control": "public, max-age=31536000, immutable",
                    },
                    "body_head": spa_bytes.decode("utf-8"),
                }
            return {
                "url": url,
                "final_url": url,
                "status": 200,
                "sampled_bytes": len(spa_bytes),
                "body_sha256_prefix": spa_hash_prefix,
                "headers": {"content-type": "text/html; charset=utf-8"},
                "body_head": spa_bytes.decode("utf-8"),
            }

        with mock.patch.object(mod, "_passive_get", side_effect=fake_passive_get):
            res_live = run_cli(
                ANTI_REA_SCRIPT,
                "check-url",
                "https://app.example.com/studio/tool",
                "--asset-path",
                "/tool/app.min.js",
                "--asset-path",
                "/tool/missing.js",
                "--allow-live",
                "--strict",
            )
            self.assertEqual(res_live.returncode, 1)
            live_report = json.loads(res_live.stdout)
            live_codes = {f["code"] for f in live_report["findings"]}
            self.assertIn("F-ROBOTS-MISSING", live_codes)
            self.assertIn("F-CSP-FRAME-ANCESTORS", live_codes)
            self.assertIn("F-SECFETCH-BYPASS", live_codes)
            self.assertIn("F-SPA-IMMUTABLE-CACHE", live_codes)


def _build_minimal_binary_axml(package_name: str = "com.example.app") -> bytes:
    """Construct a valid minimal Android Binary XML (AXML) manifest with debuggable/allowBackup/cleartext."""
    strings = [
        "http://schemas.android.com/apk/res/android",
        "android",
        "manifest",
        "package",
        package_name,
        "uses-sdk",
        "minSdkVersion",
        "targetSdkVersion",
        "application",
        "debuggable",
        "allowBackup",
        "usesCleartextTraffic",
        "activity",
        "name",
        ".MainActivity",
    ]
    res_ids = [
        0,  # ns url
        0,  # ns prefix
        0,  # manifest
        0,  # package
        0,  # pkg val
        0,  # uses-sdk
        0x0101020C,  # minSdkVersion
        0x01010270,  # targetSdkVersion
        0,  # application
        0x0101000F,  # debuggable
        0x01010280,  # allowBackup
        0x010104EC,  # usesCleartextTraffic
    ]

    encoded_entries: list[bytes] = []
    offsets: list[int] = []
    cur = 0
    for s in strings:
        u16 = s.encode("utf-16le")
        entry = struct.pack("<H", len(s)) + u16 + b"\x00\x00"
        offsets.append(cur)
        encoded_entries.append(entry)
        cur += len(entry)
    pool_blob = b"".join(encoded_entries)
    while len(pool_blob) % 4 != 0:
        pool_blob += b"\x00"

    strings_start = 28 + 4 * len(strings)
    sp_size = strings_start + len(pool_blob)
    sp_chunk = (
        struct.pack("<HHIIIIII", 0x0001, 28, sp_size, len(strings), 0, 0, strings_start, 0)
        + b"".join(struct.pack("<I", o) for o in offsets)
        + pool_blob
    )

    rm_body = b"".join(struct.pack("<I", r) for r in res_ids)
    rm_chunk = struct.pack("<HHI", 0x0180, 8, 8 + len(rm_body)) + rm_body

    def attr_str(ns: int, name_idx: int, str_idx: int) -> bytes:
        return struct.pack("<IIIHBBI", ns, name_idx, str_idx, 8, 0, 0x03, str_idx)

    def attr_int(ns: int, name_idx: int, data_type: int, val: int) -> bytes:
        return struct.pack("<IIIHBBI", ns, name_idx, 0xFFFFFFFF, 8, 0, data_type, val & 0xFFFFFFFF)

    def start_el(name_idx: int, attrs: list[bytes]) -> bytes:
        body = struct.pack("<IIIIHHHHHH", 1, 0xFFFFFFFF, 0xFFFFFFFF, name_idx, 20, 20, len(attrs), 0, 0, 0) + b"".join(attrs)
        return struct.pack("<HHI", 0x0102, 16, 8 + len(body)) + body

    def end_el(name_idx: int) -> bytes:
        return struct.pack("<HHIIIII", 0x0103, 16, 24, 1, 0xFFFFFFFF, 0xFFFFFFFF, name_idx)

    ns_uri = 0
    no_ns = 0xFFFFFFFF
    xml_body = b"".join(
        [
            sp_chunk,
            rm_chunk,
            start_el(2, [attr_str(no_ns, 3, 4)]),
            start_el(5, [attr_int(ns_uri, 6, 0x10, 24), attr_int(ns_uri, 7, 0x10, 34)]),
            end_el(5),
            start_el(
                8,
                [
                    attr_int(ns_uri, 9, 0x12, 0xFFFFFFFF),
                    attr_int(ns_uri, 10, 0x12, 0xFFFFFFFF),
                    attr_int(ns_uri, 11, 0x12, 0xFFFFFFFF),
                ],
            ),
            start_el(12, [attr_str(ns_uri, 13, 14)]),
            end_el(12),
            end_el(8),
            end_el(2),
        ]
    )
    return struct.pack("<HHI", 0x0003, 8, 8 + len(xml_body)) + xml_body


def _build_minimal_dex035() -> bytes:
    """Construct a valid minimal 116-byte DEX 035 image with 0-entry map_list, SHA-1, and Adler-32."""
    hdr = bytearray(116)
    hdr[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", hdr, 32, 116)  # file_size
    struct.pack_into("<I", hdr, 36, 112)  # header_size
    struct.pack_into("<I", hdr, 40, 0x12345678)  # endian_tag
    struct.pack_into("<I", hdr, 52, 112)  # map_off
    struct.pack_into("<I", hdr, 104, 4)  # data_size
    struct.pack_into("<I", hdr, 108, 112)  # data_off
    hdr[12:32] = hashlib.sha1(bytes(hdr[32:])).digest()
    struct.pack_into("<I", hdr, 8, zlib.adler32(bytes(hdr[12:])) & 0xFFFFFFFF)
    return bytes(hdr)


def _build_minimal_wasm_with_data(payload: bytes) -> bytes:
    def uleb(v: int) -> bytes:
        out = bytearray()
        while True:
            b = v & 0x7F
            v >>= 7
            if v:
                b |= 0x80
            out.append(b)
            if not v:
                break
        return bytes(out)

    def sec(sec_id: int, body: bytes) -> bytes:
        return bytes([sec_id]) + uleb(len(body)) + body

    data_sec = sec(11, bytes([1, 0x00, 0x41, 0x00, 0x0B]) + uleb(len(payload)) + payload)
    return (
        b"\x00asm\x01\x00\x00\x00"
        + sec(1, b"\x01\x60\x00\x00")
        + sec(3, b"\x01\x00")
        + sec(5, b"\x01\x00\x01")
        + sec(7, b"\x01\x03nop\x00\x00")
        + sec(10, b"\x01\x02\x00\x0b")
        + data_sec
    )


class TestAntiReaOrchestratorPacks(unittest.TestCase):
    def test_zero_context_inflation_and_packs_registry(self) -> None:
        repo_root = SKILLS_ROOT.parent.parent
        packs_root = repo_root / "_skill_packs"
        self.assertTrue((packs_root / "INDEX.md").is_file(), "Missing _skill_packs/INDEX.md")
        leaked_skill_mds = list(packs_root.rglob("SKILL.md"))
        self.assertEqual(
            leaked_skill_mds,
            [],
            f"_skill_packs must contain zero SKILL.md files to prevent context inflation: {leaked_skill_mds}",
        )

        res = run_cli(ANTI_REA_SCRIPT, "packs", "--format", "json")
        self.assertEqual(res.returncode, 0, res.stderr)
        payload = json.loads(res.stdout)
        pack_ids = {p["id"] for p in payload["packs"]}
        self.assertEqual(
            pack_ids,
            {
                "bla-counter-rea",
                "web-edge-metering",
                "static-hardener-configs",
                "apk-exposure-inspector",
            },
        )
        for p in payload["packs"]:
            self.assertTrue((repo_root / p["playbook"]).is_file(), f"Missing playbook {p['playbook']}")

        # Verify flat custom --packs-dir override (outside _skill_packs/anti_rea parent hierarchy)
        with tempfile.TemporaryDirectory() as tmp:
            flat_dir = Path(tmp) / "custom_packs"
            flat_dir.mkdir()
            (flat_dir / "pack_registry.json").write_text(
                json.dumps(
                    {
                        "schema": "anti-rea.pack-registry/v1",
                        "packs": [
                            {
                                "id": "custom-test-pack",
                                "playbook": "PLAYBOOK.md",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            custom_pkg = flat_dir / "bla_counter_rea"
            custom_pkg.mkdir()
            (custom_pkg / "__init__.py").write_text("", encoding="utf-8")
            (custom_pkg / "packaging_gates.py").write_text(
                "def run_packaging_gates(target_path):\n"
                "    return {'schema': 'custom-gates/v1', 'finding_count': 0, 'findings': []}\n",
                encoding="utf-8",
            )
            flat_res = run_cli(ANTI_REA_SCRIPT, "--packs-dir", str(flat_dir), "packs", "--format", "json")
            self.assertEqual(flat_res.returncode, 0, flat_res.stderr)
            flat_payload = json.loads(flat_res.stdout)
            self.assertEqual([p["id"] for p in flat_payload["packs"]], ["custom-test-pack"])

            ov_res = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(ANTI_REA_SCRIPT),
                    f"--packs-dir={flat_dir}",
                    "lint-gates",
                    str(flat_dir),
                    "--format",
                    "json",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            self.assertEqual(ov_res.returncode, 0, ov_res.stderr)
            self.assertEqual(json.loads(ov_res.stdout)["schema"], "custom-gates/v1")

            missing_res = run_cli(ANTI_REA_SCRIPT, "--packs-dir", str(Path(tmp) / "missing_packs"), "packs")
            self.assertEqual(missing_res.returncode, 1)

        # Verify all relative Markdown links in _skill_packs/** and .agents/skills/anti-rea/** resolve on disk
        md_link_re = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
        broken_links: list[str] = []
        for md_root in (packs_root, SKILLS_ROOT / "anti-rea"):
            for md_file in md_root.rglob("*.md"):
                content = md_file.read_text(encoding="utf-8")
                for match in md_link_re.finditer(content):
                    target_ref = match.group(1).strip().split("#", 1)[0]
                    if not target_ref or target_ref.startswith(
                        ("http://", "https://", "mailto:", "conversation://", "file:///")
                    ):
                        continue
                    if not (md_file.parent / target_ref).exists():
                        broken_links.append(f"{md_file.relative_to(repo_root).as_posix()} -> {target_ref}")
        self.assertEqual(broken_links, [], f"Broken relative Markdown links: {broken_links}")

    def test_lint_gates_all_ten_footguns_and_honesty_caps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # 1. lane-independence + 4. js-aes-unwrap + 5. js-wasm-hydrate-dump + 8. panel-derive + 9. plaintext-secret
            (root / "license.cjs").write_text(
                "\n".join(
                    [
                        "const WRAP_KEY_HEX = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';",
                        "const SEALED_HDR = 'd17ea004';",
                        "const secretFlag = 'FLAG{synthetic_flag_123456}';",
                        "const panelTokenSha256 = 'abcd';",
                        "function deriveLocal(x) { return x; }",
                        "function check(key, crypto, mem, exp) {",
                        "  const d = crypto.createDecipheriv('aes-256-ctr', Buffer.from(WRAP_KEY_HEX, 'hex'), Buffer.alloc(16));",
                        "  exp.hydrate(0);",
                        "  const raw = Buffer.from(new Uint8Array(mem.buffer));",
                        "  const salt = raw.readInt32LE(0); const rounds = raw[4]; const clen = raw.readUInt16LE(24); const cipher = raw.slice(26);",
                        "  return key.charCodeAt(0) === 65 && key.charCodeAt(1) === 66 && key.charCodeAt(2) === 67 && Boolean(d && salt && rounds && clen && cipher);",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            # 2. seal-commitment (reversible ARX) + 7. sibling revision for wasm-seal-xor-known-plaintext
            rev_bytes = bytes(range(1, 33))
            (root / "seal.json").write_text(
                json.dumps(
                    {
                        "schema": "test-seal/v1",
                        "revision": rev_bytes.hex(),
                        "scheduleSalt": 12345,
                        "rounds": 16,
                        "certificateCipherHex": "deadbeefcafebabe",
                    }
                ),
                encoding="utf-8",
            )
            # 3. wasm-param-carrier + 6. wasm-xor-mask-sidecar
            mask = bytes((i * 7 + 3) & 0xFF for i in range(32))
            cipher_blob = bytes((0x80 + (i * 13)) & 0xFF for i in range(24))
            pack_plain = bytearray(26 + len(cipher_blob))
            struct.pack_into("<i", pack_plain, 0, 0x12345678)
            pack_plain[4] = 32  # rounds
            struct.pack_into("<iiii", pack_plain, 8, 0x1111, 0x2222, 0x3333, 0x4444)
            struct.pack_into("<H", pack_plain, 24, len(cipher_blob))
            pack_plain[26:] = cipher_blob
            masked_sidecar = bytes(pack_plain[i] ^ mask[i % 32] for i in range(len(pack_plain))) + mask
            (root / "sidecar.wasm").write_bytes(_build_minimal_wasm_with_data(masked_sidecar))

            # 3. clear carrier magic R3PARM\x00\x00 + binary bytes
            (root / "carrier.wasm").write_bytes(
                _build_minimal_wasm_with_data(b"R3PARM\x00\x00\x01\x02\x80\x90\xa0\xb0\xc0\xd0\xe0\xf0\x00\x11")
            )

            # 7. wasm-seal-xor-known-plaintext
            kp_plain = bytearray(42 + 24)
            struct.pack_into("<i", kp_plain, 0, 0x22223333)
            kp_plain[4] = 24
            kp_plain[8:40] = rev_bytes
            struct.pack_into("<H", kp_plain, 40, 24)
            kp_plain[42:] = cipher_blob
            kp_masked = bytes(kp_plain[i] ^ mask[i % 32] for i in range(len(kp_plain)))
            (root / "seal_kp.wasm").write_bytes(_build_minimal_wasm_with_data(kp_masked))

            # 10. release-hygiene (.env with secret assignment - value must NOT be echoed)
            sentinel_secret = "DO_NOT_ECHO_THIS_SECRET_991122"
            (root / ".env").write_text(f"API_SECRET={sentinel_secret}\n", encoding="utf-8")

            res = run_cli(ANTI_REA_SCRIPT, "lint-gates", str(root), "--strict", "--format", "json")
            self.assertEqual(res.returncode, 1, res.stderr)
            self.assertNotIn(sentinel_secret, res.stdout)
            report = json.loads(res.stdout)
            self.assertEqual(report["rea_limits_count"], 106)
            self.assertEqual(report["counter_rea_vectors"], 24)
            triggered = {g["gate"] for g in report["gates"] if g["finding_count"] > 0}
            self.assertEqual(
                triggered,
                {
                    "lane-independence",
                    "seal-commitment",
                    "wasm-param-carrier",
                    "js-aes-unwrap",
                    "js-wasm-hydrate-dump",
                    "wasm-xor-mask-sidecar",
                    "wasm-seal-xor-known-plaintext",
                    "panel-derive",
                    "plaintext-secret",
                    "release-hygiene",
                },
            )
            self.assertLessEqual(report["honesty"]["cappedScore"], 92)

    def test_verify_build_carry_buffer_and_audit_dir_integration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Straddle the exact 1 MiB (1048576) boundary with //# sourceMappingURL=app.js.map
            prefix_len = (1024 * 1024) - 10
            marker = b"\n//# sourceMappingURL=straddle.js.map\n"
            (root / "straddle.js").write_bytes((b"a" * prefix_len) + marker + (b"b" * 2048))
            (root / "bundle.js.map.gz").write_bytes(b"\x1f\x8b\x08\x00")
            (root / "_headers").write_text("/app.js\n  SourceMap: /app.js.map\n", encoding="utf-8")
            (root / "renamed.json").write_text(
                json.dumps({"version": 3, "sources": ["src/index.ts"], "mappings": "AAAA"}),
                encoding="utf-8",
            )
            # Negative control: non-sourcemap JSON with "mappings" and "sources" keys but no version 3
            (root / "benign_schema.json").write_text(
                json.dumps({"mappings": {"a": 1}, "sources": ["catalog"]}),
                encoding="utf-8",
            )

            vb_res = run_cli(ANTI_REA_SCRIPT, "verify-build", str(root), "--strict", "--format", "json")
            self.assertEqual(vb_res.returncode, 1, vb_res.stderr)
            vb = json.loads(vb_res.stdout)
            flagged_paths = {f["path"] for f in vb["findings"]}
            self.assertIn("straddle.js", flagged_paths)
            self.assertIn("bundle.js.map.gz", flagged_paths)
            self.assertIn("_headers", flagged_paths)
            self.assertIn("renamed.json", flagged_paths)
            self.assertNotIn("benign_schema.json", flagged_paths)

            ad_res = run_cli(ANTI_REA_SCRIPT, "audit-dir", str(root), "--strict", "--format", "json")
            self.assertEqual(ad_res.returncode, 1, ad_res.stderr)
            ad = json.loads(ad_res.stdout)
            ad_codes = {f["code"] for f in ad["findings"]}
            self.assertIn("F-SOURCEMAP-COMMENT", ad_codes)
            self.assertIn("F-COMPRESSED-SOURCEMAP", ad_codes)
            self.assertIn("F-HEADERS-SOURCEMAP", ad_codes)
            self.assertIn("F-RENAMED-SOURCEMAP", ad_codes)

    def test_scan_score_gen_config_and_harden_py(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src_dir = root / "app_src"
            src_dir.mkdir()
            (src_dir / "package.json").write_text('{"name":"demo","dependencies":{"electron":"^30.0.0"}}', encoding="utf-8")
            (src_dir / "billing.py").write_text(
                'def compute_discount(base_price: int) -> str:\n'
                '    secret_banner = "VIP_ENTERPRISE_TIER_UNLOCKED"\n'
                '    adjusted_total = base_price - 7\n'
                '    return f"{secret_banner}:{adjusted_total}"\n',
                encoding="utf-8",
            )

            sc_res = run_cli(ANTI_REA_SCRIPT, "scan-score", str(src_dir), "--format", "json")
            self.assertEqual(sc_res.returncode, 0, sc_res.stderr)
            sc = json.loads(sc_res.stdout)
            self.assertIn("reversibility_score", sc)
            self.assertIn("resistance_score", sc)

            cfg_dir = root / "generated_configs"
            gc_res = run_cli(ANTI_REA_SCRIPT, "gen-config", str(src_dir), "--out-dir", str(cfg_dir), "--format", "json")
            self.assertEqual(gc_res.returncode, 0, gc_res.stderr)
            for jname in ("terser.config.json", "javascript-obfuscator.json"):
                parsed_cfg = json.loads((cfg_dir / jname).read_text(encoding="utf-8"))
                self.assertIsInstance(parsed_cfg, dict)

            # In-tree destination must fail closed with exit 1
            bad_res = run_cli(ANTI_REA_SCRIPT, "harden-py", str(src_dir), str(src_dir / "nested"))
            self.assertEqual(bad_res.returncode, 1)

            out_dir = root / "app_hardened"
            hp_res = run_cli(
                ANTI_REA_SCRIPT,
                "harden-py",
                str(src_dir),
                str(out_dir),
                "--rename",
                "--format",
                "json",
            )
            self.assertEqual(hp_res.returncode, 0, hp_res.stderr)
            hardened_py = (out_dir / "billing.py").read_text(encoding="utf-8")
            self.assertNotIn("VIP_ENTERPRISE_TIER_UNLOCKED", hardened_py)
            self.assertNotIn("adjusted_total", hardened_py)
            mod = _load_script_module(out_dir / "billing.py")
            self.assertEqual(mod.compute_discount(50), "VIP_ENTERPRISE_TIER_UNLOCKED:43")

    def test_inspect_apk_binary_axml_dex_and_admission_guards(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk_path = root / "sample.apk"
            with zipfile.ZipFile(apk_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("AndroidManifest.xml", _build_minimal_binary_axml("com.alpha.studio"))
                zf.writestr("classes.dex", _build_minimal_dex035())
                zf.writestr(
                    "assets/www/app.js",
                    "\n".join([f"function step{i}() {{\n  const x = {i};\n  return x;\n}}" for i in range(6)]),
                )
                elf_hdr = bytearray(64)
                elf_hdr[0:7] = b"\x7fELF\x02\x01\x01"
                struct.pack_into("<HH", elf_hdr, 16, 3, 183)
                struct.pack_into("<H", elf_hdr, 52, 64)
                zf.writestr("lib/arm64-v8a/libengine.so", bytes(elf_hdr))

            res = run_cli(ANTI_REA_SCRIPT, "inspect-apk", str(apk_path), "--strict", "--format", "json")
            self.assertEqual(res.returncode, 1, res.stderr)
            report = json.loads(res.stdout)
            self.assertEqual(report["analysisKind"], "apk-static-inspection")
            self.assertEqual(report["manifest"]["package"], "com.alpha.studio")
            self.assertTrue(report["manifest"]["application"]["debuggable"])
            codes = {f["code"] for f in report["findings"]}
            self.assertIn("APK_DEBUGGABLE", codes)
            self.assertIn("APK_READABLE_JAVASCRIPT", codes)

            tiny_apk = root / "tiny.apk"
            tiny_apk.write_bytes(b"PK\x03\x04short")
            bad_tiny = run_cli(ANTI_REA_SCRIPT, "inspect-apk", str(tiny_apk))
            self.assertEqual(bad_tiny.returncode, 1)

            corrupt_apk = root / "corrupt.apk"
            corrupt_apk.write_bytes(b"NOT_A_ZIP_FILE_AT_ALL_30_BYTES")
            bad_corrupt = run_cli(ANTI_REA_SCRIPT, "inspect-apk", str(corrupt_apk))
            self.assertEqual(bad_corrupt.returncode, 1)
            self.assertIn("Malformed or unsupported APK structure", bad_corrupt.stderr)
            self.assertNotIn("Traceback", bad_corrupt.stderr)

            link_apk = root / "symlink.apk"
            try:
                os.symlink(apk_path, link_apk)
            except OSError:
                pass
            else:
                bad_link = run_cli(ANTI_REA_SCRIPT, "inspect-apk", str(link_apk))
                self.assertEqual(bad_link.returncode, 1)

            # PCR-05: Markdown projection must display manifest['package'] and clean evidence strings
            md_res = run_cli(ANTI_REA_SCRIPT, "inspect-apk", str(apk_path), "--format", "md")
            self.assertEqual(md_res.returncode, 0, md_res.stderr)
            self.assertIn("`com.alpha.studio`", md_res.stdout)
            self.assertNotIn("`unknown`", md_res.stdout)
            self.assertNotIn("['AndroidManifest.xml", md_res.stdout)

    def test_review_regressions_future_imports_rename_boundaries_and_url_safety(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            # PCR-01 + PCR-02 + PCR-06 + PCR-09:
            # 1) `from __future__ import annotations` must stay above header and pass compile()
            # 2) `except ... as e:` and `match/case` bindings must not be corrupted by --rename
            # 3) URL basic-auth userinfo must be redacted in scan-score
            src_dir = root / "ModernApp"
            src_dir.mkdir()
            (src_dir / "service.py").write_text(
                '"""Module docstring to strip."""\n'
                "from __future__ import annotations\n\n"
                'API_DSN = "https://admin:TopSecretPass99@internal.example.com/v1/charge"\n\n'
                "def evaluate_flow(payload: object) -> tuple[str, str, str]:\n"
                "    json = None\n"
                "    try:\n"
                "        import json\n"
                "    except ImportError:\n"
                "        pass\n"
                '    err = "STALE_OUTER_ERR"\n'
                '    captured = "STALE_OUTER_MATCH"\n'
                '    tail = ["STALE_TAIL"]\n'
                "    try:\n"
                '        raise RuntimeError("REAL_INNER_EXCEPTION")\n'
                "    except RuntimeError as err:\n"
                "        caught_msg = str(err)\n"
                "    match payload:\n"
                "        case [head, *tail] as captured:\n"
                '            summary = f"{head}:{len(tail)}:{len(captured)}:{json is not None}"\n'
                "        case _:\n"
                '            summary = "fallback"\n'
                '    banner = "PRO_ENTITLEMENT_SEAL"\n'
                "    return caught_msg, summary, banner\n",
                encoding="utf-8",
            )

            sc_res = run_cli(ANTI_REA_SCRIPT, "scan-score", str(src_dir), "--format", "json")
            self.assertEqual(sc_res.returncode, 0, sc_res.stderr)
            self.assertNotIn("TopSecretPass99", sc_res.stdout)
            self.assertIn("<REDACTED>", sc_res.stdout)

            if os.name == "nt":
                swapped_in_tree = str(src_dir).swapcase() + os.sep + "nested_out"
                case_res = run_cli(ANTI_REA_SCRIPT, "harden-py", str(src_dir), swapped_in_tree)
                self.assertEqual(case_res.returncode, 1)

            out_dir = root / "ModernAppHardened"
            hp_res = run_cli(
                ANTI_REA_SCRIPT,
                "harden-py",
                str(src_dir),
                str(out_dir),
                "--rename",
                "--format",
                "json",
            )
            self.assertEqual(hp_res.returncode, 0, hp_res.stderr)
            hp_manifest = json.loads(hp_res.stdout)["manifest"]
            self.assertEqual(hp_manifest["python_files_hardened"], 1)
            hardened_code = (out_dir / "service.py").read_text(encoding="utf-8")
            compile(hardened_code, str(out_dir / "service.py"), "exec")
            self.assertNotIn("PRO_ENTITLEMENT_SEAL", hardened_code)
            mod = _load_script_module(out_dir / "service.py")
            self.assertEqual(
                mod.evaluate_flow(["item0", "item1", "item2"]),
                ("REAL_INNER_EXCEPTION", "item0:2:3:True", "PRO_ENTITLEMENT_SEAL"),
            )

            # PCR-04: inline data: sourceMappingURL straddling 1 MiB chunk boundary + CSS sourcemap in audit-dir
            web_dir = root / "web_dist"
            web_dir.mkdir()
            inline_marker = b"\n//# sourceMappingURL=data:application/json;base64,e30=\n"
            (web_dir / "chunk_inline.js").write_bytes((b"x" * ((1024 * 1024) - 24)) + inline_marker + (b"y" * 128))
            vb_inline = json.loads(run_cli(ANTI_REA_SCRIPT, "verify-build", str(web_dir), "--format", "json").stdout)
            signals = [f["signal"] for f in vb_inline["findings"] if f["path"] == "chunk_inline.js"]
            self.assertEqual(signals, ["inline-source-map"])

            css_only_dir = root / "css_dist"
            css_only_dir.mkdir()
            (css_only_dir / "styles.css").write_text("body{color:red}\n/*# sourceMappingURL=styles.css.map */\n", encoding="utf-8")
            ad_css = run_cli(ANTI_REA_SCRIPT, "audit-dir", str(css_only_dir), "--strict", "--format", "json")
            self.assertEqual(ad_css.returncode, 1, ad_css.stderr)
            self.assertIn("F-SOURCEMAP-COMMENT", {f["code"] for f in json.loads(ad_css.stdout)["findings"]})

            # PCR-03: check-url rejects file:// and cross-origin --asset-path and handles URLError cleanly
            bad_file_asset = run_cli(
                ANTI_REA_SCRIPT,
                "check-url",
                "https://app.example.com/studio",
                "--allow-live",
                "--asset-path",
                "file:///C:/Windows/win.ini",
            )
            self.assertEqual(bad_file_asset.returncode, 1)
            bad_cross_asset = run_cli(
                ANTI_REA_SCRIPT,
                "check-url",
                "https://app.example.com/studio",
                "--allow-live",
                "--asset-path",
                "https://evil.example.org/bundle.js",
            )
            self.assertEqual(bad_cross_asset.returncode, 1)

            auditor_mod = _load_script_module(ANTI_REA_SCRIPT)
            with mock.patch.object(
                auditor_mod,
                "_HTTP_OPENER",
                mock.Mock(open=mock.Mock(side_effect=urllib.error.URLError("connection refused"))),
            ):
                net_err_rep = auditor_mod.check_live_url("https://app.example.com/studio", allow_live=True, timeout=1.0)
                self.assertEqual(net_err_rep["checks"][0]["status"], 0)

            # PCR-05: standalone audit_anti_rea.py copied outside the REA repo works with flat --packs-dir
            standalone_dir = root / "standalone_cli"
            standalone_dir.mkdir()
            standalone_script = standalone_dir / "audit_anti_rea.py"
            shutil.copy2(ANTI_REA_SCRIPT, standalone_script)
            flat_packs = root / "standalone_packs"
            shutil.copytree(SKILLS_ROOT.parent.parent / "_skill_packs" / "anti_rea", flat_packs)
            ext_res = subprocess.run(
                [sys.executable, "-I", "-B", str(standalone_script), "--packs-dir", str(flat_packs), "packs", "--format", "json"],
                cwd=str(standalone_dir),
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            self.assertEqual(ext_res.returncode, 0, ext_res.stderr)
            self.assertEqual(json.loads(ext_res.stdout)["pack_count"], 4)


class TestClaudeSkillsParity(unittest.TestCase):
    def test_claude_skills_mirror_agents_skills_byte_for_byte(self) -> None:
        repo_root = SKILLS_ROOT.parent.parent
        claude_skills = repo_root / ".claude" / "skills"
        for skill_name in (
            "rea-js-reverse-lab",
            "rea-android-kotlin-recovery",
            "rea-case-review",
            "anti-rea",
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
