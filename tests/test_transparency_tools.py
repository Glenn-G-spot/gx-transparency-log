"""Offline fixtures and negative controls for the Python transparency tools."""

import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gx_build_closure as closure
import gx_ots_max as ots
import gx_verify_max as maximum


PROOF_ID = "20260211T192351Z"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def snapshot(root):
    return {str(path.relative_to(root)): path.read_bytes()
            for path in root.rglob("*") if path.is_file()}


def varuint(value):
    encoded = bytearray()
    while value >= 128:
        encoded.append((value & 127) | 128)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def varbytes(value):
    return varuint(len(value)) + value


def detached(target, timestamp):
    return ots.OTS_MAGIC + b"\x01\x08" + hashlib.sha256(target).digest() + timestamp


def pending_proof(target, uri="https://a.calendar.opentimestamps.org"):
    timestamp = b"\x00" + ots.PENDING_TAG + varbytes(varbytes(uri.encode("ascii")))
    return detached(target, timestamp)


# Independent Bitcoin Core mainnet genesis vector:
# https://github.com/bitcoin/bitcoin/blob/master/src/kernel/chainparams.cpp
GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
GENESIS_MERKLE = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
GENESIS_HEADER = (
    struct.pack("<I", 1) + bytes(32) + bytes.fromhex(GENESIS_MERKLE)[::-1]
    + struct.pack("<III", 1231006505, 0x1D00FFFF, 2083236893)
)
GENESIS_MESSAGE = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
GENESIS_SCRIPT = bytes.fromhex("04ffff001d0104") + varbytes(GENESIS_MESSAGE)
GENESIS_PUBKEY = bytes.fromhex(
    "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649"
    "f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
)
GENESIS_TX = (
    struct.pack("<I", 1) + b"\x01" + bytes(32) + bytes.fromhex("ffffffff")
    + varbytes(GENESIS_SCRIPT) + bytes.fromhex("ffffffff") + b"\x01"
    + struct.pack("<Q", 5_000_000_000) + varbytes(varbytes(GENESIS_PUBKEY) + b"\xac")
    + bytes(4)
)
GENESIS_PROOF = detached(GENESIS_TX, b"\x08\x00" + ots.BITCOIN_TAG + varbytes(b"\x00"))


def provider_response(url, limit=ots.MAX_PROVIDER_BYTES):
    if url.endswith("/block-height/0"):
        value = GENESIS_HASH
    elif url.endswith("/header"):
        value = GENESIS_HEADER.hex()
    elif url.endswith("/blocks/tip/height"):
        value = "0"
    else:
        value = json.dumps({"id": GENESIS_HASH, "height": 0, "timestamp": 1231006505,
                            "merkle_root": GENESIS_MERKLE})
    return value, {"url": url, "mocked": True}


class TemporaryFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gx-tools-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()

    def maximum_args(self, *extra):
        with mock.patch.object(sys, "argv", ["gx_verify_max.py", "--repo", str(self.repo), *extra]):
            return maximum.parse_args()

    def quiet(self, function, *args):
        with contextlib.redirect_stdout(io.StringIO()):
            return function(*args)


class ClosureTests(TemporaryFixture):
    def setUp(self):
        super().setUp()
        self.pack = self.root / "pack"
        self.pack.mkdir()
        self.output = self.root / "closure"
        payloads = {"one.txt": b"first artifact\n", "two.txt": b"second artifact\n"}
        rows = ["path\tbytes\tsha256"]
        for name, data in payloads.items():
            (self.pack / name).write_bytes(data)
            rows.append(f"{name}\t{len(data)}\t{digest(data)}")
        self.manifest = self.pack / f"GX_PROOF_MANIFEST_{PROOF_ID}.tsv"
        self.manifest.write_text("\n".join(rows) + "\n")
        bundle = self.pack / f"GX_PROOF_PACK_{PROOF_ID}.tar.gz"
        with tarfile.open(bundle, "w:gz") as archive:
            for name, data in payloads.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        root_file = self.pack / f"GX_PROOF_ROOT_{PROOF_ID}.txt"
        root_file.write_text(f"manifest_sha256: {digest(self.manifest.read_bytes())}\n"
                             f"bundle_sha256: {digest(bundle.read_bytes())}\nmerkle_root_sha256: \n")
        summary = self.pack / f"GX_PROOF_SUMMARY_{PROOF_ID}.txt"
        summary.write_text("synthetic proof pack\n")
        (self.pack / f"GX_LEAVES_{PROOF_ID}.txt").write_text(
            "\n".join(sorted(digest(data) for data in payloads.values())) + "\n")
        self.index = self.pack / "GX_PROOF_INDEX.txt"
        self.index.write_text("\n".join(sorted(path.name for path in self.pack.iterdir())) + "\n")
        (self.pack / "GX_PROOF_INDEX.txt.sha256").write_text(
            digest(self.index.read_bytes()) + "  GX_PROOF_INDEX.txt\n")
        level = sorted(digest(path.read_bytes()) for path in (root_file, bundle, self.manifest, summary))
        while len(level) > 1:
            level = [digest((level[i] + level[i + 1]).encode("ascii")) for i in range(0, len(level), 2)]
        self.declared = self.repo / f"GX_MERKLE_ROOT_{PROOF_ID}.txt"
        self.declared.write_text(f"gx-merkle-root-v2 id={PROOF_ID} algo=sha256 root={level[0]}\n")
        self.args = argparse.Namespace(
            proof_pack_dir=self.pack, repo_merkle_root=self.declared, output_dir=self.output,
            repo_index=None, proof_pack_builder=None, merkle_v2_builder=None,
        )

    def build(self):
        self.quiet(closure.build_package, self.args)

    def verify(self):
        self.quiet(closure.verify_package, self.output, self.pack, self.declared)

    def test_build_and_verify_preserve_sources_and_external_gates(self):
        before = snapshot(self.pack), snapshot(self.repo)
        self.build()
        self.verify()
        self.assertEqual(before, (snapshot(self.pack), snapshot(self.repo)))
        preflight = json.loads((self.output / f"GX_TRANSPARENCY_CLOSURE_PREFLIGHT_{PROOF_ID}.json").read_text())
        self.assertEqual(preflight["overall"], "LOCAL_REPRODUCIBILITY_PASS_EXTERNAL_CLOSURE_REQUIRED")
        self.assertFalse(preflight["signed_or_published"])
        self.assertGreater(preflight["counts"]["not_verified"], 0)

    def test_changed_indexed_bytes_are_rejected(self):
        self.build()
        (self.pack / "one.txt").write_bytes(b"changed source")
        with self.assertRaises(closure.ClosureError):
            self.verify()

    def test_verify_rechecks_index_self_checksum(self):
        self.build()
        self.index.write_text(self.index.read_text() + "\n")
        with self.assertRaises(closure.ClosureError):
            self.verify()

    def test_checksum_manifest_requires_complete_unique_safe_coverage(self):
        self.build()
        sums = self.output / "SHA256SUMS"
        rows = sums.read_text().splitlines()
        for text in ("", "\n".join(rows[1:]), "\n".join(rows + [rows[0]]),
                     "0" * 64 + "  ../outside", "0" * 64 + "  /tmp/outside"):
            with self.subTest(text=text):
                sums.write_text(text + "\n" if text else "")
                with self.assertRaises(closure.ClosureError):
                    self.verify()

    def test_transcript_tamper_fails_even_with_updated_checksums(self):
        self.build()
        name = f"GX_MERKLE_V2_DERIVATION_TRANSCRIPT_{PROOF_ID}.json"
        path = self.output / name
        value = json.loads(path.read_text())
        value["reconstructed_root_sha256"] = "0" * 64
        path.write_text(json.dumps(value))
        sums = self.output / "SHA256SUMS"
        sums.write_text("\n".join(f"{digest((self.output / item).read_bytes())}  {item}"
                                  for item in closure.PACKAGE_FILES) + "\n")
        with self.assertRaises(closure.ClosureError):
            self.verify()

    def test_output_inside_either_source_is_rejected_before_writing(self):
        for source in (self.pack, self.repo):
            with self.subTest(source=source):
                self.args.output_dir = source / "output"
                before = snapshot(source)
                with self.assertRaises(closure.ClosureError):
                    self.build()
                self.assertEqual(before, snapshot(source))
                self.assertFalse(self.args.output_dir.exists())

    def test_index_rejects_traversal_duplicate_and_ambiguous_paths(self):
        for text in ("../outside\n", "/outside\n", "one.txt\none.txt\n", ".\n", "./one.txt\n", "one\tfile\n"):
            with self.subTest(text=text):
                self.index.write_text(text)
                with self.assertRaises(closure.ClosureError):
                    closure.safe_entries(self.index)

    def test_intermediate_symlink_cannot_escape_pack(self):
        external = self.root / "external"
        external.mkdir()
        (external / "payload").write_bytes(b"outside the proof pack")
        (self.pack / "linked").symlink_to(external, target_is_directory=True)
        with self.assertRaises(closure.ClosureError):
            closure.collect_records(self.pack, ["linked/payload"])

    def test_empty_manifest_cannot_pass_maximum_verification(self):
        self.manifest.write_text("path\tbytes\tsha256\n")
        (self.pack / f"GX_LEAVES_{PROOF_ID}.txt").write_text("")
        ledger = maximum.Ledger(self.repo, False)
        self.quiet(maximum.check_proof_pack, ledger, self.maximum_args("--proof-pack-dir", str(self.pack)), [])
        self.assertIn("FAIL", [item["status"] for item in ledger.checks if item["id"] == "proof_pack:manifest_content"])

    def test_unlisted_bundle_member_is_rejected(self):
        self.manifest.write_text("\n".join(self.manifest.read_text().splitlines()[:2]) + "\n")
        ledger = maximum.Ledger(self.repo, False)
        self.quiet(maximum.check_proof_pack, ledger, self.maximum_args("--proof-pack-dir", str(self.pack)), [])
        self.assertIn("FAIL", [item["status"] for item in ledger.checks if item["id"] == "proof_pack:manifest_content"])


class MaximumTests(TemporaryFixture):
    def test_report_cannot_replace_explicit_evidence_input(self):
        output = self.root / "reports"
        output.mkdir()
        evidence = output / "GX_TRANSPARENCY_MAX_VERIFY_RESULT.json"
        evidence.write_text("source evidence")
        args = self.maximum_args("--output-dir", str(output), "--ots-evidence", str(evidence))
        with self.assertRaises(ValueError):
            maximum.report_directory(args, self.repo)
        self.assertEqual(evidence.read_text(), "source evidence")

    def test_output_in_checkout_is_rejected_before_any_check(self):
        with mock.patch.object(sys, "argv", ["gx_verify_max.py", "--repo", str(self.repo), "--output-dir", str(self.repo / "reports")]), \
                mock.patch.object(maximum, "check_repository") as check:
            self.assertEqual(self.quiet(maximum.main), 1)
            check.assert_not_called()
        self.assertFalse((self.repo / "reports").exists())

    def test_report_does_not_overwrite_source_through_links(self):
        source = self.repo / "proof.txt"
        source.write_bytes(b"historical evidence")
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                output = self.root / kind
                if kind == "symlink":
                    output.symlink_to(source)
                else:
                    os.link(source, output)
                maximum.write_report(output, "new report")
                self.assertEqual(source.read_bytes(), b"historical evidence")
                self.assertEqual(output.read_text(), "new report")

    def test_main_writes_partial_ledger_outside_sources(self):
        names = ("check_repository", "check_public_tag_publication", "check_index", "check_proof_pack",
                 "check_required_files", "check_snapshot_binding", "check_anchor_semantics", "check_gpg", "check_ots", "check_rfc3161")
        def unavailable(ledger, *args):
            ledger.add("fixture:external_gate", "NOT_VERIFIED", "unavailable")
            return []
        with contextlib.ExitStack() as stack:
            for name in names:
                stack.enter_context(mock.patch.object(maximum, name, side_effect=unavailable))
            stack.enter_context(mock.patch.object(sys, "argv", ["gx_verify_max.py", "--repo", str(self.repo), "--output-dir", str(self.root / "reports")]))
            self.assertEqual(self.quiet(maximum.main), 2)
        report = json.loads((self.root / "reports/GX_TRANSPARENCY_MAX_VERIFY_RESULT.json").read_text())
        self.assertEqual(report["overall"], "PARTIAL_NOT_VERIFIED")
        self.assertFalse(report["network_fetch_allowed"])

    def test_non_object_evidence_is_a_reported_failure(self):
        evidence = self.root / "evidence.json"
        for value in ([], None, "text", 1):
            with self.subTest(value=value):
                evidence.write_text(json.dumps(value))
                ledger = maximum.Ledger(self.repo, False)
                self.quiet(maximum.check_ots_evidence, ledger, evidence, self.root / "target", self.root / "proof")
                self.assertEqual(ledger.overall(), "FAIL")

    def test_local_rpc_requires_explicit_opt_in(self):
        ledger = maximum.Ledger(self.repo, False)
        with mock.patch.object(maximum, "executable_candidates") as candidates, mock.patch.object(maximum, "run_bounded") as run:
            self.quiet(maximum.check_local_full_node, ledger, self.maximum_args())
            candidates.assert_not_called()
            run.assert_not_called()
        self.assertEqual(ledger.overall(), "PARTIAL_NOT_VERIFIED")

    def test_opted_in_rpc_rechecks_mainchain_block_identity(self):
        evidence = self.root / "evidence.json"
        evidence.write_text(json.dumps({"bitcoin_attestations": [{"expected_block_hash": GENESIS_HASH, "height": 0}]}))
        args = self.maximum_args("--allow-local-rpc", "--ots-evidence", str(evidence))
        synced = {"chain": "main", "initialblockdownload": False, "blocks": 100, "headers": 100, "verificationprogress": 1}
        header = {"hash": GENESIS_HASH, "height": 0, "confirmations": 100}
        with mock.patch.object(maximum, "executable_candidates", return_value=["bitcoin-cli"]), \
                mock.patch.object(maximum, "run_bounded", side_effect=[(0, json.dumps(synced)), (0, json.dumps(header))]) as run:
            ledger = maximum.Ledger(self.repo, False)
            self.quiet(maximum.check_local_full_node, ledger, args)
            self.assertEqual(ledger.overall(), "PASS")
            self.assertEqual(run.call_count, 2)

    def test_rfc3161_negative_control_uses_same_intermediate_certificates(self):
        source = self.root / "source"
        source.write_bytes(b"timestamped source")
        imprint = digest(source.read_bytes())
        ca, intermediate = self.root / "ca.pem", self.root / "intermediate.pem"
        ca.write_text("fixture")
        intermediate.write_text("fixture")
        for label in ("digicert", "globalsign"):
            (self.repo / f"GX_MERKLE_SUPER_COMBINED_{PROOF_ID}.txt.{label}.tsr").write_bytes(b"fixture")
        def openssl(command, **kwargs):
            if "-reply" in command:
                return 0, "fixture reply"
            if "-untrusted" not in command:
                return 1, "unable to get issuer certificate"
            if command[command.index("-digest") + 1] == imprint:
                return 0, "Verification: OK"
            return 1, "message imprint mismatch"
        args = self.maximum_args("--rfc3161-source", str(source), "--ca-file", str(ca), "--untrusted-certificates", str(intermediate))
        with mock.patch.object(maximum, "preferred_openssl", return_value=("openssl", "OpenSSL fixture")), \
                mock.patch.object(maximum, "tsr_details", return_value={"message_imprint": imprint, "nonce": "0x01"}), \
                mock.patch.object(maximum, "run_bounded", side_effect=openssl):
            ledger = maximum.Ledger(self.repo, False)
            self.quiet(maximum.check_rfc3161, ledger, args)
        controls = [item for item in ledger.checks if item["id"].endswith(":negative_control")]
        self.assertEqual([item["status"] for item in controls], ["PASS", "PASS"])

    def test_gpg_executable_path_is_shell_quoted(self):
        gpg = self.root / "gpg $(touch GX_SHOULD_NOT_EXIST)"
        fingerprint = "A" * 40
        status = f"[GNUPG:] VALIDSIG {fingerprint} 0 0 0 0 0 0 0\n"
        gpg.write_text("#!/bin/sh\nprintf '%s\\n' '[GNUPG:] VALIDSIG " + fingerprint + " 0 0 0 0 0 0 0'\n")
        gpg.chmod(0o700)
        key = self.root / "public-key"
        key.write_text("fixture")
        for relative in (f"GX_MERKLE_ROOT_{PROOF_ID}.txt", f"GX_DNS_TXT_ANCHOR_{PROOF_ID}.txt", f"snapshots/{PROOF_ID}.json"):
            material = self.repo / relative
            material.parent.mkdir(exist_ok=True)
            material.write_text("fixture")
            material.with_name(material.name + ".asc").write_text("fixture")
        def run(command, **kwargs):
            if "--fingerprint" in command:
                return 0, "fpr:::::::::" + fingerprint + ":\n"
            if "verify-tag" in command or "verify-commit" in command:
                wrapper = next(part.split("=", 1)[1] for part in command if part.startswith("gpg.program="))
                result = subprocess.run([wrapper], capture_output=True, text=True, cwd=self.root, env=kwargs["env"], timeout=5)
                return result.returncode, result.stdout + result.stderr
            if any("^{commit}" in part for part in command):
                return 0, "b" * 40
            return 0, status
        with mock.patch.object(maximum, "executable_candidates", return_value=[str(gpg)]), \
                mock.patch.object(maximum, "run_bounded", side_effect=run):
            ledger = maximum.Ledger(self.repo, False)
            self.quiet(maximum.check_gpg, ledger, self.maximum_args("--gpg-public-key", str(key)))
        tag = next(item for item in ledger.checks if item["id"].startswith("gpg:git_tag"))
        self.assertEqual(tag["status"], "PASS")
        self.assertFalse((self.root / "GX_SHOULD_NOT_EXIST").exists())


class OpenTimestampsTests(TemporaryFixture):
    def run_audit(self, target_bytes, proof_bytes, *, same_name=False):
        target_dir, proof_dir = self.root / "target-dir", self.root / "proof-dir"
        target_dir.mkdir(exist_ok=True)
        proof_dir.mkdir(exist_ok=True)
        target = target_dir / "artifact"
        proof = proof_dir / ("artifact" if same_name else "artifact.ots")
        target.write_bytes(target_bytes)
        proof.write_bytes(proof_bytes)
        evidence = self.root / "evidence.json"
        code = self.quiet(ots.run, ["--target", str(target), "--proof", str(proof), "--evidence", str(evidence)])
        self.assertEqual(target.read_bytes(), target_bytes)
        self.assertEqual(proof.read_bytes(), proof_bytes)
        return code, json.loads(evidence.read_text())

    def test_parser_reads_exact_proof_and_rejects_malformed_inputs(self):
        proof = pending_proof(b"target")
        parsed = ots.parse_detached_proof(proof)
        self.assertEqual(parsed["file_digest"], digest(b"target"))
        self.assertEqual(parsed["attestations"][0]["type"], "pending")
        for invalid in (proof[:-1], proof + b"\x00", bytes(ots.MAX_PROOF_BYTES + 1), b"invalid"):
            with self.subTest(length=len(invalid)), self.assertRaises(ots.ParseError):
                ots.parse_detached_proof(invalid)

    def test_calendar_allowlist_rejects_malformed_ports_and_credentials(self):
        self.assertTrue(ots.calendar_host_allowed("https://a.calendar.opentimestamps.org"))
        for uri in ("https://a.calendar.opentimestamps.org:invalid", "https://[invalid", "http://a.calendar.opentimestamps.org",
                    "https://user@a.calendar.opentimestamps.org", "https://a.calendar.opentimestamps.org.attacker.invalid",
                    "https://a.calendar.opentimestamps.org/?redirect=1"):
            with self.subTest(uri=uri):
                self.assertFalse(ots.calendar_host_allowed(uri))

    def test_target_mismatch_fails_before_network_reads(self):
        with mock.patch.object(ots, "http_get_bytes") as calendars, mock.patch.object(ots, "http_get_text") as providers:
            code, evidence = self.run_audit(b"changed target", pending_proof(b"original target"))
            calendars.assert_not_called()
            providers.assert_not_called()
        self.assertEqual(code, 1)
        self.assertEqual(evidence["checks"]["target_binding"]["status"], "FAIL")
        self.assertEqual(evidence["checks"]["source_unchanged"]["status"], "PASS")

    def test_same_basename_inputs_remain_distinct_when_network_unavailable(self):
        with mock.patch.object(ots, "http_get_bytes", side_effect=ots.NetworkUnavailable("offline")):
            code, evidence = self.run_audit(b"target", pending_proof(b"target"), same_name=True)
        self.assertEqual(code, 2)
        self.assertEqual(evidence["checks"]["target_binding"]["status"], "PASS")
        self.assertEqual(evidence["checks"]["calendar_upgrades"]["status"], "NOT_VERIFIED")

    def test_capability_probe_is_opt_in(self):
        with mock.patch.object(ots.shutil, "which", return_value="bitcoin-cli"), \
                mock.patch.object(ots.subprocess, "run", return_value=argparse.Namespace(returncode=0, stdout='{"chain":"main"}')) as run:
            capabilities = ots.probe_capabilities()
            run.assert_not_called()
            self.assertFalse(capabilities["local_full_node"]["rpc_probe_performed"])
            opted_in = ots.probe_capabilities(allow_local_rpc=True)
            run.assert_called_once()
            self.assertTrue(opted_in["local_full_node"]["rpc_probe_performed"])

    def test_opted_in_probe_reports_non_object_json_without_crashing(self):
        with mock.patch.object(ots.shutil, "which", return_value="bitcoin-cli"), \
                mock.patch.object(ots.subprocess, "run", return_value=argparse.Namespace(returncode=0, stdout="[]")):
            result = ots.probe_capabilities(allow_local_rpc=True)
        self.assertEqual(result["local_full_node"]["rpc_probe_result"], "reachable_but_invalid_json_object")

    def test_genesis_header_and_pow_match_independent_vector(self):
        with mock.patch.object(ots, "http_get_text", side_effect=provider_response):
            result = ots.corroborate_bitcoin_attestation(0, bytes.fromhex(GENESIS_MERKLE)[::-1].hex())
        self.assertEqual(result["calculated_block_hash"], GENESIS_HASH)
        for field in ("header_hash_match", "ots_merkle_binding", "json_merkle_binding", "compact_bits_valid_mainnet", "pow_target_pass"):
            self.assertTrue(result[field], field)

    def test_complete_corroboration_still_requires_official_client_and_node(self):
        self.assertEqual(hashlib.sha256(hashlib.sha256(GENESIS_TX).digest()).digest()[::-1].hex(), GENESIS_MERKLE)
        with mock.patch.object(ots, "http_get_text", side_effect=provider_response):
            code, evidence = self.run_audit(GENESIS_TX, GENESIS_PROOF)
        self.assertEqual(code, 2)
        self.assertEqual(evidence["overall"]["status"], "CORROBORATED_PARTIAL_NOT_VERIFIED")
        self.assertEqual(evidence["checks"]["compact_bits_pow"]["status"], "PASS")
        self.assertEqual(evidence["checks"]["official_client"]["status"], "NOT_VERIFIED")
        self.assertEqual(evidence["checks"]["local_full_node"]["status"], "NOT_VERIFIED")

    def test_provider_disagreement_is_failure(self):
        def disagree(url, limit=ots.MAX_PROVIDER_BYTES):
            if "mempool.space" in url and "/block-height/" in url:
                return "f" * 64, {"mocked": True}
            return provider_response(url, limit)
        with mock.patch.object(ots, "http_get_text", side_effect=disagree):
            code, evidence = self.run_audit(GENESIS_TX, GENESIS_PROOF)
        self.assertEqual(code, 1)
        self.assertEqual(evidence["checks"]["dual_provider_block_headers"]["status"], "FAIL")

    def test_changed_raw_header_is_failure(self):
        def corrupt(url, limit=ots.MAX_PROVIDER_BYTES):
            if url.endswith("/header"):
                return (GENESIS_HEADER[:-1] + b"\x00").hex(), {"mocked": True}
            return provider_response(url, limit)
        with mock.patch.object(ots, "http_get_text", side_effect=corrupt):
            code, evidence = self.run_audit(GENESIS_TX, GENESIS_PROOF)
        self.assertEqual(code, 1)
        self.assertEqual(evidence["checks"]["header_hash"]["status"], "FAIL")

    def test_compact_target_rejects_negative_and_overflow_encodings(self):
        for bits in (0x1D80FFFF, 0x23000001):
            target, metadata = ots.compact_to_target(bits)
            self.assertTrue(metadata["negative"] or metadata["overflow"])


if __name__ == "__main__":
    unittest.main()
