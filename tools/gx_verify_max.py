#!/usr/bin/env python3
"""Maximum, fail-closed verifier for the GX transparency evidence checkout.

The repository is never modified. Optional network verification is performed on
temporary copies, and GPG always uses an isolated temporary keyring.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any


PROOF_ID = "20260211T192351Z"
TAG = f"gx-proof-{PROOF_ID}-r2"
REQUIRED_FILES = (
    f"GX_MERKLE_ROOT_{PROOF_ID}.txt",
    f"GX_MERKLE_ROOT_{PROOF_ID}.txt.asc",
    f"GX_MERKLE_ROOT_{PROOF_ID}.txt.ots",
    f"GX_DNS_TXT_ANCHOR_{PROOF_ID}.txt",
    f"GX_DNS_TXT_ANCHOR_{PROOF_ID}.txt.asc",
    f"snapshots/{PROOF_ID}.json",
    f"snapshots/{PROOF_ID}.json.asc",
    f"GX_MERKLE_SUPER_COMBINED_{PROOF_ID}.txt.digicert.tsr",
    f"GX_MERKLE_SUPER_COMBINED_{PROOF_ID}.txt.globalsign.tsr",
)
RFC3161_SOURCE_NAME = f"GX_MERKLE_SUPER_COMBINED_{PROOF_ID}.txt"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_fingerprint(value: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", value).upper()


def run_bounded(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 20,
) -> tuple[int, str]:
    proc = subprocess.Popen(
        argv,
        cwd=str(cwd) if cwd else None,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    try:
        output, _ = proc.communicate(timeout=timeout)
        return proc.returncode, output
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            output, _ = proc.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            output, _ = proc.communicate()
        return 124, output + f"\nTIMEOUT_SECONDS={timeout}\n"


def tail_text(value: str, limit: int = 4000) -> str:
    value = value.strip()
    return value if len(value) <= limit else value[-limit:]


def executable_candidates(name: str, extra: tuple[str, ...] = ()) -> list[str]:
    values = [*extra]
    discovered = shutil.which(name)
    if discovered:
        values.append(discovered)
    values.extend((f"/opt/homebrew/bin/{name}", f"/usr/local/bin/{name}", f"/usr/bin/{name}"))
    found: list[str] = []
    for value in values:
        candidate = str(Path(value))
        if candidate not in found and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            found.append(candidate)
    return found


def preferred_openssl() -> tuple[str | None, str | None]:
    candidates = executable_candidates(
        "openssl", ("/opt/homebrew/opt/openssl@3/bin/openssl",)
    )
    fallback: tuple[str | None, str | None] = (None, None)
    for candidate in candidates:
        rc, version = run_bounded([candidate, "version"], timeout=5)
        if rc != 0:
            continue
        version = version.strip()
        if fallback == (None, None):
            fallback = (candidate, version)
        if version.startswith("OpenSSL ") and "LibreSSL" not in version:
            return candidate, version
    return fallback


class Ledger:
    def __init__(self, repo: Path, network_allowed: bool) -> None:
        self.repo = repo
        self.network_allowed = network_allowed
        self.checks: list[dict[str, Any]] = []
        self.observed_files: list[dict[str, Any]] = []
        self.context: dict[str, Any] = {}

    def add(
        self,
        check_id: str,
        status: str,
        evidence: str,
        *,
        severity: str = "info",
        details: Any | None = None,
    ) -> None:
        item: dict[str, Any] = {
            "id": check_id,
            "status": status,
            "severity": severity,
            "evidence": evidence,
        }
        if details is not None:
            item["details"] = details
        self.checks.append(item)
        print(f"{status}={check_id}:{evidence}")

    def observe(self, relative_path: str, path: Path) -> None:
        if path.is_file():
            self.observed_files.append(
                {"path": relative_path, "size_bytes": path.stat().st_size, "sha256": sha256(path)}
            )

    def overall(self) -> str:
        statuses = {item["status"] for item in self.checks}
        if "FAIL" in statuses:
            return "FAIL"
        if "NOT_VERIFIED" in statuses:
            return "PARTIAL_NOT_VERIFIED"
        return "PASS"

    def payload(self) -> dict[str, Any]:
        counts = {
            status.lower(): sum(1 for item in self.checks if item["status"] == status)
            for status in ("PASS", "FAIL", "NOT_VERIFIED", "INFO")
        }
        return {
            "schema": "gx_transparency_max_verify_v2",
            "generated_at_utc": utc_now(),
            "proof_id": PROOF_ID,
            "repository": str(self.repo),
            "read_only": True,
            "network_fetch_allowed": self.network_allowed,
            "overall": self.overall(),
            "counts": counts,
            "context": self.context,
            "checks": self.checks,
            "observed_files": sorted(self.observed_files, key=lambda item: item["path"]),
            "truth_boundary": {
                "proves": [
                    "current local checkout structure and selected local artifact bytes",
                    "only the cryptographic checks explicitly marked PASS",
                ],
                "does_not_prove": [
                    "current GX runtime health",
                    "release or deployment readiness",
                    "public distribution safety",
                    "global or production status",
                ],
            },
        }


def parse_args() -> argparse.Namespace:
    script_repo = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=script_repo)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--proof-pack-dir", type=Path)
    parser.add_argument("--proof-pack-peer", type=Path, action="append", default=[])
    parser.add_argument("--proof-pack-builder", type=Path)
    parser.add_argument("--merkle-v2-builder", type=Path)
    parser.add_argument("--gpg-public-key", type=Path)
    parser.add_argument("--trusted-fingerprint", default="")
    parser.add_argument(
        "--ots-evidence",
        type=Path,
        help=(
            "JSON emitted by gx_ots_max.py. The verifier rebinds it to the "
            "current target/proof hashes before accepting its corroborated checks."
        ),
    )
    parser.add_argument("--rfc3161-source", type=Path)
    parser.add_argument(
        "--rfc3161-request",
        action="append",
        default=[],
        metavar="LABEL=PATH",
        help="Explicit DigiCert/GlobalSign timestamp request; repeat once per authority.",
    )
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--untrusted-certificates", type=Path)
    return parser.parse_args()


def check_repository(ledger: Ledger) -> None:
    git = shutil.which("git")
    if not git:
        ledger.add("repository:git", "FAIL", "git_unavailable", severity="critical")
        return
    rc, output = run_bounded([git, "-C", str(ledger.repo), "rev-parse", "--show-toplevel"])
    if rc != 0:
        ledger.add("repository:checkout", "FAIL", "not_a_git_checkout", severity="critical", details=tail_text(output))
        return
    root = Path(output.strip()).resolve()
    if root != ledger.repo:
        ledger.add("repository:root", "FAIL", "resolved_root_mismatch", severity="critical", details=str(root))
        return
    ledger.add("repository:checkout", "PASS", "git_checkout")
    rc, head = run_bounded([git, "-C", str(ledger.repo), "rev-parse", "HEAD"])
    rc2, branch = run_bounded([git, "-C", str(ledger.repo), "branch", "--show-current"])
    rc3, status = run_bounded([git, "-C", str(ledger.repo), "status", "--porcelain=v1"])
    ledger.context["git"] = {
        "head": head.strip() if rc == 0 else None,
        "branch": branch.strip() if rc2 == 0 else None,
        "worktree_entries": [line for line in status.splitlines() if line] if rc3 == 0 else None,
    }
    if rc3 == 0 and not status.strip():
        ledger.add("repository:worktree", "PASS", "clean")
    elif rc3 == 0:
        ledger.add("repository:worktree", "INFO", f"dirty_entries={len(status.splitlines())}", details=status.splitlines())
    else:
        ledger.add("repository:worktree", "NOT_VERIFIED", "status_unavailable", severity="medium", details=tail_text(status))


def check_public_tag_publication(ledger: Ledger) -> None:
    git = shutil.which("git")
    if git is None:
        ledger.add("publication:remote_tag_identity", "NOT_VERIFIED", "git_unavailable", severity="medium")
        return
    rc, remote = run_bounded([git, "-C", str(ledger.repo), "remote", "get-url", "origin"], timeout=10)
    if rc != 0 or not remote.strip():
        ledger.add("publication:remote_tag_identity", "NOT_VERIFIED", "origin_remote_unavailable", severity="medium")
        return
    if not ledger.network_allowed:
        ledger.add("publication:remote_tag_identity", "NOT_VERIFIED", "network_verification_not_authorized", severity="medium")
        return
    ref = f"refs/tags/{TAG}"
    rc, output = run_bounded([git, "ls-remote", "--refs", remote.strip(), ref], timeout=30)
    if rc != 0:
        ledger.add(
            "publication:remote_tag_identity",
            "NOT_VERIFIED",
            "remote_tag_lookup_failed",
            severity="medium",
            details=tail_text(output),
        )
        return
    rows = [line.split() for line in output.splitlines() if line.strip()]
    matches = [row[0] for row in rows if len(row) == 2 and row[1] == ref and re.fullmatch(r"[0-9a-f]{40,64}", row[0])]
    if len(matches) != 1:
        ledger.add("publication:remote_tag_identity", "NOT_VERIFIED", "expected_public_tag_not_found", severity="medium")
        return
    local_rc, local_object = run_bounded([git, "-C", str(ledger.repo), "rev-parse", TAG], timeout=10)
    if local_rc != 0:
        ledger.add("publication:remote_tag_identity", "FAIL", "local_tag_missing_for_remote_comparison", severity="high")
        return
    local_object = local_object.strip()
    if matches[0] != local_object:
        ledger.add(
            "publication:remote_tag_identity",
            "FAIL",
            "public_and_local_tag_objects_differ",
            severity="critical",
            details={"local": local_object, "remote": matches[0]},
        )
        return
    ledger.add(
        "publication:remote_tag_identity",
        "PASS",
        f"public_origin_tag_object_matches_local={local_object}",
        details={"tag": TAG, "remote": remote.strip()},
    )


def check_index(ledger: Ledger, args: argparse.Namespace) -> list[str]:
    index_path = ledger.repo / "GX_PROOF_INDEX.txt"
    checksum_path = ledger.repo / "GX_PROOF_INDEX.txt.sha256"
    if not index_path.is_file() or not checksum_path.is_file():
        ledger.add("index:self_checksum", "FAIL", "index_or_checksum_missing", severity="critical")
        return []
    checksum_line = checksum_path.read_text(encoding="utf-8", errors="replace").strip()
    match = re.fullmatch(r"([0-9A-Fa-f]{64})\s+[* ]?(.+)", checksum_line)
    if not match:
        ledger.add("index:self_checksum", "FAIL", "checksum_file_malformed", severity="critical")
    else:
        expected, filename = match.groups()
        actual = sha256(index_path)
        if filename != "GX_PROOF_INDEX.txt":
            ledger.add("index:self_checksum", "FAIL", "checksum_targets_unexpected_file", severity="critical", details=filename)
        elif actual.lower() != expected.lower():
            ledger.add("index:self_checksum", "FAIL", "digest_mismatch", severity="critical", details={"expected": expected.lower(), "actual": actual.lower()})
        else:
            ledger.add("index:self_checksum", "PASS", "GX_PROOF_INDEX.txt_matches_stored_digest")
    entries = [line.strip() for line in index_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    safe_entries: list[str] = []
    unsafe_entries: list[str] = []
    for entry in entries:
        candidate = Path(entry)
        if candidate.is_absolute() or ".." in candidate.parts:
            unsafe_entries.append(entry)
        else:
            safe_entries.append(entry)
    if unsafe_entries:
        ledger.add("index:path_safety", "FAIL", f"unsafe_entries={len(unsafe_entries)}", severity="critical", details=unsafe_entries)
    else:
        ledger.add("index:path_safety", "PASS", f"safe_entries={len(safe_entries)}")
    checkout_present = [entry for entry in safe_entries if (ledger.repo / entry).exists()]
    checkout_absent = [entry for entry in safe_entries if not (ledger.repo / entry).exists()]
    checkout_coverage = (len(checkout_present) / len(safe_entries)) if safe_entries else 0.0
    ledger.context["index"] = {
        "entry_count": len(safe_entries),
        "checkout_present_count": len(checkout_present),
        "checkout_absent_count": len(checkout_absent),
        "checkout_coverage_rate": checkout_coverage,
        "checkout_absent_paths": checkout_absent,
        "semantic_note": "GX_PROOF_INDEX.txt is self-hashed; it is not a per-artifact checksum manifest.",
    }
    ledger.add(
        "index:checkout_coverage",
        "INFO",
        f"present={len(checkout_present)} total={len(safe_entries)} absent={len(checkout_absent)}",
        details=checkout_absent,
    )
    proof_pack = args.proof_pack_dir.expanduser().resolve() if args.proof_pack_dir else None
    if proof_pack is None:
        ledger.add("index:proof_pack_coverage", "NOT_VERIFIED", "proof_pack_directory_not_supplied", severity="high")
    elif not proof_pack.is_dir():
        ledger.add("index:proof_pack_coverage", "FAIL", "proof_pack_directory_missing", severity="critical", details=str(proof_pack))
    else:
        pack_index = proof_pack / "GX_PROOF_INDEX.txt"
        if not pack_index.is_file() or sha256(pack_index) != sha256(index_path):
            ledger.add("index:proof_pack_index_identity", "FAIL", "pack_index_does_not_match_checkout_index", severity="critical")
        else:
            ledger.add("index:proof_pack_index_identity", "PASS", "pack_and_checkout_index_bytes_match")
        pack_present = [entry for entry in safe_entries if (proof_pack / entry).exists()]
        pack_absent = [entry for entry in safe_entries if not (proof_pack / entry).exists()]
        pack_coverage = (len(pack_present) / len(safe_entries)) if safe_entries else 0.0
        ledger.context["index"].update(
            {
                "proof_pack_directory": str(proof_pack),
                "proof_pack_present_count": len(pack_present),
                "proof_pack_absent_count": len(pack_absent),
                "proof_pack_coverage_rate": pack_coverage,
                "proof_pack_absent_paths": pack_absent,
            }
        )
        if pack_absent:
            ledger.add("index:proof_pack_coverage", "FAIL", f"present={len(pack_present)} total={len(safe_entries)} absent={len(pack_absent)}", severity="critical", details=pack_absent)
        elif safe_entries:
            ledger.add("index:proof_pack_coverage", "PASS", f"present={len(pack_present)} total={len(safe_entries)}")
        else:
            ledger.add("index:proof_pack_coverage", "FAIL", "index_empty", severity="critical")
        for entry in pack_present:
            ledger.observe(f"proof_pack/{entry}", proof_pack / entry)
    ledger.add("index:artifact_digests", "NOT_VERIFIED", "index_contains_names_not_per_artifact_sha256_values", severity="high")
    ledger.observe("GX_PROOF_INDEX.txt", index_path)
    ledger.observe("GX_PROOF_INDEX.txt.sha256", checksum_path)
    return safe_entries


def parse_root_fields(path: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields[key.strip()] = value.strip()
    return fields


def raw_pairwise_merkle(leaves: list[str]) -> tuple[str, list[list[str]]]:
    levels = [list(leaves)]
    level = [bytes.fromhex(value) for value in leaves]
    while len(level) > 1:
        next_level = []
        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            next_level.append(hashlib.sha256(left + right).digest())
        level = next_level
        levels.append([value.hex() for value in level])
    return (level[0].hex() if level else ""), levels


def ascii_pairwise_merkle(leaves: list[str]) -> tuple[str, list[list[str]]]:
    levels = [list(leaves)]
    level = list(leaves)
    while len(level) > 1:
        next_level = []
        for index in range(0, len(level), 2):
            if index + 1 >= len(level):
                raise ValueError("historical ASCII-pair algorithm has an unmatched odd leaf")
            next_level.append(
                hashlib.sha256((level[index] + level[index + 1]).encode("ascii")).hexdigest()
            )
        level = next_level
        levels.append(list(level))
    return (level[0] if level else ""), levels


def check_proof_pack(ledger: Ledger, args: argparse.Namespace, index_entries: list[str]) -> None:
    if args.proof_pack_dir is None:
        ledger.add("proof_pack:validation", "NOT_VERIFIED", "proof_pack_directory_not_supplied", severity="high")
        return
    pack = args.proof_pack_dir.expanduser().resolve()
    if not pack.is_dir():
        ledger.add("proof_pack:validation", "FAIL", "proof_pack_directory_missing", severity="critical")
        return
    root = pack / f"GX_PROOF_ROOT_{PROOF_ID}.txt"
    manifest = pack / f"GX_PROOF_MANIFEST_{PROOF_ID}.tsv"
    bundle = pack / f"GX_PROOF_PACK_{PROOF_ID}.tar.gz"
    if not all(path.is_file() for path in (root, manifest, bundle)):
        ledger.add("proof_pack:core_files", "FAIL", "root_manifest_or_bundle_missing", severity="critical")
        return
    fields = parse_root_fields(root)
    expected_manifest = fields.get("manifest_sha256", "").lower()
    expected_bundle = fields.get("bundle_sha256", "").lower()
    actual_manifest = sha256(manifest)
    actual_bundle = sha256(bundle)
    if expected_manifest and expected_manifest == actual_manifest:
        ledger.add("proof_pack:root_manifest_binding", "PASS", f"sha256={actual_manifest}")
    else:
        ledger.add("proof_pack:root_manifest_binding", "FAIL", "manifest_digest_mismatch_or_missing", severity="critical", details={"expected": expected_manifest, "actual": actual_manifest})
    if expected_bundle and expected_bundle == actual_bundle:
        ledger.add("proof_pack:root_bundle_binding", "PASS", f"sha256={actual_bundle}")
    else:
        ledger.add("proof_pack:root_bundle_binding", "FAIL", "bundle_digest_mismatch_or_missing", severity="critical", details={"expected": expected_bundle, "actual": actual_bundle})
    if fields.get("merkle_root_sha256"):
        ledger.add("proof_pack:root_merkle_field", "PASS", "populated")
    else:
        ledger.add("proof_pack:root_merkle_field", "NOT_VERIFIED", "merkle_root_sha256_empty", severity="high")

    try:
        with tarfile.open(bundle, mode="r:gz") as archive:
            members = archive.getmembers()
            unsafe = []
            member_map: dict[str, tarfile.TarInfo] = {}
            for member in members:
                candidate = Path(member.name)
                if candidate.is_absolute() or ".." in candidate.parts or member.issym() or member.islnk() or not member.isfile():
                    unsafe.append(member.name)
                else:
                    member_map[member.name] = member
            if unsafe:
                ledger.add("proof_pack:tar_safety", "FAIL", f"unsafe_or_nonregular_members={len(unsafe)}", severity="critical", details=unsafe)
                return
            ledger.add("proof_pack:tar_safety", "PASS", f"regular_safe_members={len(members)}")
            rows = list(csv.DictReader(manifest.read_text(encoding="utf-8", errors="replace").splitlines(), delimiter="\t"))
            bad_rows = []
            for row in rows:
                source_path = row.get("path", "")
                if "/_reports/" in source_path:
                    relative = "_reports/" + source_path.split("/_reports/", 1)[1]
                else:
                    relative = source_path.lstrip("/")
                member = member_map.get(relative)
                if member is None:
                    bad_rows.append({"path": source_path, "error": "missing_from_bundle"})
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    bad_rows.append({"path": source_path, "error": "not_readable"})
                    continue
                data = extracted.read()
                expected_bytes = row.get("bytes", "")
                expected_sha = row.get("sha256", "").lower()
                actual_sha = hashlib.sha256(data).hexdigest()
                if str(len(data)) != expected_bytes or actual_sha != expected_sha:
                    bad_rows.append(
                        {
                            "path": source_path,
                            "expected_bytes": expected_bytes,
                            "actual_bytes": len(data),
                            "expected_sha256": expected_sha,
                            "actual_sha256": actual_sha,
                        }
                    )
            if bad_rows:
                ledger.add("proof_pack:manifest_content", "FAIL", f"bad_rows={len(bad_rows)} total={len(rows)}", severity="critical", details=bad_rows)
            else:
                ledger.add("proof_pack:manifest_content", "PASS", f"verified_rows={len(rows)}")
                leaves_file = pack / f"GX_LEAVES_{PROOF_ID}.txt"
                if leaves_file.is_file():
                    leaves = [
                        line.strip().lower()
                        for line in leaves_file.read_text(encoding="utf-8", errors="replace").splitlines()
                        if line.strip()
                    ]
                    manifest_leaves = sorted(
                        str(row.get("sha256", "")).lower() for row in rows
                    )
                    valid_leaves = all(re.fullmatch(r"[0-9a-f]{64}", value) for value in leaves)
                    if valid_leaves and leaves == manifest_leaves:
                        reconstructed_root, levels = raw_pairwise_merkle(leaves)
                        details: dict[str, Any] = {
                            "leaf_count": len(leaves),
                            "reconstructed_root": reconstructed_root,
                            "level_sizes": [len(level) for level in levels],
                            "algorithm": "sorted SHA-256 file digests; parent=SHA256(raw_left||raw_right); duplicate odd leaf",
                        }
                        if args.proof_pack_builder and args.proof_pack_builder.is_file():
                            details["builder_source_sha256"] = sha256(args.proof_pack_builder)
                        ledger.context["proof_pack_merkle_reconstruction"] = details
                        ledger.add(
                            "proof_pack:merkle_reconstruction",
                            "PASS",
                            f"manifest_bound_root={reconstructed_root}",
                            details=details,
                        )
                    else:
                        ledger.add(
                            "proof_pack:merkle_reconstruction",
                            "FAIL",
                            "historical_leaves_do_not_match_sorted_manifest_sha256_values",
                            severity="critical",
                            details={"leaf_count": len(leaves), "manifest_rows": len(rows)},
                        )
                else:
                    ledger.add(
                        "proof_pack:merkle_reconstruction",
                        "NOT_VERIFIED",
                        "historical_leaves_file_missing",
                        severity="high",
                    )
    except (tarfile.TarError, OSError) as exc:
        ledger.add("proof_pack:tar_parse", "FAIL", "tar_read_failed", severity="critical", details=str(exc))

    for peer_arg in args.proof_pack_peer:
        peer = peer_arg.expanduser().resolve()
        mismatches = []
        for entry in index_entries:
            left = pack / entry
            right = peer / entry
            if left.is_file() and right.is_file():
                if sha256(left) != sha256(right):
                    mismatches.append(entry)
            elif left.is_dir() and right.is_dir():
                left_files = sorted(str(path.relative_to(left)) for path in left.rglob("*") if path.is_file())
                right_files = sorted(str(path.relative_to(right)) for path in right.rglob("*") if path.is_file())
                if left_files != right_files or any(sha256(left / item) != sha256(right / item) for item in left_files):
                    mismatches.append(entry)
            else:
                mismatches.append(entry)
        peer_root = re.sub(r"[^A-Za-z0-9._-]+", "_", peer.parent.parent.name).strip("_") or "peer"
        peer_suffix = hashlib.sha256(str(peer).encode("utf-8")).hexdigest()[:8]
        check_id = f"proof_pack:peer_identity:{peer_root}_{peer_suffix}"
        if mismatches:
            ledger.add(check_id, "FAIL", f"mismatches={len(mismatches)}", severity="critical", details=mismatches)
        else:
            ledger.add(check_id, "PASS", f"identical_indexed_entries={len(index_entries)}")
    if args.proof_pack_peer:
        ledger.add("proof_pack:peer_independence", "NOT_VERIFIED", "byte_identical_copies_do_not_prove_independent_provenance", severity="medium")


def check_required_files(ledger: Ledger, index_entries: list[str]) -> None:
    index_set = set(index_entries)
    required_not_indexed: list[str] = []
    for relative in REQUIRED_FILES:
        path = ledger.repo / relative
        if path.is_file():
            ledger.add(f"artifact:present:{relative}", "PASS", "regular_file")
            ledger.observe(relative, path)
        else:
            ledger.add(f"artifact:present:{relative}", "FAIL", "missing", severity="critical")
        if relative not in index_set:
            required_not_indexed.append(relative)
    if required_not_indexed:
        ledger.add("index:required_subset_alignment", "NOT_VERIFIED", f"required_files_not_named_by_index={len(required_not_indexed)}", severity="high", details=required_not_indexed)
    else:
        ledger.add("index:required_subset_alignment", "PASS", "all_required_files_named_by_index")


def check_snapshot_binding(ledger: Ledger, args: argparse.Namespace) -> None:
    snapshot_path = ledger.repo / f"snapshots/{PROOF_ID}.json"
    entry_path = ledger.repo / f"entries/{PROOF_ID}.json"
    if not snapshot_path.is_file() or not entry_path.is_file():
        ledger.add("snapshot:entry_binding", "FAIL", "snapshot_or_entry_missing", severity="critical")
        return
    try:
        snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
        entry = json.loads(entry_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        ledger.add("snapshot:json", "FAIL", "json_parse_failed", severity="critical", details=str(exc))
        return
    leaves = snapshot.get("leaf_hashes_sha256_sorted")
    entries_count = snapshot.get("entries")
    root = snapshot.get("merkle_root_sha256")
    entry_digest = sha256(entry_path)
    if entries_count == 1 and isinstance(leaves, list) and leaves == [entry_digest] and root == entry_digest:
        ledger.add("snapshot:entry_binding", "PASS", f"single_leaf_sha256={entry_digest}")
    else:
        ledger.add(
            "snapshot:entry_binding",
            "FAIL",
            "entry_digest_leaf_or_root_mismatch",
            severity="critical",
            details={"entries": entries_count, "leaves": leaves, "root": root, "entry_sha256": entry_digest},
        )
    if args.proof_pack_dir is None:
        ledger.add("snapshot:proof_pack_binding", "NOT_VERIFIED", "proof_pack_directory_not_supplied", severity="high")
        return
    pack = args.proof_pack_dir.expanduser().resolve()
    expected_files = {
        "bundle_sha256": pack / str(entry.get("bundle_name", "")),
        "manifest_sha256": pack / f"GX_PROOF_MANIFEST_{PROOF_ID}.tsv",
        "rootfile_sha256": pack / f"GX_PROOF_ROOT_{PROOF_ID}.txt",
    }
    mismatches = []
    verified = {}
    for field, path in expected_files.items():
        expected = entry.get(field)
        if not isinstance(expected, str) or not path.is_file():
            mismatches.append({"field": field, "error": "expected_digest_or_file_missing", "path": str(path)})
            continue
        actual = sha256(path)
        verified[field] = actual
        if actual != expected.lower():
            mismatches.append({"field": field, "expected": expected.lower(), "actual": actual})
    if mismatches:
        ledger.add("snapshot:proof_pack_binding", "FAIL", f"mismatches={len(mismatches)}", severity="critical", details=mismatches)
    else:
        ledger.add("snapshot:proof_pack_binding", "PASS", "entry_digests_match_bundle_manifest_and_root", details=verified)


def check_anchor_semantics(ledger: Ledger, args: argparse.Namespace) -> None:
    anchor_path = ledger.repo / f"GX_DNS_TXT_ANCHOR_{PROOF_ID}.txt"
    merkle_path = ledger.repo / f"GX_MERKLE_ROOT_{PROOF_ID}.txt"
    if anchor_path.is_file() and args.proof_pack_dir:
        tokens = dict(
            token.split("=", 1)
            for token in anchor_path.read_text(encoding="utf-8", errors="replace").split()
            if "=" in token
        )
        pack = args.proof_pack_dir.expanduser().resolve()
        expected = {
            "root_sha256": pack / f"GX_PROOF_ROOT_{PROOF_ID}.txt",
            "pack_sha256": pack / f"GX_PROOF_PACK_{PROOF_ID}.tar.gz",
            "manifest_sha256": pack / f"GX_PROOF_MANIFEST_{PROOF_ID}.tsv",
            "summary_sha256": pack / f"GX_PROOF_SUMMARY_{PROOF_ID}.txt",
        }
        mismatches = []
        for field, path in expected.items():
            actual = sha256(path) if path.is_file() else None
            if actual is None or tokens.get(field, "").lower() != actual:
                mismatches.append({"field": field, "declared": tokens.get(field), "actual": actual})
        if mismatches:
            ledger.add("dns_anchor:proof_pack_binding", "FAIL", f"mismatches={len(mismatches)}", severity="critical", details=mismatches)
        else:
            ledger.add("dns_anchor:proof_pack_binding", "PASS", "four_declared_digests_match_proof_pack")
    elif not anchor_path.is_file():
        ledger.add("dns_anchor:proof_pack_binding", "FAIL", "anchor_file_missing", severity="critical")
    else:
        ledger.add("dns_anchor:proof_pack_binding", "NOT_VERIFIED", "proof_pack_directory_not_supplied", severity="high")
    ledger.add("dns_anchor:publication", "NOT_VERIFIED", "no_domain_record_or_dnssec_lookup_target_declared", severity="high")

    if not merkle_path.is_file():
        ledger.add("merkle_v2:format", "FAIL", "merkle_root_file_missing", severity="critical")
        return
    text = merkle_path.read_text(encoding="utf-8", errors="replace").strip()
    match = re.fullmatch(r"gx-merkle-root-v2 id=(\d{8}T\d{6}Z) algo=sha256 root=([0-9a-f]{64})", text)
    if match and match.group(1) == PROOF_ID:
        ledger.add("merkle_v2:format", "PASS", f"declared_root={match.group(2)}")
    else:
        ledger.add("merkle_v2:format", "FAIL", "unexpected_schema_or_value", severity="critical", details=text)
    declared_root = match.group(2) if match and match.group(1) == PROOF_ID else None
    if args.proof_pack_dir and declared_root:
        pack = args.proof_pack_dir.expanduser().resolve()
        inputs = [
            pack / f"GX_PROOF_ROOT_{PROOF_ID}.txt",
            pack / f"GX_PROOF_PACK_{PROOF_ID}.tar.gz",
            pack / f"GX_PROOF_MANIFEST_{PROOF_ID}.tsv",
            pack / f"GX_PROOF_SUMMARY_{PROOF_ID}.txt",
        ]
        if all(path.is_file() for path in inputs):
            leaves = sorted(sha256(path) for path in inputs)
            try:
                reconstructed_root, levels = ascii_pairwise_merkle(leaves)
            except ValueError as exc:
                ledger.add(
                    "merkle_v2:derivation",
                    "FAIL",
                    "historical_derivation_algorithm_not_applicable",
                    severity="critical",
                    details=str(exc),
                )
            else:
                details = {
                    "input_sha256_sorted": leaves,
                    "levels": levels,
                    "reconstructed_root": reconstructed_root,
                    "declared_root": declared_root,
                    "algorithm": "pairwise SHA256(ASCII_hex_left||ASCII_hex_right)",
                }
                if args.merkle_v2_builder and args.merkle_v2_builder.is_file():
                    details["builder_source_sha256"] = sha256(args.merkle_v2_builder)
                ledger.context["merkle_v2_derivation"] = details
                if reconstructed_root == declared_root:
                    ledger.add(
                        "merkle_v2:derivation",
                        "PASS",
                        "four_core_artifact_hashes_reproduce_declared_root",
                        details=details,
                    )
                else:
                    ledger.add(
                        "merkle_v2:derivation",
                        "FAIL",
                        "reconstructed_root_does_not_match_declared_root",
                        severity="critical",
                        details=details,
                    )
        else:
            ledger.add(
                "merkle_v2:derivation",
                "NOT_VERIFIED",
                "one_or_more_core_derivation_inputs_missing",
                severity="high",
            )
    else:
        ledger.add(
            "merkle_v2:derivation",
            "NOT_VERIFIED",
            "proof_pack_or_declared_root_unavailable_for_reconstruction",
            severity="high",
        )


def gpg_base(gpg: str, home: Path) -> list[str]:
    return [gpg, "--homedir", str(home), "--batch", "--no-tty", "--no-autostart", "--no-auto-key-locate", "--no-auto-key-retrieve", "--lock-never"]


def check_gpg(ledger: Ledger, args: argparse.Namespace) -> None:
    gpg_candidates = executable_candidates("gpg")
    gpg = gpg_candidates[0] if gpg_candidates else None
    if gpg is None:
        for label in ("merkle_root", "dns_anchor", "snapshot", "git_tag"):
            ledger.add(f"gpg:{label}", "NOT_VERIFIED", "gpg_unavailable", severity="high")
        return
    key_file = args.gpg_public_key
    if key_file is None:
        candidate = ledger.repo / "GX_AUDIT_AUTHORITY_PUBLICKEY.asc"
        if candidate.is_file():
            key_file = candidate
    if key_file is None or not key_file.is_file():
        for label in ("merkle_root", "dns_anchor", "snapshot", "git_tag"):
            ledger.add(f"gpg:{label}", "NOT_VERIFIED", "public_key_unavailable", severity="high")
        return
    trusted = normalize_fingerprint(args.trusted_fingerprint)
    with tempfile.TemporaryDirectory(prefix="gx-gpg-") as temp:
        home = Path(temp)
        home.chmod(0o700)
        base = gpg_base(gpg, home)
        rc, output = run_bounded(base + ["--status-fd", "1", "--import", str(key_file)], timeout=15)
        if rc != 0:
            for label in ("merkle_root", "dns_anchor", "snapshot", "git_tag"):
                ledger.add(f"gpg:{label}", "NOT_VERIFIED", "public_key_import_failed", severity="high", details=tail_text(output))
            return
        rc, listing = run_bounded(base + ["--with-colons", "--fingerprint"], timeout=10)
        fingerprints = []
        if rc == 0:
            for line in listing.splitlines():
                fields = line.split(":")
                if fields and fields[0] == "fpr" and len(fields) > 9:
                    fingerprints.append(normalize_fingerprint(fields[9]))
        ledger.context["gpg"] = {
            "public_key_file": str(key_file),
            "public_key_sha256": sha256(key_file),
            "imported_fingerprints": fingerprints,
            "trusted_fingerprint_supplied": bool(trusted),
        }
        if trusted and trusted not in fingerprints:
            ledger.add("gpg:trust_anchor", "FAIL", "trusted_fingerprint_not_in_imported_key", severity="critical")
            return
        if trusted:
            ledger.add("gpg:trust_anchor", "PASS", f"fingerprint={trusted}")
        else:
            ledger.add("gpg:trust_anchor", "NOT_VERIFIED", "signer_identity_not_independently_pinned", severity="high")
        pairs = [
            ("merkle_root", ledger.repo / f"GX_MERKLE_ROOT_{PROOF_ID}.txt.asc", ledger.repo / f"GX_MERKLE_ROOT_{PROOF_ID}.txt"),
            ("dns_anchor", ledger.repo / f"GX_DNS_TXT_ANCHOR_{PROOF_ID}.txt.asc", ledger.repo / f"GX_DNS_TXT_ANCHOR_{PROOF_ID}.txt"),
            ("snapshot", ledger.repo / f"snapshots/{PROOF_ID}.json.asc", ledger.repo / f"snapshots/{PROOF_ID}.json"),
        ]
        key_self_signature = key_file.with_name(key_file.name + ".asc")
        if key_self_signature.is_file():
            pairs.append(("public_key_file_self_signature", key_self_signature, key_file))
        if args.proof_pack_dir:
            pack = args.proof_pack_dir.expanduser().resolve()
            pairs.extend(
                [
                    ("proof_pack_root", pack / f"GX_PROOF_ROOT_{PROOF_ID}.txt.asc", pack / f"GX_PROOF_ROOT_{PROOF_ID}.txt"),
                    ("proof_pack_tarball", pack / f"GX_PROOF_PACK_{PROOF_ID}.tar.gz.asc", pack / f"GX_PROOF_PACK_{PROOF_ID}.tar.gz"),
                    ("proof_pack_manifest", pack / f"GX_PROOF_MANIFEST_{PROOF_ID}.tsv.asc", pack / f"GX_PROOF_MANIFEST_{PROOF_ID}.tsv"),
                    ("proof_pack_summary", pack / f"GX_PROOF_SUMMARY_{PROOF_ID}.txt.asc", pack / f"GX_PROOF_SUMMARY_{PROOF_ID}.txt"),
                    ("proof_pack_key_file", pack / "GX_AUDIT_AUTHORITY_PUBLICKEY.asc.asc", pack / "GX_AUDIT_AUTHORITY_PUBLICKEY.asc"),
                    ("proof_pack_fingerprint", pack / "KEY_FINGERPRINT.txt.asc", pack / "KEY_FINGERPRINT.txt"),
                    ("proof_pack_readme", pack / "README_VERIFY.txt.asc", pack / "README_VERIFY.txt"),
                    ("proof_pack_deliverable_v2", pack / "GX_PROOF_DELIVERABLE_20260211T184337Z_V2.zip.asc", pack / "GX_PROOF_DELIVERABLE_20260211T184337Z_V2.zip"),
                ]
            )
        for label, signature, material in pairs:
            if not signature.is_file() or not material.is_file():
                ledger.add(f"gpg:{label}:cryptographic_validity", "FAIL", "signature_or_material_missing", severity="critical")
                continue
            rc, output = run_bounded(base + ["--status-fd", "1", "--verify", str(signature), str(material)], timeout=15)
            valid = re.search(r"^\[GNUPG:\] VALIDSIG ([0-9A-F]+) ", output, flags=re.MULTILINE)
            if rc == 0 and valid:
                signer = normalize_fingerprint(valid.group(1))
                ledger.add(f"gpg:{label}:cryptographic_validity", "PASS", f"validsig={signer}")
                if trusted and signer == trusted:
                    ledger.add(f"gpg:{label}:signer_identity", "PASS", "matches_trusted_fingerprint")
                else:
                    ledger.add(f"gpg:{label}:signer_identity", "NOT_VERIFIED", "valid_signature_but_signer_unpinned", severity="high")
            else:
                ledger.add(f"gpg:{label}:cryptographic_validity", "FAIL", "signature_verification_failed", severity="critical", details=tail_text(output))
        git = shutil.which("git")
        if not git:
            ledger.add("gpg:git_tag", "NOT_VERIFIED", "git_unavailable", severity="high")
            return
        rc, _ = run_bounded([git, "-C", str(ledger.repo), "rev-parse", "-q", "--verify", f"refs/tags/{TAG}"])
        if rc != 0:
            ledger.add("gpg:git_tag", "NOT_VERIFIED", "tag_absent", severity="high")
            return
        wrapper = home / "gpg-wrapper.sh"
        wrapper.write_text(
            "#!/bin/sh\nexec " + " ".join([json.dumps(gpg), "--batch", "--no-tty", "--no-autostart", "--no-auto-key-locate", "--no-auto-key-retrieve", "--lock-never", '"$@"']) + "\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o700)
        env = os.environ.copy()
        env["GNUPGHOME"] = str(home)
        rc, output = run_bounded([git, "-c", f"gpg.program={wrapper}", "-C", str(ledger.repo), "verify-tag", "--raw", TAG], env=env, timeout=15)
        valid = re.search(r"^\[GNUPG:\] VALIDSIG ([0-9A-F]+) ", output, flags=re.MULTILINE)
        if rc == 0 and valid:
            signer = normalize_fingerprint(valid.group(1))
            ledger.add("gpg:git_tag:cryptographic_validity", "PASS", f"validsig={signer}")
            if trusted and signer == trusted:
                ledger.add("gpg:git_tag:signer_identity", "PASS", "matches_trusted_fingerprint")
            else:
                ledger.add("gpg:git_tag:signer_identity", "NOT_VERIFIED", "valid_signature_but_signer_unpinned", severity="high")
        elif rc == 124:
            ledger.add("gpg:git_tag", "NOT_VERIFIED", "verification_timed_out", severity="high", details=tail_text(output))
        else:
            ledger.add("gpg:git_tag", "FAIL", "signature_verification_failed", severity="critical", details=tail_text(output))
        rc, commit = run_bounded([git, "-C", str(ledger.repo), "rev-parse", f"{TAG}^{{commit}}"])
        if rc != 0:
            ledger.add("gpg:tag_commit", "NOT_VERIFIED", "tag_target_commit_unavailable", severity="high")
            return
        commit_id = commit.strip()
        rc, output = run_bounded(
            [git, "-c", f"gpg.program={wrapper}", "-C", str(ledger.repo), "verify-commit", "--raw", commit_id],
            env=env,
            timeout=15,
        )
        valid = re.search(r"^\[GNUPG:\] VALIDSIG ([0-9A-F]+) ", output, flags=re.MULTILINE)
        if rc == 0 and valid:
            signer = normalize_fingerprint(valid.group(1))
            ledger.add("gpg:tag_commit:cryptographic_validity", "PASS", f"commit={commit_id} validsig={signer}")
            if trusted and signer == trusted:
                ledger.add("gpg:tag_commit:signer_identity", "PASS", "matches_trusted_fingerprint")
            else:
                ledger.add("gpg:tag_commit:signer_identity", "NOT_VERIFIED", "valid_signature_but_signer_unpinned", severity="high")
        elif rc == 124:
            ledger.add("gpg:tag_commit", "NOT_VERIFIED", "verification_timed_out", severity="high", details=tail_text(output))
        else:
            ledger.add("gpg:tag_commit", "FAIL", "signature_verification_failed", severity="critical", details=tail_text(output))


def check_ots_evidence(
    ledger: Ledger, evidence_path: Path, material: Path, proof: Path
) -> None:
    try:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        ledger.add(
            "opentimestamps:evidence",
            "FAIL",
            "corroboration_evidence_unreadable",
            severity="critical",
            details=str(exc),
        )
        return
    if evidence.get("schema") != "gx.ots-max-evidence.v1":
        ledger.add(
            "opentimestamps:evidence",
            "FAIL",
            "unexpected_evidence_schema",
            severity="critical",
            details=evidence.get("schema"),
        )
        return

    inputs = evidence.get("inputs")
    checks = evidence.get("checks")
    source_integrity = evidence.get("source_integrity")
    if not isinstance(inputs, dict) or not isinstance(checks, dict) or not isinstance(source_integrity, dict):
        ledger.add(
            "opentimestamps:evidence",
            "FAIL",
            "required_evidence_objects_missing",
            severity="critical",
        )
        return
    target_record = inputs.get("target")
    proof_record = inputs.get("proof")
    target_sha = sha256(material)
    proof_sha = sha256(proof)
    hashes_match = (
        isinstance(target_record, dict)
        and isinstance(proof_record, dict)
        and target_record.get("sha256") == target_sha
        and proof_record.get("sha256") == proof_sha
    )
    ledger.context["opentimestamps"] = {
        "evidence_file": str(evidence_path),
        "evidence_sha256": sha256(evidence_path),
        "evidence_started_utc": evidence.get("started_utc"),
        "evidence_finished_utc": evidence.get("finished_utc"),
        "target_sha256": target_sha,
        "proof_sha256": proof_sha,
        "earliest_attestation": evidence.get("earliest_attestation"),
        "current_tip": evidence.get("current_tip"),
    }
    if not hashes_match:
        ledger.add(
            "opentimestamps:evidence_binding",
            "FAIL",
            "evidence_target_or_proof_hash_mismatch",
            severity="critical",
            details={
                "current_target_sha256": target_sha,
                "evidence_target_sha256": target_record.get("sha256") if isinstance(target_record, dict) else None,
                "current_proof_sha256": proof_sha,
                "evidence_proof_sha256": proof_record.get("sha256") if isinstance(proof_record, dict) else None,
            },
        )
        return
    ledger.add(
        "opentimestamps:evidence_binding",
        "PASS",
        "evidence_rebound_to_current_target_and_proof_sha256",
    )

    required_checks = {
        "proof_parse": "detached_v1_proof_parsed_to_exact_eof",
        "target_binding": "proof_digest_matches_current_target",
        "calendar_upgrades": "all_pending_calendar_paths_returned_bitcoin_attestations",
        "dual_provider_block_headers": "blockstream_and_mempool_headers_agree",
        "header_hash": "raw_header_double_sha256_matches_block_hash",
        "merkle_root": "ots_message_matches_raw_header_merkle_field",
        "compact_bits_pow": "compact_target_and_proof_of_work_pass",
        "source_unchanged": "target_and_proof_unchanged_during_audit",
    }
    for source_name, evidence_label in required_checks.items():
        item = checks.get(source_name)
        if not isinstance(item, dict):
            ledger.add(
                f"opentimestamps:{source_name}",
                "FAIL",
                "required_check_missing_from_evidence",
                severity="critical",
            )
        elif item.get("status") == "PASS":
            ledger.add(
                f"opentimestamps:{source_name}",
                "PASS",
                evidence_label,
                details=item,
            )
        else:
            status = "FAIL" if item.get("status") == "FAIL" else "NOT_VERIFIED"
            ledger.add(
                f"opentimestamps:{source_name}",
                status,
                "corroboration_check_did_not_pass",
                severity="critical" if status == "FAIL" else "high",
                details=item,
            )

    blocks = evidence.get("bitcoin_attestations")
    block_fields = (
        "provider_headers_match",
        "provider_block_hashes_match",
        "provider_json_core_fields_match",
        "header_hash_match",
        "ots_merkle_binding",
        "json_merkle_binding",
        "compact_bits_valid_mainnet",
        "pow_target_pass",
    )
    blocks_valid = (
        isinstance(blocks, list)
        and bool(blocks)
        and all(
            isinstance(block, dict)
            and block.get("status") == "PASS"
            and all(block.get(field) is True for field in block_fields)
            for block in blocks
        )
    )
    if blocks_valid:
        ledger.add(
            "opentimestamps:block_attestations",
            "PASS",
            f"fully_consistent_attestations={len(blocks)}",
            details=[
                {
                    "height": block.get("height"),
                    "block_hash": block.get("expected_block_hash"),
                    "timestamp_utc": (block.get("block_header") or {}).get("timestamp_utc"),
                }
                for block in blocks
            ],
        )
    else:
        ledger.add(
            "opentimestamps:block_attestations",
            "FAIL",
            "bitcoin_attestation_detail_incomplete_or_inconsistent",
            severity="critical",
        )
    tip = evidence.get("current_tip")
    if isinstance(tip, dict) and tip.get("status") == "PASS" and tip.get("providers_match") is True:
        ledger.add(
            "opentimestamps:tip_corroboration",
            "PASS",
            "two_provider_tip_heights_match_at_evidence_time",
            details={"heights": tip.get("heights"), "queried_utc": tip.get("queried_utc")},
        )
    else:
        ledger.add(
            "opentimestamps:tip_corroboration",
            "NOT_VERIFIED",
            "matching_provider_tip_not_available_in_evidence",
            severity="medium",
            details=tip,
        )


def check_local_full_node(ledger: Ledger, args: argparse.Namespace) -> None:
    clients = executable_candidates("bitcoin-cli")
    if not clients:
        ledger.add("opentimestamps:local_full_node", "NOT_VERIFIED", "bitcoin_cli_unavailable", severity="high")
        return
    client = clients[0]
    rc, output = run_bounded([client, "-rpcwait=0", "getblockchaininfo"], timeout=8)
    if rc != 0:
        ledger.add(
            "opentimestamps:local_full_node",
            "NOT_VERIFIED",
            "bitcoin_cli_available_but_node_unreachable",
            severity="high",
            details=tail_text(output),
        )
        return
    try:
        chain = json.loads(output)
    except json.JSONDecodeError:
        ledger.add("opentimestamps:local_full_node", "FAIL", "node_returned_invalid_json", severity="critical")
        return
    synced = (
        chain.get("chain") == "main"
        and chain.get("initialblockdownload") is False
        and isinstance(chain.get("blocks"), int)
        and chain.get("blocks") == chain.get("headers")
        and float(chain.get("verificationprogress", 0)) >= 0.999999
    )
    if not synced:
        ledger.add(
            "opentimestamps:local_full_node",
            "NOT_VERIFIED",
            "local_node_not_fully_synchronized_mainnet",
            severity="high",
            details={key: chain.get(key) for key in ("chain", "blocks", "headers", "verificationprogress", "initialblockdownload")},
        )
        return
    if not args.ots_evidence or not args.ots_evidence.expanduser().is_file():
        ledger.add("opentimestamps:local_full_node", "NOT_VERIFIED", "ots_block_evidence_unavailable_for_node_recheck", severity="high")
        return
    try:
        evidence = json.loads(args.ots_evidence.expanduser().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        ledger.add("opentimestamps:local_full_node", "FAIL", "ots_evidence_unreadable_for_node_recheck", severity="critical", details=str(exc))
        return
    blocks = evidence.get("bitcoin_attestations")
    if not isinstance(blocks, list) or not blocks:
        ledger.add("opentimestamps:local_full_node", "FAIL", "ots_attested_blocks_missing", severity="critical")
        return
    verified = []
    for block in blocks:
        expected_hash = block.get("expected_block_hash") if isinstance(block, dict) else None
        expected_height = block.get("height") if isinstance(block, dict) else None
        if not isinstance(expected_hash, str) or not isinstance(expected_height, int):
            ledger.add("opentimestamps:local_full_node", "FAIL", "malformed_attested_block_record", severity="critical")
            return
        header_rc, header_output = run_bounded([client, "-rpcwait=0", "getblockheader", expected_hash, "true"], timeout=10)
        if header_rc != 0:
            ledger.add("opentimestamps:local_full_node", "NOT_VERIFIED", "attested_block_unavailable_from_local_node", severity="high", details={"block_hash": expected_hash, "output": tail_text(header_output)})
            return
        try:
            header = json.loads(header_output)
        except json.JSONDecodeError:
            ledger.add("opentimestamps:local_full_node", "FAIL", "local_node_header_json_invalid", severity="critical")
            return
        if header.get("hash") != expected_hash or header.get("height") != expected_height or int(header.get("confirmations", 0)) <= 0:
            ledger.add("opentimestamps:local_full_node", "FAIL", "local_node_block_identity_or_mainchain_mismatch", severity="critical", details=header)
            return
        verified.append({"height": expected_height, "block_hash": expected_hash, "confirmations": header.get("confirmations")})
    ledger.add(
        "opentimestamps:local_full_node",
        "PASS",
        f"synchronized_mainnet_node_confirmed_attested_blocks={len(verified)}",
        details={"node": {key: chain.get(key) for key in ("chain", "blocks", "headers", "verificationprogress", "pruned")}, "blocks": verified},
    )


def check_ots(ledger: Ledger, args: argparse.Namespace) -> None:
    material = ledger.repo / f"GX_MERKLE_ROOT_{PROOF_ID}.txt"
    proof = ledger.repo / f"GX_MERKLE_ROOT_{PROOF_ID}.txt.ots"
    if not material.is_file() or not proof.is_file():
        ledger.add("opentimestamps:binding", "FAIL", "material_or_proof_missing", severity="critical")
        return
    if args.ots_evidence:
        evidence_path = args.ots_evidence.expanduser().resolve()
        if evidence_path.is_file():
            check_ots_evidence(ledger, evidence_path, material, proof)
        else:
            ledger.add(
                "opentimestamps:evidence",
                "FAIL",
                "supplied_evidence_file_missing",
                severity="critical",
                details=str(evidence_path),
            )
    else:
        ledger.add(
            "opentimestamps:corroborated_evidence",
            "NOT_VERIFIED",
            "gx_ots_max_evidence_not_supplied",
            severity="high",
        )
    check_local_full_node(ledger, args)
    if not args.allow_network:
        ledger.add(
            "opentimestamps:official_client",
            "NOT_VERIFIED",
            "official_client_network_verification_not_requested",
            severity="high",
        )
        return
    ots_candidates = executable_candidates("ots")
    ots = ots_candidates[0] if ots_candidates else None
    if ots is None:
        ledger.add("opentimestamps:official_client", "NOT_VERIFIED", "ots_client_unavailable", severity="high")
        return
    with tempfile.TemporaryDirectory(prefix="gx-ots-") as temp:
        temp_dir = Path(temp)
        shutil.copy2(material, temp_dir / material.name)
        shutil.copy2(proof, temp_dir / proof.name)
        rc, output = run_bounded([ots, "verify", proof.name], cwd=temp_dir, timeout=150)
    lower = output.lower()
    if rc == 0:
        ledger.add("opentimestamps:official_client", "PASS", "ots_verify_exit_0", details=tail_text(output))
    elif "does not match" in lower or "invalid" in lower or "mismatch" in lower:
        ledger.add("opentimestamps:official_client", "FAIL", "proof_or_binding_invalid", severity="critical", details=tail_text(output))
    else:
        ledger.add("opentimestamps:official_client", "NOT_VERIFIED", f"ots_verify_exit={rc}", severity="high", details=tail_text(output))


def tsr_details(text: str) -> dict[str, Any]:
    details: dict[str, Any] = {}
    patterns = {
        "status": r"Status:\s*([^\n]+)",
        "hash_algorithm": r"Hash Algorithm:\s*([^\n]+)",
        "serial_number": r"Serial number:\s*([^\n]+)",
        "timestamp": r"Time stamp:\s*([^\n]+)",
        "tsa": r"TSA:\s*([^\n]+)",
        "nonce": r"Nonce:\s*([^\n]+)",
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            details[key] = match.group(1).strip()
    imprint_lines = []
    in_imprint = False
    for line in text.splitlines():
        if line.strip() == "Message data:":
            in_imprint = True
            continue
        if in_imprint and re.match(r"^\s*[0-9A-Fa-f]{4}\s+-\s+", line):
            hex_side = line.split("-", 1)[1]
            hex_side = re.split(r"\s{3,}", hex_side, maxsplit=1)[0]
            imprint_lines.append(re.sub(r"[^0-9A-Fa-f]", "", hex_side))
            continue
        if in_imprint:
            break
    if imprint_lines:
        details["message_imprint"] = "".join(imprint_lines).lower()
    return details


def check_rfc3161(ledger: Ledger, args: argparse.Namespace) -> None:
    openssl, openssl_version = preferred_openssl()
    responses = {
        "digicert": ledger.repo / f"GX_MERKLE_SUPER_COMBINED_{PROOF_ID}.txt.digicert.tsr",
        "globalsign": ledger.repo / f"GX_MERKLE_SUPER_COMBINED_{PROOF_ID}.txt.globalsign.tsr",
    }
    if openssl is None:
        for label in responses:
            ledger.add(f"rfc3161:{label}", "NOT_VERIFIED", "openssl_unavailable", severity="high")
        return
    ledger.context["rfc3161"] = {
        "openssl": openssl,
        "openssl_version": openssl_version,
    }
    source = args.rfc3161_source
    if source is None:
        candidate = ledger.repo / RFC3161_SOURCE_NAME
        if candidate.is_file():
            source = candidate
        elif args.proof_pack_dir:
            candidate = args.proof_pack_dir.expanduser().resolve() / RFC3161_SOURCE_NAME
            if candidate.is_file():
                source = candidate
    ca_file = args.ca_file
    if ca_file is None:
        system_ca = Path("/etc/ssl/cert.pem")
        if system_ca.is_file():
            ca_file = system_ca
    imprints: dict[str, str] = {}
    request_overrides: dict[str, Path] = {}
    for value in args.rfc3161_request:
        label, separator, raw_path = value.partition("=")
        if not separator or label not in responses or not raw_path:
            ledger.add("rfc3161:request_arguments", "FAIL", "invalid_LABEL_PATH_argument", severity="critical", details=value)
            continue
        request_overrides[label] = Path(raw_path).expanduser().resolve()
    for label, response in responses.items():
        if not response.is_file():
            ledger.add(f"rfc3161:{label}:structure", "FAIL", "response_missing", severity="critical")
            continue
        rc, output = run_bounded([openssl, "ts", "-reply", "-in", str(response), "-text"], timeout=20)
        if rc != 0:
            ledger.add(f"rfc3161:{label}:structure", "FAIL", "response_parse_failed", severity="critical", details=tail_text(output))
            continue
        parsed = tsr_details(output)
        ledger.add(f"rfc3161:{label}:structure", "PASS", "response_parsed", details=parsed)
        digest = parsed.get("message_imprint")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            ledger.add(f"rfc3161:{label}:token_chain", "FAIL", "sha256_message_imprint_unavailable", severity="critical")
            continue
        imprints[label] = digest
        if ca_file is None or not ca_file.is_file():
            ledger.add(f"rfc3161:{label}:token_chain", "NOT_VERIFIED", "trusted_ca_bundle_unavailable", severity="high")
        else:
            command = [openssl, "ts", "-verify", "-digest", digest, "-in", str(response), "-CAfile", str(ca_file)]
            if args.untrusted_certificates and args.untrusted_certificates.is_file():
                command += ["-untrusted", str(args.untrusted_certificates)]
            rc, chain_output = run_bounded(command, timeout=25)
            if rc == 0:
                ledger.add(
                    f"rfc3161:{label}:token_chain",
                    "PASS",
                    "token_signature_and_chain_valid_for_declared_imprint",
                    details={"ca_file": str(ca_file), "output": tail_text(chain_output)},
                )
                wrong_first = "0" if digest[0] != "0" else "1"
                wrong_digest = wrong_first + digest[1:]
                wrong_rc, wrong_output = run_bounded(
                    [openssl, "ts", "-verify", "-digest", wrong_digest, "-in", str(response), "-CAfile", str(ca_file)],
                    timeout=25,
                )
                if wrong_rc != 0 and "message imprint mismatch" in wrong_output.lower():
                    ledger.add(f"rfc3161:{label}:negative_control", "PASS", "wrong_digest_rejected")
                else:
                    ledger.add(
                        f"rfc3161:{label}:negative_control",
                        "FAIL",
                        "wrong_digest_not_rejected_as_expected",
                        severity="critical",
                        details=tail_text(wrong_output),
                    )
            elif "libressl" in (openssl_version or "").lower() and "ess signing certificate error" in chain_output.lower():
                ledger.add(
                    f"rfc3161:{label}:token_chain",
                    "NOT_VERIFIED",
                    "libressl_ess_compatibility_limit_requires_modern_openssl_or_macos_security",
                    severity="high",
                    details=tail_text(chain_output),
                )
            else:
                ledger.add(f"rfc3161:{label}:token_chain", "FAIL", "token_or_chain_verification_failed", severity="critical", details=tail_text(chain_output))
        if source is None or not source.is_file():
            ledger.add(f"rfc3161:{label}:content_binding", "NOT_VERIFIED", "timestamped_source_material_unavailable", severity="high")
        else:
            source_digest = sha256(source)
            if source_digest == digest:
                ledger.add(
                    f"rfc3161:{label}:content_binding",
                    "PASS",
                    "source_sha256_matches_timestamp_imprint",
                    details={"source_sha256": source_digest, "source_bytes": source.stat().st_size},
                )
            else:
                ledger.add(
                    f"rfc3161:{label}:content_binding",
                    "FAIL",
                    "source_hash_does_not_match_timestamp_imprint",
                    severity="critical",
                    details={"source_sha256": source_digest, "timestamp_imprint": digest},
                )
        request_candidates = [
            request_overrides.get(label),
            response.with_suffix(".tsq"),
            ledger.repo / f"GX_MERKLE_SUPER_COMBINED_{PROOF_ID}.txt.{label}.tsq",
        ]
        if args.proof_pack_dir:
            request_candidates.append(
                args.proof_pack_dir.expanduser().resolve()
                / f"GX_MERKLE_SUPER_COMBINED_{PROOF_ID}.txt.{label}.tsq"
            )
        request = next((path for path in request_candidates if path is not None and path.is_file()), None)
        if request is not None:
            request_rc, request_output = run_bounded(
                [openssl, "ts", "-query", "-in", str(request), "-text"], timeout=20
            )
            request_details = tsr_details(request_output) if request_rc == 0 else {}
            request_imprint = request_details.get("message_imprint")
            response_nonce = parsed.get("nonce")
            request_nonce = request_details.get("nonce")
            source_imprint = sha256(source) if source is not None and source.is_file() else None
            nonce_matches = (
                isinstance(request_nonce, str)
                and isinstance(response_nonce, str)
                and request_nonce.lower() == response_nonce.lower()
            )
            if request_rc == 0 and request_imprint == digest and source_imprint == digest and nonce_matches:
                ledger.add(
                    f"rfc3161:{label}:request_binding",
                    "PASS",
                    "request_source_and_response_imprint_nonce_match",
                    details={
                        "request_sha256": sha256(request),
                        "message_imprint": request_imprint,
                        "nonce": request_nonce,
                    },
                )
            else:
                ledger.add(
                    f"rfc3161:{label}:request_binding",
                    "FAIL",
                    "request_source_or_response_binding_mismatch",
                    severity="critical",
                    details={
                        "request_parse_exit": request_rc,
                        "request_imprint": request_imprint,
                        "response_imprint": digest,
                        "source_imprint": source_imprint,
                        "request_nonce": request_nonce,
                        "response_nonce": response_nonce,
                    },
                )
        else:
            ledger.add(f"rfc3161:{label}:request_binding", "NOT_VERIFIED", "timestamp_request_absent", severity="medium")
        ledger.add(f"rfc3161:{label}:archived_revocation", "NOT_VERIFIED", "no_archived_crl_or_ocsp_ltv_evidence", severity="medium")
    if len(imprints) == len(responses) and len(set(imprints.values())) == 1:
        ledger.add(
            "rfc3161:cross_tsa_imprint",
            "PASS",
            f"both_tokens_declare_sha256={next(iter(imprints.values()))}",
        )
    elif len(imprints) == len(responses):
        ledger.add(
            "rfc3161:cross_tsa_imprint",
            "FAIL",
            "timestamp_tokens_declare_different_imprints",
            severity="critical",
            details=imprints,
        )
    else:
        ledger.add(
            "rfc3161:cross_tsa_imprint",
            "NOT_VERIFIED",
            "one_or_more_timestamp_imprints_unavailable",
            severity="high",
            details=imprints,
        )


def render_markdown(payload: dict[str, Any]) -> str:
    counts = payload["counts"]
    index = payload.get("context", {}).get("index", {})
    lines = [
        "# GX Transparency Maximum Verification",
        "",
        f"Generated: `{payload['generated_at_utc']}`",
        "",
        f"## Verdict: `{payload['overall']}`",
        "",
        f"- PASS: {counts['pass']}",
        f"- FAIL: {counts['fail']}",
        f"- NOT_VERIFIED: {counts['not_verified']}",
        f"- INFO: {counts['info']}",
        "",
        "This is a read-only local evidence result. It is not a runtime, release, deployment, public-distribution, or global-production claim.",
        "",
    ]
    if index:
        lines += [
            "## Index coverage",
            "",
            f"- Listed paths: {index.get('entry_count')}",
            f"- Present in Git checkout: {index.get('checkout_present_count')}",
            f"- Absent from Git checkout: {index.get('checkout_absent_count')}",
            f"- Checkout coverage: {index.get('checkout_coverage_rate', 0):.1%}",
            f"- Present in supplied proof pack: {index.get('proof_pack_present_count', 'not supplied')}",
            f"- Absent from supplied proof pack: {index.get('proof_pack_absent_count', 'not supplied')}",
            f"- Proof-pack coverage: {index.get('proof_pack_coverage_rate', 0):.1%}",
            "",
            "`GX_PROOF_INDEX.txt.sha256` authenticates only the index file bytes. The index does not contain per-artifact SHA-256 values.",
            "",
        ]
    lines += ["## Checks", "", "| Status | Check | Evidence |", "|---|---|---|"]
    for item in payload["checks"]:
        evidence = str(item["evidence"]).replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {item['status']} | `{item['id']}` | {evidence} |")
    lines += ["", "## Remaining closure inputs", ""]
    if payload["overall"] == "PASS":
        lines.append("None for the checks implemented by this verifier.")
    else:
        for item in payload["checks"]:
            if item["status"] in {"FAIL", "NOT_VERIFIED"}:
                lines.append(f"- **{item['status']}** `{item['id']}` — {item['evidence']}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    repo = args.repo.expanduser().resolve()
    print("GX_TRANSPARENCY_MAX_VERIFY=START")
    print(f"REPO={repo}")
    print("READ_ONLY=TRUE")
    print(f"NETWORK_FETCH_ALLOWED={'TRUE' if args.allow_network else 'FALSE'}")
    ledger = Ledger(repo, args.allow_network)
    check_repository(ledger)
    check_public_tag_publication(ledger)
    entries = check_index(ledger, args)
    check_proof_pack(ledger, args, entries)
    check_required_files(ledger, entries)
    check_snapshot_binding(ledger, args)
    check_anchor_semantics(ledger, args)
    check_gpg(ledger, args)
    check_ots(ledger, args)
    check_rfc3161(ledger, args)
    payload = ledger.payload()
    if args.output_dir:
        output_dir = args.output_dir.expanduser().resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        json_path = output_dir / "GX_TRANSPARENCY_MAX_VERIFY_RESULT.json"
        md_path = output_dir / "GX_TRANSPARENCY_MAX_VERIFY_REPORT.md"
        json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        md_path.write_text(render_markdown(payload), encoding="utf-8")
        print(f"RESULT_JSON={json_path}")
        print(f"RESULT_REPORT={md_path}")
    print(f"OVERALL={payload['overall']}")
    if payload["overall"] == "FAIL":
        return 1
    if payload["overall"] == "PARTIAL_NOT_VERIFIED":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
