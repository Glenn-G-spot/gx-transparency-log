#!/usr/bin/env python3
"""Build or verify a read-only GX transparency closure candidate.

The historical proof pack is never modified. Generated outputs are explicitly
new, unsigned evidence and may not be represented as historical attestations.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any


PROOF_ID = "20260211T192351Z"
SCHEMA = "gx_transparency_closure_candidate_v1"
HEX64 = re.compile(r"[0-9a-f]{64}")
PACKAGE_FILES = (
    f"GX_ARTIFACT_CONTENT_MANIFEST_{PROOF_ID}.tsv",
    f"GX_PROOF_PACK_MERKLE_RECONSTRUCTION_{PROOF_ID}.json",
    f"GX_MERKLE_V2_DERIVATION_TRANSCRIPT_{PROOF_ID}.json",
    f"GX_TRANSPARENCY_CLOSURE_PREFLIGHT_{PROOF_ID}.json",
    f"GX_TRANSPARENCY_CLOSURE_SUMMARY_{PROOF_ID}.md",
)


class ClosureError(Exception):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_text(path: Path, value: str) -> None:
    write_atomic(path, value.encode("utf-8"))


def write_json(path: Path, value: Any) -> None:
    write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def safe_entries(index_path: Path) -> list[str]:
    entries = [line.strip() for line in index_path.read_text(encoding="utf-8", errors="strict").splitlines() if line.strip()]
    if not entries:
        raise ClosureError("proof index is empty")
    if len(entries) != len(set(entries)):
        raise ClosureError("proof index contains duplicate entries")
    for entry in entries:
        candidate = Path(entry)
        if (
            candidate.is_absolute() or ".." in candidate.parts or entry == "."
            or candidate.as_posix() != entry or any(char in entry for char in "\t\r\n\0")
        ):
            raise ClosureError(f"unsafe index entry: {entry}")
    return entries


def verify_index_self_hash(pack: Path) -> dict[str, str]:
    index = pack / "GX_PROOF_INDEX.txt"
    checksum = pack / "GX_PROOF_INDEX.txt.sha256"
    match = re.fullmatch(
        r"([0-9A-Fa-f]{64})\s+[* ]?GX_PROOF_INDEX\.txt",
        checksum.read_text(encoding="utf-8", errors="strict").strip(),
    )
    if not match:
        raise ClosureError("GX_PROOF_INDEX.txt.sha256 is malformed")
    actual = sha256_file(index)
    if actual != match.group(1).lower():
        raise ClosureError("proof index self-checksum mismatch")
    return {"expected": match.group(1).lower(), "actual": actual}


def directory_digest(path: Path) -> tuple[int, str]:
    children = []
    total_bytes = 0
    for child in sorted(path.rglob("*"), key=lambda value: str(value.relative_to(path)).encode("utf-8")):
        if child.is_symlink():
            raise ClosureError(f"symlink inside indexed directory: {child.name}")
        if child.is_file():
            relative = str(child.relative_to(path))
            size = child.stat().st_size
            total_bytes += size
            children.append(f"file\0{relative}\0{size}\0{sha256_file(child)}\n")
        elif child.is_dir():
            children.append(f"directory\0{child.relative_to(path)}\0\n")
        else:
            raise ClosureError(f"special file inside indexed directory: {child.name}")
    material = b"gx-index-directory-v1\0" + "".join(children).encode("utf-8")
    return total_bytes, sha256_bytes(material)


def collect_records(pack: Path, entries: list[str]) -> list[dict[str, Any]]:
    records = []
    for entry in entries:
        path = pack / entry
        if any((pack.joinpath(*Path(entry).parts[:index])).is_symlink()
               for index in range(1, len(Path(entry).parts) + 1)):
            raise ClosureError(f"indexed symlink rejected: {entry}")
        if path.is_file():
            records.append({"path": entry, "type": "file", "bytes": path.stat().st_size, "sha256": sha256_file(path)})
        elif path.is_dir():
            size, digest = directory_digest(path)
            records.append({"path": entry, "type": "directory", "bytes": size, "sha256": digest})
        else:
            raise ClosureError(f"indexed path missing or special: {entry}")
    return records


def raw_pairwise_merkle(leaves: list[str]) -> tuple[str, list[list[str]]]:
    level = [bytes.fromhex(value) for value in leaves]
    levels = [list(leaves)]
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
    level = list(leaves)
    levels = [list(leaves)]
    while len(level) > 1:
        if len(level) % 2:
            raise ClosureError("historical Merkle-v2 ASCII-pair algorithm received an odd level")
        level = [
            sha256_bytes((level[index] + level[index + 1]).encode("ascii"))
            for index in range(0, len(level), 2)
        ]
        levels.append(list(level))
    return (level[0] if level else ""), levels


def parse_declared_v2_root(path: Path) -> str:
    match = re.fullmatch(
        rf"gx-merkle-root-v2 id={PROOF_ID} algo=sha256 root=([0-9a-f]{{64}})",
        path.read_text(encoding="utf-8", errors="strict").strip(),
    )
    if not match:
        raise ClosureError("declared Merkle-v2 root file is malformed")
    return match.group(1)


def historical_pack_merkle(pack: Path) -> dict[str, Any]:
    leaves_path = pack / f"GX_LEAVES_{PROOF_ID}.txt"
    manifest_path = pack / f"GX_PROOF_MANIFEST_{PROOF_ID}.tsv"
    leaves = [line.strip().lower() for line in leaves_path.read_text(encoding="utf-8", errors="strict").splitlines() if line.strip()]
    rows = list(csv.DictReader(manifest_path.read_text(encoding="utf-8", errors="strict").splitlines(), delimiter="\t"))
    manifest_leaves = sorted(str(row.get("sha256", "")).lower() for row in rows)
    if not leaves or not all(HEX64.fullmatch(value) for value in leaves):
        raise ClosureError("historical leaf file is empty or malformed")
    if leaves != manifest_leaves:
        raise ClosureError("historical leaves do not equal sorted manifest SHA-256 values")
    root, levels = raw_pairwise_merkle(leaves)
    negative = list(leaves)
    negative[0] = ("0" if negative[0][0] != "0" else "1") + negative[0][1:]
    negative_root, _ = raw_pairwise_merkle(negative)
    if negative_root == root:
        raise ClosureError("historical Merkle negative control did not change the root")
    root_fields = {}
    for line in (pack / f"GX_PROOF_ROOT_{PROOF_ID}.txt").read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            root_fields[key.strip()] = value.strip()
    return {
        "algorithm": "sorted manifest SHA-256 digests; parent=SHA256(raw_left||raw_right); duplicate odd leaf",
        "leaf_count": len(leaves),
        "leaves_match_manifest_sorted": True,
        "levels": levels,
        "reconstructed_root_sha256": root,
        "negative_control_root_sha256": negative_root,
        "negative_control_changed_root": True,
        "signed_historical_root_field": root_fields.get("merkle_root_sha256", ""),
        "signed_historical_root_field_status": "NOT_VERIFIED_EMPTY_FIELD" if not root_fields.get("merkle_root_sha256") else "POPULATED",
    }


def merkle_v2_derivation(pack: Path, repo_root_file: Path) -> dict[str, Any]:
    inputs = [
        pack / f"GX_PROOF_ROOT_{PROOF_ID}.txt",
        pack / f"GX_PROOF_PACK_{PROOF_ID}.tar.gz",
        pack / f"GX_PROOF_MANIFEST_{PROOF_ID}.tsv",
        pack / f"GX_PROOF_SUMMARY_{PROOF_ID}.txt",
    ]
    records = [{"name": path.name, "sha256": sha256_file(path)} for path in inputs]
    leaves = sorted(record["sha256"] for record in records)
    root, levels = ascii_pairwise_merkle(leaves)
    declared = parse_declared_v2_root(repo_root_file)
    negative = list(leaves)
    negative[0] = ("0" if negative[0][0] != "0" else "1") + negative[0][1:]
    negative_root, _ = ascii_pairwise_merkle(negative)
    if negative_root == root:
        raise ClosureError("Merkle-v2 negative control did not change the root")
    return {
        "algorithm": "sort four SHA-256 hex strings; parent=SHA256(ASCII_hex_left||ASCII_hex_right)",
        "inputs": records,
        "input_sha256_sorted": leaves,
        "levels": levels,
        "reconstructed_root_sha256": root,
        "declared_root_sha256": declared,
        "declared_root_matches": root == declared,
        "negative_control_root_sha256": negative_root,
        "negative_control_changed_root": True,
    }


def manifest_tsv(records: list[dict[str, Any]]) -> str:
    lines = ["path\ttype\tbytes\tsha256"]
    lines.extend(f"{row['path']}\t{row['type']}\t{row['bytes']}\t{row['sha256']}" for row in records)
    return "\n".join(lines) + "\n"


def manifest_file_map(root: Path) -> dict[str, str]:
    values = {}
    for line in (root / "SHA256SUMS").read_text(encoding="utf-8", errors="strict").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise ClosureError("SHA256SUMS is malformed")
        name = match.group(2)
        if name not in PACKAGE_FILES or name in values:
            raise ClosureError(f"unexpected or duplicate SHA256SUMS entry: {name}")
        values[name] = match.group(1)
    if set(values) != set(PACKAGE_FILES):
        raise ClosureError("SHA256SUMS must cover every closure output exactly once")
    return values


def verify_package(package: Path, pack: Path, repo_root_file: Path) -> None:
    checksums = manifest_file_map(package)
    for relative, expected in checksums.items():
        path = package / relative
        if path.is_symlink() or not path.is_file() or sha256_file(path) != expected:
            raise ClosureError(f"closure package checksum mismatch: {relative}")

    verify_index_self_hash(pack)
    entries = safe_entries(pack / "GX_PROOF_INDEX.txt")
    records = collect_records(pack, entries)
    stored_manifest = (package / f"GX_ARTIFACT_CONTENT_MANIFEST_{PROOF_ID}.tsv").read_text(encoding="utf-8", errors="strict")
    if stored_manifest != manifest_tsv(records):
        raise ClosureError("per-artifact content manifest does not match current proof-pack bytes")

    expected_pack_merkle = historical_pack_merkle(pack)
    stored_pack_merkle = json.loads((package / f"GX_PROOF_PACK_MERKLE_RECONSTRUCTION_{PROOF_ID}.json").read_text(encoding="utf-8"))
    for field in ("levels", "reconstructed_root_sha256", "negative_control_root_sha256", "leaves_match_manifest_sorted"):
        if stored_pack_merkle.get(field) != expected_pack_merkle.get(field):
            raise ClosureError(f"historical proof-pack Merkle transcript mismatch: {field}")

    expected_v2 = merkle_v2_derivation(pack, repo_root_file)
    stored_v2 = json.loads((package / f"GX_MERKLE_V2_DERIVATION_TRANSCRIPT_{PROOF_ID}.json").read_text(encoding="utf-8"))
    for field in ("input_sha256_sorted", "levels", "reconstructed_root_sha256", "declared_root_sha256", "declared_root_matches", "negative_control_root_sha256"):
        if stored_v2.get(field) != expected_v2.get(field):
            raise ClosureError(f"Merkle-v2 transcript mismatch: {field}")
    if not expected_v2["declared_root_matches"]:
        raise ClosureError("reconstructed Merkle-v2 root does not match declared root")
    print("VERIFY_CLOSURE_PACKAGE=PASS")


def build_package(args: argparse.Namespace) -> None:
    pack = args.proof_pack_dir.expanduser().resolve(strict=True)
    repo_root_file = args.repo_merkle_root.expanduser().resolve(strict=True)
    output = args.output_dir.expanduser().resolve()
    if any(root == output or root in output.parents for root in (pack, repo_root_file.parent)):
        raise ClosureError("output directory may not be inside the proof pack or repository root directory")
    output.mkdir(parents=True, exist_ok=True)

    index = pack / "GX_PROOF_INDEX.txt"
    index_hash = verify_index_self_hash(pack)
    entries = safe_entries(index)
    if args.repo_index:
        repo_index = args.repo_index.expanduser().resolve(strict=True)
        if repo_index.read_bytes() != index.read_bytes():
            raise ClosureError("repository index bytes differ from proof-pack index")

    records_before = collect_records(pack, entries)
    pack_merkle = historical_pack_merkle(pack)
    v2 = merkle_v2_derivation(pack, repo_root_file)
    if not v2["declared_root_matches"]:
        raise ClosureError("Merkle-v2 derivation does not reproduce the declared root")

    builder_sources = {}
    for label, value in (("proof_pack_builder", args.proof_pack_builder), ("merkle_v2_builder", args.merkle_v2_builder)):
        if value:
            path = value.expanduser().resolve(strict=True)
            builder_sources[label] = {"name": path.name, "sha256": sha256_file(path)}
    pack_merkle["builder_source"] = builder_sources.get("proof_pack_builder")
    v2["builder_source"] = builder_sources.get("merkle_v2_builder")

    manifest_name = f"GX_ARTIFACT_CONTENT_MANIFEST_{PROOF_ID}.tsv"
    pack_merkle_name = f"GX_PROOF_PACK_MERKLE_RECONSTRUCTION_{PROOF_ID}.json"
    v2_name = f"GX_MERKLE_V2_DERIVATION_TRANSCRIPT_{PROOF_ID}.json"
    preflight_name = f"GX_TRANSPARENCY_CLOSURE_PREFLIGHT_{PROOF_ID}.json"
    summary_name = f"GX_TRANSPARENCY_CLOSURE_SUMMARY_{PROOF_ID}.md"

    write_text(output / manifest_name, manifest_tsv(records_before))
    write_json(output / pack_merkle_name, {"schema": "gx_proof_pack_merkle_reconstruction_v1", "proof_id": PROOF_ID, **pack_merkle})
    write_json(output / v2_name, {"schema": "gx_merkle_v2_derivation_transcript_v1", "proof_id": PROOF_ID, **v2})

    records_after = collect_records(pack, entries)
    source_unchanged = records_before == records_after
    checks = [
        {"id": "index_self_checksum", "status": "PASS", "evidence": index_hash},
        {"id": "indexed_artifact_presence", "status": "PASS", "evidence": {"present": len(records_before), "total": len(entries)}},
        {"id": "per_artifact_content_manifest", "status": "PASS", "evidence": {"records": len(records_before)}},
        {"id": "historical_leaves_manifest_binding", "status": "PASS", "evidence": {"leaves": pack_merkle["leaf_count"]}},
        {"id": "historical_proof_pack_merkle_reconstruction", "status": "PASS", "evidence": pack_merkle["reconstructed_root_sha256"]},
        {"id": "historical_signed_root_merkle_field", "status": "NOT_VERIFIED", "evidence": "signed historical field is empty; reconstruction is new evidence"},
        {"id": "merkle_v2_declared_root_derivation", "status": "PASS", "evidence": v2["reconstructed_root_sha256"]},
        {"id": "negative_controls", "status": "PASS", "evidence": "both one-nibble substitutions changed their roots"},
        {"id": "source_unchanged", "status": "PASS" if source_unchanged else "FAIL", "evidence": "indexed bytes unchanged during build"},
        {"id": "signer_identity", "status": "NOT_VERIFIED", "evidence": "independent owner binding required"},
        {"id": "dns_publication", "status": "NOT_VERIFIED", "evidence": "controlled domain and DNSSEC receipt required"},
        {"id": "official_ots_local_full_node", "status": "NOT_VERIFIED", "evidence": "official client plus synchronized local node required"},
        {"id": "rfc3161_source_request_ltv", "status": "NOT_VERIFIED", "evidence": "original source, TSQ and archived revocation evidence required"},
    ]
    if not source_unchanged:
        raise ClosureError("proof-pack source changed while building closure evidence")
    preflight = {
        "schema": SCHEMA,
        "proof_id": PROOF_ID,
        "generated_at_utc": utc_now(),
        "read_only_source": True,
        "historical_artifacts_modified": False,
        "signed_or_published": False,
        "overall": "LOCAL_REPRODUCIBILITY_PASS_EXTERNAL_CLOSURE_REQUIRED",
        "counts": {
            "pass": sum(item["status"] == "PASS" for item in checks),
            "fail": sum(item["status"] == "FAIL" for item in checks),
            "not_verified": sum(item["status"] == "NOT_VERIFIED" for item in checks),
        },
        "checks": checks,
        "outputs": [manifest_name, pack_merkle_name, v2_name, summary_name],
        "truth_boundary": "New reproducibility evidence; not a historical signature, identity attestation, DNS publication, release, deployment or global claim.",
    }
    write_json(output / preflight_name, preflight)
    summary = f"""# GX Transparency Closure Candidate — {PROOF_ID}

## Result

`LOCAL_REPRODUCIBILITY_PASS_EXTERNAL_CLOSURE_REQUIRED`

- Indexed artifacts: {len(records_before)}/{len(entries)} present and content-hashed.
- Historical manifest leaves: {pack_merkle['leaf_count']} bound and deterministically reconstructed.
- Reconstructed historical proof-pack root: `{pack_merkle['reconstructed_root_sha256']}`.
- Reconstructed Merkle-v2 root: `{v2['reconstructed_root_sha256']}`.
- Declared Merkle-v2 root match: `PASS`.
- Negative controls: `PASS`.
- Source unchanged during build: `PASS`.

The signed historical proof-root field remains empty. This package does not rewrite it. Independent signer identity, DNS publication, official OTS/local-node validation, and RFC 3161 source/request/LTV evidence remain external gates.
"""
    write_text(output / summary_name, summary)

    checksum_rows = []
    for name in sorted(PACKAGE_FILES):
        checksum_rows.append(f"{sha256_file(output / name)}  {name}")
    write_text(output / "SHA256SUMS", "\n".join(checksum_rows) + "\n")
    verify_package(output, pack, repo_root_file)
    print(f"CLOSURE_OUTPUT={output}")
    print("LOCAL_CLOSURE=PASS")
    print("EXTERNAL_CLOSURE=REQUIRED")
    print("HISTORICAL_MUTATION=FALSE")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("build", "verify"):
        sub = subparsers.add_parser(name)
        sub.add_argument("--proof-pack-dir", required=True, type=Path)
        sub.add_argument("--repo-merkle-root", required=True, type=Path)
        sub.add_argument("--output-dir", required=True, type=Path)
        if name == "build":
            sub.add_argument("--repo-index", type=Path)
            sub.add_argument("--proof-pack-builder", type=Path)
            sub.add_argument("--merkle-v2-builder", type=Path)
    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
        pack = args.proof_pack_dir.expanduser().resolve(strict=True)
        repo_root_file = args.repo_merkle_root.expanduser().resolve(strict=True)
        output = args.output_dir.expanduser().resolve()
        if args.command == "build":
            build_package(args)
        else:
            verify_package(output, pack, repo_root_file)
        return 0
    except (OSError, ValueError, json.JSONDecodeError, ClosureError) as exc:
        print(f"CLOSURE_FAIL={str(exc).replace(chr(10), ' ')[:500]}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
