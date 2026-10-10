#!/usr/bin/env python3
"""Read-only, stdlib-only audit of one detached OpenTimestamps proof.

The script copies the target and proof to a TemporaryDirectory before parsing,
queries only allow-listed HTTPS calendars and two fixed Bitcoin data providers,
and writes one JSON evidence file. It never upgrades or writes the source proof.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


TOOL_VERSION = "1.0.0"
SCHEMA = "gx.ots-max-evidence.v1"
OTS_MAGIC = bytes.fromhex(
    "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294"
)
PENDING_TAG = bytes.fromhex("83dfe30d2ef90c8e")
BITCOIN_TAG = bytes.fromhex("0588960d73d71901")
LITECOIN_TAG = bytes.fromhex("06869a0d73d71b45")
MAX_PROOF_BYTES = 1_000_000
MAX_CALENDAR_BYTES = 20_000
MAX_PROVIDER_BYTES = 100_000
MAX_VARBYTES = 8192
MAX_MESSAGE_BYTES = 4096
MAX_RECURSION = 256
NETWORK_TIMEOUT_SECONDS = 20.0
RPC_TIMEOUT_SECONDS = 5.0

ALLOWED_CALENDAR_HOST_SUFFIXES = (
    ".calendar.opentimestamps.org",
    ".calendar.eternitywall.com",
    ".calendar.catallaxy.com",
)
PROVIDERS = {
    "blockstream": "https://blockstream.info/api",
    "mempool": "https://mempool.space/api",
}


class AuditError(Exception):
    """Base class for deterministic audit failures."""


class ParseError(AuditError):
    """The proof or a calendar response is malformed or unsupported."""


class NetworkUnavailable(AuditError):
    """A bounded network read could not be completed."""


class RemoteEvidenceError(AuditError):
    """A remote endpoint returned contradictory or malformed evidence."""


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects so a proof cannot redirect an audit to another host."""

    def redirect_request(  # type: ignore[override]
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


HTTP_OPENER = urllib.request.build_opener(NoRedirectHandler())


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


def file_fingerprint(path: Path) -> Dict[str, Any]:
    stat = path.stat()
    return {
        "path": str(path),
        "sha256": sha256_file(path),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "mode": oct(stat.st_mode & 0o7777),
        "device": stat.st_dev,
        "inode": stat.st_ino,
    }


def fingerprints_equal(before: Dict[str, Any], after: Dict[str, Any]) -> bool:
    fields = ("sha256", "size", "mtime_ns", "mode", "device", "inode")
    return all(before.get(field) == after.get(field) for field in fields)


def check(status: str, detail: str, **extra: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {"status": status, "detail": detail}
    result.update(extra)
    return result


def safe_error(exc: BaseException) -> str:
    text = str(exc).replace("\r", " ").replace("\n", " ").strip()
    return text[:500] if text else exc.__class__.__name__


class Reader:
    def __init__(self, data: bytes, label: str):
        self.data = data
        self.label = label
        self.pos = 0

    def read(self, length: int) -> bytes:
        if length < 0 or self.pos + length > len(self.data):
            raise ParseError(
                f"{self.label}: truncated at offset {self.pos}; need {length} bytes"
            )
        value = self.data[self.pos : self.pos + length]
        self.pos += length
        return value

    def read_varuint(self) -> int:
        value = 0
        shift = 0
        for _ in range(10):
            byte = self.read(1)[0]
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value
            shift += 7
        raise ParseError(f"{self.label}: oversized varuint at offset {self.pos}")

    def read_varbytes(self, limit: int = MAX_VARBYTES) -> bytes:
        length = self.read_varuint()
        if length > limit:
            raise ParseError(
                f"{self.label}: varbytes length {length} exceeds limit {limit}"
            )
        return self.read(length)

    def assert_eof(self) -> None:
        if self.pos != len(self.data):
            raise ParseError(
                f"{self.label}: trailing bytes at offset {self.pos} of {len(self.data)}"
            )


def parse_inner_varbytes(payload: bytes, label: str) -> bytes:
    reader = Reader(payload, label)
    value = reader.read_varbytes(MAX_VARBYTES)
    reader.assert_eof()
    return value


def parse_inner_varuint(payload: bytes, label: str) -> int:
    reader = Reader(payload, label)
    value = reader.read_varuint()
    reader.assert_eof()
    return value


def apply_op(tag: int, reader: Reader, message: bytes) -> Tuple[bytes, Dict[str, Any]]:
    if tag == 0x08:
        result = hashlib.sha256(message).digest()
        operation = {"op": "sha256"}
    elif tag == 0x02:
        result = hashlib.sha1(message).digest()
        operation = {"op": "sha1"}
    elif tag == 0x03:
        try:
            result = hashlib.new("ripemd160", message).digest()
        except ValueError as exc:
            raise ParseError("RIPEMD-160 is unavailable in this Python runtime") from exc
        operation = {"op": "ripemd160"}
    elif tag in (0xF0, 0xF1):
        argument = reader.read_varbytes(MAX_MESSAGE_BYTES)
        if not argument:
            raise ParseError(f"{reader.label}: empty append/prepend argument")
        if tag == 0xF0:
            result = message + argument
            operation = {"op": "append", "argument_hex": argument.hex()}
        else:
            result = argument + message
            operation = {"op": "prepend", "argument_hex": argument.hex()}
    elif tag == 0xF2:
        if not message:
            raise ParseError(f"{reader.label}: cannot reverse an empty message")
        result = message[::-1]
        operation = {"op": "reverse"}
    elif tag == 0xF3:
        if not message:
            raise ParseError(f"{reader.label}: cannot hexlify an empty message")
        result = message.hex().encode("ascii")
        operation = {"op": "hexlify"}
    else:
        raise ParseError(
            f"{reader.label}: unsupported operation tag 0x{tag:02x} at offset {reader.pos - 1}"
        )
    if not result or len(result) > MAX_MESSAGE_BYTES:
        raise ParseError(
            f"{reader.label}: operation result length {len(result)} is invalid"
        )
    return result, operation


def parse_timestamp(
    reader: Reader,
    initial_message: bytes,
    depth: int = 0,
    path: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    if depth >= MAX_RECURSION:
        raise ParseError(f"{reader.label}: recursion limit exceeded")
    if not initial_message or len(initial_message) > MAX_MESSAGE_BYTES:
        raise ParseError(f"{reader.label}: invalid initial message length")
    operation_path = list(path or [])
    attestations: List[Dict[str, Any]] = []

    def parse_item(tag: int) -> None:
        if tag == 0x00:
            attestation_tag = reader.read(8)
            payload = reader.read_varbytes(MAX_VARBYTES)
            if attestation_tag == PENDING_TAG:
                raw_uri = parse_inner_varbytes(payload, f"{reader.label}: pending URI")
                try:
                    detail: Any = raw_uri.decode("ascii")
                except UnicodeDecodeError as exc:
                    raise ParseError(f"{reader.label}: pending URI is not ASCII") from exc
                attestation_type = "pending"
            elif attestation_tag == BITCOIN_TAG:
                detail = parse_inner_varuint(payload, f"{reader.label}: Bitcoin height")
                attestation_type = "bitcoin"
            elif attestation_tag == LITECOIN_TAG:
                detail = parse_inner_varuint(payload, f"{reader.label}: Litecoin height")
                attestation_type = "litecoin"
            else:
                detail = payload.hex()
                attestation_type = "unknown"
            attestations.append(
                {
                    "type": attestation_type,
                    "tag_hex": attestation_tag.hex(),
                    "detail": detail,
                    "message_hex": initial_message.hex(),
                    "operations": list(operation_path),
                }
            )
            return

        next_message, operation = apply_op(tag, reader, initial_message)
        attestations.extend(
            parse_timestamp(
                reader,
                next_message,
                depth=depth + 1,
                path=operation_path + [operation],
            )
        )

    tag = reader.read(1)[0]
    while tag == 0xFF:
        parse_item(reader.read(1)[0])
        tag = reader.read(1)[0]
    parse_item(tag)
    return attestations


def parse_detached_proof(data: bytes) -> Dict[str, Any]:
    if len(data) > MAX_PROOF_BYTES:
        raise ParseError(f"detached proof exceeds {MAX_PROOF_BYTES} bytes")
    reader = Reader(data, "detached proof")
    if reader.read(len(OTS_MAGIC)) != OTS_MAGIC:
        raise ParseError("detached proof magic does not match OpenTimestamps")
    version = reader.read_varuint()
    if version != 1:
        raise ParseError(f"unsupported detached proof version {version}")
    file_hash_op = reader.read(1)[0]
    if file_hash_op != 0x08:
        raise ParseError(
            f"unsupported detached file-hash operation 0x{file_hash_op:02x}; expected SHA-256"
        )
    file_digest = reader.read(32)
    attestations = parse_timestamp(reader, file_digest)
    reader.assert_eof()
    return {
        "format_version": version,
        "file_hash_algorithm": "sha256",
        "file_digest": file_digest.hex(),
        "serialized_bytes": len(data),
        "attestations": attestations,
    }


def parse_calendar_timestamp(
    data: bytes, commitment: bytes, label: str
) -> List[Dict[str, Any]]:
    if len(data) > MAX_CALENDAR_BYTES:
        raise ParseError(f"{label}: response exceeds {MAX_CALENDAR_BYTES} bytes")
    reader = Reader(data, label)
    attestations = parse_timestamp(reader, commitment)
    reader.assert_eof()
    return attestations


def calendar_host_allowed(uri: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(uri)
        port = parsed.port
    except ValueError:
        return False
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    if parsed.username or parsed.password or port not in (None, 443):
        return False
    if parsed.query or parsed.fragment or parsed.params:
        return False
    host = parsed.hostname.lower()
    return any(host.endswith(suffix) for suffix in ALLOWED_CALENDAR_HOST_SUFFIXES)


def http_get_bytes(url: str, limit: int) -> Tuple[bytes, Dict[str, Any]]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.opentimestamps.v1",
            "User-Agent": f"GX-OTS-Max-Audit/{TOOL_VERSION}",
        },
        method="GET",
    )
    started = time.monotonic()
    try:
        with HTTP_OPENER.open(request, timeout=NETWORK_TIMEOUT_SECONDS) as response:
            body = response.read(limit + 1)
            if len(body) > limit:
                raise RemoteEvidenceError(f"response from {url} exceeds {limit} bytes")
            final_url = response.geturl()
            if final_url != url:
                raise RemoteEvidenceError(f"unexpected redirect from {url} to {final_url}")
            metadata = {
                "url": url,
                "status_code": getattr(response, "status", None),
                "bytes": len(body),
                "sha256": sha256_bytes(body),
                "duration_ms": round((time.monotonic() - started) * 1000, 3),
                "fetched_utc": utc_now(),
                "headers": {
                    key.lower(): response.headers.get(key)
                    for key in ("Date", "Content-Type", "Content-Length", "Server")
                    if response.headers.get(key) is not None
                },
            }
            if metadata["status_code"] != 200:
                raise RemoteEvidenceError(
                    f"unexpected HTTP status {metadata['status_code']} from {url}"
                )
            return body, metadata
    except RemoteEvidenceError:
        raise
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
        raise NetworkUnavailable(f"network read failed for {url}: {safe_error(exc)}") from exc


def http_get_text(url: str, limit: int = MAX_PROVIDER_BYTES) -> Tuple[str, Dict[str, Any]]:
    body, metadata = http_get_bytes(url, limit)
    try:
        return body.decode("utf-8").strip(), metadata
    except UnicodeDecodeError as exc:
        raise RemoteEvidenceError(f"response from {url} is not UTF-8") from exc


def compact_to_target(bits: int) -> Tuple[int, Dict[str, Any]]:
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    negative = bool(bits & 0x00800000)
    if exponent <= 3:
        target = mantissa >> (8 * (3 - exponent))
    else:
        target = mantissa << (8 * (exponent - 3))
    overflow = mantissa != 0 and (
        exponent > 34
        or (mantissa > 0xFF and exponent > 33)
        or (mantissa > 0xFFFF and exponent > 32)
    )
    metadata = {
        "bits_hex": f"{bits:08x}",
        "exponent": exponent,
        "mantissa": mantissa,
        "negative": negative,
        "overflow": overflow,
        "target_hex": f"{target:064x}" if 0 <= target < (1 << 256) else hex(target),
    }
    return target, metadata


MAINNET_POW_LIMIT, _ = compact_to_target(0x1D00FFFF)


def parse_json_object(text: str, label: str) -> Dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RemoteEvidenceError(f"{label}: invalid JSON: {safe_error(exc)}") from exc
    if not isinstance(value, dict):
        raise RemoteEvidenceError(f"{label}: expected a JSON object")
    return value


def corroborate_bitcoin_attestation(height: int, ots_message_hex: str) -> Dict[str, Any]:
    provider_data: Dict[str, Any] = {}
    hashes: Dict[str, str] = {}
    headers: Dict[str, str] = {}
    block_json: Dict[str, Dict[str, Any]] = {}

    for provider, base_url in PROVIDERS.items():
        block_hash, hash_meta = http_get_text(f"{base_url}/block-height/{height}")
        if len(block_hash) != 64:
            raise RemoteEvidenceError(
                f"{provider}: invalid block hash length for height {height}"
            )
        try:
            bytes.fromhex(block_hash)
        except ValueError as exc:
            raise RemoteEvidenceError(
                f"{provider}: non-hex block hash for height {height}"
            ) from exc
        block_hash = block_hash.lower()
        hashes[provider] = block_hash
        header_hex, header_meta = http_get_text(
            f"{base_url}/block/{block_hash}/header"
        )
        if len(header_hex) != 160:
            raise RemoteEvidenceError(
                f"{provider}: block header is not exactly 80 bytes at height {height}"
            )
        try:
            bytes.fromhex(header_hex)
        except ValueError as exc:
            raise RemoteEvidenceError(
                f"{provider}: block header is not hex at height {height}"
            ) from exc
        headers[provider] = header_hex.lower()
        raw_json, json_meta = http_get_text(f"{base_url}/block/{block_hash}")
        block_json[provider] = parse_json_object(
            raw_json, f"{provider} block JSON at height {height}"
        )
        provider_data[provider] = {
            "base_url": base_url,
            "block_hash_request": hash_meta,
            "header_request": header_meta,
            "block_json_request": json_meta,
        }

    providers_hash_match = len(set(hashes.values())) == 1
    providers_header_match = len(set(headers.values())) == 1
    if not providers_hash_match or not providers_header_match:
        raise RemoteEvidenceError(f"providers disagree on block {height}")

    expected_hash = next(iter(hashes.values()))
    raw_header = bytes.fromhex(next(iter(headers.values())))
    header_digest_internal = hashlib.sha256(
        hashlib.sha256(raw_header).digest()
    ).digest()
    calculated_hash = header_digest_internal[::-1].hex()
    raw_merkle_field = raw_header[36:68].hex()
    display_merkle_root = raw_header[36:68][::-1].hex()
    timestamp = struct.unpack("<I", raw_header[68:72])[0]
    bits = struct.unpack("<I", raw_header[72:76])[0]
    nonce = struct.unpack("<I", raw_header[76:80])[0]
    version = struct.unpack("<I", raw_header[0:4])[0]
    previous_block_hash = raw_header[4:36][::-1].hex()
    target, compact_metadata = compact_to_target(bits)
    hash_as_integer = int.from_bytes(header_digest_internal, "little")
    compact_valid = (
        target > 0
        and not compact_metadata["negative"]
        and not compact_metadata["overflow"]
        and target <= MAINNET_POW_LIMIT
    )
    pow_pass = compact_valid and hash_as_integer <= target

    json_core_matches = True
    json_summaries: Dict[str, Any] = {}
    for provider, info in block_json.items():
        summary = {
            "id": info.get("id"),
            "height": info.get("height"),
            "timestamp": info.get("timestamp"),
            "merkle_root": info.get("merkle_root"),
        }
        json_summaries[provider] = summary
        json_core_matches = json_core_matches and (
            summary["id"] == expected_hash
            and summary["height"] == height
            and summary["timestamp"] == timestamp
            and summary["merkle_root"] == display_merkle_root
        )
    json_core_matches = json_core_matches and len(
        {json.dumps(value, sort_keys=True) for value in json_summaries.values()}
    ) == 1

    return {
        "height": height,
        "ots_attested_message_hex": ots_message_hex,
        "providers": provider_data,
        "provider_block_hashes": hashes,
        "provider_headers_match": providers_header_match,
        "provider_block_hashes_match": providers_hash_match,
        "provider_json_core_fields_match": json_core_matches,
        "block_header": {
            "bytes": len(raw_header),
            "version": version,
            "previous_block_hash": previous_block_hash,
            "raw_merkle_field_hex": raw_merkle_field,
            "display_merkle_root": display_merkle_root,
            "timestamp_unix": timestamp,
            "timestamp_utc": dt.datetime.fromtimestamp(
                timestamp, dt.timezone.utc
            ).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "bits": compact_metadata,
            "nonce": nonce,
        },
        "expected_block_hash": expected_hash,
        "calculated_block_hash": calculated_hash,
        "header_hash_match": calculated_hash == expected_hash,
        "ots_merkle_binding": raw_merkle_field == ots_message_hex,
        "json_merkle_binding": all(
            value["merkle_root"] == display_merkle_root
            for value in json_summaries.values()
        ),
        "compact_bits_valid_mainnet": compact_valid,
        "pow_target_pass": pow_pass,
        "json_core": json_summaries,
    }


def query_tip_heights() -> Dict[str, Any]:
    heights: Dict[str, int] = {}
    requests: Dict[str, Any] = {}
    for provider, base_url in PROVIDERS.items():
        text, metadata = http_get_text(f"{base_url}/blocks/tip/height")
        try:
            height = int(text)
        except ValueError as exc:
            raise RemoteEvidenceError(f"{provider}: invalid tip height {text!r}") from exc
        if height < 0:
            raise RemoteEvidenceError(f"{provider}: negative tip height")
        heights[provider] = height
        requests[provider] = metadata
    return {
        "status": "PASS" if len(set(heights.values())) == 1 else "FAIL",
        "heights": heights,
        "providers_match": len(set(heights.values())) == 1,
        "requests": requests,
        "queried_utc": utc_now(),
    }


def probe_capabilities(allow_local_rpc: bool = False) -> Dict[str, Any]:
    ots_path = shutil.which("ots")
    bitcoin_cli_path = shutil.which("bitcoin-cli")
    local_node: Dict[str, Any] = {
        "status": "NOT_VERIFIED",
        "bitcoin_cli_path": bitcoin_cli_path,
        "rpc_probe_performed": False,
        "rpc_reachable": False,
        "full_chain_verification_performed": False,
        "reason": "No local full-node chain verification is performed by this audit.",
    }
    if bitcoin_cli_path and allow_local_rpc:
        local_node["rpc_probe_performed"] = True
        try:
            process = subprocess.run(
                [bitcoin_cli_path, "getblockchaininfo"],
                check=False,
                capture_output=True,
                text=True,
                timeout=RPC_TIMEOUT_SECONDS,
            )
            local_node["rpc_probe_returncode"] = process.returncode
            if process.returncode == 0:
                try:
                    info = json.loads(process.stdout)
                except json.JSONDecodeError:
                    local_node["rpc_probe_result"] = "reachable_but_invalid_json"
                else:
                    local_node["rpc_reachable"] = True
                    if isinstance(info, dict):
                        local_node["rpc_probe_result"] = {
                            "chain": info.get("chain"),
                            "blocks": info.get("blocks"),
                            "headers": info.get("headers"),
                            "initialblockdownload": info.get("initialblockdownload"),
                        }
                    else:
                        local_node["rpc_probe_result"] = "reachable_but_invalid_json_object"
            else:
                local_node["rpc_probe_result"] = "unreachable_or_rejected"
        except subprocess.TimeoutExpired:
            local_node["rpc_probe_result"] = "timeout"
        except OSError as exc:
            local_node["rpc_probe_result"] = f"probe_error:{safe_error(exc)}"

    return {
        "official_ots_client": {
            "status": "NOT_VERIFIED",
            "path": ots_path,
            "available": bool(ots_path),
            "verification_performed": False,
            "reason": (
                "This stdlib audit does not invoke an official OTS client; no proof upgrade is written."
            ),
        },
        "local_full_node": local_node,
    }


def write_json_atomic(path: Path, evidence: Dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = (
        json.dumps(evidence, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    with tempfile.NamedTemporaryFile(
        mode="wb", prefix=f".{path.name}.", dir=path.parent, delete=False
    ) as handle:
        temporary_name = Path(handle.name)
        handle.write(serialized)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.replace(temporary_name, path)
    finally:
        if temporary_name.exists():
            temporary_name.unlink()
    return sha256_bytes(serialized)


def aggregate_status(values: Iterable[str]) -> str:
    statuses = list(values)
    if any(value == "FAIL" for value in statuses):
        return "FAIL"
    if any(value == "NOT_VERIFIED" for value in statuses):
        return "NOT_VERIFIED"
    return "PASS"


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    default_evidence = Path(__file__).resolve().with_name("evidence.json")
    parser = argparse.ArgumentParser(
        description="Read-only OpenTimestamps target/calendar/Bitcoin header audit"
    )
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--proof", required=True, type=Path)
    parser.add_argument("--evidence", type=Path, default=default_evidence)
    parser.add_argument("--allow-local-rpc", action="store_true", help="Allow a read-only capability probe of bitcoin-cli's configured node.")
    return parser.parse_args(argv)


def run(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    target = args.target.expanduser().resolve(strict=True)
    proof = args.proof.expanduser().resolve(strict=True)
    evidence_path = args.evidence.expanduser().resolve()
    if target == proof or evidence_path in (target, proof):
        raise AuditError("target, proof, and evidence paths must be distinct")
    if not target.is_file() or not proof.is_file():
        raise AuditError("target and proof must both be regular files")

    started_monotonic = time.monotonic()
    started_utc = utc_now()
    target_before = file_fingerprint(target)
    proof_before = file_fingerprint(proof)
    evidence: Dict[str, Any] = {
        "schema": SCHEMA,
        "tool": {
            "name": "gx_ots_max.py",
            "version": TOOL_VERSION,
            "script_path": str(Path(__file__).resolve()),
            "script_sha256": sha256_file(Path(__file__).resolve()),
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "stdlib_only": True,
        },
        "run_id": str(uuid.uuid4()),
        "started_utc": started_utc,
        "scope": {
            "read_only_source": True,
            "temporary_copies_only": True,
            "installs_performed": False,
            "proof_upgrade_written": False,
            "source_mutation_authorized": False,
            "network_timeout_seconds": NETWORK_TIMEOUT_SECONDS,
            "rpc_timeout_seconds": RPC_TIMEOUT_SECONDS,
            "calendar_allowlist_suffixes": list(ALLOWED_CALENDAR_HOST_SUFFIXES),
            "bitcoin_providers": PROVIDERS,
        },
        "inputs": {
            "target": target_before,
            "proof": proof_before,
            "evidence_path": str(evidence_path),
        },
        "capabilities": probe_capabilities(args.allow_local_rpc),
        "checks": {},
        "proof": None,
        "calendar_upgrades": [],
        "bitcoin_attestations": [],
        "current_tip": None,
        "errors": [],
    }
    checks: Dict[str, Dict[str, Any]] = evidence["checks"]
    checks["official_client"] = check(
        "NOT_VERIFIED",
        "Official OTS client verification was intentionally not performed.",
    )
    checks["local_full_node"] = check(
        "NOT_VERIFIED",
        "A local full-node chain verification was not performed.",
    )

    with tempfile.TemporaryDirectory(prefix="gx-ots-max-") as temp_name:
        temp_dir = Path(temp_name)
        target_copy = temp_dir / "target"
        proof_copy = temp_dir / "proof.ots"
        shutil.copy2(target, target_copy)
        shutil.copy2(proof, proof_copy)
        evidence["temporary_workspace"] = {
            "used": True,
            "automatically_removed": True,
            "target_copy_sha256": sha256_file(target_copy),
            "proof_copy_sha256": sha256_file(proof_copy),
        }

        try:
            with proof_copy.open("rb") as handle:
                parsed_proof = parse_detached_proof(handle.read(MAX_PROOF_BYTES + 1))
        except (OSError, AuditError) as exc:
            checks["proof_parse"] = check("FAIL", safe_error(exc))
            checks["target_binding"] = check(
                "NOT_VERIFIED", "Proof could not be parsed."
            )
            evidence["errors"].append(
                {"stage": "proof_parse", "error": safe_error(exc)}
            )
            parsed_proof = None
        else:
            evidence["proof"] = parsed_proof
            checks["proof_parse"] = check(
                "PASS",
                "Detached OpenTimestamps v1 proof parsed to exact EOF.",
                serialized_bytes=parsed_proof["serialized_bytes"],
                attestation_count=len(parsed_proof["attestations"]),
            )
            target_copy_hash = sha256_file(target_copy)
            binding_pass = parsed_proof["file_digest"] == target_copy_hash
            checks["target_binding"] = check(
                "PASS" if binding_pass else "FAIL",
                (
                    "Proof file digest exactly matches the target SHA-256."
                    if binding_pass
                    else "Proof file digest does not match the target SHA-256."
                ),
                proof_file_digest=parsed_proof["file_digest"],
                target_sha256=target_copy_hash,
            )

        calendar_results: List[Dict[str, Any]] = evidence["calendar_upgrades"]
        bitcoin_candidates: List[Dict[str, Any]] = []
        if parsed_proof is not None and checks["target_binding"]["status"] == "PASS":
            pending = [
                item
                for item in parsed_proof["attestations"]
                if item["type"] == "pending"
            ]
            embedded_bitcoin = [
                item
                for item in parsed_proof["attestations"]
                if item["type"] == "bitcoin"
            ]
            evidence["proof"]["pending_attestation_count"] = len(pending)
            evidence["proof"]["embedded_bitcoin_attestation_count"] = len(
                embedded_bitcoin
            )
            bitcoin_candidates.extend(
                {
                    "source": "embedded_proof",
                    "height": int(item["detail"]),
                    "message_hex": item["message_hex"],
                }
                for item in embedded_bitcoin
            )

            for index, item in enumerate(pending, start=1):
                uri = str(item["detail"])
                commitment = bytes.fromhex(item["message_hex"])
                result: Dict[str, Any] = {
                    "index": index,
                    "calendar_uri": uri,
                    "commitment_hex": commitment.hex(),
                    "allowlisted": calendar_host_allowed(uri),
                    "status": "NOT_VERIFIED",
                }
                calendar_results.append(result)
                if not result["allowlisted"]:
                    result["detail"] = "Calendar URI is outside the strict HTTPS allowlist."
                    continue
                url = uri.rstrip("/") + "/timestamp/" + commitment.hex()
                try:
                    response, request_meta = http_get_bytes(url, MAX_CALENDAR_BYTES)
                    response_copy = temp_dir / f"calendar-{index}.timestamp"
                    response_copy.write_bytes(response)
                    attestations = parse_calendar_timestamp(
                        response_copy.read_bytes(), commitment, f"calendar {uri}"
                    )
                except NetworkUnavailable as exc:
                    result["status"] = "NOT_VERIFIED"
                    result["detail"] = safe_error(exc)
                    evidence["errors"].append(
                        {"stage": "calendar_network", "calendar": uri, "error": safe_error(exc)}
                    )
                    continue
                except (OSError, ParseError, RemoteEvidenceError) as exc:
                    result["status"] = "FAIL"
                    result["detail"] = safe_error(exc)
                    evidence["errors"].append(
                        {"stage": "calendar_parse", "calendar": uri, "error": safe_error(exc)}
                    )
                    continue
                bitcoin_from_calendar = [
                    attestation
                    for attestation in attestations
                    if attestation["type"] == "bitcoin"
                ]
                result.update(
                    {
                        "status": "PASS" if bitcoin_from_calendar else "NOT_VERIFIED",
                        "detail": (
                            "Calendar returned a valid Bitcoin-attested timestamp path "
                            "for the exact commitment."
                            if bitcoin_from_calendar
                            else "Calendar response is valid but contains no Bitcoin attestation."
                        ),
                        "request": request_meta,
                        "response_sha256": sha256_bytes(response),
                        "response_bytes": len(response),
                        "attestations": attestations,
                        "bitcoin_attestation_count": len(bitcoin_from_calendar),
                    }
                )
                bitcoin_candidates.extend(
                    {
                        "source": uri,
                        "height": int(attestation["detail"]),
                        "message_hex": attestation["message_hex"],
                    }
                    for attestation in bitcoin_from_calendar
                )

            if not pending and not embedded_bitcoin:
                checks["calendar_upgrades"] = check(
                    "FAIL", "Proof contains neither pending nor Bitcoin attestations."
                )
            elif pending:
                calendar_status = aggregate_status(
                    result["status"] for result in calendar_results
                )
                if calendar_status == "PASS" and not bitcoin_candidates:
                    calendar_status = "FAIL"
                checks["calendar_upgrades"] = check(
                    calendar_status,
                    (
                        "Every pending calendar returned a valid Bitcoin-attested timestamp path."
                        if calendar_status == "PASS"
                        else "One or more calendar upgrade paths were unavailable or invalid."
                    ),
                    pending_count=len(pending),
                    bitcoin_candidate_count=len(bitcoin_candidates),
                )
            else:
                checks["calendar_upgrades"] = check(
                    "PASS",
                    "Proof already contains Bitcoin attestations; no pending calendar was required.",
                )
        else:
            checks["calendar_upgrades"] = check(
                "NOT_VERIFIED", "Calendar reads skipped because target binding was not proven."
            )

        unique_candidates: List[Dict[str, Any]] = []
        seen_candidates = set()
        for candidate in bitcoin_candidates:
            key = (candidate["height"], candidate["message_hex"])
            if key not in seen_candidates:
                seen_candidates.add(key)
                unique_candidates.append(candidate)

        block_results: List[Dict[str, Any]] = evidence["bitcoin_attestations"]
        block_network_unavailable = False
        block_evidence_failed = False
        for candidate in unique_candidates:
            try:
                result = corroborate_bitcoin_attestation(
                    int(candidate["height"]), str(candidate["message_hex"])
                )
            except NetworkUnavailable as exc:
                block_network_unavailable = True
                block_results.append(
                    {
                        **candidate,
                        "status": "NOT_VERIFIED",
                        "detail": safe_error(exc),
                    }
                )
                evidence["errors"].append(
                    {
                        "stage": "bitcoin_provider_network",
                        "height": candidate["height"],
                        "error": safe_error(exc),
                    }
                )
                continue
            except (RemoteEvidenceError, ParseError, ValueError) as exc:
                block_evidence_failed = True
                block_results.append(
                    {**candidate, "status": "FAIL", "detail": safe_error(exc)}
                )
                evidence["errors"].append(
                    {
                        "stage": "bitcoin_provider_evidence",
                        "height": candidate["height"],
                        "error": safe_error(exc),
                    }
                )
                continue
            result["source"] = candidate["source"]
            result["status"] = (
                "PASS"
                if all(
                    (
                        result["provider_headers_match"],
                        result["provider_block_hashes_match"],
                        result["provider_json_core_fields_match"],
                        result["header_hash_match"],
                        result["ots_merkle_binding"],
                        result["json_merkle_binding"],
                        result["compact_bits_valid_mainnet"],
                        result["pow_target_pass"],
                    )
                )
                else "FAIL"
            )
            if result["status"] == "FAIL":
                block_evidence_failed = True
            block_results.append(result)

        if block_evidence_failed:
            block_status = "FAIL"
        elif block_network_unavailable or not block_results:
            block_status = "NOT_VERIFIED"
        else:
            block_status = "PASS"

        checks["dual_provider_block_headers"] = check(
            block_status,
            "Blockstream and mempool.space supplied matching block hashes and raw headers."
            if block_status == "PASS"
            else "Dual-provider block-header corroboration is incomplete or contradictory.",
        )
        for name, key in (
            ("header_hash", "header_hash_match"),
            ("merkle_root", "ots_merkle_binding"),
            ("compact_bits_pow", "pow_target_pass"),
        ):
            if block_status == "NOT_VERIFIED":
                status = "NOT_VERIFIED"
            elif any(result.get("status") == "FAIL" for result in block_results):
                status = "FAIL"
            elif all(result.get(key) is True for result in block_results):
                status = "PASS"
            else:
                status = "FAIL"
            checks[name] = check(
                status,
                f"{name} passed for every corroborated Bitcoin attestation."
                if status == "PASS"
                else f"{name} was not proven for every Bitcoin attestation.",
            )

        if block_status == "PASS":
            try:
                evidence["current_tip"] = query_tip_heights()
            except NetworkUnavailable as exc:
                evidence["current_tip"] = {
                    "status": "NOT_VERIFIED",
                    "detail": safe_error(exc),
                }
            except RemoteEvidenceError as exc:
                evidence["current_tip"] = {
                    "status": "FAIL",
                    "detail": safe_error(exc),
                }
        else:
            evidence["current_tip"] = {
                "status": "NOT_VERIFIED",
                "detail": "Tip query skipped because block corroboration was not PASS.",
            }

        if block_results:
            passed_blocks = [
                item for item in block_results if item.get("status") == "PASS"
            ]
            if passed_blocks:
                earliest = min(
                    passed_blocks,
                    key=lambda item: item["block_header"]["timestamp_unix"],
                )
                evidence["earliest_attestation"] = {
                    "height": earliest["height"],
                    "block_hash": earliest["expected_block_hash"],
                    "block_header_time_utc": earliest["block_header"][
                        "timestamp_utc"
                    ],
                    "claim": (
                        "The exact target bytes existed before this attesting Bitcoin block, "
                        "subject to the stated dual-provider and no-local-full-node boundary."
                    ),
                }

    target_after = file_fingerprint(target)
    proof_after = file_fingerprint(proof)
    target_unchanged = fingerprints_equal(target_before, target_after)
    proof_unchanged = fingerprints_equal(proof_before, proof_after)
    checks["source_unchanged"] = check(
        "PASS" if target_unchanged and proof_unchanged else "FAIL",
        "Target and proof fingerprints are unchanged after the audit."
        if target_unchanged and proof_unchanged
        else "Target or proof changed during the audit.",
    )
    evidence["source_integrity"] = {
        "target_before": target_before,
        "target_after": target_after,
        "target_unchanged": target_unchanged,
        "proof_before": proof_before,
        "proof_after": proof_after,
        "proof_unchanged": proof_unchanged,
    }

    required = (
        "proof_parse",
        "target_binding",
        "calendar_upgrades",
        "dual_provider_block_headers",
        "header_hash",
        "merkle_root",
        "compact_bits_pow",
        "source_unchanged",
    )
    required_statuses = [checks[name]["status"] for name in required]
    if any(status == "FAIL" for status in required_statuses):
        overall_status = "FAIL"
        exit_code = 1
    elif any(status == "NOT_VERIFIED" for status in required_statuses):
        overall_status = "PARTIAL_NOT_VERIFIED"
        exit_code = 2
    else:
        overall_status = "CORROBORATED_PARTIAL_NOT_VERIFIED"
        exit_code = 2
    evidence["finished_utc"] = utc_now()
    evidence["duration_ms"] = round((time.monotonic() - started_monotonic) * 1000, 3)
    evidence["overall"] = {
        "status": overall_status,
        "exit_code": exit_code,
        "required_cryptographic_checks": {name: checks[name]["status"] for name in required},
        "official_ots_client": "NOT_VERIFIED",
        "local_full_node": "NOT_VERIFIED",
        "claim_boundary": (
            "PASS means exact target/proof binding plus calendar and raw Bitcoin-header "
            "corroboration. It is not official-client verification or independent local "
            "full-node chain validation."
        ),
    }
    evidence_sha256 = write_json_atomic(evidence_path, evidence)
    print(f"EVIDENCE={evidence_path}")
    print(f"EVIDENCE_SHA256={evidence_sha256}")
    for name in (
        "proof_parse",
        "target_binding",
        "calendar_upgrades",
        "dual_provider_block_headers",
        "header_hash",
        "merkle_root",
        "compact_bits_pow",
        "source_unchanged",
        "official_client",
        "local_full_node",
    ):
        print(f"{name.upper()}={checks[name]['status']}")
    print(f"OVERALL={overall_status}")
    print(f"EXIT_CODE={exit_code}")
    return exit_code


def main() -> None:
    try:
        raise SystemExit(run())
    except (OSError, AuditError) as exc:
        print(f"FATAL={safe_error(exc)}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
