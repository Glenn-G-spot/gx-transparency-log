# GX Transparency Log — Verification Guide

This repository contains integrity evidence for GX proof artifacts. It is not
the `gx-se1` source tree and does not build or start `gx_node`.

## Run the verifier

Do **not** paste this README, a pull-request diff, lines beginning with `+`, or
terminal output into `zsh`. Run the checked-in verifier instead. It resolves the
repository from its own location, so it works even when Terminal is currently
in `$HOME` or another directory.

If the checkout is at `~/gx-transparency-log`, run exactly this one command:

```sh
"$HOME/gx-transparency-log/tools/gx_verify_local.sh"
```

If that path does not exist, locate the script without executing anything:

```sh
find "$HOME" -maxdepth 6 -type f -name gx_verify_local.sh -print 2>/dev/null
```

Then run the exact path printed by `find`, enclosed in double quotes. Do not run
`.env.local`: it is a configuration file, not an executable command.

## Run the maximum verifier

`tools/gx_verify_max.py` is the stricter, audit-oriented companion. It keeps the
checkout read-only and adds exact index-coverage measurement, observed SHA-256
digests for every inspected artifact, bounded subprocesses, isolated GPG state,
machine-readable JSON, and optional OpenTimestamps/RFC 3161 verification. The
stdlib-only `tools/gx_ots_max.py` companion performs bounded, allow-listed
calendar reads and independently recomputes the Bitcoin header hash, Merkle
binding, and compact-target proof of work against two public providers.

Run the complete local-only profile and save a ledger outside the repository:

```sh
python3 "$HOME/Documents/gx-transparency-log/tools/gx_verify_max.py" \
  --repo "$HOME/Documents/gx-transparency-log" \
  --output-dir "$HOME/Desktop/GX-Transparency-Max-Verify"
```

Optional trust inputs are never guessed. Supply them explicitly only after they
have been obtained through an independently trusted channel:

```sh
python3 "$HOME/Documents/gx-transparency-log/tools/gx_verify_max.py" \
  --repo "$HOME/Documents/gx-transparency-log" \
  --output-dir "$HOME/Desktop/GX-Transparency-Max-Verify" \
  --gpg-public-key "/trusted/path/GX_AUDIT_AUTHORITY_PUBLICKEY.asc" \
  --trusted-fingerprint "FULL_FINGERPRINT" \
  --rfc3161-source "/trusted/path/GX_MERKLE_SUPER_COMBINED_20260211T192351Z.txt" \
  --rfc3161-request "digicert=/trusted/path/GX_MERKLE_SUPER_COMBINED_20260211T192351Z.txt.digicert.tsq" \
  --rfc3161-request "globalsign=/trusted/path/GX_MERKLE_SUPER_COMBINED_20260211T192351Z.txt.globalsign.tsq" \
  --ca-file "/trusted/path/tsa-ca-bundle.pem" \
  --allow-network
```

Network-backed OpenTimestamps verification runs against a temporary copy. GPG
always uses a temporary isolated keyring. A cryptographically valid signature
without an independently pinned signer identity remains `NOT_VERIFIED`.
With network access enabled, the verifier also compares the local signed-tag
object to the exact tag published by `origin`; this proves public object
identity, not the real-world identity of the signer.

When a proof-pack directory is supplied, the verifier can discover the
historical RFC 3161 source and per-authority `.tsq` requests there. A request is
accepted only when its SHA-256 imprint and nonce match both the source and its
response. If `bitcoin-cli` is installed, the verifier makes a read-only RPC
probe: a running, fully synchronized mainnet node can independently confirm all
OTS-attested blocks. It never starts a node.

To generate corroboration evidence without installing software or changing the
proof, run the companion first and then bind its JSON back into the maximum
ledger:

```sh
OUT="$HOME/Desktop/GX-Transparency-Max-Verify"
mkdir -p "$OUT"
python3 "$HOME/Documents/gx-transparency-log/tools/gx_ots_max.py" \
  --target "$HOME/Documents/gx-transparency-log/GX_MERKLE_ROOT_20260211T192351Z.txt" \
  --proof "$HOME/Documents/gx-transparency-log/GX_MERKLE_ROOT_20260211T192351Z.txt.ots" \
  --evidence "$OUT/GX_OTS_MAX_EVIDENCE.json"
python3 "$HOME/Documents/gx-transparency-log/tools/gx_verify_max.py" \
  --repo "$HOME/Documents/gx-transparency-log" \
  --output-dir "$OUT" \
  --ots-evidence "$OUT/GX_OTS_MAX_EVIDENCE.json"
```

The OTS companion intentionally exits `2` after successful corroboration:
official-client verification and independent local-full-node validation remain
`NOT_VERIFIED`. Its JSON is accepted only when its recorded target and proof
SHA-256 values match the files currently being checked.

## Build the reproducibility closure candidate

`tools/gx_build_closure.py` converts the historical filename-only inventory
into new, explicitly unsigned reproducibility evidence. It hashes all 46
indexed artifacts, reconstructs the eight-leaf historical proof-pack Merkle
tree, derives the declared Merkle-v2 root from the four core artifacts, runs
negative controls, and verifies that the inspected source bytes did not change.
It never rewrites or upgrades the historical proof.

Run it against the local proof pack and save the new evidence outside both the
repository and the proof pack:

```sh
python3 "$HOME/Documents/gx-transparency-log/tools/gx_build_closure.py" build \
  --proof-pack-dir "$HOME/transfer/GX_UNIVERSE 4/_reports/_proof_packs" \
  --repo-merkle-root "$HOME/Documents/gx-transparency-log/GX_MERKLE_ROOT_20260211T192351Z.txt" \
  --repo-index "$HOME/Documents/gx-transparency-log/GX_PROOF_INDEX.txt" \
  --proof-pack-builder "$HOME/gx_analysis/extracted/GX_UNIVERSE/_reports/GX_PROOF_PACK_AUTOMATION_V4.sh" \
  --merkle-v2-builder "$HOME/gx_analysis/extracted/GX_UNIVERSE/GX_TRANSPARENCY_LOG/tools/gx_core_rebuild.sh" \
  --output-dir "$HOME/Desktop/GX-Transparency-Closure"
```

Verify a previously created closure directory without rebuilding it:

```sh
python3 "$HOME/Documents/gx-transparency-log/tools/gx_build_closure.py" verify \
  --proof-pack-dir "$HOME/transfer/GX_UNIVERSE 4/_reports/_proof_packs" \
  --repo-merkle-root "$HOME/Documents/gx-transparency-log/GX_MERKLE_ROOT_20260211T192351Z.txt" \
  --output-dir "$HOME/Desktop/GX-Transparency-Closure"
```

The expected honest result is
`LOCAL_REPRODUCIBILITY_PASS_EXTERNAL_CLOSURE_REQUIRED`. The historical signed
proof-root field is empty and remains `NOT_VERIFIED`; the reconstructed root is
new evidence, not a retroactive signature. Independent signer identity, DNS
publication, official OTS/local-node validation, and RFC 3161 source/request/LTV
evidence remain external gates.

## Result meanings

The verifier is read-only. Its default profile performs no network fetch; a
network-backed check runs only when explicitly requested. It prints one final
status and exits with the corresponding code:

| Output | Exit | Meaning |
| --- | ---: | --- |
| `OVERALL=PASS` | 0 | Every check implemented by the verifier passed. |
| `OVERALL=FAIL` | 1 | A checksum, required file, or attempted signature check failed. |
| `OVERALL=PARTIAL_NOT_VERIFIED` | 2 | Local integrity checks passed, but required evidence or verification capability is unavailable. |

Missing tags, public keys, network-backed OpenTimestamps validation, and RFC
3161 certificate-chain validation are reported as `NOT_VERIFIED`; they are never
promoted to PASS. The verifier reports GPG checks separately for the Merkle root,
DNS anchor, and signed snapshot. A signed tag whose key or local GPG verification
capability is unavailable is also `NOT_VERIFIED`; an actually invalid tag
signature is `FAIL`.

The current checkout includes the proof run `20260211T192351Z`, detached GPG
signatures, an OpenTimestamps proof, and two RFC 3161 responses. Passing a local
artifact check does not prove source-build, runtime, release, deployment,
commercial, or global status.

`GX_PROOF_INDEX.txt.sha256` authenticates only the bytes of
`GX_PROOF_INDEX.txt`. The index is a filename inventory, not a per-artifact
checksum manifest. The maximum verifier therefore reports its historical
limitation separately. A closure candidate created with `gx_build_closure.py`
adds a new 46-record content manifest without pretending those hashes existed in
the signed historical evidence.

## Manual Git inspection (optional)

The verifier uses `git -C`, so it does not depend on the current directory. For
manual inspection, use the same pattern:

```sh
REPO="$HOME/gx-transparency-log"
git -C "$REPO" status --short
git -C "$REPO" log -1 --oneline
git -C "$REPO" remote -v
git -C "$REPO" tag --list 'gx-proof-*'
```

An empty remote or tag list is not a PASS. Do not run `git fetch`, `git apply`,
`git am`, or `patch` unless you intentionally mean to modify or update a verified
checkout.
