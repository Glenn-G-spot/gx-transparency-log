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

## Result meanings

The verifier is read-only and performs no network fetch. It prints one final
status and exits with the corresponding code:

| Output | Exit | Meaning |
| --- | ---: | --- |
| `OVERALL=PASS` | 0 | Every check implemented by the verifier passed. |
| `OVERALL=FAIL` | 1 | A checksum, required file, or attempted signature check failed. |
| `OVERALL=PARTIAL_NOT_VERIFIED` | 2 | Local integrity checks passed, but required evidence or verification capability is unavailable. |

Missing tags, public keys, network-backed OpenTimestamps validation, and RFC
3161 certificate-chain validation are reported as `NOT_VERIFIED`; they are never
promoted to PASS. The verifier reports GPG checks separately for the Merkle root,
DNS anchor, and signed snapshot.

The current checkout includes the proof run `20260211T192351Z`, detached GPG
signatures, an OpenTimestamps proof, and two RFC 3161 responses. Passing a local
artifact check does not prove source-build, runtime, release, deployment,
commercial, or global status.

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
