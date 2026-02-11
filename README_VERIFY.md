# GX Transparency Log — Verification Guide

This repository publishes signed snapshots ("tags") that attest to the integrity of GX proof-pack artifacts.

## What you can verify here
A signed Git tag (annotated) contains a status report that:
- identifies the latest proof-run ID (e.g. 20260211T192351Z)
- confirms core artifacts exist for that ID
- verifies GPG signatures over those artifacts
- confirms OpenTimestamps .ots proof files are present

If any referenced file is altered, GPG verification fails.

---

## 1) Verify the signed tag
Fetch tags and verify the tag signature:

git fetch --tags
git verify-tag gx-proof-20260211T192351Z-r2

Show the attested status report stored inside the tag:

git show gx-proof-20260211T192351Z-r2:GX_STATUS_REPORT.txt | sed -n '1,120p'

---

## 2) Verify GPG signatures on the proof-pack artifacts (local proof-pack folder)
ID="20260211T192351Z"
cd /Users/next-move/GX_UNIVERSE/_reports/_proof_packs

gpg --verify "GX_PROOF_ROOT_${ID}.txt.asc"     "GX_PROOF_ROOT_${ID}.txt"
gpg --verify "GX_PROOF_PACK_${ID}.tar.gz.asc"  "GX_PROOF_PACK_${ID}.tar.gz"
gpg --verify "GX_PROOF_MANIFEST_${ID}.tsv.asc" "GX_PROOF_MANIFEST_${ID}.tsv"
gpg --verify "GX_PROOF_SUMMARY_${ID}.txt.asc"  "GX_PROOF_SUMMARY_${ID}.txt"

---

## 3) OpenTimestamps (.ots) verification
source $HOME/ots-venv/bin/activate
cd /Users/next-move/GX_UNIVERSE/_reports/_proof_packs

ots upgrade "GX_PROOF_ROOT_${ID}.txt.ots" || true
ots upgrade "GX_PROOF_PACK_${ID}.tar.gz.ots" || true

ots --no-bitcoin verify "GX_PROOF_ROOT_${ID}.txt.ots"
ots --no-bitcoin verify "GX_PROOF_PACK_${ID}.tar.gz.ots"
