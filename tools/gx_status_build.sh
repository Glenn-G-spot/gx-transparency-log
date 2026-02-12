#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PROOFDIR="$HOME/GX_UNIVERSE/_reports/_proof_packs"

cd "$PROOFDIR"

ID="$(
  ls -1 GX_PROOF_ROOT_[0-9TZ]*Z.txt 2>/dev/null \
  | sed -E 's/^GX_PROOF_ROOT_([0-9TZ]+Z)\.txt$/\1/' \
  | sort | tail -n 1
)"

[ -n "${ID:-}" ] || { echo "NO_ID_FOUND in $PROOFDIR" >&2; exit 2; }

# detect core artifacts
ROOT="GX_PROOF_ROOT_${ID}.txt"
PACK="GX_PROOF_PACK_${ID}.tar.gz"
MAN="GX_PROOF_MANIFEST_${ID}.tsv"
SUM="GX_PROOF_SUMMARY_${ID}.txt"

MERKLE="GX_MERKLE_ROOT_${ID}.txt"
DNS="GX_DNS_TXT_ANCHOR_${ID}.txt"

# helper
exists() { [ -f "$1" ] && echo "DONE" || echo "TODO"; }

# OTS pending detector
ots_pending="NA"
if [ -f "GX_MERKLE_ROOT_${ID}.txt.ots" ]; then
  if grep -qiE "Pending confirmation|Timestamp not complete" "$PROOFDIR/GX_OTS_AUTO.log" 2>/dev/null; then
    ots_pending="PENDING"
  else
    ots_pending="DONE"
  fi
fi

# write JSON status (machine)
cat > "$REPO/GX_SYSTEM_STATUS.json" <<JSON
{
  "id": "$ID",
  "core": {
    "root": { "status": "$(exists "$ROOT")" },
    "pack": { "status": "$(exists "$PACK")" },
    "manifest": { "status": "$(exists "$MAN")" },
    "summary": { "status": "$(exists "$SUM")" }
  },
  "layer1": {
    "merkle_root": { "status": "$(exists "$MERKLE")" }
  },
  "anchoring": {
    "dns_anchor_file": { "status": "$(exists "$DNS")" },
    "ots_merkle": { "status": "$ots_pending" }
  }
}
JSON

# write Markdown dashboard (human)
cat > "$REPO/GX_SYSTEM_STATUS.md" <<MD
# GX SYSTEM STATUS

**latest_id:** \`$ID\`

## Core artifacts
- ROOT: \`$ROOT\` → **$(exists "$ROOT")**
- PACK: \`$PACK\` → **$(exists "$PACK")**
- MANIFEST: \`$MAN\` → **$(exists "$MAN")**
- SUMMARY: \`$SUM\` → **$(exists "$SUM")**

## Layer 1 — Merkle
- Merkle root file: \`$MERKLE\` → **$(exists "$MERKLE")**

## Layer 2 — Anchoring
- DNS anchor file: \`$DNS\` → **$(exists "$DNS")**
- OTS (merkle): **$ots_pending**

### Verify commands
\`\`\`bash
cd "$PROOFDIR"
gpg --verify "GX_PROOF_ROOT_${ID}.txt.asc" "$ROOT"
gpg --verify "GX_PROOF_PACK_${ID}.tar.gz.asc" "$PACK"
gpg --verify "GX_PROOF_MANIFEST_${ID}.tsv.asc" "$MAN"
gpg --verify "GX_PROOF_SUMMARY_${ID}.txt.asc" "$SUM"
\`\`\`

MD

echo "[OK] wrote:"
echo " - $REPO/GX_SYSTEM_STATUS.json"
echo " - $REPO/GX_SYSTEM_STATUS.md"
