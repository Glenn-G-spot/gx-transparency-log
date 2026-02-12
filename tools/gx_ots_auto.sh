#!/usr/bin/env bash
set -euo pipefail

DIR="$HOME/GX_UNIVERSE/_reports/_proof_packs"
REPO="$HOME/GX_UNIVERSE/GX_TRANSPARENCY_LOG"
LOG="$DIR/GX_OTS_AUTO.log"

STATE_ID="$DIR/GX_OTS_AUTO_LAST_ID.txt"
STATE_PENDING="$DIR/GX_OTS_AUTO_PENDING.txt"

OTS="$HOME/ots-venv/bin/ots"

cd "$DIR"

ID="$(
  ls -1 GX_PROOF_ROOT_[0-9TZ]*Z.txt 2>/dev/null \
  | sed -E 's/^GX_PROOF_ROOT_([0-9TZ]+Z)\.txt$/\1/' \
  | LC_ALL=C sort | tail -n 1
)"

{
  date
  echo "[GX] dir=$DIR"
  echo "[GX] repo=$REPO"
  echo "[GX] ots_bin=$OTS"
  echo "[GX] latest_id=$ID"
} >>"$LOG" 2>&1

if [ -z "${ID:-}" ]; then
  echo "[PANIC] NO_ID_FOUND" >>"$LOG"
  exit 2
fi

LAST_ID=""
[ -f "$STATE_ID" ] && LAST_ID="$(tr -d '\n\r' < "$STATE_ID" || true)"

LAST_PENDING="0"
[ -f "$STATE_PENDING" ] && LAST_PENDING="$(tr -d '\n\r' < "$STATE_PENDING" || true)"
case "$LAST_PENDING" in
  0|1) : ;;
  *) LAST_PENDING="0" ;;
esac

# Only care about current ID .ots files
shopt -s nullglob
OTS_FILES=( *"${ID}"*.ots )
shopt -u nullglob

if [ "${#OTS_FILES[@]}" -eq 0 ]; then
  echo "[PANIC] No .ots files for ID=$ID in $DIR" >>"$LOG"
  exit 4
fi

# If nothing new AND previously not pending -> exit fast
if [ "$ID" = "$LAST_ID" ] && [ "$LAST_PENDING" = "0" ]; then
  echo "[GX] no new ID and previous run had no pending -> exit" >>"$LOG"
  exit 0
fi

PENDING=0

echo "[1/2] upgrade all" >>"$LOG"
for f in "${OTS_FILES[@]}"; do
  echo " - upgrade $f" >>"$LOG"
  OUT="$("$OTS" upgrade "$f" 2>&1 || true)"
  printf "%s\n" "$OUT" >>"$LOG"
  echo "$OUT" | grep -qiE "Timestamp not complete|Pending confirmation|waiting for [0-9]+ confirmations" && PENDING=1
done

echo "[2/2] verify all (no bitcoin node)" >>"$LOG"
for f in "${OTS_FILES[@]}"; do
  echo " - verify $f" >>"$LOG"
  "$OTS" --no-bitcoin verify "$f" >>"$LOG" 2>&1 || true
done

echo "$ID" > "$STATE_ID"
echo "$PENDING" > "$STATE_PENDING"
echo "[GX] state updated: $STATE_ID=$ID pending=$PENDING" >>"$LOG"

# If still pending, stop here
if [ "$PENDING" = "1" ]; then
  echo "[GX] still pending -> not publishing" >>"$LOG"
  echo "DONE." >>"$LOG"
  exit 0
fi

# ---- publish to transparency repo (only when pending becomes 0) ----
echo "[GX] pending cleared -> publishing to transparency repo" >>"$LOG"

# Copy any .ots/.asc/.txt that belongs to this ID and exists
for f in *"${ID}"*.ots *"${ID}"*.asc *"${ID}"*.txt; do
  [ -f "$f" ] || continue
  cp -f "$DIR/$f" "$REPO/" 2>/dev/null || true
done

cd "$REPO"
git add *"${ID}"* 2>/dev/null || true
git commit -m "Publish upgraded OTS artifacts for ${ID}" >>"$LOG" 2>&1 || true
git push >>"$LOG" 2>&1 || true

# Auto-increment tag for merkle publish (or generic publish)
NEXT_R="$(
  git tag -l "gx-proof-${ID}-ots-r*" \
  | sed -E 's/^.*-r([0-9]+)$/\1/' \
  | sort -n \
  | tail -n 1
)"
if [ -z "${NEXT_R:-}" ]; then R=1; else R=$((NEXT_R + 1)); fi
TAG="gx-proof-${ID}-ots-r${R}"

git tag -a "$TAG" -m "OTS complete + published (${ID})" >>"$LOG" 2>&1
git push --tags >>"$LOG" 2>&1
git verify-tag "$TAG" >>"$LOG" 2>&1 || true

echo "[GX] published tag=$TAG" >>"$LOG"
echo "DONE." >>"$LOG"
