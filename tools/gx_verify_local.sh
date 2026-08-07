#!/usr/bin/env bash
set -u

# Read-only verifier for the artifacts tracked by this checkout.  It can be run
# from any working directory; all paths are resolved relative to this script.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)" || exit 2
REPO="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)" || exit 2
ID="20260211T192351Z"
TAG="gx-proof-${ID}-r2"
incomplete=0
failed=0

pass() {
  printf 'PASS=%s\n' "$1"
}

not_verified() {
  printf 'NOT_VERIFIED=%s\n' "$1"
  incomplete=1
}

fail() {
  printf 'FAIL=%s\n' "$1" >&2
  failed=1
}

run_gpg_check() {
  signature=$1
  material=$2
  label=$3

  if ! command -v gpg >/dev/null 2>&1; then
    not_verified "$label:gpg_unavailable"
    return
  fi

  gpg_output="$(gpg --batch --status-fd 1 --verify "$signature" "$material" 2>&1)"
  gpg_rc=$?
  if [ "$gpg_rc" -eq 0 ]; then
    pass "$label"
  elif printf '%s\n' "$gpg_output" | grep -q '^\[GNUPG:\] NO_PUBKEY '; then
    not_verified "$label:public_key_unavailable"
  else
    printf '%s\n' "$gpg_output" >&2
    fail "$label:signature_check_failed"
  fi
}

printf '%s\n' 'GX_TRANSPARENCY_LOG_LOCAL_VERIFY=START'
printf 'REPO=%s\n' "$REPO"
printf 'PROOF_ID=%s\n' "$ID"
printf '%s\n' 'READ_ONLY=TRUE' 'NETWORK_FETCH_PERFORMED=FALSE'

if ! git -C "$REPO" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  fail 'repository:not_a_git_checkout'
  printf '%s\n' 'OVERALL=FAIL'
  exit 1
fi
pass 'repository:git_checkout'

if (cd "$REPO" && shasum -a 256 -c GX_PROOF_INDEX.txt.sha256); then
  pass 'checksum:GX_PROOF_INDEX.txt'
else
  fail 'checksum:GX_PROOF_INDEX.txt'
fi

required_files="
GX_MERKLE_ROOT_${ID}.txt
GX_MERKLE_ROOT_${ID}.txt.asc
GX_MERKLE_ROOT_${ID}.txt.ots
GX_DNS_TXT_ANCHOR_${ID}.txt
GX_DNS_TXT_ANCHOR_${ID}.txt.asc
snapshots/${ID}.json
snapshots/${ID}.json.asc
GX_MERKLE_SUPER_COMBINED_${ID}.txt.digicert.tsr
GX_MERKLE_SUPER_COMBINED_${ID}.txt.globalsign.tsr
"
printf '%s\n' "$required_files" | while IFS= read -r file; do
  [ -n "$file" ] || continue
  if [ -f "$REPO/$file" ]; then
    printf 'PASS=present:%s\n' "$file"
  else
    printf 'FAIL=missing:%s\n' "$file" >&2
    exit 1
  fi
done
presence_rc=$?
if [ "$presence_rc" -ne 0 ]; then
  failed=1
fi

run_gpg_check \
  "$REPO/GX_MERKLE_ROOT_${ID}.txt.asc" \
  "$REPO/GX_MERKLE_ROOT_${ID}.txt" \
  'gpg:merkle_root'
run_gpg_check \
  "$REPO/GX_DNS_TXT_ANCHOR_${ID}.txt.asc" \
  "$REPO/GX_DNS_TXT_ANCHOR_${ID}.txt" \
  'gpg:dns_anchor'
run_gpg_check \
  "$REPO/snapshots/${ID}.json.asc" \
  "$REPO/snapshots/${ID}.json" \
  'gpg:snapshot'

if git -C "$REPO" rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  tag_output="$(git -C "$REPO" verify-tag --raw "$TAG" 2>&1)"
  tag_rc=$?
  if [ "$tag_rc" -eq 0 ]; then
    pass "git_tag:$TAG"
  elif printf '%s\n' "$tag_output" | grep -Eq \
    '^\[GNUPG:\] NO_PUBKEY |No public key|waiting for lock|Operation timed out'; then
    not_verified "git_tag:$TAG:verification_capability_unavailable"
  else
    printf '%s\n' "$tag_output" >&2
    fail "git_tag:$TAG:signature_check_failed"
  fi
else
  not_verified "git_tag:$TAG:absent"
fi

not_verified 'opentimestamps:proof_present_but_network_verification_not_performed'
not_verified 'rfc3161:responses_present_but_certificate_chain_verification_not_performed'

if [ "$failed" -ne 0 ]; then
  printf '%s\n' 'OVERALL=FAIL'
  exit 1
fi
if [ "$incomplete" -ne 0 ]; then
  printf '%s\n' 'OVERALL=PARTIAL_NOT_VERIFIED'
  exit 2
fi

printf '%s\n' 'OVERALL=PASS'
