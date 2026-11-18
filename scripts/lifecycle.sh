#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib.sh
source "$ROOT/scripts/lib.sh"

PATH_NAME="secret/roles-anywhere/payment-reconciler"
WORK="$RUN/lifecycle"

need docker
need openssl
need python3

if [[ "$(docker inspect -f '{{.State.Running}}' "$VAULT_CONTAINER" 2>/dev/null || true)" != "true" ]]; then
  die "Vault is not running. Start it with ./demo.sh up"
fi
if ! vault read -field=certificate pki-issuing/cert/ca >/dev/null 2>&1; then
  die "issuing CA is missing. Run ./demo.sh up"
fi

mkdir -p "$WORK"

say "Clock"
printf '   root:          Private CA, general-purpose. Signs the intermediate. Not the trust anchor.\n'
printf '   intermediate:  Private CA, short-lived. Last in the chain. Renewed every 7 days.\n'
printf '   issues:        at most 7 days, through IssueCertificate. ACM does not issue from it.\n'
printf '   store:         Vault %s\n' "$PATH_NAME"
printf '   accounts:      the identity account trusts the intermediate. Payment and inventory do not.\n'
printf '   lab stand-in:  local issuing CA. This command does not create a Private CA.\n'

issue_one_aside() {
  local slot="$1"
  vault write -format=json pki-issuing/issue/payment \
    common_name="payment-reconciler" \
    ttl=24h >"$WORK/${slot}.json"
  python3 - "$WORK/${slot}.json" "$WORK/${slot}.pem" "$WORK/${slot}.key" "$WORK/${slot}.serial" <<'PY'
import json, os, sys
doc = json.load(open(sys.argv[1]))["data"]
open(sys.argv[2], "w").write(doc["certificate"].strip() + "\n")
open(sys.argv[3], "w").write(doc["private_key"].strip() + "\n")
open(sys.argv[4], "w").write(doc["serial_number"].strip() + "\n")
os.chmod(sys.argv[2], 0o644)
os.chmod(sys.argv[3], 0o600)
PY
  assert_end_entity "$WORK/${slot}.pem" "payment-reconciler"
}

store_version() {
  local slot="$1"
  local serial not_after
  serial="$(tr -d '\n' <"$WORK/${slot}.serial")"
  not_after="$(openssl x509 -in "$WORK/${slot}.pem" -noout -enddate | cut -d= -f2-)"
  python3 - "$WORK/${slot}.pem" "$WORK/${slot}.key" "$serial" "$not_after" "$WORK/${slot}.payload.json" <<'PY'
import json, pathlib, sys
pem, key, serial, not_after, dest = sys.argv[1:]
json.dump({
    "certificate": pathlib.Path(pem).read_text(),
    "private_key": pathlib.Path(key).read_text(),
    "serial": serial,
    "not_after": not_after,
}, open(dest, "w"))
PY
  vault_stage "$WORK/${slot}.payload.json" /tmp/lifecycle-payload.json
  vault kv put "$PATH_NAME" @/tmp/lifecycle-payload.json >/dev/null
  rm -f "$WORK/${slot}.payload.json"
  printf '%s\n' "$serial" "$not_after"
}

read_meta() {
  local version="${1:-}"
  if [[ -n "$version" ]]; then
    vault kv get -format=json -version="$version" "$PATH_NAME" >"$WORK/current.json"
  else
    vault kv get -format=json "$PATH_NAME" >"$WORK/current.json"
  fi
  python3 - "$WORK/current.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
data = doc["data"]["data"]
meta = doc["data"]["metadata"]
key = data.get("private_key", "")
print("version %s" % meta["version"])
print("serial %s" % data["serial"])
print("not_after %s" % data["not_after"])
print("private_key stored" if key.startswith("-----BEGIN") else "private_key missing")
PY
}

say "Issue into Vault"
issue_one_aside first
store_version first >"$WORK/first.meta"
first_serial="$(sed -n '1p' "$WORK/first.meta")"
first_after="$(sed -n '2p' "$WORK/first.meta")"
ok "serial ${first_serial}"
ok "notAfter ${first_after}"
ok "$(read_meta | tr '\n' ' ')"

say "Renew before notAfter"
held="$(read_meta | sed -n 's/^version //p')"
issue_one_aside second
store_version second >"$WORK/second.meta"
second_serial="$(sed -n '1p' "$WORK/second.meta")"
second_after="$(sed -n '2p' "$WORK/second.meta")"
ok "serial ${second_serial}"
ok "notAfter ${second_after}"
previous="$(read_meta "$held" | sed -n 's/^serial //p')"
[[ "$previous" == "$first_serial" ]] || die "version ${held} no longer holds the first serial"
ok "version ${held} still holds ${previous}"
ok "$(read_meta | tr '\n' ' ')"

say "Revoke the previous serial in Vault"
vault write pki-issuing/revoke serial_number="$first_serial" >/dev/null
ok "revoked ${first_serial} in Vault"
ok "CRL was not imported. Roles Anywhere still accepts that serial until notAfter"
current="$(read_meta | sed -n 's/^serial //p')"
[[ "$current" == "$second_serial" ]] || die "current Vault version is not the renewed certificate"
ok "current version is ${current}"
printf '\n   The files under certs/ were left as they were.\n'
