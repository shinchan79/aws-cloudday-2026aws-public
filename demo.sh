#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$ROOT/scripts/lib.sh"

usage() {
  cat <<'EOF'
Usage:
  ./demo.sh up              Start Vault and create the CAs
  ./demo.sh aws             Create the trust anchor, roles, profiles, and two buckets
  ./demo.sh aws --yes       Same, without the prompt
  ./demo.sh certs           Print subject, issuer, validity, key usage. Not the private key
  ./demo.sh run             Issue certs, take S1, revoke, import the CRL, check access
  ./demo.sh stage           Same preparation, then four steps. Enter between steps
  ./demo.sh contain         Deny an issued session with aws:TokenIssueTime, then remove the deny
  ./demo.sh down --yes      Destroy AWS resources, stop Vault, delete local certificates

First run: up, aws, run.
EOF
}

wait_for_vault() {
  local i
  for i in $(seq 1 40); do
    if vault status >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  die "Vault is not ready. docker compose -f \"$ROOT/docker-compose.yml\" logs"
}

pki_ready() {
  vault read -field=certificate pki-issuing/cert/ca >/dev/null 2>&1
}

write_role() {
  local name="$1" cn="$2"
  vault write "pki-issuing/roles/${name}" \
    allowed_domains="$cn" \
    allow_bare_domains=true \
    allow_subdomains=false \
    allow_glob_domains=false \
    allow_any_name=false \
    allow_ip_sans=false \
    enforce_hostnames=false \
    server_flag=false \
    client_flag=true \
    key_type=rsa \
    key_bits=2048 \
    key_usage=DigitalSignature \
    ext_key_usage=ClientAuth \
    organization=Lab \
    ou=production \
    require_cn=true \
    ttl=168h \
    max_ttl=720h >/dev/null
}

init_pki() {
  say "Root CA and issuing CA"
  vault secrets disable pki-issuing >/dev/null 2>&1 || true
  vault secrets disable pki-root >/dev/null 2>&1 || true
  vault secrets enable -path=pki-root -description="lab root, not a trust anchor" pki >/dev/null
  vault secrets tune -max-lease-ttl=87600h pki-root >/dev/null
  vault write pki-root/root/generate/internal \
    common_name="lab-root.example" \
    ttl=87600h \
    key_type=rsa \
    key_bits=4096 >/dev/null
  vault read -field=certificate pki-root/cert/ca >"$CERTS/root-ca.pem"

  vault secrets enable -path=pki-issuing -description="lab issuing CA, this is the trust anchor" pki >/dev/null
  vault secrets tune -max-lease-ttl=43800h pki-issuing >/dev/null
  vault write -format=json pki-issuing/intermediate/generate/internal \
    common_name="lab-issuing.example" \
    key_type=rsa \
    key_bits=4096 >"$RUN/issuing-csr.json"
  python3 - "$RUN/issuing-csr.json" "$RUN/issuing.csr" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
open(sys.argv[2], "w").write(doc["data"]["csr"])
if not doc["data"]["csr"].startswith("-----BEGIN"):
    sys.exit("CSR is not PEM")
PY
  vault_stage "$RUN/issuing.csr" /tmp/issuing.csr
  vault write -format=json pki-root/root/sign-intermediate \
    csr=@/tmp/issuing.csr \
    format=pem \
    ttl=43800h >"$RUN/issuing-signed.json"
  python3 - "$RUN/issuing-signed.json" "$RUN/issuing-signed.pem" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
cert = doc["data"]["certificate"].strip() + "\n"
open(sys.argv[2], "w").write(cert)
if cert.count("BEGIN CERTIFICATE") != 1:
    sys.exit("sign-intermediate returned more than one certificate")
PY
  vault_stage "$RUN/issuing-signed.pem" /tmp/issuing-signed.pem
  vault write pki-issuing/intermediate/set-signed certificate=@/tmp/issuing-signed.pem >/dev/null
  vault write pki-issuing/config/crl expiry=720h >/dev/null
  vault read -field=certificate pki-issuing/cert/ca >"$CERTS/issuing-ca.pem"
  python3 - "$CERTS/issuing-ca.pem" <<'PY'
import sys
pem = open(sys.argv[1]).read()
if pem.count("BEGIN CERTIFICATE") != 1:
    sys.exit("issuing-ca.pem must contain exactly one certificate")
PY
  openssl verify -CAfile "$CERTS/root-ca.pem" "$CERTS/issuing-ca.pem" >/dev/null
  if [[ -f "$TF_DIR/terraform.tfstate" ]]; then
    printf '\nIssuing CA was recreated. Run ./demo.sh aws --yes so the trust anchor matches it.\n'
  fi
}

assert_issuing_ca() {
  python3 - "$CERTS/issuing-ca.pem" <<'PY'
import subprocess, sys
path = sys.argv[1]
text = subprocess.check_output(["openssl", "x509", "-in", path, "-noout", "-text"], text=True)
low = text.lower()
if "ca:true" not in low:
    sys.exit("issuing CA is missing CA:TRUE")
if "certificate sign" not in low:
    sys.exit("issuing CA is missing key usage Certificate Sign")
if "cn = lab-issuing.example" not in low and "cn=lab-issuing.example" not in low:
    sys.exit("issuing CA CN is not lab-issuing.example")
PY
}

reject_foreign_cn() {
  local err="$RUN/foreign-cn.err"
  set +e
  vault write pki-issuing/issue/payment common_name="inventory-worker" ttl=1h >"$RUN/foreign-cn.json" 2>"$err"
  local rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    die "payment role issued CN=inventory-worker"
  fi
  ok "payment role refused CN=inventory-worker"
}

issue_one() {
  local role="$1" cn="$2"
  vault write -format=json "pki-issuing/issue/${role}" \
    common_name="$cn" \
    ttl=168h >"$RUN/${cn}.json"
  python3 - "$RUN/${cn}.json" "$CERTS/${cn}.pem" "$CERTS/${cn}.key" "$RUN/${cn}.serial" <<'PY'
import json, os, sys
doc = json.load(open(sys.argv[1]))["data"]
open(sys.argv[2], "w").write(doc["certificate"].strip() + "\n")
open(sys.argv[3], "w").write(doc["private_key"].strip() + "\n")
open(sys.argv[4], "w").write(doc["serial_number"].strip() + "\n")
os.chmod(sys.argv[2], 0o644)
os.chmod(sys.argv[3], 0o600)
PY
  assert_end_entity "$CERTS/${cn}.pem" "$cn"
  ok "issued ${cn}"
}

cmd_up() {
  need docker
  need openssl
  need python3
  say "Vault dev on 127.0.0.1:8200"
  docker compose -f "$ROOT/docker-compose.yml" up -d
  wait_for_vault
  if pki_ready; then
    ok "issuing CA already present"
  else
    init_pki
  fi
  assert_issuing_ca
  write_role payment payment-reconciler
  write_role inventory inventory-worker
  reject_foreign_cn
  issue_one payment payment-reconciler
  issue_one inventory inventory-worker
  revoke_cn payment-reconciler
  revoke_cn inventory-worker
  ok "roles lock the CN. Test certificates revoked in Vault."
  vault read -field=certificate pki-issuing/cert/ca >"$CERTS/issuing-ca.pem"
  ok "issuing CA: $CERTS/issuing-ca.pem"
  printf '\nnext: ./demo.sh aws\n'
}

account_line() {
  local which="$1" label="$2" meta
  meta="$(aws_as "$which" sts get-caller-identity --output json)"
  python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print("%s\t%s\t%s" % (sys.argv[2], d["Account"], d["Arn"]))' "$meta" "$label"
}

cmd_aws() {
  need terraform
  need aws
  need python3
  [[ -s "$CERTS/issuing-ca.pem" ]] || die "no issuing CA. Run ./demo.sh up."
  assert_issuing_ca
  load_accounts
  cat >"$TF_DIR/terraform.tfvars" <<EOF
region              = "${REGION}"
issuing_ca_pem_path = "${CERTS}/issuing-ca.pem"
name_prefix         = "${NAME_PREFIX:-}"
EOF
  say "Terraform init"
  tf init -input=false
  say "Three admin callers. These credentials are not given to the workload."
  local identity_id payment_id inventory_id line
  line="$(account_line identity "identity")"
  identity_id="$(printf '%s' "$line" | cut -f2)"
  printf '   %s\n' "$(printf '%s' "$line" | tr '\t' '  ')"
  line="$(account_line payment "payment")"
  payment_id="$(printf '%s' "$line" | cut -f2)"
  printf '   %s\n' "$(printf '%s' "$line" | tr '\t' '  ')"
  line="$(account_line inventory "inventory")"
  inventory_id="$(printf '%s' "$line" | cut -f2)"
  printf '   %s\n' "$(printf '%s' "$line" | tr '\t' '  ')"
  [[ "$identity_id" != "$payment_id" && "$identity_id" != "$inventory_id" && "$payment_id" != "$inventory_id" ]] \
    || die "identity, payment, and inventory must be three different accounts."
  printf '   region:     %s\n' "$REGION"
  printf '   identity account: trust anchor, roles, profiles. No bucket.\n'
  printf '   payment and inventory accounts: one bucket each. No trust anchor.\n'
  if tf state list 2>/dev/null | grep -qx 'aws_s3_bucket.lab'; then
    printf '   The previous one-account bucket in this state will be deleted.\n'
  fi
  if [[ "${1:-}" != "--yes" ]]; then
    printf 'Type yes to create them: '
    read -r answer
    [[ "$answer" == "yes" ]] || die "stopped before creating resources."
  fi
  tf apply -input=false -auto-approve
  ok "next: ./demo.sh run"
}

cmd_certs() {
  need openssl
  [[ -s "$CERTS/issuing-ca.pem" ]] || die "no certificate. Run ./demo.sh up."
  say "Root CA. Not uploaded."
  show_cert "$CERTS/root-ca.pem"
  say "Issuing CA. This is the trust anchor."
  show_cert "$CERTS/issuing-ca.pem"
  if [[ -s "$CERTS/payment-reconciler.pem" ]]; then
    say "payment-reconciler"
    show_cert "$CERTS/payment-reconciler.pem"
  fi
  if [[ -s "$CERTS/inventory-worker.pem" ]]; then
    say "inventory-worker"
    show_cert "$CERTS/inventory-worker.pem"
  fi
}

save_s1() {
  cp "$RUN/payment-reconciler-session.json" "$RUN/s1.json"
  chmod 600 "$RUN/s1.json"
}

print_s1() {
  local meta arn exp
  meta="$(session_meta "$RUN/s1.json")"
  arn="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["Arn"])' "$meta")"
  exp="$(session_expiration "$RUN/s1.json")"
  printf '   label:      S1, issued before revoke\n'
  printf '   Arn:        %s\n' "$arn"
  printf '   expires:    %s\n' "$exp"
}

expect_session() {
  local name="$1" profile="$2" role="$3"
  if create_session "$name" "$profile" "$role" "$trust_anchor_arn"; then
    return 0
  fi
  return 1
}

expect_deny_session() {
  local name="$1" profile="$2" role="$3" label="$4"
  if expect_session "$name" "$profile" "$role"; then
    die "$label got a session."
  fi
  no "$label"
  printf '   reason:     %s\n' "$(last_error "$RUN/${name}-session.err")"
}

expect_object() {
  local creds="$1" bucket="$2" key="$3" label="$4"
  local dest="$RUN/object-body.json"
  if get_object "$creds" "$bucket" "$key" "$dest"; then
    ok "$label"
    printf '   body:       %s\n' "$(tr -d '\n' <"$dest")"
    return 0
  fi
  return 1
}

expect_deny_object() {
  local creds="$1" bucket="$2" key="$3" label="$4"
  local dest="$RUN/object-body.json"
  set +e
  get_object "$creds" "$bucket" "$key" "$dest" 2>"$RUN/get-object.err"
  local rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    die "$label read the object."
  fi
  no "$label"
}

revoke_cn() {
  local cn="$1" serial
  serial="$(tr -d '[:space:]' <"$RUN/${cn}.serial")"
  [[ -n "$serial" ]] || die "no serial for ${cn}."
  vault write pki-issuing/revoke serial_number="$serial" >/dev/null
}

revoke_payment() {
  local serial
  serial="$(tr -d '[:space:]' <"$RUN/payment-reconciler.serial")"
  revoke_cn payment-reconciler
  vault read -field=certificate pki-issuing/cert/crl >"$RUN/crl.pem"
  openssl crl -in "$RUN/crl.pem" -noout -text >"$RUN/crl.txt"
  python3 - "$serial" "$RUN/crl.txt" <<'PY'
import sys
serial = sys.argv[1].replace(":", "").lower()
text = open(sys.argv[2], errors="replace").read().lower().replace(":", "")
if serial not in text:
    sys.exit("CRL does not contain the revoked serial")
PY
  ok "revoked the current payment certificate"
}

publish_crl() {
  local existing
  existing="$(aws_admin rolesanywhere list-crls --output json | python3 -c '
import json, sys
wanted = "ra-lab-crl"
for item in json.load(sys.stdin).get("crls", []):
    if item.get("name") == wanted:
        print(item["crlId"])
        break
')"
  if [[ -n "$existing" ]]; then
    aws_admin rolesanywhere update-crl \
      --crl-id "$existing" \
      --crl-data "fileb://${RUN}/crl.pem" \
      --output json >"$RUN/crl-update.json"
    aws_admin rolesanywhere enable-crl --crl-id "$existing" >/dev/null
    ok "updated imported CRL $existing"
  else
    aws_admin rolesanywhere import-crl \
      --name ra-lab-crl \
      --trust-anchor-arn "$trust_anchor_arn" \
      --crl-data "fileb://${RUN}/crl.pem" \
      --enabled \
      --output json >"$RUN/crl-import.json"
    ok "imported CRL and enabled it"
  fi
}

wait_until_revoked() {
  local i
  for i in $(seq 1 12); do
    if expect_session payment-reconciler "$payment_profile_arn" "$payment_role_arn"; then
      printf '   new session still issued, try %s/12\n' "$i"
      sleep 5
    else
      return 0
    fi
  done
  return 1
}

trust_anchor_absent() {
  local which="$1" count
  count="$(aws_as "$which" rolesanywhere list-trust-anchors --output json | python3 -c '
import json, sys
name = sys.argv[1]
doc = json.load(sys.stdin)
found = [item for item in doc.get("trustAnchors", []) if item.get("name") == name]
print(len(found))
' "$trust_anchor_name")"
  [[ "$count" == "0" ]] || die "$which account has trust anchor $trust_anchor_name. This lab registers the CA in the identity account only."
  ok "$which account does not trust this CA"
}

prepare_credentials() {
  need aws
  need python3
  need openssl
  need docker
  ensure_helper
  load_accounts
  load_outputs
  [[ "$region" == "$REGION" ]] || die "AWS_REGION=$REGION but Terraform is in $region. Use the same region."
  delete_crl
  issue_one payment payment-reconciler
  issue_one inventory inventory-worker
  say "S1, while the payment certificate is still valid"
  expect_session payment-reconciler "$payment_profile_arn" "$payment_role_arn" \
    || die "S1 was not issued. $RUN/payment-reconciler-session.err — $(last_error "$RUN/payment-reconciler-session.err")"
  save_s1
  print_s1
  say "Revoke the payment certificate and import the CRL. S1 is kept and not requested again."
  revoke_payment
  publish_crl
  wait_until_revoked || die "payment still received a new session after the CRL import. See $RUN/crl.txt and the trust anchor."
  ok "new payment session denied"
}

step_inventory_denied() {
  say "inventory-worker requests PaymentReconcilerRole"
  expect_deny_session inventory-worker "$payment_profile_arn" "$payment_role_arn" \
    "inventory-worker denied PaymentReconcilerRole"
}

step_s1_reads_payment() {
  say "S1 reads the payment account"
  expect_object "$RUN/s1.json" "$payment_bucket" "payment-reconciler/input.json" \
    "S1 read payment-reconciler/input.json in the payment account" \
    || die "S1 could not read the payment object. The session may have expired, the bucket policy may not allow the role, or lab-token-issue-deny is still attached."
}

step_s1_authorization() {
  say "S1 reads its prefix in the payment account"
  expect_object "$RUN/s1.json" "$payment_bucket" "payment-reconciler/input.json" \
    "S1 read payment-reconciler/input.json" \
    || die "S1 could not read the payment object."
  say "Role allows the payment bucket. Session policy does not allow audit/."
  expect_deny_object "$RUN/s1.json" "$payment_bucket" "audit/input.json" \
    "S1 denied audit/input.json"
  say "Identity policy and the session policy allow the inventory object. The inventory bucket policy does not."
  expect_deny_object "$RUN/s1.json" "$inventory_bucket" "inventory-worker/input.json" \
    "S1 denied the inventory account"
}

step_s2_denied() {
  say "payment certificate requests a new session"
  expect_deny_session payment-reconciler "$payment_profile_arn" "$payment_role_arn" \
    "payment certificate denied a new session"
}

cmd_run() {
  prepare_credentials
  say "Certificates in use. The payment certificate is on the CRL."
  show_cert "$CERTS/payment-reconciler.pem"
  printf '\n'
  show_cert "$CERTS/inventory-worker.pem"

  say "Trust anchor is registered in the identity account only"
  trust_anchor_absent payment
  trust_anchor_absent inventory

  say "inventory-worker requests InventoryWorkerRole"
  expect_session inventory-worker "$inventory_profile_arn" "$inventory_role_arn" \
    || die "inventory-worker was denied its own role. $(last_error "$RUN/inventory-worker-session.err")"
  ok "inventory-worker received InventoryWorkerRole"
  expect_object "$RUN/inventory-worker-session.json" "$inventory_bucket" "inventory-worker/input.json" \
    "inventory-worker read its object in the inventory account" \
    || die "inventory-worker could not read its object."

  step_inventory_denied
  step_s1_authorization
  step_s2_denied
  step_s1_reads_payment
  printf '\nIssued session still reads. A new session for the revoked certificate does not.\n'
  printf 'To deny S1 as well: ./demo.sh contain\n'
}

cmd_stage() {
  PAUSE=1
  say "Prepare S1, revoke, and import the CRL"
  prepare_credentials
  printf '\nReady. Next four steps print the ARN, the expiry, and the result.\n'
  pause() { printf '\n[Enter]\n'; read -r _; }
  pause
  say "1. S1 was issued before revoke. The data accounts do not trust this CA."
  print_s1
  trust_anchor_absent payment
  trust_anchor_absent inventory
  pause
  step_inventory_denied
  pause
  step_s1_authorization
  pause
  step_s2_denied
  step_s1_reads_payment
  printf '\nDone. Step 2 is the role trust. Step 3 is the two accounts. Step 4 is the issued session.\n'
}

cmd_contain() {
  need aws
  need python3
  load_accounts
  load_outputs
  [[ -s "$RUN/s1.json" ]] || die "no S1. Run ./demo.sh run while the session is still valid."
  local cutoff role dest
  role="$payment_role_name"
  if date -u -v+60S +%Y-%m-%dT%H:%M:%SZ >/dev/null 2>&1; then
    cutoff="$(date -u -v+60S +%Y-%m-%dT%H:%M:%SZ)"
  else
    cutoff="$(date -u -d '+60 seconds' +%Y-%m-%dT%H:%M:%SZ)"
  fi
  dest="$RUN/contain-deny.json"
  python3 - "$cutoff" "$dest" <<'PY'
import json, sys
cutoff, path = sys.argv[1], sys.argv[2]
policy = {
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenySessionsIssuedBeforeCutoff",
    "Effect": "Deny",
    "Action": "s3:GetObject",
    "Resource": "*",
    "Condition": {"DateLessThan": {"aws:TokenIssueTime": cutoff}}
  }]
}
json.dump(policy, open(path, "w"))
PY
  cleanup() {
    aws_admin iam delete-role-policy \
      --role-name "$role" \
      --policy-name lab-token-issue-deny >/dev/null 2>&1 || true
  }
  trap cleanup EXIT
  say "Explicit deny for credentials issued before $cutoff"
  printf '   Matches every session of %s issued before T, not only S1.\n' "$role"
  printf '   Action is s3:GetObject only.\n'
  aws_admin iam put-role-policy \
    --role-name "$role" \
    --policy-name lab-token-issue-deny \
    --policy-document "file://${dest}" >/dev/null
  local i
  for i in $(seq 1 12); do
    if expect_object "$RUN/s1.json" "$payment_bucket" "payment-reconciler/input.json" "probe" >/dev/null 2>&1; then
      printf '   policy not visible yet, try %s/12\n' "$i"
      sleep 5
    else
      no "S1 denied by aws:TokenIssueTime"
      break
    fi
    if [[ "$i" == "12" ]]; then
      die "S1 can still read. The deny may not have propagated."
    fi
  done
  say "Remove the deny and read again"
  cleanup
  trap - EXIT
  for i in $(seq 1 12); do
    if get_object "$RUN/s1.json" "$payment_bucket" "payment-reconciler/input.json" "$RUN/object-body.json" 2>/dev/null; then
      ok "S1 read the object after the deny was removed"
      printf '   body:       %s\n' "$(tr -d '\n' <"$RUN/object-body.json")"
      ok "deleted lab-token-issue-deny"
      return 0
    fi
    printf '   delete not visible yet, try %s/12\n' "$i"
    sleep 5
  done
  die "policy deleted but S1 is still denied. Check inline policy lab-token-issue-deny on $role."
}

delete_crl() {
  local id
  id="$(aws_admin rolesanywhere list-crls --output json | python3 -c '
import json, sys
for item in json.load(sys.stdin).get("crls", []):
    if item.get("name") == "ra-lab-crl":
        print(item["crlId"])
        break
')"
  if [[ -n "$id" ]]; then
    aws_admin rolesanywhere delete-crl --crl-id "$id" >/dev/null
    ok "deleted CRL $id"
  fi
}

cmd_down() {
  [[ "${1:-}" == "--yes" ]] || die "this deletes both buckets, the roles, the profiles, the trust anchor, and local certificates. Run: ./demo.sh down --yes"
  if [[ -f "$ROOT/accounts.env" ]]; then
    load_accounts
    if command -v aws >/dev/null 2>&1 && [[ -f "$TF_DIR/terraform.tfstate" ]]; then
      delete_crl || true
    fi
    if command -v terraform >/dev/null 2>&1 && [[ -f "$TF_DIR/terraform.tfstate" ]]; then
      say "Terraform destroy"
      tf destroy -input=false -auto-approve
    fi
  else
    printf 'no accounts.env, so the AWS resources were left in place.\n'
  fi
  if command -v docker >/dev/null 2>&1; then
    docker compose -f "$ROOT/docker-compose.yml" down -v >/dev/null 2>&1 || true
  fi
  rm -rf "$RUN" "$BIN"
  find "$CERTS" -type f ! -name '.gitignore' -delete
  ok "local lab removed. If destroy failed, delete the remaining resources in the three accounts."
}

main() {
  case "${1:-}" in
    up) cmd_up ;;
    aws) cmd_aws "${2:-}" ;;
    certs) cmd_certs ;;
    run) cmd_run ;;
    stage) cmd_stage ;;
    contain) cmd_contain ;;
    down) cmd_down "${2:-}" ;;
    -h|--help|help|"") usage ;;
    *) usage; die "unknown command '$1'." ;;
  esac
}

main "$@"
