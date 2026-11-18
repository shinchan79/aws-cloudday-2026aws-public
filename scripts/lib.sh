#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN="$ROOT/.run"
CERTS="$ROOT/certs"
BIN="$ROOT/bin"
TF_DIR="$ROOT/terraform"

VAULT_TOKEN="${VAULT_TOKEN:-lab-root-token}"
VAULT_CONTAINER="${VAULT_CONTAINER:-ra-lab-vault}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-southeast-1}}"
HELPER_VERSION="1.8.6"

mkdir -p "$RUN" "$CERTS" "$BIN"
umask 077

say() { printf '\n== %s\n' "$*"; }
ok() { printf '   OK   %s\n' "$*"; }
no() { printf '   DENY %s\n' "$*"; }
die() { printf '\nerror: %s\n' "$*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || die "missing '$1'. See README.md."
}

vault() {
  docker exec \
    -e VAULT_TOKEN="$VAULT_TOKEN" \
    -e VAULT_ADDR="http://127.0.0.1:8200" \
    "$VAULT_CONTAINER" \
    vault "$@"
}

vault_stage() {
  local host="$1" dest="$2"
  docker cp "$host" "${VAULT_CONTAINER}:${dest}"
  docker exec "$VAULT_CONTAINER" chmod 644 "$dest"
}

load_accounts() {
  local envf="$ROOT/accounts.env"
  local which prefix id_var secret_var token_var
  [[ -f "$envf" ]] || die "missing accounts.env in this directory. Copy accounts.env.example."
  set -a
  # shellcheck disable=SC1091
  source "$envf"
  set +a
  REGION="${AWS_REGION:-$REGION}"
  export AWS_REGION="$REGION" AWS_DEFAULT_REGION="$REGION"
  for which in identity payment inventory; do
    prefix="$(printf '%s' "$which" | tr '[:lower:]' '[:upper:]')"
    id_var="${prefix}_AWS_ACCESS_KEY_ID"
    secret_var="${prefix}_AWS_SECRET_ACCESS_KEY"
    token_var="${prefix}_AWS_SESSION_TOKEN"
    [[ -n "${!id_var:-}" && -n "${!secret_var:-}" ]] || die "$which credentials are missing in accounts.env"
    printf -v "TF_VAR_${which}_access_key" '%s' "${!id_var}"
    printf -v "TF_VAR_${which}_secret_key" '%s' "${!secret_var}"
    printf -v "TF_VAR_${which}_session_token" '%s' "${!token_var:-}"
    export "TF_VAR_${which}_access_key" "TF_VAR_${which}_secret_key" "TF_VAR_${which}_session_token"
  done
}

aws_as() {
  local which="$1"
  shift
  local prefix id_var secret_var token_var id secret token
  case "$which" in
    identity|payment|inventory) ;;
    *) die "unknown account '$which'" ;;
  esac
  prefix="$(printf '%s' "$which" | tr '[:lower:]' '[:upper:]')"
  id_var="${prefix}_AWS_ACCESS_KEY_ID"
  secret_var="${prefix}_AWS_SECRET_ACCESS_KEY"
  token_var="${prefix}_AWS_SESSION_TOKEN"
  id="${!id_var:-}"
  secret="${!secret_var:-}"
  token="${!token_var:-}"
  [[ -n "$id" && -n "$secret" ]] || die "$which credentials are missing in accounts.env"
  if [[ -n "$token" ]]; then
    AWS_PAGER="" AWS_ACCESS_KEY_ID="$id" AWS_SECRET_ACCESS_KEY="$secret" AWS_SESSION_TOKEN="$token" \
      aws --region "$REGION" "$@"
  else
    AWS_PAGER="" AWS_ACCESS_KEY_ID="$id" AWS_SECRET_ACCESS_KEY="$secret" \
      aws --region "$REGION" "$@"
  fi
}

aws_admin() {
  aws_as identity "$@"
}

tf() {
  terraform -chdir="$TF_DIR" "$@"
}

load_outputs() {
  [[ -f "$TF_DIR/terraform.tfstate" ]] || die "no Terraform state. Run ./demo.sh aws."
  local rendered
  rendered="$(tf output -json | python3 -c '
import json, shlex, sys
data = json.load(sys.stdin)
for key, value in data.items():
    raw = value["value"]
    print("%s=%s" % (key, shlex.quote(str(raw))))
')" || die "could not read Terraform output."
  [[ -n "$rendered" ]] || die "Terraform output is empty."
  eval "$rendered"
}

signing_helper_url() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os:$arch" in
    Darwin:arm64) printf 'https://rolesanywhere.amazonaws.com/releases/%s/Aarch64/MacOS/Sonoma/aws_signing_helper' "$HELPER_VERSION" ;;
    Darwin:x86_64) printf 'https://rolesanywhere.amazonaws.com/releases/%s/X86_64/MacOS/Sonoma/aws_signing_helper' "$HELPER_VERSION" ;;
    Linux:x86_64) printf 'https://rolesanywhere.amazonaws.com/releases/%s/X86_64/Linux/Amzn2023/aws_signing_helper' "$HELPER_VERSION" ;;
    Linux:aarch64|Linux:arm64) printf 'https://rolesanywhere.amazonaws.com/releases/%s/Aarch64/Linux/Amzn2023/aws_signing_helper' "$HELPER_VERSION" ;;
    *) die "no signing-helper URL for $os $arch. Use 1.8.6 from the credential-helper doc." ;;
  esac
}

signing_helper_sha() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os:$arch" in
    Darwin:arm64) printf '%s\n' "56ee7a162249d0c2427e754ebcd6c9e5d672dc8b6a89623d67cfd4fd970e243c" ;;
    Darwin:x86_64) printf '%s\n' "484443b80b0fccbbe33137326a30020614c634b3a2fa5456a1f39ec991f17b80" ;;
    Linux:x86_64) printf '%s\n' "3553fdc515e5682541a9ebdd37031ec7f461169aa13ccbb6fbd5b7259644113d" ;;
    Linux:aarch64|Linux:arm64) printf '%s\n' "b8a1800a9f483674a376170e1eabc0796a4ad3b7ac048670de9346975e9925dc" ;;
    *) die "no checksum for $os $arch." ;;
  esac
}

ensure_helper() {
  local dest="$BIN/aws_signing_helper"
  local url sha actual
  url="$(signing_helper_url)"
  sha="$(signing_helper_sha)"
  if [[ ! -x "$dest" ]]; then
    say "download aws_signing_helper $HELPER_VERSION"
    curl -fsSL "$url" -o "$dest"
    chmod 700 "$dest"
    if [[ "$(uname -s)" == "Darwin" ]] && command -v xattr >/dev/null 2>&1; then
      xattr -d com.apple.quarantine "$dest" 2>/dev/null || true
    fi
  fi
  if command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$dest" | awk '{print $1}')"
  else
    actual="$(sha256sum "$dest" | awk '{print $1}')"
  fi
  [[ "$actual" == "$sha" ]] || die "signing-helper checksum mismatch. Delete $dest and retry. expected $sha, got $actual."
}

show_cert() {
  local file="$1"
  python3 - "$file" <<'PY'
import subprocess, sys
path = sys.argv[1]
text = subprocess.check_output(["openssl", "x509", "-in", path, "-noout", "-text"], text=True)
subject = issuer = nb = na = sig = ""
ku = []
ca = "absent"
capture = None
for raw in text.splitlines():
    line = raw.strip()
    if line.startswith("Signature Algorithm:") and not sig:
        sig = line.split(":", 1)[1].strip()
    elif line.startswith("Issuer:"):
        issuer = line.split(":", 1)[1].strip()
    elif line.startswith("Subject:"):
        subject = line.split(":", 1)[1].strip()
    elif line.startswith("Not Before:"):
        nb = line.split(":", 1)[1].strip()
    elif line.startswith("Not After :"):
        na = line.split(":", 1)[1].strip()
    elif line.startswith("X509v3 Key Usage:"):
        capture = "ku"
        continue
    elif line.startswith("X509v3 Basic Constraints:"):
        capture = "bc"
        continue
    elif capture == "ku":
        if line.startswith("X509v3 ") or line.startswith("Signature "):
            capture = None
        else:
            ku.append(line)
            capture = None
    elif capture == "bc":
        if "CA:TRUE" in line:
            ca = "CA:TRUE"
        elif "CA:FALSE" in line:
            ca = "CA:FALSE"
        capture = None
print(f"subject:    {subject}")
print(f"issuer:     {issuer}")
print(f"not before: {nb}")
print(f"not after:  {na}")
print(f"signature:  {sig}")
print(f"key usage:  {', '.join(ku) if ku else '(unreadable)'}")
print(f"basic:      {ca}")
PY
}

assert_end_entity() {
  local file="$1" expect_cn="$2"
  python3 - "$file" "$expect_cn" <<'PY'
import subprocess, sys
path, expect = sys.argv[1], sys.argv[2]
text = subprocess.check_output(["openssl", "x509", "-in", path, "-noout", "-text"], text=True)
low = text.lower()
if f"cn = {expect}".lower() not in low and f"cn={expect}".lower() not in low:
    sys.exit(f"{path}: missing CN={expect}")
if "ou = production" not in low and "ou=production" not in low:
    sys.exit(f"{path}: missing OU=production")
if "ca:true" in low:
    sys.exit(f"{path}: end-entity must not be a CA")
if "digital signature" not in low:
    sys.exit(f"{path}: key usage is missing Digital Signature")
first_sig = ""
for line in text.splitlines():
    if "Signature Algorithm:" in line:
        first_sig = line.lower()
        break
if "sha1" in first_sig or "md5" in first_sig:
    sys.exit(f"{path}: SHA-1 or MD5 signature is rejected by Roles Anywhere")
if "subject:" in low:
    for line in text.splitlines():
        if line.strip().startswith("Subject:"):
            value = line.split(":", 1)[1].strip()
            if not value:
                sys.exit(f"{path}: empty subject is not supported")
PY
}

create_session() {
  local name="$1" profile_arn="$2" role_arn="$3" trust_arn="$4"
  local out="$RUN/${name}-session.json"
  local err="$RUN/${name}-session.err"
  set +e
  "$BIN/aws_signing_helper" credential-process \
    --certificate "$CERTS/${name}.pem" \
    --private-key "$CERTS/${name}.key" \
    --profile-arn "$profile_arn" \
    --role-arn "$role_arn" \
    --trust-anchor-arn "$trust_arn" \
    --region "$REGION" \
    >"$out" 2>"$err"
  local rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    rm -f "$out"
    return "$rc"
  fi
  python3 - "$out" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
for key in ("AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"):
    if not doc.get(key):
        sys.exit(f"credential-process response is missing {key}")
PY
}

session_meta() {
  local file="$1"
  (
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_DEFAULT_REGION AWS_REGION
    unset AWS_PROFILE AWS_SESSION_EXPIRATION || true
    AWS_ACCESS_KEY_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["AccessKeyId"])' "$file")"
    AWS_SECRET_ACCESS_KEY="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["SecretAccessKey"])' "$file")"
    AWS_SESSION_TOKEN="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["SessionToken"])' "$file")"
    AWS_DEFAULT_REGION="$REGION"
    AWS_REGION="$REGION"
    AWS_PAGER="" aws sts get-caller-identity --output json
  )
}

session_expiration() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["Expiration"])' "$1"
}

get_object() {
  local creds="$1" bucket="$2" key="$3" dest="$4"
  (
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_DEFAULT_REGION AWS_REGION
    unset AWS_PROFILE AWS_SESSION_EXPIRATION || true
    AWS_ACCESS_KEY_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["AccessKeyId"])' "$creds")"
    AWS_SECRET_ACCESS_KEY="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["SecretAccessKey"])' "$creds")"
    AWS_SESSION_TOKEN="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["SessionToken"])' "$creds")"
    AWS_DEFAULT_REGION="$REGION"
    AWS_REGION="$REGION"
    AWS_PAGER="" aws s3api get-object --bucket "$bucket" --key "$key" "$dest" >/dev/null
  )
}

last_error() {
  local file="$1"
  python3 - "$file" <<'PY'
import sys
text = open(sys.argv[1], errors="replace").read().strip().splitlines()
interesting = [line for line in text if line.strip()]
print(interesting[-1][:400] if interesting else "(no stderr)")
PY
}
