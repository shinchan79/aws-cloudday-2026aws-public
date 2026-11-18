# IAM Roles Anywhere lab

Watch `iam-roles-anywhere-demo.mp4` for a real `./demo.sh run`. The recording shows account IDs, role ARNs, and API results. It does not show access keys or session tokens.

This directory is the lab. It does not contain credentials, private keys, issued certificates, or Terraform state. Those are created locally and listed in `.gitignore`.

Three accounts, one Region. Vault dev issues a root and an issuing CA. The trust anchor is the issuing certificate, and it is registered only in the identity account.

| Account | Holds | Does not hold |
| --- | --- | --- |
| identity | trust anchor, both roles, both profiles | a bucket |
| payment | bucket `payment-reconciler/input.json` and `audit/input.json` | a trust anchor |
| inventory | bucket `inventory-worker/input.json` | a trust anchor |

| Certificate | Role | Where it can read |
| --- | --- | --- |
| `payment-reconciler` | `PaymentReconcilerRole` | `payment-reconciler/` in the payment account |
| `inventory-worker` | `InventoryWorkerRole` | `inventory-worker/` in the inventory account |

Registering the CA in the identity account does not create a trust anchor anywhere else. A second account vends its own sessions only after it has its own trust anchor, profile, and role trust. This lab does not do that.

Both certificates get `OU=production` from the Vault role when the issue request omits OU. The trust policy separates them by CN. Do not give the Vault token to the workload: a caller that holds it can supply a different OU.

## What `run` proves

1. The payment and inventory accounts do not have this trust anchor.
2. `inventory-worker` gets `InventoryWorkerRole` and reads its object in the inventory account. Both sides allow that call.
3. `inventory-worker` cannot `CreateSession` into `PaymentReconcilerRole`.
4. S1 reads `payment-reconciler/input.json` in the payment account. The role, the session policy, and the bucket policy all allow it.
5. S1 is denied `audit/input.json` in the same bucket. The role and the bucket policy allow it. The session policy does not.
6. S1 is denied the inventory object. The identity policy and the session policy allow that object on purpose. The inventory bucket policy does not grant `PaymentReconcilerRole`.
7. After the payment certificate is revoked and the CRL is imported, that certificate cannot get a new session.
8. S1, issued before revoke, still reads the payment object. Stop it with a deny. The CRL does not reach an issued session.

## Requirements

- Docker with Compose
- AWS CLI v2
- Terraform >= 1.5
- `openssl`, `python3`, `curl`
- egress to `rolesanywhere.<region>.amazonaws.com` and S3
- admin credentials for three accounts, in `accounts.env` (gitignored). Copy `accounts.env.example`.

Leave the session token empty only for a long-term key. The three account IDs must differ. These credentials create the resources. They are not given to the workload. Workload credentials are written under `.run/` mode `0600` and are not printed.

Default region is `ap-southeast-1` unless `accounts.env` sets `AWS_REGION`. `aws` and `run` both use that value. Use one region for all three accounts.

First `run` downloads `aws_signing_helper` 1.8.6 and checks the SHA-256 published on the credential-helper page.

## PKI

`docker compose` runs `vault server -dev`. Token `lab-root-token`. Listen `127.0.0.1:8200`. Dev mode keeps the CA in memory. Recreate the container and the CA is gone: run `./demo.sh up`, then `./demo.sh aws --yes`, so the trust anchor matches the new issuing certificate.

| Mount | Subject | Uploaded |
| --- | --- | --- |
| `pki-root` | `CN=lab-root.example` | no |
| `pki-issuing` | `CN=lab-issuing.example` | yes, this is the trust anchor |

Vault roles `payment` and `inventory`:

- `allowed_domains` is that workload's CN
- `allow_bare_domains=true`, `allow_any_name=false`, `enforce_hostnames=false`
- `ou=production`, `key_usage=DigitalSignature`, `ext_key_usage=ClientAuth`
- `ttl=168h`, `max_ttl=720h`

`up` fails if the payment role issues `CN=inventory-worker`.

End-entity check before a certificate is used: non-empty subject, not a CA, key usage Digital Signature, signature algorithm not SHA-1 or MD5.

No CDP URL is set. `crlDpRevocationEnabled` stays off. Roles Anywhere would have to fetch a localhost CDP, and turning that check on denies `CreateSession`. OCSP is not consulted.

## IAM

Trust policy on both roles:

- principal `rolesanywhere.amazonaws.com`
- `sts:AssumeRole`, `sts:TagSession`, `sts:SetSourceIdentity`
- `ArnEquals` on `aws:SourceArn` for this trust anchor
- `StringEquals` on `aws:PrincipalTag/x509Subject/CN` and `aws:PrincipalTag/x509Subject/OU`

`PaymentReconcilerRole` identity policy allows `s3:GetObject` on both data buckets. That is wider than the call we want to succeed.

`InventoryWorkerRole` identity policy allows `s3:GetObject` on the inventory bucket only.

Payment session policy allows `payment-reconciler/*` in the payment bucket, and `inventory-worker/*` in the inventory bucket. It does not allow `audit/*`. The inventory object is included so a deny on that object is the bucket policy, not the session policy. A session policy does not grant. It intersects.

Inventory session policy allows `inventory-worker/*` in the inventory bucket.

Payment bucket policy allows `PaymentReconcilerRole`. Inventory bucket policy allows `InventoryWorkerRole`. Each statement names the role ARN. Across accounts, the identity side and the bucket policy both have to allow. An explicit deny on either side wins. Granting the role ARN does not skip the session policy.

Profile duration is the API default, 3600 seconds. The API maximum is 43200.

## Commands

```bash
./demo.sh up
./demo.sh aws
./demo.sh run
```

Run the commands from this directory.

`aws` prints the three callers and waits for `yes`. `aws --yes` skips the prompt.

| Command | What it does |
| --- | --- |
| `up` | Start Vault, build the CAs and roles, reject a foreign CN, issue two certs, revoke them in Vault. |
| `aws` | Trust anchor, two roles, and two profiles in the identity account. One bucket in each data account. |
| `run` | Issue fresh certs, take S1, revoke payment, import the CRL, run the checks below. |
| `stage` | Same preparation, then four steps. Enter between steps. Prints the assumed-role ARN and expiry only. |
| `certs` | Subject, issuer, validity, signature, key usage, basic constraints. Does not print the private key. |
| `contain` | Put inline policy `lab-token-issue-deny` on `PaymentReconcilerRole`: deny `s3:GetObject` when `aws:TokenIssueTime` is before now+60s. Wait until S1 is denied, then delete the policy. |
| `down --yes` | Delete CRL `ra-lab-crl`, `terraform destroy` in all three accounts, `docker compose down -v`, delete `.run/`, `bin/`, and cert files. |

`run` deletes `ra-lab-crl` before S1 is issued, then imports a CRL signed by the current issuing CA after revoke. A CRL left from an older issuing key makes `CreateSession` fail with `Untrusted signing certificate`.

`run` sequence:

- the payment and inventory accounts have no trust anchor of this name
- `inventory-worker` receives `InventoryWorkerRole` and reads the inventory account
- `inventory-worker` is denied `PaymentReconcilerRole` (role trust, not an enrollment result)
- S1 reads `payment-reconciler/input.json` in the payment account
- S1 is denied `audit/input.json` (session policy)
- S1 is denied the inventory object (bucket policy in the inventory account)
- the payment certificate is denied a new session
- S1 reads the payment object again

The default role session name is the certificate serial in hex.

## Source identity

`payment-reconciler` is 19 characters, so the expected `sts:SourceIdentity` is `CN=payment-reconciler`. Put the value CloudTrail recorded into the deny. The bare CN is the wrong condition. The trust-model page has an example that prints the bare CN; the prefix rule on that page is the rule.

| CN | `sts:SourceIdentity` |
| --- | --- |
| present, 1–61 characters | `CN=` + CN |
| absent | `ID=` + hex serial, padded to an even number of digits |
| 62–256 characters | the CN, no prefix |
| longer than 256 | `CreateSession` fails |

No built-in X.509 principal tag carries the serial.

## CRL

`run` revokes by the serial in the issue response, reads the PEM CRL from `pki-issuing`, checks that `openssl crl -text` contains the serial, then `import-crl` or `update-crl`.

- name: `ra-lab-crl`
- `--crl-data fileb://` the PEM
- `--enabled`, then `enable-crl` on update
- trust anchor ARN of this issuing CA

An imported CRL is not dropped when `nextUpdate` passes. Import again when the CA publishes. The CRL has to be signed by the issuing CA. `ImportCrl` requires PEM.

`CreateSession` is retried up to 12 times, 5 seconds apart, until a new payment session is denied.

## Containment

`contain` requires a live `.run/s1.json`. The deny is attached in the identity account and matches every session of `PaymentReconcilerRole` issued before T, not only S1. The next read is the payment object in the other account. The action in the lab policy is only `s3:GetObject`.

`EXIT` deletes `lab-token-issue-deny`. If the process is killed before the trap runs, delete that inline policy before reading the result of a later `GetObject`.

## Out of scope

- AWS Private CA
- CDP, including the documented delay of up to 30 minutes after publication
- OCSP
- a trust anchor in the payment or inventory account
- a trust anchor set to the root
- an empty subject (Roles Anywhere rejects it, including a SPIFFE X.509-SVID left in that shape)

## Failures

| Symptom | Check |
| --- | --- |
| Vault never becomes ready | Docker is up. `docker compose -f docker-compose.yml logs` |
| `aws` rejects the CA file | `./demo.sh up` again. `issuing-ca.pem` must be one CA certificate, `CA:TRUE`, key usage Certificate Sign, `CN=lab-issuing.example`. |
| `CreateSession` denied before revoke | The profile lists that role. `aws:SourceArn` is this trust anchor. The cert has the expected CN and `OU=production`. An old CRL named `ra-lab-crl` was signed by a previous issuing key. `run` deletes that CRL before S1. |
| S1 is denied `payment-reconciler/input.json` | Payment bucket policy must allow `PaymentReconcilerRole`. The identity policy must allow that bucket. The session policy must allow that prefix. |
| S1 can read the inventory object | Inventory bucket policy grants `PaymentReconcilerRole`, or the session policy was replaced. The lab policy grants only `InventoryWorkerRole`. |
| The three account IDs are not distinct | `accounts.env` points two names at one account. |
| A new session is still issued after import | CRL enabled on this trust anchor, and `.run/crl.txt` contains the serial. |
| S1 is `AccessDenied` before `contain` | Inline policy `lab-token-issue-deny` left on the role. Delete it. |
| macOS blocks the helper | The script removes `com.apple.quarantine`. If Gatekeeper still blocks it, allow `bin/aws_signing_helper`. |
| Region error at the start of `run` | `AWS_REGION` and the Terraform output differ. Run `aws` and `run` in the same region. |

`CreateSession` quota is per Region and adjustable. The User Guide and the General Reference do not currently list the same default. Use the applied value in Service Quotas.
