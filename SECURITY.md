# Security policy

## Supported versions
| Version | Supported |
|---|---|
| Latest minor release (`1.8.x`) | ✅ security fixes |
| Previous minor release | ✅ critical fixes for 90 days after a new minor release |
| Older | ❌ upgrade |

## Reporting a vulnerability
**Do not open a public issue.** Report privately via GitHub *Security advisories → Report a vulnerability* on this
repository, or contact the repository owners directly. Include the affected component and version, reproduction steps,
impact and any proposed fix.

| Severity (CVSS v3.1) | Acknowledgement | Fix or mitigation target |
|---|---|---|
| Critical (9.0–10) | 2 business days | 7 days |
| High (7.0–8.9) | 5 business days | 30 days |
| Medium / Low | 10 business days | next minor release |

We coordinate disclosure with the reporter and credit them in the release notes unless they prefer otherwise.

## Supply chain
- Releases are signed tags `vX.Y.Z`; the release tarball is published with `SHA256SUMS`. Verify both before use.
- The CI pipeline (`cloudbuild-ci.yaml`) runs secret scanning, licence checks, Python lint/SAST/tests, dependency
  audit, shell analysis and Terraform validation / policy checks on every change.
- Dependencies are pinned (`gateway/requirements.txt`, `terraform/.terraform.lock.hcl`); Dependabot alerts are enabled.

## Handling secrets
- Never commit `terraform.tfvars`, `install.conf`, Terraform state, keys, certificates or credentials (see `.gitignore`).
- Runtime secrets are created in Secret Manager by Terraform; device keys are generated on the device.
- Use a remote, encrypted, access-controlled Terraform backend (GCS + CMEK + versioning + IAM); the installer creates one.
- Run `DENYLIST='<your ids>' scripts/pre-publish-check.sh` before every push.

## Scope and limitations
This is a reference implementation, not an officially supported product. See `docs/ARCHITECTURE.md` for the threat
model, residual risks, known product limitations and production considerations.
