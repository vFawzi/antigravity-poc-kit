# Contributing

Thank you for helping improve this reference implementation.

## Ground rules
- **Security first.** Changes must keep least privilege (no basic roles), private networking (no public IPs; administrative access via IAP), EU data residency, CMEK on stored data and audit logging. Explain any deviation in the pull request.
- **No secrets or environment identifiers.** Never commit tfvars, Terraform state, keys, certificates, credentials, project IDs, domains or e-mail addresses. Run `DENYLIST='<your ids>' scripts/pre-publish-check.sh` before pushing.
- **Signed commits.** Commits and tags must be signed (SSH or GPG) and show as *Verified*.

## Workflow
1. Open an issue describing the change (for security issues see [SECURITY.md](SECURITY.md) - do not open a public issue).
2. Branch from `main`; keep pull requests small and focused.
3. Run locally before opening the pull request:
   ```bash
   make test                                   # unit tests + syntax checks
   python3 scripts/license_headers.py --check  # licence headers
   (cd terraform && terraform fmt -check -recursive && terraform validate)
   ```
4. Open a pull request using the template. The Cloud Build CI pipeline (`cloudbuild-ci.yaml`) must pass.
5. A code owner reviews. Changes to IAM, network exposure, evidence handling, endpoint hardening or the client modes need a reviewer from the security owners (see [CODEOWNERS](CODEOWNERS)).
6. Squash-merge; the pull request title becomes the commit message.

## Releases
Releases follow [Semantic Versioning](https://semver.org/). Each release is a signed tag `vX.Y.Z` with a changelog entry, the release tarball and its `SHA256SUMS`, built from the allowlist packaging and validated end to end (gateway and seat client modes) on clean projects.

## Code style
- Python: typed (PEP 484), `ruff` clean, tests with `pytest`.
- Shell: `bash` with `set -euo pipefail`, `shellcheck` clean.
- Terraform: modular, no hardcoded environment values, mandatory labels, `terraform fmt`.
- Every source file carries the Apache-2.0 header (`python3 scripts/license_headers.py` adds it).

## Licence
By contributing you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
