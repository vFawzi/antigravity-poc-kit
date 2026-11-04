#!/usr/bin/env bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Pre-publish check: fail if secrets, state, environment-specific identifiers or binaries are present.
# Usage: scripts/pre-publish-check.sh [path]   (default: repository root)
set -uo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT" || exit 2
FAIL=0
hit() { echo "  ✗ $1"; FAIL=1; }

echo "== forbidden files"
while IFS= read -r f; do hit "$f"; done < <(find . \( -name '*.tfstate' -o -name '*.tfstate.*' -o -name 'terraform.tfvars' -o -name 'zz-adopt-imports.tf' -o -name 'zz-template-suffix.auto.tfvars' -o -name '.terraform' \
  -o -name '.venv' -o -name '__pycache__' -o -name '.pytest_cache' -o -name '.crd-pin-*' -o -name '*.pem' -o -name '*.key' \
  -o -name '*.p12' -o -name '*.tgz' -o -name '*.tar.gz' -o -name '*.deb' -o -name '.env' -o -name 'credentials*.json' \
  -o -name '*service-account*.json' -o -iname '*.docx' -o -iname '*.doc' -o -iname '*.xlsx' -o -iname '*.xls' \
  -o -iname '*.pptx' -o -iname '*.ppt' -o -iname '*.pdf' -o -iname '*.odt' -o -iname '*.key' -o -iname '*.numbers' \
  -o -iname '*.pages' -o -iname '*.zip' -o -iname '*.png' -o -iname '*.jpg' -o -iname '*.csv' \) -not -path './.git/*' 2>/dev/null)

echo "== secret patterns"
PATTERNS='-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|AIza[0-9A-Za-z_\-]{35}|ya29\.[0-9A-Za-z_\-]+|"private_key"\s*:|AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{36}|xox[baprs]-[0-9A-Za-z-]+|eyJhbGciOi[0-9A-Za-z_\-]{20,}\.'
grep -rIEn --exclude-dir=.git --exclude=pre-publish-check.sh -e "$PATTERNS" . && FAIL=1 || echo "  ✓ none"

echo "== environment-specific identifiers (set DENYLIST to your own project ids, domains, emails)"
if [[ -z "${DENYLIST:-}" ]]; then
  echo "  ! DENYLIST not set - export DENYLIST='your-project-id|your-domain\.com|...' and re-run"
else
  grep -rIEn --exclude-dir=.git --exclude=pre-publish-check.sh -e "$DENYLIST" . && FAIL=1 || echo "  ✓ none"
fi

echo "== binary or large files (>512 KB)"
while IFS= read -r f; do hit "$f"; done < <(find . -type f -size +512k -not -path './.git/*')
while IFS= read -r f; do grep -Iq . "$f" 2>/dev/null || hit "binary: $f"; done < <(find . -type f -size +0 -not -path './.git/*')

[[ $FAIL -eq 0 ]] && echo "PASS: ready to publish" || { echo "FAIL: fix the items above before publishing"; exit 1; }
