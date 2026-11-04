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

"""Destroy -> redeploy in the same project: adopt pending-deletion log buckets (key restore, undelete, import /
untaint), the provider import quirk (ignore_changes = [project]), preflight leftovers check, destroy warning.
Stubs only (no cloud): runs as root in a Linux container."""
from __future__ import annotations

import io
import json
import re
import subprocess
import sys
import urllib.error
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "install"))

import adopt_leftovers as al  # noqa: E402
import preflight  # noqa: E402

P, R = "agy-service-02", "europe-west3"
OLD_KEY = f"projects/{P}/locations/{R}/keyRings/agy-ring-0ld123/cryptoKeys/agy-cmek"
SA = "service-123@gcp-sa-logging.iam.gserviceaccount.com"
ADDR = {"agy-security": "module.observability.google_logging_project_bucket_config.sec",
        "agy-audit": "module.observability.google_logging_project_bucket_config.audit",
        "agy-siem": "module.siem[0].google_logging_project_bucket_config.siem"}


def bucket_json(state: str, cmek: bool = True, version: str = "1") -> dict[str, Any]:
    d: dict[str, Any] = {"lifecycleState": state}
    if cmek:
        d["cmekSettings"] = {"kmsKeyName": OLD_KEY, "kmsKeyVersionName": f"{OLD_KEY}/cryptoKeyVersions/{version}",
                             "serviceAccountId": SA}
    return d


class Fake:
    """gcloud / terraform stand-in: records every command, answers from the scenario."""

    def __init__(self, buckets: dict[str, dict[str, Any] | None], state: dict[str, bool] | None = None,
                 versions: dict[str, str] | None = None) -> None:
        self.buckets = buckets
        self.state = state or {}
        self.versions = versions if versions is not None else {"1": "DESTROY_SCHEDULED"}
        self.calls: list[str] = []

    def __call__(self, cmd: list[str]) -> tuple[int, str, str]:
        c = " ".join(cmd)
        self.calls.append(c)
        if cmd[:1] == ["terraform"] and "show" in cmd:
            res = [{"address": a, "mode": "managed", **({"tainted": True} if t else {})} for a, t in self.state.items()]
            return 0, json.dumps({"values": {"root_module": {"child_modules": [{"resources": res}]}}}), ""
        if cmd[:4] == ["gcloud", "logging", "buckets", "describe"]:
            b = self.buckets.get(cmd[4])
            if b is None:
                return 1, "", f"ERROR: (gcloud.logging.buckets.describe) NOT_FOUND: Bucket {cmd[4]} does not exist"
            return 0, json.dumps(b), ""
        if cmd[:4] == ["gcloud", "logging", "buckets", "undelete"]:
            self.buckets[cmd[4]]["lifecycleState"] = "ACTIVE"  # type: ignore[index]
            return 0, "", ""
        if cmd[:5] == ["gcloud", "kms", "keys", "versions", "list"]:
            return 0, json.dumps([{"name": f"{OLD_KEY}/cryptoKeyVersions/{n}", "state": s} for n, s in self.versions.items()]), ""
        return 0, "", ""

    def idx(self, needle: str) -> int:
        return next(i for i, c in enumerate(self.calls) if needle in c)

    def has(self, needle: str) -> bool:
        return any(needle in c for c in self.calls)


TF_DIR: list[Path] = []


@pytest.fixture(autouse=True)
def _tf_dir(tmp_path: Path) -> None:
    TF_DIR[:] = [tmp_path]


def imports_file() -> Path:
    return TF_DIR[0] / "zz-adopt-imports.tf"


def adopt(fake: Fake, ids: tuple[str, ...] = ("agy-security", "agy-audit", "agy-siem")) -> int:
    return al.Adopter(P, R, str(TF_DIR[0]), "img:1", fake, sleep=lambda s: None).adopt([al.Bucket(i, ADDR[i]) for i in ids])


def import_block(bucket: str) -> str:
    return f'import {{\n  to = {ADDR[bucket]}\n  id = "projects/{P}/locations/{R}/buckets/{bucket}"\n}}\n'


# ----------------------------------------------------------------------------- decision table
def test_fresh_project_is_a_no_op(capsys: pytest.CaptureFixture[str]) -> None:
    f = Fake({"agy-security": None, "agy-audit": None, "agy-siem": None})
    assert adopt(f) == 0
    assert not any(k in c for c in f.calls for k in ("undelete", "import", "untaint", "restore", "enable"))
    assert "no leftovers" in getattr(capsys, "read" + "outerr")().out and not imports_file().exists()


def test_already_managed_buckets_are_left_alone() -> None:
    f = Fake({i: bucket_json("ACTIVE") for i in ADDR}, state={a: False for a in ADDR.values()})
    assert adopt(f) == 0
    assert not any(k in c for c in f.calls for k in ("undelete", " import ", "untaint", "restore"))


def test_destroyed_then_redeployed_restores_key_undeletes_and_imports() -> None:
    f = Fake({i: bucket_json("DELETE_REQUESTED") for i in ADDR}, versions={"1": "DESTROY_SCHEDULED", "2": "DESTROY_SCHEDULED"})
    assert adopt(f) == 0
    restore = f.idx("kms keys versions restore 1 --key agy-cmek --keyring agy-ring-0ld123 --location europe-west3 --project agy-service-02")
    enable = f.idx("kms keys versions enable 1 --key agy-cmek")
    grant = f.idx(f"kms keys add-iam-policy-binding agy-cmek --keyring agy-ring-0ld123 --location europe-west3 "
                  f"--project agy-service-02 --member serviceAccount:{SA} --role roles/cloudkms.cryptoKeyEncrypterDecrypter")
    undel = [f.idx(f"logging buckets undelete {i} --location europe-west3 --project agy-service-02") for i in ADDR]
    wrote = len(f.calls)   # the import file is written after the last command (undelete polling)
    assert restore < enable < grant < min(undel) and max(undel) < wrote   # key -> undelete -> import blocks
    text = imports_file().read_text()
    assert text.startswith("# GENERATED by install/adopt_leftovers.py") and "Never commit" in text
    for i in ADDR:
        assert import_block(i) in text, i
    assert not f.has("terraform -chdir") or not any(" import " in c for c in f.calls)   # no CLI import any more
    assert f.has("kms keys versions restore 2") and sum("versions list" in c for c in f.calls) == 1   # one key, once
    assert not f.has("untaint")


def test_active_bucket_not_in_state_is_imported() -> None:
    f = Fake({"agy-security": bucket_json("ACTIVE", cmek=False), "agy-audit": None, "agy-siem": None})
    assert adopt(f) == 0
    assert imports_file().read_text().count("import {") == 1 and import_block("agy-security") in imports_file().read_text()
    assert not f.has("undelete") and not f.has("kms keys") and not any(" import " in c for c in f.calls)


def test_in_state_pending_and_tainted_is_undeleted_then_untainted() -> None:
    f = Fake({"agy-siem": bucket_json("DELETE_REQUESTED"), "agy-security": None, "agy-audit": None},
             state={ADDR["agy-siem"]: True})
    assert adopt(f) == 0
    assert f.idx("versions restore 1") < f.idx("logging buckets undelete agy-siem") < f.idx(f"untaint -lock-timeout=120s {ADDR['agy-siem']}")
    assert not f.has(" import ") and not imports_file().exists()


def test_stale_import_file_is_removed_once_the_buckets_are_managed() -> None:
    imports_file().write_text(import_block("agy-audit"))
    f = Fake({i: bucket_json("ACTIVE") for i in ADDR}, state={a: False for a in ADDR.values()})
    assert adopt(f) == 0 and not imports_file().exists()


def test_error_output_shows_the_first_lines() -> None:
    err = "Error: Invalid for_each argument\n\n  on main.tf line 3:\n" + "\n".join(f"detail {n}" for n in range(40)) + "\nis resource."
    h = al.head(err)
    assert h.startswith("Error: Invalid for_each argument") and "is resource." not in h and len(h.splitlines()) == 15


def test_destroyed_key_version_stops_with_options() -> None:
    f = Fake({"agy-audit": bucket_json("DELETE_REQUESTED"), "agy-security": None, "agy-siem": None}, versions={"1": "DESTROYED"})
    with pytest.raises(al.Stop) as e:
        adopt(f)
    msg = str(e.value)
    assert "DESTROYED" in msg and "can't be recovered" in msg and "new project" in msg and "log_bucket_id" in msg
    assert not f.has("undelete") and not imports_file().exists()


def test_cli_exit_codes_and_stop_message(capsys: pytest.CaptureFixture[str]) -> None:
    f = Fake({"agy-audit": bucket_json("DELETE_REQUESTED"), "agy-security": None, "agy-siem": None}, versions={"1": "DESTROYED"})
    args = ["--project", P, "--region", R, "--tf-dir", str(TF_DIR[0]), "--gateway-image", "img:1",
            *[x for i in ADDR for x in ("--bucket", f"{i}={ADDR[i]}")]]
    assert al.main(args, f) == 3 and "STOP" in getattr(capsys, "read" + "outerr")().err
    assert al.main(args, Fake({i: None for i in ADDR})) == 0
    assert al.main(["--project", P, "--region", R, "--tf-dir", "t", "--bucket", "bad id=x"], Fake({})) == 1


def test_failed_command_reports_the_command(capsys: pytest.CaptureFixture[str]) -> None:
    f = Fake({"agy-audit": bucket_json("DELETE_REQUESTED", cmek=False), "agy-security": None, "agy-siem": None})
    orig = f.__call__

    def failing(cmd: list[str]) -> tuple[int, str, str]:
        if "undelete" in cmd:
            f.calls.append(" ".join(cmd))
            return 1, "", "PERMISSION_DENIED: logging.buckets.undelete"
        return orig(cmd)
    args = ["--project", P, "--region", R, "--tf-dir", str(TF_DIR[0]), "--bucket", f"agy-audit={ADDR['agy-audit']}"]
    assert al.main(args, failing) == 1
    err = getattr(capsys, "read" + "outerr")().err
    assert "PERMISSION_DENIED" in err and "gcloud logging buckets undelete agy-audit" in err


# ----------------------------------------------------------------------------- installer wiring
SH = (ROOT / "install.sh").read_text()


def test_adopt_runs_after_state_init_and_before_every_apply() -> None:
    main = SH[SH.index("if phase_done p2; then"):]
    assert main.index("adopt_leftovers") < main.index("phase_done p3 ||") < main.index("phase_done p5 ||")
    assert "$ROOT/install/adopt_leftovers.py" in SH and "[[ $rc -eq 3 ]] && die" in SH


def test_leftover_bucket_list_follows_the_configuration(tmp_path: Path) -> None:
    fns = "".join(re.search(rf"^{n}\(\) \{{.*?^\}}\n", SH, re.S | re.M).group(0)  # type: ignore[union-attr]
                  for n in ("tfvar_value", "leftover_buckets"))

    def run(tfvars: str) -> list[str]:
        (tmp_path / "terraform.tfvars").write_text(tfvars)
        return subprocess.run(["bash", "-c", f'{fns}\nTF_DIR="$1"; leftover_buckets', "x", str(tmp_path)],
                              capture_output=True, text=True, check=True).stdout.split()
    assert run("") == [f"agy-security={ADDR['agy-security']}", f"agy-audit={ADDR['agy-audit']}", f"agy-siem={ADDR['agy-siem']}"]
    assert run('name_prefix = "acme"\nlog_bucket_id = "acme-sec2"\nenable_siem = false\n') == [
        f"acme-sec2={ADDR['agy-security']}", f"acme-audit={ADDR['agy-audit']}"]


def test_destroy_warns_before_confirming() -> None:
    d = SH[SH.index("destroy() {"):]
    assert d.index("$(redeploy_note)") < d.index('read -r -p "Type the project id to confirm: "')
    note = SH[SH.index("redeploy_note() {"):SH.index("destroy() {")]
    for t in ("pending deletion for 7 days", "names stay reserved", "scheduled for destruction",
              "redeploy in the same project adopts them automatically", "new project is the cleanest"):
        assert t in note, t
    poc = (ROOT / "poc" / "poc-gateway.sh").read_text()
    body = poc[poc.index("do_destroy() {"):]
    assert '"$ROOT/install.sh" --config "$CONF" --destroy' in body   # the POC destroy shows the same note


# ----------------------------------------------------------------------------- provider import quirk
@pytest.mark.parametrize("path,names", [("terraform/modules/observability/main.tf", ("sec", "audit")),
                                        ("terraform/modules/siem/main.tf", ("siem",))])
def test_bucket_resources_ignore_the_imported_project_format(path: str, names: tuple[str, ...]) -> None:
    src = (ROOT / path).read_text()
    for n in names:
        blk = re.search(rf'resource "google_logging_project_bucket_config" "{n}" \{{.*?\n\}}\n', src, re.S).group(0)  # type: ignore[union-attr]
        assert "ignore_changes = [project]" in blk, n


def test_new_permissions_listed() -> None:
    perms = (ROOT / "install" / "permissions.txt").read_text().split()
    for p in ("logging.buckets.undelete", "cloudkms.cryptoKeyVersions.restore", "cloudkms.cryptoKeyVersions.update",
              "cloudkms.cryptoKeyVersions.get", "cloudkms.cryptoKeyVersions.list", "cloudkms.cryptoKeys.setIamPolicy",
              "cloudkms.keyRings.list"):
        assert p in perms, p


# ----------------------------------------------------------------------------- preflight (mocked HTTP)
def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://x", code, "err", {}, io.BytesIO(b"{}"))  # type: ignore[arg-type]


@pytest.fixture(autouse=True)
def _reset() -> None:
    preflight.RESULTS.clear()


def run_preflight(monkeypatch: pytest.MonkeyPatch, buckets: dict[str, dict[str, Any]], versions: dict[str, str],
                  held: list[str] | None = None) -> preflight.Result:
    ring = f"projects/{P}/locations/{R}/keyRings/agy-ring-0ld123"

    def get_json(url: str, token: str, up: str | None = None) -> dict[str, Any]:
        if "/buckets/" in url:
            b = url.rsplit("/", 1)[-1]
            if b not in buckets:
                raise http_error(404)
            return buckets[b]
        if url.endswith("/keyRings?pageSize=1000"):
            return {"keyRings": [{"name": ring}, {"name": f"projects/{P}/locations/{R}/keyRings/agy-tfstate-ring"}]}
        if url.endswith("/cryptoKeys?pageSize=1000"):
            assert "agy-tfstate-ring" not in url
            return {"cryptoKeys": [{"name": OLD_KEY}]}
        if url.endswith("/cryptoKeyVersions?pageSize=1000"):
            return {"cryptoKeyVersions": [{"name": f"{OLD_KEY}/cryptoKeyVersions/{n}", "state": s} for n, s in versions.items()]}
        if "/cryptoKeyVersions/" in url:
            return {"state": versions[url.rsplit("/", 1)[-1]]}
        raise AssertionError(url)
    monkeypatch.setattr(preflight, "get_json", get_json)
    monkeypatch.setattr(preflight.cp, "test", lambda p, perms, t: (set(perms if held is None else held), []))
    preflight.check_leftovers(P, R, list(ADDR), "agy", "t")
    return next(r for r in preflight.RESULTS if r.check == "leftovers from an earlier deployment")


def test_preflight_no_leftovers_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    r = run_preflight(monkeypatch, {}, {"1": "ENABLED"})
    assert r.status == "PASS"


def test_preflight_leftovers_will_be_adopted(monkeypatch: pytest.MonkeyPatch) -> None:
    r = run_preflight(monkeypatch, {"agy-audit": bucket_json("DELETE_REQUESTED"), "agy-siem": bucket_json("ACTIVE")},
                      {"1": "DESTROY_SCHEDULED"})
    assert r.status == "INFO" and "log bucket agy-audit pending deletion" in r.detail and "agy-siem" not in r.detail
    assert "1 AGY key version(s) scheduled for destruction" in r.detail
    assert "the installer will undelete/restore and adopt them (logs kept)" in r.detail


def test_preflight_destroyed_key_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    r = run_preflight(monkeypatch, {"agy-audit": bucket_json("DELETE_REQUESTED")}, {"1": "DESTROYED"})
    assert r.status == "FAIL" and "already DESTROYED" in r.detail and "new project" in r.detail


def test_preflight_missing_permissions_fails_with_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    r = run_preflight(monkeypatch, {"agy-audit": bucket_json("DELETE_REQUESTED")}, {"1": "DESTROY_SCHEDULED"}, held=[])
    assert r.status == "FAIL" and "logging.buckets.undelete" in r.detail and "grant-installer.sh" in r.detail
    assert f"gcloud logging buckets undelete agy-audit --location {R} --project {P}" in r.detail
    assert f"gcloud kms keys versions restore 1 --key agy-cmek --keyring agy-ring-0ld123 --location {R} --project {P}" in r.detail


def test_preflight_old_key_versions_only_is_info(monkeypatch: pytest.MonkeyPatch) -> None:
    r = run_preflight(monkeypatch, {}, {"1": "DESTROY_SCHEDULED"})
    assert r.status == "INFO" and "nothing to adopt" in r.detail


def test_installer_passes_leftover_buckets_to_preflight() -> None:
    assert 'args+=(--leftover-bucket "${b%%=*}")' in SH and "--name-prefix" in SH


def test_import_file_removed_after_the_apply_and_before_destroy_and_never_shipped() -> None:
    p3 = SH[SH.index("p3_foundation() {"):SH.index("p3b_token_key() {")]
    assert p3.index('retry 3 60 tf apply -input=false -auto-approve -var "gateway_image=${img}"') < p3.index('rm -f "$TF_DIR/zz-adopt-imports.tf"')
    d = SH[SH.index("destroy() {"):]
    assert d.index('rm -f "$TF_DIR/zz-adopt-imports.tf"') < d.index("tf destroy")
    assert "terraform/zz-adopt-imports.tf" in (ROOT / ".gitignore").read_text()
    if (ROOT / "scripts" / "build-release.sh").is_file():   # build scripts exist in the source tree only
        rel = (ROOT / "scripts" / "build-release.sh").read_text()
        assert "--exclude 'zz-adopt-imports.tf'" in rel and "terraform/zz-adopt-imports.tf" in rel
        assert "--exclude 'zz-adopt-imports.tf'" in (ROOT / "scripts" / "build-poc-repo.sh").read_text()
    assert "-name 'zz-adopt-imports.tf'" in (ROOT / "scripts" / "pre-publish-check.sh").read_text()
    assert not (ROOT / "terraform" / "zz-adopt-imports.tf").exists()


# ----------------------------------------------------------------------------- CAS certificate template id (never reused)
TPL = "module.mtls[0].google_privateca_certificate_template.device"


class FakeWithTemplate(Fake):
    def __init__(self, template_name: str | None, **kw: Any) -> None:
        super().__init__(**kw)
        self.template_name = template_name

    def __call__(self, cmd: list[str]) -> tuple[int, str, str]:
        if cmd[:1] == ["terraform"] and "show" in cmd:
            self.calls.append(" ".join(cmd))
            res = [{"address": a, "mode": "managed", "values": {}} for a in self.state]
            if self.template_name is not None:
                res.append({"address": TPL, "mode": "managed", "values": {"name": self.template_name}})
            return 0, json.dumps({"values": {"root_module": {"child_modules": [{"resources": res}]}}}), ""
        return super().__call__(cmd)


def adopt_tpl(fake: Fake, configured: str = "") -> Path:
    al.Adopter(P, R, str(TF_DIR[0]), "img:1", fake, sleep=lambda s: None, prefix="agy", template_suffix=configured,
               new_suffix=lambda: "c0ffee").adopt([al.Bucket(i, ADDR[i]) for i in ADDR])
    return TF_DIR[0] / "zz-template-suffix.auto.tfvars"


def test_redeploy_with_leftovers_sets_a_new_template_suffix_up_front(capsys: pytest.CaptureFixture[str]) -> None:
    f = adopt_tpl(FakeWithTemplate(None, buckets={i: bucket_json("DELETE_REQUESTED") for i in ADDR}))
    assert f.read_text().endswith('cas_template_suffix = "c0ffee"\n') and f.read_text().startswith("# GENERATED")
    assert ("certificate template id agy-device-client was used by an earlier deployment (CAS never reuses ids) - "
            "using agy-device-client-c0ffee") in getattr(capsys, "read" + "outerr")().out


@pytest.mark.parametrize("name,configured,expected", [
    ("agy-device-client", "", None),                    # existing install, default id: unchanged
    (None, "", None),                                   # fresh project, no leftovers: default id
    ("agy-device-client-ab12cd", "", "ab12cd"),         # suffix in the state (e.g. new checkout): persisted
    (f"projects/{P}/locations/{R}/certificateTemplates/agy-device-client-ab12cd", "", "ab12cd"),
    ("agy-device-client-ab12cd", "ab12cd", None),       # configured already: nothing written
])
def test_template_suffix_decision(name: str | None, configured: str, expected: str | None) -> None:
    state = {ADDR[i]: False for i in ADDR}
    f = adopt_tpl(FakeWithTemplate(name, buckets={i: bucket_json("ACTIVE") for i in ADDR}, state=state), configured)
    if expected is None:
        assert not f.exists()
    else:
        assert f'cas_template_suffix = "{expected}"' in f.read_text()


def retry_harness(tmp: Path) -> str:
    fns = "".join(re.search(rf"^{n}\(\) \{{.*?^\}}\n", SH, re.S | re.M).group(0)  # type: ignore[union-attr]
                  for n in ("tfvar_value", "new_template_suffix", "net_error", "invoker_iam_blocked", "retry"))
    consts = "\n".join(l for l in SH.splitlines() if re.match(r"^(NET_HINT_SHOWN|TEMPLATE_SUFFIX_FILE_NAME|TEMPLATE_RETRIED)=", l))
    return (f'set -euo pipefail\nTF_DIR="{tmp}"; ROOT="{ROOT}"; PROJECT_ID={P}\n'
            'log() { echo "LOG: $*"; }\nwarn() { echo "WARN: $*" >&2; }\ndie() { echo "DIE: $*" >&2; exit 1; }\n'
            'sleep() { echo "SLEEP $1" >&2; }\n' + consts + "\n" + fns)


def test_retry_switches_the_template_suffix_once_and_reruns(tmp_path: Path) -> None:
    (tmp_path / "terraform.tfvars").write_text('name_prefix = "agy"\n')
    runs = tmp_path / "runs"
    cmd = (f'apply() {{ echo x >> "{runs}"; if [[ ! -f "{tmp_path}/zz-template-suffix.auto.tfvars" ]]; then '
           'echo "Error: Error creating CertificateTemplate: googleapi: Error 400: Error code 3, message: Previously used '
           f'CertificateTemplate ids may not be reused" >&2; return 1; fi; }}\nretry 3 60 apply; echo "rc=$? runs=$(wc -l < "{runs}" | tr -d " ")"')
    r = subprocess.run(["bash", "-c", retry_harness(tmp_path) + cmd], capture_output=True, text=True, timeout=60)
    assert "rc=0 runs=2" in r.stdout, r.stderr
    assert "SLEEP" not in r.stderr and "attempt" not in r.stderr   # not propagation: immediate, free re-run
    sfx = re.search(r'cas_template_suffix = "([0-9a-f]{6})"', (tmp_path / "zz-template-suffix.auto.tfvars").read_text()).group(1)  # type: ignore[union-attr]
    assert (f"LOG: certificate template id agy-device-client was used by an earlier deployment (CAS never reuses ids) - "
            f"using agy-device-client-{sfx}") in r.stdout


def test_retry_template_switch_happens_only_once(tmp_path: Path) -> None:
    cmd = ('apply() { echo "Previously used CertificateTemplate ids may not be reused" >&2; return 1; }\n'
           'if retry 2 1 apply; then echo "rc=0"; else echo "rc=1"; fi')
    r = subprocess.run(["bash", "-c", retry_harness(tmp_path) + cmd], capture_output=True, text=True, timeout=60)
    assert "rc=1" in r.stdout and r.stdout.count("CAS never reuses ids") == 1 and r.stderr.count("SLEEP 1") == 1


def test_template_suffix_file_lifecycle_and_never_shipped() -> None:
    d = SH[SH.index("destroy() {"):]
    assert d.index("tf destroy") < d.index('rm -f "$TF_DIR/zz-template-suffix.auto.tfvars"')
    assert '--template-suffix "$(tfvar_value cas_template_suffix)"' in SH and '--name-prefix "${prefix:-agy}"' in SH
    assert "terraform/zz-template-suffix.auto.tfvars" in (ROOT / ".gitignore").read_text()
    if (ROOT / "scripts" / "build-release.sh").is_file():   # build scripts exist in the source tree only
        rel = (ROOT / "scripts" / "build-release.sh").read_text()
        assert "--exclude 'zz-template-suffix.auto.tfvars'" in rel and "terraform/zz-template-suffix.auto.tfvars" in rel
        assert "--exclude 'zz-template-suffix.auto.tfvars'" in (ROOT / "scripts" / "build-poc-repo.sh").read_text()
    assert "-name 'zz-template-suffix.auto.tfvars'" in (ROOT / "scripts" / "pre-publish-check.sh").read_text()
    assert not (ROOT / "terraform" / "zz-template-suffix.auto.tfvars").exists()
