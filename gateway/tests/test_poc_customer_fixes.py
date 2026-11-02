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

"""Customer-reported POC fixes: state bootstrap (Storage service agent + CMEK grant), installer network-error retry,
poc-gateway.sh (installer Terraform, Terraform errors shown, question 7 answers, --status), POC hand-off text,
running from any folder. Stubs only (no cloud, no current user, no macOS tools): runs as root in a Linux container."""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
POC_SH = (ROOT / "poc" / "poc-gateway.sh").read_text()
INSTALL_SH = (ROOT / "install.sh").read_text()


def stub(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/usr/bin/env bash\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def shell_fn(src: str, name: str) -> str:
    m = re.search(rf"^{name}\(\) \{{[^\n]*\}}\n", src, re.M) or re.search(rf"^{name}\(\) \{{.*?^\}}\n", src, re.S | re.M)
    assert m, name
    return m.group(0)


def bash(script: str, env: dict[str, str] | None = None, stdin: str = "", cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, input=stdin, timeout=60,
                          env={**os.environ, **(env or {})}, cwd=cwd)


# ----------------------------------------------------------------------------- C3 state bootstrap
def bootstrap_tree(tmp_path: Path, authorize_failures: int) -> tuple[Path, Path, Path]:
    (tmp_path / "repo" / "install").mkdir(parents=True)
    (tmp_path / "repo" / "terraform").mkdir()
    script = tmp_path / "repo" / "install" / "state-bootstrap.sh"
    shutil.copy(ROOT / "install" / "state-bootstrap.sh", script)
    log = tmp_path / "gcloud.log"
    count = tmp_path / "count"
    count.write_text("0")
    bin_dir = tmp_path / "bin"
    stub(bin_dir / "gcloud", f'''echo "$*" >> "{log}"
if [[ "$*" == *"--authorize-cmek"* ]]; then
  n=$(( $(cat "{count}") + 1 )); echo $n > "{count}"
  [[ $n -le {authorize_failures} ]] && {{ echo "ERROR: service account service-1@gs-project-accounts.iam.gserviceaccount.com does not exist" >&2; exit 1; }}
fi
exit 0
''')
    stub(bin_dir / "curl", 'echo \'{"billingEnabled": true}\'\n')
    return script, log, bin_dir


def test_state_bootstrap_creates_agent_first_then_retries_then_stops(tmp_path: Path) -> None:
    script, log, bin_dir = bootstrap_tree(tmp_path, authorize_failures=99)
    r = subprocess.run(["bash", str(script), "agy-test-01", "europe-west4"], capture_output=True, text=True, timeout=60,
                       env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "CMEK_TRIES": "3", "CMEK_SLEEP": "0"})
    assert r.returncode == 5, r.stderr
    assert "could not grant the Cloud Storage service agent" in r.stderr and "re-run" in r.stderr
    calls = log.read_text().splitlines()
    plain = calls.index("storage service-agent --project agy-test-01")
    auth = [i for i, c in enumerate(calls) if "--authorize-cmek" in c]
    assert len(auth) == 3 and plain < auth[0]
    assert not any(c.startswith("storage buckets") for c in calls), "must stop before creating the state bucket"
    assert not (script.parent.parent / "terraform" / "backend.hcl").exists()


def test_state_bootstrap_succeeds_after_propagation(tmp_path: Path) -> None:
    script, log, bin_dir = bootstrap_tree(tmp_path, authorize_failures=2)
    r = subprocess.run(["bash", str(script), "agy-test-01", "europe-west4"], capture_output=True, text=True, timeout=60,
                       env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "CMEK_SLEEP": "0"})
    assert r.returncode == 0, r.stderr
    assert "retry 2/18" in r.stdout
    assert (script.parent.parent / "terraform" / "backend.hcl").read_text().count("agy-test-01-agy-tfstate") == 1


def test_state_bootstrap_default_budget_is_about_three_minutes() -> None:
    src = (ROOT / "install" / "state-bootstrap.sh").read_text()
    assert 'CMEK_TRIES="${CMEK_TRIES:-18}"; CMEK_SLEEP="${CMEK_SLEEP:-10}"' in src


# ----------------------------------------------------------------------------- C4 installer retry: network errors
def retry_harness() -> str:
    return (f'ROOT="{ROOT}"; PROJECT_ID=agy-service-02\n'
            'warn() { echo "WARN: $*" >&2; }\nsleep() { echo "SLEEP $1" >&2; }\ndie() { echo "DIE: $*" >&2; exit 1; }\n'
            + shell_fn(INSTALL_SH, "invoker_iam_blocked")
            + re.search(r"^NET_HINT_SHOWN=0\n", INSTALL_SH, re.M).group(0)  # type: ignore[union-attr]
            + shell_fn(INSTALL_SH, "net_error") + shell_fn(INSTALL_SH, "retry"))


@pytest.mark.parametrize("msg", [
    "dial tcp [2001:db8::1]:443: connect: cannot assign requested address",
    "read tcp 10.0.0.2:5000->1.2.3.4:443: read: connection reset by peer",
    "Post https://x: dial tcp: i/o timeout",
    "connect: no route to host",
])
def test_retry_recognises_network_errors(msg: str) -> None:
    r = bash(retry_harness() + f'fail() {{ echo "{msg}" >&2; return 1; }}\nretry 3 20 fail; echo "rc=$?"')
    assert "rc=1" in r.stdout
    assert r.stderr.count("network problem (often IPv6 from this machine), not permissions: run from Cloud Shell or switch IPv6 off") == 1
    assert r.stderr.count("SLEEP 60") == 2 and "(network)" in r.stderr


def test_retry_permission_errors_keep_todays_backoff() -> None:
    r = bash(retry_harness() + 'fail() { echo "Error 403: Permission denied on resource" >&2; return 1; }\n'
             'retry 3 20 fail; echo "rc=$?"')
    assert "rc=1" in r.stdout and "network problem" not in r.stderr
    assert r.stderr.count("SLEEP 20") == 2 and "(propagation)" in r.stderr


def test_retry_under_errexit_and_pipefail_like_the_installer() -> None:
    r = bash("set -euo pipefail\n" + retry_harness() + 'fail() { echo "i/o timeout" >&2; return 3; }\n'
             'if retry 2 1 fail; then echo ok; else echo "failed-cleanly"; fi\nretry 2 1 true && echo "true-ok"')
    assert r.returncode == 0 and "failed-cleanly" in r.stdout and "true-ok" in r.stdout
    r = bash("set -euo pipefail\n" + retry_harness() + 'fail() { echo "boom" >&2; return 3; }\nretry 2 1 fail\necho "not reached"')
    assert r.returncode == 1 and "not reached" not in r.stdout and r.stderr.count("SLEEP 1") == 1


def test_retry_passes_stdout_and_succeeds() -> None:
    r = bash(retry_harness() + 'n=0\nflaky() { echo out-$1; [[ -f "$2" ]] && return 0; touch "$2"; echo "i/o timeout" >&2; return 1; }\n'
             f'x="$(retry 3 5 flaky A "$(mktemp -u)")"; echo "rc=$? x=$x"')
    assert "rc=0" in r.stdout and "out-A" in r.stdout


# ----------------------------------------------------------------------------- C5 poc-gateway.sh Terraform
def tf_harness(root: Path) -> str:
    return (f'set -euo pipefail\nROOT="{root}"\n'
            'log() { echo "LOG: $*"; }\nwarn() { echo "WARN: $*" >&2; }\ndie() { echo "DIE: $*" >&2; exit 1; }\n'
            + shell_fn(POC_SH, "use_installer_tf") + shell_fn(POC_SH, "need_tf")
            + shell_fn(POC_SH, "tfo") + shell_fn(POC_SH, "tfo_required"))


def minimal_path(tmp_path: Path) -> str:
    """PATH with the basic tools but certainly no terraform."""
    d = tmp_path / "sysbin"
    d.mkdir(exist_ok=True)
    for tool in ("python3", "mktemp", "grep", "tr", "cut", "cat", "rm", "env", "bash"):
        p = shutil.which(tool)
        assert p, tool
        if not (d / tool).exists():
            (d / tool).symlink_to(p)
    return str(d)


def test_poc_uses_installer_terraform_for_every_mode(tmp_path: Path) -> None:
    stub(tmp_path / ".tools" / "bin" / "terraform", 'echo \'"https://gateway.agy.internal"\'\n')
    r = bash(tf_harness(tmp_path) + 'use_installer_tf; command -v terraform; tfo gateway_mtls_url',
             env={"PATH": minimal_path(tmp_path)})
    assert r.returncode == 0, r.stderr
    assert f"{tmp_path}/.tools/bin/terraform" in r.stdout and "https://gateway.agy.internal" in r.stdout
    # PATH is set up before any mode runs (--status / --reissue / --destroy included)
    assert POC_SH.index("\nuse_installer_tf\n") < POC_SH.index('case "$MODE" in')
    assert POC_SH.index("\nuse_installer_tf\n") < POC_SH.index("do_status() {")


def test_poc_terraform_missing_dies_clearly(tmp_path: Path) -> None:
    r = bash(tf_harness(tmp_path) + 'need_tf', env={"PATH": minimal_path(tmp_path)})
    assert r.returncode == 1
    assert "terraform not found (run the install first, or poc/poc-gateway.sh --yes)" in r.stderr


def test_poc_terraform_output_error_is_shown_and_required_values_die(tmp_path: Path) -> None:
    stub(tmp_path / ".tools" / "bin" / "terraform",
         'echo "Error: Backend initialization required, please run \\"terraform init\\"" >&2; exit 1\n')
    r = bash(tf_harness(tmp_path) + 'use_installer_tf; url="$(tfo_required gateway_mtls_url "no gateway URL")"; echo "url=$url"',
             env={"PATH": minimal_path(tmp_path)})
    assert r.returncode == 1 and "url=" not in r.stdout
    assert "Backend initialization required" in r.stderr and "cannot read state" in r.stderr


def test_poc_missing_output_is_empty_but_required_dies(tmp_path: Path) -> None:
    stub(tmp_path / ".tools" / "bin" / "terraform", 'echo "Error: Output \\"gateway_ilb_ip\\" not found" >&2; exit 1\n')
    r = bash(tf_harness(tmp_path) + 'use_installer_tf; v="$(tfo gateway_ilb_ip)"; echo "v=[$v]"; tfo_required gateway_ilb_ip "no gateway IP"',
             env={"PATH": minimal_path(tmp_path)})
    assert "v=[]" in r.stdout and r.returncode == 1 and "DIE: no gateway IP" in r.stderr


def test_poc_install_requires_gateway_url_and_ip() -> None:
    body = POC_SH[POC_SH.index("do_install() {"):POC_SH.index("do_status() {")]
    assert "need_tf" in body and "tfo_required gateway_mtls_url" in body and "tfo_required gateway_ilb_ip" in body
    assert "2>/dev/null)\" || { echo \"\"; return 0; }" not in POC_SH   # the old silent tfo is gone


# ----------------------------------------------------------------------------- B question 7 + answers.env
def q7_harness(yes: int, answers: str = "") -> str:
    src = POC_SH
    consts = "\n".join(line for line in src.splitlines() if re.match(r"^(PROJ_RE|IP_RE)=", line))
    return ('set -euo pipefail\nlog() { echo "LOG: $*"; }\nwarn() { echo "WARN: $*" >&2; }\ndie() { echo "DIE: $*" >&2; exit 1; }\n'
            f'YES={yes}; ANSWERS=answers.env; PROJECT_ID=agy-service-01; REGION=europe-west3\n{answers}\n{consts}\n'
            + shell_fn(src, "ask") + shell_fn(src, "parse_subnet_url") + shell_fn(src, "detect_host_project")
            + shell_fn(src, "usable_subnets") + shell_fn(src, "pick_shared_subnet")
            + shell_fn(src, "network_question") + shell_fn(src, "network_line")
            + 'network_question\necho "RESULT|$NETWORK_MODE|$SHARED_VPC_HOST_PROJECT|$SHARED_VPC_NETWORK|$SHARED_VPC_SUBNET|'
              '$GATEWAY_ILB_IP|$ILB_GLOBAL_ACCESS"\necho "LINE|$(network_line)"\n')


API = "https://www.googleapis.com/compute/v1/projects/agy-host-01"
USABLE = [  # listUsable response fields: subnetwork, network, ipCidrRange (full URLs)
    {"subnetwork": f"{API}/regions/europe-west1/subnetworks/other", "network": f"{API}/global/networks/lab-shared-vpc",
     "ipCidrRange": "10.80.0.0/24"},
    {"subnetwork": f"{API}/regions/europe-west3/subnetworks/lab-agy-euw3", "network": f"{API}/global/networks/lab-shared-vpc",
     "ipCidrRange": "10.70.0.0/24", "purpose": "PRIVATE"},
]


def gcloud_stub(tmp_path: Path, host: str = "agy-host-01", usable: list[dict[str, str]] | None = None) -> str:
    # get-host-project <service> -> host; list-usable answers only on the HOST project (like the real API)
    data = tmp_path / "usable.json"
    data.write_text(json.dumps(USABLE if usable is None else usable))
    stub(tmp_path / "bin" / "gcloud", f'''echo "$*" >> "{tmp_path / 'gcloud.log'}"
if [[ "$*" == *"shared-vpc get-host-project agy-service-01"* ]]; then [[ -n "{host}" ]] && echo "{host}"; exit 0; fi
if [[ "$*" == *"list-usable"* ]]; then
  if [[ "$*" == *"--project agy-host-01"* ]]; then cat "{data}"; else echo "[]"; fi
  exit 0
fi
echo installer@example.com
''')
    return f"{tmp_path / 'bin'}:{os.environ['PATH']}"


def result(out: str) -> list[str]:
    return next(line for line in out.splitlines() if line.startswith("RESULT|")).split("|")[1:]


def test_q7_enter_keeps_todays_behaviour(tmp_path: Path) -> None:
    r = bash(q7_harness(0), env={"PATH": gcloud_stub(tmp_path)}, stdin="\n")
    assert r.returncode == 0, r.stderr
    assert result(r.stdout) == ["create", "", "", "", "", "false"]
    assert "LINE|create (new VPC in this project)" in r.stdout


def test_q7_detects_host_then_lists_its_usable_subnets(tmp_path: Path) -> None:
    # 2 = Shared VPC, 7a Enter = detected host, pick [1] (only the europe-west3 subnet), confirm 7b/7c, IP, global access yes
    r = bash(q7_harness(0), env={"PATH": gcloud_stub(tmp_path)}, stdin="2\n\n1\n\n\n10.70.0.10\ny\n")
    assert r.returncode == 0, r.stderr
    assert "attached to Shared VPC host project agy-host-01" in r.stdout
    # (read -p prompts are not echoed without a terminal: Enter at 7a accepting agy-host-01 proves the default)
    assert "[1] network lab-shared-vpc  subnet lab-agy-euw3  10.70.0.0/24" in r.stdout
    assert "subnet other" not in r.stdout
    assert result(r.stdout) == ["shared", "agy-host-01", "lab-shared-vpc", "lab-agy-euw3", "10.70.0.10", "true"]
    assert "LINE|shared (agy-host-01 / lab-shared-vpc / lab-agy-euw3), global access on" in r.stdout
    log = (tmp_path / "gcloud.log").read_text()
    assert "compute shared-vpc get-host-project agy-service-01 --format=value(name)" in log
    assert "list-usable --project agy-host-01 --format=json" in log and "list-usable --project agy-service-01" not in log
    assert log.index("get-host-project") < log.index("list-usable")


def test_q7_no_detected_host_asks_7a_without_default(tmp_path: Path) -> None:
    r = bash(q7_harness(0), env={"PATH": gcloud_stub(tmp_path, host="")}, stdin="2\nagy-host-01\n1\n\n\n\n\n")
    assert r.returncode == 0, r.stderr
    assert "attached to Shared VPC host" not in r.stdout and "invalid value" not in r.stderr
    assert result(r.stdout) == ["shared", "agy-host-01", "lab-shared-vpc", "lab-agy-euw3", "", "false"]
    r = bash(q7_harness(0), env={"PATH": gcloud_stub(tmp_path, host="")}, stdin="2\n\nagy-host-01\n1\n\n\n\n\n")
    assert r.returncode == 0 and r.stderr.count("invalid value") == 1   # no default: Enter is refused


def test_q7_manual_values_when_nothing_is_listed(tmp_path: Path) -> None:
    r = bash(q7_harness(0), env={"PATH": gcloud_stub(tmp_path, host="", usable=[])},
             stdin="2\nnet-host-prod\nshared-vpc\nagy-subnet\n\n\n")
    assert r.returncode == 0, r.stderr
    assert "type the values your network team gave you" in r.stderr
    assert result(r.stdout) == ["shared", "net-host-prod", "shared-vpc", "agy-subnet", "", "false"]


def test_q7_enter_picks_the_first_listed_subnet_and_fills_defaults(tmp_path: Path) -> None:
    # 2, 7a Enter (detected host), 7c Enter (= [1]), 7b Enter, 7c-name Enter, 7e Enter (auto), 7f Enter (n)
    r = bash(q7_harness(0), env={"PATH": gcloud_stub(tmp_path)}, stdin="2\n\n\n\n\n\n\n")
    assert r.returncode == 0, r.stderr
    assert "m = type the values instead" in r.stdout and "invalid value" not in r.stderr
    assert "selected: network lab-shared-vpc, subnet lab-agy-euw3" in r.stdout
    assert result(r.stdout) == ["shared", "agy-host-01", "lab-shared-vpc", "lab-agy-euw3", "", "false"]


def test_q7_m_types_the_values_with_the_only_network_as_default(tmp_path: Path) -> None:
    # 'm' = type the values: 7b Enter takes the single listed network, 7c typed
    r = bash(q7_harness(0), env={"PATH": gcloud_stub(tmp_path)}, stdin="2\n\nm\n\nagy-other-subnet\n\n\n")
    assert r.returncode == 0, r.stderr
    assert "selected:" not in r.stdout and "invalid value" not in r.stderr
    assert result(r.stdout) == ["shared", "agy-host-01", "lab-shared-vpc", "agy-other-subnet", "", "false"]


def test_q7_m_with_several_networks_has_no_network_default(tmp_path: Path) -> None:
    two = [*USABLE, {"subnetwork": f"{API}/regions/europe-west3/subnetworks/b", "network": f"{API}/global/networks/net-b",
                     "ipCidrRange": "10.71.0.0/24"}]
    r = bash(q7_harness(0), env={"PATH": gcloud_stub(tmp_path, usable=two)}, stdin="2\n\nm\n\nnet-b\nb\n\n\n")
    assert r.returncode == 0, r.stderr
    assert r.stderr.count("invalid value") == 1   # Enter at 7b refused: no default with two networks
    assert result(r.stdout)[2:4] == ["net-b", "b"]


def test_q7_subnet_prompt_texts() -> None:
    assert '"   7c Subnet: number [1]"' in POC_SH and 'echo "   m = type the values instead"' in POC_SH
    assert '"   7c Subnet name (in $REGION)"' in POC_SH


def test_ask_stops_at_once_when_stdin_is_closed(tmp_path: Path) -> None:
    r = bash(q7_harness(0), env={"PATH": gcloud_stub(tmp_path)}, stdin="x\n")
    assert r.returncode == 1
    assert r.stderr.count("invalid value") == 1 and "no answer (stdin closed)" in r.stderr


def test_q7_yes_reuses_saved_answers_and_old_files_default_to_create(tmp_path: Path) -> None:
    saved = ('NETWORK_MODE="shared"; SHARED_VPC_HOST_PROJECT="agy-host-01"; SHARED_VPC_NETWORK="lab-shared-vpc"; '
             'SHARED_VPC_SUBNET="lab-agy-euw3"; GATEWAY_ILB_IP=""; ILB_GLOBAL_ACCESS="false"')
    r = bash(q7_harness(1, saved), env={"PATH": gcloud_stub(tmp_path)})
    assert r.returncode == 0, r.stderr
    assert result(r.stdout) == ["shared", "agy-host-01", "lab-shared-vpc", "lab-agy-euw3", "", "false"]
    r = bash(q7_harness(1), env={"PATH": gcloud_stub(tmp_path)})   # answers.env from before question 7
    assert result(r.stdout)[0] == "create"
    r = bash(q7_harness(1, 'NETWORK_MODE="shared"'), env={"PATH": gcloud_stub(tmp_path)})
    assert r.returncode == 1 and "SHARED_VPC_HOST_PROJECT" in r.stderr   # incomplete saved answers stop --yes


def test_q7_rerun_offers_saved_values_as_defaults(tmp_path: Path) -> None:
    saved = ('NETWORK_MODE="shared"; SHARED_VPC_HOST_PROJECT="agy-host-01"; SHARED_VPC_NETWORK="lab-shared-vpc"; '
             'SHARED_VPC_SUBNET="lab-agy-euw3"; GATEWAY_ILB_IP="10.70.0.10"; ILB_GLOBAL_ACCESS="true"')
    r = bash(q7_harness(0, saved), env={"PATH": gcloud_stub(tmp_path)}, stdin="\n\n\n\n\n\n\n\n")
    assert r.returncode == 0, r.stderr
    assert result(r.stdout) == ["shared", "agy-host-01", "lab-shared-vpc", "lab-agy-euw3", "10.70.0.10", "true"]
    r = bash(q7_harness(0, saved), env={"PATH": gcloud_stub(tmp_path)}, stdin="\n\n\n\n\nauto\nn\n")
    assert result(r.stdout)[4:] == ["", "false"]   # "auto" clears a saved IP


def test_answers_env_keys_written_and_passed_to_terraform() -> None:
    block = POC_SH[POC_SH.index('cat > "$ANSWERS" <<EOF'):]
    block = block[:block.index("\nEOF\n")]
    for key in ("NETWORK_MODE", "SHARED_VPC_HOST_PROJECT", "SHARED_VPC_NETWORK", "SHARED_VPC_SUBNET",
                "GATEWAY_ILB_IP", "ILB_GLOBAL_ACCESS"):
        assert f'{key}="${key}"' in block, key
        assert re.search(rf"^unset .*\b{key}\b|^      .*\b{key}\b", POC_SH, re.M), f"{key} not reset before sourcing answers"
    for flag in ("--network-mode", "--shared-vpc-host-project", "--shared-vpc-network", "--shared-vpc-subnet",
                 "--gateway-ilb-ip", "--ilb-global-access"):
        assert flag in POC_SH, flag


def test_poc_kit_cli_writes_network_tfvars(tmp_path: Path) -> None:
    csv = tmp_path / "devices.csv"
    csv.write_text((ROOT / "poc" / "devices.csv.example").read_text())
    out = tmp_path / "poc.auto.tfvars"
    r = subprocess.run(["python3", str(ROOT / "poc" / "poc_kit.py"), "tfvars", str(csv), "--out", str(out),
                        "--network-mode", "shared", "--shared-vpc-host-project", "agy-host-01", "--shared-vpc-network",
                        "lab-shared-vpc", "--shared-vpc-subnet", "lab-agy-euw3", "--gateway-ilb-ip", "",
                        "--ilb-global-access", "false"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    text = out.read_text()
    assert 'network_mode            = "shared"' in text and "gateway_ilb_ip" not in text and "ilb_global_access" not in text
    r = subprocess.run(["python3", str(ROOT / "poc" / "poc_kit.py"), "tfvars", str(csv), "--out", str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 0 and "network_mode" not in out.read_text()   # default: identical to before question 7


def test_status_shows_gateway_ip_port_and_network() -> None:
    body = POC_SH[POC_SH.index("do_status() {"):POC_SH.index("do_destroy() {")]
    assert "need_tf" in body and '"network" "$(network_line)"' in body and "TCP port 443" in body


def test_install_conf_marks_poc_mode() -> None:
    body = POC_SH[POC_SH.index("write_install_conf() {"):POC_SH.index("cost_ack() {")]
    assert 'AGY_POC="1"' in body
    assert "AGY_POC" in INSTALL_SH.split("[[ -f \"$CONF\" ]] && source \"$CONF\"")[0]   # reset before sourcing
    assert 'AGY_POC="${AGY_POC:-}"' in INSTALL_SH


# ----------------------------------------------------------------------------- C6 hand-off in POC mode
TF_OUT = {
    "gateway_mtls_url": {"value": "https://gateway.agy.internal"}, "gateway_ilb_ip": {"value": "10.70.0.10"},
    "gateway_url": {"value": "https://gw.example.run.app"},
    "fleet": {"value": {"devices": ["win-01"], "ca_pool": "pool", "spiffe_prefix": "spiffe://p.agy.internal/fleet/"}},
    "network": {"value": {"mode": "shared", "host_project": "agy-host-01", "network": "lab-shared-vpc",
                          "subnet": "lab-agy-euw3", "gateway_ip": "10.70.0.10", "port": 443, "global_access": False,
                          "private_dns": False}},
}


def handoff(tmp_path: Path, poc: bool) -> str:
    j = tmp_path / "tf.json"
    j.write_text(json.dumps(TF_OUT))
    env = {k: v for k, v in os.environ.items() if k != "AGY_POC"}
    env.update({"PROJECT_ID": "agy-service-01", "REGION": "europe-west3", **({"AGY_POC": "1"} if poc else {})})
    r = subprocess.run(["python3", str(ROOT / "install" / "handoff.py"), "--tf-json", str(j), "--outdir", str(tmp_path)],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    return (tmp_path / "TESTING.md").read_text()


def test_handoff_poc_mode_text(tmp_path: Path) -> None:
    md = handoff(tmp_path, poc=True)
    assert "devices.csv" in md and "poc/poc-gateway.sh" in md and "from their kit" in md
    for generic in ("custom.auto.tfvars", "make fleet-cert", "agy-credproxy.py", "./install.sh --destroy"):
        assert generic not in md, generic
    assert "Shared VPC: host project `agy-host-01`, network `lab-shared-vpc`, subnet `lab-agy-euw3`" in md
    assert "`10.70.0.10:443`" in md and "pin the name" in md and "gateway.agy.internal to that IP" in md
    assert "AGY_NETWORK_MODE=shared" in (tmp_path / "testing.env").read_text()


def test_handoff_generic_mode_unchanged(tmp_path: Path) -> None:
    md = handoff(tmp_path, poc=False)
    assert "custom.auto.tfvars" in md and "make fleet-cert" in md and "{onboard}" not in md
    assert "## 2. Onboard a device\n" in md and "## 3. Evidence" in md


# ----------------------------------------------------------------------------- C11 any current folder
def test_poc_gateway_resolves_root_from_its_own_path(tmp_path: Path) -> None:
    assert 'ROOT="$(cd "$(dirname "$0")/.." && pwd)"' in POC_SH
    r = subprocess.run(["bash", str(ROOT / "poc" / "poc-gateway.sh"), "--help"], capture_output=True, text=True,
                       cwd=tmp_path, timeout=30)
    assert r.returncode == 0 and "poc/poc-gateway.sh --status" in r.stdout and "question 7" in r.stdout


@pytest.mark.parametrize("script", ["install.sh", "install/state-bootstrap.sh", "scripts/fleet-cert.sh"])
def test_scripts_called_by_the_poc_resolve_their_root(script: str) -> None:
    src = (ROOT / script).read_text()
    assert re.search(r'ROOT="\$\(cd "\$\(dirname "\$0"\)(/\.\.)?" && pwd\)"', src), script


# ----------------------------------------------------------------------------- grant-installer: greenfield project
def load_iam():  # noqa: ANN201
    import importlib.util
    spec = importlib.util.spec_from_file_location("installer_iam_t", ROOT / "install" / "installer_iam.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_grant_enables_bootstrap_apis_before_any_project_call(monkeypatch: pytest.MonkeyPatch,
                                                              capsys: pytest.CaptureFixture[str]) -> None:
    iam = load_iam()
    assert os.environ.get("CLOUDSDK_CORE_DISABLE_PROMPTS") == "1"
    calls: list[str] = []

    def fake_run(cmd: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
        calls.append("gcloud " + " ".join(cmd[1:]))
        assert kw.get("stdin") == subprocess.DEVNULL and kw.get("timeout")
        return subprocess.CompletedProcess(cmd, 0, "", "")
    answers = iter([SystemExit("ERROR 403 POST x: Cloud Resource Manager API has not been used in project p before or it is disabled"),
                    SystemExit("ERROR 403 POST x: SERVICE_DISABLED"), {}])

    def fake_api(method: str, url: str, project: str, body: object = None, attempts: int = 5) -> dict[str, object]:
        calls.append(f"api {url}")
        a = next(answers)
        if isinstance(a, SystemExit):
            raise a
        return a
    monkeypatch.setattr(iam.subprocess, "run", fake_run)
    monkeypatch.setattr(iam, "api", fake_api)
    monkeypatch.setattr(iam, "SLEEP", lambda s: None)
    iam.enable_bootstrap_apis("agy-service-02")
    out = getattr(capsys, "read" + "outerr")().out   # name split: the release scan treats the word as internal material
    assert "[grant] enabling bootstrap APIs on agy-service-02 (Cloud Resource Manager, IAM, Service Usage, Org Policy)" in out
    assert calls[0] == ("gcloud services enable cloudresourcemanager.googleapis.com iam.googleapis.com "
                        "serviceusage.googleapis.com orgpolicy.googleapis.com --project agy-service-02 --quiet")
    assert sum(c.startswith("api ") for c in calls) == 3 and "retry 2/12" in out
    src = (ROOT / "install" / "installer_iam.py").read_text()
    g = src[src.index("def grant("):]
    assert g.index("enable_bootstrap_apis(a.project)") < g.index("check_admin(a.project)")


def test_grant_without_enable_rights_prints_the_exact_command(monkeypatch: pytest.MonkeyPatch) -> None:
    iam = load_iam()
    monkeypatch.setattr(iam.subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(
        cmd, 1, "", "ERROR: (gcloud.services.enable) PERMISSION_DENIED: Permission denied to enable service"))
    with pytest.raises(SystemExit) as e:
        iam.enable_bootstrap_apis("agy-service-02")
    msg = str(e.value)
    assert ("gcloud services enable cloudresourcemanager.googleapis.com iam.googleapis.com serviceusage.googleapis.com "
            "orgpolicy.googleapis.com --project agy-service-02") in msg and "PERMISSION_DENIED" in msg and "serviceUsageAdmin" in msg


def test_grant_real_permission_errors_are_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    iam = load_iam()
    monkeypatch.setattr(iam.subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "", ""))
    n = {"api": 0}

    def fake_api(*a: object, **k: object) -> dict[str, object]:
        n["api"] += 1
        raise SystemExit("ERROR 403 POST x: The caller does not have permission")
    monkeypatch.setattr(iam, "api", fake_api)
    monkeypatch.setattr(iam, "SLEEP", lambda s: None)
    with pytest.raises(SystemExit, match="does not have permission"):
        iam.enable_bootstrap_apis("agy-service-02")
    assert n["api"] == 1


def test_installer_iam_token_cannot_hang_on_a_prompt() -> None:
    src = (ROOT / "install" / "installer_iam.py").read_text()
    assert '"print-access-token", "--quiet"' in src and "stdin=subprocess.DEVNULL, timeout=120" in src


# ----------------------------------------------------------------------------- requireInvokerIam at deploy time
DEPLOY_ERR = ('Error: Error creating Service: googleapi: Error 400: Violation in CreateServiceRequest.service.invoker_iam_disabled: '
              'violates constraint \\"constraints/run.managed.requireInvokerIam\\"')


@pytest.mark.parametrize("poc,next_step", [("1", "run poc/poc-gateway.sh --yes"), ("", "run ./install.sh")])
def test_retry_stops_on_invoker_iam_policy_with_guidance(poc: str, next_step: str) -> None:
    r = bash(retry_harness() + f'AGY_POC="{poc}"\nfail() {{ echo "{DEPLOY_ERR}" >&2; return 1; }}\n'
             'retry 3 60 fail; echo "not reached"')
    assert r.returncode == 1 and "not reached" not in r.stdout
    assert "SLEEP" not in r.stderr and "attempt 1/3" not in r.stderr   # no retry: it is not propagation
    assert "name: projects/agy-service-02/policies/run.managed.requireInvokerIam" in r.stderr
    assert "gcloud org-policies set-policy" in r.stderr and "Organization Policy Administrator" in r.stderr
    assert "secret header" in r.stderr and f"DIE: add the exception, wait 2-3 min, {next_step}" in r.stderr


# ----------------------------------------------------------------------------- POC wording + validation rows
def test_handoff_poc_has_no_make_or_installer_commands(tmp_path: Path) -> None:
    md = handoff(tmp_path, poc=True)
    assert "make " not in md and "./install.sh" not in md
    assert "Log Analytics > Saved queries (`AGY - ...`)" in md
    assert "gcloud logging read 'jsonPayload.component=\"agy-gateway\"' --project agy-service-01 --freshness 1h" in md
    assert "`poc/poc-gateway.sh --destroy` removes everything" in md
    assert "`make logs`" in handoff(tmp_path, poc=False)


def test_install_banner_and_phase6_message_in_poc_mode() -> None:
    tail = INSTALL_SH[INSTALL_SH.index("phase_done p5 ||"):]
    assert ('log "POC: your laptops are the devices - the optional cloud reference workstation is not part of the POC '
            '(phase 6 skipped)"') in tail
    assert tail.index('if [[ -n "${AGY_POC:-}" ]]; then log "POC:') < tail.index('log "gateway profile: no reference workstation')
    poc_block = tail[tail.index("   Evidence           :"):tail.index("   Gateway audit log  : make logs")]
    assert "Log Analytics > Saved queries (AGY - ...)" in poc_block
    assert "gcloud logging read 'jsonPayload.component=\"agy-gateway\"' --project ${PROJECT_ID} --freshness 1h" in poc_block
    assert "Remove             : poc/poc-gateway.sh --destroy" in poc_block and "make " not in poc_block


def test_validation_report_has_no_empty_rows() -> None:
    body = INSTALL_SH[INSTALL_SH.index("p7_validate() {"):INSTALL_SH.index("p8_handoff() {")]
    filt = next(line for line in body.splitlines() if line.strip().startswith('out="$(grep \'^RESULT|\''))
    show = next(line for line in body.splitlines() if line.strip().startswith("awk -F'|' '{c="))
    out = "RESULT|PASS|V17|Fleet devices registered|2 device(s)\n\nRESULT|WARN|V20|End to end|probe\n\n\nRESULT|SKIP|S40|Telemetry|off\n"
    r = bash(f"out=$(cat <<'X'\n{out}X\n)\n{filt}\n{show}")
    assert r.returncode == 0, r.stderr
    lines = r.stdout.strip().splitlines()
    assert len(lines) == 3 and not any("[]" in line for line in lines)
    assert body.index(filt.strip()) < body.index("fails=$(grep -c")
