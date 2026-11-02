# POC admin guide: command cheat sheet

All commands in one place, for admins who know the flow. To run the POC the first time, follow [POC-STEP-BY-STEP.md](POC-STEP-BY-STEP.md); for what each command does, its options, checks and errors, see [POC-TECHNICAL-REFERENCE.md](POC-TECHNICAL-REFERENCE.md).

## Cloud (Cloud Shell, in the POC repository folder)

| Task | Command |
|---|---|
| Grant the installer (project admin) | `install/grant-installer.sh --project my-poc-project --principal user:installer@example.com --no-evidence` |
| Show the grant | `install/installer_iam.py show --project my-poc-project --principal user:installer@example.com` |
| Optional preflight (read-only) | `python3 install/preflight.py --project my-poc-project --region europe-west4 --zone europe-west4-a --mtls --no-evidence` |
| Validate `devices.csv` | `python3 poc/poc_kit.py validate poc/devices.csv` |
| Deploy and create kits (6 questions) | `poc/poc-gateway.sh` |
| Re-run with saved answers (also: renew certificates with fewer than 7 days left, add / remove devices) | `poc/poc-gateway.sh --yes` |
| After week 1: kits in enforce mode (use on every later run) | `HOOK_NOISY=enforce poc/poc-gateway.sh --yes` |
| Re-issue all certificates | `poc/poc-gateway.sh --yes --reissue` |
| Status | `poc/poc-gateway.sh --status` |
| Remove the cloud resources, kits and keys | `poc/poc-gateway.sh --destroy` |
| Revoke the installer (project admin) | `install/revoke-installer.sh --project my-poc-project --principal user:installer@example.com` |

## Windows laptop (PowerShell as administrator, in the kit folder)

| Task | Command |
|---|---|
| Unblock the downloaded files | `Get-ChildItem -Recurse \| Unblock-File` |
| Install | `powershell -ExecutionPolicy Bypass -File .\install-windows.ps1 -Install` (`-User <account>`, `-Yes`, `-Offline`, `-AppControl`, `-Sysmon`) |
| Test | `powershell -ExecutionPolicy Bypass -File .\install-windows.ps1 -Test` |
| Evidence | `powershell -ExecutionPolicy Bypass -File .\install-windows.ps1 -Collect` |
| Uninstall | `powershell -ExecutionPolicy Bypass -File .\install-windows.ps1 -Uninstall` |

## Mac (Terminal, administrator account, in the kit folder)

| Task | Command |
|---|---|
| Install | `sudo bash install-macos.sh --install` (`--user <short name>`, `--yes`, `--offline`) |
| Test | `sudo bash install-macos.sh --test` |
| Evidence | `sudo bash install-macos.sh --collect` |
| Uninstall | `sudo bash install-macos.sh --uninstall` |

## Attack pack

| Task | Command |
|---|---|
| Cloud-side simulation (Cloud Shell) | `cd poc/attack-pack && python3 runner.py run --mode deterministic --os windows --persona dev --out results/` |
| Report | `python3 runner.py report --in results/` |
| Live tests on a laptop (owner) | See [POC-USER-GUIDE.md](POC-USER-GUIDE.md#attack-pack-tests) |
