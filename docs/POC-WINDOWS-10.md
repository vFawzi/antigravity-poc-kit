# POC on Windows 10 laptops

A **short-term mitigation** for POC laptops that still run Windows 10. Move these laptops to Windows 11 (the normal POC path) as soon as you can.

## Supported versions

| Version | Build | Support status |
|---|---|---|
| Windows 10 21H2 / Enterprise LTSC 2021 | 19044 | LTSC 2021 is supported until 12 January 2027 |
| Windows 10 22H2 | 19045 | End of support 14 October 2025: use Extended Security Updates (ESU) |

Client editions only; other builds are refused by the script.

## What is different from Windows 11

| Topic | Windows 10 |
|---|---|
| Approval mode | Windows 10 has no Antigravity terminal sandbox. Every agent command needs the user's approval, except allow-listed read-only commands. Self-test **P07** checks this mode |
| Administrator protection | Not available: **V81 WARN** is normal |
| App Control (`-AppControl`) | Only on Enterprise or Education (including LTSC and IoT). AppLocker works at once; WDAC becomes active after the next reboot (**V74 WARN** until the reboot, then PASS) |
| Everything else | The same as Windows 11: hook, locked settings, local proxy and certificate, personas, Remote Desktop rule |

## Steps

1. **`devices.csv`**: set the laptop's `os` column to `windows10`:
   ```text
   win10-dev-01,developer3@example.com,dev,windows10
   ```
2. **Kits**: run `poc/poc-gateway.sh --yes`. The kit (`poc-kit/<device>.zip` and `.tar.gz`) contains `install-windows10.ps1` instead of `install-windows.ps1`.
3. **Install** (endpoint admin, PowerShell as administrator, in the kit folder): the same as for Windows 11 ([Part C](POC-STEP-BY-STEP.md#part-c-endpoint-admin)), with the Windows 10 script:
   ```powershell
   cd C:\AGYKit\win10-dev-01
   ls          # install-windows10.ps1 must be listed
   Get-ChildItem -Path . -Recurse | Unblock-File
   powershell -ExecutionPolicy Bypass -File .\install-windows10.ps1 -Install
   ```
   An elevated PowerShell starts in `C:\Windows\system32`: always `cd` to the kit folder first.
   Options: `-User`, `-Yes`, `-Offline`, `-AppControl`, `-Sysmon` (no `-AllowServer`).
4. **Test, evidence, uninstall**: `-Test`, `-Collect`, `-Uninstall` with `install-windows10.ps1`. **0 FAIL** is what matters; V81 WARN is normal (and V74 WARN until a reboot when you used `-AppControl`).

## Lab results

| Item | Result |
|---|---|
| Install time | About 1.5 minutes |
| Attack pack (automated scenarios) | 24 of 24 as expected, including 16 of 16 critical |
| Normal development work | Allowed, also with App Control on |
