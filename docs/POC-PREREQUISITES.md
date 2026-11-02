# POC prerequisites checklist

Checklist for the pay-as-you-go POC: Antigravity through the customer-run gateway, reached over your VPN, on corporate laptops (Windows 11 and macOS) used by standard users. Clear the **blockers** first. How the POC runs: [POC-STEP-BY-STEP.md](POC-STEP-BY-STEP.md); details: [POC-TECHNICAL-REFERENCE.md](POC-TECHNICAL-REFERENCE.md); every permission and change in detail: [POC-PERMISSIONS.md](POC-PERMISSIONS.md).

**Legend**
- **Blocker**: the POC can't start without it.
- **Needed by**: **K** = kick-off (before the cloud deployment), **D** = before device install, **R** = before the evidence is shared.
- **Verify**: how you check it together with the POC team.

## A. Google Cloud and billing

| # | Item | Owner | Blocker | Needed by | Verify |
|---|---|---|---|---|---|
| A1 | A dedicated Google Cloud project for the POC under your organisation, linked to the pay-as-you-go billing account | Cloud admin | Yes | K | `gcloud projects describe` |
| A2 | The installer identity has the time-bound custom role from `install/grant-installer.sh` or the predefined roles listed in [POC-PERMISSIONS.md](POC-PERMISSIONS.md) (never Owner or Editor). Wait 2–5 minutes after the grant (IAM propagation); revoke right after the setup with `install/revoke-installer.sh` | Cloud admin | Yes | K | Installer preflight permission check = PASS |
| A3 | Organisation-level IAM deny admin: **not needed** for the POC (prompt logging `hash`, no prompt-evidence deny policy); grant with `--no-evidence` | Org admin | No | K | Preflight report |
| A4 | **Billing Account Costs Manager** on the billing account for the installer, granted by a billing account administrator (mandatory: budgets can't be in a project custom role), to create budgets for one budget per persona, for example developers 2,000 and contractors 1,000 in the billing account currency, alerts at 50 / 90 / 100 % | Billing admin | Yes for cost per persona | K | Budgets visible in Billing |
| A5 | **Detailed billing export to BigQuery** enabled, for the invoiced cost per persona (the gateway view `v_persona_usage` gives an estimate without it). Data appears with a delay of hours to a day | Billing admin | No (estimate available) | K (≥ 2 days before go-live) | Export dataset has rows |
| A6 | Organisation policies reviewed for conflicts: resource locations (must allow `europe-west4` / `eu`), CMEK requirement, restricted services (`gcp.restrictServiceUsage`), Cloud Run ingress, domain-restricted sharing, service-account key creation (not needed) | Cloud admin + POC team | Yes if conflicting | K | Preflight organisation-policy check |
| A6b | Organisation policy `run.managed.requireInvokerIam` not enforced on the POC project, **or** a project exception set by an Organization Policy Administrator (the gateway runs behind the internal load balancer without the Cloud Run invoker check; see [the exception](POC-TECHNICAL-REFERENCE.md#organisation-policy-runmanagedrequireinvokeriam)) | Org admin | Yes | K | Preflight `org policy run.managed.requireInvokerIam` = PASS |
| A7 | These APIs may be enabled: Vertex AI, Model Armor, Sensitive Data Protection, Private CA, Certificate Manager, Network Security, Cloud DNS, Cloud Run, Artifact Registry, Cloud Build, KMS, Secret Manager, Logging, Monitoring, BigQuery. No Cloud Armor: the POC gateway is reached only through an internal load balancer | Cloud admin | Yes | K | The installer enables them; check for errors |
| A8 | The selected Gemini models are available in the EU region with quota for the POC users (Flash for contractors, the approved Pro model for developers) | Cloud admin + POC team | Yes | K | Live test call per model through the gateway |
| A9 | Model Armor and Sensitive Data Protection available in the chosen EU location; template policy agreed (prompt injection, jailbreak, secrets / personal data thresholds) | Security | No (defaults exist) | K | Model Armor template present |
| A10 | Contact e-mail for budget and security alerts (a group, not a person) | POC owner | Yes | K | Test notification received |
| A11 | Outside Cloud Shell: a dedicated `gcloud` profile for the installer identity (`CLOUDSDK_CONFIG`, see [POC-PERMISSIONS.md](POC-PERMISSIONS.md) §1.1); nothing extra in Cloud Shell | Cloud admin | No | K | `gcloud config list` in that profile shows the installer |

## B. Network, VPN and DNS

**Network requirements at a glance**

| Need | Detail |
|---|---|
| Laptops → gateway | Only TCP 443 to the gateway IP, over your VPN or Interconnect |
| TLS inspection | None on that path |
| DNS | Not needed (the install pins the gateway name in the hosts file) |
| Internet during the install | Windows: `www.python.org`, `storage.googleapis.com` (plus `download.sysinternals.com` only with `-Sysmon`; optional `github.com` for Windows Terminal: if blocked, the install continues with a warning). Mac: `storage.googleapis.com` and the Google-hosted Antigravity CLI release manifest |
| Gateway IP and port for the network team | `poc/poc-gateway.sh --status` |
| Existing Shared VPC instead of a new network | [POC-SHARED-VPC.md](POC-SHARED-VPC.md) |


| # | Item | Owner | Blocker | Needed by | Verify |
|---|---|---|---|---|---|
| B1 | Site-to-site VPN (HA VPN + Cloud Router / BGP) between the office and the POC project VPC | Network | Yes | D | Tunnel `ESTABLISHED`, BGP up |
| B2 | Routes: on-premises learns the gateway subnet (internal load balancer IP); Google Cloud learns the on-premises client ranges | Network | Yes | D | `Test-NetConnection <gateway-ip> -Port 443` from a laptop |
| B3 | **Remote workers:** laptops outside the office need a route into that network (client VPN / SSE / ZTNA) that sends the gateway IP through the tunnel (a split tunnel must include it) | Network | Yes, if users work from home | D | Same test from home |
| B4 | Firewalls: the corporate firewall allows TCP 443 from the POC laptops to the gateway IP (only). No Google Cloud firewall rule is needed. Own POC network: terminate the VPN in the deployment region. Shared VPC whose connection ends in another region: global dynamic routing and answer 7f = yes ([POC-SHARED-VPC.md](POC-SHARED-VPC.md)) | Network | Yes | D | Connection test |
| B5 | **DNS:** nothing to configure. The gateway name is `gateway.agy.internal` in a private Cloud DNS zone (visible only inside the VPC); the device script pins it to the gateway IP in the laptop's hosts file | Endpoint team | No | D | P01 / M07 `PASS` |
| B6 | **No TLS inspection** on the path to the gateway (mTLS breaks when a proxy intercepts it). Add a bypass for the gateway host name / IP in proxy, PAC and SSE | Network / Security | Yes | D | mTLS handshake succeeds (P02 / M11 `PASS`) |
| B7 | Local proxy settings: loopback (`127.0.0.1`, `localhost`) excluded from the system proxy / PAC | Endpoint team | Yes | D | Self-test passes |
| B8 | Install-time outbound HTTPS to the Antigravity download location (`storage.googleapis.com/antigravity-public/…`) and the Python installer source (Windows), **or** internal mirrors with pinned hashes | Network | Yes | D | Install log |
| B9 | Laptops reach the corporate time source; clock in sync (certificate and mTLS validation fail on a wrong clock) | Endpoint team | Yes | D | `w32tm /query /status`, `sntp` |

## C. Windows 11 laptops

| # | Item | Owner | Blocker | Needed by | Verify |
|---|---|---|---|---|---|
| C1 | **Windows 11 24H2 (build 26100) or later** (tested on build 26300); Windows 10 21H2 / LTSC 2021 or 22H2 only as a short-term mitigation ([POC-WINDOWS-10.md](POC-WINDOWS-10.md)). Needed for the agent terminal sandbox; the script refuses older builds. Windows Server works only as a lab simulation without the sandbox (every agent command needs approval) | Endpoint team | Yes | D | `winver`; registry `CurrentBuild` ≥ 26100 |
| C2 | Edition Enterprise or Education (Pro works for the must-haves; the optional AppLocker / WDAC layer needs Enterprise or Education) | Endpoint team | No | D | `Get-ComputerInfo WindowsProductName` |
| C3 | x64 hardware, ≥ 8 GB RAM, ≥ 10 GB free disk | Endpoint team | Yes | D | — |
| C4 | Users are **standard users** (not in local Administrators); IT has a local / LAPS administrator to run the script | Endpoint team | Yes | D | `net localgroup administrators` |
| C5 | The device owner's account (local, AD or Entra ID) is known; the script adds it to the local persona group `AGY-Dev` or `AGY-Contractor` | Endpoint team | Yes | D | `whoami /groups` after sign-in (P03) |
| C6 | Administrator protection (Windows 11 26100+) may be on; a reboot can be planned once if you want it (the POC itself needs no reboot) | Endpoint team | No | D | Self-test |
| C7 | **EDR / antivirus:** SOC informed; allow the POC scripts, Python, the local credential proxy (listens on `127.0.0.1:8443`) and the hook. No silent quarantine | Security / SOC | Yes | D | Install completes; no unresolved EDR alerts |
| C8 | Existing application control (AppLocker / WDAC / Defender ASR) and PowerShell policy allow running the install script as administrator (execution policy for that session, or signed scripts) | Endpoint team | Yes | D | Install runs |
| C9 | MDM / Group Policy doesn't overwrite `C:\ProgramData\Antigravity\` or remove the AGY scheduled tasks during the POC | Endpoint team | Yes | D | `-Test` after 24 h |
| C10 | Developer toolchains installed **machine-wide** (standard users can't install them): Git, the languages and build tools used in normal work, package registry access | Endpoint team + developers | Yes for the false-block measure | D | Attack-pack control scenarios A26–A28 `allow` |
| C11 | Port 8443 on loopback free | Endpoint team | Yes | D | Self-test |

## D. macOS laptops

| # | Item | Owner | Blocker | Needed by | Verify |
|---|---|---|---|---|---|
| D1 | **macOS 14 or later** (tested on macOS 15), Apple silicon or Intel | Endpoint team | Yes | D | `sw_vers`, `uname -m` |
| D2 | **python3 for root:** Xcode Command Line Tools installed (`/usr/bin/python3` is only a stub without them), or a signed Python 3.9+ | Endpoint team | Yes | D | `/usr/bin/python3 --version` runs without a prompt (M10) |
| D3 | Users are standard users; IT has an administrator account for `sudo` once | Endpoint team | Yes | D | `dseditgroup -o checkmember -m <user> admin` = no |
| D4 | The device owner's short name is known; the script adds it to the local persona group `agy-dev` or `agy-contractor` | Endpoint team | Yes | D | `id <user>` (M08) |
| D5 | MDM (Jamf / Intune) doesn't push conflicting Antigravity settings or remove the AGY LaunchDaemons / locked files during the POC | Endpoint team | Yes | D | `--test` after 24 h |
| D6 | EDR on macOS informed; allow the credential proxy LaunchDaemon and the hook | Security / SOC | Yes | D | Install completes |
| D7 | Gatekeeper / MDM policy doesn't block the pinned Antigravity CLI (installed under `/usr/local/libexec/agy`) | Endpoint team | Yes | D | M09 `PASS`, `agy --version` as the user |
| D8 | Developer toolchains installed (Homebrew under IT control or a software catalogue) | Endpoint team | Yes for the false-block measure | D | A26–A28 `allow` |

## E. People, data and governance

| # | Item | Owner | Blocker | Needed by | Verify |
|---|---|---|---|---|---|
| E1 | `devices.csv`: device name (a free label, 2–63 characters `a-z0-9._-`; the laptop's short host name in lowercase is recommended), owner, persona (`dev` / `contractor`), OS (`windows` / `windows10` / `macos`) for every POC laptop. Suggested mix: about 3 developers, 2 contractors (at least 1 contractor per OS) | POC owner | Yes | K | File validated by `poc-gateway.sh` |
| E2 | **Works council / privacy:** POC users are informed that prompts are inspected and that model calls, blocked actions and token usage are logged per device and persona; DPIA screening done; works council consulted where required (employee monitoring) | DPO / HR | Yes (employee monitoring rules) | K | Signed note |
| E3 | Contractors: the contract allows AI tool use and logging; data classification of the code they may use | Legal / procurement | Yes | K | Confirmation |
| E4 | Log retention and access for POC data agreed (default: EU location, CMEK, 30 days, read access only for the POC team) | Security | No (defaults) | K | Settings in the report |
| E5 | Allowed data: which repositories may be used (no production secrets or customer personal data in the POC) | Security + developers | Yes | K | Repository list |
| E6 | Model choice signed off: developers (including the Pro model for complex tasks) and contractors (Flash only) | POC owner | Yes | K | Sign-off |
| E7 | AI literacy: short briefing for POC users (EU AI Act Art. 4), plus [POC-USER-GUIDE.md](POC-USER-GUIDE.md) | POC owner | No | D | Attendance |
| E8 | Success criteria agreed with your Google contact before the start | POC sponsor | Yes | K | Agreed criteria |
| E9 | Named contacts: POC sponsor, cloud admin, network, endpoint (Windows and macOS), SOC, DPO; a change window for the install day | POC owner | Yes | K | Contact sheet |
| E10 | Normal-work sample: 3–5 typical developer tasks and repositories for the false-block measure | Development lead | Yes for the false-block measure | D | Scenario list |

## What the POC team delivers

| Item | When |
|---|---|
| Gateway deployment with `poc/poc-gateway.sh`; device kits (one archive per laptop: script, `poc.json`, certificate, key) handed over through a secure channel | After K |
| Install, self-test, uninstall and evidence scripts per OS | D |
| Attack pack (`poc/attack-pack`) | D |
| End of POC: certificates expire (short-lived, at most 30 days), budget and project teardown, or promotion to production | End |

## Top stoppers to clear first

1. **C1:** Windows build below 24H2 (26100) → no terminal sandbox → the script refuses the device.
2. **B6:** TLS inspection on the gateway path → mTLS fails.
3. **B3:** remote workers without a route to the gateway.
4. **D2:** macOS without Command Line Tools → no python3 → no hook and no credential proxy.
5. **C7 / D6:** EDR quarantining the proxy or hook.
6. **A5:** billing export enabled too late → no invoiced cost per persona in the evidence.
7. **E2:** works council / privacy not cleared → the POC can't log prompts.
