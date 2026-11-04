# POC permissions and changes

Every permission the pay-as-you-go POC needs, and every change it makes, on the cloud side and on the laptops. Prerequisites checklist: [POC-PREREQUISITES.md](POC-PREREQUISITES.md); how to run the POC: [POC-STEP-BY-STEP.md](POC-STEP-BY-STEP.md); details: [POC-TECHNICAL-REFERENCE.md](POC-TECHNICAL-REFERENCE.md).

## 1. Cloud side

### 1.1 Installer identity (the account that runs `poc/poc-gateway.sh`)

Never Owner or Editor. Choose one option; the installer's preflight checks every permission (`projects.testIamPermissions`) before it creates anything.

**Option A: least-privilege custom role, time-bound (recommended).** A project administrator runs:

| Command | Effect |
|---|---|
| `install/grant-installer.sh --project <id> --principal user:<installer> [--hours 8] [--no-evidence]` | Creates the custom role `agyPocInstaller` with about 315 permissions (exact list: `install/permissions.txt`, minus the few permissions Google doesn't allow in custom roles; validated with a non-Owner installer on a clean project) and binds it with an expiry condition (default 8 hours). Use `--no-evidence` for the POC (prompt logging `hash`): no organisation-level role is needed, and the preflight skips the deny-policy permissions in this mode |
| `install/installer_iam.py show --project <id> --principal user:<installer>` | Shows the current grant |
| `install/revoke-installer.sh --project <id> --principal user:<installer>` | Right after the setup (the grant also expires on its own, default 8 hours): removes exactly these bindings and deletes the custom role (`--keep-role` keeps it) |

The role includes five KMS permissions for a redeploy after a destroy (adopting the old log buckets and their keys): `cloudkms.cryptoKeyVersions.get`, `cloudkms.cryptoKeyVersions.restore`, `cloudkms.cryptoKeyVersions.update`, `cloudkms.cryptoKeys.list`, `cloudkms.keyRings.list`. Installer grants made before they were added must be re-run with `install/grant-installer.sh`.

IAM propagation after the grant takes about 2–5 minutes and is intermittent at first (some calls pass, some get `403`): wait a few minutes before `poc/poc-gateway.sh`. Terraform apply is retried 3 times automatically; if a `403` persists, re-run `poc/poc-gateway.sh --yes` (idempotent).

Before the grant, the script enables the bootstrap APIs on the project (Cloud Resource Manager, IAM, Service Usage) and waits for them; this needs Service Usage Admin (`roles/serviceusage.serviceUsageAdmin`; an Owner has it) and a linked billing account. If it can't, it prints the exact `gcloud services enable … --project <id>` command.

The administrator who grants needs project IAM and role administration (`resourcemanager.projects.setIamPolicy`, `iam.roles.*`) and `serviceusage.services.enable`.

**Option B: predefined roles on the project.**

| Area | Role |
|---|---|
| APIs | `roles/serviceusage.serviceUsageAdmin` |
| Project IAM | `roles/resourcemanager.projectIamAdmin` |
| Service accounts | `roles/iam.serviceAccountAdmin` + `roles/iam.serviceAccountUser` |
| Custom roles | `roles/iam.roleAdmin` |
| Tags | `roles/resourcemanager.tagAdmin` + `roles/resourcemanager.tagUser` |
| Organisation policies (read) | `roles/orgpolicy.policyViewer` |
| Network, load balancer, VMs | `roles/compute.admin` |
| IAP | `roles/iap.admin` |
| KMS (CMEK) | `roles/cloudkms.admin` + `roles/cloudkms.cryptoKeyEncrypter` |
| Privileged Access Manager | `roles/privilegedaccessmanager.admin` |
| Storage | `roles/storage.admin` |
| Secrets | `roles/secretmanager.admin` |
| Container images and build | `roles/artifactregistry.admin`, `roles/cloudbuild.builds.editor` |
| Gateway service | `roles/run.admin` |
| Prompt inspection | `roles/modelarmor.admin` |
| Models | `roles/aiplatform.user` |
| Device certificates | `roles/privateca.admin`, `roles/certificatemanager.owner` |
| mTLS front door | `roles/networksecurity.admin` |
| DNS | `roles/dns.admin` |
| Logging, monitoring, SIEM | `roles/logging.admin`, `roles/monitoring.editor`, `roles/bigquery.admin` |

**Outside Cloud Shell (admin laptop):** use a dedicated `gcloud` profile for the installer identity, so your own configuration stays untouched. In Cloud Shell nothing extra is needed.

```bash
export CLOUDSDK_CONFIG=$HOME/.agy-poc-installer
gcloud auth login installer@example.com
gcloud auth application-default login
export GOOGLE_APPLICATION_CREDENTIALS=$CLOUDSDK_CONFIG/application_default_credentials.json
poc/poc-gateway.sh
```

### 1.2 Organisation level

| Permission | POC | Without it |
|---|---|---|
| `roles/iam.denyAdmin` (can only be granted on the organisation) | Not needed: the POC uses prompt logging `hash`, so no prompt-evidence store and no deny policy is created | Only relevant with prompt evidence (`deidentified` / `evidence`): the evidence deny policy that stops project owners from reading evidence can't be created |
| Organisation policies | Read only (preflight) | The preflight can't report conflicting policies |

### 1.3 Billing account

| Item | Needed for |
|---|---|
| **Billing Account Costs Manager** (or Billing Account Administrator) on the billing account, granted by a billing account administrator. Mandatory: budgets are scoped to the billing account and can't be part of a project custom role | The per-persona budget alerts (`billingbudgets.googleapis.com`) |
| Billing account linked to the project, readable by the installer | `poc-gateway.sh` reads the linked billing account |
| Detailed billing export to BigQuery (set up in the console) | Invoiced cost per persona; the gateway view `v_persona_usage` gives an estimate without it |

### 1.4 APIs the installer enables

Compute Engine, Cloud Run, Cloud Build, Artifact Registry, Model Armor, Secret Manager, Cloud Logging, Cloud Monitoring, IAP, Cloud KMS, Cloud Storage, BigQuery, BigQuery Data Transfer, OS Login, IAM, Security Token Service, Cloud Resource Manager, Service Usage, Vertex AI, Gemini for Google Cloud (`cloudaicompanion`), Gemini Enterprise APIs (`businessaicode`, `discoveryengine`), Certificate Authority Service, Certificate Manager, Network Security, Cloud DNS, Sensitive Data Protection (`dlp`), Privileged Access Manager, Pub/Sub, Cloud Identity; with budgets also Cloud Billing and Billing Budgets.

### 1.5 Organisation policy constraints that must allow the POC

| Constraint | Must allow |
|---|---|
| Resource locations | The EU region (default `europe-west4`) and `eu` |
| CMEK requirement (if enforced) | The services above with your keys; the installer creates the CMEK keys |
| Restricted service usage (`gcp.restrictServiceUsage`) | The APIs in §1.4 |
| Cloud Run ingress | Internal ingress (the gateway is reached only through the internal load balancer) |
| Service-account key creation | Not needed (no keys are created) |

### 1.6 Runtime identities the installer creates (no keys)

| Identity | Granted (least privilege) |
|---|---|
| Gateway service account | Custom role with only `aiplatform.endpoints.predict` (generate calls); Model Armor user; log writer; metric writer; read access to one secret (load balancer header) |
| Build service account | Artifact Registry writer on the gateway repository; log writer; object admin on its own source bucket |
| Model Armor service agent | Sensitive Data Protection user / reader (inspect and de-identify templates) |
| SIEM detection service account | BigQuery data editor on the detections dataset, data viewer on the log dataset, job user, log view accessor; tokens minted by the BigQuery Data Transfer service agent |
| Certificate Manager service agent | Certificate requester on the gateway's CA pool |
| Google service agents for CMEK | Encrypt / decrypt on their own keys only |

### 1.7 Network

| Item | Requirement |
|---|---|
| VPN | Site-to-site VPN (or interconnect) to the POC VPC; remote workers need a route through it |
| Routes and firewalls | Laptops → gateway internal IP (VPC subnet, default `10.40.0.0/24`), TCP 443, allowed by your corporate firewall. Own POC network: the internal load balancer is regional without global access, so terminate the VPN in the deployment region. Shared VPC: see [POC-SHARED-VPC.md](POC-SHARED-VPC.md) (question 7f for a connection in another region) |
| DNS | Nothing to configure: `gateway.agy.internal` is in a private zone; the device script pins it in the laptop's hosts file |
| TLS inspection | None on the gateway path (mTLS) |

## 2. Endpoint side

### 2.1 Windows 11

| Item | Detail |
|---|---|
| Who runs it | A local administrator, once, in an elevated PowerShell. The device owner is a **standard user** (administrators are refused) and signs in once before |
| Folders | `C:\ProgramData\Antigravity` (controls, hook, policy, logs; `credproxy\` with the device certificate and key: SYSTEM / Administrators only), `C:\ProgramData\AntigravityPOC` (install record, test and evidence output; Administrators only), `C:\Program Files\Antigravity` (client), `C:\Program Files\Python312`, `C:\Program Files\WindowsTerminal`, `C:\projects` (workspaces); per user: locked settings, hooks, MCP configuration and browser allowlist |
| Scheduled tasks (SYSTEM) | `AGY-Bootstrap` (startup), `AGY-Policy` (logon and every 5 minutes: drift correction), `AGY-CredProxy` (local credential proxy on `127.0.0.1:8443`), `AGY-EgressSync` |
| Local groups | `AGY-Dev`, `AGY-Contractor` (the owner is added to one); container groups `AGY-NoContainers` / `AGY-ContainerDev` |
| Hosts file | The gateway name → internal IP (`# agy-poc-gw`); sinkholes for direct model endpoints and tunnel services (`# agy-pin`) |
| User rights | Persona groups: "Deny log on through Remote Desktop Services" and removed from Remote Desktop Users (RDP for Administrators / SYSTEM only); *Create symbolic links* for developers |
| Baseline | Standard-user UAC prompts auto-denied, sudo off, long paths, audit policy, PowerShell script-block logging, process command lines in event 4688; optional AppLocker / WDAC (`-AppControl`) and Sysmon (`-Sysmon`) |
| Downloads at install (or your mirrors) | Python 3.12 from `www.python.org` (signature checked), Antigravity from `storage.googleapis.com/antigravity-public` (hash and signature checked), Windows Terminal from `github.com` (pinned SHA-256), Sysmon from `download.sysinternals.com` only with `-Sysmon` (signature checked) |
| Removal | `-Uninstall`: removes the above (persona groups included); keeps Python, workspaces, the OS hardening baseline and the evidence folder |

### 2.2 macOS

| Item | Detail |
|---|---|
| Who runs it | An administrator with `sudo`, once. The device owner is a **standard user** (administrators are refused) and signs in once before |
| Prerequisite | Command Line Tools (`/usr/bin/python3` 3.9+) |
| Files | `/Library/Application Support/Antigravity/` (admin settings, hook policy, `credproxy/` with the device key: root only, `gateway_url`), `/Library/Application Support/AntigravityPOC` (install record, evidence; root only), `/usr/local/libexec/agy-hook`, `/usr/local/libexec/agy/` (CLI, proxy), `/usr/local/bin/agy` (launcher), `/Library/Logs/Antigravity`; per user: locked files in `~/.gemini` (`root:wheel`, `chflags schg`; `~/.gemini` immutable) |
| LaunchDaemons | `com.google.agy.credproxy`, `com.google.agy.policy` (drift repair every 5 minutes) |
| Local groups | `agy-dev`, `agy-contractor` |
| Hosts file | Gateway name (`# agy-poc-gw`) and sinkholes (`# agy-pin`) |
| Downloads at install | Antigravity CLI from `storage.googleapis.com/antigravity-public` (sha512 from the official release manifest) |
| Removal | `--uninstall`: removes the above; the user's own files in `~/.gemini` stay |

### 2.3 EDR / antivirus allow-list

| Windows | macOS |
|---|---|
| The kit scripts and `C:\ProgramData\Antigravity\` (controls, hook) | The kit scripts, `/usr/local/libexec/agy-hook`, `/usr/local/libexec/agy/` |
| Python 3.12 running the hook and the credential proxy | `/usr/bin/python3` running the hook and the proxy LaunchDaemon |
| The credential proxy listening on `127.0.0.1:8443` | Same |
| Scheduled tasks `AGY-*` running as SYSTEM | LaunchDaemons `com.google.agy.*` |

## 3. What the POC team needs back

| From | What |
|---|---|
| Each laptop | `-Collect` zip from `C:\ProgramData\AntigravityPOC` / `--collect` archive from `/Library/Application Support/AntigravityPOC` (events, self-test, logs; no keys) |
| Each laptop after removal | `-Test` / `--test` output with P00 `PASS` |
| Attack pack | `attack-report.md` / `attack-report.json` per OS and persona |
| Cloud | Read access to the gateway logs and the BigQuery views (`v_gateway_events`, `v_persona_usage`); billing export if enabled |
| Users | False-block reports (time, action, message) |
