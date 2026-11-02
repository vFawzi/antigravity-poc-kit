# Changing POC settings

A catalogue of the settings you may want to change during the POC, each with the same steps. What each part does: [POC-HOW-IT-WORKS.md](POC-HOW-IT-WORKS.md). Commands run in Cloud Shell in the POC repository folder unless a step says otherwise.

> **Safety rules**
> - Change one thing at a time, and keep a copy of the original file (`cp <file> <file>.orig`).
> - Never weaken the critical rules (secrets, protected paths, remote scripts, review bypass). They are always enforced, also in audit mode.
> - After each change, run the attack pack again ([POC-STEP-BY-STEP.md](POC-STEP-BY-STEP.md), Part D).
> - Every change is logged: cloud changes in the project's Cloud Audit Logs (Admin Activity); laptop changes in the laptop's AGY events (Windows Application log, source `agy-mdm`; Mac log `agy-mdm`), included in `-Collect` / `--collect`.
> - After week 1, start every `poc/poc-gateway.sh --yes` with `HOOK_NOISY=enforce`, or the new kits go back to audit mode.

**Where cloud overrides go.** `poc/poc-gateway.sh` rewrites `terraform/terraform.tfvars` and `terraform/poc.auto.tfvars` on every run; never edit them. Put your own values in **`terraform/custom.auto.tfvars`** (never overwritten). Only for the two values that `poc.auto.tfvars` itself sets and that you may want to change (budget thresholds, saved queries), use **`terraform/zz-overrides.auto.tfvars`**: Terraform reads these files in alphabetical order and the last value wins.

**Three ways a change reaches its target:**

| Kind | Run | Then |
|---|---|---|
| Cloud (gateway, logging, budgets) | `poc/poc-gateway.sh --yes` (re-deploys what changed, about 5 minutes) | Nothing on the laptops |
| Kit (laptop rules, devices, certificates) | `poc/poc-gateway.sh --yes` (rebuilds every kit) | Endpoint admin re-runs the install on each affected laptop with its new kit ([Part C](POC-STEP-BY-STEP.md#part-c-endpoint-admin)) |
| Laptop only (Windows registry) | — | Applied by the laptop's policy task within 5 minutes |

## Contents

| Group | Settings |
|---|---|
| People and devices | [1 Add a laptop](#1-add-a-laptop) · [2 Remove a laptop](#2-remove-or-block-a-laptop) · [3 Change a laptop's persona](#3-change-a-laptops-persona) · [4 Change the owner](#4-change-a-laptops-owner) · [5 Certificate lifetime](#5-certificate-lifetime) · [6 Renew certificates](#6-renew-certificates) |
| Cost | [7 Budget amounts](#7-budget-amounts) · [8 Budget alert thresholds](#8-budget-alert-thresholds) · [9 Model prices for the estimate](#9-model-prices-for-the-cost-estimate) |
| Models and AI checks | [10 Models per persona](#10-models-per-persona) · [11 Model Armor](#11-model-armor) · [12 Sensitive data types](#12-sensitive-data-types-and-sensitivity) · [13 Mask or block](#13-mask-or-block-sensitive-data-pci-scope) · [14 Blocked prompt topics](#14-blocked-prompt-topics-and-the-ai-classifier) |
| Laptop rules | [15 Audit or enforce](#15-week-1-audit-or-enforce) · [16 Protected paths and blocked commands](#16-protected-paths-blocked-commands-blocked-tools) · [17 MCP servers](#17-allowed-mcp-servers-per-persona) · [18 Browser allowlist](#18-browser-allowlist) · [19 Antigravity settings](#19-antigravity-settings-cli-and-desktop) · [20 App Control and Sysmon](#20-app-control-and-sysmon-windows) · [21 Remote Desktop](#21-remote-desktop-windows) |
| Logging and evidence | [22 Saved queries](#22-saved-queries) · [23 Log retention](#23-log-retention) · [24 Alert e-mail](#24-alert-e-mail) |
| Region and project | [25 Region or project](#25-region-or-project) |
| — | [Not changeable in the POC](#not-changeable-in-the-poc) |

---

## People and devices

### 1. Add a laptop
- **What:** give one more laptop access. **Default:** the laptops in `poc/devices.csv`.
- **Where:** `poc/devices.csv`.
- **How:** 1. Add a line (`device,owner,persona,os`). 2. `python3 poc/poc_kit.py validate poc/devices.csv`. 3. `poc/poc-gateway.sh --yes`.
- **Reaches:** the gateway registers the laptop; a new kit `poc-kit/<device>.*` is written. Install it ([Part C](POC-STEP-BY-STEP.md#part-c-endpoint-admin)).
- **Check:** `poc/poc-gateway.sh --status` lists the laptop. **Undo:** [2](#2-remove-or-block-a-laptop).

### 2. Remove or block a laptop
- **What:** the laptop can no longer use the gateway (lost, stolen, end of POC).
- **Where:** `poc/devices.csv`.
- **How:** 1. Delete its line. 2. `poc/poc-gateway.sh --yes`. 3. Delete `poc-kit/<device>.*` and `poc/.state/certs/<device>.*`. 4. If you still have the laptop: uninstall it.
- **Reaches:** the gateway refuses the laptop at once (`401`, "Unmanaged device (fleet_device_unregistered)"). Its certificate stays technically valid until it expires (at most 30 days).
- **Check:** saved query "AGY - rejected devices …" shows its attempts. **Undo:** [1](#1-add-a-laptop) (new kit).

### 3. Change a laptop's persona
- **What:** move a laptop between `dev` and `contractor`.
- **Where:** `poc/devices.csv`, column `persona`.
- **How:** 1. Change the value. 2. `poc/poc-gateway.sh --yes`. 3. Re-run the install on that laptop with the new kit.
- **Reaches:** the gateway applies the new persona at once; the install moves the owner to the matching local group (`AGY-Dev` / `AGY-Contractor`, Mac `agy-dev` / `agy-contractor`) and installs that persona's rules. The owner signs out and in once.
- **Check:** the test shows the owner in the new group (Windows `P03`, Mac `M08`). **Undo:** change it back the same way.

### 4. Change a laptop's owner
- **What:** another person uses the laptop.
- **Where:** `poc/devices.csv`, column `owner` (the name the gateway logs), and the install's owner choice.
- **How:** 1. Change `owner`, run `poc/poc-gateway.sh --yes`. 2. On the laptop: **uninstall**, then install with the new kit as the new owner (signed in once; or `-User` / `--user`). Uninstalling first matters: a re-install alone adds the new owner but leaves the previous one in the persona group.
- **Check:** the test shows the new owner in the persona group. **Undo:** the same steps with the old owner.

### 5. Certificate lifetime
- **What:** how long a laptop certificate is valid. **Default:** 30 days (also the maximum).
- **Where:** the variable `CERT_DAYS` (1–30) when you run the script.
- **How:** `CERT_DAYS=14 poc/poc-gateway.sh --yes --reissue` (all certificates are re-issued with the new lifetime). Keep using `CERT_DAYS=14` on later runs, or new certificates get 30 days again.
- **Reaches:** new kits; re-install every laptop. **Check:** `--status` shows the days left. **Undo:** run without `CERT_DAYS` and with `--reissue`.

### 6. Renew certificates
- **What:** replace certificates before they expire.
- **How:** `poc/poc-gateway.sh --yes` renews every certificate with fewer than 7 days left; `--yes --reissue` renews all.
- **Reaches:** new kits; re-install the affected laptops. **Check:** `--status`; the laptop test shows the certificate check `PASS`.

## Cost

### 7. Budget amounts
- **What:** the monthly alert amount per persona. **Default:** your answers 4 and 5 (examples: 2000 / 1000, in the billing account currency).
- **Where:** the questions of `poc/poc-gateway.sh` (saved in `poc/.state/answers.env`).
- **How:** run `poc/poc-gateway.sh` **without** `--yes`; it asks again with your current answers as defaults; change answers 4 and 5, keep the others (press Enter).
- **Reaches:** cloud (budgets updated). **Check:** `--status` shows the new amounts. **Undo:** run again with the old values.

### 8. Budget alert thresholds
- **What:** when the budget alerts fire. **Default:** 50 %, 90 % and 100 %.
- **Where:** `terraform/zz-overrides.auto.tfvars` (the thresholds are fixed in the generated file, so this override is the only way).
- **How:** create the file with both personas (amounts here replace answers 4 and 5 from now on):
  ```hcl
  persona_budgets = {
    "dev"        = { amount = 2000, thresholds = [0.5, 0.75, 1.0] }
    "contractor" = { amount = 1000, thresholds = [0.5, 0.75, 1.0] }
  }
  ```
  Then `poc/poc-gateway.sh --yes`.
- **Reaches:** cloud. **Check:** `--status` (ALERTS column). **Undo:** delete the file and run `--yes`.

### 9. Model prices for the cost estimate
- **What:** the list prices used for `est_cost_usd` in `v_persona_usage` (an estimate; your invoice is the reference).
- **Where:** `poc/model-prices.json` (USD per million tokens, per model).
- **How:** 1. Edit the `input` / `output` values. 2. `poc/poc-gateway.sh --yes`.
- **Reaches:** cloud (the view). **Check:** query `v_persona_usage`. **Undo:** restore the file and run `--yes`.

## Models and AI checks

All these go into `terraform/custom.auto.tfvars`, followed by `poc/poc-gateway.sh --yes`. They change only the gateway: no laptop re-install. Check with the attack pack and the saved queries.

### 10. Models per persona
- **What:** which models each persona may use, and which model "Auto" picks. **Default:** developers all Gemini 4 Argon and Gemini 3.8 Flash levels; contractors only the three Flash levels; Auto: light / default / complex = Flash low / Flash medium / Argon high (contractors: Flash high).
- **Where:** variable `group_policy` (and `authorized_models` for the list of models). The map replaces the default, so always list **both** personas.
- **How:** for example, to cap developers at Flash too:
  ```hcl
  group_policy = {
    "agy-dev" = {
      allowed = ["gemini-3.8-flash-high", "gemini-3.8-flash-medium", "gemini-3.8-flash-low"]
      tiers   = { light = "gemini-3.8-flash-low", default = "gemini-3.8-flash-medium", complex = "gemini-3.8-flash-high" }
    }
    "agy-contractor" = {
      allowed   = ["gemini-3.8-flash-high", "gemini-3.8-flash-medium", "gemini-3.8-flash-low"]
      tiers     = { light = "gemini-3.8-flash-low", default = "gemini-3.8-flash-medium", complex = "gemini-3.8-flash-high" }
      pci_scope = true
    }
  }
  ```
- **Check:** saved query "AGY - model routing per persona …". **Undo:** remove `group_policy` from the file and run `--yes`.

### 11. Model Armor
- **What:** blocking prompts when Model Armor is unavailable. **Default:** `model_armor_fail_closed = true` (block).
- **How:** `model_armor_fail_closed = false` in `custom.auto.tfvars` (not recommended), then `--yes`.
- The Model Armor filter strictness is fixed in the POC (see [Not changeable](#not-changeable-in-the-poc)).

### 12. Sensitive data types and sensitivity
- **What:** which kinds of sensitive data are masked or blocked, and how sure the detector must be. **Default:** card numbers, IBAN, SWIFT, e-mail, phone, names, addresses, dates of birth, passports, several national ids, IP addresses, cloud credentials and tokens, passwords, keys, JWTs, cookies; likelihood `LIKELY`.
- **Where:** variables `sdp_info_types` (list; replaces the default) and `sdp_min_likelihood` (`POSSIBLE` | `LIKELY` | `VERY_LIKELY`; lower = more masking and more false positives).
- **How:** e.g. `sdp_min_likelihood = "POSSIBLE"`, then `--yes`. **Undo:** remove the line, `--yes`.

### 13. Mask or block sensitive data (PCI scope)
- **What:** for a persona, block a request or answer with sensitive data instead of masking it. **Default:** contractors block (`pci_scope = true`), developers mask.
- **Where:** `pci_scope` per persona in `group_policy` ([10](#10-models-per-persona); list both personas).
- **Check:** attack-pack scenario with a card number; saved query "AGY - sensitive data masked …" or "AGY - blocked …".

### 14. Blocked prompt topics and the AI classifier
- **What:** prompt topics the gateway blocks (port scanning, denial of service, DLP evasion, reconnaissance, credential theft, access-control evasion, endpoint tampering, mail impersonation, data exfiltration, ransomware, phishing) and the AI intent classifier.
- **Where:** `prompt_categories` (name → regular expression; the map replaces the default list, so copy the defaults from `terraform/variables.tf` and add or remove entries); `classifier_threshold` (default `0.7`); per persona `classifier = "enforce" | "audit" | "off"` and `blocked_categories` (the topics that apply to that persona; empty = all) inside `group_policy`.
- **Check:** saved query "AGY - blocked or flagged prompts …". **Undo:** remove the lines, `--yes`.

## Laptop rules

These change files in the repository. After editing: `poc/poc-gateway.sh --yes` rebuilds the kits, then re-install each laptop with its new kit.

### 15. Week 1 audit or enforce
- **What:** whether destructive commands and some workspace commands and file writes are only logged (audit) or blocked. **Default:** audit for new kits.
- **How:** after week 1: `HOOK_NOISY=enforce poc/poc-gateway.sh --yes`, then re-install every laptop. Keep `HOOK_NOISY=enforce` on every later run.
- **Check:** in the laptop test output, Mac `M02` shows "audit classes:" empty; the attack pack shows these scenarios as blocked. **Undo:** `poc/poc-gateway.sh --yes` without it, re-install.

### 16. Protected paths, blocked commands, blocked tools
- **What:** add folders the agent may not touch, commands it may not run, or agent tools it may not use, for all laptops or one persona.
- **Where:** two files, one per platform: `endpoint/files/hooks/policy.json` (Macs) and `windows/files/hooks/policy.windows.json` (Windows). Section `default` = everyone; section `groups` → `agy-dev` / `agy-contractor` = that persona only (added to the defaults).
- **How:**
  1. Protected path: add it to `deny_paths` (for example `"~/customer-data"`).
  2. Blocked command: copy an existing entry of `deny_commands` in the same file (for example the one with `ngrok|cloudflared|…`) and replace the names inside the parentheses with your command. Keep the start of the entry unchanged: it makes the rule also catch wrapped forms.
  3. Blocked tool: add the tool name to `deny_tools`.
  4. Check the file is valid: `python3 -m json.tool endpoint/files/hooks/policy.json > /dev/null` (same for the Windows file).
  5. `poc/poc-gateway.sh --yes`, re-install the laptops.
- **Note:** the Windows file is generated by `windows/files/hooks/gen-policy.py`. If someone regenerates it later, your direct edits are lost; keep a copy of your changes.
- **Check:** ask the agent to do the blocked action: "Blocked by corporate policy …". **Undo:** restore the `.orig` files, `--yes`, re-install.

### 17. Allowed MCP servers per persona
- **What:** which MCP servers (agent plug-ins) the agent may use. **Default:** none.
- **Where:** two places, both needed: the server definition in `endpoint/files/policies/agy-dev.mcp_config.json` (or `agy-contractor…`), and the server name in `mcp_allowed_servers` of both hook files ([16](#16-protected-paths-blocked-commands-blocked-tools)).
- **How:**
  1. Add the server under `"mcpServers"` in the persona's `mcp_config.json`.
  2. Add its name to `mcp_allowed_servers`: in `groups` → `agy-dev` for developers only (a persona's list replaces the default list), or in `default` for everyone.
  3. `python3 windows/gen-policies.py` (copies the MCP and settings files to the Windows bundle).
  4. `poc/poc-gateway.sh --yes`, re-install the laptops.
- **Check:** the agent can call the server; other servers are still blocked. **Undo:** restore the files, repeat steps 3–4.

### 18. Browser allowlist
- **What:** extra web sites the agent's browser may open (besides `localhost` and `127.0.0.1`). **Default:** none.
- **Where (Windows):** the laptop's policy registry key.
- **How (Windows, as administrator on the laptop):** `reg add "HKLM\SOFTWARE\Policies\AGY" /v agy-browser-allowlist /t REG_SZ /d "docs.example.com,*.example.com" /f`
- **Reaches:** the laptop's policy task applies it within 5 minutes (also after a re-install, because the registry wins over the kit settings).
- **Undo:** `reg delete "HKLM\SOFTWARE\Policies\AGY" /v agy-browser-allowlist /f`.
- **Macs:** see [Not changeable](#not-changeable-in-the-poc).

### 19. Antigravity settings (CLI and Desktop)
- **What:** the locked Antigravity settings per persona: commands that need approval or are denied, sandbox, workspace access, review policy, telemetry. CLI and Desktop use the same managed files.
- **Where:** `endpoint/files/policies/agy-dev.settings.json` / `agy-contractor.settings.json` (source for both platforms).
- **How:**
  1. Edit the persona's file; check it with `python3 -m json.tool <file> > /dev/null`.
  2. `python3 windows/gen-policies.py` (generates the Windows copies).
  3. `poc/poc-gateway.sh --yes`, re-install the laptops.
- **Do not change** `admin_settings.json` (it points Antigravity to the local proxy).
- **Undo:** restore the file, repeat steps 2–3.

### 20. App Control and Sysmon (Windows)
- **What:** application control (AppLocker per persona + WDAC in audit) and Sysmon. **Default:** off.
- **How:** re-install the laptop with `-AppControl` and / or `-Sysmon`: `powershell -ExecutionPolicy Bypass -File .\install-windows.ps1 -Install -AppControl -Sysmon`.
- **Check:** the test no longer shows these checks as `SKIP`.
- **Undo:** uninstall, then install without the options (a re-install alone doesn't remove an applied AppLocker policy).

### 21. Remote Desktop (Windows)
- **What:** who may use Remote Desktop. **Default:** administrators only (`admins`).
- **How (on the laptop, as administrator):** `reg add "HKLM\SOFTWARE\Policies\AGY" /v agy-rdp /t REG_SZ /d on /f` (`on` = also the device owner; `off` = Remote Desktop not enabled by AGY).
- **Reaches:** applied within 5 minutes. The POC check for Remote Desktop then reports `FAIL`, because it expects `admins`.
- **Undo:** `reg delete "HKLM\SOFTWARE\Policies\AGY" /v agy-rdp /f`.

## Logging and evidence

### 22. Saved queries
- **What:** the five shared "AGY - …" queries in Log Analytics. **Default:** on.
- **How (to remove them):** `enable_saved_queries = false` in `terraform/zz-overrides.auto.tfvars`, then `--yes`. Changing a query's content isn't possible in the POC; save your own copy in Log Analytics instead.

### 23. Log retention
- **What:** how long logs are kept. **Default:** security log bucket 30 days (`log_retention_days`), SIEM 400 days (`siem_retention_days`), audit logs 400 days (`audit_log_retention_days`).
- **How:** set the variable in `terraform/custom.auto.tfvars` (for example `siem_retention_days = 90`), then `--yes`.
- **Do not** set `log_lock_days` in the POC: locking a log bucket is irreversible.
- **Undo:** remove the line, `--yes`.

### 24. Alert e-mail
- **What:** the address for budget and security alerts (question 3; it is also the operator account).
- **How:** run `poc/poc-gateway.sh` without `--yes` and change answer 3 (keep the others).
- **Check:** a test alert arrives. **Undo:** the same with the old address.

## Region and project

### 25. Region or project
- Not changeable in place. Finish with the old project first (uninstall the laptops, `poc/poc-gateway.sh --destroy`), then run `poc/poc-gateway.sh` again and give the new project or region (answers 1 and 2). New kits for every laptop.

---

## Not changeable in the POC

| Setting | Why | Workaround |
|---|---|---|
| Model Armor filter strictness (confidence levels for harmful content, prompt injection / jailbreak, malicious links) | Fixed in the Terraform code; a change in the console is reset by the next `--yes` | None in the POC |
| Content of the saved queries | Defined in the Terraform code | Save your own query copy in Log Analytics |
| Browser allowlist on Macs | The kit has no setting for it; the Terraform `browser_allowlist` doesn't reach POC laptops | Before installing, add `"browser_allowlist": "docs.example.com"` to the kit's `poc.json` (lost when the kit is rebuilt) |
| Laptop layer defaults set by the install script (`agy-rdp`, egress firewall, hosts entries) | Written by the script on every install | Windows: registry overrides ([18](#18-browser-allowlist), [21](#21-remote-desktop-windows)) |
| Gateway name (`gateway.agy.internal`) | Not part of the 6 questions | Nothing to do: the laptops pin it in their hosts file |
| Turning off critical hook rules (secrets, protected paths, review bypass, remote scripts) | Always enforced by design, also in audit mode | — |
| Directory (AD / Entra) groups as personas | The POC uses local groups only | — |
