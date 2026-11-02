#!/usr/bin/env python3
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

"""Generates policy.windows.json (agy-hook policy for Windows workstations). Run: python3 gen-policy.py > policy.windows.json

Regexes are matched case-insensitively on Windows (agy-hook WIN mode) against the full command line, so the command
position prefix also catches cmd /c, powershell -Command, start/call and '&' (PowerShell call operator) wrappers."""
from __future__ import annotations

import json

# command position: start, separator, quote, or an inline shell (cmd /c, powershell|pwsh [-flags] -c|-Command)
POS = (r"(?:^|[;|&(){}'\"]|\b(?:cmd(?:\.exe)?\s+/[ck]|(?:powershell|pwsh)(?:\.exe)?\s+(?:-\S+\s+)*?-c(?:ommand)?)\s)"
       r"\s*(?:&\s*)?(?:(?:start|call)\s+(?:/\S+\s+)*)?(?:\S*[\\/])?")
END = r"(?:\.exe|\.com)?(?=\s|$|[\"');|&])"


def cmd(names: str, tail: str = "") -> str:
    return f"{POS}(?:{names}){END}{tail}"


def ps_upload() -> list[str]:
    return [
        cmd("iwr|irm|invoke-webrequest|invoke-restmethod", r"[^;|&]*\s-(?:method\s+(?:post|put|patch)|infile|body)\b"),
        cmd("curl", r"[^;|&]*\s(?:-d|--data\S*|-F|--form\S*|-T|--upload-file|--json)(?:\s|=|$)"),
    ]


# inbound tunnels bypass IAP and the egress allowlist
TUNNELS = "ngrok|cloudflared|devtunnel|localtunnel|lt|bore|frpc"
TUNNEL_SUB = [("code|code-insiders", r"\s+tunnel\b"), ("tailscale", r"\s+(?:funnel|serve)\b")]

DEFAULT_DENY = [
    cmd(TUNNELS), *(cmd(n, t) for n, t in TUNNEL_SUB),
    cmd("ssh|scp|sftp|plink|pscp|psftp|putty|telnet|nc|ncat|netcat|socat|nmap|mstsc"),
    cmd("powershell|pwsh", r"[^;|&]*\s-e(?:nc(?:odedcommand)?)?\s"),
    cmd("iex|invoke-expression|add-type"),
    *ps_upload(),
    cmd("start-bitstransfer|bitsadmin"),
    cmd("certutil", r"[^;|&]*\s[-/](?:urlcache|encode|decode|f)\b"),
    cmd("cipher", r"[^;|&]*\s/[ewx]\b"),
    cmd("vssadmin|wbadmin|wmic", r"[^;|&]*\s(?:delete|shadowcopy)\b"),
    cmd("set-mppreference|add-mppreference"),
    cmd("netsh", r"[^;|&]*\s(?:advfirewall|firewall|interface\s+portproxy)\b"),
    cmd("runas|psexec|gsudo|sudo"),
    cmd("reg", r"[^;|&]*\s(?:add|delete|import|load)\b"),
    cmd("set-executionpolicy|new-service|sc|schtasks|bcdedit"),
    cmd("gpg|sdelete"),
    r"\\\\tsclient\\",
    r"C:[\\/]+ProgramData[\\/]+Antigravity",
]

# ---- elevation and persistence (agent only; the human uses the catalog / pre-provisioned rights) -------------------
# container options that escape to the host (shared with the Linux policy: same tail, own command-position prefix)
CONTAINER_TOOLS = "docker|podman|nerdctl"
CONTAINER_ESCAPE = (r"[^;|&]*(?:\s(?:--privileged|--cap-add|--device)\b|\s--(?:pid|network|net|ipc|userns|uts)[= ]host\b"
                    r"|\s--security-opt[= ]\S*unconfined|\s(?:-v|--volume)[= ]?['\"]?/:|docker\.sock|docker_engine"
                    r"|\s--mount[= ]\S*source=/[,\s])")
REG_PATH = r"[^;|&]*(?:\b(?:hkcu|hklm|hkcr|hku|hkcc):|registry::)"
ELEVATION_WIN = [
    cmd("start-process|saps|start", r"[^;|&]*\s-verb\s+['\"]?runas\b"), r"\.verb\s*=\s*['\"]runas['\"]",
    r"-comobject\s+['\"]?shell\.application\b", r"\binvokeverb(?:ex)?\b", r"\bshellexecute(?:ex)?\b",
    cmd("invoke-command|icm|enter-pssession|etsn|new-pssession|nsn|winrs|enable-psremoting"),
    cmd("register-scheduledtask|new-scheduledtask|new-scheduledtaskaction|new-scheduledtasktrigger|set-scheduledtask"),
    r"schedule\.service",
    cmd("set-service|start-service|sasv|stop-service|spsv|restart-service|suspend-service"), r"\bwin32_service\b",
    cmd("new-item|ni|new-itemproperty|set-itemproperty|sp|set-item|si|remove-item|ri|rm|del|erase|remove-itemproperty|rp"
        "|rename-item|rni|rename-itemproperty|rnp|copy-item|cpi|cp|copy|move-item|mi|mv|move", REG_PATH),
    r"\[microsoft\.win32\.registry(?:key)?\]",
    cmd("setx"), r"\bsetenvironmentvariable\b",
    r"(?:>{1,2}\s*|(?:set-content|add-content|out-file|tee-object|tee|new-item|copy-item|move-item)\b[^;|&]*)\$profile\b",
    cmd("import-certificate|import-pfxcertificate", r"[^;|&]*\broot\b"), r"\bx509store\b[^;|&]*\broot\b",
    cmd("dotnet", r"\s+dev-certs\s+https\b[^;|&]*\s--trust\b"), cmd("certutil", r"[^;|&]*\s[-/]addstore\b"),
    cmd("winget", r"\s+(?:install|upgrade|source|import|configure|uninstall)\b"), cmd("choco|chocolatey|scoop"),
    cmd("msiexec", r"[^;|&]*\s/(?:i|a|j|x|package|uninstall|update|p)\b"),
    cmd("vs_installer|vs_installershell|vs_setup|vs_enterprise|vs_professional|vs_community|vs_buildtools"),
    cmd("dism|pnputil"),
    cmd("enable-windowsoptionalfeature|disable-windowsoptionalfeature|add-windowscapability|install-windowsfeature"
        "|add-windowsfeature|add-appxpackage|add-appxprovisionedpackage"),
    cmd("install-module|install-psresource|install-package|install-script", r"[^;|&]*\s-scope\s+allusers\b"),
    r"root\\+ccm\\+clientsdk",
    cmd("wsl", r"[^;|&]*\s(?:-u|--user)\s+root\b"), cmd("wsl", r"[^;|&]*\s--(?:import|import-in-place|mount|debug-shell|install)\b"),
    cmd(CONTAINER_TOOLS, CONTAINER_ESCAPE),
    cmd("get-credential"),
]
# Linux: names / tails used with the Linux command-position prefix (see the Linux policy.json)
ELEVATION_LINUX_NAMES = "run0|machinectl|systemd-run|newgrp|sg|setcap|usermod|gpasswd|at|chsh|chfn|update-ca-certificates"
ELEVATION_LINUX_TAILS = [("loginctl", r"\s+enable-linger\b"), ("sysctl", r"\b[^;|&]*\s-w\b"),
                         ("certutil", r"\b(?=[^;|&]*\s-d\s+['\"]?sql:)[^;|&]*\s-[ADEMN]\b"), ("trust", r"\s+anchor\b"),
                         ("crontab", r"(?!\s+-l(?:\s|$))(?:\s|$)"),   # listing (-l) stays allowed
                         (CONTAINER_TOOLS, CONTAINER_ESCAPE)]
# Startup folder / profile scripts: never written by the agent (file tools and shell writes)
PERSISTENCE_WRITE_FILES = ["Start Menu/Programs/Startup/**", "*profile.ps1", ".bashrc", ".bash_profile", ".profile",
                           ".zshrc", ".zprofile", ".pam_environment", ".config/autostart/**", ".config/systemd/**",
                           ".config/environment.d/**", ".local/share/applications/**", ".pki/**",
                           # macOS launchd: ~/Library/LaunchAgents, /Library/LaunchAgents, /Library/LaunchDaemons
                           "Library/LaunchAgents/**", "Library/LaunchDaemons/**"]

# credentials in agent-written file content (write / edit tools): never on disk in the workspace
B64 = "A-Za-z0-9/+="
DENY_WRITE_SECRETS = [
    {"name": "aws_access_key",
     "regex": (rf"\b(?:AKIA|ASIA)[0-9A-Z]{{16}}\b[\s\S]{{0,300}}?(?<![{B64}])(?=[{B64}]*[a-z])(?=[{B64}]*[A-Z])[{B64}]{{40}}"
               rf"(?![{B64}])|(?<![{B64}])(?=[{B64}]*[a-z])(?=[{B64}]*[A-Z])[{B64}]{{40}}(?![{B64}])[\s\S]{{0,300}}?"
               rf"\b(?:AKIA|ASIA)[0-9A-Z]{{16}}\b")},
    {"name": "gcp_service_account_key",
     "regex": r"(?s)\A(?=.*\"type\"\s*:\s*\"service_account\")(?=.*\"private_key\"\s*:\s*\"-----BEGIN)"},
    {"name": "private_key",
     "regex": (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----(?:\s|\\[nr])+"
               r"(?:[A-Za-z0-9+/=]{16,}|Proc-Type:|Version:|Comment:)")},
    {"name": "github_token", "regex": r"\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{50,}"},
    {"name": "gitlab_token", "regex": r"\bglpat-[A-Za-z0-9_-]{20,}"},
    {"name": "slack_token", "regex": r"\bxox[baprs]-[A-Za-z0-9-]{10,}"},
    {"name": "google_api_key", "regex": r"\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"},
    {"name": "azure_storage_key", "regex": r"(?i)AccountKey=[A-Za-z0-9+/]{60,}={0,2}"},
    {"name": "jwt", "regex": r"\beyJ(?=[A-Za-z0-9_.-]{97,})[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{16,}"},
]

DESTRUCTIVE = [
    cmd("remove-item|ri|rm|del|erase|rd|rmdir", r"[^;|&]*\s(?:-r(?:ecurse)?|/s)\b"),
    cmd("format|diskpart|clear-disk|remove-partition"),
    cmd("git", r"\s+clean\s[^;|&]*-[a-z]*f"),
    cmd("git", r"\s+(?:reset\s+--hard|push\s[^;|&]*(?:--force|-f)(?:\s|$))"),
    cmd("rimraf"), cmd("npx|pnpx|bunx", r"\s+(?:-\S+\s+)*rimraf\b"),
    cmd("python|python3|py|node", r"\s+(?:-\S+\s+)*-[ce]\s.*?(?:rmtree|rmSync|rmdirSync|removedirs)\s*\("),
]

# ---- shared with the Linux policy.json (a unit test keeps both identical) --------------------------------------
# configuration that executes code or redirects the supply chain: the agent may not write it (the developer may)
DENY_WRITE_FILES = [
    ".git/hooks/**", ".git/config", ".gitmodules", ".envrc",
    "nuget.config", ".npmrc", ".yarnrc", ".yarnrc.yml", ".pnpmfile.cjs", "pip.conf", "pip.ini", ".pypirc",
    ".terraformrc", "terraform.rc", ".devcontainer/**", "devcontainer.json", ".vscode/**", ".idea/**",
    "*.code-workspace", "Directory.Build.props", "Directory.Build.targets", "Directory.Build.rsp",
    "Directory.Packages.props", "*.targets", ".github/workflows/**", ".github/actions/**", "azure-pipelines*.yml",
    "azure-pipelines*.yaml", "cloudbuild*.yaml", "cloudbuild*.yml", ".gitlab-ci.yml", "Jenkinsfile",
    ".pre-commit-config.yaml", ".husky/**", "AGENTS.md", "GEMINI.md", "mcp_config.json", ".mcp.json",
    # binaries: developers may run their own builds from the build root; the agent may not drop / copy binaries there
    "*.exe", "*.dll", "*.com", "*.scr", "*.msi", "*.sys", "*.cpl",
]
# project files: allowed, but not with new build-time code
EXEC_CONTENT_FILES = ["*.csproj", "*.vbproj", "*.fsproj", "*.vcxproj", "*.proj", "*.props", "package.json"]
EXEC_CONTENT_PATTERNS = [
    r"(?i)<\s*Exec\b", r"(?i)<\s*UsingTask\b", r"(?i)\bTaskFactory\b",
    r"\"(?:pre|post)?install\"\s*:", r"\"prepare\"\s*:", r"\"(?:pre|post)(?:pack|publish)\"\s*:", r"\"prepublish(?:Only)?\"\s*:",
]
DENY_CONFIG_COMMANDS = [
    r"(?i)\b(?:npx|pnpx|bunx|dlx)(?:\.cmd)?\s+(?:-\S+\s+)*(?:localtunnel|lt|ngrok|cloudflared)(?:@\S*)?(?:\s|$)",  # tunnels via runners
    r"(?i)\bgit(?:\.exe)?\s+(?:-\S+\s+)*config\b(?![^;|&]*\s(?:--get\S*|--list|-l|--show-origin|--show-scope)(?:\s|$))",
    r"(?i)\bgit(?:\.exe)?\s[^;|&]*-c\s+['\"]?(?:core\.(?:hookspath|fsmonitor|sshcommand|pager|editor|askpass)|credential\.|url\.|http\.proxy|include\.)",
    r"(?i)\bgit(?:\.exe)?\s+remote\s+(?:add|set-url)\b",
    r"(?i)\b(?:npm|pnpm|yarn)(?:\.cmd)?\s+config\s+(?:set|delete|edit)\b",
    r"(?i)\bnpm(?:\.cmd)?\s+set\s",
    r"(?i)\bpip3?(?:\.exe)?\s+config\s+(?:set|unset|edit)\b",
    r"(?i)\bdotnet(?:\.exe)?\s+nuget\s+(?:add|update|enable)\s+source\b",
    r"(?i)\bnuget(?:\.exe)?\s+sources?\s+(?:add|update|enable)\b",
    r"(?i)\s--(?:registry|index-url|extra-index-url|trusted-host)(?:[= ]|$)",
    r"(?i)\bdotnet(?:\.exe)?\s[^;|&]*\s(?:-s|--source|--add-source)\s",
]
GCLOUD_DENY_VERBS = [
    "auth print-access-token", "auth print-identity-token", "auth application-default print-access-token",
    "auth application-default login", "auth login", "auth activate-service-account", "auth revoke",
    "iam service-accounts keys create", "config set", "config unset", "config configurations activate",
    "config configurations create", "secrets versions access",
]
# sessions that skip human review: client options are read from the process tree; these payload fields are checked
# too in case the client reports its permission / agent mode to hooks (field names logged as payload_keys)
REVIEW_BYPASS_PAYLOAD = {
    "permissionMode": ["auto", "accept-edits", "bypassPermissions", "dangerously-skip-permissions", "always-proceed"],
    "agentMode": ["auto", "accept-edits"], "executionMode": ["auto", "accept-edits"],
    "skipPermissions": [True], "dangerouslySkipPermissions": [True], "skipPermissionChecks": [True],
}
CONTRACTOR_WRITE_FILES = ["*.csproj", "*.vbproj", "*.fsproj", "*.props", "*.sln", "package.json"]

# ---- remote script execution: a network download fed straight into an interpreter (never reviewed, never on disk) --
# interpreter reading the script from stdin: no arguments, only flags, or '-' / '--' (e.g. bash -s -- args)
INTERP_TAIL = r"(?:\s+-[A-Za-z]+)*(?:\s+--?(?=\s|$|['\"])|\s*(?=$|[;&|)]|['\"]\s*(?:$|[;&|)])))"
DOWNLOADERS_WIN = "iwr|irm|invoke-webrequest|invoke-restmethod|curl|wget|start-bitstransfer"
REMOTE_EXEC_WIN = [
    cmd(DOWNLOADERS_WIN, r"[^;&]*\|\s*(?:&\s*)?(?:iex|invoke-expression)\b"),
    cmd(DOWNLOADERS_WIN, r"[^;&]*\|\s*(?:&\s*)?(?:\S*[\\/])?(?:powershell|pwsh|cmd|python\d*|py|node|perl|ruby|bash|sh)"
                         r"(?:\.exe)?" + INTERP_TAIL),
    r"(?:\biex\b|\binvoke-expression\b|\[scriptblock\]::create)[^;|&]*\.download(?:string|data)\b",
    r"\.download(?:string|data)\b[^;&]*\|\s*(?:&\s*)?(?:iex|invoke-expression)\b",
    cmd("powershell|pwsh", r"[^;|&]*\s-c(?:ommand)?\s+[\"'(&$\s]*(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b"),
]
# git push straight to a URL, scp-style address or path (code to an unreviewed destination); named remotes unchanged
GIT_PUSH_DIRECT = cmd("git", r"[^;&|]*?\spush\b[^;&|]*?(?:\s--repo[= ]|\s['\"]?(?:(?:https?|ssh|git|file|ftps?)://"
                             r"|[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:|[A-Za-z]:[\\/]|\\\\|[/~]|\.\.?[\\/]))")

DEFAULT_DENY = DEFAULT_DENY + ELEVATION_WIN + REMOTE_EXEC_WIN + [GIT_PUSH_DIRECT]
DENY_WRITE_FILES = DENY_WRITE_FILES + [g for g in PERSISTENCE_WRITE_FILES if g not in DENY_WRITE_FILES]
# sessions run elevated / by admins: deny everything (agy must run as a standard user)
ELEVATED_GROUPS_LINUX = ["sudo", "wheel", "admin", "docker", "libvirt", "lxd"]

POLICY = {
    "_comment": ("Policy for agy-hook on Windows (C:\\ProgramData\\Antigravity\\hooks\\policy.json, Administrators-only "
                 "ACL). Generated by gen-policy.py - edit there. Regexes are case-insensitive on Windows. Same schema as "
                 "the Linux policy.json."),
    "default": {
        "deny_commands": DEFAULT_DENY,
        "deny_paths": [
            "C:/ProgramData/Antigravity", "C:/ProgramData/agy-credproxy", "C:/Windows/System32/config",
            "C:/secure-admin", "C:/Users/Administrator", "C:/Program Files/CorpTools",
            "~/.ssh", "~/.aws", "~/.docker", "~/.kube", "~/.git-credentials", "~/.netrc",
            "~/AppData/Roaming/gcloud", "~/AppData/Roaming/GitHub CLI", "~/AppData/Roaming/Microsoft/Credentials",
            "~/AppData/Local/Microsoft/Credentials", "~/AppData/Roaming/Microsoft/Protect",
        ],
        "deny_tools": [],
        "ask_commands": [],
        "workspace_only_commands": ["icacls", "takeown"],
        "deny_file_globs": [".env", ".env.*", "*.env", "*.pem", "id_rsa", "id_ed25519", "*.p12", "*.pfx", "credentials.json"],
        "allow_file_globs": [".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults", "*.env.example",
                             "*.env.sample", "*.env.template"],
        "deny_sandbox_bypass": True,
        "deny_write_dirnames": [".agents", ".gemini", ".antigravity"],
        "workspace": "D:/projects/{user}",
        "write_tools": "(write|edit|replace|create|delete|remove|move|rename|patch|append|save)",
        "write_also": ["~/.gemini/antigravity-cli/brain"],
        "deny_write_files": DENY_WRITE_FILES,
        "exec_content_files": EXEC_CONTENT_FILES,
        "exec_content_patterns": EXEC_CONTENT_PATTERNS,
        "deny_config_commands": DENY_CONFIG_COMMANDS,
        "gcloud_deny_verbs": GCLOUD_DENY_VERBS,
        "agent_service_account": "",
        "deny_review_bypass": True,
        "deny_elevated_session": True,
        "elevated_groups": ELEVATED_GROUPS_LINUX,
        "review_bypass_payload": REVIEW_BYPASS_PAYLOAD,
        # rule classes whose denies are only logged (AUDIT_ALLOW) and allowed: destructive, workspace_write,
        # workspace_commands (see agy-hook AUDITABLE); [] = enforce all
        "audit_classes": [],
        # MCP servers the agent may call (hook check; a group list replaces this one); [] = none
        "mcp_allowed_servers": [],
        "deny_write_secrets": DENY_WRITE_SECRETS,
    },
    "groups": {
        "agy-dev": {
            "ask_commands": DESTRUCTIVE,
            "ask_as_deny": True,   # Auto mode is invisible to hooks: destructive commands are run by the human
            "cli_ask_prefixes": ["Remove-Item", "rm", "del", "erase", "rd", "rmdir", "ri", "Move-Item", "move",
                                 "git clean", "git reset --hard", "git push"],
        },
        "agy-contractor": {
            "deny_tools": ["read_url_content", "search_web", "browser_.*"],   # same as the Linux contractor group
            "deny_write_files": CONTRACTOR_WRITE_FILES,
            "deny_commands": DESTRUCTIVE + [
                cmd("curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|robocopy|ftp|tftp") + r"|\bnet\s+use\b",
            ],
        },
    },
}

if __name__ == "__main__":
    print(json.dumps(POLICY, indent=2))
