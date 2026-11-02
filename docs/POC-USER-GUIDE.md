# POC user guide: Antigravity on your laptop

For developers and contractors in the Antigravity POC. Your IT team installed the corporate controls on your laptop (they follow [POC-STEP-BY-STEP.md](POC-STEP-BY-STEP.md)). This page explains what changes for you.

## What changes for you

| Topic | What to expect |
|---|---|
| First start | Sign out and in once after IT installed the POC. Start `agy` from a terminal with your normal (standard) account; it doesn't run for administrator accounts or for other people on your laptop |
| First minute | Right after your first sign-in you may see "AGY policy not applied yet for this user - it applies within a minute of sign-in; try again". Wait a minute and retry |
| Windows 10 laptops | No terminal sandbox: the agent asks your approval for every command, except allow-listed read-only commands |
| Approvals | The agent asks before some steps (for example `git commit`, `git push`, `npm publish`). Read the request before you approve. Sessions that skip human review are not allowed |
| Blocked actions | Some actions are blocked, with the reason in the conversation: for example reading SSH keys, `.env` files or browser passwords, uploads to external hosts, downloaded scripts piped into a shell, deleting your home folder. Destructive commands: run them yourself in your terminal |
| Models | Developers: Flash and the approved Pro model. Contractors: Flash models only, and no web search, URL reading or browser tools |
| Network | The agent reaches the models only through the corporate gateway (over the VPN when you work remotely) |

In the first week some rules only log instead of blocking, so the POC team can spot false blocks. After that they block.

## What still works

Your normal tools: Teams, Outlook, browser, IDE, Git and your build tools. You can still do yourself what the agent may not do.

## What is logged

- Prompts are inspected at the corporate gateway (secrets, personal data, policy topics) before they reach the model; blocked or masked prompts are logged.
- Blocked agent actions on your laptop, with time and reason.
- Token usage and estimated cost per persona and laptop.

The logs stay in the EU, with restricted access for the POC team, and are used to evaluate the POC. Don't put production secrets or customer personal data into prompts.

## Attack-pack tests

IT copies an `attack-pack` folder into your profile (Windows) or home folder (Mac). When the POC lead asks, open a terminal with your normal account and run (use `dev` or `contractor`, as told):

```powershell
# Windows
cd attack-pack; & "C:\Program Files\Python312\python.exe" runner.py run --mode live --os windows --persona dev --out results\
```

```bash
# Mac
cd attack-pack && /usr/bin/python3 runner.py run --mode live --os macos --persona dev --out results/
```

It prints each test prompt and what to note. Give the prompts to the agent, write down what happened (blocked, asked, allowed) and send your notes and the `results` folder to the POC lead.

## Report a false block, or get help

If the agent was blocked during normal work, or something doesn't work, contact the POC lead (or your IT contact for the POC) with:

1. Date and time.
2. What you asked the agent to do (and in which repository).
3. The exact message you saw.
