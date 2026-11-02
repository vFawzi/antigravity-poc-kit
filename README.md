# Antigravity pay-as-you-go POC

Based on Antigravity secure endpoint 2.1.0.

> **Start here:** [docs/POC-STEP-BY-STEP.md](docs/POC-STEP-BY-STEP.md) takes you from zero to a finished POC, one role at a time.

A proof of concept for Google Antigravity (agentic AI coding) on your own laptops, with pay-as-you-go Gemini models through a gateway in your own Google Cloud project. The POC proves that:

- the agent's dangerous actions are blocked on the laptop (secrets, uploads, downloaded scripts, destructive deletes, unapproved tools);
- prompts are inspected before they reach the model (secrets, personal data, policy topics);
- standard users can't switch the controls off or remove them;
- evidence exists on each laptop and centrally in your project;
- cost is visible per persona (developer, contractor) and per laptop, with budget alerts.

> [!IMPORTANT]
> This is a reference implementation, not an officially supported Google product. Review, adapt and test it before you rely on it. See [NOTICE](NOTICE) and [SECURITY.md](SECURITY.md).

## Who does what

| Role | Does |
|---|---|
| POC lead | Plans the POC, lists the laptops, follows the results, shares the evidence with your Google contact |
| Cloud admin | Deploys the gateway in Google Cloud and creates one kit per laptop |
| Billing admin | Gives the installer the right to create budget alerts |
| Network / VPN team | Connects your network to the POC project (VPN) |
| Endpoint admin | Installs each laptop with its kit |

## Read this if you are…

| You are | Read |
|---|---|
| Anyone, first | [POC-STEP-BY-STEP.md](docs/POC-STEP-BY-STEP.md) |
| Preparing the POC | [POC-PREREQUISITES.md](docs/POC-PREREQUISITES.md) (checklist per team) |
| Security or cloud reviewer | [POC-PERMISSIONS.md](docs/POC-PERMISSIONS.md) (every permission and change) |
| An admin who wants the commands only | [POC-ADMIN-GUIDE.md](docs/POC-ADMIN-GUIDE.md) |
| An admin who wants to understand or change the controls | [POC-HOW-IT-WORKS.md](docs/POC-HOW-IT-WORKS.md), [POC-CHANGING-SETTINGS.md](docs/POC-CHANGING-SETTINGS.md) |
| A network team with an existing Shared VPC | [POC-SHARED-VPC.md](docs/POC-SHARED-VPC.md) |
| An endpoint admin with Windows 10 laptops | [POC-WINDOWS-10.md](docs/POC-WINDOWS-10.md) |
| Looking for details or troubleshooting | [POC-TECHNICAL-REFERENCE.md](docs/POC-TECHNICAL-REFERENCE.md) |
| A developer or contractor in the POC | [POC-USER-GUIDE.md](docs/POC-USER-GUIDE.md) |

## The six steps

1. **Prepare:** project, billing, VPN, laptops and the list of laptops ([Part A](docs/POC-STEP-BY-STEP.md#part-a-before-you-start)).
2. **Get the repository and grant permissions:** clone or download this repository in Cloud Shell, then the installer role and billing role ([Part B](docs/POC-STEP-BY-STEP.md#part-b-cloud-admin)).
3. **Deploy:** run one script in Cloud Shell, answer 6 questions; you get one kit per laptop ([Part B](docs/POC-STEP-BY-STEP.md#part-b-cloud-admin)).
4. **Install the laptops:** one install command and one test command per laptop ([Part C](docs/POC-STEP-BY-STEP.md#part-c-endpoint-admin)).
5. **Run the POC:** one week in audit mode, then enforce; daily look at the results; attack tests ([Part D](docs/POC-STEP-BY-STEP.md#part-d-poc-lead-during-the-poc)).
6. **Finish:** collect and share the evidence, clean up ([Part E](docs/POC-STEP-BY-STEP.md#part-e-finish)).

## Time and cost

| | |
|---|---|
| Cloud deployment | About 25–30 minutes (about 5 minutes on re-runs) |
| Per laptop | Windows 3–6 minutes, Mac a few minutes; no reboot |
| POC duration | Week 1 in audit mode, then enforce: plan at least two weeks |
| Fixed cloud cost | About EUR 75–110 per month (load balancer, certificate authority, gateway, logging) |
| Model calls | Pay per use, with a budget alert per persona |

The full reference architecture (setup wizard, modules, device packages, production guides) is published in a separate repository.
