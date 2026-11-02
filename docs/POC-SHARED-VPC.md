# POC with a Shared VPC

By default the POC creates its own network (VPC) in the POC project. If your company already has a **Shared VPC** that your on-premises network can reach, the gateway can use a subnet of that network instead. Run the POC: [POC-STEP-BY-STEP.md](POC-STEP-BY-STEP.md) (question 7 in step B5).

## When to choose it

| Choose | When |
|---|---|
| New VPC (question 7: `1` or Enter, the default) | You will connect a VPN or Interconnect to the new POC network |
| Existing Shared VPC (question 7: `2`) | Your on-premises network already reaches a Shared VPC; the network team shares one subnet with the POC project |

## What the network team provides

| # | Item | Check |
|---|---|---|
| 1 | Shared VPC enabled on the host project (for example `net-host-project`), and the POC project (`my-poc-project`) attached as a service project | Preflight: "shared VPC: project attached" |
| 2 | A regular (private) subnet in the POC region, shared with the POC project, in a range your on-premises network already allows, with at least one free IP | Preflight: "shared subnet: network and region" |
| 3 | A proxy-only subnet (purpose `REGIONAL_MANAGED_PROXY`, role `ACTIVE`, /26 or larger) in the same network and region | Preflight: "shared VPC: proxy-only subnet" |
| 4 | **Compute Network User** for the installer on that one subnet (not on the whole host project) | Preflight: "shared subnet: installer may use it" |
| 5 | The organisation policies `compute.restrictSharedVpcHostProjects` and `compute.restrictSharedVpcSubnetworks` allow this host and subnet | Preflight: "org policy compute.restrictSharedVpc…" |
| 6 | Routing from on-premises to the subnet. If the VPN / Interconnect ends in **another region**: global dynamic routing on the VPC, and answer **7f = yes** | Laptop self-test (gateway check) |
| 7 | The corporate firewall allows TCP 443 from the POC laptops to the gateway IP (only) | Laptop self-test |
| 8 | Optional: permission to list the host project's subnets (`compute.subnetworks.list`) for the installer, so the preflight can confirm item 3 | Preflight shows PASS instead of WARN for item 3 |

No Google Cloud firewall rule is needed for the gateway.

**Commands for the network team** (they run these, not the POC scripts; replace the placeholders):

```bash
H=net-host-project; S=my-poc-project; R=europe-west4; INSTALLER=user:installer@example.com
# subnet for the POC (often exists already): a range your on-premises network allows
gcloud compute networks subnets create <poc-subnet> --project $H --network <shared-vpc> --region $R \
  --range <allowlisted /24 or smaller> --enable-private-ip-google-access
# proxy-only subnet for regional internal load balancers (one per region per network; skip if it exists)
gcloud compute networks subnets create <proxy-subnet> --project $H --network <shared-vpc> --region $R \
  --range <unused /26 or larger> --purpose REGIONAL_MANAGED_PROXY --role ACTIVE
# host enabled and the POC project attached (often done already)
gcloud compute shared-vpc enable $H
gcloud compute shared-vpc associated-projects add $S --host-project $H
# the installer may use that one subnet
gcloud compute networks subnets add-iam-policy-binding <poc-subnet> --project $H --region $R \
  --member $INSTALLER --role roles/compute.networkUser
```

## Question 7 in step B5

| Step | You see | Answer |
|---|---|---|
| 7 | `7 Network [1/2]` | `2` (existing Shared VPC) |
| 7a | `7a Host project ID` (proposed automatically when the POC project is attached) | Enter, or the host project ID |
| — | A numbered list "Subnets you may use in <region>" | The number of the subnet (or Enter to type the values) |
| 7b / 7c | Network name, subnet (filled in from your choice) | Enter to confirm |
| 7e | `7e Gateway IP (auto = any free IP in the subnet, or a specific free IP)` | `auto`, or a free IP your network team gave you |
| 7f | `7f Does your on-prem connection (VPN/Interconnect) end in another region than <region>? [y/N]` | `y` only if it does |

The answers are saved in `poc/.state/answers.env` (`NETWORK_MODE`, `SHARED_VPC_HOST_PROJECT`, `SHARED_VPC_NETWORK`, `SHARED_VPC_SUBNET`, `GATEWAY_ILB_IP`, `ILB_GLOBAL_ACCESS`); `--yes` reuses them. `poc/poc-gateway.sh --status` shows the network and the gateway IP with TCP port 443: give these to the network team.

## What the POC creates in shared mode

| Created | Not created |
|---|---|
| The gateway's internal IP in your subnet, the internal load balancer, the gateway, certificates, logging, budgets | No VPC, subnets, router, NAT, firewall rules, proxy-only subnet or private DNS zone. The laptops don't need DNS: they pin the gateway name in their hosts file |

## Switching an existing POC from its own VPC to the Shared VPC

- **Who** · cloud admin (installer). **Where** · Cloud Shell, in the repository folder.
- **Do** · `poc/poc-gateway.sh` (without `--yes`), keep answers 1–6 (Enter), answer question 7 with `2` and the values above.
- **You should see** · the POC network is removed, the gateway gets a new IP from your subnet, the kits are rebuilt automatically. Certificates stay valid. About 7 minutes.
- **Then** · laptops that were already installed: re-install them with their new kit (the gateway IP in the kit changed).

## Preflight checks (shared mode)

| Check | FAIL / WARN means | Fix |
|---|---|---|
| shared VPC settings | Host, network or subnet missing, or the host is the POC project itself | Answer question 7 again |
| shared subnet: installer may use it | Subnet not shared with you, or no Compute Network User on it | Network team: items 2 and 4 |
| shared subnet: network and region | Subnet not found in this region, belongs to another network, or is not a regular subnet | Pick the right subnet |
| shared VPC: proxy-only subnet | FAIL: none active in this network and region. WARN: the installer can't list the host's subnets (normal for a service-project installer) | Network team: item 3 (and item 8 to turn the WARN into PASS) |
| shared VPC: project attached | The POC project is not attached to this host | Network team: item 1 |
| org policy compute.restrictSharedVpcHostProjects / …Subnetworks | The policy blocks this host or subnet | Network / organisation admin: item 5 |
