<div align="center">

```
██████╗ ███████╗██╗   ██╗███████╗███████╗ ██████╗
██╔══██╗██╔════╝██║   ██║██╔════╝██╔════╝██╔════╝
██║  ██║█████╗  ██║   ██║███████╗█████╗  ██║
██║  ██║██╔══╝  ╚██╗ ██╔╝╚════██║██╔══╝  ██║
██████╔╝███████╗ ╚████╔╝ ███████║███████╗╚██████╗
╚═════╝ ╚══════╝  ╚═══╝  ╚══════╝╚══════╝ ╚═════╝

    P O L I C Y - E N F O R C E D   D E V S E C O P S
```

**Enterprise Azure security platform — every resource declared, scanned, policy-evaluated, and validated.**

---

[![Pipeline](https://img.shields.io/badge/Pipeline-19%20Stages-2ea44f?style=for-the-badge&logo=jenkins&logoColor=white)](jenkins/Jenkinsfile)
[![Policies](https://img.shields.io/badge/OPA%20Policies-3%20Enforced-7D3C98?style=for-the-badge&logo=openpolicyagent&logoColor=white)](policies/)
[![Resources](https://img.shields.io/badge/Azure%20Resources-71-0078D4?style=for-the-badge&logo=microsoft-azure&logoColor=white)](terraform/)
[![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-12%20Techniques-CC0000?style=for-the-badge&logo=shield&logoColor=white)](#threat-model)

[![Azure](https://img.shields.io/badge/Azure-Cloud-0078D4?style=flat-square&logo=microsoft-azure)](https://azure.microsoft.com)
[![Terraform](https://img.shields.io/badge/Terraform-1.6+-7B42BC?style=flat-square&logo=terraform)](terraform/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.28-326CE5?style=flat-square&logo=kubernetes)](k8s/)
[![OPA](https://img.shields.io/badge/OPA-Conftest-7D3C98?style=flat-square&logo=openpolicyagent)](policies/)
[![Checkov](https://img.shields.io/badge/Checkov-IaC%20Scan-5D8AA8?style=flat-square)](terraform/)
[![Trivy](https://img.shields.io/badge/Trivy-Container%20Scan-1904DA?style=flat-square)](jenkins/Jenkinsfile)
[![Sentinel](https://img.shields.io/badge/Sentinel-Runtime%20Detect-0078D4?style=flat-square&logo=microsoft-azure)](sentinel/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

</div>

---

## What Makes This Different

> Most DevSecOps demos add a Trivy scan to a pipeline. This platform enforces security policy
> at every layer — from the Terraform plan to the live Azure control plane.

| Layer | Tool | Gate |
|:---:|:---:|:---:|
| Source code | gitleaks + Bandit | Blocks on any secret or HIGH severity |
| Dependencies | pip-audit | Advisory check against OSV/PyPI |
| IaC (source) | Checkov + tfsec | Blocks on CRITICAL/HIGH — parallel |
| IaC (runtime) | OPA / Conftest | Blocks on plan-evaluated policy violations |
| Container | Trivy | Blocks on CRITICAL/HIGH CVEs in image |
| Infrastructure | validate_azure.sh | Blocks deploy if live Azure state fails checks |
| Runtime | Microsoft Sentinel | KQL detections with 5-minute polling |
| Drift | terraform plan | Daily — unstable if production diverges |

---

## Architecture

```
                               ╔═══════════════╗
                               ║    INTERNET    ║
                               ╚═══════╤═══════╝
                                       │ HTTPS only
                               ╔═══════▼═══════╗
                               ║ APP GATEWAY   ║  ← Sole internet-facing boundary
                               ║ WAF v2        ║    DDoS, SQL inj., TLS termination
                               ╚═══════╤═══════╝
                                       │
╔══════════════════════════════════════╪══════════════════════════════════════╗
║              VIRTUAL NETWORK  10.0.0.0/16                                  ║
║                                      │                                     ║
║  ╔══════════════════════════════════════════════════════════╗               ║
║  ║         AKS CLUSTER  (private API server)                ║               ║
║  ║                                                          ║               ║
║  ║  ╔═══════════════════╗     ╔═══════════════════════════╗ ║               ║
║  ║  ║  secure-app       ║     ║  monitoring               ║ ║               ║
║  ║  ║  ─────────────    ║     ║  ─────────────────────    ║ ║               ║
║  ║  ║  Flask API  x2    ║     ║  Prometheus  Grafana      ║ ║               ║
║  ║  ║  NetworkPolicy    ║     ║  Alertmanager             ║ ║               ║
║  ║  ║  (default-deny)   ║     ║  node-exporter            ║ ║               ║
║  ║  ╚═══════════════════╝     ╚═══════════════════════════╝ ║               ║
║  ╚══════════════════════════════════════════════════════════╝               ║
║                                                                             ║
║  ╔══════════════╗  ╔═══════════════╗  ╔═══════════╗  ╔══════════════════╗  ║
║  ║  JENKINS VM  ║  ║   AZURE SQL   ║  ║ KEY VAULT ║  ║  ACR (Premium)   ║  ║
║  ║  IaC + CI/CD ║  ║  Private EP   ║  ║ MSI-only  ║  ║  Admin disabled  ║  ║
║  ╚══════════════╝  ╚═══════════════╝  ╚═══════════╝  ╚══════════════════╝  ║
║                                                                             ║
║  ╔═══════════════════════════════════════════════════════════════════════╗  ║
║  ║  LOG ANALYTICS WORKSPACE  (90-day retention)                         ║  ║
║  ║  AKS audit → Microsoft Sentinel → KQL rules → Incident → Playbook   ║  ║
║  ╚═══════════════════════════════════════════════════════════════════════╝  ║
╚═════════════════════════════════════════════════════════════════════════════╝
```

<details>
<summary><strong>Deployed Resources — 71 Total</strong></summary>

| Category | Resources |
|---|---|
| **Compute** | AKS (private, RBAC, AAD, autoscale 2–5 nodes), Jenkins VM |
| **Networking** | VNet, 5 Subnets, 5 NSGs (default-deny), Application Gateway WAF v2 |
| **Data** | Azure SQL (private endpoint), Key Vault (MSI-only, purge-protect) |
| **Containers** | ACR Premium (admin disabled), Flask API (x2 pods, non-root) |
| **Observability** | Prometheus, Grafana, Alertmanager, kube-state-metrics, node-exporter |
| **Security** | Managed Identities, RBAC Assignments, NetworkPolicies, Sentinel Rules |
| **Governance** | Log Analytics (90d retention), Diagnostic Settings (all resources) |

</details>

---

## CI/CD Pipeline — 19 Stages

```
 EVERY BRANCH / PR
 ┌─────────────────────────────────────────────────────────────────────────┐
 │                                                                         │
 │  [1]Checkout ──► [2]Secrets Scan ──► [3]Dependency Scan ──► [4]SAST   │
 │                       │                                        │        │
 │                    BLOCKS                                   BLOCKS      │
 │                  on any leak                              on HIGH sev   │
 │                                                                │        │
 │  [5]Unit Tests ◄────────────────────────────────────────────────        │
 │       │                                                                 │
 │       ▼                                                                 │
 │  [6]Terraform Init + fmt-check + validate                               │
 │       │  BLOCKS if unformatted or invalid schema                        │
 │       │                                                                 │
 │       ▼                                                                 │
 │  [7]IaC Security Scan ─────────── parallel ─────────────────────────   │
 │       │         Checkov (NIST/CIS/SOC2)    tfsec (Azure-specific)      │
 │       │         BLOCKS on CRITICAL/HIGH    BLOCKS on CRITICAL/HIGH     │
 │       │                                                                 │
 │  [8]Terraform Plan ──► saves binary plan + JSON                        │
 │       │  (binary reused for apply — no TOCTOU)                         │
 │       │                                                                 │
 │       ▼                                                                 │
 │  [9]OPA / Conftest Policy Check                                         │
 │       │   deny_public_ip.rego ──── no internet-facing resources        │
 │       │   deny_open_nsg.rego  ──── no 0.0.0.0/0 on mgmt ports         │
 │       │   require_tags.rego   ──── 6 mandatory tags enforced           │
 │       │   kubernetes.rego     ──── container security baseline         │
 │       │   BLOCKS on ANY policy violation                                │
 │       │                                                                 │
 │  [10]Build ──► [11]Trivy Scan ──► [12]Push ACR                        │
 │                     │                                                  │
 │                  BLOCKS on                                              │
 │                  CRIT/HIGH CVE                                          │
 │                                                                         │
 │  [13]Validate K8s  [14]Validate Monitoring                             │
 │                                                                         │
 └─────────────────────────────────────────────────────────────────────────┘

 MAIN BRANCH ONLY  ── manual approval gate captures JIRA ticket
 ┌─────────────────────────────────────────────────────────────────────────┐
 │                                                                         │
 │  [15]Terraform Apply (exact plan from stage 8)                         │
 │       │                                                                 │
 │       ▼                                                                 │
 │  [16]Azure Post-Deploy Validation (validate_azure.sh)                  │
 │       │   Queries LIVE Azure control plane — not Terraform state       │
 │       │   Private cluster / RBAC / node IPs / NSGs / ACR / Logs        │
 │       │   BLOCKS AKS deployment on any critical finding                 │
 │       │                                                                 │
 │  [17]Deploy to AKS ──► [18]Deploy Monitoring ──► [19]Smoke Tests      │
 │                                                                         │
 └─────────────────────────────────────────────────────────────────────────┘

 SCHEDULED NIGHTLY (separate job)
 ┌────────────────────────────────────────────────┐
 │  terraform plan -detailed-exitcode             │
 │  exit 2 → UNSTABLE + alert #security-ops       │
 │  "Drift detection: nightly posture check"      │
 └────────────────────────────────────────────────┘
```

---

## Policy-as-Code

OPA/Conftest evaluates the **Terraform plan JSON** — not the source code.
This means it sees what will _actually_ be deployed, including computed values
and resource combinations that look fine individually but create risk together.

```
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
conftest test tfplan.json --policy policies/ --output table
```

### `policies/deny_public_ip.rego` — MITRE T1190, T1046

```
DENY  azurerm_public_ip on any non-approved resource
DENY  AKS cluster without private_cluster_enabled = true
DENY  SQL server with public_network_access_enabled = true
DENY  Key Vault with network_acls.default_action = "Allow"
ALLOW Application Gateway  (approved DMZ boundary)
ALLOW Azure Bastion        (approved management entry point)
```

### `policies/deny_open_nsg.rego` — MITRE T1021, T1133

```
DENY  Allow-Inbound from 0.0.0.0/0 → port 22   (SSH)
DENY  Allow-Inbound from 0.0.0.0/0 → port 3389  (RDP)
DENY  Allow-Inbound from 0.0.0.0/0 → port *     (wildcard)
DENY  AKS subnet NSG with any inbound from internet
WARN  Allow-Outbound to 0.0.0.0/0 on all ports  (T1041 exfil risk)
```

### `policies/require_tags.rego` — Governance / Compliance

```
DENY  Missing: Environment | Team | CostCenter | Owner | ManagedBy | DataClassification
DENY  DataClassification not in {public|internal|confidential|restricted}
DENY  ManagedBy != "Terraform"  (unmanaged = bypasses pipeline scanning)
DENY  CostCenter not matching CC-XXXX format
DENY  Prod databases/vaults with DataClassification = "public"
WARN  Owner tag is not an email address  (can't page during incident)
```

---

## Infrastructure Drift Detection

A dedicated Jenkins job runs every morning at 06:00:

```bash
terraform plan -detailed-exitcode -var-file=terraform.tfvars

# Exit codes:
#   0 = no changes     → green
#   1 = plan error     → pipeline failure (investigate)
#   2 = drift detected → UNSTABLE + Slack alert to #security-ops
```

**Why this matters:**
A drifted resource is an unreviewed change — equivalent to an unreviewed PR.
Common causes: emergency portal fixes, Azure platform updates, compromised
accounts modifying resources directly (MITRE T1578).

Drift detection closes the gap from "discovered at next audit" to "discovered
by 06:15 AM the next morning."

---

## Post-Deploy Validation

`validation/validate_azure.sh` queries the **live Azure control plane** after
every apply. Terraform state can diverge from reality — provider bugs, race
conditions, and manual edits all create gaps. This script is the authoritative check.

| # | Check | Method | MITRE |
|:---:|---|---|:---:|
| 1 | AKS private cluster enabled | `az aks show` | T1046 |
| 2 | AKS RBAC enabled | `az aks show` | T1078 |
| 3 | No public IPs on AKS nodes | `az network nic list` | T1190 |
| 4 | No 0.0.0.0/0 on SSH/RDP in NSGs | `az network nsg list` | T1021 |
| 5 | ACR admin account disabled | `az acr show` | T1525 |
| 6 | AcrPull role exists on ACR | `az role assignment list` | T1610 |
| 7 | AKS diagnostic logs enabled | `az monitor diagnostic-settings list` | T1562 |

Pipeline behavior: any CRITICAL failure returns exit code 1 — Stage 17 (AKS deploy) does not run.

---

## Defense in Depth

```
 GOVERNANCE ──────────────────────────────────────────────────────────────
  OPA plan evaluation    Catches misconfig before any Azure API call
  Checkov + tfsec        NIST 800-53, CIS, SOC 2, Azure-specific rules
  Drift detection        Nightly posture check against Terraform state
  Mandatory tagging      Owner + CostCenter + DataClassification enforced

 NETWORK ──────────────────────────────────────────────────────────────────
  Default-deny NSGs      No implicit permit between subnets
  K8s NetworkPolicies    Pod-level default-deny in every namespace
  Private AKS            API server reachable only inside VNet
  App Gateway WAF        Single internet entry point; all else private

 IDENTITY ─────────────────────────────────────────────────────────────────
  Managed Identity       No passwords, keys, or connection strings stored
  OIDC pipeline auth     Short-lived tokens; no ARM_CLIENT_SECRET
  Azure AD + K8s RBAC    Least-privilege at every layer

 CONTAINER ────────────────────────────────────────────────────────────────
  Non-root (UID 65534)   No process runs as root inside containers
  ReadOnly root FS       Filesystem immutable at runtime
  Dropped capabilities   All Linux caps removed; none added back
  PSS restricted         Pod Security Standards enforced at namespace level

 PIPELINE ─────────────────────────────────────────────────────────────────
  gitleaks               Blocks on any secret/credential detected
  Bandit SAST            Blocks on HIGH severity code findings
  pip-audit              Dependency CVE check against OSV advisories
  Checkov + tfsec        IaC misconfig — blocks on CRITICAL/HIGH
  OPA / Conftest         Plan-level policy enforcement
  Trivy                  Container image CVE — blocks on CRITICAL/HIGH

 DETECT & RESPOND ─────────────────────────────────────────────────────────
  Microsoft Sentinel     KQL analytics rules with 5-minute polling
  AKS audit logs         kubectl exec, privileged pods, RBAC escalation
  Prometheus alerts      CPU/memory anomalies, error rate spikes
  Post-deploy checks     Live Azure state validated after every apply
```

---

## Threat Model

<details>
<summary><strong>STRIDE Analysis</strong></summary>

| Category | Attack Scenario | Control | Detection |
|---|---|---|---|
| **Spoofing** | Stolen kubeconfig used to exec into pod | Private cluster (no external API) | Sentinel T1609 — 5-min alert |
| **Tampering** | Portal edit opens NSG to 0.0.0.0/0 | NSG OPA policy (plan-time) | Drift detection catches by 06:15 AM |
| **Repudiation** | No audit trail for infrastructure changes | Terraform state + Log Analytics (90d) | All API calls logged |
| **Info Disclosure** | ACR admin password leaked in CI logs | Admin disabled; MSI-only auth | No password exists to leak |
| **Denial of Service** | Cryptomining container spikes CPU | Resource limits + HPA | Prometheus alert in minutes |
| **Elevation of Privilege** | cluster-admin binding via compromised SA | OPA deny (pipeline) | Sentinel KQL (runtime) |

</details>

<details>
<summary><strong>MITRE ATT&CK Coverage</strong></summary>

| Technique | Description | Control |
|---|---|---|
| T1190 | Exploit Public-Facing Application | No public IPs (OPA + post-deploy) |
| T1046 | Network Service Discovery | Private AKS + NSG default-deny |
| T1021 | Remote Services (SSH/RDP) | NSG policy + Azure Bastion only |
| T1078 | Valid Accounts (RBAC escalation) | RBAC enforced + Sentinel KQL |
| T1525 | Implant Internal Image | ACR admin disabled + Trivy scan |
| T1552 | Credentials in Files | gitleaks + OIDC (no stored secrets) |
| T1562 | Disable/Modify Cloud Logs | Diagnostic settings validated |
| T1609 | Container Administration Command | Sentinel KQL — exec detection |
| T1610 | Deploy Container | AcrPull role enforced |
| T1611 | Escape to Host | Non-root + dropped caps + PSS |
| T1578 | Modify Cloud Compute Infrastructure | Drift detection — nightly check |
| T1195 | Supply Chain Compromise | pip-audit + pinned providers |

</details>

---

## Observability

```
Prometheus (metrics) ──► Grafana (dashboards) ──► Alertmanager (routing)
                                                        │
                              ┌─────────────────────────┼────────────────┐
                         critical                    warning          inhibit
                              │                          │               │
                        PagerDuty               Email (8h repeat)  dedup warn
                        (0s delay,                                  same alert
                         1h repeat)                                 + namespace
```

**Security dashboard panels:** request rate · error rate · P95/P99 latency ·
auth failure rate · pod restarts · CPU/memory utilization · active pods by namespace

---

## Runtime Detection (Microsoft Sentinel)

```
AKS API Server
    → kube-audit logs
    → Diagnostic Settings
    → Log Analytics (AKSAudit table)
    → Sentinel Analytics Rules (5-min KQL polling)
    → Incident + Entity Mapping
    → Logic App Playbook (auto-response)
```

| Detection | Severity | MITRE | KQL File |
|---|:---:|:---:|---|
| `kubectl exec` into running pod | High → Critical | T1609 | `kql/aks_pod_exec_detection.kql` |
| Privileged container deployed | High → Critical | T1611 | `kql/privileged_pod_detection.kql` |
| Dangerous `hostPath` mount | Medium → Critical | T1611 | `kql/privileged_pod_detection.kql` |
| `cluster-admin` binding created | Critical | T1078 | `kql/privileged_pod_detection.kql` |

---

## Project Structure

```
secure-cloud-platform/
│
├── terraform/                     Infrastructure as Code (71 resources)
│   ├── main.tf                    Module orchestration
│   ├── variables.tf               Input validation with constraints
│   ├── outputs.tf                 References for downstream consumers
│   ├── providers.tf               Pinned providers, OIDC auth, remote state
│   └── modules/
│       ├── networking/            VNet · 5 Subnets · 5 NSGs
│       ├── aks/                   Private cluster · RBAC · AAD · Azure CNI
│       ├── acr/                   Premium · private endpoint · admin disabled
│       ├── sql/                   Private endpoint · AAD auth
│       ├── keyvault/              MSI-only · purge-protect · network restricted
│       ├── appgateway/            WAF v2 · TLS termination
│       └── jenkins/               CI/CD VM in management subnet
│
├── policies/                      OPA / Conftest policy bundle
│   ├── deny_public_ip.rego        T1190/T1046 — no public IPs on internals
│   ├── deny_open_nsg.rego         T1021 — no 0.0.0.0/0 on mgmt ports
│   ├── require_tags.rego          Governance — 6 mandatory resource tags
│   └── kubernetes.rego            Container security baseline
│
├── validation/
│   └── validate_azure.sh          Post-deploy Azure CLI checks (7 controls)
│
├── jenkins/
│   └── Jenkinsfile                19-stage pipeline + drift detection template
│
├── app/                           Flask API — metrics source + attack surface sim
├── k8s/                           Application manifests (PSS restricted)
├── monitoring/                    Prometheus · Grafana · Alertmanager stack
├── sentinel/                      KQL detection rules + ARM templates
└── docs/                          Runtime detection guide + SOC runbook
```

---

## Quick Start

```bash
# 1. Prerequisites
az login && az account set --subscription <id>
terraform version   # >= 1.6
conftest version    # >= 0.46

# 2. Infrastructure
cd terraform
cp terraform.tfvars.example terraform.tfvars && vim terraform.tfvars
terraform init
checkov -d . --hard-fail-on CRITICAL,HIGH
tfsec . --minimum-severity HIGH
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
conftest test tfplan.json --policy ../policies \
  --namespace terraform.deny_public_ip \
  --namespace terraform.deny_open_nsg \
  --namespace terraform.require_tags
terraform apply tfplan

# 3. Validate live state
RESOURCE_GROUP=rg-seccloud-prod \
AKS_CLUSTER_NAME=aks-seccloud-prod \
ACR_NAME=acrseccloudprod \
./validation/validate_azure.sh

# 4. Access Grafana
kubectl port-forward svc/grafana 3000:3000 -n monitoring
# → http://localhost:3000
```

---

## Interview Talking Points

<details>
<summary><strong>"How do you prevent cloud misconfiguration?"</strong></summary>

Three layers. Checkov and tfsec scan the Terraform source code for known-bad
patterns. OPA evaluates the actual plan JSON — what will be created including
computed values that only resolve at runtime. Then `validate_azure.sh` queries
the live Azure control plane after apply. Each layer catches what the previous
one cannot. Terraform state diverges from live state more often than people expect.

</details>

<details>
<summary><strong>"What is Policy-as-Code and why does it matter at scale?"</strong></summary>

Policy-as-Code treats security rules as version-controlled artifacts.
Every change to a Rego policy is a PR with a diff, review, and approval —
creating an audit trail of every policy decision. It also scales infinitely:
100 engineers committing simultaneously all get the same policy evaluation.
Manual security review cannot match that consistency. The OPA policies in
this repo block a new engineer from accidentally creating a public-facing
database as reliably as they block a senior engineer.

</details>

<details>
<summary><strong>"How do you handle secrets in a CI/CD pipeline?"</strong></summary>

No secrets. The pipeline authenticates to Azure via OIDC Workload Identity
Federation — the Jenkins agent exchanges a short-lived OIDC token for a
scoped Azure access token at runtime. No `ARM_CLIENT_SECRET` is stored
anywhere. Application secrets live in Key Vault, accessed by pods through
Managed Identity. gitleaks scans every commit so accidental inclusions
never reach remote. MITRE T1552.

</details>

<details>
<summary><strong>"How do you detect infrastructure drift?"</strong></summary>

A scheduled Jenkins job runs `terraform plan -detailed-exitcode` every
morning. Exit code 2 means drift — a resource differs from Terraform state.
This catches emergency portal changes that were never committed, Azure
platform updates that modified properties, and — critically — unauthorized
modifications by a compromised identity (MITRE T1578). The window between
a change and its detection goes from "next audit" to "before 07:00 AM."

</details>

<details>
<summary><strong>"Why not just use Azure Policy for enforcement?"</strong></summary>

Azure Policy enforces at the Azure API layer — after a resource is created
or modified. OPA enforces at the Terraform plan layer — before any API call
is made. OPA also supports governance rules that aren't misconfigurations
per se: tagging formats, naming conventions, approved regions, cost center
validation. The combination gives shift-left enforcement (OPA in CI) plus
runtime backstop (Azure Policy), with full audit trail for both.

</details>

---

## Compliance Coverage

| Framework | Controls |
|---|---|
| **PCI-DSS** | Network segmentation · encryption at rest/transit · access control · 90-day audit logs · vulnerability scanning |
| **SOC 2** | Availability (HPA, multi-node) · access controls · change management (Terraform gates) · security monitoring |
| **HIPAA** | Encryption (TDE + TLS 1.2+) · MSI/RBAC access · audit trails · minimum necessary access |
| **NIST CSF** | Identify (tagging) · Protect (IaC controls) · Detect (Sentinel) · Respond (runbooks) · Recover (drift detection) |

---

## Tech Stack

| | Technology | Purpose |
|:---:|---|---|
| ☁️ | Microsoft Azure | Cloud platform (71 resources) |
| 🏗️ | Terraform 1.6+ | Infrastructure as Code, remote state, OIDC |
| ⚖️ | OPA / Conftest | Policy-as-Code on Terraform plan JSON |
| 🔍 | Checkov + tfsec | IaC security scanning (parallel, NIST/CIS/Azure) |
| 🐳 | Docker + Kubernetes 1.28 | Containerised workloads, private cluster |
| 🔧 | Jenkins | 19-stage DevSecOps pipeline |
| 🛡️ | Trivy + Bandit + gitleaks | Container, SAST, and secrets scanning |
| 📡 | Microsoft Sentinel | SIEM/SOAR — KQL runtime detection |
| 📊 | Prometheus + Grafana | Metrics, dashboards, alert routing |
| 🔐 | Azure Key Vault + Managed Identity | Secrets management, zero stored credentials |
| 🐍 | Python 3.11 + Flask | Application layer |
| 📝 | Bash + Azure CLI | Post-deploy infrastructure validation |

---

<div align="center">

**Every commit evaluated. Every resource validated. Every change audited.**

*Built to demonstrate $130k–$150k DevSecOps engineering depth across*
*governance, automation, enforcement, and cloud security posture.*

</div>
