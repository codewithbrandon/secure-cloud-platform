# Runtime Detection Layer — AKS + Microsoft Sentinel

> **Component:** Runtime Detection & Response
> **Platform:** Azure Kubernetes Service + Microsoft Sentinel
> **Coverage:** MITRE ATT&CK T1609, T1611, T1610, T1078, T1548
> **Maintained by:** Platform Security Engineering

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Log Pipeline: AKS → Sentinel](#2-log-pipeline-aks--sentinel)
3. [Enabling Kubernetes Audit Logging](#3-enabling-kubernetes-audit-logging)
4. [Detection Rules](#4-detection-rules)
5. [Attack Simulation Guide](#5-attack-simulation-guide)
6. [Sentinel Incident Behavior](#6-sentinel-incident-behavior)
7. [Sentinel Analytics Rule Configuration](#7-sentinel-analytics-rule-configuration)
8. [MITRE ATT&CK Coverage Map](#8-mitre-attck-coverage-map)
9. [CI/CD Security Gate Integration](#9-cicd-security-gate-integration)
10. [Screenshots Checklist](#10-screenshots-checklist)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                     DETECTION ARCHITECTURE FLOW                     │
└─────────────────────────────────────────────────────────────────────┘

   [Attacker / Operator]
          │
          │  kubectl exec / privileged pod / cluster-admin binding
          ▼
   ┌─────────────────────┐
   │   AKS API Server    │  ← Kubernetes control plane
   │  (kube-apiserver)   │    All requests pass through here
   └────────┬────────────┘
            │
            │  Kubernetes Audit Events (JSON)
            │  Stage: RequestReceived → ResponseComplete
            ▼
   ┌─────────────────────┐
   │  AKS Audit Policy   │  ← Defines what gets logged
   │  (kube-audit)       │    Level: Request (captures pod specs)
   └────────┬────────────┘
            │
            │  Diagnostic Settings (Resource-Specific mode)
            ▼
   ┌─────────────────────┐
   │  Log Analytics      │  ← AKSAudit table
   │  Workspace (LAW)    │    AKSControlPlane table
   └────────┬────────────┘
            │
            │  KQL Analytics Rules (5-minute polling)
            ▼
   ┌─────────────────────┐
   │  Microsoft Sentinel │  ← SIEM + SOAR layer
   │                     │
   │  Analytics Rules ───┼──► Incidents
   │  Entity Mapping  ───┼──► Entities (Accounts, IPs, Resources)
   │  Logic Apps      ───┼──► Automated Response Playbooks
   └─────────────────────┘
            │
            │  Alert → Incident → Playbook Trigger
            ▼
   ┌─────────────────────┐
   │  SOC / Response     │  ← Investigation & Containment
   │  Team               │    NetworkPolicy, Pod deletion, RBAC review
   └─────────────────────┘
```

### Defense-in-Depth Layer Model

```
Layer 5: DETECT & RESPOND ──── Microsoft Sentinel (this component)
Layer 4: RUNTIME SECURITY  ──── Falco / Defender for Containers
Layer 3: ADMISSION CONTROL ──── OPA Gatekeeper / Kyverno policies
Layer 2: NETWORK ISOLATION ──── NetworkPolicy + Private Cluster
Layer 1: IDENTITY          ──── Azure AD + Kubernetes RBAC
Layer 0: INFRASTRUCTURE    ──── Terraform hardened AKS + Azure Policy
```

This document covers **Layer 5**. Each layer below it reduces the likelihood
that a threat reaches the detection layer, but assumes breach at every level.

---

## 2. Log Pipeline: AKS → Sentinel

### Data Flow Detail

| Stage | Component | Output | Schema |
|-------|-----------|--------|--------|
| API Request | kube-apiserver | Kubernetes Audit Event (JSON) | [K8s Audit Policy](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/) |
| Log Export | Diagnostic Settings | Resource-Specific Logs | `AKSAudit` table |
| Storage | Log Analytics Workspace | Structured KQL-queryable rows | See table schema below |
| Detection | Sentinel Analytics Rule | Alerts → Incidents | Sentinel schema |
| Enrichment | UEBA + TI | Entity behavior, threat intel match | Sentinel Entities |

### AKSAudit Table Schema (Key Fields)

```
Column                    Type        Description
─────────────────────────────────────────────────────────────────────
TimeGenerated             datetime    Event timestamp (UTC)
Stage                     string      RequestReceived | ResponseComplete
Verb                      string      create | get | list | patch | delete | watch
ObjectRef_Resource        string      pods | deployments | clusterrolebindings...
ObjectRef_Subresource     string      exec | log | portforward | status...
ObjectRef_Name            string      Resource name (pod name, etc.)
ObjectRef_Namespace       string      Kubernetes namespace
User_Username             string      Authenticated principal (UPN or system:...)
User_Groups               dynamic     Group memberships of the principal
UserAgent                 string      Client user-agent (kubectl/1.x, Go-http-client...)
SourceIps                 dynamic     Array of source IP addresses
ResponseStatus_Code       int         HTTP response code (101, 200, 403, etc.)
RequestObject             string      JSON body of the request (requires audit level: Request)
AuditID                   string      Unique audit event identifier (for deduplication)
ResourceId                string      Full Azure resource ID of the AKS cluster
```

> **Note on RequestObject:** Pod spec inspection (privileged flags, hostPath
> volumes) requires this field to be populated. This requires the AKS audit
> policy level to be set to `Request` or `RequestResponse` for the relevant
> resources. `Metadata` level logging will NOT populate this field.

---

## 3. Enabling Kubernetes Audit Logging

### Step 1: Create Log Analytics Workspace (Terraform)

```hcl
resource "azurerm_log_analytics_workspace" "security" {
  name                = "law-${var.cluster_name}-security"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = 90  # Minimum for security compliance (adjust to 365 for regulated)

  tags = {
    purpose     = "security-monitoring"
    compliance  = "soc2-iso27001"
    environment = var.environment
  }
}
```

### Step 2: Configure AKS Diagnostic Settings (Terraform)

```hcl
resource "azurerm_monitor_diagnostic_setting" "aks_audit" {
  name               = "aks-audit-to-sentinel"
  target_resource_id = azurerm_kubernetes_cluster.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.security.id

  # CRITICAL: Use resource-specific mode for AKSAudit table
  # (vs AzureDiagnostics which has schema instability and performance issues)
  log_analytics_destination_type = "Dedicated"

  enabled_log {
    category = "kube-audit"          # Core K8s API audit events — REQUIRED
    retention_policy { enabled = false }
  }

  enabled_log {
    category = "kube-audit-admin"    # Admin operations (RBAC, config changes)
    retention_policy { enabled = false }
  }

  enabled_log {
    category = "kube-apiserver"      # API server internal events
    retention_policy { enabled = false }
  }

  enabled_log {
    category = "kube-controller-manager"  # Controller events (deployment, etc.)
    retention_policy { enabled = false }
  }

  enabled_log {
    category = "kube-scheduler"      # Scheduling decisions
    retention_policy { enabled = false }
  }

  # Control plane metrics for anomaly detection
  metric {
    category = "AllMetrics"
    enabled  = true
    retention_policy { enabled = false }
  }
}
```

### Step 3: Connect Log Analytics to Microsoft Sentinel

```hcl
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "main" {
  workspace_id = azurerm_log_analytics_workspace.security.id
}

# Enable AKS-specific Sentinel data connector
resource "azurerm_sentinel_data_connector_azure_active_directory" "main" {
  name                       = "AKS-Sentinel-Connector"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.security.workspace_id
}
```

### Step 4: Verify Log Ingestion

Run the following KQL in Log Analytics to confirm audit logs are flowing:

```kql
// Confirm AKSAudit table exists and is receiving data
AKSAudit
| where TimeGenerated > ago(1h)
| summarize EventCount = count() by bin(TimeGenerated, 5m)
| render timechart

// Verify exec events are captured (run a test kubectl exec first)
AKSAudit
| where TimeGenerated > ago(30m)
| where ObjectRef_Subresource =~ "exec"
| project TimeGenerated, User_Username, ObjectRef_Name, ObjectRef_Namespace, Stage
```

### Audit Policy Verification

```bash
# Confirm the kube-audit category is enabled on your AKS cluster
az monitor diagnostic-settings list \
  --resource $(az aks show -n <cluster-name> -g <rg> --query id -o tsv) \
  --query "[].logs[?enabled==\`true\`].category"
```

---

## 4. Detection Rules

### Rule 1: AKS Unauthorized Pod Exec Detection

**File:** `sentinel/kql/aks_pod_exec_detection.kql`

#### What It Detects

This rule identifies interactive `kubectl exec` sessions and programmatic API
calls to the `pods/exec` subresource that originate from:

- Unexpected users (not in the authorized allowlist)
- Anonymous / unauthenticated principals
- Non-system user agents (kubectl, Go HTTP client, curl)
- Production or sensitive namespaces

#### Why This Matters

`kubectl exec` establishes a direct shell session into a running container.
In a post-compromise scenario, an attacker with stolen credentials (kubeconfig,
service account token) will use exec to explore the environment, access mounted
secrets, pivot to adjacent services, or attempt a container escape.

Unlike deploying a new pod, exec requires no new workload creation — it leaves
a minimal footprint and bypasses many admission controls.

#### Detection Logic Summary

```
AKSAudit
  WHERE Stage = "ResponseComplete"
    AND ObjectRef_Resource = "pods"
    AND ObjectRef_Subresource = "exec"
    AND Verb = "create"
    AND User_Username NOT IN (system components, authorized accounts)
  ENRICH with:
    - IsAnonymous flag
    - IsKubectl flag (user-agent analysis)
    - IsSensitiveNamespace flag
    - ExecSucceeded (HTTP 101/200) vs ExecBlocked (401/403)
  SCORE (0-100) based on risk factors
  ALERT where RiskScore >= 45 OR IsAnonymous OR IsSensitiveNamespace
```

#### Alert Severity Matrix

| Condition | Severity | Response SLA |
|-----------|----------|--------------|
| Anonymous exec succeeded | Critical | 5min / 30min |
| Exec into sensitive namespace (success) | Critical | 5min / 30min |
| Anonymous exec attempt (blocked) | High | 15min / 60min |
| kubectl exec succeeded (any namespace) | High | 15min / 60min |
| kubectl exec blocked | Medium | 60min / 4hr |
| Programmatic exec succeeded | Medium | 60min / 4hr |

---

### Rule 2: Privileged Container & Risky K8s Config Detection

**File:** `sentinel/kql/privileged_pod_detection.kql`

#### Sub-Detection 2a: Privileged Container Creation

Detects containers created with:

| Security Context Flag | Risk | MITRE |
|-----------------------|------|-------|
| `privileged: true` | Root access to host kernel, all devices | T1611 |
| `allowPrivilegeEscalation: true` + `runAsUser: 0` | Child processes can gain root | T1611 |
| `capabilities.add: [SYS_ADMIN, NET_ADMIN, SYS_PTRACE]` | Specific kernel privilege grants | T1611 |
| `hostPID: true` | Attacker can ptrace host processes | T1611 |
| `hostNetwork: true` | Container can sniff host network traffic | T1610 |

**Attack chain enabled by a privileged container:**

```
kubectl exec privileged-pod /bin/bash
→ nsenter -t 1 -m -u -i -n /bin/bash     # Enter host namespace
→ cat /var/lib/kubelet/config.yaml         # Steal node credentials
→ kubectl --kubeconfig=<stolen> get secrets --all-namespaces
```

#### Sub-Detection 2b: Dangerous hostPath Mounts

| Mounted Path | Risk Level | Impact |
|-------------|------------|--------|
| `/` | Critical | Full host filesystem R/W |
| `/var/run/docker.sock`, `/run/containerd/containerd.sock` | Critical | Spawn privileged containers |
| `/etc/kubernetes` | Critical | PKI certificates, kubeconfig |
| `/proc` | High | Read host process memory, namespace escape |
| `/sys`, `/dev` | High | Kernel parameter writes, device access |
| `/var/log` | Medium | Node log exfiltration |

#### Sub-Detection 2c: cluster-admin ClusterRoleBinding

Detects creation of any binding that grants `cluster-admin` or equivalent
wildcard role to any subject (User, ServiceAccount, or Group).

`cluster-admin` = complete read/write access to all K8s resources across all
namespaces. This includes secrets, certificates, and the ability to create
additional privileged workloads.

**All matches from this detection are severity: Critical with no exceptions.**

---

## 5. Attack Simulation Guide

> **Safety Note:** All simulations below use isolated namespaces and
> non-production workloads. Never simulate against production pods or
> real sensitive data. Run in a dedicated security-testing AKS cluster.

### Prerequisites

```bash
# Create isolated simulation namespace
kubectl create namespace security-sim
kubectl label namespace security-sim purpose=security-testing

# Create a benign target pod
kubectl run target-pod \
  --image=nginx:alpine \
  --namespace=security-sim \
  --restart=Never

# Wait for pod to be running
kubectl wait pod/target-pod -n security-sim --for=condition=Ready --timeout=60s
```

### Simulation 1: kubectl exec Detection

```bash
# This command will generate an AKSAudit event:
# ObjectRef_Resource=pods, Subresource=exec, Verb=create
kubectl exec -n security-sim target-pod -- /bin/sh -c "whoami && id"

# Verify in Log Analytics (run ~5 minutes after exec):
# AKSAudit
# | where TimeGenerated > ago(15m)
# | where ObjectRef_Subresource =~ "exec"
# | where ObjectRef_Namespace =~ "security-sim"
# | project TimeGenerated, User_Username, UserAgent, ObjectRef_Name, ResponseStatus_Code
```

**Expected Sentinel behavior:** Alert generated within 5-10 minutes,
classified as Medium or High depending on your user identity and namespace.

### Simulation 2: Privileged Pod Creation

```bash
# Create a privileged pod spec (DO NOT deploy in production namespaces)
cat <<EOF | kubectl apply -f - --namespace=security-sim
apiVersion: v1
kind: Pod
metadata:
  name: priv-test-pod
  namespace: security-sim
  labels:
    purpose: security-test
    delete-after: "true"
spec:
  containers:
  - name: priv-container
    image: alpine:latest
    command: ["sleep", "3600"]
    securityContext:
      privileged: true            # Trigger: PrivilegedContainer detection
      allowPrivilegeEscalation: true
    volumeMounts:
    - name: host-proc
      mountPath: /host/proc       # Trigger: HostPathMount detection
  volumes:
  - name: host-proc
    hostPath:
      path: /proc                 # Trigger: HostPath High severity
EOF
```

**Expected Sentinel behavior:** Two alerts — PrivilegedContainer (High) and
HostPathMount (High) — merged into a single incident.

### Simulation 3: cluster-admin Binding (DESTRUCTIVE — use with extreme caution)

```bash
# WARNING: This creates a real cluster-admin binding.
# Run ONLY in a throwaway cluster. Delete immediately after testing.

cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: sim-cluster-admin-test
  labels:
    purpose: security-sim
    delete-immediately: "true"
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: sim-test-sa
  namespace: security-sim
EOF

# IMMEDIATELY delete after creating (test window = 5 seconds)
kubectl delete clusterrolebinding sim-cluster-admin-test
```

**Expected Sentinel behavior:** Critical alert within 5 minutes of creation,
even if the binding was immediately deleted. The AuditID and actor will be
captured for forensic reference.

### Cleanup After Simulation

```bash
# Remove all simulation resources
kubectl delete namespace security-sim --force --grace-period=0
kubectl delete clusterrolebinding sim-cluster-admin-test --ignore-not-found

# Verify no privileged workloads remain
kubectl get pods --all-namespaces \
  -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}: privileged={.spec.containers[*].securityContext.privileged}{"\n"}{end}'
```

---

## 6. Sentinel Incident Behavior

### Incident Lifecycle

```
AKSAudit Event
      │
      ▼ (5-min polling)
KQL Analytics Rule Match
      │
      ▼
Sentinel Alert Created
  - Title:    [K8s Exec | High] kubectl → prod/payment-api-7f8b
  - Severity: High
  - Entities: Account(actor), IP(source), CloudResource(cluster)
      │
      ▼ (alert grouping — 5-min window, same namespace)
Sentinel Incident Created
  - All related alerts in same namespace grouped
  - MITRE tactics tagged: Execution, Lateral Movement
  - Entity timeline populated automatically
      │
      ▼ (if Logic App playbook attached)
Automated Response Triggered
  - SOC notification (Teams/PagerDuty)
  - Pod annotation: security.io/under-investigation=true
  - Optional: cordon pod via AKS API call
      │
      ▼
SOC Analyst Investigation
  (see incident-response-runbook.md)
```

### Entity Mapping Configuration

Configure the following entity mappings in the Sentinel Analytics Rule UI:

```
Entity Type   | Identifier | KQL Field
─────────────────────────────────────────────────
Account       | Name       | ActorUsername
Account       | UPNSuffix  | (extract from ActorUsername)
IP            | Address    | SourceIPs
CloudResource | ResourceId | ClusterResourceId
```

### Alert Grouping Strategy

For the pod exec rule, use **"Group all alerts triggered by this rule into
a single incident"** with a grouping window of **5 minutes**.

This prevents alert storms when a single attacker runs multiple exec commands
in rapid succession — grouping surfaces one incident with full timeline context
rather than dozens of individual alerts.

For the privileged container rule, use **"Alert per row"** since each unique
workload creation event represents a distinct risk that deserves individual
investigation.

---

## 7. Sentinel Analytics Rule Configuration

### Pod Exec Rule — ARM/Bicep Reference

```json
{
  "kind": "Scheduled",
  "properties": {
    "displayName": "AKS - Unauthorized Pod Exec Detected",
    "description": "Detects unauthorized kubectl exec or API exec calls into Kubernetes pods. Maps to MITRE T1609/T1611.",
    "severity": "High",
    "enabled": true,
    "query": "<contents of aks_pod_exec_detection.kql>",
    "queryFrequency": "PT5M",
    "queryPeriod": "PT5M",
    "triggerOperator": "GreaterThan",
    "triggerThreshold": 0,
    "suppressionDuration": "PT1H",
    "suppressionEnabled": false,
    "tactics": ["Execution", "LateralMovement"],
    "techniques": ["T1609", "T1611"],
    "alertDetailsOverride": {
      "alertDisplayNameFormat": "{{IncidentTitle}}",
      "alertSeverityColumnName": "AlertSeverity"
    },
    "eventGroupingSettings": {
      "aggregationKind": "AlertPerResult"
    },
    "incidentConfiguration": {
      "createIncident": true,
      "groupingConfiguration": {
        "enabled": true,
        "reopenClosedIncident": false,
        "lookbackDuration": "PT5M",
        "matchingMethod": "Selected",
        "groupByEntities": ["Account", "CloudApplication"],
        "groupByAlertDetails": ["DisplayName"],
        "groupByCustomDetails": []
      }
    },
    "entityMappings": [
      {
        "entityType": "Account",
        "fieldMappings": [
          { "identifier": "Name", "columnName": "ActorUsername" }
        ]
      },
      {
        "entityType": "IP",
        "fieldMappings": [
          { "identifier": "Address", "columnName": "SourceIPs" }
        ]
      },
      {
        "entityType": "CloudResource",
        "fieldMappings": [
          { "identifier": "ResourceId", "columnName": "ClusterResourceId" }
        ]
      }
    ]
  }
}
```

---

## 8. MITRE ATT&CK Coverage Map

| Tactic | Technique | Sub-Technique | Detection Rule | Severity |
|--------|-----------|---------------|----------------|----------|
| Execution | T1609 Container Administration Command | — | pod_exec | High |
| Execution | T1610 Deploy Container | — | privileged_pod | High |
| Privilege Escalation | T1611 Escape to Host | — | privileged_pod (privileged flag, hostPath) | Critical/High |
| Privilege Escalation | T1548 Abuse Elevation Control | — | privileged_pod (capabilities) | High |
| Persistence | T1078 Valid Accounts | T1078.004 Cloud Accounts | cluster_admin_binding | Critical |
| Lateral Movement | T1021 Remote Services | — | pod_exec (exec as remote shell) | High |
| Discovery | T1613 Container and Resource Discovery | — | pod_exec + audit log correlation | Medium |

---

## 9. CI/CD Security Gate Integration

Runtime detections integrate into the CI/CD pipeline as a **post-deployment
security validation gate** in the Jenkins pipeline:

```groovy
// Jenkinsfile — Post-Deployment Security Gate
stage('Runtime Security Validation') {
    steps {
        script {
            // Query Sentinel for open incidents related to this deployment
            def sentinelCheck = sh(
                script: """
                    az sentinel incidents list \
                      --workspace-name ${LAW_NAME} \
                      --resource-group ${RG} \
                      --filter "properties/status eq 'New'" \
                      --query "length([?contains(properties.title, 'K8s')])" \
                      -o tsv
                """,
                returnStdout: true
            ).trim()

            if (sentinelCheck.toInteger() > 0) {
                error("SECURITY GATE FAILED: ${sentinelCheck} open Sentinel K8s incidents detected. " +
                      "Deployment halted pending SOC review.")
            }
        }
    }
    post {
        failure {
            // Notify security team and block merge
            slackSend(
                channel: '#security-alerts',
                color: 'danger',
                message: "Security gate blocked deployment to ${ENVIRONMENT}. " +
                         "Open Sentinel incidents require SOC review before proceeding."
            )
        }
    }
}
```

---

## 10. Screenshots Checklist

Use this checklist when documenting the detection capability for your portfolio:

### Log Analytics Workspace
- [ ] `AKSAudit` table visible in Log Analytics schema explorer
- [ ] Diagnostic settings showing `kube-audit` category enabled
- [ ] KQL query returning exec events (after simulation)
- [ ] Data ingestion graph showing consistent event flow

### Sentinel Analytics Rules
- [ ] Analytics rule listing showing both rules enabled
- [ ] Pod exec rule detail: query, frequency, entity mappings
- [ ] Privileged pod rule detail: query, MITRE tactics
- [ ] Rule test using "Test with current data" showing results

### Sentinel Incidents
- [ ] Incident queue showing generated incidents after simulation
- [ ] Incident detail: title, severity, timeline, entities
- [ ] Entity panel: Account entity with username, IP entity with source address
- [ ] MITRE ATT&CK matrix with T1609/T1611 highlighted
- [ ] Investigation graph showing entity relationships

### Automation (if playbook configured)
- [ ] Logic App triggered by incident
- [ ] Teams/Slack notification received
- [ ] AKS pod annotation added (or pod cordoned) in response
