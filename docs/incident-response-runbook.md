# Incident Response Runbook — Kubernetes Runtime Security

> **Classification:** INTERNAL — SOC RESTRICTED
> **Runbook Version:** 2.1
> **Applies To:** AKS clusters managed under the secure-cloud-platform
> **Review Cycle:** Quarterly or after major incident
> **Owner:** Platform Security Engineering / SOC Tier 2

---

## Quick Reference

| Severity | Acknowledge SLA | Contain SLA | Escalate To |
|----------|----------------|-------------|-------------|
| Critical | 5 minutes | 30 minutes | CISO + VP Engineering |
| High | 15 minutes | 60 minutes | Security Lead |
| Medium | 60 minutes | 4 hours | SOC Team Lead |
| Low | 4 hours | Next business day | Assigned Analyst |

**Emergency Contacts:**

```
SOC On-Call:       PagerDuty → #security-oncall rotation
AKS Platform:      PagerDuty → #platform-oncall rotation
CISO Office:       Internal directory → escalation bridge
Vendor Support:    Microsoft Unified Support → case portal
```

---

## Runbook Index

| Scenario | Section |
|----------|---------|
| Unauthorized Pod Exec Detected | [Section 1](#scenario-1-unauthorized-pod-exec) |
| Privileged Container Created | [Section 2](#scenario-2-privileged-container-creation) |
| Dangerous hostPath Mount | [Section 3](#scenario-3-dangerous-hostpath-mount) |
| cluster-admin Binding Created | [Section 4](#scenario-4-cluster-admin-binding) |
| Combined / Multi-Stage Attack | [Section 5](#scenario-5-combined-multi-stage-attack) |

---

## Scenario 1: Unauthorized Pod Exec

**Triggered by:** `AKS - Unauthorized Pod Exec Detected` (Sentinel Analytics Rule)
**MITRE:** T1609 Container Administration Command, T1611 Escape to Host

---

### Phase 1: Triage (0–5 minutes)

**1.1 — Open the Sentinel Incident**

Navigate to: `Microsoft Sentinel → Incidents → [Incident Title]`

Immediately assess:
- [ ] Severity: Critical or High?
- [ ] Is `ExecSucceeded = true`? (HTTP 101 or 200 means exec stream opened)
- [ ] Is `IsAnonymous = true`? (Unauthenticated access — escalate immediately)
- [ ] Is the target namespace in `SensitiveNamespaces`? (production, payments, secrets)
- [ ] Is `SourceIPs` an internal CI/CD IP or an unexpected external address?

> **CRITICAL INDICATOR:** If `ExecSucceeded = true` AND `IsSensitiveNamespace = true`,
> **immediately escalate** to Security Lead and proceed to containment without
> waiting for full investigation.

**1.2 — Pull Full Investigation Context (KQL)**

Run in Log Analytics → AKS cluster workspace:

```kql
// Full context for the incident's actor and time window
// Replace <actor>, <namespace>, <pod> with values from the Sentinel incident
let InvestigationActor = "<ActorUsername from incident>";
let InvestigationPod   = "<TargetPod from incident>";
let InvestigationNS    = "<TargetNamespace from incident>";
let IncidentTime       = datetime(<TimeGenerated from incident>);

// [1] All actions by this actor in the last 24 hours
AKSAudit
| where TimeGenerated between ((IncidentTime - 24h) .. (IncidentTime + 1h))
| where User_Username =~ InvestigationActor
| project TimeGenerated, Verb, ObjectRef_Resource, ObjectRef_Subresource,
          ObjectRef_Name, ObjectRef_Namespace, ResponseStatus_Code, UserAgent
| order by TimeGenerated asc

// [2] All activity on the target pod in the last 24 hours
AKSAudit
| where TimeGenerated between ((IncidentTime - 24h) .. (IncidentTime + 1h))
| where ObjectRef_Name =~ InvestigationPod
    and ObjectRef_Namespace =~ InvestigationNS
| project TimeGenerated, User_Username, Verb, ObjectRef_Subresource,
          ResponseStatus_Code, SourceIps, UserAgent
| order by TimeGenerated asc

// [3] Other exec events from the same source IP
AKSAudit
| where TimeGenerated between ((IncidentTime - 1h) .. (IncidentTime + 1h))
| where ObjectRef_Subresource =~ "exec"
| where SourceIps has_any (
    // Extract IP from incident — paste IP here
    "<SourceIP from incident>"
)
| project TimeGenerated, User_Username, ObjectRef_Name, ObjectRef_Namespace,
          ResponseStatus_Code, AuditID
| order by TimeGenerated asc
```

**1.3 — Assess Pod Posture**

```bash
# Check if the exec'd pod is privileged or has dangerous config
kubectl get pod <pod-name> -n <namespace> -o yaml | \
  python3 -c "
import yaml, sys
pod = yaml.safe_load(sys.stdin)
for c in pod['spec'].get('containers', []):
    sc = c.get('securityContext', {})
    print(f'Container: {c[\"name\"]}')
    print(f'  privileged: {sc.get(\"privileged\", False)}')
    print(f'  runAsUser: {sc.get(\"runAsUser\", \"default\")}')
    print(f'  allowPrivilegeEscalation: {sc.get(\"allowPrivilegeEscalation\", True)}')
for v in pod['spec'].get('volumes', []):
    if 'hostPath' in v:
        print(f'  hostPath: {v[\"hostPath\"][\"path\"]}')
"

# Check pod's service account and what permissions it has
SA=$(kubectl get pod <pod-name> -n <namespace> \
  -o jsonpath='{.spec.serviceAccountName}')
echo "Service Account: $SA"

kubectl auth can-i --list \
  --as=system:serviceaccount:<namespace>:${SA} \
  --namespace=<namespace>

# Check if the pod has any mounted secrets
kubectl get pod <pod-name> -n <namespace> \
  -o jsonpath='{range .spec.volumes[*]}{.name}: {.secret.secretName}{"\n"}{end}'
```

---

### Phase 2: Investigation (5–30 minutes)

**2.1 — Identity Verification**

```bash
# Verify if the actor identity is a known service account
kubectl get serviceaccount -A | grep -i "<actor-name>"

# Check what RBAC permissions this identity has
kubectl auth can-i --list --as=<ActorUsername>

# Check if actor is associated with any CI/CD system
# Cross-reference with Jenkins build logs, Azure DevOps pipeline history
# Look for: did any pipeline run execute a kubectl exec at this time?
```

**2.2 — Source IP Analysis**

Cross-reference the `SourceIPs` value:

```kql
// Check if this IP has appeared in other security-relevant events
union AKSAudit, SigninLogs, AzureActivity
| where TimeGenerated > ago(7d)
| where tostring(SourceIps) contains "<suspicious-IP>"
   or tostring(IPAddress) contains "<suspicious-IP>"
| project TimeGenerated, Type, OperationName, tostring(SourceIps),
          tostring(IPAddress), Identity, ResultType
| order by TimeGenerated desc
```

Check IP against threat intelligence:
- [ ] Is it in the corporate VPN/office IP range?
- [ ] Is it a known cloud provider IP (Azure DevOps agent, GitHub Actions)?
- [ ] Is it an external IP with no known association?
- [ ] Query Microsoft Sentinel TI Blade for IP reputation

**2.3 — Determine What Was Executed**

If `RequestObject` contains command data, extract it:

```kql
AKSAudit
| where AuditID == "<AuditID from incident>"
| extend ExecArgs = parse_json(RequestObject)
| project ExecArgs, User_Username, TimeGenerated
```

Even if the command body is not captured, check for subsequent log access:

```kql
// Did the actor or pod access secrets after the exec?
AKSAudit
| where TimeGenerated between (datetime(<exec-time>) .. (datetime(<exec-time>) + 30m))
| where User_Username =~ "<actor>"
    or ObjectRef_Name =~ "<pod>"
| where ObjectRef_Resource =~ "secrets"
    or ObjectRef_Subresource =~ "log"
| project TimeGenerated, Verb, ObjectRef_Name, ObjectRef_Namespace, User_Username
```

**2.4 — Container Runtime Evidence**

If possible, examine container logs before containment:

```bash
# Capture current stdout logs (may contain evidence of commands run)
kubectl logs <pod-name> -n <namespace> --previous > /tmp/pod-logs-$(date +%s).txt 2>&1
kubectl logs <pod-name> -n <namespace> >> /tmp/pod-logs-$(date +%s).txt 2>&1

# If exec succeeded, check for suspicious processes (if pod is still accessible)
# CAUTION: Only do this if the pod is still running and you have authorization
kubectl exec <pod-name> -n <namespace> -- ps auxf
kubectl exec <pod-name> -n <namespace> -- netstat -anltp
kubectl exec <pod-name> -n <namespace> -- cat /proc/1/cmdline
```

---

### Phase 3: Containment (30–60 minutes)

> **Containment Priority Order:**
> 1. Stop the exec session (evict pod)
> 2. Prevent new exec sessions (NetworkPolicy + RBAC)
> 3. Isolate the namespace
> 4. Preserve evidence

**3.1 — Option A: Immediate Pod Eviction (Recommended for Critical)**

```bash
# Preserve final log state before deletion
kubectl logs <pod-name> -n <namespace> --all-containers > \
  /evidence/pod-<pod-name>-$(date +%s).log

# Delete the pod — if managed by a Deployment/ReplicaSet, it will restart
# This terminates any active exec session immediately
kubectl delete pod <pod-name> -n <namespace> --grace-period=0

# If the pod keeps restarting via a controller, scale down the controller
kubectl scale deployment <deployment-name> -n <namespace> --replicas=0
# OR for DaemonSet (requires editing):
kubectl patch daemonset <ds-name> -n <namespace> \
  -p '{"spec":{"template":{"spec":{"nodeSelector":{"non-existing":"true"}}}}}'
```

**3.2 — Option B: Namespace Network Quarantine (Preferred for Investigation Preservation)**

Apply a deny-all NetworkPolicy to isolate the namespace while preserving
the pod for forensic examination:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: quarantine-deny-all
  namespace: <target-namespace>
  annotations:
    security.io/quarantine-reason: "Sentinel incident <incident-id>"
    security.io/quarantine-time: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    security.io/quarantine-by: "<analyst-name>"
spec:
  podSelector: {}          # Applies to ALL pods in namespace
  policyTypes:
  - Ingress
  - Egress
  # No ingress/egress rules = deny all traffic
EOF

echo "Namespace <target-namespace> is now in network quarantine."
echo "All ingress and egress traffic is blocked."
echo "Existing TCP connections may persist briefly — monitor with kubectl get events -n <namespace>"
```

**3.3 — RBAC Lockdown — Revoke Exec Permissions**

```bash
# Find all RoleBindings/ClusterRoleBindings that grant exec to the actor
kubectl get rolebindings,clusterrolebindings -A \
  -o json | jq -r \
  '.items[] | select(.subjects[]? | .name == "<actor-name>") |
   "\(.kind)/\(.metadata.namespace)/\(.metadata.name)"'

# If actor has explicit exec RBAC, annotate for review and optionally delete
kubectl annotate rolebinding <binding-name> -n <namespace> \
  security.io/under-review=true \
  security.io/review-reason="Sentinel incident <incident-id>"

# For confirmed unauthorized access — delete the binding
kubectl delete rolebinding <binding-name> -n <namespace>
```

**3.4 — Invalidate Actor Credentials**

If the actor is an Azure AD user or service principal:

```bash
# Revoke Azure AD session tokens for the user
az ad user revoke-sign-in-sessions --id <user-principal-name>

# If a service account token was compromised, delete and recreate the SA
kubectl delete serviceaccount <sa-name> -n <namespace>
kubectl create serviceaccount <sa-name> -n <namespace>
# All existing tokens for this SA are immediately invalidated upon deletion

# Rotate kubeconfig credentials if a kubeconfig file was suspected stolen
az aks get-credentials \
  --resource-group <rg> \
  --name <cluster-name> \
  --overwrite-existing \
  --admin  # Generates fresh admin kubeconfig
```

---

### Phase 4: Secret Rotation

> **Trigger this phase if:** exec succeeded AND the pod had mounted secrets,
> database credentials, API keys, or certificates.

**4.1 — Identify All Secrets Accessible to the Compromised Pod**

```bash
# List all secrets mounted to the pod at time of incident
kubectl get pod <pod-name> -n <namespace> -o jsonpath=\
  '{range .spec.volumes[*]}{.secret.secretName}{"\n"}{end}' | \
  grep -v "^$"

# List all secrets in the namespace that the pod's SA could access
kubectl auth can-i get secrets -n <namespace> \
  --as=system:serviceaccount:<namespace>:<sa-name>

# Get all secret names in the namespace (not values)
kubectl get secrets -n <namespace> -o name
```

**4.2 — Rotate Secrets in Azure Key Vault**

```bash
# For each secret identified in 4.1, rotate in Azure Key Vault
az keyvault secret set \
  --vault-name <keyvault-name> \
  --name <secret-name> \
  --value "<new-rotated-value>"

# Update the Kubernetes secret with the new value
kubectl create secret generic <k8s-secret-name> \
  --from-literal=<key>=<new-value> \
  --namespace=<namespace> \
  --dry-run=client -o yaml | kubectl apply -f -

# Rolling restart to pick up new secret values
kubectl rollout restart deployment/<deployment-name> -n <namespace>
kubectl rollout status deployment/<deployment-name> -n <namespace>
```

**4.3 — Rotate TLS Certificates (if cert-manager in scope)**

```bash
# Force cert-manager to renew certificates in the affected namespace
kubectl annotate certificate <cert-name> -n <namespace> \
  cert-manager.io/issueTime="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --overwrite

# Or delete the secret — cert-manager will auto-renew
kubectl delete secret <tls-secret-name> -n <namespace>
```

**4.4 — Rotate Database Credentials**

For managed databases (Azure SQL, PostgreSQL Flexible Server):

```bash
# Rotate the admin password (use strong generated value)
NEW_PASSWORD=$(openssl rand -base64 32)

az postgres flexible-server update \
  --resource-group <rg> \
  --name <db-server-name> \
  --admin-password "${NEW_PASSWORD}"

# Update corresponding Kubernetes secret
kubectl create secret generic db-credentials \
  --from-literal=password="${NEW_PASSWORD}" \
  --namespace=<namespace> \
  --dry-run=client -o yaml | kubectl apply -f -
```

---

### Phase 5: RBAC Review

**5.1 — Full RBAC Audit for the Affected Namespace**

```bash
# Generate comprehensive RBAC report for the namespace
echo "=== ClusterRoleBindings affecting this namespace ==="
kubectl get clusterrolebindings -o json | jq -r \
  '.items[] | select(.subjects[]? | .namespace == "<namespace>" or .namespace == null) |
   "\(.metadata.name): \(.roleRef.name) → \(.subjects[].name) (\(.subjects[].kind))"'

echo "=== RoleBindings in namespace ==="
kubectl get rolebindings -n <namespace> -o json | jq -r \
  '.items[] | "\(.metadata.name): \(.roleRef.name) → \(.subjects[].name) (\(.subjects[].kind))"'

echo "=== Service accounts in namespace ==="
kubectl get serviceaccounts -n <namespace>

# For each service account, check permissions
for SA in $(kubectl get sa -n <namespace> -o name | cut -d/ -f2); do
  echo "--- SA: $SA ---"
  kubectl auth can-i --list \
    --as=system:serviceaccount:<namespace>:${SA} \
    --namespace=<namespace> | grep -v "^no\|^Resources"
done
```

**5.2 — Identify Over-Permissioned Bindings**

```kql
// KQL: Find all subjects granted exec permissions in audit history
AKSAudit
| where TimeGenerated > ago(30d)
| where ObjectRef_Resource =~ "rolebindings" or ObjectRef_Resource =~ "clusterrolebindings"
| where Verb in~ ("create", "update")
| where ResponseStatus_Code in (200, 201)
| extend RoleRef = tostring(parse_json(RequestObject).roleRef.name)
| where RoleRef contains "exec" or RoleRef contains "admin"
| project TimeGenerated, User_Username, ObjectRef_Name, ObjectRef_Namespace, RoleRef
| order by TimeGenerated desc
```

**5.3 — Apply Least-Privilege Remediation**

```yaml
# Replace broad exec permissions with scoped exec role
# Create: sentinel/remediation/exec-role-least-privilege.yaml

apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-exec-restricted
  namespace: <namespace>
  annotations:
    security.io/reason: "Least-privilege replacement post-incident"
    security.io/created-by: "SOC incident response"
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
  # Note: No exec permission here — exec is a subresource
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
  # Scope to specific pod labels if possible
  resourceNames: ["<specific-pod-names-only>"]
```

---

### Phase 6: Recovery & Post-Incident

**6.1 — Restore Namespace from Quarantine**

```bash
# Remove quarantine NetworkPolicy
kubectl delete networkpolicy quarantine-deny-all -n <namespace>

# Restore normal network policies
kubectl apply -f infrastructure/k8s/network-policies/<namespace>/

# Verify connectivity is restored
kubectl exec -n <namespace> <pod-name> -- curl -s http://kubernetes.default.svc.cluster.local
```

**6.2 — Validate Security Controls**

```bash
# Confirm OPA/Gatekeeper policies are enforcing
kubectl get constrainttemplate
kubectl get constraints -A

# Run a smoke test of detection rules (synthetic audit event)
# Use the simulation commands from detections-runtime.md in a non-prod namespace
kubectl run probe-exec --image=alpine --restart=Never -n monitoring -- sleep 60
kubectl exec probe-exec -n monitoring -- whoami
kubectl delete pod probe-exec -n monitoring

# Verify the smoke test generated a Sentinel alert within 5-10 minutes
```

**6.3 — Documentation & Post-Incident Review**

Complete the following within 24 hours of incident closure:

```
INCIDENT REPORT TEMPLATE
═════════════════════════
Incident ID:       [Sentinel Incident Number]
Detection Time:    [TimeGenerated from alert]
Triage Start:      [Analyst acknowledgement timestamp]
Containment Time:  [Time of first containment action]
Resolution Time:   [Incident closed timestamp]

MTTR Breakdown:
  Detection Gap:   [Time between attack and alert] minutes
  Triage Duration: [Triage start to containment start] minutes
  Containment:     [Containment start to isolation complete] minutes
  Recovery:        [Isolation complete to services restored] minutes

Root Cause:
  [What allowed the exec? Missing RBAC control? Stolen credential?]

Attack Path:
  [Step-by-step reconstruction of attacker actions]

Impact Assessment:
  - Secrets potentially accessed: [list]
  - Data potentially exfiltrated: [assessment]
  - Systems potentially pivoted to: [list]

Remediation Actions Taken:
  - [List all containment and recovery actions]

Detection Gap Analysis:
  - Were all detection rules firing as expected?
  - Was the alert severity appropriate?
  - Was the response SLA met?

Process Improvements:
  - [Any runbook updates needed?]
  - [Any detection rule tuning needed?]
  - [Any infrastructure control gaps identified?]
```

---

## Scenario 2: Privileged Container Creation

**Triggered by:** `AKS - Privileged Container & Risky K8s Config Detection` (DetectionType = PrivilegedContainer)
**MITRE:** T1611 Escape to Host, T1610 Deploy Container

### Investigation Steps

```bash
# 1. Identify the container and inspect its full spec
kubectl get <resource-kind> <resource-name> -n <namespace> -o yaml

# 2. Determine if the container has been running long enough to have escaped
kubectl get pod <pod-name> -n <namespace> \
  -o jsonpath='{.status.startTime}'

# 3. Check for signs of host namespace access from within the pod
# (only if safe to exec — consider containment risk)
kubectl exec <pod-name> -n <namespace> -- ls /proc/1/root/ 2>/dev/null
# If this returns host filesystem contents → container has host access

# 4. Check for unusual processes that suggest escape has occurred
kubectl exec <pod-name> -n <namespace> -- ps auxf | \
  grep -E "nsenter|chroot|unshare|mount"
```

### Containment

```bash
# Immediate: Delete privileged pod
kubectl delete pod <pod-name> -n <namespace> --grace-period=0

# Block further privileged pods via PodSecurity admission
kubectl label namespace <namespace> \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest

# Verify PodSecurity label is applied
kubectl get namespace <namespace> --show-labels
```

---

## Scenario 3: Dangerous hostPath Mount

**Triggered by:** `AKS - Privileged Container & Risky K8s Config Detection` (DetectionType = HostPathMount)
**MITRE:** T1611 Escape to Host

### Critical Path Assessment

If `HostPathValue` contains a container runtime socket:

```bash
# CRITICAL: Check if the container runtime socket was mounted and accessible
# This allows spawning new privileged containers — treat as node compromise

# From inside the container (if still running and forensics required):
kubectl exec <pod-name> -n <namespace> -- ls -la /var/run/docker.sock 2>/dev/null
kubectl exec <pod-name> -n <namespace> -- ls -la /run/containerd/containerd.sock 2>/dev/null

# If socket is accessible, assume node is compromised.
# Initiate node draining and replacement:
kubectl cordon <node-name>
kubectl drain <node-name> --ignore-daemonsets --delete-emptydir-data
# Terminate the VM and let AKS replace it via node pool scaling
az vmss delete-instances \
  --resource-group <node-rg> \
  --name <vmss-name> \
  --instance-ids <instance-id>
```

---

## Scenario 4: cluster-admin Binding

**Triggered by:** `AKS - Privileged Container & Risky K8s Config Detection` (DetectionType = ClusterAdminBinding)
**MITRE:** T1078 Valid Accounts, T1548 Abuse Elevation Control

> **This is always a Critical incident. Do not downgrade.**

### Immediate Response (0–5 minutes)

```bash
# 1. Delete the unauthorized binding IMMEDIATELY
kubectl delete clusterrolebinding <binding-name>
# OR for a RoleBinding:
kubectl delete rolebinding <binding-name> -n <namespace>

# 2. Verify deletion
kubectl get clusterrolebinding <binding-name> 2>&1 | grep "not found"

# 3. Check what actions the newly bound subject took during the window
# (time between binding creation and deletion)
```

```kql
// All actions by the newly privileged subject after binding was created
AKSAudit
| where TimeGenerated between (datetime(<binding-creation-time>) .. now())
| where User_Username =~ "<granted-to-subject>"
| project TimeGenerated, Verb, ObjectRef_Resource, ObjectRef_Name,
          ObjectRef_Namespace, ResponseStatus_Code, UserAgent, SourceIps
| order by TimeGenerated asc
```

### RBAC Blast Radius Assessment

```bash
# What could they have done with cluster-admin? Answer: Everything.
# Focus on what the audit logs show they DID do:

# Check for: secret reads (credential harvesting)
# Check for: additional RBAC mutations (persistence establishment)
# Check for: new workload creation (backdoor pods)
# Check for: namespace creation (hidden workspaces)

kubectl get clusterrolebindings,rolebindings -A \
  --field-selector metadata.creationTimestamp=2025-xx-xxTxx:xx:xxZ 2>/dev/null
# Adjust timestamp to binding creation window
```

---

## Scenario 5: Combined Multi-Stage Attack

**Pattern:** Attacker uses exec (T1609) to deploy a privileged pod (T1611) and
then creates a cluster-admin binding (T1078) for persistence.

### Detection: Correlation Query

```kql
// Correlate exec, privileged pod, and RBAC events by actor or IP
let AttackWindow = 2h;
let SuspiciousActors =
    AKSAudit
    | where TimeGenerated > ago(AttackWindow)
    | where ObjectRef_Subresource =~ "exec"
    | where User_Username !startswith "system:"
    | summarize ExecCount=count() by User_Username, SourceIPs=tostring(SourceIps)
    | where ExecCount >= 1;

let PrivilegedWorkloads =
    AKSAudit
    | where TimeGenerated > ago(AttackWindow)
    | where ObjectRef_Resource in~ ("pods", "deployments")
    | where Verb in~ ("create", "update")
    | where parse_json(RequestObject).spec.containers[0].securityContext.privileged == true
    | project User_Username, ObjectRef_Name, ObjectRef_Namespace, TimeGenerated;

let RBACEscalation =
    AKSAudit
    | where TimeGenerated > ago(AttackWindow)
    | where ObjectRef_Resource in~ ("clusterrolebindings", "rolebindings")
    | where Verb in~ ("create", "update")
    | where tostring(parse_json(RequestObject).roleRef.name) contains "admin"
    | project User_Username, ObjectRef_Name, TimeGenerated;

// Join: actors who did exec AND privileged pod creation
SuspiciousActors
| join kind=inner PrivilegedWorkloads on User_Username
| join kind=leftouter RBACEscalation on User_Username
| project
    Actor = User_Username,
    ExecCount,
    PrivilegedPod = ObjectRef_Name,
    Namespace = ObjectRef_Namespace,
    RBACBinding = ObjectRef_Name1,
    SourceIPs,
    AttackStages = case(
        isnotempty(RBACBinding), "Exec → PrivilegedPod → RBAC Escalation (FULL KILL CHAIN)",
        "Exec → PrivilegedPod (PARTIAL KILL CHAIN)"
    )
```

### Response: Assume Full Cluster Compromise

If the full kill chain is confirmed:

1. **Engage CISO and VP Engineering immediately**
2. **Freeze all deployments** — Jenkins gates active
3. **Cordon all nodes** — prevent scheduling of new workloads
4. **Rotate ALL cluster credentials:**
   - Azure AD application credentials
   - AKS service principal / managed identity
   - All Kubernetes secrets across all namespaces
   - Certificate Authority if cert-manager is in scope
5. **Consider cluster rebuild** if node-level compromise is confirmed
6. **Forensic preservation** — take node VM snapshots before draining
7. **Activate Business Continuity Plan** if production is impacted

```bash
# Emergency: Rotate AKS service principal credentials
az ad sp credential reset \
  --id <aks-sp-app-id> \
  --append false

# Emergency: Rotate cluster certificates (triggers rolling node restart)
az aks rotate-certs \
  --resource-group <rg> \
  --name <cluster-name> \
  --yes

# This operation takes 30-45 minutes and will briefly disrupt API access
```

---

## Appendix A: Evidence Preservation Checklist

Before any destructive containment action, preserve:

- [ ] `kubectl logs <pod> -n <ns> --all-containers --previous > evidence/`
- [ ] `kubectl get pod <pod> -n <ns> -o yaml > evidence/pod-spec-$(date +%s).yaml`
- [ ] `kubectl describe pod <pod> -n <ns> > evidence/pod-describe-$(date +%s).txt`
- [ ] Sentinel incident export (JSON) including all alert details and entity data
- [ ] Log Analytics KQL query results covering the incident time window (CSV export)
- [ ] `kubectl get events -n <ns> --sort-by='.lastTimestamp' > evidence/events.txt`
- [ ] AKS diagnostic logs for the cluster (export from Azure Storage if configured)

## Appendix B: Useful KQL Reference Queries

```kql
// Show all unique actors who used exec in the last 30 days
AKSAudit
| where TimeGenerated > ago(30d)
| where ObjectRef_Subresource =~ "exec"
| where Stage =~ "ResponseComplete"
| summarize ExecCount=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated),
            Namespaces=make_set(ObjectRef_Namespace),
            TargetPods=make_set(ObjectRef_Name)
  by User_Username, tostring(SourceIps)
| order by ExecCount desc

// Detect rapid successive exec attempts (brute-force / script behavior)
AKSAudit
| where TimeGenerated > ago(1h)
| where ObjectRef_Subresource =~ "exec"
| summarize ExecCount=count() by User_Username, bin(TimeGenerated, 1m)
| where ExecCount > 5
| order by ExecCount desc

// Show all cluster-admin bindings currently in the cluster
// (not audit — this uses AKSAudit history; for live state use kubectl)
AKSAudit
| where TimeGenerated > ago(90d)
| where ObjectRef_Resource =~ "clusterrolebindings"
| where Verb in~ ("create", "update")
| where tostring(parse_json(RequestObject).roleRef.name) =~ "cluster-admin"
| summarize arg_max(TimeGenerated, *) by ObjectRef_Name
| where Verb !~ "delete"
| project TimeGenerated, ObjectRef_Name, User_Username, Subjects=parse_json(RequestObject).subjects
```

## Appendix C: Contact & Escalation Matrix

| Scenario | Primary | Secondary | Executive |
|----------|---------|-----------|-----------|
| Exec into production pod | SOC Lead | Platform Security | Engineering VP |
| Node-level compromise suspected | SOC Lead + Platform | CISO | CTO |
| Cluster-admin binding created | SOC Lead | CISO | CTO + Legal |
| Data exfiltration suspected | SOC Lead + CISO | Legal / Privacy | CEO (if regulated data) |
| Full cluster compromise | CISO | External IR Firm | Board notification (if material) |
