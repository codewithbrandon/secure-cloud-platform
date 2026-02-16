# =============================================================================
# KUBERNETES SECURITY POLICIES (OPA/Rego)
# =============================================================================
# These policies enforce security requirements for Kubernetes manifests
# Used by conftest in the CI/CD pipeline
#
# Usage:
#   conftest test k8s/*.yaml --policy policies/
# =============================================================================

package main

import future.keywords.in

# =============================================================================
# CONTAINER SECURITY
# =============================================================================

# Deny containers running as root
deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.runAsNonRoot
    msg := sprintf("Container '%s' must set securityContext.runAsNonRoot to true", [container.name])
}

# Deny containers without resource limits
deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.resources.limits
    msg := sprintf("Container '%s' must define resource limits", [container.name])
}

# Deny containers without resource requests
deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.resources.requests
    msg := sprintf("Container '%s' must define resource requests", [container.name])
}

# Deny privilege escalation
deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    container.securityContext.allowPrivilegeEscalation == true
    msg := sprintf("Container '%s' must not allow privilege escalation", [container.name])
}

# Deny privileged containers
deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf("Container '%s' must not run in privileged mode", [container.name])
}

# Require dropping all capabilities
warn[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.capabilities.drop
    msg := sprintf("Container '%s' should drop all capabilities", [container.name])
}

# =============================================================================
# IMAGE SECURITY
# =============================================================================

# Deny using 'latest' tag
deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    endswith(container.image, ":latest")
    msg := sprintf("Container '%s' should not use 'latest' tag", [container.name])
}

# Deny images without explicit tag
deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not contains(container.image, ":")
    msg := sprintf("Container '%s' must specify an explicit image tag", [container.name])
}

# =============================================================================
# POD SECURITY
# =============================================================================

# Require pod security context
warn[msg] {
    input.kind == "Deployment"
    not input.spec.template.spec.securityContext
    msg := "Deployment should define pod-level securityContext"
}

# Require runAsNonRoot at pod level
deny[msg] {
    input.kind == "Deployment"
    input.spec.template.spec.securityContext
    not input.spec.template.spec.securityContext.runAsNonRoot
    msg := "Pod securityContext must set runAsNonRoot to true"
}

# =============================================================================
# HEALTH CHECKS
# =============================================================================

# Require liveness probe
warn[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.livenessProbe
    msg := sprintf("Container '%s' should define a liveness probe", [container.name])
}

# Require readiness probe
warn[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.readinessProbe
    msg := sprintf("Container '%s' should define a readiness probe", [container.name])
}

# =============================================================================
# SERVICE SECURITY
# =============================================================================

# Warn against NodePort services
warn[msg] {
    input.kind == "Service"
    input.spec.type == "NodePort"
    msg := "Service uses NodePort which exposes ports on all nodes"
}

# Warn against LoadBalancer without internal annotation
warn[msg] {
    input.kind == "Service"
    input.spec.type == "LoadBalancer"
    not input.metadata.annotations["service.beta.kubernetes.io/azure-load-balancer-internal"]
    msg := "LoadBalancer service should consider using internal load balancer"
}

# =============================================================================
# NAMESPACE SECURITY
# =============================================================================

# Require pod security labels on namespace
deny[msg] {
    input.kind == "Namespace"
    not input.metadata.labels["pod-security.kubernetes.io/enforce"]
    msg := "Namespace must define pod-security.kubernetes.io/enforce label"
}

# =============================================================================
# NETWORK POLICY
# =============================================================================

# Network policies should have specific pod selector
warn[msg] {
    input.kind == "NetworkPolicy"
    count(input.spec.podSelector.matchLabels) == 0
    msg := "NetworkPolicy should target specific pods with matchLabels"
}
