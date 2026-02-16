# Security Architecture Tradeoffs

## Portfolio-Friendly vs Production Deployment

This document outlines the architectural decisions made to balance cost optimization for a portfolio demonstration while maintaining security best practices. For each tradeoff, we document:
- What was simplified
- What production would require
- Security implications
- Estimated cost difference

---

## Cost Summary

| Deployment Type | Estimated Monthly Cost |
|-----------------|----------------------|
| **Portfolio (This Project)** | ~$250-350/month |
| **Production Enterprise** | ~$1,200-1,800/month |

---

## Network Architecture

### AKS API Server Access

| Aspect | Portfolio | Production |
|--------|-----------|------------|
| **Configuration** | Public with authorized IP ranges | Private cluster |
| **How it works** | API server has public IP, filtered by IP allowlist | API server only accessible via private endpoint |
| **Cost Impact** | None | +$140/month (Azure Bastion required) |
| **Security Trade-off** | API endpoint visible to internet scanners | Zero internet exposure |

**Production Recommendation:**
```hcl
private_cluster_enabled = true
private_dns_zone_id     = "System"
```

### Private Endpoints

| Resource | Portfolio | Production |
|----------|-----------|------------|
| **Azure SQL** | Service endpoints | Private endpoint |
| **Azure Container Registry** | Service endpoints | Private endpoint |
| **Azure Key Vault** | Service endpoints | Private endpoint |
| **Cost per endpoint** | Included | ~$7.30/month + data processing |

**Security Implication:**
- Service endpoints: Traffic stays on Azure backbone but uses public DNS
- Private endpoints: Traffic uses private IP, never touches public network

**Production Recommendation:** Enable private endpoints for all PaaS services in regulated environments (PCI-DSS, HIPAA, SOC2).

---

## Compute Resources

### AKS Node Configuration

| Aspect | Portfolio | Production |
|--------|-----------|------------|
| **VM Size** | Standard_B2s (2 vCPU, 4GB) | Standard_D4s_v3 (4 vCPU, 16GB) |
| **Node Count** | 2 nodes | 3+ nodes across availability zones |
| **Node Pools** | Single pool | Separate system/user pools |
| **Cost Impact** | ~$60/month | ~$350/month |

**Security Implication:**
- Larger nodes can run more security tools (Falco, OPA, etc.)
- Zone redundancy protects against datacenter failures
- Separate pools isolate system components from workloads

### Jenkins Server

| Aspect | Portfolio | Production |
|--------|-----------|------------|
| **VM Size** | Standard_B2s | Standard_D2s_v3 or larger |
| **Storage** | Standard SSD | Premium SSD |
| **Availability** | Single VM | VM Scale Set or AKS deployment |
| **Cost Impact** | ~$30/month | ~$100/month |

---

## Database Tier

### Azure SQL Database

| Aspect | Portfolio | Production |
|--------|-----------|------------|
| **SKU** | S0 (10 DTUs) | P1 or higher (125+ DTUs) |
| **Geo-Replication** | Disabled | Enabled (secondary region) |
| **Backup Redundancy** | Local | Geo-redundant |
| **Cost Impact** | ~$15/month | ~$465/month |

**Security Implication:**
- Higher tiers include Advanced Threat Protection at no extra cost
- Geo-replication enables disaster recovery
- Premium tier supports customer-managed keys (CMK)

---

## Application Gateway

### WAF Configuration

| Aspect | Portfolio | Production |
|--------|-----------|------------|
| **SKU** | Standard_v2 | WAF_v2 |
| **WAF Ruleset** | None | OWASP 3.2 |
| **Custom Rules** | None | Rate limiting, geo-filtering |
| **Cost Impact** | ~$175/month | ~$350/month |

**Security Implication:**
- WAF_v2 provides protection against OWASP Top 10
- Required for PCI-DSS compliance
- Blocks SQL injection, XSS, and other common attacks

**Production Recommendation:**
```hcl
waf_configuration {
  enabled          = true
  firewall_mode    = "Prevention"
  rule_set_type    = "OWASP"
  rule_set_version = "3.2"
}
```

---

## Identity & Access

### Local Kubernetes Accounts

| Aspect | Portfolio | Production |
|--------|-----------|------------|
| **Local Accounts** | Enabled | Disabled |
| **Authentication** | Azure AD + local | Azure AD only |

**Security Implication:**
- Local accounts provide backdoor access if Azure AD fails
- Production should enforce Azure AD only for audit trail
- Conditional Access policies only apply to Azure AD authentication

### Azure AD Groups

| Aspect | Portfolio | Production |
|--------|-----------|------------|
| **Admin Groups** | Not configured | Dedicated admin groups |
| **RBAC Roles** | Cluster admin | Granular namespace roles |

---

## Monitoring & Security Services

### Microsoft Defender for Cloud

| Aspect | Portfolio | Production |
|--------|-----------|------------|
| **Defender for Containers** | Enabled (free tier) | Enabled (paid features) |
| **Defender for SQL** | Basic | Advanced Threat Protection |
| **Defender for Key Vault** | Enabled | Enabled |
| **Cost Impact** | ~$15/month | ~$50/month |

### Log Retention

| Aspect | Portfolio | Production |
|--------|-----------|------------|
| **Retention Period** | 30 days | 90-365 days |
| **Cost Impact** | Free | ~$2.30/GB/month after 30 days |

**Compliance Note:** PCI-DSS requires 1 year retention; HIPAA requires 6 years.

---

## SSL/TLS Configuration

### Certificate Management

| Aspect | Portfolio | Production |
|--------|-----------|------------|
| **SSL Certificate** | Self-signed/None | Azure Key Vault managed |
| **TLS Version** | 1.2 | 1.2+ (1.3 preferred) |
| **Certificate Rotation** | Manual | Automated via Key Vault |

---

## Recommendations for Production Migration

### High Priority (Security Critical)

1. **Enable Private Endpoints**
   - SQL Database
   - Container Registry
   - Key Vault

2. **Enable WAF_v2**
   - OWASP 3.2 ruleset
   - Custom rate limiting rules

3. **Disable Local AKS Accounts**
   - Enforce Azure AD authentication
   - Configure admin groups

4. **Implement Private AKS Cluster**
   - Deploy Azure Bastion for access
   - Configure private DNS zones

### Medium Priority (Operational Excellence)

5. **Upgrade Database Tier**
   - Enable geo-replication
   - Configure long-term backup retention

6. **Implement Zone Redundancy**
   - AKS nodes across zones
   - Zone-redundant storage

7. **Extend Log Retention**
   - Minimum 90 days for security
   - 1 year for compliance

### Lower Priority (Cost Optimization)

8. **Right-size Resources**
   - Monitor actual usage
   - Adjust VM sizes accordingly

9. **Consider Reserved Instances**
   - 1-3 year commitments
   - Up to 72% cost savings

---

## Security Controls Maintained

Despite cost optimizations, these security controls are **fully implemented**:

| Control | Status |
|---------|--------|
| Network Segmentation | ✅ Implemented |
| NSG Default-Deny Rules | ✅ Implemented |
| Managed Identities | ✅ Implemented |
| RBAC Authorization | ✅ Implemented |
| TLS 1.2+ Enforcement | ✅ Implemented |
| Encryption at Rest | ✅ Implemented |
| Audit Logging | ✅ Implemented |
| Azure Policy | ✅ Implemented |
| Network Policies (Calico) | ✅ Implemented |
| Kubernetes Pod Security | ✅ Implemented |

---

## Conclusion

This portfolio deployment demonstrates enterprise security architecture patterns while optimizing for cost. The documented tradeoffs provide a clear migration path to full production deployment when budget allows.

**Key Takeaway:** Security architecture is not binary. Understanding the risk/cost tradeoffs enables informed decisions based on threat model and compliance requirements.
