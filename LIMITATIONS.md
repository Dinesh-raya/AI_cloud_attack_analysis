# Limitations

This document outlines the intentional boundaries and limitations of the Cloud Attack Analysis tool. Understanding these limitations is critical for appropriate use.

---

## What This Tool IS

- ✅ **Static Analysis Engine**: Analyzes Terraform/JSON configurations without executing code
- ✅ **Deterministic**: Produces consistent, reproducible results
- ✅ **Explainable**: Every decision can be traced to specific rules and logic
- ✅ **Offline**: Runs entirely on your local machine
- ✅ **Privacy-First**: No data leaves your environment

---

## What This Tool IS NOT

### 1. Not a Runtime Detector
This tool analyzes **infrastructure configuration**, not running systems. It cannot detect:
- Active intrusions or breaches in progress
- Runtime anomalies or behavioral indicators
- Memory-resident malware or fileless attacks
- Real-time credential abuse

**Use CSPM/CNAPP tools for runtime monitoring.**

### 2. No Cloud Credentials Required
The tool operates entirely on Terraform files. It does **not**:
- Connect to AWS, Azure, or GCP APIs
- Query live infrastructure state
- Access secrets or credentials
- Make any network requests

### 3. No Zero-Day Detection
This tool identifies **known misconfiguration patterns**. It cannot:
- Detect novel attack techniques
- Identify zero-day vulnerabilities
- Predict unknown threat actor behavior
- Perform vulnerability scanning (CVE matching)

**Use vulnerability scanners (Trivy, Grype) for CVE detection.**

### 4. No Alerting or Monitoring
This is a **point-in-time analysis tool**. It does not:
- Send alerts or notifications
- Integrate with SIEM or SOAR systems
- Provide continuous monitoring
- Track changes over time

**Integrate with CI/CD pipelines for continuous enforcement.**

### 5. No Multi-Cloud Support
Currently, the tool focuses strictly on **AWS**. We intentionally chose depth over breadth.

---

## Scope Boundaries

| Feature | In Scope | Out of Scope |
|---------|----------|--------------|
| Terraform HCL | ✅ | |
| Terraform Plan JSON | ✅ | |
| CloudFormation | | ❌ |
| Pulumi/CDK | | ❌ |
| Azure/GCP | | ❌ |
| Container Images | | ❌ |
| Kubernetes Manifests | | ❌ |

---

## Design Philosophy

> "Do one thing, do it well, and explain every decision."

We intentionally limit scope to provide **deep, explainable analysis** rather than shallow, broad coverage. Every limitation listed above is a deliberate design choice that enables:

1. **Determinism**: Same input always produces same output
2. **Explainability**: Every finding can be defended in an interview
3. **Performance**: Static analysis scales better than runtime tools
4. **Privacy**: No data exfiltration risk

---

## When to Use Other Tools

| Scenario | Recommended Tool |
|----------|------------------|
| Runtime threat detection | AWS GuardDuty, Wiz |
| Container vulnerability scanning | Trivy, Grype |
| Secrets detection | TruffleHog, GitLeaks |
| Compliance auditing | Prowler, ScoutSuite |
| Network security | AWS VPC Flow Logs |
| SIEM integration | Splunk, Elastic |

**This tool complements, not replaces, the security stack.**
