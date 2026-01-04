# Real-World Breach Analysis & Tool Verification

This document maps the **Cloud Attack Analysis** capabilities to two historical, high-profile cloud security breaches. It demonstrates how the tool's graph-based engine detects the specific kill chains that traditional point-in-time scanners often miss.

---

## 1. The Capital One Breach (2019)
**Type**: SSRF + IAM Privilege Escalation  
**Impact**: 100M+ Credit Card Applications Leaked

### The Attack Path
1.  **Ingress**: Attacker found a misconfigured Web Application Firewall (WAF) running on EC2.
2.  **Exploit**: Used Server-Side Request Forgery (SSRF) to query the `169.254.169.254` Instance Metadata Service (IMDS).
3.  **Credential Access**: Stole the temporary AWS Information Security Credentials for the IAM Role attached to the EC2.
4.  **Lateral Movement**: The IAM Role (`*-WAF-Role`) had excessive permissions (`s3:ListBuckets`, `s3:Sync`).
5.  **Exfiltration**: Attacker used the credentials to sync sensitive S3 buckets to a local machine.

### How Cloud Attack Analysis Detects It
The tool models this exact "Identity Pivot":

*   **Node A**: `aws_instance.waf_server` (Publicly exposed via SG `0.0.0.0/0`).
*   **Edge 1**: `Internet` -> `waf_server` (Method: "Network Reachability").
*   **Node B**: `aws_iam_role.waf_role`.
*   **Edge 2**: `waf_server` -> `waf_role` (Method: "IMDS/Credential Access").
*   **Node C**: `aws_s3_bucket.sensitive_data`.
*   **Edge 3**: `waf_role` -> `sensitive_data` (Method: "IAM Permission allow").

**Why Traditional Scanners Missed It**:
*   **Scanner View**: "S3 Buckets are Private (ACL=private)". ✅ COMPLIANT.
*   **Scanner View**: "EC2 instance is patched". ✅ COMPLIANT.
*   **Graph View (Our Tool)**: "Public EC2 has Admin access to Private S3." ❌ CRITICAL.

---

## 2. ShadowRay Attack (2023)
**Type**: AI Workload Exposure + RCE  
**Impact**: Thousands of Ray AI clusters compromised for crypto-mining and data theft.

### The Attack Path
1.  **Ingress**: Ray (open-source AI framework) Dashboard listens on port 8265.
2.  **Exploit**: Misconfigured Security Groups allowed `0.0.0.0/0` access to port 8265.
3.  **RCE**: The Dashboard has no authentication by default. Attackers submitted jobs to run arbitrary code.
4.  **Credential Access**: Malicious jobs queried IMDS to steal IAM credentials.
5.  **Action**: Attackers downloaded data or launched GPU mining instances.

### How Cloud Attack Analysis Detects It
This highlights the **AI Threat Model** extension.

*   **Node A**: `aws_instance.ray_head_node` (Tagged or identified as AI workload).
*   **Edge 1**: `Internet` -> `ray_head_node` (Method: "Network Reachability" - identified by SG `0.0.0.0/0`).
    *   *Refinement*: The tool flags this risk specifically as "Exploit Public Service".
*   **Node B**: `aws_iam_role.ray_worker_role`.
*   **Edge 2**: `ray_head_node` -> `ray_worker_role` (Method: "IMDS/Credential Access").
*   **Node C**: `aws_s3_bucket.training_data`.
*   **Edge 3**: `ray_worker_role` -> `training_data` (Method: "IAM Permission allow").

**Why Traditional Scanners Missed It**:
*   They treated the EC2 instance as a generic server, ignoring the context of the **unauthenticated AI service** (Ray) running on it, which elevates the risk of "Public Reachability" to "Confirmed RCE".

---

## 3. Simulation
We have provided a Terraform simulation of the ShadowRay attack path in `examples/real_world_breaches/main.tf`.

**Run the verification:**
```bash
python -m cloud_attack_analysis.cli scan ./examples/real_world_breaches
```
