# Cloud Attack Analysis – AI-Aware Edition

**A Production-Quality Offline Security Engine for AI-Cloud Infrastructure**

## Problem Statement
In the era of AI, cloud infrastructure is no longer just EC2 and S3. It now includes Vector Stores, LLM Endpoints (SageMaker, Bedrock), and massive datasets of prompt history. Traditional security tools often overlook the unique risks posed by these AI services.

Calculated Risk = `Exposure` × `Privilege` × `AI Data Sensitivity`

This tool allows security engineers to **model attack paths deterministically** from Terraform code, answering the question:
> "Can an attacker starting from the Internet reach my sensitive AI prompt logs?"

## Features
- **Offline & Private**: No cloud credentials required. Runs entirely on your local machine.
- **AI-Aware**: Specifically models Bedrock and SageMaker as high-value targets.
- **Graph-Based Engine**: Uses NetworkX to build a directed graph of resources and trust relationships.
- **Deterministic**: No "hallucinating" AI guesses. Logic is based on rigid security rules.

## Architecture

1. **Parser**: Reading Terraform (HCL) maps them to normalized Resource objects.
2. **Graph Builder**: Connects resources (EC2 -> SG, Role -> Policy, AI -> S3).
3. **Rules Engine**: Flags misconfigurations (e.g., `0.0.0.0/0`, `Effect: Allow *`).
4. **Attack Engine**: Simulates an attacker traversing the graph (BFS) to find the "Crown Jewels".
5. **Reporter**: specific fix recommendations.

### Attack Path Diagram (ASCII)

```
[ Internet ] 
     | (Public SG vulnerability)
     v
[ EC2 Instance ]
     | (Instance Profile / Assumes Role)
     v
[ IAM Role (Admin/*) ]
     | (Over-permissive Policy)
     v
[ Bedrock Logging Config ]
     | (Logs_to relationship)
     v
[ S3 Bucket (Prompt Logs) ] ---> EXFILTRATION (Critical Risk)
```

## Installation

Requires Python 3.10+

```bash
pip install -r requirements.txt
python setup.py install
```

## Usage

**Scanning a Terraform Directory**

```bash
python -m cloud_attack_analysis.cli scan ./examples/vulnerable_infra
```

**Example Output**

```
[*] Scanning directory: ./examples/vulnerable_infra...
[*] Parsed 6 resources.
[*] Built resource graph with 6 nodes.
[*] Detected 3 misconfigurations.

[!] CRITICAL ATTACK PATH DETECTED [!]
Risk Score: 50.0 | Severity: Critical
------------------------------------------------------------
1. [External] Internet
   🔻 exploits trust to reach
2. [aws_instance] aws_instance.app_server
   🔻 exploits trust to reach
3. [aws_iam_role] aws_iam_role.ec2_ai_role
   🔻 exploits trust to reach
4. [aws_bedrock_model_invocation_logging_configuration] aws_bedrock_model_invocation_logging_configuration.main
   🔻 exploits trust to reach
5. [aws_s3_bucket] aws_s3_bucket.ai_logs
   🛑 exploits trust to reach
------------------------------------------------------------
Narrative:
The attacker starts at the Internet.
They locate a public-facing instance or service.
Through lateral movement (role assumption or permissions), they pivot.
Finally, they reach aws_s3_bucket.ai_logs, containing sensitive AI artifacts.
------------------------------------------------------------
RECOMMENDED FIXES:
1. Restrict Security Group ingress (Remove 0.0.0.0/0).
2. Enforce Least Privilege on IAM Roles (Remove '*').
3. Encrypt AI Model Logs and block public S3 access.
```

## Why This Matters
AI logs often contain:
- Proprietary algorithms (in prompts)
- PII/Customer data (in RAG contexts)
- API keys (accidentally pasted)

This tool treats these logs as "Critical Data" nodes in the graph, ensuring they are prioritized in risk analysis.

## Project Philosophy
1.  **Deterministic over Probabilistic**: We do not use LLMs to *guess* if something is secure. We use graph theory and rigid policy evaluation. Security tools must be predictable.
2.  **Infrastructure is Code**: We analyze the *intent* (HCL), not just the live state. This allows for Shift-Left security.
3.  **Restraint**: We focus *only* on the critical path to data. We do flag every minor best-practice violation (e.g., missing tags). Signal > Noise.

## What This Tool Intentionally Does NOT Do
*   **Runtime Detection**: We are not an EDR. We do not monitor running processes or network packets.
*   **Multi-Cloud Sprawl**: We currently focus strictly on AWS. Quality over quantity.
*   **"Magic" Remediation**: We suggest fixes, but we will never auto-apply changes to your code. Humans must remain in the loop.

## Roadmap
*   **v1.0 (Current)**: 
    *   Core Graph Engine (NetworkX).
    *   Basic AWS Resource Support (EC2, S3, IAM, Bedrock, SageMaker).
    *   Pathfinding Algorithm targeting "logs_to" relationships.
*   **v2.0 (Planned)**: 
    *   Expanded IAM parsing (Condition keys, `NotAction`).
    *   Support for vector databases (Pinecone, Weaviate) if declared in Terraform.
    *   CI/CD Integration (GitHub Actions output).
*   **v3.0 (Long Term)**: 
    *   Live State Ingestion (boto3) to augment static analysis.
    *   Visual Graph Export (GraphViz/Mermaid).
