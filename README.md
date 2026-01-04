# Cloud Attack Analysis – AI-Aware Edition

**A Production-Quality Offline Security Engine for AI-Cloud Infrastructure**

## Problem Statement
In the era of AI, cloud infrastructure is no longer just EC2 and S3. It now includes Vector Stores, LLM Endpoints (SageMaker, Bedrock), and massive datasets of prompt history. Traditional security tools often overlook the unique risks posed by these AI services.

Calculated Risk = `Exposure` × `Privilege` × `AI Data Sensitivity`

This tool allows security engineers to **model attack paths deterministically** from Terraform code, answering the question:
> "Can an attacker starting from the Internet reach my sensitive AI prompt logs?"

---

## 🏰 The Castle Analogy (Explained for the Rest of Us)

If you're wondering how this differs from other tools, imagine your Cloud Infrastructure is a giant **Lego Castle**.

#### 1. Standard Tools (The Building Inspector)
Tools like **Prowler** or **ScoutSuite** act like a Building Inspector with a clipboard. They check one thing at a time:
*   "Is the front gate locked?" -> **YES** ✅
*   "Does the guard have a badge?" -> **YES** ✅

The Inspector says: **"Great job! Your castle is safe."**

#### 2. The Problem
The Inspector misses the *story*. He didn't notice that the cat window is open, and the cat knows a secret tunnel to the treasury.

#### 3. Cloud Attack Analysis (The Heist Planner)
This tool acts like a **Master Thief**. It doesn't look at a checklist; it draws a **Map of Connections**:
1.  "I can crawl through the Cat Window..." (Public Web Server)
2.  "...to get to the Kitchen..." (Server climbs into the internal network)
3.  "...steal the Cook's Key..." (Steal IAM Role Credentials)
4.  "...and walk right into the Treasury!" (Access the S3 Bucket with Critical Data).

**In short:** Other tools check if you followed the rules; this tool checks if a bad guy can actually win.

---

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
python -m cloud_attack_analysis.cli scan ./examples/vulnerable_infra --visualize
```

## 📁 The Grand Catalog of AI-Cloud Attacks

The `examples/scenarios/` directory contains 8 real-world templates for testing the engine:

1.  **`rag_data_leak`**: SSRF on a web server leading to the exfiltration of an internal Vector Database (OpenSearch).
2.  **`sagemaker_notebook_admin`**: The risk of "Lazy IAM" where an AI researcher's notebook has `AdministratorAccess`.
3.  **`bedrock_agent_injection`**: Demonstration of Prompt Injection where an agent is tricked into using a Lambda tool to leak S3 data.
4.  **`training_pipeline_poison`**: An insecure S3 bucket trigger that allows an attacker to inject malicious code into a CodeBuild training job.
5.  **`model_package_registry_leak`**: A SageMaker Model Registry with a public resource policy, allowing Model IP theft.
6.  **`unprotected_vector_store`**: A Vector DB directly exposed to the internet via an over-permissive Security Group (Port 9200).
7.  **`ai_assistant_tool_abuse`**: An AI assistant tool (Lambda) that has broad `dynamodb:*` access, leading to PII leaks.
8.  **`capital_one_repro`**: A formalized reproduction of the 2019 breach involving IMDSv1 credential theft and S3 Sync.

---

## Roadmap
*   **v1.0 (Released)**: 
    *   Core Graph Engine (NetworkX).
    *   Visualization (`--visualize`).
    *   CI/CD Integration.
    *   Terraform Plan JSON Support.
*   **v2.0 (Planned)**: 
    *   Expanded IAM parsing (Condition keys, `NotAction`).
    *   Support for vector databases (Pinecone, Weaviate) if declared in Terraform.
