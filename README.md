# Cloud Attack Analysis – Security Decision Engine

**A Production-Quality Offline Security Engine for AI-Cloud Infrastructure**

[![Security Scan](https://github.com/Dinesh-raya/AI_cloud_attack_analysis/actions/workflows/security_scan.yml.svg)](https://github.com/Dinesh-raya/AI_cloud_attack_analysis/actions)

## 🎯 The Core Question This Tool Answers

> "If I can fix ONLY ONE issue today, which fix reduces the MOST real-world risk?"

This is not a vulnerability scanner. This is a **Security Decision Engine** that thinks like an attacker.

---

## 🌐 Why This Tool Matters in the AI Era

### The Landscape Has Changed

Traditional cloud infrastructure (EC2, S3, IAM) has been augmented with new **AI-native services**:
- **SageMaker Notebooks**: Where researchers experiment with your data
- **Bedrock Agents**: AI assistants that can call tools on your behalf
- **Vector Databases**: Containing your company's entire knowledge base
- **Training Data Buckets**: The crown jewels of any AI company

### The Problem with Existing Tools

| Tool Category | What They Do | What They Miss |
|--------------|--------------|----------------|
| **Scanners** (Prowler, ScoutSuite) | Check individual rules | Don't connect the dots |
| **CSPM** (Wiz, Orca) | Detect misconfigurations | Don't prioritize by attack impact |
| **SIEM** (Splunk, Elastic) | Monitor runtime events | Too late—the breach happened |

### What Makes This Tool Different

1. **Graph-Based Reasoning**: We build a map of your infrastructure, then simulate attacker movement
2. **Attack Stage Classification**: Every finding is tagged with its role in the kill chain
3. **Impact-Based Prioritization**: Fixes are ranked by how many attack paths they break
4. **AI-Aware Targeting**: AI/ML resources are treated as high-value targets by default

### The New Reality

```
Identity is the new perimeter.
AI services massively expand blast radius.
Static misconfigurations enable model & data theft.
```

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

## 🚀 Quick Start

```bash
# Clone and install
git clone https://github.com/your-repo/cloud-attack-analysis.git
cd cloud-attack-analysis
pip install -r requirements.txt

# Run the demo
python main.py --input demo/terraform --output report.json

# View interactive attack graph
python main.py --input demo/terraform --visualize
```

---

## 📊 Output Format

The tool produces a deterministic JSON report:

```json
{
  "status": "VULNERABLE",
  "total_attack_paths": 4,
  "priority_fixes": [
    {
      "rank": 1,
      "resource": "aws_iam_role: SageMakerExecutionRole",
      "risk_score": 27,
      "breaks_attack_paths": 4,
      "attack_stages_blocked": [
        "Initial Access",
        "Privilege Escalation",
        "AI Training Data Exfiltration"
      ],
      "why_this_matters": "Fixing this role removes attacker access to LLM training data and prevents lateral movement into S3 and Bedrock.",
      "recommended_fix": "Restrict iam:PassRole, remove wildcard permissions, and scope policies to minimum required actions."
    }
  ]
}
```

---

## 🧮 Risk Scoring Formula

Every fix is scored using this **deterministic, explainable formula**:

```
Risk Score =
  (AttackPathCount × 3)
+ (IsEntryPoint × 5)
+ (PrivilegeEscalation × 4)
+ (AIDataExposure × 6)
+ (InternetExposed × 5)
```

| Factor | Weight | Why |
|--------|--------|-----|
| Attack Path Count | ×3 | More paths = greater blast radius |
| Entry Point | +5 | First hop in any attack chain |
| Privilege Escalation | +4 | Enables lateral movement |
| AI Data Exposure | +6 | Crown jewels of AI companies |
| Internet Exposed | +5 | Attackable without credentials |

---

## 📁 Scenario Library

The `examples/scenarios/` directory contains 8 real-world attack patterns:

1. **`rag_data_leak`**: SSRF to Vector Database
2. **`sagemaker_notebook_admin`**: Lazy IAM leading to account takeover
3. **`bedrock_agent_injection`**: Prompt injection via AI tools
4. **`training_pipeline_poison`**: S3-triggered code injection
5. **`model_package_registry_leak`**: SageMaker model theft
6. **`unprotected_vector_store`**: Direct OpenSearch exposure
7. **`ai_tool_abuse`**: PII leak through AI assistant tools
8. **`capital_one_repro`**: Classic IMDSv1 SSRF attack

---

## 📚 Documentation

- [USAGE_GUIDE.md](USAGE_GUIDE.md) - Step-by-step usage instructions
- [LIMITATIONS.md](LIMITATIONS.md) - What this tool does NOT do
- [PERFORMANCE.md](PERFORMANCE.md) - Complexity analysis and benchmarks

---

## 🛡️ Design Constraints

This tool is intentionally constrained:

- ✅ CLI only (no dashboards)
- ✅ Deterministic output (no ML models)
- ✅ Fully explainable logic (no black boxes)
- ✅ Offline operation (no cloud credentials)
- ✅ Privacy-first (no data exfiltration)

---

## 🎓 Definition of Done

The project is DONE when:
- ✅ One command produces ranked fix decisions
- ✅ Each fix clearly explains WHY it matters
- ✅ Every scoring decision can be defended in an interview
- ✅ The tool behaves like a security engineer, not a scanner

---

## 📝 License

MIT License - Use freely, contribute boldly.
