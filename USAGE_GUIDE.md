# User Guide: Cloud Attack Analysis

This guide provides a comprehensive, step-by-step approach to using the **AI Cloud Attack Analysis** tool. Whether you are a security professional or a cloud developer, follow these steps to secure your infrastructure.

---

## 🛠️ Step 1: Preparation (Before You Start)

Before running the tool, ensure your environment is ready:

1.  **Python Environment**: Ensure you have **Python 3.10 or higher** installed. Check via `python --version`.
2.  **Dependencies**: Install the required libraries.
    ```bash
    pip install -r requirements.txt
    ```
3.  **Target Code**: Have your Terraform code ready. The tool does **not** need access to your live AWS account; it only needs your code files.
4.  *(Optional)* **Terraform CLI**: Only needed if you want to use the high-precision "Plan JSON" mode.

---

## 📥 Step 2: Understanding Inputs

The tool is flexible and takes two types of "Blueprints" as input:

### Option A: The "Intent" (HCL Files)
*   **What it is**: Your raw `.tf` files.
*   **Best for**: Fast checks during coding or on every `git commit`.
*   **Pros**: Extremely fast; no setup needed.

### Option B: The "Reality" (Terraform Plan JSON)
*   **What it is**: The final computed result of your terraform.
*   **Best for**: Highly accurate security reviews before a major deployment.
*   **How to generate it**:
    ```bash
    terraform plan -out=tf.plan
    terraform show -json tf.plan > plan.json
    ```

---

## 🚀 Step 3: Running the Analysis

Open your terminal in the project root and run the command that fits your needs.

### 1. Basic Security Scan
This prints a narrative report of any discovered attack paths.
```bash
python -m cloud_attack_analysis.cli scan ./path/to/your/infra
```

### 2. Interactive Visualization (Recommended)
This generates an interactive HTML map that you can explore in your browser.
```bash
python -m cloud_attack_analysis.cli scan ./path/to/your/infra --visualize
```

---

## 📤 Step 4: Understanding the Outputs

The tool provides output in two formats:

### 1. The Narrative Report (Terminal)
*   **Risk Score**: A severity rating (0-100). 100 means an attacker is already "standing next to your secrets."
*   **The Chain**: A step-by-step list of how an attacker hops from one resource to another.
*   **Actionable Fixes**: A list of the TOP 5 most important changes to make. Fixing the first item often breaks multiple attack paths.

### 2. The Interactive Graph (`attack_graph.html`)
Open this file in any web browser to see your infrastructure as a living map:
*   **Cyan Node**: The "Attacker" (Internet).
*   **Orange Nodes**: Your servers, Lambdas, or entry points.
*   **Red Nodes**: IAM Roles and Permissions (The "Keys").
*   **Green/Magenta Nodes**: Your data (S3) and AI services (Bedrock).
*   **The Lines**: Show the "Trust Relationships." If a line goes from a public server to a private database, you should ask "Why?".

---

## 💡 Best Practices

1.  **Shift-Left**: Add the basic scan to your GitHub/GitLab pipeline so security is checked on every code change.
2.  **Test the Scenarios**: If you're new to cloud security, run the templates in `examples/scenarios/` to see what a "failed" infrastructure looks like.
3.  **Verify after Fixes**: After fixing a misconfiguration, run the scan again. The **Risk Score** should drop, and the attack path should disappear!

---

**Mission**: Move from *detecting* vulnerabilities to *visualizing* and *breaking* attack paths. 🛡️
