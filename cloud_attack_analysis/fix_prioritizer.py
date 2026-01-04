"""
Fix Impact Prioritization Engine

This module answers the question:
"If I can fix ONLY ONE issue today, which fix reduces the MOST real-world risk?"

Scoring Formula (Deterministic, No ML):
Risk Score =
  (AttackPathCount × 3)
+ (IsEntryPoint × 5)
+ (PrivilegeEscalation × 4)
+ (AIDataExposure × 6)
+ (InternetExposed × 5)
"""

from typing import List, Dict, Any, Set
from dataclasses import dataclass, field
import networkx as nx


@dataclass
class PriorityFix:
    rank: int
    resource: str
    risk_score: int
    breaks_attack_paths: int
    attack_stages_blocked: List[str]
    why_this_matters: str
    recommended_fix: str


class FixPrioritizer:
    """
    Analyzes misconfigurations and attack paths to produce a ranked list
    of fixes ordered by real-world risk reduction.
    """

    # Resource types classified by attack stage
    ENTRY_POINT_TYPES = {"aws_security_group", "aws_lb", "aws_api_gateway_rest_api", "aws_cloudfront_distribution"}
    PRIV_ESC_TYPES = {"aws_iam_role", "aws_iam_policy", "aws_iam_role_policy", "aws_iam_role_policy_attachment"}
    AI_DATA_TYPES = {"aws_s3_bucket", "aws_sagemaker_notebook_instance", "aws_sagemaker_model_package_group",
                     "aws_bedrock_agent", "aws_bedrock_model_invocation_logging_configuration",
                     "aws_opensearch_domain", "aws_dynamodb_table"}

    def __init__(self, graph: nx.DiGraph, attack_paths: List[List[str]], misconfigurations: List[Any]):
        self.graph = graph
        self.attack_paths = attack_paths
        self.misconfigurations = misconfigurations
        self._path_participation: Dict[str, int] = {}
        self._compute_path_participation()

    def _compute_path_participation(self):
        """Count how many attack paths each resource participates in."""
        for path in self.attack_paths:
            for node_id in path:
                self._path_participation[node_id] = self._path_participation.get(node_id, 0) + 1

    def _is_entry_point(self, resource_id: str) -> bool:
        """Check if resource is an initial access point (public-facing)."""
        res_type = self._get_resource_type(resource_id)
        if res_type in self.ENTRY_POINT_TYPES:
            return True
        # Check for 0.0.0.0/0 in security groups
        attrs = self._get_resource_attrs(resource_id)
        ingress = attrs.get("ingress", [])
        if isinstance(ingress, list):
            for rule in ingress:
                if isinstance(rule, dict) and "0.0.0.0/0" in str(rule.get("cidr_blocks", [])):
                    return True
        return False

    def _is_privilege_escalation(self, resource_id: str) -> bool:
        """Check if resource enables privilege escalation."""
        res_type = self._get_resource_type(resource_id)
        if res_type in self.PRIV_ESC_TYPES:
            attrs = self._get_resource_attrs(resource_id)
            policy_str = str(attrs.get("policy", ""))
            # Check for wildcard permissions
            if '"Action": "*"' in policy_str or '"Action":"*"' in policy_str:
                return True
            if '"Resource": "*"' in policy_str or '"Resource":"*"' in policy_str:
                return True
            # Check for admin policy attachment
            if "AdministratorAccess" in str(attrs.get("policy_arn", "")):
                return True
        return False

    def _is_ai_data_exposure(self, resource_id: str) -> bool:
        """Check if resource impacts AI/ML data or services."""
        res_type = self._get_resource_type(resource_id)
        if res_type in self.AI_DATA_TYPES:
            return True
        # Check for AI-related naming conventions
        name_lower = resource_id.lower()
        ai_keywords = ["sagemaker", "bedrock", "training", "model", "embedding", "vector", "llm", "ai", "ml"]
        return any(kw in name_lower for kw in ai_keywords)

    def _is_internet_exposed(self, resource_id: str) -> bool:
        """Check if resource is reachable from the internet."""
        # Check if node is directly connected to Internet node
        if self.graph.has_node("Internet"):
            if self.graph.has_edge("Internet", resource_id):
                return True
            # Check if any predecessor is Internet
            for predecessor in self.graph.predecessors(resource_id):
                if predecessor == "Internet":
                    return True
        return self._is_entry_point(resource_id)

    def _get_resource_type(self, resource_id: str) -> str:
        """Extract resource type from ID."""
        if self.graph.has_node(resource_id):
            return self.graph.nodes[resource_id].get("type", "unknown")
        # Fallback: parse from ID
        parts = resource_id.split(".")
        return parts[0] if parts else "unknown"

    def _get_resource_attrs(self, resource_id: str) -> Dict:
        """Get resource attributes from graph."""
        if self.graph.has_node(resource_id):
            return self.graph.nodes[resource_id].get("attributes", {})
        return {}

    def _classify_attack_stages(self, resource_id: str) -> List[str]:
        """Classify which attack stages this resource participates in."""
        stages = []
        if self._is_entry_point(resource_id) or self._is_internet_exposed(resource_id):
            stages.append("Initial Access")
        if self._is_privilege_escalation(resource_id):
            stages.append("Privilege Escalation")
        # Lateral movement: if resource connects to other resources
        if self.graph.out_degree(resource_id) > 1:
            stages.append("Lateral Movement")
        if self._is_ai_data_exposure(resource_id):
            stages.append("AI Training Data Exfiltration")
        return stages if stages else ["Misconfiguration"]

    def _compute_risk_score(self, resource_id: str) -> int:
        """
        Compute deterministic risk score using the formula:
        Risk Score =
          (AttackPathCount × 3)
        + (IsEntryPoint × 5)
        + (PrivilegeEscalation × 4)
        + (AIDataExposure × 6)
        + (InternetExposed × 5)
        """
        attack_path_count = self._path_participation.get(resource_id, 0)
        is_entry = 1 if self._is_entry_point(resource_id) else 0
        is_priv_esc = 1 if self._is_privilege_escalation(resource_id) else 0
        is_ai_data = 1 if self._is_ai_data_exposure(resource_id) else 0
        is_internet = 1 if self._is_internet_exposed(resource_id) else 0

        score = (
            (attack_path_count * 3) +
            (is_entry * 5) +
            (is_priv_esc * 4) +
            (is_ai_data * 6) +
            (is_internet * 5)
        )
        return score

    def _generate_why_this_matters(self, resource_id: str, stages: List[str], path_count: int) -> str:
        """Generate a human-readable explanation of why fixing this matters."""
        res_type = self._get_resource_type(resource_id)
        
        explanations = []
        if "Initial Access" in stages:
            explanations.append("removes the attacker's entry point into the environment")
        if "Privilege Escalation" in stages:
            explanations.append("prevents attackers from gaining elevated permissions")
        if "Lateral Movement" in stages:
            explanations.append("blocks lateral movement to connected resources")
        if "AI Training Data Exfiltration" in stages:
            explanations.append("protects sensitive AI/ML data and model artifacts")

        if path_count > 1:
            explanations.append(f"breaks {path_count} distinct attack paths simultaneously")

        return f"Fixing this {res_type.replace('aws_', '')} " + ", ".join(explanations) + "."

    def _generate_recommended_fix(self, resource_id: str) -> str:
        """Generate actionable fix recommendation based on resource type."""
        res_type = self._get_resource_type(resource_id)

        fixes = {
            "aws_security_group": "Restrict ingress rules to specific IPs. Remove 0.0.0.0/0 CIDR blocks. Use VPC endpoints for internal traffic.",
            "aws_iam_role": "Apply least privilege. Remove wildcard (*) actions and resources. Scope to specific services and ARNs.",
            "aws_iam_policy": "Remove overly permissive statements. Use condition keys to restrict access context.",
            "aws_iam_role_policy": "Scope policy to minimum required actions. Add resource constraints and conditions.",
            "aws_iam_role_policy_attachment": "Review attached managed policies. Replace AdministratorAccess with scoped policies.",
            "aws_s3_bucket": "Enable bucket versioning and encryption. Block public access. Use VPC endpoints.",
            "aws_s3_bucket_policy": "Remove Principal: * statements. Scope to specific IAM roles and conditions.",
            "aws_sagemaker_notebook_instance": "Disable direct internet access. Use VPC-only mode. Restrict IAM role permissions.",
            "aws_bedrock_agent": "Scope agent tools to minimum required permissions. Enable logging and monitoring.",
            "aws_opensearch_domain": "Enable fine-grained access control. Use VPC deployment. Restrict access policies.",
            "aws_instance": "Enable IMDSv2 (http_tokens = required). Use private subnets. Minimize IAM role permissions.",
        }

        return fixes.get(res_type, "Review and restrict permissions following the principle of least privilege.")

    def prioritize(self) -> List[PriorityFix]:
        """
        Main entry point. Analyzes all misconfigurations and returns
        a ranked list of fixes ordered by risk reduction impact.
        """
        # Collect all misconfigured resource IDs
        misconfigured_ids: Set[str] = set()
        for misconfig in self.misconfigurations:
            if hasattr(misconfig, 'resource_id'):
                misconfigured_ids.add(misconfig.resource_id)
            elif hasattr(misconfig, 'resource'):
                misconfigured_ids.add(misconfig.resource)

        # Also include resources that appear in attack paths
        for path in self.attack_paths:
            for node_id in path:
                if node_id != "Internet":
                    misconfigured_ids.add(node_id)

        # Score each resource
        scored_resources = []
        for res_id in misconfigured_ids:
            score = self._compute_risk_score(res_id)
            if score > 0:  # Only include resources with risk
                scored_resources.append((res_id, score))

        # Sort by score descending
        scored_resources.sort(key=lambda x: x[1], reverse=True)

        # Build priority fix list
        priority_fixes = []
        for rank, (res_id, score) in enumerate(scored_resources, start=1):
            stages = self._classify_attack_stages(res_id)
            path_count = self._path_participation.get(res_id, 0)

            fix = PriorityFix(
                rank=rank,
                resource=f"{self._get_resource_type(res_id)}: {res_id.split('.')[-1]}",
                risk_score=score,
                breaks_attack_paths=path_count,
                attack_stages_blocked=stages,
                why_this_matters=self._generate_why_this_matters(res_id, stages, path_count),
                recommended_fix=self._generate_recommended_fix(res_id)
            )
            priority_fixes.append(fix)

        return priority_fixes

    def to_dict(self) -> Dict[str, Any]:
        """Export prioritized fixes as a dictionary for JSON serialization."""
        fixes = self.prioritize()
        return {
            "priority_fixes": [
                {
                    "rank": f.rank,
                    "resource": f.resource,
                    "risk_score": f.risk_score,
                    "breaks_attack_paths": f.breaks_attack_paths,
                    "attack_stages_blocked": f.attack_stages_blocked,
                    "why_this_matters": f.why_this_matters,
                    "recommended_fix": f.recommended_fix
                }
                for f in fixes
            ]
        }
