import networkx as nx
import logging
import json
from typing import List, Optional, Set, Dict, Any
from .models import Resource, AttackNode, AttackPath, RuleResult

class AttackEngine:
    """
    Advanced Attack Graph Engine.
    Models attacker movement based on REALISTIC capabilities and permissions.
    """
    def __init__(self, resource_graph: nx.DiGraph, rule_results: List[RuleResult]):
        self.graph = resource_graph
        self.rules = rule_results
        self.attack_graph = nx.DiGraph()
        self._build_attack_overlay()

    def _build_attack_overlay(self):
        """Constructs the high-fidelity attack graph."""
        self.attack_graph.add_node("Internet", type="External", data={})

        # --- Phase 1: Ingress (Network Reachability) ---
        for node, data in self.graph.nodes(data=True):
            res = data.get('resource')
            if not res: continue

            if res.type == "aws_instance":
                if self._is_instance_publicly_exposed(res):
                    self.attack_graph.add_edge("Internet", node, 
                                               method="Network Reachability", 
                                               risk="Exploit Public Service (SSRF/RCE)")
            
            if res.type == "aws_s3_bucket":
                if self._is_bucket_public(res):
                    self.attack_graph.add_edge("Internet", node,
                                               method="Public ACL/Policy",
                                               risk="Data Leakage")
            
            if res.is_vector_store:
                if self._is_vector_store_exposed(res):
                     self.attack_graph.add_edge("Internet", node,
                                               method="Public Endpoint",
                                               risk="Knowledge Base Theft")

        # --- Phase 2: Identity Assumption (Compute -> Identity) ---
        for u, v, attr in self.graph.edges(data=True):
            if attr.get("relationship") == "assumes_role":
                self.attack_graph.add_edge(u, v, 
                                           method="IMDS/Credential Access", 
                                           risk="Lateral Movement")
            
            if attr.get("relationship") == "uses_identity":
                self.attack_graph.add_edge(u, v, 
                                           method="Prompt Injection / Tool Abuse", 
                                           risk="Indirect Privilege Escalation")
                                           
            if attr.get("relationship") == "linked_role":
                self.attack_graph.add_edge(u, v,
                                           method="Identity Link",
                                           risk="Lateral Movement")

        # --- Phase 3: Permission-Based Access (Identity -> Resource) ---
        roles = [n for n, d in self.graph.nodes(data=True) if d.get('resource') and d.get('resource').type == "aws_iam_role"]
        
        for role_id in roles:
            policies = self._get_attached_policies(role_id)
            for target_id, target_data in self.graph.nodes(data=True):
                target_res = target_data.get('resource')
                if not target_res: continue
                if target_id == role_id: continue

                capability = self._check_permission(policies, target_res)
                if capability:
                    self.attack_graph.add_edge(role_id, target_id, 
                                               method="IAM Permission allow", 
                                               risk=capability)

        # --- Phase 4: Data Flow / Indirect Access ---
        for u, v, attr in self.graph.edges(data=True):
            if attr.get("relationship") == "logs_to":
                self.attack_graph.add_edge(u, v, 
                                           method="Data Flow", 
                                           risk="Log Poisoning / Indirect Write")

    def _is_instance_publicly_exposed(self, res: Resource) -> bool:
        if res.id in self.graph:
            # 1. Check Subnet Context (If available)
            # If located_in a subnet, check if that subnet is explicitly private
            for successor in self.graph.successors(res.id):
                edge_data = self.graph.get_edge_data(res.id, successor)
                if edge_data and edge_data.get("relationship") == "located_in":
                    subnet_res = self.graph.nodes[successor].get('resource')
                    if subnet_res:
                        # Heuristic: If map_public_ip_on_launch is explicitly False, assume Private
                        # This is not perfect (could have EIP), but reduces False Positives for internal workloads.
                        pub_ip = subnet_res.attributes.get("map_public_ip_on_launch", True)
                        if str(pub_ip).lower() == "false":
                            return False # Hides behind private subnet

            # 2. Check Security Groups
            for successor in self.graph.successors(res.id):
                edge_data = self.graph.get_edge_data(res.id, successor)
                if not edge_data: continue 
                if edge_data.get("relationship") == "protected_by":
                    sg_node = self.graph.nodes[successor].get('resource')
                    if sg_node and self._is_sg_public(sg_node):
                        return True
        return False

    def _is_sg_public(self, res: Resource) -> bool:
        ingresses = res.attributes.get("ingress", [])
        if not isinstance(ingresses, list): ingresses = [ingresses]
        
        for rule in ingresses:
            if isinstance(rule, list):
                for sub in rule:
                    if isinstance(sub, dict):
                         if self._check_cidrs(sub.get("cidr_blocks", [])): return True
            elif isinstance(rule, dict):
                if self._check_cidrs(rule.get("cidr_blocks", [])): return True
        return False
        
    def _check_cidrs(self, cidrs) -> bool:
        if not cidrs: return False
        if isinstance(cidrs, list):
            for c in cidrs:
                if isinstance(c, list):
                    if "0.0.0.0/0" in c: return True
                elif c == "0.0.0.0/0": return True
        return False

    def _is_bucket_public(self, res: Resource) -> bool:
        acl = res.attributes.get("acl", "")
        if isinstance(acl, list) and len(acl) > 0:
            acl = acl[0]
        return acl in ["public-read", "public-read-write"]

    def _is_vector_store_exposed(self, res: Resource) -> bool:
        return True 

    def _get_attached_policies(self, role_id: str) -> List[Any]:
        policies = []
        if role_id in self.graph:
            for successor in self.graph.successors(role_id):
                edge_data = self.graph.get_edge_data(role_id, successor)
                if not edge_data: continue
                if edge_data.get("relationship") == "has_policy":
                    policy_res = self.graph.nodes[successor].get('resource')
                    if policy_res:
                        raw_policy = policy_res.attributes.get("policy")
                        if raw_policy:
                            policies.append(raw_policy)
        return policies

    def _check_permission(self, policies: List[Any], target: Resource) -> Optional[str]:
        target_service = target.type.split("_")[1] 
        
        for pol in policies:
            # 1. Normalize Policy to Dict
            policy_doc = self._normalize_policy(pol)
            if not policy_doc: continue
            
            statements = policy_doc.get("Statement", [])
            if isinstance(statements, dict): statements = [statements]
            
            for stmt in statements:
                if not isinstance(stmt, dict): continue
                
                effect = stmt.get("Effect", "Allow")
                if effect != "Allow": continue 
                
                # Check NotAction Risk
                if "NotAction" in stmt:
                    # simplified check for wildcard NotAction
                    not_actions = self._to_list(stmt.get("NotAction"))
                    # If target service is excluded, skipped.
                    # e.g. NotAction: "iam:*", and target is IAM -> Skip.
                    pass

                actions = self._to_list(stmt.get("Action"))
                resources = self._to_list(stmt.get("Resource"))
                
                # Check Admin
                if "*" in actions and "*" in resources:
                    return "Full Admin Access"

                # Check Service Wildcard
                for act in actions:
                    if act == f"{target_service}:*" and "*" in resources:
                        return f"Full {target_service.upper()} Access"

                # Check Specific S3
                if target.type == "aws_s3_bucket":
                    if self._check_action_match(actions, ["s3:GetObject", "s3:PutObject", "s3:*"]):
                       if "*" in resources or target.name in str(resources): # lenient resource check
                           return "S3 Data Access"

                # Check AI
                if target.is_ai_service:
                    if self._check_action_match(actions, ["bedrock:InvokeAgent"]):
                        return "Agent Invocation"
                    if self._check_action_match(actions, ["bedrock:InvokeModel", "sagemaker:InvokeEndpoint"]):
                        return "Model Invocation"
        return None

    def _normalize_policy(self, pol_ref: Any) -> dict:
        """Converts string/hcl-dict policy to standard Python dict."""
        if isinstance(pol_ref, dict):
            return pol_ref
        
        if isinstance(pol_ref, str):
            try:
                # cleanse heredoc markers if any
                clean = pol_ref.strip()
                if clean.startswith("<<EOF"): 
                     clean = clean.split("EOF")[0].replace("<<EOF", "")
                elif clean.startswith("<<-EOF"):
                     clean = clean.split("EOF")[0].replace("<<-EOF", "")
                return json.loads(clean)
            except json.JSONDecodeError:
                return {}
        return {}

    def _to_list(self, val: Any) -> list:
        if isinstance(val, list): return val
        if isinstance(val, str): return [val]
        return []

    def _check_action_match(self, actions: list, targets: list) -> bool:
        for act in actions:
            if act in targets: return True
            # handle wildcards e.g. s3:* matching s3:GetObject
            if act.endswith("*"):
                prefix = act.rstrip("*")
                for t in targets:
                    if t.startswith(prefix): return True
        return False

    def find_critical_path(self) -> Optional[AttackPath]:
        targets = []
        for u, v, attr in self.graph.edges(data=True):
            if attr.get("relationship") == "logs_to":
                targets.append(v)
        
        for node, data in self.graph.nodes(data=True):
            res = data.get('resource')
            if res and res.type == "aws_s3_bucket":
                 if node not in targets: targets.append(node)

        if not targets:
            return None

        shortest_path = None
        
        for target in targets:
            try:
                if target not in self.attack_graph:
                    continue

                path_ids = nx.shortest_path(self.attack_graph, source="Internet", target=target)
                
                nodes = []
                for pid in path_ids:
                    node_data = self.graph.nodes[pid] if pid in self.graph.nodes else {"type": "External"}
                    res = node_data.get("resource")
                    node_type = res.type if res else "External"
                    nodes.append(AttackNode(id=pid, type=node_type))
                
                path = AttackPath(
                    steps=nodes, 
                    risk_score=len(nodes) * 20, 
                    severity="Critical", 
                )
                
                if not shortest_path or len(path.steps) < len(shortest_path.steps):
                    shortest_path = path

            except nx.NetworkXNoPath:
                continue
            except nx.NodeNotFound:
                continue
                
        return shortest_path
