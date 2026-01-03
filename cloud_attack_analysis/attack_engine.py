import networkx as nx
from typing import List, Optional
from .models import Resource, AttackNode, AttackPath, RuleResult

class AttackEngine:
    """
    The Core Brain.
    Models attacker movement from Internet -> Compromise -> Data Exfiltration.
    """
    def __init__(self, resource_graph: nx.DiGraph, rule_results: List[RuleResult]):
        self.graph = resource_graph
        self.rules = rule_results
        self.attack_graph = nx.DiGraph()
        self._build_attack_overlay()

    def _build_attack_overlay(self):
        """Constructs an attack graph by augmenting the resource graph with vulnerability edges."""
        
        # 1. Add Attacker Start Node
        self.attack_graph.add_node("Internet", type="External", data={})

        # 2. Map vulnerabilities to edges
        # Find Public EC2s
        for res_id, res_data in self.graph.nodes(data=True):
            resource = res_data.get('resource')
            if not resource: continue

            # VULN: Public SG -> Internet Access
            # We look for the rule result associated with this resource
            vulns = [r for r in self.rules if r.resource_id == res_id and not r.is_compliant]
            
            for v in vulns:
                if v.rule_id == "NET-001": # Public SG
                    # If this SG protects an EC2, Attacker can reach EC2
                    # Find EC2s protected by this SG
                    for src, dest, attr in self.graph.in_edges(res_id, data=True):
                        # The edge is EC2 -> SG (protected_by)
                        # So Dest is SG. Src is EC2.
                        # Wait, edge direction in resource graph:
                        # EC2 -> SG means EC2 uses SG.
                        if attr.get("relationship") == "protected_by":
                             self.attack_graph.add_edge("Internet", src, method="Public Network Access", risk="Exploit SSH/App Vuln")

        # 3. Lateral Movement (EC2 -> Role)
        for u, v, attr in self.graph.edges(data=True):
            if attr.get("relationship") == "assumes_role":
                # If attacker Compromises EC2 (u), they get Role (v)
                self.attack_graph.add_edge(u, v, method="Instance Profile Abuse", risk="Credential Theft")

        # 4. Permission Abuse (Role -> Resources)
        # Find overly permissive policies attached to roles
        for u, v, attr in self.graph.edges(data=True):
            # u = Role, v = Policy
            if attr.get("relationship") == "has_policy":
                # Check if policy is permissive
                vulns = [r for r in self.rules if r.resource_id == v and r.rule_id == "IAM-001"]
                if vulns:
                    # Role has Admin/Star access. 
                    # Conceptually, this allows access to ALMOST ANY resource.
                    # We map this to specific high-value targets in the graph for the path finding to work.
                    
                    # Target: AI Services
                    ai_nodes = [n for n, d in self.graph.nodes(data=True) if d.get('resource').is_ai_service]
                    for ai in ai_nodes:
                        self.attack_graph.add_edge(u, ai, method="Over-permissive Policy", risk="Invoke Model")
                    
                    # Target: S3 Buckets
                    s3_nodes = [n for n, d in self.graph.nodes(data=True) if d.get('resource').type == "aws_s3_bucket"]
                    for s3 in s3_nodes:
                        self.attack_graph.add_edge(u, s3, method="Over-permissive Policy", risk="Data Access")

        # 5. AI Service -> Logs (Data Ref)
        for u, v, attr in self.graph.edges(data=True):
            if attr.get("relationship") == "logs_to":
                # u = AI Config, v = S3 Bucket
                # Accessing AI config implies ability to read/poison logs if permissions allow, 
                # but physically the data flows to S3.
                # If attacker controls AI, they generate prompts. Prompts go to S3.
                # If attacker controls S3, they read prompts.
                
                # Path: AI Service -> S3 (Data Flow)
                self.attack_graph.add_edge(u, v, method="Logging Configuration", risk="Prompt Injection / Leakage")

        # 6. S3 -> Exfiltration (If public)
        for res_id, res_data in self.graph.nodes(data=True):
            resource = res_data.get('resource')
            if resource and resource.type == "aws_s3_bucket":
                vulns = [r for r in self.rules if r.resource_id == res_id and r.rule_id == "STO-001"]
                if vulns:
                    # Bucket is public.
                    # If we are AT the bucket node, we can exfiltrate.
                    # OR if we are at Internet, we can read directly.
                    
                    # In this graph, "Internet" is the start. 
                    # If we reach S3 from internal path, and it's public, that's just leaking.
                    # But the "Goal" is to find a path TO the data.
                    pass

    def find_critical_path(self) -> Optional[AttackPath]:
        """Finds the Shortest Path to sensitive data (S3 with AI logs)."""
        
        # Identify Targets: S3 buckets that store AI logs
        targets = []
        for u, v, attr in self.graph.edges(data=True):
            if attr.get("relationship") == "logs_to":
                targets.append(v) # v is the S3 bucket

        if not targets:
            return None

        # BFS for shortest path (simplest valid attack chain)
        shortest_path = None
        
        for target in targets:
            try:
                path_ids = nx.shortest_path(self.attack_graph, source="Internet", target=target)
                
                # Convert IDs to AttackNodes
                nodes = []
                for pid in path_ids:
                    node_data = self.graph.nodes[pid] if pid in self.graph.nodes else {"type": "External"}
                    res = node_data.get("resource")
                    node_type = res.type if res else "External"
                    nodes.append(AttackNode(id=pid, type=node_type))
                
                # Calculate simple score
                score = len(nodes) * 10 # heuristic
                
                path = AttackPath(
                    steps=nodes, 
                    risk_score=score, 
                    severity="Critical", 
                )
                
                if not shortest_path or len(path.steps) < len(shortest_path.steps):
                    shortest_path = path

            except nx.NetworkXNoPath:
                continue
                
        return shortest_path
