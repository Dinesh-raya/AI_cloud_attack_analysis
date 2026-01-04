import networkx as nx
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass
from .models import AttackPath

@dataclass
class Remediation:
    id: str
    description: str
    paths_blocked: int
    edge_source: str
    edge_target: str
    risk_type: str

class FixEngine:
    """
    Prioritizes remediations using Greedy Path Breaking.
    Finds the minimum set of edges to remove to disconnect Internet from Critical Targets.
    """
    def __init__(self, attack_graph: nx.DiGraph, targets: List[str]):
        self.original_graph = attack_graph
        self.targets = targets
        self.internet_node = "Internet"

    def calculate_fix_order(self) -> List[Remediation]:
        """
        Returns a prioritized list of fixes.
        Ref: Set Cover Problem (Greedy Approx).
        """
        # Work on a copy of the graph to simulate fixes
        current_graph = self.original_graph.copy()
        remediations = []
        
        while True:
            # 1. Find ALL current paths from Internet to ANY Target
            all_paths = self._find_all_paths(current_graph)
            
            if not all_paths:
                break # No more attack paths!

            # 2. Count edge frequency across all paths
            edge_counts: Dict[Tuple[str, str], int] = {}
            for path in all_paths:
                # path is list of nodes [Internet, A, B, Target]
                # edges: (Internet,A), (A,B), (B,Target)
                for i in range(len(path) - 1):
                    u, v = path[i], path[i+1]
                    # We only fix "Vulnerability" edges. 
                    # Some edges might be structural (like "Role -> Agent" if that's structural? 
                    # Actually in our graph, almost all edges except maybe "Logs To" are actionable.)
                    # Let's verify edge data to see if it's fixable.
                    # For now, assume all edges in Attack Graph are actionable risks.
                    edge = (u, v)
                    edge_counts[edge] = edge_counts.get(edge, 0) + 1

            # 3. Select the "Best" edge (Greedy choice)
            # breaking the edge with max counts blocks the most paths
            if not edge_counts:
                break 
                
            best_edge = max(edge_counts, key=edge_counts.get)
            count = edge_counts[best_edge]
            
            # 4. Create Remediation Object
            u, v = best_edge
            edge_data = current_graph.get_edge_data(u, v)
            risk_type = edge_data.get("risk", "Unknown Risk")
            method = edge_data.get("method", "Unknown Method")
            
            fix_desc = self._get_fix_description(method, u, v)
            
            rem = Remediation(
                id=f"FIX-{len(remediations)+1:03d}",
                description=fix_desc,
                paths_blocked=count,
                edge_source=u,
                edge_target=v,
                risk_type=risk_type
            )
            remediations.append(rem)
            
            # 5. Simulate Fix: Remove edge from graph
            current_graph.remove_edge(u, v)
            
        return remediations

    def _find_all_paths(self, graph: nx.DiGraph) -> List[List[str]]:
        """Finds all simple paths from Internet to any target."""
        paths = []
        for target in self.targets:
            try:
                # limited depth to avoid explosion in cyclic graphs (though AG shouldn't be cyclic)
                # usage of all_simple_paths can be expensive on massive graphs.
                # For this tool scope, it's acceptable. 
                # Optimization: Use a max path length?
                target_paths = list(nx.all_simple_paths(graph, source=self.internet_node, target=target, cutoff=10))
                paths.extend(target_paths)
            except nx.NetworkXNoPath:
                continue
            except nx.NodeNotFound:
                continue
        return paths

    def _get_fix_description(self, method: str, source: str, target: str) -> str:
        """Maps attack method to human-readable fix."""
        if method == "Network Reachability":
            return f"Restrict Security Group on {target} (Remove 0.0.0.0/0)"
        if method == "Public ACL/Policy":
            return f"Make S3 Bucket {target} Private (Block Public Access)"
        if method == "IMDS/Credential Access":
            return f"Enforce IMDSv2 on {source} to prevent credential theft"
        if method == "IAM Permission allow":
            return f"Scope down IAM Policy on {source} to deny access to {target}"
        if method == "Prompt Injection / Tool Abuse":
            return f"Implement Input Guardrails on Agent {source} or restrict Role {target}"
        if method == "Data Flow":
            return f"Encrypt Logs or Restrict Write Access from {source} to {target}"
        if method == "Public Endpoint":
            return f"Enable VPC Access Policy for Vector Store {target}"
            
        return f"Break relationship between {source} and {target}"
