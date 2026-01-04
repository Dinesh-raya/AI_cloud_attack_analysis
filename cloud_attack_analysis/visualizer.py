from pyvis.network import Network
import networkx as nx
import os

class Visualizer:
    """Generates interactive HTML graph visualizations."""

    def __init__(self, graph: nx.DiGraph):
        self.graph = graph

    def generate_html(self, output_path: str = "attack_graph.html"):
        net = Network(notebook=False, height="750px", width="100%", bgcolor="#222222", font_color="white", directed=True)
        
        # Add Nodes with styling
        for node in self.graph.nodes():
            res_type = self.graph.nodes[node].get("type", "unknown")
            color = self._get_color(res_type)
            # Shorten label for readability
            label = node.split(".")[-1] if "." in node else node
            title = f"ID: {node}\nType: {res_type}"
            
            net.add_node(node, label=label, title=title, color=color, shape="dot")

        # Add Edges
        for u, v in self.graph.edges():
            edge_data = self.graph.get_edge_data(u, v)
            label = edge_data.get("method", "")
            # Color edges based on risk? Maybe later. For now, white lines.
            net.add_edge(u, v, title=label, color="#aaaaaa")

        # Physics options for better stability
        net.barnes_hut()
        
        try:
            net.save_graph(output_path)
            print(f"[*] Visual graph saved to: {os.path.abspath(output_path)}")
        except Exception as e:
            print(f"[!] Error saving visualization: {e}")

    def _get_color(self, res_type: str) -> str:
        if "iam" in res_type: return "#ff4444" # Red for IAM
        if "s3" in res_type: return "#44ff44" # Green for Storage
        if "instance" in res_type or "lambda" in res_type or "security_group" in res_type: return "#ffaa00" # Orange for Compute/Net
        if "Internet" in res_type: return "#00ffff" # Cyan for Attacker/Internet
        if "bedrock" in res_type: return "#ff00ff" # Magenta for AI
        return "#888888" # Gray for others
