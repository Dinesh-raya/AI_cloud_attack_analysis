import networkx as nx
from typing import List, Dict
from .models import Resource

class GraphBuilder:
    """Builds a directed graph of infrastructure resources. Optimized & Config-Driven."""

    # Configuration: Relationship Registry
    # Format: Source Type -> List of Relationship Rules
    RELATIONSHIP_REGISTRY = {
        "aws_instance": [
            {"attr": "vpc_security_group_ids", "target_type": "aws_security_group", "rel": "protected_by", "list": True},
            {"attr": "iam_instance_profile", "target_type": "aws_iam_instance_profile", "rel": "assumes_role"},
            {"attr": "subnet_id", "target_type": "aws_subnet", "rel": "located_in"},
        ],
        "aws_bedrock_agent": [
            {"attr": "agent_resource_role_arn", "target_type": "aws_iam_role", "rel": "uses_identity"}
        ],
        "aws_iam_instance_profile": [
            {"attr": "role", "target_type": "aws_iam_role", "rel": "linked_role"}
        ]
    }

    def __init__(self, resources: List[Resource]):
        self.resources = resources
        self.resource_map = {r.id: r for r in resources}
        self.graph = nx.DiGraph()
        
        # Optimization: O(1) Lookup Indices
        self.name_index = {}
        self.bucket_index = {}
        self._build_indices()

    def _build_indices(self):
        """Builds indices for fast lookup."""
        for r in self.resources:
            # Index by name
            self.name_index[(r.type, r.name)] = r.id
            # Index by bucket (if applicable)
            bucket_val = r.attributes.get("bucket")
            if bucket_val:
                self.bucket_index[(r.type, bucket_val)] = r.id

    def build(self) -> nx.DiGraph:
        """Constructs the graph nodes and edges."""
        # Add all resources as nodes
        for res in self.resources:
            self.graph.add_node(res.id, type=res.type, resource=res)

        # Build relationships
        for res in self.resources:
            self._connect_related_resources(res)

        return self.graph

    def _connect_related_resources(self, res: Resource):
        """Connects resources based on registry and custom logic."""
        attrs = res.attributes
        
        # 1. Generic Registry Processor
        rules = self.RELATIONSHIP_REGISTRY.get(res.type, [])
        for rule in rules:
            self._process_rule(res, attrs, rule)

        # 2. Specific/Complex Logic (Hard to generalize without complex schema)
        
        # IAM Role Policy Attachment (Tricky because it links two OTHER nodes)
        if res.type == "aws_iam_role_policy_attachment":
            role = self._resolve_reference(attrs.get("role", ""))
            policy = self._resolve_reference(attrs.get("policy_arn", ""))
            if role and policy:
                self.graph.add_edge(role, policy, relationship="has_policy")

        # AI Service Logging (Deeply nested dicts)
        if res.type == "aws_bedrock_model_invocation_logging_configuration":
             self._process_bedrock_logging(res, attrs)

    def _process_rule(self, res: Resource, attrs: dict, rule: dict):
        """Process a standard relationship rule."""
        raw_val = attrs.get(rule["attr"])
        if not raw_val: return

        targets = raw_val if isinstance(raw_val, list) and rule.get("list") else [raw_val]
        
        for ref in targets:
            target_id = self._resolve_reference(ref)
            
            # Fallback for simple names (like roles in agents)
            if not target_id and rule["target_type"] == "aws_iam_role" and "/" in str(ref):
                 role_name = str(ref).split("/")[-1]
                 target_id = self._find_resource_by_name("aws_iam_role", role_name)

            if target_id:
                self.graph.add_edge(res.id, target_id, relationship=rule["rel"])

    def _process_bedrock_logging(self, res: Resource, attrs: dict):
        """Helper for complex Bedrock logging structure."""
        log_config = attrs.get("logging_config", [])
        if isinstance(log_config, list) and len(log_config) > 0: log_config = log_config[0]
        elif not isinstance(log_config, dict): log_config = {}

        s3_config = log_config.get("s3_config", [])
        if isinstance(s3_config, list) and len(s3_config) > 0: s3_config = s3_config[0]
        if not isinstance(s3_config, dict): s3_config = {}

        bucket_name = s3_config.get("bucket_name", "")
        if bucket_name:
            bucket_id = self._find_resource_by_name("aws_s3_bucket", bucket_name)
            if bucket_id:
                 self.graph.add_edge(res.id, bucket_id, relationship="logs_to")

    def _resolve_reference(self, ref_string: str) -> str:
        """Tries to resolve a Terraform reference string."""
        if not isinstance(ref_string, str):
            return None
            
        parts = ref_string.replace("${", "").replace("}", "").split(".")
        if len(parts) >= 2:
            res_type = parts[0]
            if res_type == "data": 
                 if len(parts) >= 3:
                     # e.g., data.aws_iam_policy_document.foo
                     res_type = parts[1]
                     res_name = parts[2]
                     candidate = f"data.{res_type}.{res_name}"
                     if candidate in self.resource_map:
                         return candidate
            else:
                res_name = parts[1]
                candidate = f"{res_type}.{res_name}"
                if candidate in self.resource_map:
                    return candidate
        return None

    def _find_resource_by_name(self, type_name: str, resource_name: str) -> str:
        """Finds a resource ID given its type and exact name (O(1) with index)."""
        # Try Bucket Index
        if (type_name, resource_name) in self.bucket_index:
            return self.bucket_index[(type_name, resource_name)]
            
        # Try Name Index
        if (type_name, resource_name) in self.name_index:
            return self.name_index[(type_name, resource_name)]
            
        return None
