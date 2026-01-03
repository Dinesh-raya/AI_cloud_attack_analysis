import networkx as nx
from typing import List, Dict
from .models import Resource

class GraphBuilder:
    """Builds a directed graph of infrastructure resources."""

    def __init__(self, resources: List[Resource]):
        self.resources = resources
        self.resource_map = {r.id: r for r in resources}
        self.graph = nx.DiGraph()

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
        """Heuristic logic to connect resources based on attributes."""
        attrs = res.attributes
        
        # 1. EC2 -> Security Group
        if res.type == "aws_instance":
            # flexible checking for vpc_security_group_ids or security_groups
            sgs = attrs.get("vpc_security_group_ids", [])
            if not isinstance(sgs, list): sgs = [sgs]
            
            for sg_ref in sgs:
                target = self._resolve_reference(sg_ref)
                if target:
                    self.graph.add_edge(res.id, target, relationship="protected_by")
            
            # EC2 -> IAM Role (via instance profile usually, but simplifed here for direct connection if modeled)
            iam_profile = attrs.get("iam_instance_profile", "")
            if iam_profile:
                target = self._resolve_reference(iam_profile)
                if target:
                    self.graph.add_edge(res.id, target, relationship="assumes_role")

        # 2. IAM Role -> Policy Attachment 
        # (Modeling direct policy attachment or assuming standalone policies attached to roles)
        if res.type == "aws_iam_role_policy_attachment":
            role = self._resolve_reference(attrs.get("role", ""))
            policy = self._resolve_reference(attrs.get("policy_arn", ""))
            if role and policy:
                self.graph.add_edge(role, policy, relationship="has_policy")

        # 3. AI Service -> Logging Config (S3)
        # Bedrock logging config
        if res.type == "aws_bedrock_model_invocation_logging_configuration":
            # This resource connects a simplified "model" or "account" concept to an S3 bucket
            # In our simplified model, we might treat this as a node that connects to S3
            bucket_name = attrs.get("logging_config", {}).get("s3_config", {}).get("bucket_name", "")
            if bucket_name:
                # Need to find the bucket resource by name (not ID) since it might be a string ref
                bucket_id = self._find_resource_by_name("aws_s3_bucket", bucket_name)
                if bucket_id:
                     self.graph.add_edge(res.id, bucket_id, relationship="logs_to")

        # 4. IAM Policy -> S3 or AI (Permission edges)
        # This is strictly about the DEFINITION of access.
        # We might handle this in the Rules Engine or Attack Engine more dynamically.
        # But adding structural edges helps.
        pass

    def _resolve_reference(self, ref_string: str) -> str:
        """Tries to resolve a Terraform reference string (e.g., '${aws_s3_bucket.foo.id}') to a resource ID."""
        if not isinstance(ref_string, str):
            return None
            
        # Simplistic parsing for '${aws_type.name.attr}' or 'aws_type.name.attr'
        parts = ref_string.replace("${", "").replace("}", "").split(".")
        if len(parts) >= 2:
            res_type = parts[0]
            if res_type == "data": # Handle data resources data.type.name
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
        """Finds a resource ID given its type and exact name (useful for string refs)."""
        # Note: Terraform names vs user defined names.
        # If bucket_name is linked to `aws_s3_bucket.b.bucket`, we need to match the *value* of the attribute.
        # This acts as a rudimentary symbol table lookup.
        for r in self.resources:
            if r.type == type_name:
                # Check if the 'bucket' attribute matches, or if the TF resource name matches
                if r.attributes.get("bucket") == resource_name or r.name == resource_name:
                    return r.id
        return None
