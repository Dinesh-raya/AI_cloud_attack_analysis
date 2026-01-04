import json
from typing import List, Dict, Any
from .models import Resource

class PlanParser:
    """
    Parses Terraform Plan JSON output (terraform show -json).
    Extracts resources from 'planned_values' to support computed state analysis.
    """

    def parse(self, file_path: str) -> List[Resource]:
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[!] Error decoding JSON plan: {e}")
            return []
        except FileNotFoundError:
            print(f"[!] File not found: {file_path}")
            return []

        resources = []
        
        # We focus on planned_values -> root_module -> resources (and child modules)
        root_module = data.get("planned_values", {}).get("root_module", {})
        resources.extend(self._extract_resources(root_module))

        return resources

    def _extract_resources(self, module: Dict[str, Any]) -> List[Resource]:
        """Recursively extracts resources from a module dictionary."""
        extracted = []

        # 1. Direct Resources
        for res_data in module.get("resources", []):
            res_type = res_data.get("type")
            res_name = res_data.get("name")
            # TF Plan 'values' contains the computed attributes
            attributes = res_data.get("values", {})
            
            # Add provider/address info if useful, but core needs type/name/attrs
            # Construct a Resource object
            # Note regarding ID: TF Plan uses 'address' (e.g. module.x.aws_s3_bucket.y) as a unique key often
            # We will use the 'type.name' convention for ID to match our HCL parser for now, 
            # or the full address if valid.
            
            # Using full address provides better uniqueness but might break graph builder lookup 
            # if graph builder expects 'type.name'.
            # Let's stick to 'type.name' for compatibility with existing GraphBuilder logic,
            # unless address is significantly better.
            # Actually, GraphBuilder._resolve_reference handles 'type.name'.
            
            res_id = f"{res_type}.{res_name}"
            
            # Normalization: Our GraphBuilder expects certain naming conventions (e.g. lists for rules)
            # TF Plan JSON is usually very explicit.
            
            extracted.append(Resource(
                id=res_id,
                type=res_type,
                name=res_name,
                attributes=attributes
            ))

        # 2. Child Modules
        for child in module.get("child_modules", []):
            extracted.extend(self._extract_resources(child))

        return extracted
