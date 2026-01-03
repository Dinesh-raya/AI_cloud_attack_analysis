import hcl2
import os
import logging
from typing import List, Dict, Any
from .models import Resource

logger = logging.getLogger(__name__)

class TerraformParser:
    """Parses Terraform files and normalizes them into Resource objects."""
    
    def __init__(self, directory: str):
        self.directory = directory
        self.resources: List[Resource] = []

    def parse(self) -> List[Resource]:
        """Scans the directory for .tf files and parses them."""
        if not os.path.exists(self.directory):
            raise FileNotFoundError(f"Directory not found: {self.directory}")

        for root, _, files in os.walk(self.directory):
            for file in files:
                if file.endswith(".tf"):
                    file_path = os.path.join(root, file)
                    self._parse_file(file_path)
        
        return self.resources

    def _parse_file(self, file_path: str):
        try:
            with open(file_path, 'r') as f:
                content = hcl2.load(f)
            
            # HCL2 parses resources as a list of dictionaries: {'resource': [{'aws_s3_bucket': {'b': {...}}}]}
            if 'resource' in content:
                for resource_entry in content['resource']:
                    # resource_entry is like {'aws_instance': {'web': {...}}}
                    for res_type, res_instances in resource_entry.items():
                        # res_instances can be a dict (name: body) or list of dicts if blocks are repeated? 
                        # hcl2 python library usually returns a dict for the named instance if unique, 
                        # but let's handle the structure carefully.
                        # Actually hcl2 usually does: {type: {name: {attrs}}}
                        
                        # Wait, python-hcl2 structure is a bit tricky.
                        # It returns a list of resources. Each item is a dict mapping type to parsed content.
                        # Let's verify strict structure. 
                        # Typical output: {'resource': [{'aws_instance': {'web': {'ami': '...', ...}}}]}
                        # Or if multiple: {'resource': [{'aws_instance': {'web': ...}}, {'aws_instance': {'db': ...}}]}
                        
                        # Correct iteration:
                         for res_name, res_attrs in res_instances.items():
                            resource_id = f"{res_type}.{res_name}"
                            
                            # Normalize attributes
                            normalized_attrs = self._normalize_attributes(res_attrs)
                            
                            res = Resource(
                                id=resource_id,
                                type=res_type,
                                name=res_name,
                                attributes=normalized_attrs
                            )
                            self.resources.append(res)
                            
            # Also parse Data sources if needed for context, but requirement focused on resources
            # We treat Prompt Logs / Vector Stores as data resources presumably? 
            # Prompt: "- AI prompt logs / vector store (modeled as data resources)"
            if 'data' in content:
                for data_entry in content['data']:
                    for data_type, data_instances in data_entry.items():
                        for data_name, data_attrs in data_instances.items():
                             resource_id = f"data.{data_type}.{data_name}"
                             res = Resource(
                                id=resource_id,
                                type=data_type,
                                name=data_name,
                                attributes=self._normalize_attributes(data_attrs)
                             )
                             self.resources.append(res)

        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")

    def _normalize_attributes(self, attrs: Any) -> Dict[str, Any]:
        """Flatten and clean up attributes."""
        # Simple pass-through for now, can be enhanced to resolve variables/locals if scope permitted
        # Since this is a static analysis tool without state, we take raw values.
        if isinstance(attrs, dict):
            return {k: self._normalize_attributes(v) for k, v in attrs.items()}
        elif isinstance(attrs, list):
            return [self._normalize_attributes(i) for i in attrs]
        return attrs
