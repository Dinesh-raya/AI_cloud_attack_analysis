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
            
            if 'resource' in content:
                for resource_entry in content['resource']:
                    for res_type, res_instances in resource_entry.items():
                         for res_name, res_attrs in res_instances.items():
                            resource_id = f"{res_type}.{res_name}"
                            
                            # Normalize attributes
                            normalized_attrs = self._normalize_attributes(res_attrs)
                            
                            # SAFETY: Ensure attributes is a dict. hcl2 might return a list for the block body.
                            if isinstance(normalized_attrs, list):
                                if len(normalized_attrs) > 0:
                                    normalized_attrs = normalized_attrs[0]
                                else:
                                    normalized_attrs = {}

                            res = Resource(
                                id=resource_id,
                                type=res_type,
                                name=res_name,
                                attributes=normalized_attrs
                            )
                            self.resources.append(res)
                            
            if 'data' in content:
                for data_entry in content['data']:
                    for data_type, data_instances in data_entry.items():
                        for data_name, data_attrs in data_instances.items():
                             resource_id = f"data.{data_type}.{data_name}"
                             normalized_attrs = self._normalize_attributes(data_attrs)
                             
                             if isinstance(normalized_attrs, list):
                                if len(normalized_attrs) > 0:
                                    normalized_attrs = normalized_attrs[0]
                                else:
                                    normalized_attrs = {}
                                    
                             res = Resource(
                                id=resource_id,
                                type=data_type,
                                name=data_name,
                                attributes=normalized_attrs
                             )
                             self.resources.append(res)

        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")

    def _normalize_attributes(self, attrs: Any) -> Dict[str, Any]:
        """Flatten and clean up attributes."""
        if isinstance(attrs, dict):
            return {k: self._normalize_attributes(v) for k, v in attrs.items()}
        elif isinstance(attrs, list):
            return [self._normalize_attributes(i) for i in attrs]
        return attrs
