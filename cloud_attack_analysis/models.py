from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

@dataclass
class Resource:
    """Represents a normalized Terraform resource."""
    id: str  # resource_type.resource_name
    type: str
    name: str
    attributes: Dict[str, Any]
    
    @property
    def is_ai_service(self) -> bool:
        return self.type in ["aws_sagemaker_endpoint", "aws_bedrock_model_invocation_logging_configuration", "aws_bedrock_agent"]

    @property
    def is_agent(self) -> bool:
        return self.type == "aws_bedrock_agent"

    @property
    def is_vector_store(self) -> bool:
        return "opensearch" in self.type or "vector" in self.type

    @property
    def is_internet_exposed(self) -> bool:
        # Simplified check for demonstration; logic often lies in rules
        return False

@dataclass
class RuleResult:
    """Result of a security rule evaluation."""
    rule_id: str
    resource_id: str
    is_compliant: bool
    description: str
    severity: str  # Critical, High, Medium, Low
    remediation: str

@dataclass
class AttackNode:
    """Node in the attack graph."""
    id: str
    type: str
    data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AttackPath:
    """A discovered path of compromise."""
    steps: List[AttackNode]
    risk_score: float
    severity: str
    
    def to_string(self) -> str:
        return " -> ".join([f"[{s.type}] {s.id}" for s in self.steps])
