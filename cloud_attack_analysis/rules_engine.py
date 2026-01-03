from typing import List
from .models import Resource, RuleResult

class RulesEngine:
    """Deterministic rules engine for identifying cloud misconfigurations."""

    @staticmethod
    def run(resources: List[Resource]) -> List[RuleResult]:
        results = []
        for res in resources:
            if res.type == "aws_security_group":
                results.extend(RulesEngine._check_sg_public_exposure(res))
            elif res.type == "aws_s3_bucket":
                results.extend(RulesEngine._check_s3_public(res))
            elif res.type == "aws_iam_policy":
                results.extend(RulesEngine._check_iam_permissive(res))
            elif res.type == "aws_bedrock_model_invocation_logging_configuration":
                results.extend(RulesEngine._check_ai_logging_plaintext(res))
        
        return results

    @staticmethod
    def _check_sg_public_exposure(res: Resource) -> List[RuleResult]:
        results = []
        ingresses = res.attributes.get("ingress", [])
        if not isinstance(ingresses, list): ingresses = [ingresses]
        
        for rule in ingresses:
            cidr_blocks = rule.get("cidr_blocks", [])
            # Handle list of strings
            if isinstance(cidr_blocks, list):
                if "0.0.0.0/0" in cidr_blocks:
                    results.append(RuleResult(
                        rule_id="NET-001",
                        resource_id=res.id,
                        is_compliant=False,
                        description="Security Group allows 0.0.0.0/0 ingress",
                        severity="High",
                        remediation="Restrict ingress to specific IPs."
                    ))
        return results

    @staticmethod
    def _check_s3_public(res: Resource) -> List[RuleResult]:
        # Simplified check: looks for acl="public-read" or similar
        # Real world would check block_public_access resources too
        acl = res.attributes.get("acl", "")
        if acl == "public-read" or acl == "public-read-write":
             return [RuleResult(
                rule_id="STO-001",
                resource_id=res.id,
                is_compliant=False,
                description=f"S3 Bucket {res.name} is public",
                severity="Critical",
                remediation="Set ACL to private and enable Block Public Access."
            )]
        return []

    @staticmethod
    def _check_iam_permissive(res: Resource) -> List[RuleResult]:
        # Check for Effect: Allow, Resource: *
        doc = res.attributes.get("policy", "")
        # In a real parser, 'policy' is a JSON string or Heredoc. 
        # We'll do a simple string check for demonstration as full JSON parsing of escaped strings is complex.
        if '"Effect": "Allow"' in doc or '"Effect": "Allow"' in str(doc): # Formatting varies
             if '"Resource": "*"' in doc or '"Action": "*"' in doc:
                  return [RuleResult(
                    rule_id="IAM-001",
                    resource_id=res.id,
                    is_compliant=False,
                    description="IAM Policy allows overly permissive access (*)",
                    severity="High",
                    remediation="Scope permissions to least privilege."
                )]
        return []

    @staticmethod
    def _check_ai_logging_plaintext(res: Resource) -> List[RuleResult]:
        # Check if AI logs are sent to S3 (potential leak of prompt data)
        # This is a structural check that informs the risk
        logging_config = res.attributes.get("logging_config", {})
        if "s3_config" in logging_config:
             return [RuleResult(
                rule_id="AI-001",
                resource_id=res.id,
                is_compliant=False,
                description="AI Model Invocation Logs stored in S3 (Sensitive Data Risk)",
                severity="Medium", # Becomes Critical if S3 is public
                remediation="Ensure target S3 bucket is encrypted and private."
            )]
        return []
