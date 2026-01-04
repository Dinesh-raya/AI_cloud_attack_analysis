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
            # Defensive coding for HCL parser lists
            cidrs = []
            if isinstance(rule, list):
                for sub in rule:
                    if isinstance(sub, dict):
                         cidrs.extend(sub.get("cidr_blocks", []))
            elif isinstance(rule, dict):
                cidrs = rule.get("cidr_blocks", [])

            # Handle list of strings
            if isinstance(cidrs, list):
                if "0.0.0.0/0" in cidrs:
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
        if isinstance(acl, list) and len(acl) > 0: acl = acl[0]
        
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
        if isinstance(doc, list) and len(doc) > 0:
            doc = doc[0] # HCL quirk

        doc_str = str(doc)
        
        if '"Effect": "Allow"' in doc_str: # Formatting varies
             if '"Resource": "*"' in doc_str or '"Action": "*"' in doc_str:
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
        if isinstance(logging_config, list) and len(logging_config) > 0:
            logging_config = logging_config[0]
            
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
