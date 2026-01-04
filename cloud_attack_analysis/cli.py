import argparse
import sys
import os
import traceback

# Add parent dir to path if running mostly as script for now
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cloud_attack_analysis.parser import TerraformParser
from cloud_attack_analysis.graph_builder import GraphBuilder
from cloud_attack_analysis.rules_engine import RulesEngine
from cloud_attack_analysis.attack_engine import AttackEngine
from cloud_attack_analysis.fix_engine import FixEngine
from cloud_attack_analysis.reporter import Reporter

def main():
    parser = argparse.ArgumentParser(description="Cloud Attack Analysis - AI Aware Edition")
    parser.add_argument("command", choices=["scan"], help="Command to execute")
    parser.add_argument("directory", help="Path to Terraform directory")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    args = parser.parse_args()

    if args.command == "scan":
        print(f"[*] Scanning directory: {args.directory}...")
        
        try:
            # 1. Parse
            tf_parser = TerraformParser(args.directory)
            resources = tf_parser.parse()
            print(f"[*] Parsed {len(resources)} resources.")

            # 2. Build Graph
            gb = GraphBuilder(resources)
            resource_graph = gb.build()
            print(f"[*] Built resource graph with {resource_graph.number_of_nodes()} nodes.")

            # 3. Rules
            rules = RulesEngine.run(resources)
            print(f"[*] Detected {len(rules)} misconfigurations.")

            # 4. Attack Path
            engine = AttackEngine(resource_graph, rules)
            path = engine.find_critical_path()
            
            # 5. Fix Prioritization
            if path:
                # Find critical targets
                targets = []
                for u, v, attr in resource_graph.edges(data=True):
                    if attr.get("relationship") == "logs_to":
                        targets.append(v)
                # Also include S3 buckets if relevant
                for node, data in resource_graph.nodes(data=True):
                    res = data.get('resource')
                    if res and res.type == "aws_s3_bucket" and node not in targets:
                         targets.append(node)

                fix_engine = FixEngine(engine.attack_graph, targets)
                remediations = fix_engine.calculate_fix_order()
            else:
                remediations = []

            # 6. Report
            if args.format == "json":
                print(Reporter.to_json(path))
            else:
                Reporter.print_report(path, remediations)

        except Exception as e:
            print(f"[!] Error: {e}")
            traceback.print_exc()
            sys.exit(1)

if __name__ == "__main__":
    main()
