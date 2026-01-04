import sys
import argparse
from .parser import TerraformParser
from .plan_parser import PlanParser
from .graph_builder import GraphBuilder
from .rules_engine import RulesEngine
from .attack_engine import AttackEngine, RuleResult
from .fix_engine import FixEngine
from .reporter import Reporter
from .visualizer import Visualizer
import os

def scan(directory, visualize=False):
    print(f"[*] Scanning target: {directory}...")
    
    resources = []
    
    # Check if input is a JSON Plan file
    if os.path.isfile(directory) and directory.endswith(".json"):
        print(f"[*] Detected Terraform Plan JSON.")
        parser = PlanParser()
        resources = parser.parse(directory)
    else:
        # Fallback to standard HCL Directory Scan
        parser = TerraformParser(directory)
        resources = parser.parse()

    print(f"[*] Parsed {len(resources)} resources.")

    builder = GraphBuilder(resources)
    graph = builder.build()
    print(f"[*] Built resource graph with {len(graph.nodes)} nodes.")

    if visualize:
        viz = Visualizer(graph)
        viz.generate_html("attack_graph.html")

    # RulesEngine is static
    misconfigs = RulesEngine.run(resources)
    print(f"[*] Detected {len(misconfigs)} misconfigurations.")

    attack_engine = AttackEngine(graph, misconfigs)
    
    critical_path = attack_engine.find_critical_path()
    
    # Identify targets for remediation
    targets = []
    for res in resources:
        if res.type == "aws_s3_bucket" or res.is_vector_store:
            targets.append(res.id)

    fix_engine = FixEngine(attack_engine.attack_graph, targets)
    remediations = fix_engine.calculate_fix_order(limit=5)
    
    Reporter.print_report(critical_path, remediations)

def main():
    parser = argparse.ArgumentParser(description="AI Cloud Attack Analysis Tool")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a directory or plan file")
    scan_parser.add_argument("target", help="Target directory or .json file")
    scan_parser.add_argument("--visualize", action="store_true", help="Generate HTML graph visualization")

    args = parser.parse_args()

    if args.command == "scan":
        scan(args.target, visualize=args.visualize)
    else:
        parser.print_help()
        
if __name__ == "__main__":
    main()
