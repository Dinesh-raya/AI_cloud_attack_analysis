#!/usr/bin/env python3
"""
Cloud Attack Analysis - Security Decision Engine

One command to rule everything:
    python main.py --input demo/terraform --output report.json

This produces a deterministic JSON report that answers:
"If I can fix ONLY ONE issue today, which fix reduces the MOST real-world risk?"
"""

import argparse
import json
import sys
import os

# Add package to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cloud_attack_analysis.parser import TerraformParser
from cloud_attack_analysis.plan_parser import PlanParser
from cloud_attack_analysis.graph_builder import GraphBuilder
from cloud_attack_analysis.rules_engine import RulesEngine
from cloud_attack_analysis.attack_engine import AttackEngine
from cloud_attack_analysis.fix_prioritizer import FixPrioritizer
from cloud_attack_analysis.visualizer import Visualizer


def run_analysis(input_path: str, output_path: str = None, visualize: bool = False):
    """
    Execute the full security analysis pipeline.
    
    Flow:
    1. Parse Terraform/JSON configs
    2. Build resource graph
    3. Detect misconfigurations
    4. Discover attack paths
    5. Prioritize fixes by impact
    6. Generate JSON report
    """
    print("=" * 60)
    print(" CLOUD ATTACK ANALYSIS - SECURITY DECISION ENGINE")
    print("=" * 60)
    print()

    # Step 1: Parse input
    print("[1/5] Parsing infrastructure configuration...")
    resources = []
    
    if os.path.isfile(input_path) and input_path.endswith(".json"):
        parser = PlanParser()
        resources = parser.parse(input_path)
    else:
        parser = TerraformParser(input_path)
        resources = parser.parse()
    
    print(f"      → Parsed {len(resources)} resources")

    # Step 2: Build graph
    print("[2/5] Building resource relationship graph...")
    builder = GraphBuilder(resources)
    graph = builder.build()
    print(f"      → Created graph with {len(graph.nodes)} nodes, {len(graph.edges)} edges")

    # Step 3: Detect misconfigurations
    print("[3/5] Detecting security misconfigurations...")
    misconfigs = RulesEngine.run(resources)
    print(f"      → Found {len(misconfigs)} misconfigurations")

    # Step 4: Discover attack paths
    print("[4/5] Discovering attack paths...")
    attack_engine = AttackEngine(graph, misconfigs)
    attack_paths = attack_engine.find_all_paths()
    critical_path = attack_engine.find_critical_path()
    
    path_count = len(attack_paths) if attack_paths else 0
    print(f"      → Discovered {path_count} exploitable attack paths")

    # Step 5: Prioritize fixes
    print("[5/5] Prioritizing fixes by risk impact...")
    prioritizer = FixPrioritizer(graph, attack_paths if attack_paths else [], misconfigs)
    report = prioritizer.to_dict()
    
    fix_count = len(report.get("priority_fixes", []))
    print(f"      → Generated {fix_count} prioritized fix recommendations")
    print()

    # Handle no vulnerabilities case
    if fix_count == 0 and path_count == 0:
        report = {
            "status": "SECURE",
            "message": "No exploitable attack paths detected.",
            "priority_fixes": []
        }
        print("✅ RESULT: No exploitable attack paths detected.")
    else:
        report["status"] = "VULNERABLE"
        report["total_attack_paths"] = path_count
        report["critical_path"] = critical_path.path if critical_path else []
        
        print("⚠️  RESULT: Security issues detected. See report for prioritized fixes.")

    # Generate visualization if requested
    if visualize:
        print()
        print("[*] Generating attack graph visualization...")
        viz = Visualizer(graph)
        viz.generate_html("attack_graph.html")

    # Output report
    if output_path:
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n[*] Report saved to: {output_path}")
    else:
        print("\n" + "=" * 60)
        print(" PRIORITY FIX REPORT")
        print("=" * 60)
        print(json.dumps(report, indent=2))

    return report


def main():
    parser = argparse.ArgumentParser(
        description="Cloud Attack Analysis - Security Decision Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --input demo/terraform --output report.json
  python main.py --input plan.json --output report.json --visualize
  python main.py --input ./my-infra

For more information, see USAGE_GUIDE.md
        """
    )
    
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Path to Terraform directory or plan.json file"
    )
    
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Path to output JSON report (prints to stdout if not specified)"
    )
    
    parser.add_argument(
        "--visualize", "-v",
        action="store_true",
        help="Generate interactive HTML attack graph visualization"
    )

    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: Input path does not exist: {args.input}")
        sys.exit(1)

    run_analysis(args.input, args.output, args.visualize)


if __name__ == "__main__":
    main()
