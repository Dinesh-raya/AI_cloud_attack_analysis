import json
from .models import AttackPath
from colorama import Fore, Style, init

init(autoreset=True)

class Reporter:
    """Handles output formatting."""

    @staticmethod
    def print_report(path: AttackPath):
        if not path:
            print(Fore.GREEN + "\n[+] No critical attack paths found.")
            return

        print(Fore.RED + "\n[!] CRITICAL ATTACK PATH DETECTED [!]")
        print(f"Risk Score: {path.risk_score} | Severity: {path.severity}")
        print("-" * 60)

        for i, step in enumerate(path.steps):
            icon = "🛑" if i == len(path.steps)-1 else "🔻"
            print(f"{i+1}. {Fore.CYAN}[{step.type}]{Style.RESET_ALL} {step.id}")
            if i < len(path.steps) - 1:
                print(f"   {icon} {Fore.YELLOW}exploits trust to reach{Style.RESET_ALL}")
        
        print("-" * 60)
        print(Fore.WHITE + "Narrative:")
        print(f"The attacker starts at the {Fore.MAGENTA}Internet{Fore.WHITE}.")
        print("They locate a public-facing instance or service.")
        print("Through lateral movement (role assumption or permissions), they pivot.")
        print(f"Finally, they reach {Fore.RED}{path.steps[-1].id}{Fore.WHITE}, containing sensitive AI artifacts.")
        print("-" * 60)
        print(Fore.GREEN + "RECOMMENDED FIXES:")
        print("1. Restrict Security Group ingress (Remove 0.0.0.0/0).")
        print("2. Enforce Least Privilege on IAM Roles (Remove '*').")
        print("3. Encrypt AI Model Logs and block public S3 access.")

    @staticmethod
    def to_json(path: AttackPath) -> str:
        if not path:
            return json.dumps({"status": "safe", "path": []}, indent=2)
        
        data = {
            "status": "vulnerable",
            "risk_score": path.risk_score,
            "severity": path.severity,
            "path": [{"id": s.id, "type": s.type} for s in path.steps]
        }
        return json.dumps(data, indent=2)
