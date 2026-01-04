# Contributing to Cloud Attack Analysis

Thank you for your interest in contributing! We value clarity, precision, and security.

## Core Principles
*   **No Hallucinations**: Code logic must be deterministic. Do not introduce probabilistic guesses about security posture.
*   **Tests are Mandatory**: Every new graph edge logic must have a corresponding test case in `tests/`.
*   **Performance Matters**: We parse large infrastructure graphs. Avoid O(N^2) lookups where O(1) maps suffice.

## Development Setup
1.  Fork the repository.
2.  Create a virtual environment: `python -m venv venv`.
3.  Install dependencies: `pip install -r requirements.txt`.
4.  Run the CLI locally: `python -m cloud_attack_analysis.cli scan ./examples/vulnerable_infra`.

## Pull Request Process
1.  **Unit Tests**: Verify that your changes do not break existing pathfinding.
2.  **Documentation**: If you add a new Resource type, update the `models.py` docstrings.
3.  **Restraint**: Do not add features "just because". Explain the *Attacker Value* of the feature.

## Reporting Bugs
Please include:
*   Minimal Terraform example needed to reproduce the bug.
*   Expected Graph Edge vs Actual Graph Edge.
