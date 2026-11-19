"""Run with: python -m scanner samples/02_insecure_ssh.yaml"""

import argparse
import json
import sys
from dataclasses import asdict

from scanner.parser import TemplateError, load_template
from scanner.rules import scan_template


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Week 1-3 CloudFormation scanner: parse files, test SG-001"
    )
    parser.add_argument("template", help="CloudFormation .yaml/.yml/.json file")
    parser.add_argument("--json", action="store_true", help="print machine-readable results")
    args = parser.parse_args(argv)

    try:
        template = load_template(args.template)
    except TemplateError as exc:
        print(f"Template error: {exc}", file=sys.stderr)
        return 2

    findings = scan_template(template)
    if args.json:
        print(json.dumps({
            "source": template.source,
            "resources_total": len(template.resources),
            "rules_implemented": ["SG-001"],
            "results": [asdict(finding) for finding in findings],
        }, indent=2))
    else:
        print(f"File: {template.source}")
        print(f"Resources found: {len(template.resources)}")
        print(f"SSH-rule assessments: {len(findings)}")
        if not findings:
            print("No supported ingress resources found (NOT a clean security verdict).")
        for finding in findings:
            print(f"[{finding.status}] {finding.rule_id}  {finding.resource_id}")
            print(f"  {finding.message}")
            print(f"  Path: {finding.path}")
            if finding.status != "PASS":
                print(f"  Advice: {finding.recommendation}")
    return 1 if any(f.status == "FAIL" for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
