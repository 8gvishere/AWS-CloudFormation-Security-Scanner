# Architecture — teaching prototype

```text
samples/template.yaml or .json
            |
            v
scanner/parser.py (safe syntactic conversion + validation)
            |
            v
scanner/models.py (Resource and Template data classes)
            |
            v
scanner/rules.py (SG-001: direct internet-wide SSH ingress)
            |
            v
scanner/__main__.py (CLI display or JSON output)
```

The parser does not assign vulnerabilities. The rule engine does not read files
or call AWS services. That separation allows independent tests and easier
future replacement with richer CloudFormation parsing.

**Not implemented (deliberately):** FastAPI dashboard, cloud deployment,
IAM or S3 security checks, all CloudFormation intrinsics, account-wide posture,
full condition evaluation, severity scoring across rules.

**Known limitations:** a declaration is not a deployed state; `REVIEW` is needed
for unresolved configuration; the parser validates only a small subset of
CloudFormation structure and not AWS resource schemas.
