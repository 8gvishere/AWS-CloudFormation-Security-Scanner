# Week 3 — The first security rule (SG-001)

**Target:** Identify unrestricted inbound SSH from a CloudFormation template.

## Understand the rule before writing it

Read [SecurityGroup ingress properties](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ec2-securitygroup-ingress.html).
A direct worldwide CIDR (`0.0.0.0/0` or `::/0`) with `IpProtocol: tcp`
and a port range containing `22` is the narrow pattern to detect. An
all-protocol (`-1`) rule also includes SSH. This is an assessment of the
*declaration*, not proof of a deployed exposure.

## Implementation sequence

1. Open `scanner/rules.py` and identify `_public_source()` and `_allows_ssh()`.
2. Make sure the code distinguishes TCP from UDP.
3. Test a narrow port range (`22`–`22`) and a wider range (`20`–`24`).
4. Add the standalone resource type `AWS::EC2::SecurityGroupIngress`.
5. Add IPv6 `::/0` testing.
6. Add a `REVIEW` state for unresolved `!Ref` expressions and conditional
   resources; do not call these `PASS` or `FAIL` without evidence.
7. Run `python -m scanner samples/02_insecure_ssh.yaml` and verify a `FAIL`.
8. Run `python -m pytest -q`.

## Required demonstrations

| Case | Expected outcome |
|---|---|
| Public SSH TCP/22, IPv4 world | FAIL |
| Restricted SSH TCP/22 | PASS for SG-001 |
| Public web HTTPS TCP/443 | PASS for SG-001 |
| Public SSH range 20–24 | FAIL |
| Dynamic CIDR (`!Ref`) | REVIEW |
| Conditional resource that would open SSH | REVIEW |
| S3 resource only | No SG-001 results; not an overall PASS |

## Your independent extension

Invent a new test case not already in this package (for example, a dynamically
specified protocol or a different SSH port-range boundary). Write down the
expected status BEFORE running the code. If your implementation behaves
incorrectly, explain and correct it in your own work.

## Completion criterion

The CLI prints correct, explainable SG-001 findings for the known fixtures.
You can defend the distinction between `PASS`, `FAIL`, and `REVIEW`.
