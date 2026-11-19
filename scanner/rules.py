"""Week 3: ONE explainable rule for internet-accessible SSH.

Rule SG-001 checks declared *inbound* permissions on security groups and
standalone security-group-ingress resources. It does not scan a live AWS account.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from scanner.models import Finding, Resource, Status, Template

RULE_ID = "SG-001"
RULE_TITLE = "SSH open to the internet"
RECOMMENDATION = (
    "Restrict SSH (TCP/22) to approved source IP ranges, "
    "or use a managed access method rather than public SSH."
)


def _is_dynamic(value: Any) -> bool:
    """Does this value contain an unresolved CloudFormation expression?"""
    return isinstance(value, dict) and any(
        key == "Ref" or key.startswith("Fn::") for key in value if isinstance(key, str)
    )


def _public_source(rule: dict[str, Any]) -> tuple[bool, bool]:
    """Return (is_public, is_unknown) for directly declared IPv4/IPv6 CIDRs."""
    public = False
    unknown = False
    found = False
    for field in ("CidrIp", "CidrIpv6"):
        if field not in rule:
            continue
        found = True
        value = rule[field]
        if _is_dynamic(value) or not isinstance(value, str):
            unknown = True
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            unknown = True
            continue
        if network.prefixlen == 0:
            public = True
    if not found and not any(
        field in rule for field in (
            "SourceSecurityGroupId", "SourceSecurityGroupName", "SourcePrefixListId"
        )
    ):
        # Malformed/partially specified rule: do not mark it secure.
        unknown = True
    return public, unknown


def _allows_ssh(rule: dict[str, Any]) -> tuple[bool, bool]:
    """Return (allows_ssh, unknown) for explicit protocol and port settings."""
    protocol = rule.get("IpProtocol")
    if _is_dynamic(protocol) or protocol is None:
        return False, True
    protocol = str(protocol).lower()
    if protocol == "-1":
        return True, False  # All-protocol rule also includes SSH.
    if protocol in ("udp", "icmp", "icmpv6", "17", "1", "58"):
        return False, False
    if protocol not in ("tcp", "6"):
        return False, True

    low, high = rule.get("FromPort"), rule.get("ToPort")
    if _is_dynamic(low) or _is_dynamic(high):
        return False, True
    try:
        # Reject bools and floats instead of accepting e.g. True as port 1.
        if isinstance(low, bool) or isinstance(high, bool):
            return False, True
        if not isinstance(low, (int, str)) or not isinstance(high, (int, str)):
            return False, True
        if not str(low).lstrip("-").isdigit() or not str(high).lstrip("-").isdigit():
            return False, True
        start, stop = int(low), int(high)
    except (ValueError, TypeError):
        return False, True
    if not (0 <= start <= stop <= 65535):
        return False, True
    return start <= 22 <= stop, False


def _evaluate_ingress(rule: dict[str, Any]) -> tuple[Status, str]:
    public, unknown_source = _public_source(rule)
    permits_ssh, unknown_port = _allows_ssh(rule)
    if public and permits_ssh:
        return "FAIL", "Declared ingress permits SSH (TCP/22) from the entire internet."
    if (public and unknown_port) or (unknown_source and permits_ssh):
        return "REVIEW", "A dynamic or invalid ingress value prevents a certain SSH assessment."
    if unknown_source and unknown_port:
        return "REVIEW", "Both source and protocol/port details require manual review."
    return "PASS", "No directly declared internet-wide SSH access found in this ingress rule."


def _record(resource: Resource, path: str, status: Status, message: str) -> Finding:
    if resource.condition and status == "FAIL":
        status = "REVIEW"
        message = (
            f"Resource has Condition {resource.condition!r}; if enabled, this ingress "
            "would expose SSH to the internet."
        )
    return Finding(
        rule_id=RULE_ID,
        status=status,
        severity="HIGH" if status == "FAIL" else "REVIEW" if status == "REVIEW" else "INFO",
        resource_id=resource.logical_id,
        path=path,
        message=message,
        recommendation=RECOMMENDATION if status != "PASS" else "No action for this rule.",
    )


def check_ssh_ingress(resource: Resource) -> list[Finding]:
    """SG-001: check a supported resource and return its individual results."""
    if resource.resource_type == "AWS::EC2::SecurityGroup":
        prefix = f"Resources.{resource.logical_id}.Properties.SecurityGroupIngress"
        ingress = resource.properties.get("SecurityGroupIngress", [])
        if _is_dynamic(ingress) or not isinstance(ingress, list):
            return [_record(resource, prefix, "REVIEW", "Ingress is not a literal list.")]
        if not ingress:
            return [_record(resource, prefix, "PASS", "No inline ingress rules are declared.")]
        results = []
        for index, item in enumerate(ingress):
            path = f"{prefix}[{index}]"
            if not isinstance(item, dict) or _is_dynamic(item):
                results.append(_record(resource, path, "REVIEW", "Ingress entry is not a literal mapping."))
            else:
                outcome, msg = _evaluate_ingress(item)
                results.append(_record(resource, path, outcome, msg))
        return results

    if resource.resource_type == "AWS::EC2::SecurityGroupIngress":
        prefix = f"Resources.{resource.logical_id}.Properties"
        outcome, message = _evaluate_ingress(resource.properties)
        return [_record(resource, prefix, outcome, message)]

    return []  # Other resource types are OUT OF SCOPE, not verified secure.


def scan_template(template: Template) -> list[Finding]:
    results: list[Finding] = []
    for resource in template.resources:
        results.extend(check_ssh_ingress(resource))
    return results
