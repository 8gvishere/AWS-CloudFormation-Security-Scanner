"""Week 3: SSH rule behaviors, including explicit uncertainty."""

from pathlib import Path

import pytest

from scanner.models import Resource
from scanner.parser import load_template
from scanner.rules import check_ssh_ingress, scan_template

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def results_for(name):
    return scan_template(load_template(SAMPLES / name))


def test_open_ipv4_ssh_is_fail():
    findings = results_for("02_insecure_ssh.yaml")
    assert len(findings) == 1
    assert findings[0].status == "FAIL"
    assert findings[0].severity == "HIGH"
    assert findings[0].resource_id == "PublicSSH"


def test_restricted_ssh_is_pass():
    assert results_for("03_secure_ssh.yaml")[0].status == "PASS"


def test_dynamic_source_requires_review():
    assert results_for("04_dynamic_source.yaml")[0].status == "REVIEW"


def test_standalone_ingress_and_port_range_detected():
    assert results_for("05_standalone_ingress.json")[0].status == "FAIL"


def test_conditional_public_ssh_requires_review():
    assert results_for("06_conditional_ingress.yaml")[0].status == "REVIEW"


def test_open_ipv6_ssh_is_fail():
    assert results_for("07_ipv6_insecure.yaml")[0].status == "FAIL"


def test_s3_not_misrepresented_as_clean():
    assert results_for("08_unchecked_s3.yaml") == []


def test_multiple_entries_report_independently():
    resource = Resource("ManyRules", "AWS::EC2::SecurityGroup", {
        "SecurityGroupIngress": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"},
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIp": "0.0.0.0/0"},
        ]
    })
    findings = check_ssh_ingress(resource)
    assert [item.status for item in findings] == ["FAIL", "PASS"]
    assert findings[0].path.endswith("[0]")


@pytest.mark.parametrize("protocol,from_port,to_port,status", [
    ("tcp", 22, 22, "FAIL"),
    ("6", 20, 30, "FAIL"),
    (-1, None, None, "FAIL"),
    ("tcp", 80, 80, "PASS"),
    ("udp", 22, 22, "PASS"),
    ({"Ref": "Protocol"}, 22, 22, "REVIEW"),
    ("tcp", {"Ref": "Port"}, 22, "REVIEW"),
])
def test_protocol_port_variations(protocol, from_port, to_port, status):
    ingress = {"IpProtocol": protocol, "CidrIp": "0.0.0.0/0"}
    if from_port is not None:
        ingress["FromPort"] = from_port
    if to_port is not None:
        ingress["ToPort"] = to_port
    resource = Resource("Sg", "AWS::EC2::SecurityGroup", {
        "SecurityGroupIngress": [ingress]
    })
    assert check_ssh_ingress(resource)[0].status == status


def test_unrecognized_protocol_requires_review():
    res = Resource("Sg", "AWS::EC2::SecurityGroupIngress", {
        "IpProtocol": "99", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"
    })
    assert check_ssh_ingress(res)[0].status == "REVIEW"


def test_missing_cidr_requires_review():
    res = Resource("Sg", "AWS::EC2::SecurityGroupIngress", {
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22
    })
    assert check_ssh_ingress(res)[0].status == "REVIEW"


def test_no_inline_ingress_passes_only_for_this_rule():
    res = Resource("Sg", "AWS::EC2::SecurityGroup", {})
    result = check_ssh_ingress(res)
    assert len(result) == 1 and result[0].status == "PASS"
