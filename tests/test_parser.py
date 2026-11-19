"""Week 2: evidence that template loading and validation actually work."""

from pathlib import Path

import pytest

from scanner.parser import MAX_TEMPLATE_BYTES, TemplateError, load_template

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def test_yaml_basic_resources():
    template = load_template(SAMPLES / "01_basic.yaml")
    assert len(template.resources) == 2
    assert template.resources[0].logical_id == "AdminSecurityGroup"
    assert template.resources[0].resource_type == "AWS::EC2::SecurityGroup"


def test_yaml_json_contain_equivalent_resource_data():
    yaml_resources = load_template(SAMPLES / "01_basic.yaml").resources
    json_resources = load_template(SAMPLES / "01_basic.json").resources
    assert yaml_resources == json_resources


def test_ref_short_form_is_not_evaluated():
    template = load_template(SAMPLES / "04_dynamic_source.yaml")
    rule = template.resources[0].properties["SecurityGroupIngress"][0]
    assert rule["CidrIp"] == {"Ref": "AllowedCidr"}


def test_conditional_resource_is_preserved():
    template = load_template(SAMPLES / "06_conditional_ingress.yaml")
    assert template.resources[0].condition == "UsePublicSSH"


def test_empty_document_rejected(tmp_path):
    bad = tmp_path / "empty.yaml"
    bad.write_text("", encoding="utf-8")
    with pytest.raises(TemplateError, match="mapping"):
        load_template(bad)


@pytest.mark.parametrize("source", [
    "Resources: []\n", "Resources: {}\n", "Nothing: here\n",
])
def test_missing_or_invalid_resources_rejected(tmp_path, source):
    bad = tmp_path / "bad.yaml"
    bad.write_text(source, encoding="utf-8")
    with pytest.raises(TemplateError, match="Resources"):
        load_template(bad)


def test_resource_missing_type_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("Resources:\n  A:\n    Properties: {}\n", encoding="utf-8")
    with pytest.raises(TemplateError, match="Type"):
        load_template(bad)


def test_properties_not_mapping_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("Resources:\n  A:\n    Type: AWS::S3::Bucket\n    Properties: []\n", encoding="utf-8")
    with pytest.raises(TemplateError, match="Properties"):
        load_template(bad)


def test_malformed_yaml_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("Resources: [unterminated", encoding="utf-8")
    with pytest.raises(TemplateError, match="Invalid template syntax"):
        load_template(bad)


def test_unsupported_yaml_tag_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("Resources:\n  A:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: !ImportValue CrossStack\n", encoding="utf-8")
    with pytest.raises(TemplateError, match="Invalid template syntax"):
        load_template(bad)


def test_repeated_yaml_key_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("Resources:\n  A: {Type: AWS::S3::Bucket}\n  A: {Type: AWS::S3::Bucket}\n", encoding="utf-8")
    with pytest.raises(TemplateError, match="Duplicate YAML key"):
        load_template(bad)


def test_repeated_json_key_rejected(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"Resources":{"A":{"Type":"AWS::S3::Bucket", "Type":"AWS::S3::Bucket"}}}', encoding="utf-8")
    with pytest.raises(TemplateError, match="Duplicate JSON key"):
        load_template(bad)


def test_bad_extension_rejected(tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text("Resources: {}", encoding="utf-8")
    with pytest.raises(TemplateError, match="Expected"):
        load_template(bad)


def test_size_limit_rejected(tmp_path):
    bad = tmp_path / "big.yaml"
    bad.write_bytes(b"a" * (MAX_TEMPLATE_BYTES + 1))
    with pytest.raises(TemplateError, match="1 MiB"):
        load_template(bad)


def test_missing_file_rejected(tmp_path):
    with pytest.raises(TemplateError, match="Cannot read"):
        load_template(tmp_path / "missing.yaml")
