"""Week 2: load a bounded subset of AWS CloudFormation YAML and JSON safely.

Parsing is not security analysis. This module converts file content into
structured Resource objects; security rules live separately in rules.py.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

from scanner.models import Resource, Template

MAX_TEMPLATE_BYTES = 1024 * 1024  # 1 MiB for this teaching prototype
SUPPORTED_EXTENSIONS = {".yaml", ".yml", ".json"}


class TemplateError(ValueError):
    """An input file cannot be interpreted as a supported template."""


class CloudFormationSafeLoader(yaml.SafeLoader):
    """SafeLoader with a SMALL allowlist of CloudFormation YAML tags."""


def _mapping_without_duplicates(loader: CloudFormationSafeLoader, node: MappingNode):
    """Fail rather than silently overwriting repeated YAML keys."""
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, (str, int, float, bool)):
            raise TemplateError("YAML mapping keys must be simple values")
        if key in result:
            raise TemplateError(f"Duplicate YAML key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=True)
    return result


CloudFormationSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping_without_duplicates
)


def _intrinsic_constructor(long_name: str):
    """Convert short CloudFormation tags to their JSON-style representation."""
    def construct(loader: CloudFormationSafeLoader, node):
        if isinstance(node, ScalarNode):
            value = loader.construct_scalar(node)
        elif isinstance(node, SequenceNode):
            value = loader.construct_sequence(node, deep=True)
        elif isinstance(node, MappingNode):
            value = loader.construct_mapping(node, deep=True)
        else:
            raise TemplateError("Unsupported intrinsic function value")
        return {long_name: value}
    return construct


for short_name, long_name in {
    "!Ref": "Ref",
    "!Sub": "Fn::Sub",
    "!GetAtt": "Fn::GetAtt",
    "!If": "Fn::If",
}.items():
    CloudFormationSafeLoader.add_constructor(
        short_name, _intrinsic_constructor(long_name)
    )


def _json_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output = {}
    for key, value in pairs:
        if key in output:
            raise TemplateError(f"Duplicate JSON key: {key!r}")
        output[key] = value
    return output


def load_template(file_path: str | Path) -> Template:
    """Load and check one template file. Do not deploy or run its contents.

    Week 2 scope: .yaml/.yml/.json, a few common intrinsic tags, Resources.
    Unknown YAML tags are rejected rather than guessed or executed.
    """
    path = Path(file_path)
    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise TemplateError("Expected a .yaml, .yml or .json template")
    try:
        if path.stat().st_size > MAX_TEMPLATE_BYTES:
            raise TemplateError("Template is larger than the 1 MiB limit")
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TemplateError(f"Cannot read {path}: {exc}") from exc
    except UnicodeError as exc:
        raise TemplateError("File must be UTF-8 text") from exc

    try:
        if path.suffix.lower() == ".json":
            raw = json.loads(content, object_pairs_hook=_json_without_duplicates)
        else:
            raw = yaml.load(content, Loader=CloudFormationSafeLoader)
    except (json.JSONDecodeError, yaml.YAMLError, UnicodeError) as exc:
        raise TemplateError(f"Invalid template syntax: {exc}") from exc

    if not isinstance(raw, dict):
        raise TemplateError("A CloudFormation template must be a mapping/object")
    resources = raw.get("Resources")
    if not isinstance(resources, dict) or not resources:
        raise TemplateError("The template must contain a nonempty Resources mapping")

    parsed = []
    for logical_id, resource in resources.items():
        if not isinstance(logical_id, str) or not isinstance(resource, dict):
            raise TemplateError("Each resource requires a string ID and a mapping")
        resource_type = resource.get("Type")
        if not isinstance(resource_type, str) or not resource_type:
            raise TemplateError(f"Resource {logical_id!r} is missing a Type string")
        properties = resource.get("Properties", {})
        if not isinstance(properties, dict):
            raise TemplateError(f"Resource {logical_id!r} needs a Properties mapping")
        condition = resource.get("Condition")
        if condition is not None and not isinstance(condition, str):
            raise TemplateError(f"Resource {logical_id!r} has an invalid Condition")
        parsed.append(Resource(logical_id, resource_type, properties, condition))

    return Template(source=str(path), resources=tuple(parsed))
