# Week 2 — Build and understand a template parser

**Target:** Load YAML and JSON locally, extract resource objects, reject bad input.

## Read first

- [`yaml.SafeLoader` and PyYAML documentation](https://pyyaml.org/wiki/PyYAMLDocumentation)
- [CloudFormation intrinsic-function reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/intrinsic-function-reference.html)

## Build the parser in stages

1. Open `scanner/parser.py`. Trace how `load_template()` reads a file and chooses
   JSON or YAML parsing based on its extension.
2. Follow `Resources` into a dictionary; explain `Resource` in `scanner/models.py`.
3. Write your own small function that prints every logical ID and resource type.
4. Deliberately introduce a missing `Type`, malformed YAML and duplicate key.
   Observe the error from the parser and connect it to a test in `tests/test_parser.py`.
5. Study how `!Ref` is converted into `{"Ref": "..."}` rather than being resolved.
   This tool cannot know deployed values from a template alone.
6. Run `python -m pytest -q`; correct any failures caused by your own changes.

## Write down design decisions

- Why use JSON and YAML parsers instead of manually splitting lines?
- Why subclass the *safe* YAML loader rather than use unsafe object constructors?
- Why should malformed templates fail early?
- Why can `!Ref` not be assumed to have a known value?

## Completion criterion

From a local file path, the parser returns a tuple of resources with ID, type,
properties, and optional condition. You can explain every branch of this code.
