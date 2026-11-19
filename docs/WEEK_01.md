# Week 1 — YAML, JSON and CloudFormation basics

**Target:** Explain the meaning of a template; write two equivalent files yourself.
Do not start the web application or create an AWS account.

## Reading (official sources)

1. [CloudFormation template structure](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-structure.html)
2. [Resources section](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resources-section-structure.html)
3. [Python JSON library](https://docs.python.org/3/library/json.html)

## Daily practical tasks

| Day | Study | Checkable result |
|---|---|---|
| 1 | YAML indentation, mappings, strings | Explain each line of `samples/01_basic.yaml` |
| 2 | YAML lists and nested resources | Create a second resource and indent it correctly |
| 3 | JSON braces, arrays, commas | Convert your YAML into JSON manually |
| 4 | CloudFormation `Resources`, `Type`, `Properties` | Identify logical IDs and AWS resource types |
| 5 | AWS security groups and SSH | Explain protocol TCP, port 22, CIDR prefix |
| 6 | Compare YAML vs JSON | Compare `samples/01_basic.yaml` and `samples/01_basic.json` |
| 7 | Review | Independently create `samples/my_first_template.yaml` |

## Exercise

Create `samples/my_first_template.yaml` from memory. It should contain one
`AWS::EC2::SecurityGroup` whose SSH ingress source is `192.0.2.0/24` (a reserved
example network). Then create a matching `.json` file.

Record in `docs/DEVELOPMENT_LOG.md`: what you understood, your own questions,
and any syntax errors you had to correct.
