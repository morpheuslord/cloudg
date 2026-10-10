---
command: mcp prompts
lede: Lists the MCP prompts a server would expose, with the arguments each one takes.
intro: |
  cloudg's prompts are ready-made workflows, such as a security posture review or an incident triage, that a client can offer its user as one-click tasks. `cloudg mcp prompts` shows which of them a principal can see and what arguments they expect.
---

## How it works

The command builds the layer from the shared options (see [cloudg mcp serve](/cli/mcp-serve/#building-the-layer)) and prints the prompts visible to one principal: the local user by default, or the one described by `--role` and `--principal-id` (see [cloudg mcp tools](/cli/mcp-tools/) for how those work). `--prefix` is applied to prompt names as well as tool names.

The table has four columns. Arguments are listed in order, and a `*` marks the required ones. In 0.6.0 there are 11 prompts, all in the `prompts` category, and every built-in policy lists all of them for the local user:

```console
$ cloudg mcp prompts
                                                                   cloudg MCP prompts (11)
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Prompt                     ┃ Category ┃ Arguments             ┃ Description                                                                                ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ security_posture_review    │ prompts  │ dataset               │ Whole-estate security review: risks, exposure, identity pivots, coverage gaps, compliance. │
│ executive_summary          │ prompts  │ dataset               │ Non-technical one-page summary of the estate's security state.                             │
│ attack_surface_report      │ prompts  │ dataset               │ External attack surface: exposed assets, open admin ports, internet-to-crown-jewel paths.  │
│ investigate_asset          │ prompts  │ ref*, dataset         │ Deep dive on one asset: config, relations, exposure, findings, blast radius.               │
│ blast_radius_assessment    │ prompts  │ ref*, dataset         │ Impact of compromise or loss of one asset.                                                 │
│ change_impact_analysis     │ prompts  │ ref*, change, dataset │ What a planned change to one asset affects, with rollout and rollback plan.                │
│ cross_account_trust_review │ prompts  │ dataset               │ IAM trust and grants across account boundaries, external accounts, pivot chains.           │
│ compliance_gap_analysis    │ prompts  │ framework*, dataset   │ Failing controls, responsible assets and a remediation backlog for one framework.          │
│ remediation_plan           │ prompts  │ severity, dataset     │ Phased fix plan for findings at or above a severity.                                       │
│ incident_triage            │ prompts  │ finding_id*, dataset  │ Exploitability, impact and containment for one finding.                                    │
│ drift_review               │ prompts  │ base*, target         │ Explain the differences between two datasets (before / after).                             │
└────────────────────────────┴──────────┴───────────────────────┴────────────────────────────────────────────────────────────────────────────────────────────┘
```

`dataset` is optional everywhere and means the active dataset when left empty.

`--json` prints the `prompts/list` entries a client receives. Each has `name`, `title`, `description`, `arguments` (with `name`, `required` and `description`) and `_meta`:

```console
$ cloudg mcp prompts --json | jq '.[3]'
{
  "name": "investigate_asset",
  "description": "Deep dive on one asset: config, relations, exposure, findings, blast radius.",
  "arguments": [
    {
      "name": "ref",
      "required": true,
      "description": "Asset id, ARN or unique name."
    },
    {
      "name": "dataset",
      "required": false,
      "description": "Dataset name; empty = active dataset."
    }
  ],
  "title": "Investigate asset",
  "_meta": {
    "cloudg/category": "prompts",
    "cloudg/sensitivity": "confidential",
    "cloudg/tags": [
      "workflow"
    ]
  }
}
```

The CLI lists prompts but has no command to render one. A client does that through `prompts/get`. To see the rendered messages yourself, call the layer from Python (example below). A rendered prompt is a set of user messages: the instructions, a JSON context block, and often an embedded resource with the current data, such as the asset's detail for `investigate_asset`.

## Examples

List every prompt:

```bash
cloudg mcp prompts
```

See which prompts a principal with the `analyst` role gets under your own policy:

```bash
cloudg mcp prompts --policy ./mcp-policy.yaml --role analyst
```

List only the names of prompts with a required argument:

```bash
cloudg mcp prompts --json | jq -r '.[] | select(any(.arguments[]; .required)) | .name'
```

Render a prompt in-process to read what the assistant would receive:

```python title="render_prompt.py"
import asyncio
import json

from cloudg.mcp.server import create_layer_from_options

layer = create_layer_from_options(datasets=["prod=./reports/inventory-map.json"])
result = asyncio.run(layer.get_prompt("investigate_asset", {"ref": "bastion"}))
print(json.dumps(result.to_wire(), indent=2))
```

A missing required argument raises `Missing required prompt arguments: ref`, and an unknown or hidden prompt raises `Unknown prompt: <name>`.

## Exit codes

| Code | When |
|---|---|
| 0 | The list was printed |
| 1 | The layer could not be built |
| 2 | Click rejected an option |

## Related

:::links
- [Prompts](/mcp/tools/prompts/) Each prompt with its arguments and rendered output.
- [cloudg mcp tools](/cli/mcp-tools/) The tools the prompts tell the assistant to call.
- [In-process use](/mcp/server/in-process-use/) Driving the layer from Python.
- [cloudg mcp serve](/cli/mcp-serve/) The shared layer options in full.
:::
