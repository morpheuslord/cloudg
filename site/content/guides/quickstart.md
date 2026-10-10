---
title: Quickstart
lede: "Scan one AWS region and open the report. Then, if you have no credentials to hand, get the same report from scanner files you already have, or map an account without any scanners."
meta:
  - [Time, "about 10 minutes, plus scanner run time"]
  - [Needs, "Python 3.11+, read-only AWS credentials"]
source: site/content/guides/quickstart.md
---

This page takes the shortest path to each of cloudg's three entry points. It sticks to AWS and one region so the first run is quick; every command takes `-p azure`, `-p gcp` or `-p all` the same way.

## Scan an AWS account

::::steps
### Install cloudg and a scanner

```bash
pip install "cloudg[aws]"
pip install prowler
```

Prowler is enough for a first run. cloudg skips scanners it cannot find on `PATH`, so you will see warnings for ScoutSuite, Checkov and Trivy; that is expected. [Installation](/guides/installation/) covers the rest, and the [Docker image](/guides/docker/) has Prowler, Checkov and Trivy built in.

### Authenticate

With no credential flags, cloudg uses boto3's default chain: the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` variables, then `AWS_PROFILE` or the default profile in `~/.aws`, cached SSO credentials, and on cloud compute the instance or task role. If the AWS CLI works, cloudg will too:

```bash
aws sso login --profile audit
export AWS_PROFILE=audit
aws sts get-caller-identity
```

:::tip Use read-only credentials
cloudg only reads. The AWS managed policies `SecurityAudit` and `ViewOnlyAccess` are the usual starting point for the role or user you scan with.
:::

### Run the pipeline

```bash
cloudg run -p aws --regions us-east-1
```

The run goes through five phases, printed as it goes: asset collection, graph analysis (plus RAG export), security scanning with every available scanner in parallel, normalisation, and report generation. The ontology is built after the scanners so it can include their findings. Prowler usually takes the longest.

To pick the profile on the command line instead of the environment, add `--profile audit`. To scan every enabled region, use `--regions all`.

### Open the report

```bash
open reports/report.html        # macOS
xdg-open reports/report.html    # Linux
```

`report.html` is a single file with the findings, assets and graph data embedded in it: the topology graph, the findings table and the compliance matrix. Chart.js and D3 are embedded too, so it opens without network access.
::::

### What lands in ./reports

```text
reports/
├── report.html               the report, open this first
├── findings.json             assets, normalised findings, compliance, graph data
├── topology.svg              static picture of the graph
├── topology.graphml          the graph for Gephi, yEd or NetworkX
├── ontology.ttl              RDF ontology (Turtle)
├── ontology.jsonld           RDF ontology (JSON-LD)
├── rag_chunks.jsonl          retrieval chunks, one JSON object per line
├── rag_metadata_index.json   index over the chunks
└── prowler/aws/              Prowler's own ASFF output
```

ScoutSuite, when installed, writes its report under `reports/scoutsuite/aws/`. Set `graph.export_cytoscape: true` in `config.yaml` to also get `topology-cytoscape.json`, the graph for Cytoscape. Add `--terraform` and you also get `reports/terraform/` with `.tf.json` files that recreate what was collected.

If the summary says 0 assets, collection did not authenticate. The Collection Coverage table at the end shows 0% for the region, and the log lines above it carry the reason. A profile that does not exist ("could not be found") fails the whole region: the run ends with a "Collection failed for every target" panel and exit status 3. When boto3 finds no credentials at all ("Unable to locate credentials"), each service fails on its own, the table lists them, and the run ends the same way, with the panel and exit status 3.

To re-render the report later without touching the cloud:

```bash
cloudg report -i reports/findings.json --format html
```

## No credentials: ingest scanner output

If someone else runs the scanners (in CI, on a schedule, on another network), you only need their output files. `cloudg ingest` needs no cloud access and no scanner binaries, and the core package without extras is enough.

::::steps
### Install the core package

```bash
pip install cloudg
```

### Point it at the files

Pass any combination of tools. Each flag takes a file or a directory and can be repeated:

```bash
cloudg ingest \
  --prowler ./prowler-output/ \
  --checkov ./results_json.json \
  --trivy ./trivy-image.json \
  -o ./reports
```

Prowler's input is its OCSF JSON (`*.ocsf.json`, Prowler 4's default) or ASFF JSON (`prowler aws -M json-asff`), Checkov's is `checkov -o json`, Trivy's is `trivy image -f json` or `trivy fs -f json`. ScoutSuite is read from its `scoutsuite_results_*.js` file or report directory with `--scoutsuite`.

### Read the result

```console
$ ls reports
findings.json  raw-findings.json  report.html
```

`raw-findings.json` holds every parsed finding before deduplication. `findings.json` and `report.html` hold the merged, compliance-mapped set. The last line of the output tells you how many duplicates were merged, for example "Ingested 3 findings from 3 tool(s), 3 after deduplication".
::::

There is no topology in an ingest report, because nothing was collected. [Ingesting existing output](/guides/ingesting/) covers the exact input formats and how to combine ingested findings with a live collection.

## No scanners: map the inventory

`cloudg map` answers "what is deployed, and what depends on what". It needs read-only credentials and the provider extra, but no scanners.

::::steps
### Map one region

```bash
cloudg map -p aws --regions us-east-1
```

This runs the deep collectors, a Cloud Control sweep over every listable resource type, and the relationship linker. It reads far more services than `cloudg run` does, so expect it to take longer.

### Look at the files

```console
$ ls reports
inventory-dependencies.json  inventory-graph.json  inventory-map.graphml  inventory-map.json
```

`inventory-map.json` is the map itself: every asset, every typed relationship, and a summary by service. `inventory-dependencies.json` lists shared dependencies, blast radius, cross-account edges and gaps in security service coverage.

### Ask about one asset

```bash
cloudg deps arn:aws:iam::123456789012:role/app-role
```

`cloudg deps` reads the saved map from `./reports` and prints what that asset depends on and what would break without it. `-d down` shows only the blast radius.
::::

When you do run scanners later, merge their findings into the map with `cloudg map --findings ./reports/findings.json` (or the `raw-findings.json` that `cloudg ingest` and `cloudg scan` write), which adds `asset-map.json` and `compliance-map.json`. [Inventory mapping](/guides/inventory-mapping/) goes through the map in depth.

## Next steps

:::links
- [The pipeline](/guides/pipeline/) What each phase of cloudg run does, and how to drive it from Python.
- [Authentication](/guides/authentication/) Profiles, role assumption, OIDC in CI, Azure and GCP.
- [Running scanners](/guides/running-scanners/) IaC directories, container images and scanner arguments.
- [Reports](/guides/reports/) Reading report.html and findings.json.
:::
