---
title: Credits
description: The projects, data and standards cloudg builds on, and the licenses that come with them.
---

cloudg builds on other people's work, and some of it ships inside the package. This page lists where each piece comes from and under which license.
{ .lede }

## At a glance

| Project | License | What cloudg uses |
|---|---|---|
| [Prowler](https://github.com/prowler-cloud/prowler) | Apache-2.0 | 22 compliance framework files generated from its compliance JSON; its ASFF and OCSF output |
| [Checkov](https://github.com/bridgecrewio/checkov) | Apache-2.0 | Run as a separate program; reports parsed, `CKV_*` check IDs |
| [Trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | Run as a separate program; reports parsed, `AVD-*` check IDs |
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | GPL-2.0 | Run as a separate program; reports parsed |
| [Cloud Custodian](https://github.com/cloud-custodian/cloud-custodian) | Apache-2.0 | Policy format and the `custodian` CLI for `cloudg/policies/` |
| [parliament](https://github.com/duo-labs/parliament) | BSD-3-Clause | IAM policy linting |
| [MITRE ATT&CK®](https://attack.mitre.org/) | Used with permission | Technique IDs and descriptions |
| [Chart.js](https://www.chartjs.org) 4.4.0 | MIT | Charts in report.html |
| [D3](https://d3js.org) 7.9.0 | ISC | The 2D graph view in report.html |
| [Anatomy](https://github.com/wheresryan22/anatomy) iso-kit | MIT | The camera, solids and shading of the isometric map in report.html |
| [Hairline](https://hairline.lucasmarkes.com) 0.5.1 kernel | MIT | The line figures in report.html's empty states |

## Prowler

[Prowler](https://github.com/prowler-cloud/prowler) (Apache-2.0). The 22 framework files in `cloudg/rules/frameworks/` are generated from Prowler's compliance JSON by `scripts/import_prowler_compliance.py`. That covers the control IDs, the control titles and descriptions, and the mapping from each control to Prowler check names. Every generated file says so in its header and in its `source` field. Prowler check names also appear in `cloudg/rules/check_equivalence.yaml`, and cloudg runs Prowler and parses its ASFF and OCSF output.

## Scanners

[Checkov](https://github.com/bridgecrewio/checkov) (Apache-2.0), [Trivy](https://github.com/aquasecurity/trivy) (Apache-2.0) and [ScoutSuite](https://github.com/nccgroup/ScoutSuite) (GPL-2.0) are run as separate programs, and their reports are parsed. Their check IDs (`CKV_*`, `AVD-*`) are used in the check-equivalence map. None of their code is part of cloudg. The Docker image installs Prowler, Checkov and Trivy, so their own licenses apply to those copies.

## Cloud Custodian

[Cloud Custodian](https://github.com/cloud-custodian/cloud-custodian) (Apache-2.0). The policy packs in `cloudg/policies/` are written in Cloud Custodian's policy format and run with its `custodian` CLI.

## parliament

[parliament](https://github.com/duo-labs/parliament) (BSD-3-Clause) from Duo Labs does the IAM policy linting.

## Drawing engines

The estate map in report.html is drawn with the iso-kit from [Anatomy](https://github.com/wheresryan22/anatomy) (MIT, Copyright (c) 2026 Ryan): its camera, its solids and their four-tone shading. The empty states use the kernel of [Hairline](https://hairline.lucasmarkes.com) 0.5.1 (MIT, Copyright (c) 2026 Lucas Marques), with a figure of an empty tray written for cloudg in Hairline's own format. Both files sit in `cloudg/templates/vendor/` and are embedded in every report, so the map works offline. The Hairline kernel is unmodified. The iso-kit is wrapped so it can sit inside a script element; [`NOTICE`](https://github.com/morpheuslord/cloudg/blob/main/cloudg/templates/vendor/NOTICE) lists exactly what changed.

## MITRE ATT&CK

[MITRE ATT&CK®](https://attack.mitre.org/). The `mitre_attack_*.yaml` files contain ATT&CK technique IDs and descriptions. © The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. ATT&CK is a registered trademark of The MITRE Corporation.

## Standards

The hand-written rulesets in `cloudg/rules/` reference public control numbering from the CIS Benchmarks for AWS, Azure and GCP, NIST SP 800-53, NIST CSF, PCI DSS, the AICPA SOC 2 Trust Services Criteria, the HIPAA Security Rule, GDPR, ISO/IEC 27001:2022 and the AWS Foundational Security Best Practices. The standards belong to their publishers. CIS Benchmarks is a trademark of the Center for Internet Security, and cloudg is not affiliated with or endorsed by CIS or any other publisher named here.

## Python libraries

The Python libraries cloudg depends on (NetworkX, rdflib, pydantic, Click, Rich and the rest) are listed in [`pyproject.toml`](https://github.com/morpheuslord/cloudg/blob/main/pyproject.toml).

## License

cloudg itself is released under the [MIT License](https://github.com/morpheuslord/cloudg/blob/main/LICENSE). report.html embeds unmodified builds of Chart.js and D3 when `report.inline_js` is true (the default), and always embeds the Anatomy iso-kit and the Hairline kernel, so the report works offline. Their notices are in [`cloudg/templates/vendor/NOTICE`](https://github.com/morpheuslord/cloudg/blob/main/cloudg/templates/vendor/NOTICE).
