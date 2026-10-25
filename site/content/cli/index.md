---
title: CLI reference
description: Every cloudg command and the flags it takes, generated from the click definitions so the tables match --help.
---

Every `cloudg` command and the flags it takes. The tables are generated from the click definitions at build time, so they match `--help`.
{ .lede }

Options that belong to the root command go before the subcommand: `cloudg -c config.yaml map ...`. Without `-c`, cloudg runs on its built-in defaults and does not look for a `config.yaml` on its own. The flags shared by several commands have pages of their own: [provider and region flags](provider-flags.md), [auth flags](auth-flags.md) and [output flags](output-flags.md).

<!-- cloudg:cli-index -->
