---
name: summarize-items
description: Summarize a supplied list of synthetic work items by status for the gateway skills tutorial.
license: Apache-2.0
---

# Summarize synthetic work items

Read [the output format](references/output.md) before preparing the summary.
Use [the helper](./scripts/summarize.js) in Code Mode with `input.items` containing
objects with a `status` string. Return the compact counts, not the original list.
The helper makes no connector calls and changes no external state.
