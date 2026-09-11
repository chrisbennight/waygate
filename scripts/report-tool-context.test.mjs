#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { budgetViolations, buildReport } from "./report-tool-context.mjs";

const schema = { type: "object", properties: {} };
const scriptDirectory = dirname(fileURLToPath(import.meta.url));

test("accepts each standard tools/list capture shape", () => {
  const tool = { name: "weather", inputSchema: schema };
  for (const document of [[tool], { tools: [tool] }, { jsonrpc: "2.0", result: { tools: [tool] } }]) {
    assert.equal(buildReport(document).toolCount, 1);
  }
});

test("reports field bytes, repeated strings, and largest declarations deterministically", () => {
  const repeated = 'This "operator-facing" explanation repeats a \\ path and newline.\n';
  const report = buildReport({
    tools: [
      {
        name: "small",
        description: repeated,
        inputSchema: schema,
      },
      {
        name: "large",
        description: repeated,
        inputSchema: {
          type: "object",
          properties: { query: { type: "string", description: "A sufficiently detailed query." } },
        },
      },
    ],
  });

  assert.equal(report.fieldValueBytes.descriptions, 2 * JSON.stringify(repeated).length);
  assert.equal(report.repeatedStrings[0].occurrences, 2);
  assert.equal(report.repeatedStrings[0].bytesEach, Buffer.byteLength(JSON.stringify(repeated)));
  assert.equal(report.repeatedStrings[0].preview, repeated);
  assert.equal(report.largestDeclarations[0].name, "large");
  assert.equal(report.estimatedTokensAtFourBytesPerToken, Math.ceil(report.toolsJsonBytes / 4));
});

test("detects repeated leading instructions and canonical output envelopes", () => {
  const instructions = "Use the server instructions once for every tool in this namespace.";
  const firstEnvelope = {
    type: "object",
    properties: { result: { type: "object" }, ok: { type: "boolean" } },
    required: ["ok", "result"],
  };
  const secondEnvelope = {
    required: ["result", "ok"],
    properties: { ok: { type: "boolean" }, result: { type: "object" } },
    type: "object",
  };
  const report = buildReport({
    tools: [
      {
        name: "alpha",
        description: `${instructions}\n\nAlpha's downstream description.`,
        inputSchema: schema,
        outputSchema: firstEnvelope,
      },
      {
        name: "beta",
        description: `${instructions}\n\nBeta's downstream description.`,
        inputSchema: schema,
        outputSchema: secondEnvelope,
      },
    ],
  });

  assert.deepEqual(report.repeatedDescriptionLeadingBlocks, [
    {
      occurrences: 2,
      bytesEach: Buffer.byteLength(instructions),
      repeatedBytes: Buffer.byteLength(instructions),
      preview: instructions,
      sampleTools: ["alpha", "beta"],
    },
  ]);
  assert.equal(report.repeatedOutputSchemas.length, 1);
  assert.equal(report.repeatedOutputSchemas[0].occurrences, 2);
  assert.deepEqual(report.repeatedOutputSchemas[0].sampleTools, ["alpha", "beta"]);
});

test("preserves order-sensitive schema arrays and instance values", () => {
  const report = buildReport({
    tools: [
      {
        name: "first",
        inputSchema: schema,
        outputSchema: {
          type: "array",
          prefixItems: [{ type: "string" }, { type: "number" }],
          const: { required: ["first", "second"] },
        },
      },
      {
        name: "second",
        inputSchema: schema,
        outputSchema: {
          const: { required: ["second", "first"] },
          prefixItems: [{ type: "number" }, { type: "string" }],
          type: "array",
        },
      },
    ],
  });

  assert.deepEqual(report.repeatedOutputSchemas, []);
});

test("normalizes required arrays in schemas whose map key looks like an instance keyword", () => {
  const outputSchema = (required) => ({
    type: "object",
    $defs: {
      default: {
        type: "object",
        properties: { first: { type: "string" }, second: { type: "string" } },
        required,
      },
    },
    properties: {
      const: {
        type: "object",
        properties: { first: { type: "string" }, second: { type: "string" } },
        required,
      },
    },
  });
  const report = buildReport({
    tools: [
      { name: "first", inputSchema: schema, outputSchema: outputSchema(["first", "second"]) },
      { name: "second", inputSchema: schema, outputSchema: outputSchema(["second", "first"]) },
    ],
  });

  assert.equal(report.repeatedOutputSchemas.length, 1);
});

test("preserves required arrays inside custom keyword data", () => {
  const outputSchema = (required) => ({
    type: "object",
    "x-contract": { required },
    properties: { value: { type: "string" } },
  });
  const report = buildReport({
    tools: [
      { name: "first", inputSchema: schema, outputSchema: outputSchema(["first", "second"]) },
      { name: "second", inputSchema: schema, outputSchema: outputSchema(["second", "first"]) },
    ],
  });

  assert.deepEqual(report.repeatedOutputSchemas, []);
});

test("rejects malformed tool records", () => {
  assert.throws(() => buildReport({ tools: [{ name: "missing-schema" }] }), /inputSchema/);
});

test("equal-cost rows use locale-independent code-unit ordering", () => {
  const upper = "Z-prefixed repeated explanation with equal encoded size.";
  const lower = "a-prefixed repeated explanation with equal encoded size.";
  const report = buildReport({
    tools: [
      { name: "a1", description: lower, inputSchema: schema },
      { name: "Z2", description: upper, inputSchema: schema },
      { name: "a2", description: lower, inputSchema: schema },
      { name: "Z1", description: upper, inputSchema: schema },
    ],
  });

  assert.deepEqual(
    report.largestDeclarations.map((item) => item.name),
    ["Z1", "Z2", "a1", "a2"],
  );
  assert.deepEqual(
    report.repeatedStrings.map((item) => item.preview),
    [upper, lower],
  );
});

test("long repeated strings sort by their full value before preview projection", () => {
  const sharedPrefix = "x".repeat(117);
  const shorter = `${sharedPrefix}A${"a".repeat(30)}`;
  const longer = `${sharedPrefix}B${"b".repeat(180)}`;
  const tools = [
    { name: "short-1", description: shorter, inputSchema: schema },
    { name: "long-1", description: longer, inputSchema: schema },
    { name: "short-2", description: shorter, inputSchema: schema },
    { name: "long-2", description: longer, inputSchema: schema },
    { name: "short-3", description: shorter, inputSchema: schema },
  ];

  const forward = buildReport({ tools }).repeatedStrings;
  const reversed = buildReport({ tools: [...tools].reverse() }).repeatedStrings;
  assert.deepEqual(forward, reversed);
  assert.equal(forward[0].preview, forward[1].preview);
  assert.equal(forward[0].occurrences, 3);
  assert.equal(forward[1].occurrences, 2);
});

test("the checked-in standard fixture and CLI produce the complete baseline", () => {
  const fixturePath = join(scriptDirectory, "fixtures/tool-context/standard-tools-list.json");
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
  const expected = {
    formatVersion: 2,
    toolCount: 3,
    toolsJsonBytes: 1392,
    estimatedTokensAtFourBytesPerToken: 348,
    fieldValueBytes: {
      names: 63,
      titles: 47,
      descriptions: 138,
      inputSchemas: 581,
      outputSchemas: 87,
      annotations: 267,
      meta: 0,
    },
    repeatedStringBytes: 0,
    repeatedStrings: [],
    repeatedDescriptionLeadingBlockBytes: 0,
    repeatedDescriptionLeadingBlocks: [],
    repeatedOutputSchemaBytes: 0,
    repeatedOutputSchemas: [],
    largestDeclarations: [
      { name: "demo-m.send_message", bytes: 524 },
      { name: "demo-o.query_range", bytes: 524 },
      { name: "demo-m.list_contacts", bytes: 340 },
    ],
  };

  assert.deepEqual(buildReport(fixture), expected);
  const cliReport = JSON.parse(
    execFileSync(process.execPath, [join(scriptDirectory, "report-tool-context.mjs"), fixturePath], {
      encoding: "utf8",
    }),
  );
  assert.deepEqual(cliReport, expected);
});

test("a budget reports every material regression", () => {
  const fixturePath = join(scriptDirectory, "fixtures/tool-context/standard-tools-list.json");
  const report = buildReport(JSON.parse(readFileSync(fixturePath, "utf8")));
  const budget = {
    formatVersion: 1,
    reportFormatVersion: report.formatVersion,
    expectedToolCount: report.toolCount,
    maximums: {
      toolsJsonBytes: report.toolsJsonBytes,
      "fieldValueBytes.names": report.fieldValueBytes.names,
      "fieldValueBytes.titles": report.fieldValueBytes.titles,
      "fieldValueBytes.descriptions": report.fieldValueBytes.descriptions,
      "fieldValueBytes.inputSchemas": report.fieldValueBytes.inputSchemas,
      "fieldValueBytes.outputSchemas": report.fieldValueBytes.outputSchemas,
      "fieldValueBytes.annotations": report.fieldValueBytes.annotations,
      "fieldValueBytes.meta": report.fieldValueBytes.meta,
      repeatedStringBytes: report.repeatedStringBytes,
      repeatedDescriptionLeadingBlockBytes: report.repeatedDescriptionLeadingBlockBytes,
      repeatedOutputSchemaBytes: report.repeatedOutputSchemaBytes,
      largestDeclarationBytes: report.largestDeclarations[0].bytes,
    },
  };
  const regressed = structuredClone(report);
  regressed.toolCount += 1;
  regressed.toolsJsonBytes += 1;
  regressed.fieldValueBytes.descriptions += 1;
  regressed.repeatedDescriptionLeadingBlockBytes += 1;
  regressed.largestDeclarations[0].bytes += 1;

  assert.deepEqual(budgetViolations(regressed, budget), [
    "toolCount: 4 does not match expected 3",
    "toolsJsonBytes: 1393 exceeds maximum 1392",
    "fieldValueBytes.descriptions: 139 exceeds maximum 138",
    "repeatedDescriptionLeadingBlockBytes: 1 exceeds maximum 0",
    "largestDeclarationBytes: 525 exceeds maximum 524",
  ]);
});

test("the CLI rejects partial and unsafe --top values", () => {
  const fixturePath = join(scriptDirectory, "fixtures/tool-context/standard-tools-list.json");
  const scriptPath = join(scriptDirectory, "report-tool-context.mjs");
  for (const value of ["2junk", "1.5", "0", "9007199254740992"]) {
    const attempt = spawnSync(process.execPath, [scriptPath, "--top", value, fixturePath], {
      encoding: "utf8",
    });
    assert.notEqual(attempt.status, 0, `--top ${value} must fail`);
    assert.match(attempt.stderr, /--top must be a positive integer/);
  }
});

test("the CLI reads a standard capture from stdin", () => {
  const fixturePath = join(scriptDirectory, "fixtures/tool-context/standard-tools-list.json");
  const scriptPath = join(scriptDirectory, "report-tool-context.mjs");
  const fixture = readFileSync(fixturePath, "utf8");
  const expected = buildReport(JSON.parse(fixture));
  const actual = JSON.parse(
    execFileSync(process.execPath, [scriptPath, "-"], {encoding: "utf8", input: fixture}),
  );

  assert.deepEqual(actual, expected);
});
