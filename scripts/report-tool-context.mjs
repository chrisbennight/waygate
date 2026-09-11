#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import process from "node:process";

const MIN_REPEATED_STRING_BYTES = 24;
const MIN_REPEATED_DESCRIPTION_BLOCK_BYTES = 24;
const MIN_REPEATED_OUTPUT_SCHEMA_BYTES = 24;
const DEFAULT_TOP = 10;
const SAMPLE_TOOL_NAMES = 5;

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

function usage() {
  return `usage: node scripts/report-tool-context.mjs [--top N] [--budget budget.json] <tools-list.json|->

Accepts a standard MCP tools/list JSON-RPC response, a bare {"tools": [...]}
result, or a bare tool array. Prints a deterministic JSON context-cost report.
Use '-' to read stdin. A budget fails when the capture exceeds a checked-in
maximum or no longer has the budget's expected tool count.`;
}

const BUDGET_FORMAT_VERSION = 1;
const BUDGET_MEASURES = new Map([
  ["toolsJsonBytes", (report) => report.toolsJsonBytes],
  ["fieldValueBytes.names", (report) => report.fieldValueBytes.names],
  ["fieldValueBytes.titles", (report) => report.fieldValueBytes.titles],
  ["fieldValueBytes.descriptions", (report) => report.fieldValueBytes.descriptions],
  ["fieldValueBytes.inputSchemas", (report) => report.fieldValueBytes.inputSchemas],
  ["fieldValueBytes.outputSchemas", (report) => report.fieldValueBytes.outputSchemas],
  ["fieldValueBytes.annotations", (report) => report.fieldValueBytes.annotations],
  ["fieldValueBytes.meta", (report) => report.fieldValueBytes.meta],
  ["repeatedStringBytes", (report) => report.repeatedStringBytes],
  [
    "repeatedDescriptionLeadingBlockBytes",
    (report) => report.repeatedDescriptionLeadingBlockBytes,
  ],
  ["repeatedOutputSchemaBytes", (report) => report.repeatedOutputSchemaBytes],
  ["largestDeclarationBytes", (report) => report.largestDeclarations[0]?.bytes ?? 0],
]);

function byteLength(value) {
  if (value === undefined) return 0;
  return Buffer.byteLength(JSON.stringify(value), "utf8");
}

function toolsFrom(document) {
  const candidates = [document?.result?.tools, document?.tools, document];
  const tools = candidates.find(Array.isArray);
  if (!tools) {
    throw new Error(
      "input must be a tools/list JSON-RPC response, a {tools: [...]} result, or a tool array",
    );
  }
  for (const [index, tool] of tools.entries()) {
    if (!tool || typeof tool !== "object" || Array.isArray(tool)) {
      throw new Error(`tools[${index}] must be an object`);
    }
    if (typeof tool.name !== "string" || tool.name.length === 0) {
      throw new Error(`tools[${index}].name must be a non-empty string`);
    }
    if (!tool.inputSchema || typeof tool.inputSchema !== "object") {
      throw new Error(`tools[${index}].inputSchema must be an object`);
    }
  }
  return tools;
}

function collectStrings(value, counts) {
  if (typeof value === "string") {
    const bytes = byteLength(value);
    if (bytes >= MIN_REPEATED_STRING_BYTES) {
      const current = counts.get(value) ?? { count: 0, bytes };
      current.count += 1;
      counts.set(value, current);
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, counts);
    return;
  }
  if (value && typeof value === "object") {
    for (const item of Object.values(value)) collectStrings(item, counts);
  }
}

const SINGLE_SCHEMA_KEYWORDS = new Set([
  "additionalItems",
  "additionalProperties",
  "contains",
  "contentSchema",
  "else",
  "if",
  "items",
  "not",
  "propertyNames",
  "then",
  "unevaluatedItems",
  "unevaluatedProperties",
]);
const SCHEMA_ARRAY_KEYWORDS = new Set(["allOf", "anyOf", "oneOf", "prefixItems"]);
const SCHEMA_MAP_KEYWORDS = new Set([
  "$defs",
  "definitions",
  "dependentSchemas",
  "patternProperties",
  "properties",
]);

function canonicalizeValue(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalizeValue);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort(compareStrings)
        .map((key) => [key, canonicalizeValue(value[key])]),
    );
  }
  return value;
}

function canonicalizeSchemaMap(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return canonicalizeValue(value);
  }
  return Object.fromEntries(
    Object.keys(value)
      .sort(compareStrings)
      .map((key) => [key, canonicalizeSchema(value[key])]),
  );
}

function canonicalizeDependencies(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return canonicalizeValue(value);
  }
  return Object.fromEntries(
    Object.keys(value)
      .sort(compareStrings)
      .map((key) => [
        key,
        Array.isArray(value[key])
          ? canonicalizeValue(value[key])
          : canonicalizeSchema(value[key]),
      ]),
  );
}

function canonicalizeSchema(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return canonicalizeValue(value);
  }
  return Object.fromEntries(
    Object.keys(value)
      .sort(compareStrings)
      .map((key) => {
        const child = value[key];
        if (key === "required" && Array.isArray(child) && child.every((item) => typeof item === "string")) {
          return [key, [...child].sort(compareStrings)];
        }
        if (SINGLE_SCHEMA_KEYWORDS.has(key)) return [key, canonicalizeSchema(child)];
        if (SCHEMA_ARRAY_KEYWORDS.has(key) && Array.isArray(child)) {
          return [key, child.map(canonicalizeSchema)];
        }
        if (SCHEMA_MAP_KEYWORDS.has(key)) return [key, canonicalizeSchemaMap(child)];
        if (key === "dependencies") return [key, canonicalizeDependencies(child)];
        return [key, canonicalizeValue(child)];
      }),
  );
}

function leadingDescriptionBlock(description) {
  if (typeof description !== "string") return undefined;
  const [block] = description.trim().split(/\r?\n\s*\r?\n/, 1);
  if (Buffer.byteLength(block, "utf8") < MIN_REPEATED_DESCRIPTION_BLOCK_BYTES) {
    return undefined;
  }
  return block;
}

function preview(value) {
  return value.length <= 120 ? value : `${value.slice(0, 117)}...`;
}

function compareStrings(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function repeatedValues(items) {
  const counts = new Map();
  for (const item of items) {
    const current = counts.get(item.key) ?? {
      occurrences: 0,
      bytesEach: item.bytes,
      preview: item.preview,
      tools: [],
    };
    current.occurrences += 1;
    current.tools.push(item.tool);
    counts.set(item.key, current);
  }
  return [...counts.entries()]
    .filter(([, item]) => item.occurrences > 1)
    .sort(
      ([leftKey, left], [rightKey, right]) =>
        right.bytesEach * (right.occurrences - 1) -
          left.bytesEach * (left.occurrences - 1) || compareStrings(leftKey, rightKey),
    )
    .map(([, item]) => ({
      occurrences: item.occurrences,
      bytesEach: item.bytesEach,
      repeatedBytes: item.bytesEach * (item.occurrences - 1),
      preview: item.preview,
      sampleTools: item.tools.sort(compareStrings).slice(0, SAMPLE_TOOL_NAMES),
    }));
}

export function buildReport(document, top = DEFAULT_TOP) {
  const tools = toolsFrom(document);
  const stringCounts = new Map();
  collectStrings(tools, stringCounts);

  const declarations = tools
    .map((tool) => ({ name: tool.name, bytes: byteLength(tool) }))
    .sort((left, right) => right.bytes - left.bytes || compareStrings(left.name, right.name));
  const repeatedStrings = [...stringCounts.entries()]
    .filter(([, item]) => item.count > 1)
    .sort(
      ([leftValue, left], [rightValue, right]) =>
        right.bytes * (right.count - 1) - left.bytes * (left.count - 1) ||
        compareStrings(leftValue, rightValue),
    )
    .map(([value, item]) => ({
      occurrences: item.count,
      bytesEach: item.bytes,
      repeatedBytes: item.bytes * (item.count - 1),
      preview: preview(value),
    }));
  const repeatedDescriptionLeadingBlocks = repeatedValues(
    tools.flatMap((tool) => {
      const block = leadingDescriptionBlock(tool.description);
      if (block === undefined) return [];
      return [{
        key: block,
        bytes: Buffer.byteLength(block, "utf8"),
        preview: preview(block),
        tool: tool.name,
      }];
    }),
  );
  const repeatedOutputSchemas = repeatedValues(
    tools.flatMap((tool) => {
      if (tool.outputSchema === undefined) return [];
      const canonical = JSON.stringify(canonicalizeSchema(tool.outputSchema));
      const bytes = Buffer.byteLength(canonical, "utf8");
      if (bytes < MIN_REPEATED_OUTPUT_SCHEMA_BYTES) return [];
      return [{ key: canonical, bytes, preview: preview(canonical), tool: tool.name }];
    }),
  );

  const toolsJsonBytes = byteLength(tools);
  const fieldValueBytes = {
    names: tools.reduce((sum, tool) => sum + byteLength(tool.name), 0),
    titles: tools.reduce(
      (sum, tool) => sum + byteLength(tool.title ?? tool.annotations?.title),
      0,
    ),
    descriptions: tools.reduce((sum, tool) => sum + byteLength(tool.description), 0),
    inputSchemas: tools.reduce((sum, tool) => sum + byteLength(tool.inputSchema), 0),
    outputSchemas: tools.reduce((sum, tool) => sum + byteLength(tool.outputSchema), 0),
    annotations: tools.reduce((sum, tool) => sum + byteLength(tool.annotations), 0),
    meta: tools.reduce((sum, tool) => sum + byteLength(tool._meta), 0),
  };

  return {
    formatVersion: 2,
    toolCount: tools.length,
    toolsJsonBytes,
    estimatedTokensAtFourBytesPerToken: Math.ceil(toolsJsonBytes / 4),
    fieldValueBytes,
    repeatedStringBytes: repeatedStrings.reduce((sum, item) => sum + item.repeatedBytes, 0),
    repeatedStrings: repeatedStrings.slice(0, top),
    repeatedDescriptionLeadingBlockBytes: repeatedDescriptionLeadingBlocks.reduce(
      (sum, item) => sum + item.repeatedBytes,
      0,
    ),
    repeatedDescriptionLeadingBlocks: repeatedDescriptionLeadingBlocks.slice(0, top),
    repeatedOutputSchemaBytes: repeatedOutputSchemas.reduce(
      (sum, item) => sum + item.repeatedBytes,
      0,
    ),
    repeatedOutputSchemas: repeatedOutputSchemas.slice(0, top),
    largestDeclarations: declarations.slice(0, top),
  };
}

export function budgetViolations(report, budget) {
  if (!budget || typeof budget !== "object" || Array.isArray(budget)) {
    throw new Error("budget must be an object");
  }
  if (budget.formatVersion !== BUDGET_FORMAT_VERSION) {
    throw new Error(`budget formatVersion must be ${BUDGET_FORMAT_VERSION}`);
  }
  if (budget.reportFormatVersion !== report.formatVersion) {
    throw new Error(
      `budget reportFormatVersion ${budget.reportFormatVersion} does not match report formatVersion ${report.formatVersion}`,
    );
  }
  if (!Number.isSafeInteger(budget.expectedToolCount) || budget.expectedToolCount < 0) {
    throw new Error("budget expectedToolCount must be a non-negative safe integer");
  }
  if (!budget.maximums || typeof budget.maximums !== "object" || Array.isArray(budget.maximums)) {
    throw new Error("budget maximums must be an object");
  }

  const provided = Object.keys(budget.maximums).sort(compareStrings);
  const expected = [...BUDGET_MEASURES.keys()].sort(compareStrings);
  if (JSON.stringify(provided) !== JSON.stringify(expected)) {
    throw new Error(`budget maximums must contain exactly: ${expected.join(", ")}`);
  }
  for (const [name, maximum] of Object.entries(budget.maximums)) {
    if (!Number.isSafeInteger(maximum) || maximum < 0) {
      throw new Error(`budget maximum ${name} must be a non-negative safe integer`);
    }
  }

  const violations = [];
  if (report.toolCount !== budget.expectedToolCount) {
    violations.push(
      `toolCount: ${report.toolCount} does not match expected ${budget.expectedToolCount}`,
    );
  }
  for (const [name, read] of BUDGET_MEASURES) {
    const actual = read(report);
    const maximum = budget.maximums[name];
    if (actual > maximum) violations.push(`${name}: ${actual} exceeds maximum ${maximum}`);
  }
  return violations;
}

async function main(args) {
  let top = DEFAULT_TOP;
  let budgetPath;
  let input;
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === "--top") {
      const raw = args[index + 1];
      if (!/^[1-9][0-9]*$/.test(raw ?? "")) throw new Error("--top must be a positive integer");
      const parsed = Number(raw);
      if (!Number.isSafeInteger(parsed)) throw new Error("--top must be a positive integer");
      top = parsed;
      index += 1;
    } else if (args[index] === "--budget") {
      const raw = args[index + 1];
      if (!raw || raw.startsWith("--")) throw new Error("--budget requires a JSON file path");
      budgetPath = raw;
      index += 1;
    } else if (args[index] === "--help" || args[index] === "-h") {
      process.stdout.write(`${usage()}\n`);
      return;
    } else if (input === undefined) {
      input = args[index];
    } else {
      throw new Error(`unexpected argument: ${args[index]}`);
    }
  }
  if (input === undefined) throw new Error(usage());

  const raw = input === "-" ? await readStdin() : await readFile(input, "utf8");
  const report = buildReport(JSON.parse(raw), top);
  if (budgetPath !== undefined) {
    const budget = JSON.parse(await readFile(budgetPath, "utf8"));
    const violations = budgetViolations(report, budget);
    if (violations.length > 0) {
      throw new Error(`context budget exceeded:\n- ${violations.join("\n- ")}`);
    }
  }
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`report-tool-context: ${error.message}\n`);
    process.exitCode = 1;
  });
}
