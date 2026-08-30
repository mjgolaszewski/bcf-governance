#!/usr/bin/env node
/** Independent TypeScript Compiler API ownership discovery.
 *
 * Copyright 2026 Michael Golaszewski.
 * Licensed under the MIT License.
 */

import { createRequire } from "node:module";
import path from "node:path";
import process from "node:process";

let ts;

const NORMALIZERS = new Set([
  "filter",
  "join",
  "map",
  "normalize",
  "replace",
  "split",
  "toLocaleLowerCase",
  "toLocaleUpperCase",
  "toLowerCase",
  "toUpperCase",
  "trim",
  "trimEnd",
  "trimStart",
]);
const SINK_PATTERN = /^_?(activate|authorize|cache|commit|dispatch|enqueue|lease|persist|publish|save|send|store|write)(?:_|[A-Z]|$)/;
const DECODER_PATTERN = /(decode|parse|validate|assert|fromResponse|fromJson)/i;
const HTTP_TRANSPORT_NAMES = new Set([
  "apiDelete",
  "apiGet",
  "apiPatch",
  "apiPost",
  "apiPut",
  "fetch",
  "fetchFn",
  "getJson",
  "postJson",
  "requestForm",
  "requestJson",
  "requestPayload",
]);

function parseArguments(argv) {
  const marker = argv.indexOf("--repo-root");
  if (marker < 0 || !argv[marker + 1]) {
    throw new Error("--repo-root is required");
  }
  const repoRoot = path.resolve(argv[marker + 1]);
  const tsconfigMarker = argv.indexOf("--tsconfig");
  const filesMarker = argv.indexOf("--files");
  if (tsconfigMarker < 0 || !argv[tsconfigMarker + 1]) {
    throw new Error("--tsconfig is required");
  }
  if (filesMarker < 0) throw new Error("--files is required");
  const tsconfig = path.resolve(repoRoot, argv[tsconfigMarker + 1]);
  const files = argv.slice(filesMarker + 1).map((value) => path.resolve(value));
  if (files.length === 0) {
    throw new Error("at least one TypeScript source file is required");
  }
  return { repoRoot, tsconfig, files };
}

function relative(repoRoot, value) {
  return path.relative(repoRoot, value).split(path.sep).join("/");
}

function nodeName(node, sourceFile) {
  if (node.name && ts.isIdentifier(node.name)) return node.name.text;
  if (ts.isVariableDeclaration(node.parent) && ts.isIdentifier(node.parent.name)) {
    return node.parent.name.text;
  }
  return `<anonymous@${sourceFile.getLineAndCharacterOfPosition(node.pos).line + 1}>`;
}

function functionIdentity(node, repoRoot, sourceFile) {
  const names = [nodeName(node, sourceFile)];
  let current = node.parent;
  while (current && current !== sourceFile) {
    if (ts.isClassDeclaration(current) && current.name) names.unshift(current.name.text);
    current = current.parent;
  }
  return `${relative(repoRoot, sourceFile.fileName)}::${names.join(".")}`;
}

function symbolIdentity(checker, expression, repoRoot, sourceFile) {
  let symbol = checker.getSymbolAtLocation(expression);
  if (symbol && (symbol.flags & ts.SymbolFlags.Alias)) {
    symbol = checker.getAliasedSymbol(symbol);
  }
  const declaration = symbol?.valueDeclaration ?? symbol?.declarations?.[0];
  if (symbol && declaration) {
    return `${relative(repoRoot, declaration.getSourceFile().fileName)}::${checker.symbolToString(symbol)}`;
  }
  return `${relative(repoRoot, sourceFile.fileName)}::${expression.getText(sourceFile)}`;
}

function rootIdentifier(node) {
  let current = node;
  while (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current)) {
    current = current.expression;
  }
  return ts.isIdentifier(current) ? current.text : null;
}

function stringLiteral(node) {
  return ts.isStringLiteralLike(node) || ts.isNoSubstitutionTemplateLiteral(node)
    ? node.text
    : null;
}

function endpointLiteral(node) {
  const literal = stringLiteral(node);
  if (literal !== null) return literal.split("?", 1)[0];
  if (ts.isTemplateExpression(node)) {
    const prefix = node.head.text.split("?", 1)[0];
    return prefix.startsWith("/") && prefix.includes("/") ? prefix : null;
  }
  return null;
}

function isFunctionLike(node) {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isGetAccessorDeclaration(node) ||
    ts.isSetAccessorDeclaration(node)
  );
}

function discoverFunction(node, checker, repoRoot, sourceFile) {
  const caller = functionIdentity(node, repoRoot, sourceFile);
  const parameters = {};
  for (const parameter of node.parameters) {
    const name = parameter.name.getText(sourceFile);
    parameters[name] = checker.typeToString(checker.getTypeAtLocation(parameter));
  }
  const signature = checker.getSignatureFromDeclaration(node);
  const returnType = signature
    ? checker.typeToString(checker.getReturnTypeOfSignature(signature))
    : "unresolved";
  const facts = {
    symbol: caller,
    parameters,
    return_type: returnType,
    owner_shape: Object.values(parameters).every((value) => /^(string|number|boolean|Uint8Array|unknown)$/.test(value))
      ? "hostile_decoder"
      : "controlled_value_consumer",
    calls: [],
    constructors: [],
    normalizations: [],
    sinks: [],
    unresolved: [],
    fetches: [],
    endpoint_calls: [],
    decoder_calls: [],
  };
  for (const [field, typeName] of Object.entries({ ...parameters, return: returnType })) {
    if (/\b(any|unknown|object|Record<string, unknown>)\b/.test(typeName)) {
      facts.unresolved.push({
        language: "typescript",
        kind: "generic_type",
        symbol: caller,
        field,
        type: typeName,
        blockers: [typeName],
      });
    }
  }

  function visit(current) {
    if (current !== node && isFunctionLike(current)) return;
    if (ts.isNewExpression(current)) {
      const constructed = symbolIdentity(checker, current.expression, repoRoot, sourceFile);
      facts.constructors.push({
        language: "typescript",
        caller,
        constructed_symbol: constructed,
        line: sourceFile.getLineAndCharacterOfPosition(current.getStart()).line + 1,
        argument_types: (current.arguments ?? []).map((argument) =>
          checker.typeToString(checker.getTypeAtLocation(argument)),
        ),
      });
    }
    if (ts.isCallExpression(current)) {
      const called = symbolIdentity(checker, current.expression, repoRoot, sourceFile);
      const name = ts.isPropertyAccessExpression(current.expression)
        ? current.expression.name.text
        : current.expression.getText(sourceFile);
      const line = sourceFile.getLineAndCharacterOfPosition(current.getStart()).line + 1;
      const flowType = checker.typeToString(checker.getTypeAtLocation(current));
      const fact = {
        language: "typescript",
        caller,
        called_symbol: called,
        call_name: name,
        line,
        control_flow_type: flowType,
        union_variants: checker.getTypeAtLocation(current).isUnion()
          ? checker.getTypeAtLocation(current).types.map((value) => checker.typeToString(value))
          : [],
        argument_types: current.arguments.map((argument) =>
          checker.typeToString(checker.getTypeAtLocation(argument)),
        ),
      };
      facts.calls.push(fact);
      if (ts.isPropertyAccessExpression(current.expression) && NORMALIZERS.has(name)) {
        const root = rootIdentifier(current.expression.expression);
        facts.normalizations.push({
          ...fact,
          receiver_root: root,
          receiver_type: checker.typeToString(checker.getTypeAtLocation(current.expression.expression)),
          receiver_annotation: root !== null ? parameters[root] ?? null : null,
          downstream_of_parameter: root !== null && Object.hasOwn(parameters, root),
        });
      }
      if (SINK_PATTERN.test(name)) facts.sinks.push({ ...fact, sink_kind: name });
      if (HTTP_TRANSPORT_NAMES.has(name) && current.arguments.length > 0) {
        const endpoint = endpointLiteral(current.arguments[0]);
        if (endpoint !== null) {
          const endpointCall = {
            endpoint,
            caller,
            line,
            transport_name: name,
            transport_symbol: called,
          };
          facts.endpoint_calls.push(endpointCall);
          if (name === "fetch" || name === "fetchFn") {
            facts.fetches.push(endpointCall);
          }
        }
      }
      if (DECODER_PATTERN.test(name)) facts.decoder_calls.push({ symbol: called, caller, line });
      if (name === "JSON.parse" || name === "eval" || name === "Function") {
        facts.unresolved.push({
          language: "typescript",
          kind: "opaque_deserializer_or_dynamic_call",
          symbol: caller,
          called_symbol: called,
          line,
          blockers: [name],
        });
      }
    }
    ts.forEachChild(current, visit);
  }
  if (node.body) visit(node.body);
  return facts;
}

function discoverEndpointContracts(sourceFile, checker, repoRoot) {
  const contracts = [];
  function visit(node) {
    if (
      ts.isPropertySignature(node)
      && (ts.isStringLiteral(node.name) || ts.isNoSubstitutionTemplateLiteral(node.name))
    ) {
      const match = /^(GET|POST|PUT|PATCH|DELETE) (\/[^\s]+)$/.exec(node.name.text);
      if (match) {
        contracts.push({
          method: match[1],
          endpoint: match[2],
          response_type: checker.typeToString(checker.getTypeAtLocation(node)),
          symbol: `${relative(repoRoot, sourceFile.fileName)}::${node.name.text}`,
          line: sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1,
        });
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);
  return contracts;
}

function main() {
  const { repoRoot, tsconfig, files } = parseArguments(process.argv.slice(2));
  const require = createRequire(path.join(repoRoot, "package.json"));
  try {
    ts = require("typescript");
  } catch (error) {
    throw new Error(`typescript compiler API unavailable: ${String(error)}`);
  }
  const configRead = ts.readConfigFile(tsconfig, ts.sys.readFile);
  if (configRead.error) {
    throw new Error(ts.flattenDiagnosticMessageText(configRead.error.messageText, " "));
  }
  const parsed = ts.parseJsonConfigFileContent(
    configRead.config,
    ts.sys,
    path.dirname(tsconfig),
    { noEmit: true },
    tsconfig,
  );
  if (parsed.errors.length > 0) {
    throw new Error(parsed.errors.map((value) => ts.flattenDiagnosticMessageText(value.messageText, " ")).join("; "));
  }
  const program = ts.createProgram({
    rootNames: files,
    options: parsed.options,
    projectReferences: parsed.projectReferences,
  });
  const checker = program.getTypeChecker();
  const functions = [];
  const endpointContracts = [];
  const selectedFiles = new Set(files.map((value) => path.resolve(value)));
  for (const sourceFile of program.getSourceFiles()) {
    if (!selectedFiles.has(path.resolve(sourceFile.fileName))) continue;
    function visit(node) {
      if (isFunctionLike(node)) functions.push(discoverFunction(node, checker, repoRoot, sourceFile));
      ts.forEachChild(node, visit);
    }
    visit(sourceFile);
    endpointContracts.push(...discoverEndpointContracts(sourceFile, checker, repoRoot));
  }
  const diagnostics = ts.getPreEmitDiagnostics(program).map((diagnostic) => ({
    path: diagnostic.file ? relative(repoRoot, diagnostic.file.fileName) : "<compiler>",
    line: diagnostic.file && diagnostic.start !== undefined
      ? diagnostic.file.getLineAndCharacterOfPosition(diagnostic.start).line + 1
      : 0,
    code: diagnostic.code,
    message: ts.flattenDiagnosticMessageText(diagnostic.messageText, " "),
  }));
  if (diagnostics.length > 0) {
    throw new Error(`TypeScript project has ${diagnostics.length} compiler diagnostic(s): ${JSON.stringify(diagnostics.slice(0, 5))}`);
  }
  const payload = {
    language: "typescript",
    node_version: process.version,
    compiler_version: ts.version,
    files: files.map((value) => relative(repoRoot, value)).sort(),
    functions,
    constructors: functions.flatMap((value) => value.constructors),
    codecs: functions
      .filter((value) => DECODER_PATTERN.test(value.symbol.split("::").at(-1)))
      .map((value) => ({ symbol: value.symbol, return_type: value.return_type })),
    translations: functions
      .filter((value) => /(translate|project|toProtocol|toPayload)/i.test(value.symbol.split("::").at(-1)))
      .map((value) => ({ symbol: value.symbol, return_type: value.return_type })),
    normalizations: functions.flatMap((value) => value.normalizations),
    sinks: functions.flatMap((value) => value.sinks),
    unresolved: functions.flatMap((value) => value.unresolved),
    fetches: functions.flatMap((value) => value.fetches),
    endpoint_calls: functions.flatMap((value) => value.endpoint_calls),
    decoder_calls: functions.flatMap((value) => value.decoder_calls),
    endpoint_contracts: endpointContracts,
    diagnostics,
  };
  process.stdout.write(`${JSON.stringify(payload)}\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`semantic TypeScript discovery failed: ${String(error)}\n`);
  process.exit(2);
}
