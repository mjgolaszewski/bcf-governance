#!/usr/bin/env node
/** Independent TypeScript Compiler API ownership discovery.
 *
 * Copyright 2026 Michael Golaszewski.
 * Licensed under the MIT License.
 */

import { createRequire } from "node:module";
import path from "node:path";
import process from "node:process";
import { discoverEffects } from "./semantic_typescript_effects.mjs";

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
  const packageLock = path.resolve(repoRoot, argv[argv.indexOf("--package-lock") + 1]);
  const tracked = JSON.parse(argv[argv.indexOf("--tracked-files-json") + 1]).map((value) => path.resolve(repoRoot, value));
  return { repoRoot, tsconfig, files, packageLock, tracked };
}

function relative(repoRoot, value) {
  return path.relative(repoRoot, value).split(path.sep).join("/");
}

function nodeName(node, sourceFile) {
  if (ts.isConstructorDeclaration(node)) return "constructor";
  if (node === sourceFile) return "<module>";
  if (node.name && ts.isIdentifier(node.name)) return node.name.text;
  if (ts.isVariableDeclaration(node.parent) && ts.isIdentifier(node.parent.name)) {
    return node.parent.name.text;
  }
  return `<anonymous@${sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1}:${node.getStart()}>`;
}

function functionIdentity(node, repoRoot, sourceFile) {
  const names = [nodeName(node, sourceFile)];
  let current = node.parent;
  while (current && current !== sourceFile) {
    if ((ts.isClassDeclaration(current) || ts.isInterfaceDeclaration(current) || ts.isModuleDeclaration(current)) && current.name) names.unshift(current.name.text);
    else if (isFunctionLike(current)) names.unshift(nodeName(current, sourceFile));
    else if (ts.isObjectLiteralExpression(current) && ts.isVariableDeclaration(current.parent) && ts.isIdentifier(current.parent.name)) names.unshift(current.parent.name.text);
    current = current.parent;
  }
  return `${relative(repoRoot, sourceFile.fileName)}::${names.join(".")}`;
}

function declarationIdentity(declaration, repoRoot) {
  if (ts.isVariableDeclaration(declaration) && declaration.initializer && isFunctionLike(declaration.initializer)) declaration = declaration.initializer;
  return functionIdentity(declaration, repoRoot, declaration.getSourceFile());
}

function resolvedDeclaration(checker, expression, seen = new Set()) {
  let symbol = checker.getSymbolAtLocation(expression);
  if (symbol && (symbol.flags & ts.SymbolFlags.Alias)) symbol = checker.getAliasedSymbol(symbol);
  const declaration = symbol?.declarations?.find((value) => isFunctionLike(value) && value.body) ?? symbol?.valueDeclaration ?? symbol?.declarations?.[0];
  if (!declaration || seen.has(declaration)) return declaration;
  seen.add(declaration);
  if (ts.isVariableDeclaration(declaration) && declaration.initializer
      && (declaration.parent.flags & ts.NodeFlags.Const)
      && (ts.isIdentifier(declaration.initializer) || ts.isPropertyAccessExpression(declaration.initializer))) {
    return resolvedDeclaration(checker, declaration.initializer, seen) ?? declaration;
  }
  return declaration;
}

function symbolIdentity(checker, expression, repoRoot, sourceFile) {
  const declaration = resolvedDeclaration(checker, expression);
  return declaration ? declarationIdentity(declaration, repoRoot)
    : `${relative(repoRoot, sourceFile.fileName)}::${expression.getText(sourceFile)}`;
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
    ts.isSetAccessorDeclaration(node) ||
    ts.isConstructorDeclaration(node)
  );
}

function discoverFunction(node, checker, repoRoot, sourceFile, sourceFiles, polymorphicClasses, standardLibraryRoot) {
  const caller = functionIdentity(node, repoRoot, sourceFile);
  const parameters = {};
  for (const parameter of node.parameters ?? []) {
    const name = parameter.name.getText(sourceFile);
    parameters[name] = checker.typeToString(checker.getTypeAtLocation(parameter));
  }
  const signature = isFunctionLike(node) ? checker.getSignatureFromDeclaration(node) : null;
  const returnType = signature
    ? checker.typeToString(checker.getReturnTypeOfSignature(signature))
    : "void";
  const facts = {
    symbol: ts.isClassDeclaration(node) ? `${caller}.constructor` : caller,
    language: "typescript",
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
  const effectFacts = discoverEffects({
    ts, checker, node, sourceFile, caller: facts.symbol,
    identity: (value) => declarationIdentity(value, repoRoot),
    functionLike: isFunctionLike, repoRoot, sourceFiles, polymorphicClasses, standardLibraryRoot,
    resolveDeclaration: (expression) => resolvedDeclaration(checker, expression),
  });
  // Enrich existing ownership call facts with the same dispatch identity used by effects.
  const ownershipCalls = facts.calls;
  facts.calls = effectFacts.calls.map((call) => ({
    ...ownershipCalls.find((row) => row.line === call.line && row.call_name === call.call_name), ...call,
  }));
  facts.effects = effectFacts.effects;
  facts.effect_unresolved = effectFacts.effect_unresolved;
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

function discoverPublicExports(sourceFile, checker, repoRoot) {
  const moduleSymbol = checker.getSymbolAtLocation(sourceFile);
  if (!moduleSymbol) return [];
  return checker.getExportsOfModule(moduleSymbol).map((exported) => {
    const name = exported.getName();
    const resolved = exported.flags & ts.SymbolFlags.Alias
      ? checker.getAliasedSymbol(exported)
      : exported;
    const original = resolved.valueDeclaration ?? resolved.declarations?.[0];
    const declaration = original?.name ? resolvedDeclaration(checker, original.name) : original;
    return {
      name,
      source: relative(repoRoot, sourceFile.fileName),
      callable: Boolean(declaration && (ts.isClassDeclaration(declaration) || checker.getTypeOfSymbolAtLocation(resolved, declaration).getCallSignatures().length)),
      symbol: `${relative(repoRoot, sourceFile.fileName)}::${name}`,
      declaration: declaration
        ? declarationIdentity(declaration, repoRoot) + (ts.isClassDeclaration(declaration) ? ".constructor" : "")
        : null,
    };
  }).sort((left, right) => left.name.localeCompare(right.name));
}

function main() {
  const { repoRoot, tsconfig, files, packageLock, tracked } = parseArguments(process.argv.slice(2));
  const require = createRequire(path.join(path.dirname(packageLock), "package.json"));
  try {
    ts = require("typescript");
  } catch (error) {
    throw new Error(`typescript compiler API unavailable: ${String(error)}`);
  }
  const configInputs = new Set([tsconfig, packageLock, require.resolve("typescript"), path.join(path.dirname(packageLock), "node_modules/typescript/package.json")]);
  const configHost = { ...ts.sys, readFile: (file) => {
    const text = ts.sys.readFile(file);
    if (text !== undefined) configInputs.add(path.resolve(file));
    return text;
  } };
  const configRead = ts.readConfigFile(tsconfig, configHost.readFile);
  if (configRead.error) {
    throw new Error(ts.flattenDiagnosticMessageText(configRead.error.messageText, " "));
  }
  const parsed = ts.parseJsonConfigFileContent(
    configRead.config,
    configHost,
    path.dirname(tsconfig),
    { noEmit: true },
    tsconfig,
  );
  if (parsed.errors.length > 0) {
    throw new Error(parsed.errors.map((value) => ts.flattenDiagnosticMessageText(value.messageText, " ")).join("; "));
  }
  const compilerHost = ts.createCompilerHost(parsed.options);
  const readFile = compilerHost.readFile.bind(compilerHost);
  compilerHost.readFile = (file) => {
    const text = readFile(file);
    if (text !== undefined && file.endsWith(".json")) configInputs.add(path.resolve(file));
    return text;
  };
  const program = ts.createProgram({
    rootNames: [...new Set([...files, ...parsed.fileNames.filter((file) => tracked.includes(path.resolve(file)))])],
    options: parsed.options,
    projectReferences: parsed.projectReferences,
    host: compilerHost,
  });
  const checker = program.getTypeChecker();
  const standardLibraryRoot = path.dirname(ts.getDefaultLibFilePath(parsed.options));
  const functions = [];
  const types = [];
  const endpointContracts = [];
  const publicExports = [];
  const selectedFiles = new Set();
  for (const file of program.getSourceFiles()) {
    const absolute = path.resolve(file.fileName);
    if (absolute.includes(`${path.sep}node_modules${path.sep}`)) { configInputs.add(absolute); continue; }
    if (!tracked.includes(absolute)) throw new Error(`compiler source is not a tracked repository file: ${relative(repoRoot, absolute)}`);
    selectedFiles.add(absolute);
  }
  const polymorphicClasses = new Set();
  for (const sourceFile of program.getSourceFiles()) {
    if (!selectedFiles.has(path.resolve(sourceFile.fileName))) continue;
    function visit(node) {
      if (ts.isClassDeclaration(node)) for (const clause of node.heritageClauses ?? []) {
        if (clause.token !== ts.SyntaxKind.ExtendsKeyword) continue;
        polymorphicClasses.add(declarationIdentity(node, repoRoot));
        for (const type of clause.types) {
          const base = resolvedDeclaration(checker, type.expression);
          if (base) polymorphicClasses.add(declarationIdentity(base, repoRoot));
        }
      }
      ts.forEachChild(node, visit);
    }
    visit(sourceFile);
  }
  for (const sourceFile of program.getSourceFiles()) {
    if (!selectedFiles.has(path.resolve(sourceFile.fileName))) continue;
    function visit(node) {
      if (isFunctionLike(node) && node.body) functions.push(discoverFunction(node, checker, repoRoot, sourceFile, selectedFiles, polymorphicClasses, standardLibraryRoot));
      if ((ts.isClassDeclaration(node) || ts.isInterfaceDeclaration(node) || ts.isTypeAliasDeclaration(node)) && node.name) types.push(declarationIdentity(node, repoRoot));
      if (ts.isClassDeclaration(node) && !node.members.some(ts.isConstructorDeclaration)) functions.push(discoverFunction(node, checker, repoRoot, sourceFile, selectedFiles, polymorphicClasses, standardLibraryRoot));
      ts.forEachChild(node, visit);
    }
    visit(sourceFile);
    functions.push(discoverFunction(sourceFile, checker, repoRoot, sourceFile, selectedFiles, polymorphicClasses, standardLibraryRoot));
    endpointContracts.push(...discoverEndpointContracts(sourceFile, checker, repoRoot));
    publicExports.push(...discoverPublicExports(sourceFile, checker, repoRoot));
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
    files: [...selectedFiles].map((value) => relative(repoRoot, value)).sort(),
    compiler_inputs: [...configInputs].map((value) => relative(repoRoot, value)).sort(),
    types: types.sort(),
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
    public_exports: publicExports,
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
