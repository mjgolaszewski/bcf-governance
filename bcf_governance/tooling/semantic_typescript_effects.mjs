/** Compiler-resolved JavaScript effects; unknown dispatch never implies purity. */
import path from "node:path";

const MUTATORS = new Set([
  "add", "set", "delete", "clear", "push", "pop", "shift", "unshift", "splice",
  "sort", "reverse", "copyWithin", "fill", "setItem", "removeItem",
]);
const PURE_METHODS = new Set([
  "at", "concat", "entries", "every", "filter", "find", "findIndex", "findLast",
  "flat", "flatMap", "forEach", "get", "has", "includes", "indexOf", "join",
  "keys", "lastIndexOf", "map", "reduce", "reduceRight", "slice", "some", "values",
  "charAt", "charCodeAt", "codePointAt", "endsWith", "match", "matchAll", "normalize",
  "padEnd", "padStart", "repeat", "replace", "replaceAll", "search", "split",
  "startsWith", "substring", "toLowerCase", "toUpperCase", "trim", "trimEnd",
  "trimStart", "toString", "valueOf", "toFixed", "toPrecision", "toExponential",
  "then", "catch", "finally", "resolve", "reject", "all", "allSettled", "race", "any",
  "isArray", "from", "of", "isFinite", "isInteger", "isNaN", "isSafeInteger",
  "parse", "stringify", "freeze", "seal", "isFrozen", "isSealed", "isExtensible",
  "getOwnPropertyNames", "getOwnPropertySymbols", "getOwnPropertyDescriptor",
  "getOwnPropertyDescriptors", "getPrototypeOf", "hasOwn", "getItem",
]);
const AUTHORITY = /^(approve|authorize|certify|grant|merge|publish|setStatus|set_status)(?:[A-Z_]|$)/;
const FS_WRITE = /^(appendFile|chmod|chown|copyFile|cp|createWriteStream|link|mkdir|mkdtemp|rename|rm|rmdir|symlink|truncate|unlink|utimes|write|writeFile)(Sync)?$/;
const PURE_CONSTRUCTORS = new Set(["Array", "Map", "Set", "WeakMap", "WeakSet", "Date", "URL", "URLSearchParams", "RegExp", "Object", "Error", "TypeError", "Uint8Array", "ArrayBuffer"]);
const CONTAINER_RESULTS = new Set(["map", "filter", "flat", "flatMap", "slice", "concat", "from", "of", "keys", "values", "entries", "resolve", "reject"]);

export function discoverEffects({ ts, checker, node, sourceFile, caller, identity, functionLike, repoRoot, sourceFiles, resolveDeclaration, polymorphicClasses, standardLibraryRoot }) {
  const calls = [], effects = [], unresolved = [];
  const local = new Set(), fresh = new Set();
  const position = (value) => sourceFile.getLineAndCharacterOfPosition(value.getStart()).line + 1;
  const declaration = resolveDeclaration;
  const binding = (value) => checker.getSymbolAtLocation(value)?.valueDeclaration;
  function unwrap(value) {
    while (value && (ts.isParenthesizedExpression(value) || ts.isAsExpression(value) || ts.isNonNullExpression(value) || ts.isTypeAssertionExpression(value))) value = value.expression;
    return value;
  }
  function freshValue(value) {
    value = unwrap(value);
    return Boolean(value && ((ts.isObjectLiteralExpression(value) && value.properties.every(ts.isPropertyAssignment)) || ts.isArrayLiteralExpression(value)
      || (ts.isNewExpression(value) && PURE_CONSTRUCTORS.has(value.expression.getText(sourceFile)) && standardDeclaration(declaration(value.expression)))
      || (ts.isIdentifier(value) && fresh.has(binding(value)))));
  }
  function primitive(value) {
    if (!value) return false;
    const type = checker.getTypeAtLocation(value);
    const allowed = ts.TypeFlags.StringLike | ts.TypeFlags.NumberLike | ts.TypeFlags.BooleanLike | ts.TypeFlags.Null | ts.TypeFlags.Undefined | ts.TypeFlags.BigIntLike | ts.TypeFlags.ESSymbolLike;
    return type.isUnion() ? type.types.every((item) => Boolean(item.flags & allowed)) : Boolean(type.flags & allowed);
  }
  const standardDeclaration = (value) => Boolean(value && path.dirname(path.resolve(value.getSourceFile().fileName)) === path.resolve(standardLibraryRoot) && /^lib\..+\.d\.ts$/.test(path.basename(value.getSourceFile().fileName)));
  function plainData(value, seen = new Set()) {
    value = unwrap(value);
    if (!value || seen.has(value)) return false;
    seen.add(value);
    if (primitive(value)) return true;
    if (ts.isIdentifier(value)) {
      const declared = binding(value);
      return declared && ts.isVariableDeclaration(declared) && (declared.parent.flags & ts.NodeFlags.Const) && plainData(declared.initializer, seen);
    }
    if (ts.isObjectLiteralExpression(value)) return value.properties.every((item) => (ts.isPropertyAssignment(item) || ts.isSpreadAssignment(item)) && plainData(ts.isSpreadAssignment(item) ? item.expression : item.initializer, new Set(seen)));
    if (ts.isArrayLiteralExpression(value)) return value.elements.every((item) => plainData(ts.isSpreadElement(item) ? item.expression : item, new Set(seen)));
    return false;
  }

  function localContainer(value, seen = new Set()) {
    value = unwrap(value);
    if (!value || seen.has(value)) return false;
    if (plainData(value)) return true;
    seen.add(value);
    if (ts.isIdentifier(value)) {
      const declared = binding(value);
      return declared && ts.isVariableDeclaration(declared) && (declared.parent.flags & ts.NodeFlags.Const) && localContainer(declared.initializer, seen);
    }
    if (ts.isNewExpression(value)) return standardDeclaration(declaration(value.expression)) && PURE_CONSTRUCTORS.has(value.expression.getText(sourceFile)) && (value.arguments ?? []).every(nativeArgument);
    if (ts.isCallExpression(value) && standardDeclaration(declaration(value.expression))) {
      const receiver = ts.isPropertyAccessExpression(value.expression) ? value.expression.expression : null;
      const name = ts.isPropertyAccessExpression(value.expression) ? value.expression.name.text : "";
      const container = CONTAINER_RESULTS.has(name) || (["assign", "freeze", "seal"].includes(name) && plainData(value.arguments[0]));
      return container && (receiver && (standardDeclaration(declaration(receiver)) || localContainer(receiver, seen))) && value.arguments.every(nativeArgument);
    }
    return false;
  }
  function nativeArgument(value) {
    if (ts.isSpreadElement(value)) return plainData(value.expression);
    if (ts.isRegularExpressionLiteral(value) || checker.getTypeAtLocation(value).getCallSignatures().length) return true;
    return plainData(value);
  }
  function nativePromise(value, seen = new Set()) {
    value = unwrap(value);
    if (!value || seen.has(value)) return false;
    seen.add(value);
    if (ts.isIdentifier(value)) {
      const declared = binding(value);
      return declared && ts.isVariableDeclaration(declared) && (declared.parent.flags & ts.NodeFlags.Const) && nativePromise(declared.initializer, seen);
    }
    if (!ts.isCallExpression(value) || !ts.isPropertyAccessExpression(value.expression)) return false;
    const expression = value.expression;
    return ["resolve", "reject"].includes(expression.name.text)
      && standardDeclaration(declaration(expression)) && standardDeclaration(declaration(expression.expression))
      && checker.getTypeAtLocation(expression.expression).getSymbol()?.getName() === "PromiseConstructor"
      && value.arguments.every((argument) => plainData(argument));
  }
  function provenReceiver(value, seen = new Set()) {
    value = unwrap(value);
    if (!value || seen.has(value)) return false;
    if (primitive(value) || localContainer(value) || standardDeclaration(declaration(value))) return true;
    const declaredSource = declaration(value);
    if (declaredSource && ts.isSourceFile(declaredSource) && sourceFiles.has(path.resolve(declaredSource.fileName))) return true;
    seen.add(value);
    if (ts.isIdentifier(value)) {
      const declared = binding(value);
      return declared && ts.isVariableDeclaration(declared) && (declared.parent.flags & ts.NodeFlags.Const) && provenReceiver(declared.initializer, seen);
    }
    let owner = null;
    if (ts.isNewExpression(value)) owner = declaration(value.expression);
    if (value.kind === ts.SyntaxKind.ThisKeyword) {
      owner = node.parent;
      while (owner && !ts.isClassDeclaration(owner)) owner = owner.parent;
    }
    if (!owner || !ts.isClassDeclaration(owner) || polymorphicClasses.has(identity(owner))) return false;
    // Source constructors may explicitly return a structurally compatible foreign object.
    let foreignReturn = false;
    function inspectReturn(item) {
      if (ts.isReturnStatement(item) && item.expression) foreignReturn = true;
      ts.forEachChild(item, inspectReturn);
    }
    const constructor = owner.members.find(ts.isConstructorDeclaration);
    if (constructor?.body) inspectReturn(constructor.body);
    return !foreignReturn;
  }
  function localTarget(value, property = false) {
    value = unwrap(value);
    if (!value) return false;
    if (property) {
      if (value.kind === ts.SyntaxKind.ThisKeyword) return ts.isConstructorDeclaration(node) || ts.isClassDeclaration(node);
      return ts.isIdentifier(value) && fresh.has(binding(value));
    }
    return ts.isIdentifier(value) && local.has(binding(value));
  }
  function gather(value) {
    if (value !== node && (functionLike(value) || ts.isClassDeclaration(value))) return;
    if (ts.isVariableDeclaration(value) && ts.isIdentifier(value.name) && node !== sourceFile) {
      local.add(value);
      if (freshValue(value.initializer)) fresh.add(value);
    }
    ts.forEachChild(value, gather);
  }
  if (node.body) gather(node.body);
  else if (node === sourceFile) gather(node);
  function effect(value, kind, target) { effects.push({ kind, target, line: position(value) }); }
  function unknown(value, target, eligible = false) {
    unresolved.push({ kind: "unresolved_dispatch", target, line: position(value), port_eligible: eligible });
  }
  function callFact(expression, value, construct = false) {
    let target = declaration(expression);
    if (construct && target && (ts.isClassDeclaration(target) || ts.isClassExpression(target))) {
      target = target.members.find(ts.isConstructorDeclaration) ?? target;
    }
    const text = expression.getText(sourceFile);
    const name = ts.isPropertyAccessExpression(expression) ? expression.name.text
      : ts.isElementAccessExpression(expression) && ts.isStringLiteralLike(expression.argumentExpression)
        ? expression.argumentExpression.text : text;
    const targetFile = target ? path.resolve(target.getSourceFile().fileName) : null;
    const internal = targetFile && sourceFiles.has(targetFile) && ((functionLike(target) && target.body) || (construct && ts.isClassDeclaration(target))
      || (ts.isVariableDeclaration(target) && target.initializer && functionLike(target.initializer)));
    let called = target ? identity(target) : `${caller.split("::")[0]}::${text}`;
    if (construct && target && ts.isClassDeclaration(target)) called += ".constructor";
    const fact = { language: "typescript", caller, called_symbol: called, call_name: name, line: position(value), effect: "pure" };
    const standard = standardDeclaration(target);
    const parameter = target && (ts.isParameter(target) || (!standard && (ts.isPropertySignature(target) || ts.isMethodSignature(target))));
    const computed = ts.isElementAccessExpression(expression) && !ts.isStringLiteralLike(expression.argumentExpression);
    const receiverExpression = ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression) ? expression.expression : null;
    const receiverDeclaration = receiverExpression ? declaration(receiverExpression) : null;
    const variableDispatch = !standard && target && ts.isVariableDeclaration(target) && !(target.parent.flags & ts.NodeFlags.Const);
    let owner = node.parent;
    while (owner && !ts.isClassDeclaration(owner)) owner = owner.parent;
    const targetOwner = target && ts.isClassDeclaration(target.parent) ? target.parent : null;
    const virtualDispatch = internal && ((targetOwner && polymorphicClasses.has(identity(targetOwner))) || (receiverDeclaration && ts.isParameter(receiverDeclaration))
      || (receiverExpression?.kind === ts.SyntaxKind.ThisKeyword && owner && polymorphicClasses.has(identity(owner))));
    const accessorDispatch = target && ts.isGetAccessorDeclaration(target) && (ts.isCallExpression(value) || ts.isTaggedTemplateExpression(value));
    const dynamic = computed || !target || parameter || variableDispatch || virtualDispatch || accessorDispatch || ["call", "apply", "bind", "eval", "Function"].includes(name);
    if (dynamic) {
      fact.dispatch_resolution = "unresolved";
      fact.dispatch_port_eligible = false;
    } else if (internal) {
      fact.dispatch_resolution = "resolved";
    } else {
      // Only compiler-owned standard declarations get the pure builtin allowance.
      const receiver = ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression) ? expression.expression : null;
      const receiverName = receiver?.getText(sourceFile) ?? "";
      let ambient = target;
      while (ambient && !ts.isModuleDeclaration(ambient)) ambient = ambient.parent;
      const fs = (ambient && ts.isStringLiteral(ambient.name) && /^node:fs(?:\/promises)?$/.test(ambient.name.text)) || /[/\\](?:@types[/\\]node[/\\]fs|node:fs)/.test(targetFile ?? "") || /^node:fs/.test(called);
      if (fs && FS_WRITE.test(name)) fact.effect = "write";
      else if (standard && MUTATORS.has(name)) fact.effect = localTarget(receiver, true) ? "pure" : "write";
      else if (standard && ["freeze", "seal", "preventExtensions"].includes(name)) fact.effect = localTarget(value.arguments?.[0], true) || freshValue(value.arguments?.[0]) ? "pure" : "write";
      else if (standard && ["stringify", "Number", "String"].includes(name) && value.arguments?.[0] && !(checker.getTypeAtLocation(value.arguments[0]).flags & (ts.TypeFlags.StringLike | ts.TypeFlags.NumberLike | ts.TypeFlags.BooleanLike | ts.TypeFlags.Null | ts.TypeFlags.Undefined))) {
        fact.dispatch_resolution = "unresolved"; fact.dispatch_port_eligible = false;
      }
      else if (standard && name === "assign") {
        if (!plainData(value.arguments?.[0]) || !(value.arguments ?? []).slice(1).every((argument) => plainData(argument))) { fact.dispatch_resolution = "unresolved"; fact.dispatch_port_eligible = false; }
        else fact.effect = localTarget(value.arguments?.[0], true) || freshValue(value.arguments?.[0]) ? "pure" : "write";
      }
      else if (standard && (name === "from" || (construct && ["Map", "Set", "WeakMap", "WeakSet"].includes(name))) && value.arguments?.[0] && !plainData(value.arguments[0])) { fact.dispatch_resolution = "unresolved"; fact.dispatch_port_eligible = false; }
      else if (standard && name === "resolve" && value.arguments?.[0] && !plainData(value.arguments[0])) { fact.dispatch_resolution = "unresolved"; fact.dispatch_port_eligible = false; }
      else if (standard && ["defineProperty", "defineProperties", "setPrototypeOf"].includes(name)) fact.effect = "write";
      else if (standard && name === "fetch") {
        const options = value.arguments?.[1];
        let method = options ? null : "GET";
        if (options && ts.isObjectLiteralExpression(options)) {
          const property = options.properties.find((item) => item.name?.getText(sourceFile) === "method");
          method = !property ? "GET" : ts.isPropertyAssignment(property) && ts.isStringLiteralLike(property.initializer) ? property.initializer.text.toUpperCase() : null;
        }
        if (method === null) fact.dispatch_resolution = "unresolved";
        else fact.effect = ["GET", "HEAD"].includes(method) ? "pure" : "write";
      } else if (standard && ["send", "sendBeacon", "open", "postMessage"].includes(name)) fact.effect = "write";
      else if (standard && construct && PURE_CONSTRUCTORS.has(name)) fact.effect = "pure";
      else if (standard && (PURE_METHODS.has(name) || receiverName === "Math" || ["Number", "String", "Boolean", "parseInt", "parseFloat", "isNaN", "isFinite"].includes(name))) fact.effect = "pure";
      else {
        fact.dispatch_resolution = "unresolved";
        fact.dispatch_port_eligible = true;
      }
    }
    if (standard) {
      const receiver = ts.isPropertyAccessExpression(expression) ? expression.expression : null;
      const receiverSafe = !receiver || standardDeclaration(declaration(receiver)) || primitive(receiver) || localContainer(receiver);
      const argumentsSafe = (value.arguments ?? []).every(nativeArgument);
      if (!receiverSafe || !argumentsSafe) { fact.dispatch_resolution = "unresolved"; fact.dispatch_port_eligible = false; }
    }
    if (AUTHORITY.test(name) || AUTHORITY.test(called.split("::").at(-1).split(".").at(-1))) fact.authority_effect = true;
    calls.push(fact);
    if (fact.dispatch_resolution === "unresolved") unknown(value, called, fact.dispatch_port_eligible === true);
    {
      for (const argument of value.arguments ?? []) {
        if (checker.getTypeAtLocation(argument).getCallSignatures().length === 0) continue;
        const callback = functionLike(argument) ? argument : declaration(argument);
        if (callback && (functionLike(callback) || (ts.isVariableDeclaration(callback) && callback.initializer && functionLike(callback.initializer)))) {
          calls.push({ language: "typescript", caller, called_symbol: identity(callback), call_name: "<callback>", line: position(argument), dispatch_resolution: "resolved", effect: "pure", authority_effect: AUTHORITY.test(identity(callback).split("::").at(-1).split(".").at(-1)) });
        } else unknown(argument, "<dynamic callback>");
      }
    }
  }
  function writeTarget(value) {
    const property = ts.isPropertyAccessExpression(value) || ts.isElementAccessExpression(value);
    if (!localTarget(property ? value.expression : value, property)) effect(value, "write", value.getText(sourceFile));
  }
  function visit(value) {
    if (value !== node && functionLike(value)) return;
    if (value !== node && ts.isClassDeclaration(value)) {
      if (ts.getDecorators(value)?.length) unknown(value, "<decorator implicit dispatch>");
      for (const member of value.members) {
        if (ts.canHaveDecorators(member) && ts.getDecorators(member)?.length) unknown(member, "<decorator implicit dispatch>");
        if (ts.isClassStaticBlockDeclaration(member)) visit(member.body);
        if (ts.isPropertyDeclaration(member) && member.modifiers?.some((item) => item.kind === ts.SyntaxKind.StaticKeyword) && member.initializer) visit(member.initializer);
      }
      return;
    }
    if ((ts.isSpreadElement(value) || ts.isSpreadAssignment(value)) && !plainData(value.expression)) unknown(value, "<spread implicit dispatch>");
    if ((ts.isForOfStatement(value) || ts.isForInStatement(value)) && !plainData(value.expression)) unknown(value, "<iteration implicit dispatch>");
    if (ts.isYieldExpression(value) && value.asteriskToken && !plainData(value.expression)) unknown(value, "<yield iterator dispatch>");
    if (ts.isAwaitExpression(value)) {
      if (!primitive(value.expression) && !nativePromise(value.expression)) unknown(value, "<await thenable dispatch>");
    }
    if (ts.isVariableDeclaration(value)) {
      if ((ts.isObjectBindingPattern(value.name) || ts.isArrayBindingPattern(value.name)) && !plainData(value.initializer)) unknown(value, "<destructuring implicit dispatch>");
      if (checker.getTypeAtLocation(value.name).flags & (ts.TypeFlags.Any | ts.TypeFlags.Unknown)) unknown(value, "<unproven local type>");
    }
    if (ts.isComputedPropertyName(value) && !primitive(value.expression)) unknown(value, "<computed property coercion>");
    if (ts.isTemplateExpression(value) && value.templateSpans.some((span) => !primitive(span.expression))) unknown(value, "<template coercion>");
    if ((ts.isAsExpression(value) || ts.isTypeAssertionExpression(value)) && value.type.getText(sourceFile) !== "const") unknown(value, "<unproven type assertion>");
    if (ts.isBinaryExpression(value)) {
      const operator = value.operatorToken.kind;
      const coercive = [ts.SyntaxKind.PlusToken, ts.SyntaxKind.MinusToken, ts.SyntaxKind.AsteriskToken, ts.SyntaxKind.AsteriskAsteriskToken, ts.SyntaxKind.SlashToken, ts.SyntaxKind.PercentToken, ts.SyntaxKind.LessThanToken, ts.SyntaxKind.LessThanEqualsToken, ts.SyntaxKind.GreaterThanToken, ts.SyntaxKind.GreaterThanEqualsToken, ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken, ts.SyntaxKind.AmpersandToken, ts.SyntaxKind.BarToken, ts.SyntaxKind.CaretToken, ts.SyntaxKind.LessThanLessThanToken, ts.SyntaxKind.GreaterThanGreaterThanToken, ts.SyntaxKind.GreaterThanGreaterThanGreaterThanToken];
      if (coercive.includes(operator) && (!primitive(value.left) || !primitive(value.right))) unknown(value, "<operator coercion>");
      if (operator === ts.SyntaxKind.InKeyword && !plainData(value.right)) unknown(value, "<property membership dispatch>");
      if (operator === ts.SyntaxKind.InstanceOfKeyword && !standardDeclaration(declaration(value.right))) unknown(value, "<instanceof dispatch>");
    }
    if ((ts.isPrefixUnaryExpression(value) || ts.isPostfixUnaryExpression(value)) && value.operator !== ts.SyntaxKind.ExclamationToken && !primitive(value.operand)) unknown(value, "<unary coercion>");
    if (ts.isTaggedTemplateExpression(value)) callFact(value.tag, value);
    if (node === sourceFile && (ts.isImportDeclaration(value) || ts.isExportDeclaration(value)) && value.moduleSpecifier) {
      const typeOnly = value.isTypeOnly || value.importClause?.isTypeOnly
        || (value.importClause?.namedBindings && ts.isNamedImports(value.importClause.namedBindings) && value.importClause.namedBindings.elements.length > 0 && value.importClause.namedBindings.elements.every((item) => item.isTypeOnly))
        || (value.exportClause && ts.isNamedExports(value.exportClause) && value.exportClause.elements.length > 0 && value.exportClause.elements.every((item) => item.isTypeOnly));
      if (!typeOnly) {
        const imported = declaration(value.moduleSpecifier);
        const importedFile = imported?.getSourceFile().fileName;
        if (importedFile && sourceFiles.has(path.resolve(importedFile))) {
          calls.push({ language: "typescript", caller, called_symbol: `${path.relative(repoRoot, importedFile).split(path.sep).join("/")}::<module>`, call_name: "<module>", line: position(value), dispatch_resolution: "resolved", effect: "pure" });
        } else if (!value.moduleSpecifier.text.startsWith("node:")) {
          const called = importedFile ? `${path.relative(repoRoot, importedFile).split(path.sep).join("/")}::<module>` : value.moduleSpecifier.text + "::<module>";
          calls.push({ language: "typescript", caller, called_symbol: called, call_name: "<module>", line: position(value), dispatch_resolution: "unresolved", dispatch_port_eligible: Boolean(importedFile), effect: "unknown" });
          unknown(value, called, Boolean(importedFile));
        }
      }
    }
    if (ts.isBinaryExpression(value) && value.operatorToken.kind >= ts.SyntaxKind.FirstAssignment && value.operatorToken.kind <= ts.SyntaxKind.LastAssignment) {
      writeTarget(value.left);
      const setter = declaration(value.left);
      if (setter && ts.isSetAccessorDeclaration(setter)) callFact(value.left, value);
      if (checker.getTypeAtLocation(value.left).getCallSignatures().length) unknown(value, "<assigned callable>");
      if (ts.isIdentifier(value.left) && !freshValue(value.right)) fresh.delete(binding(value.left));
    }
    if ((ts.isPrefixUnaryExpression(value) || ts.isPostfixUnaryExpression(value)) && [ts.SyntaxKind.PlusPlusToken, ts.SyntaxKind.MinusMinusToken].includes(value.operator)) writeTarget(value.operand);
    if (ts.isDeleteExpression(value)) writeTarget(value.expression);
    if (ts.isCallExpression(value)) callFact(value.expression, value);
    if (ts.isNewExpression(value)) callFact(value.expression, value, true);
    if (ts.isPropertyAccessExpression(value) || ts.isElementAccessExpression(value)) {
      const target = declaration(value);
      if (target && ts.isGetAccessorDeclaration(target)) callFact(value, value);
      else if (!provenReceiver(value.expression)) unknown(value, "<member read implicit dispatch>");
    }
    ts.forEachChild(value, visit);
  }
  for (const parameter of node.parameters ?? []) {
    if (!ts.isIdentifier(parameter.name)) unknown(parameter, "<parameter destructuring dispatch>");
    if (parameter.initializer) visit(parameter.initializer);
  }
  if (node.body) visit(node.body);
  else if (node === sourceFile) visit(node);
  if (ts.isConstructorDeclaration(node) || ts.isClassDeclaration(node)) {
    const owner = ts.isClassDeclaration(node) ? node : node.parent;
    if (ts.isClassDeclaration(node)) for (const clause of node.heritageClauses ?? []) {
      if (clause.token === ts.SyntaxKind.ExtendsKeyword) for (const type of clause.types) callFact(type.expression, type, true);
    }
    for (const member of owner.members) if (ts.isPropertyDeclaration(member) && !member.modifiers?.some((item) => item.kind === ts.SyntaxKind.StaticKeyword) && member.initializer) visit(member.initializer);
  }
  return { calls, effects, effect_unresolved: unresolved };
}
