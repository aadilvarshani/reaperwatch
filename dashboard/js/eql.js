/*
 * A scoped subset of Elastic's Event Query Language (EQL), used for both the
 * Hunt view's ad-hoc search and declarative detection rules (backend/detection).
 *
 * Real EQL: https://eql.readthedocs.io/
 *
 * What's implemented (single-event "where" filtering):
 *   <event_type> where <condition>
 *   event_type: "process" (matches event_type "process_create") or "any"
 *   comparisons: == != < <= > >=
 *   membership:  field in (v1, v2, ...)
 *   boolean:     and / or / not, parens for grouping, bare true/false
 *   functions:   wildcard(field, pattern, ...)   -- glob match (* and ?), any pattern
 *                match(field, pattern, ...)      -- regex search, any pattern
 *                startsWith(field, s, ...)        endsWith(field, s, ...)
 *                length(field)                    -- usable in a numeric comparison
 *
 * Deliberately NOT implemented (a documented, future scope): sequence/join
 * queries, additional EQL pipes, and other event types (file/network/registry)
 * beyond the "process"/"any" mapping below.
 *
 * Deliberate adaptation from strict EQL: string comparisons (==, !=, in,
 * startsWith, endsWith) and function name matching are case-INSENSITIVE here,
 * since Windows process names/paths are case-insensitive in practice. Real
 * Elastic EQL is case-sensitive by default. This is a documented choice, not
 * an oversight.
 *
 * Example:
 *   process where process.name : "powershell.exe" is NOT valid here (no ":" operator);
 *   use: process where wildcard(process.name, "*powershell*") and
 *                       match(process.cmdline, "-e(nc(odedcommand)?)?\\b")
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.RWEQL = factory();
  }
}(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  class EqlError extends Error {}

  // ---------------------------------------------------------------- lexer --
  function tokenize(src) {
    const tokens = [];
    let i = 0;
    const n = src.length;
    const isSpace = c => c === " " || c === "\t" || c === "\n" || c === "\r";
    const isIdentStart = c => /[A-Za-z_]/.test(c);
    const isIdentPart = c => /[A-Za-z0-9_.]/.test(c);

    while (i < n) {
      const c = src[i];
      if (isSpace(c)) { i++; continue; }
      if (c === "(") { tokens.push({ t: "(" }); i++; continue; }
      if (c === ")") { tokens.push({ t: ")" }); i++; continue; }
      if (c === ",") { tokens.push({ t: "," }); i++; continue; }

      if (c === '"' || c === "'") {
        const quote = c;
        let j = i + 1, out = "";
        while (j < n && src[j] !== quote) {
          if (src[j] === "\\" && j + 1 < n) { out += src[j + 1]; j += 2; }
          else { out += src[j]; j++; }
        }
        if (j >= n) throw new EqlError("unterminated string literal");
        tokens.push({ t: "STRING", v: out });
        i = j + 1; continue;
      }

      if (/[0-9]/.test(c)) {
        let j = i; while (j < n && /[0-9.]/.test(src[j])) j++;
        tokens.push({ t: "NUMBER", v: parseFloat(src.slice(i, j)) });
        i = j; continue;
      }

      if (src.startsWith("==", i)) { tokens.push({ t: "CMP", v: "==" }); i += 2; continue; }
      if (src.startsWith("!=", i)) { tokens.push({ t: "CMP", v: "!=" }); i += 2; continue; }
      if (src.startsWith(">=", i)) { tokens.push({ t: "CMP", v: ">=" }); i += 2; continue; }
      if (src.startsWith("<=", i)) { tokens.push({ t: "CMP", v: "<=" }); i += 2; continue; }
      if (c === "<") { tokens.push({ t: "CMP", v: "<" }); i++; continue; }
      if (c === ">") { tokens.push({ t: "CMP", v: ">" }); i++; continue; }

      if (isIdentStart(c)) {
        let j = i; while (j < n && isIdentPart(src[j])) j++;
        const word = src.slice(i, j), lower = word.toLowerCase();
        if (lower === "and") tokens.push({ t: "AND" });
        else if (lower === "or") tokens.push({ t: "OR" });
        else if (lower === "not") tokens.push({ t: "NOT" });
        else if (lower === "in") tokens.push({ t: "IN" });
        else if (lower === "where") tokens.push({ t: "WHERE" });
        else tokens.push({ t: "IDENT", v: word });
        i = j; continue;
      }

      throw new EqlError(`unexpected character '${c}' at position ${i}`);
    }
    tokens.push({ t: "EOF" });
    return tokens;
  }

  // --------------------------------------------------------------- parser --
  const BOOL_FUNCS = new Set(["wildcard", "match", "startswith", "endswith"]);

  function parse(src) {
    const tokens = tokenize(src);
    let pos = 0;
    const peek = (ahead = 0) => tokens[pos + ahead];
    const advance = () => tokens[pos++];
    const expect = type => {
      const tok = advance();
      if (tok.t !== type) throw new EqlError(`expected ${type}, got '${tok.v ?? tok.t}'`);
      return tok;
    };

    function orExpr() {
      let node = andExpr();
      while (peek().t === "OR") { advance(); node = { op: "or", left: node, right: andExpr() }; }
      return node;
    }
    function andExpr() {
      let node = unary();
      while (peek().t === "AND") { advance(); node = { op: "and", left: node, right: unary() }; }
      return node;
    }
    function unary() {
      if (peek().t === "NOT") { advance(); return { op: "not", node: unary() }; }
      if (peek().t === "(") { advance(); const n = orExpr(); expect(")"); return n; }
      return predicate();
    }
    function predicate() {
      if (peek().t === "IDENT" && BOOL_FUNCS.has(peek().v.toLowerCase()) && peek(1).t === "(") {
        return functionPredicate();
      }
      if (peek().t === "IDENT") {
        const lower = peek().v.toLowerCase();
        if (lower === "true" || lower === "false") { advance(); return { op: "lit", value: lower === "true" }; }
      }
      return comparison();
    }
    function functionPredicate() {
      const name = advance().v.toLowerCase();
      expect("(");
      const args = argList();
      expect(")");
      return { op: "func", name, args };
    }
    function argList() {
      const args = [];
      if (peek().t !== ")") {
        args.push(operand());
        while (peek().t === ",") { advance(); args.push(operand()); }
      }
      return args;
    }
    function comparison() {
      const left = operand();
      if (peek().t === "IN") {
        advance(); expect("(");
        const values = argList();
        expect(")");
        return { op: "in", field: left, values };
      }
      const opTok = advance();
      if (opTok.t !== "CMP") {
        throw new EqlError(`expected a comparison operator (==, !=, <, <=, >, >=) or 'in' after a field`);
      }
      const right = operand();
      return { op: "cmp", cmp: opTok.v, left, right };
    }
    function operand() {
      if (peek().t === "IDENT" && peek().v.toLowerCase() === "length" && peek(1).t === "(") {
        advance(); expect("(");
        const arg = operand();
        expect(")");
        return { kind: "length", arg };
      }
      const tok = advance();
      if (tok.t === "STRING") return { kind: "lit", value: tok.v };
      if (tok.t === "NUMBER") return { kind: "lit", value: tok.v };
      if (tok.t === "IDENT") {
        const lower = tok.v.toLowerCase();
        if (lower === "true") return { kind: "lit", value: true };
        if (lower === "false") return { kind: "lit", value: false };
        if (lower === "null") return { kind: "lit", value: null };
        return { kind: "field", path: tok.v };
      }
      throw new EqlError(`unexpected token in expression: '${tok.v ?? tok.t}'`);
    }

    const eventTypeTok = expect("IDENT");
    if (eventTypeTok.v.toLowerCase() !== eventTypeTok.v && eventTypeTok.v.toLowerCase() !== "any") {
      // no-op: event type names are lowercased on use below; nothing to validate here
    }
    expect("WHERE");
    const condition = orExpr();
    expect("EOF");
    return { eventType: eventTypeTok.v.toLowerCase(), condition };
  }

  // ------------------------------------------------------------ evaluator --
  function getField(obj, path) {
    return path.split(".").reduce((o, k) => (o == null ? undefined : o[k]), obj);
  }
  function resolveOperand(node, event) {
    if (node.kind === "lit") return node.value;
    if (node.kind === "field") return getField(event, node.path);
    if (node.kind === "length") {
      const v = resolveOperand(node.arg, event);
      return v == null ? 0 : String(v).length;
    }
    throw new EqlError("invalid operand");
  }
  function looseEq(a, b) {
    if (typeof a === "string" || typeof b === "string") {
      return String(a ?? "").toLowerCase() === String(b ?? "").toLowerCase();
    }
    return a === b;
  }
  function wildcardTest(value, pattern) {
    const escaped = pattern
      .replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*/g, ".*")
      .replace(/\?/g, ".");
    return new RegExp("^" + escaped + "$", "i").test(value);
  }

  function evalNode(node, event) {
    switch (node.op) {
      case "lit": return node.value;
      case "and": return evalNode(node.left, event) && evalNode(node.right, event);
      case "or": return evalNode(node.left, event) || evalNode(node.right, event);
      case "not": return !evalNode(node.node, event);
      case "cmp": {
        const l = resolveOperand(node.left, event), r = resolveOperand(node.right, event);
        switch (node.cmp) {
          case "==": return looseEq(l, r);
          case "!=": return !looseEq(l, r);
          case "<": return Number(l) < Number(r);
          case "<=": return Number(l) <= Number(r);
          case ">": return Number(l) > Number(r);
          case ">=": return Number(l) >= Number(r);
          default: throw new EqlError(`unknown comparison operator '${node.cmp}'`);
        }
      }
      case "in": {
        const l = resolveOperand(node.field, event);
        return node.values.some(v => looseEq(l, resolveOperand(v, event)));
      }
      case "func": {
        const [fieldArg, ...patternArgs] = node.args;
        const val = String(resolveOperand(fieldArg, event) ?? "");
        const patterns = patternArgs.map(p => String(resolveOperand(p, event)));
        switch (node.name) {
          case "wildcard": return patterns.some(p => wildcardTest(val, p));
          case "match": return patterns.some(p => { try { return new RegExp(p, "i").test(val); } catch { return false; } });
          case "startswith": return patterns.some(p => val.toLowerCase().startsWith(p.toLowerCase()));
          case "endswith": return patterns.some(p => val.toLowerCase().endsWith(p.toLowerCase()));
          default: throw new EqlError(`unknown function '${node.name}'`);
        }
      }
      default: throw new EqlError("invalid query");
    }
  }

  // "process" (EQL-style category) <-> "process_create" (our event_type value).
  function eventTypeMatches(wanted, event) {
    if (wanted === "any") return true;
    if (wanted === "process") return event.event_type === "process_create";
    return event.event_type === wanted;
  }

  function evaluate(parsed, event) {
    if (!eventTypeMatches(parsed.eventType, event)) return false;
    return evalNode(parsed.condition, event);
  }

  // Small parse cache: detection rules re-evaluate the SAME query string
  // against every incoming event, so avoid re-parsing it each time.
  const parseCache = new Map();
  function parseCached(src) {
    let ast = parseCache.get(src);
    if (!ast) { ast = parse(src); parseCache.set(src, ast); }
    return ast;
  }

  function matches(src, event) {
    return evaluate(parseCached(src), event);
  }
  function runQuery(src, events) {
    const parsed = parseCached(src);
    return events.filter(e => evaluate(parsed, e));
  }

  return { parse, evaluate, matches, runQuery, EqlError };
}));
