import type { Rule, ScannedFunction, Vulnerability } from "../types";
import type { AstAwareRule } from "../engine.js";
import { locateLine, removeComments } from "../utils/rust.js";

type StorageKind = "persistent" | "temporary" | "instance";

interface FnSpan {
  name: string;
  bodyStart: number;
  bodyEnd: number;
}

interface Access {
  kind: StorageKind;
  method: string;
  key: string;
  index: number;
  depth: number;
}

const INSTANCE_KEY = "@instance";
const NEEDS_TTL = new Set(["set", "get", "update", "try_get"]);
const EXTEND_METHODS = new Set(["extend_ttl", "extend_ttl_to_threshold"]);
const BARE_IDENTIFIER = /^[A-Za-z_]\w*$/;

const FN_HEAD = /\bfn\s+([A-Za-z_]\w*)\s*(?:<[^>{]*>)?\s*\(/g;
const ACCESS =
  /\.storage\s*\(\s*\)\s*\.\s*(persistent|temporary|instance)\s*\(\s*\)\s*\.\s*(\w+)\s*\(/g;

function matchBrace(src: string, open: number): number {
  let depth = 0;
  for (let i = open; i < src.length; i += 1) {
    if (src[i] === "{") depth += 1;
    else if (src[i] === "}") {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function firstArg(src: string, afterParen: number): string {
  let depth = 0;
  for (let i = afterParen; i < src.length; i += 1) {
    const ch = src[i]!;
    if (ch === "(" || ch === "[") depth += 1;
    else if (ch === "]") depth -= 1;
    else if (ch === ")") {
      if (depth === 0) return src.slice(afterParen, i);
      depth -= 1;
    } else if (ch === "," && depth === 0) {
      return src.slice(afterParen, i);
    }
  }
  return "";
}

function normalizeKey(raw: string): string {
  return raw
    .replace(/\.clone\s*\(\s*\)/g, "")
    .replace(/\s+/g, "")
    .replace(/^&+/, "");
}

function isBareIdentifier(key: string): boolean {
  return BARE_IDENTIFIER.test(key);
}

function collectFunctions(src: string): FnSpan[] {
  const spans: FnSpan[] = [];
  FN_HEAD.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = FN_HEAD.exec(src)) !== null) {
    const brace = src.indexOf("{", m.index + m[0].length);
    if (brace < 0) continue;
    const end = matchBrace(src, brace);
    if (end < 0) continue;
    spans.push({ name: m[1]!, bodyStart: brace + 1, bodyEnd: end });
  }
  return spans;
}

function enclosing(spans: FnSpan[], index: number): FnSpan | undefined {
  let best: FnSpan | undefined;
  for (const span of spans) {
    if (index < span.bodyStart || index > span.bodyEnd) continue;
    if (!best || span.bodyStart > best.bodyStart) best = span;
  }
  return best;
}

function braceDepth(src: string, from: number, to: number): number {
  let depth = 0;
  for (let i = from; i < to; i += 1) {
    if (src[i] === "{") depth += 1;
    else if (src[i] === "}") depth -= 1;
  }
  return depth;
}

function lineOf(src: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i += 1) if (src[i] === "\n") line += 1;
  return line;
}

export class MissingExtendTtlPlugin implements Rule, AstAwareRule {
  id = "AP-STORAGE-001";
  name = "Missing Extend TTL";
  description =
    "Detects ledger storage access (persistent/temporary/instance) that is never accompanied by a matching extend_ttl call, which risks silent data expiry. Persistent and temporary storage are checked per function and key, with a variable-aliased extend_ttl key (e.g. a local resolved earlier in the function) treated as covering that function's accesses of the same kind. Instance storage is contract-wide and has no key, so any extend_ttl on instance storage anywhere in the file covers every instance access. A given storage kind+key is reported at most once per file, at its earliest uncovered access.";

  scan(code: string): Vulnerability[] {
    return this.scanCode(code, null);
  }

  scanCode(code: string, functions: ScannedFunction[] | null): Vulnerability[] {
    const src = removeComments(code);
    const spans = collectFunctions(src);
    if (spans.length === 0) return [];

    const byFn = new Map<FnSpan, Access[]>();
    ACCESS.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = ACCESS.exec(src)) !== null) {
      const span = enclosing(spans, m.index);
      if (!span) continue;
      const kind = m[1] as StorageKind;
      const method = m[2]!;
      const key =
        kind === "instance"
          ? INSTANCE_KEY
          : normalizeKey(firstArg(src, ACCESS.lastIndex));
      const access: Access = {
        kind,
        method,
        key,
        index: m.index,
        depth: braceDepth(src, span.bodyStart, m.index),
      };
      const list = byFn.get(span);
      if (list) list.push(access);
      else byFn.set(span, [access]);
    }

    // Instance storage has no key and is contract-wide in real Soroban: one
    // extend_ttl() call on instance storage anywhere in the file keeps the
    // whole instance entry alive, no matter which function reads or writes
    // it. Persistent/temporary remain function-scoped below.
    let instanceExtendedAnywhere = false;
    for (const accesses of byFn.values()) {
      if (accesses.some((a) => a.kind === "instance" && EXTEND_METHODS.has(a.method))) {
        instanceExtendedAnywhere = true;
        break;
      }
    }

    // Kind-only delegation: a function that calls a named helper which
    // extends TTL for a given kind is covered for that kind, since we can't
    // trace which key the helper actually extends across a call boundary.
    const helperExtends = new Map<string, Set<StorageKind>>();
    for (const [span, accesses] of byFn) {
      const kinds = new Set<StorageKind>();
      for (const a of accesses) {
        if (EXTEND_METHODS.has(a.method) && a.kind !== "instance") kinds.add(a.kind);
      }
      if (kinds.size > 0) helperExtends.set(span.name, kinds);
    }

    const findings: Vulnerability[] = [];
    // Dedup is global across the file: the same (kind, key) uncovered entry
    // is reported once, at its earliest access, even if multiple unrelated
    // functions touch it without extending it.
    const reported = new Set<string>();

    for (const [span, accesses] of byFn) {
      const body = src.slice(span.bodyStart, span.bodyEnd);
      const delegated = new Set<StorageKind>();
      for (const [name, kinds] of helperExtends) {
        if (name === span.name) continue;
        if (new RegExp(`\\b${name}\\s*\\(`).test(body)) {
          for (const k of kinds) delegated.add(k);
        }
      }

      const extensions = accesses.filter(
        (a) => EXTEND_METHODS.has(a.method) && a.kind !== "instance",
      );

      // A same-function extend_ttl whose key is a bare variable (not a
      // literal path like DataKey::Foo) likely aliases a key resolved
      // earlier (e.g. read from storage itself); we can't trace that
      // statically, so treat it as covering the whole kind in this
      // function rather than flagging a "different key" false positive.
      const looseKinds = new Set<StorageKind>();
      for (const e of extensions) {
        if (isBareIdentifier(e.key)) looseKinds.add(e.kind);
      }

      for (const access of accesses) {
        if (!NEEDS_TTL.has(access.method)) continue;

        if (access.kind === "instance") {
          if (instanceExtendedAnywhere) continue;
          if (reported.has("instance")) continue;
          reported.add("instance");
          findings.push(
            this.finding(
              src,
              access,
              span.name,
              "medium",
              `Instance storage accessed in '${span.name}' is never extended anywhere in this contract; the whole instance entry can expire and every field reads back as None.`,
              "Call env.storage().instance().extend_ttl(threshold, extend_to) somewhere on every invocation path to keep the contract's instance storage alive.",
              functions,
            ),
          );
          continue;
        }

        if (delegated.has(access.kind)) continue;
        if (looseKinds.has(access.kind)) continue;

        const sameKind = extensions.filter((e) => e.kind === access.kind);
        const exact = sameKind.filter((e) => e.key === access.key);
        const dedupe = `${access.kind}:${access.key}`;
        if (reported.has(dedupe)) continue;

        if (exact.length > 0) {
          if (exact.every((e) => e.depth > access.depth)) {
            reported.add(dedupe);
            findings.push(
              this.finding(
                src,
                access,
                span.name,
                "low",
                `The only extend_ttl for this ${access.kind} entry in '${span.name}' sits inside a conditional branch, so the entry expires on any path that skips it.`,
                "Extend the entry unconditionally, or extend it on every branch that writes or reads it.",
                functions,
              ),
            );
          }
          continue;
        }

        reported.add(dedupe);

        if (sameKind.length > 0) {
          findings.push(
            this.finding(
              src,
              access,
              span.name,
              "medium",
              `'${span.name}' accesses ${access.kind} key ${access.key} but only extends a different key in the same storage; the accessed entry still expires and reads back as None.`,
              `Call env.storage().${access.kind}().extend_ttl(&<the accessed key>, threshold, extend_to) for the entry actually used here.`,
              functions,
            ),
          );
          continue;
        }

        const crossKind = extensions.length > 0;
        findings.push(
          this.finding(
            src,
            access,
            span.name,
            "medium",
            crossKind
              ? `'${span.name}' accesses ${access.kind} storage but extends TTL on ${extensions[0]!.kind} storage instead; the ${access.kind} entry is never bumped and expires silently.`
              : `Ledger entries accessed in '${span.name}' are never bumped via extend_ttl; expired ${access.kind} entries read back as None.`,
            `After reading or writing ${access.kind} storage, call env.storage().${access.kind}().extend_ttl(...) for the same key to keep the entry alive.`,
            functions,
          ),
        );
      }
    }

    return findings.sort((a, b) => a.location.line - b.location.line);
  }

  private finding(
    src: string,
    access: Access,
    fn: string,
    confidence: "low" | "medium" | "high",
    message: string,
    remediation: string,
    functions: ScannedFunction[] | null,
  ): Vulnerability {
    const line = lineOf(src, access.index);
    const location = locateLine(functions, line);
    if (location.function === undefined) {
      location.function = fn;
    }
    return {
      id: "AP-STORAGE-001",
      message,
      severity: "high",
      confidence,
      location,
      remediation,
    };
  }
}

export default new MissingExtendTtlPlugin();
