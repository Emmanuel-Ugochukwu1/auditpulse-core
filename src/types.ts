export type Severity = "critical" | "high" | "medium" | "low";

export type Confidence = "high" | "medium" | "low";

export interface SourceLocation {
  line: number;
  column?: number;
  function?: string;
}

export interface Vulnerability {
  id: string;
  message: string;
  severity: Severity;
  confidence?: Confidence;
  location: SourceLocation;
  remediation?: string;
}

/**
 * A function structure shared by the AST parser and the source-text
 * fallback, so rules see one shape regardless of how it was produced.
 * Positions are 1-based; columns count characters from the start of the
 * line and are omitted when not reliably known.
 */
export interface ScannedFunction {
  /** Function name from the declaration. */
  name: string;
  /** 1-based line of the `fn` keyword (attributes excluded). */
  line: number;
  /** 1-based column of the `fn` keyword; omitted in text-fallback extraction. */
  column?: number;
  /** 1-based line of the closing brace of the body. */
  endLine: number;
  /** Full declaration text, from the `fn` token through the closing brace. */
  body: string;
  /** Text after the opening brace of the body, closing brace included. */
  bodyInner: string;
  /** 1-based line of the body's opening brace. */
  bodyLine: number;
  /** 1-based column of the body's opening brace; omitted in text-fallback extraction. */
  bodyColumn?: number;
  /**
   * Outer attributes on the declaration, in source order, as the text
   * between `#[` and `]` with whitespace collapsed (`#[only_role(caller,
   * "minter")]` becomes `only_role(caller, "minter")`). Attributes are not
   * part of `body`; omitted by extractors that do not collect them.
   */
  attributes?: string[];
}

/** Stable, machine-readable rule identifier, e.g. "AP-AUTH-001". */
export type RuleId = string;

/**
 * A single security check over Soroban (Rust) source code.
 *
 * Implementations must be reusable: calling `scan` repeatedly with the
 * same input must return the same findings.
 */
export interface Rule {
  /** Stable id stamped on every finding the rule emits. */
  id: RuleId;
  /** Short human-readable name. */
  name: string;
  /** One-line description of what the rule detects. */
  description: string;
  /** Returns the findings for the given source code. */
  scan(code: string): Vulnerability[];
}