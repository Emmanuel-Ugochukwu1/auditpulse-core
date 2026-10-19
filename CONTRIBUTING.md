# Contributing to AuditPulse Core

Thank you for your interest in contributing to AuditPulse Core! AuditPulse is a lightweight, zero-runtime-dependency static security scanner for Soroban (Rust) smart contracts.

This guide outlines the local development setup, gating verification commands, core architecture, rule authoring models, fixture conventions, and pull request expectations.

---

## Development Setup

AuditPulse is built with TypeScript and uses Tree-sitter for AST structural extraction.

### Prerequisites

- **Node.js**: v18.x or later (v20+ recommended)
- **npm**: v9.x or later

### Getting Started

```bash
# Clone the repository
git clone https://github.com/Emmanuel-Ugochukwu1/auditpulse-core.git
cd auditpulse-core

# Install dependencies
npm install

# Build TypeScript to JavaScript in dist/
npm run build
```

---

## Three Gating Commands

Every pull request and code change must pass three gating commands without errors or warnings:

```bash
# 1. Type check without emitting files
npm run typecheck

# 2. Build TypeScript distribution (runs tsc)
npm run build

# 3. Run full Vitest test suite (automatically triggers pretest: npm run build)
npm test
```

You can also use watch mode during local iterative development:

```bash
npm run test:watch
```

---

## Core Architecture & The Shape of a Rule

The scanner pipeline parses each Rust source file once, extracts structural function boundaries using Tree-sitter, and executes registered security rules against the extracted AST or source text.

### The `Rule` Interface (`src/types.ts`)

Every rule must implement the base `Rule` interface:

```typescript
export type RuleId = string; // Convention: AP-[CATEGORY]-[NUMBER], e.g. "AP-AUTH-001"

export interface Rule {
  id: RuleId;
  name: string;
  description: string;
  scan(code: string): Vulnerability[];
}
```

Findings emitted by rules follow the `Vulnerability` interface:

```typescript
export interface Vulnerability {
  id: string;               // Must match rule.id
  message: string;          // Clear description of the vulnerability
  severity: Severity;       // "critical" | "high" | "medium" | "low"
  confidence?: Confidence;  // "high" | "medium" | "low"
  location: SourceLocation; // { line: number, column?: number, function?: string }
  remediation?: string;     // Actionable guidance for remediation
}
```

### Rule Execution Capabilities (`src/engine.ts`)

Beyond the base `Rule` interface, rules can implement optional engine capabilities:

1. **`FunctionRule` (`scanFunction(fn: ScannedFunction): Vulnerability[]`)**
   - **When to choose**: The rule evaluates function-scoped patterns independently (e.g. `AP-AUTH-001`, `AP-ARITH-001`, `AP-CALL-001`, `AP-ERROR-001`).
   - **How it works**: The `AuditEngine` parses the file AST once and passes each `ScannedFunction` to the rule. This eliminates redundant tree-sitter parsing per rule.

2. **`AstAwareRule` (`scanCode(code: string, functions: ScannedFunction[] | null): Vulnerability[]`)**
   - **When to choose**: The rule operates across file-level scopes or needs contract-wide context while referencing extracted function boundaries (e.g. `AP-STORAGE-001` checking file-wide TTL extension).
   - **How it works**: The engine passes the full source text along with the extracted functions array (or `null` if the parser was unavailable or file was malformed).

3. **Base `Rule` only (`scan(code: string): Vulnerability[]`)**
   - **When to choose**: The rule performs fast, whole-file pattern or token analysis (e.g. `AP-DEBUG-001`).

---

## The `ScannedFunction` Model

Rules implementing `FunctionRule` receive `ScannedFunction` objects (`src/types.ts`):

```typescript
export interface ScannedFunction {
  name: string;        // Function identifier
  line: number;        // 1-based line of the `fn` keyword (attributes excluded)
  column?: number;     // 1-based column of the `fn` keyword
  endLine: number;     // 1-based line of the closing brace `}`
  body: string;        // Full declaration text (from `fn` through `}`)
  bodyInner: string;   // Text inside opening brace `{ ... }`
  bodyLine: number;    // 1-based line of the opening brace `{`
  bodyColumn?: number; // 1-based column of the opening brace `{`
}
```

### What the AST Guarantees vs. What it Does Not

- **Guaranteed by AST**:
  - Exact function name, start line, start column, and closing brace line.
  - Immunity to braces and keywords nested inside string literals, block comments, or doc comments.
  - Automatic fallback to text-based extraction (`src/parser/rust.ts`) if the native tree-sitter parser is unavailable or on syntax-damaged files.
- **Not Guaranteed**:
  - **No semantic or type resolution**: AuditPulse does not run rustc or semantic type analysis.
  - **No cross-file dataflow**: Each file is analyzed independently; helper functions across modules or sub-contracts are not traced.

---

## Fixture Conventions & Quality Sweeps

The `fixtures/` directory organizes real and synthetic test contracts into three standardized categories:

1. `fixtures/vulnerable/`: Contracts exhibiting specific anti-patterns. Each must trigger its corresponding rule(s) with zero false negatives.
2. `fixtures/safe/`: Clean, recommended reference implementations. Must produce zero false positives for targeted rules.
3. `fixtures/edge-cases/`: Contracts testing structural anomalies, comment noise, nested macros, or boundary conditions.

### The Well-Formedness Sweep

All findings generated across all fixtures must pass the comprehensive quality sweep in `tests/fixtures.test.ts`:

- `finding.id` must strictly match `/^AP-[A-Z]+-\d{3}$/`.
- `severity` must be one of `"critical" | "high" | "medium" | "low"`.
- `confidence` must be one of `"high" | "medium" | "low"`.
- `location.line` must be greater than 0.
- `message` length must exceed 10 characters.
- `remediation` must provide non-empty, actionable advice.

---

## Writing a New Rule

For a complete step-by-step tutorial on creating a rule plugin, registering it, and adding tests and fixtures, see the [Rule Authoring Walkthrough](docs/writing-a-rule.md).

---

## Pull Request & Commit Style

### Commit Message Conventions

We follow Conventional Commits formatting:

- `feat(rules): add AP-CAST-001 unsafe integer cast detection (#14)`
- `fix(scanner): correct column offset in multiline expressions (#10)`
- `test(fixtures): add TTL edge case fixture for temporary storage (#3)`
- `docs: add CONTRIBUTING.md and rule authoring guide (#16)`
- `refactor(parser): streamline fallback function regex extraction`

### PR Submission Checklist

Before opening a pull request, ensure:

1. [ ] `npm run typecheck` passes with zero TypeScript errors.
2. [ ] `npm run build` completes successfully.
3. [ ] `npm test` runs all tests and passes 100%.
4. [ ] Any new rule implements `Rule` (and preferably `FunctionRule`), is registered in `src/registry.ts`, and has both unit tests and fixture test coverage.
5. [ ] Commit messages follow the conventional style and reference relevant issue numbers (`#<issue>`).
