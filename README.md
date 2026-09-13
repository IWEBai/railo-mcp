# Railo MCP Server

> Mathematical Safety Guardrail for AI Code Generation.  
> Formally verify AI-generated security patches using First-Order Logic SMT invariants and Concrete Syntax Tree transformations.

[![Documentation](https://img.shields.io/badge/docs-railo.dev-000000?style=flat-square)](https://railo.dev)
[![SMT Solver](https://img.shields.io/badge/solver-Microsoft%20Z3-blue?style=flat-square)](https://github.com/Z3Prover/z3)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](https://opensource.org/licenses/MIT)

---

## Architectural Problem: Probabilistic Code Remediation

When LLMs (GPT-4o, Claude 3.5 Sonnet, GitHub Copilot) generate security patches, they operate via autoregressive next-token prediction. In security-critical paths, probabilistic fixes introduce high-severity failure modes:

* **Incomplete Sanitization:** Generating naive regex checks or `.startswith()` comparisons instead of canonical path containment (`os.path.commonpath`), leaving trivial bypasses.
* **Grammar and Structural Invalidation:** Emitting syntax errors, unclosed delimiters, or invalid method signatures that regress native test suites.
* **Package Hallucination:** Referencing unverified external dependencies, introducing supply-chain vulnerabilities.

Railo MCP provides a deterministic verification layer that evaluates proposed patches against formal First-Order Logic constraints before code is committed.

---

## Exposed Tools

### 1. `explain_vulnerability`
Returns the formal First-Order Logic safety invariant, AST pattern, and canonical remediation implementation for a specified CWE.
* **Scope:** `CWE-89` (SQL Injection), `CWE-22` (Path Traversal), `CWE-78` (Command Injection), `CWE-798` (Hardcoded Credentials), `CWE-918` (SSRF), `CWE-79` (XSS), `CWE-352` (CSRF), `CWE-601` (Open Redirect).
* **Execution:** Local, zero-latency, no network dependency.

### 2. `verify_syntax`
Parses proposed code through Python's Concrete Syntax Tree grammar. Detects unclosed delimiters, invalid indentation, and AST syntax errors prior to commit.
* **Execution:** Local AST parser.

### 3. `verify_security_patch`
Submits a patch diff for formal verification against target CWE domain invariants.
* Returns `VERIFIED (UNSAT)` if the solver proves no input can alter structural execution.
* Returns `FAILED (SAT)` with a concrete counter-example payload if the vulnerability survives.

---

## Installation and Configuration

### Package Execution

Run directly via `uvx`:

```bash
uvx railo-mcp
```

Or install via `pip`:

```bash
pip install railo-mcp
```

---

### Client Configuration

#### Cursor (`.cursor/mcp.json`)

Add the following block to `.cursor/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "railo-security": {
      "command": "uvx",
      "args": ["railo-mcp"],
      "env": {
        "RAILO_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

#### Claude Desktop (`claude_desktop_config.json`)

Add the server definition to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "railo-security": {
      "command": "uvx",
      "args": ["railo-mcp"],
      "env": {
        "RAILO_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

---

## Authentication and API Keys

1. Sign up at [railo.dev](https://railo.dev).
2. Navigate to [Dashboard → API Keys](https://railo.dev/app/api-keys).
3. Generate an API Key (Free tier includes 20 verifications per month).

---

## License

MIT License. Developed by [IWEB](https://github.com/IWEBai) and [Railo Security](https://railo.dev).
