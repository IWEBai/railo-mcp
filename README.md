# 🛡️ Railo MCP Server

> **The Mathematical Safety Guardrail for AI Code Generation.**  
> Formally verify AI-generated security patches and eliminate hallucinations in Cursor, Claude Desktop, and Windsurf.

[![Website](https://img.shields.io/badge/website-railo.dev-orange)](https://railo.dev)
[![Z3 Solver](https://img.shields.io/badge/SMT%20Solver-Microsoft%20Z3-blue)](https://github.com/Z3Prover/z3)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## ⚡ The Problem: LLMs Guess Security Fixes

When developers ask Copilot, Cursor, or Claude to fix a vulnerability, LLMs frequently produce code that looks right to a human, but fails under security scrutiny:
* **Incomplete sanitization:** Writing naive regex or `.startswith()` checks instead of canonical path containment (`os.path.commonpath`).
* **Broken syntax:** Generating unclosed brackets, missing imports, or changed function signatures that break unit tests.
* **Hallucinated packages:** Importing non-existent libraries, creating brand new supply-chain risks.

**Railo MCP connects your AI assistant to deterministic formal verification.**

---

## 🛠️ Tools Exposed

### 1. `explain_vulnerability` (Always Free & Local)
Retrieves the mathematical First-Order Logic safety invariant, AST pattern, and canonical remediation code for a specific CWE.
* **Supported:** `CWE-89` (SQLi), `CWE-22` (Path Traversal), `CWE-78` (Command Injection), `CWE-798` (Hardcoded Secrets), `CWE-918` (SSRF), `CWE-79` (XSS), `CWE-352` (CSRF), `CWE-601` (Open Redirect).

### 2. `verify_syntax` (Always Free & Local)
Validates that proposed code is syntactically sound, parses into an Abstract Syntax Tree without grammar errors, and detects unclosed tokens.

### 3. `verify_security_patch`
Submits a proposed patch diff to the Railo formal verification engine. Evaluates whether the fix eliminates the vulnerability invariant without introducing regressions.
* Returns `VERIFIED (UNSAT)` if mathematically proved safe.
* Returns `FAILED (SAT)` with a concrete counter-example payload if the vulnerability survives.

---

## 🚀 Quickstart

### 1. Installation

You can run Railo MCP directly via `uvx`:

```bash
uvx railo-mcp
```

Or install via `pip`:

```bash
pip install railo-mcp
```

---

### 2. Configuration

#### 🟢 Cursor (`.cursor/mcp.json`)
Add Railo to your project's `.cursor/mcp.json`:

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

#### 🟠 Claude Desktop (`claude_desktop_config.json`)
Add to `claude_desktop_config.json`:

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

## 🔑 Getting an API Key

1. Sign up at **[railo.dev](https://railo.dev)**.
2. Go to **Dashboard → [API Keys](https://railo.dev/app/api-keys)**.
3. Click **"Generate Key"** (Free tier includes 20 verifications/month).

---

## 📄 License

MIT License — Developed by [IWEB](https://github.com/IWEBai) & [Railo Security](https://railo.dev).
