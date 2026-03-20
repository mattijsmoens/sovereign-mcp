# Sovereign MCP — Deterministic MCP Security Architecture

**FrozenNamespace as Root of Trust for Model Context Protocol Tool Verification**

*Sovereign Shield / Mattijs Moens — March 2026*

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: BSL 1.1](https://img.shields.io/badge/license-BSL%201.1-orange.svg)](LICENSE)
[![Patent Pending](https://img.shields.io/badge/patent-pending-brightgreen.svg)]()

---

## The Problem

MCP (Model Context Protocol) has become the standard for connecting AI agents to tools. But the protocol has fundamental security gaps that no amount of patching will fix without an architectural solution.

**The 10 biggest MCP vulnerabilities today:**

1. **No authentication by default.** 78% of public MCP implementations have no proper authorization. Anyone who can reach the endpoint can invoke any tool.

2. **Tool description poisoning.** Malicious content embedded in MCP tool descriptions gets read by the model during tool discovery. The model trusts descriptions as instructions. An attacker can manipulate agent behavior just by modifying a tool's description field.

3. **Prompt injection via tool responses.** A compromised MCP tool returns prompt injection payloads in its response. The agent processes the response as trusted context and follows the injected instructions. The attack comes from a "trusted" source.

4. **Cross-tool context leakage.** Data from one tool invocation leaks into subsequent tool calls within the same session. No isolation between tool contexts. Sensitive data from Tool A is visible when Tool B runs because it all lives in the same LLM context window.

5. **No input validation.** MCP tools receive raw parameters with no schema validation. SQL injection, path traversal, and command injection through tool parameters.

6. **Excessive permissions.** MCP tools get broad system access with no least-privilege scoping. A "read file" tool that can actually read the entire filesystem including secrets and configs.

7. **No audit trail.** Most implementations do not log what was called, with what parameters, or what was returned. If something goes wrong, there are no forensics.

8. **Supply chain risk.** Third-party MCP servers run arbitrary code with access to the agent's context. One malicious server in the chain compromises everything.

9. **Token/metadata bloat as attack surface.** 18,000 tokens of metadata per MCP server. This can be weaponized for context window flooding, pushing important instructions out of the context window.

10. **No transport encryption.** Many MCP connections use stdio or unencrypted channels. Data in transit is exposed.

---

## The Core Insight

Every one of these vulnerabilities exists because MCP has **no immutable source of truth**. Tool definitions can be changed. Schemas can be modified. Output formats can be tampered with. There is no reference point that is guaranteed to be correct because nothing in the system is guaranteed to be unchanged.

**The solution: FrozenNamespace as Root of Trust.**

`FrozenNamespace` is a Python metaclass that creates objects whose attributes **physically cannot be modified** after initialization. Not through regular assignment, not through `__setattr__`, not through any runtime manipulation. The constraint is enforced at the language runtime level.

When you freeze MCP tool definitions, schemas, expected output formats, and verification data at process startup, you create an immutable reference point. Every check in the system flows back to this reference. If something does not match the frozen reference, it is **declined by default**. If it does match, you know it is correct because the reference itself cannot have been tampered with.

This is **deterministic verification**. Same input compared against same immutable reference produces same result every time. No probability. No model uncertainty. No guessing.

---

## Quick Start

```python
from sovereign_mcp import ToolRegistry, OutputGate, SchemaValidator

# ── Phase 1: Register and Freeze ──────────────────────────
registry = ToolRegistry()
registry.register_tool(
    name="get_weather",
    description="Fetch current weather for a city",
    input_schema={
        "city": {"type": "string", "required": True, "alpha_only": True}
    },
    output_schema={
        "temperature": {"type": "number", "min": -100, "max": 150},
        "condition":   {"type": "string", "enum": ["sunny", "cloudy", "rainy", "snowy"]},
    },
    capabilities=["read_api"],
    allowed_targets=["api.weather.com/*"],
    risk_level="LOW",
)
frozen = registry.freeze()
# After freeze: no tools can be registered. All definitions are immutable.
# SHA-256 hashes are computed and sealed. This is the root of trust.

# ── Phase 2: Verify Every Tool Output ─────────────────────
gate = OutputGate(frozen)
result = gate.verify("get_weather", {"temperature": 72.5, "condition": "sunny"})

if result.accepted:
    print("✓ All 4 layers passed. Safe to admit to LLM context.")
else:
    print(f"✗ BLOCKED at {result.layer}: {result.reason}")
```

---

## ⚠️ CRITICAL: The Freeze Is Irreversible

**Once you call `registry.freeze()`, the registry is permanently locked for the lifetime of the process.** This is by design — it is the core security guarantee.

After freezing:
- **No new tools can be registered.** `register_tool()` raises `RuntimeError`.
- **No existing tool definitions can be modified.** `FrozenNamespace.__setattr__` raises `TypeError`.
- **No attributes can be deleted.** `FrozenNamespace.__delattr__` raises `TypeError`.
- **No instances can be created.** `FrozenNamespace.__call__` raises `TypeError`.
- **Schema dicts/lists returned are deep copies** — modifying a returned schema does NOT modify the frozen original.
- **Even reading a mutable attribute returns a copy**, not a reference. External code cannot mutate internal state.

This is not a policy. This is an **architectural constraint enforced by the Python runtime**. There is no API to unlock, no admin override, no escape hatch. The only way to register new tools is to restart the process with a new freeze cycle.

If you need to add tools dynamically at runtime, use the **sandbox staging pattern**: new tools are discovered and validated in an isolated sandbox, then applied via a controlled process restart (blue-green deployment). See the [Dynamic Tool Registration](#dynamic-tool-registration) section in the architecture doc.

---

## The Architecture

The system operates in three phases: **Initialization**, **Runtime Verification**, and **Enforcement**.

### Phase 1: Initialization (Startup)

At process startup, before any MCP tool is available for use:

1. **Every registered MCP tool's definition is captured:**
   - Tool name, description
   - Input schema (parameter names, types, constraints)
   - Output schema (expected return format)
   - Declared capabilities (what the tool says it does)
   - Allowed targets (what resources the tool can access)
   - Risk level (LOW, MEDIUM, HIGH)
   - Value constraints (frozen numeric limits per parameter)
   - Approval thresholds (human-in-the-loop triggers)

2. **All captured definitions are locked into FrozenNamespace:**
   - The data becomes immutable
   - No code path can modify it after this point
   - Not the AI model, not the tools, not even the system administrator at runtime
   - The constraint is enforced by the Python metaclass, not by a policy
   - `__getattribute__` returns deep copies of mutable containers to prevent reference mutation

3. **SHA-256 hashes are computed for each frozen definition:**
   - Stored alongside the frozen data
   - Used for fast integrity checks during runtime
   - Any modification to the frozen data would require breaking SHA-256

After initialization, the system has an immutable, hash-sealed reference of what every tool is, what it accepts, what it returns, and what it is allowed to do.

### Phase 2: Runtime Verification (Every Tool Call)

Every time an MCP tool is invoked, the following verification chain executes:

```
Tool Call
   │
   ├─ Step 1: Tool Identity Check ──────── Is it registered? Hash match?
   ├─ Step 2: Input Validation ──────────── Matches frozen input schema?
   ├─ Step 3: Permission Check ──────────── Capability + target allowed?
   ├─ Step 4: Value Constraint Check ────── Within frozen numeric limits?
   │
   ├─ [Tool Executes]
   │
   ├─ Step 5: Layer A — Schema Check ────── Output matches frozen schema?
   ├─ Step 6: Layer B — Deception Scan ──── Known injection patterns?
   ├─ Step 7: Layer C — JSON Consensus ──── Dual-model hash match?
   └─ Step 8: Layer D — Behavioral Floor ── Within frozen capability set?
         │
         ├─ ALL PASS → Admitted to LLM context
         └─ ANY FAIL → DECLINED (default deny)
```

If **any** check fails at **any** step: the tool call is **DECLINED**. Default deny. No exceptions. No override path exists.

### Phase 3: Enforcement (Default Deny)

- If ANY check fails at ANY step: **DECLINED**
- No override path exists
- No trust score can bypass a failed check
- No administrator can modify the frozen reference at runtime
- The frozen reference is the only source of truth

**This is governance by architecture, not by policy.**

---

## The Four Verification Layers

### Layer A: Schema Validation (Deterministic)

Validates tool output against the frozen output schema before it enters the LLM context.

```python
from sovereign_mcp import SchemaValidator

# Frozen schema defines exact structure, types, and constraints
schema = {
    "customer_name": {"type": "string", "alpha_only": True, "max_length": 50},
    "age":           {"type": "integer", "min": 0, "max": 150},
    "city":          {"type": "string", "enum": ["Brussels", "London", "Tokyo"]},
}

# ✓ Valid
SchemaValidator.validate_output(
    {"customer_name": "John", "age": 34, "city": "Brussels"}, schema
)  # → (True, "Output schema validation passed.")

# ✗ Type mismatch
SchemaValidator.validate_output(
    {"customer_name": "John", "age": "thirty-four", "city": "Brussels"}, schema
)  # → (False, "Type mismatch for 'age': expected integer, got str")

# ✗ Injection blocked by alpha_only
SchemaValidator.validate_output(
    {"customer_name": "John; IGNORE PREVIOUS", "age": 34, "city": "Brussels"}, schema
)  # → (False, "Field 'customer_name': must contain only alphabetic characters.")

# ✗ Unknown field blocked
SchemaValidator.validate_output(
    {"customer_name": "John", "age": 34, "city": "Brussels", "ssn": "123-45-6789"}, schema
)  # → (False, "Unexpected output field: 'ssn' not in frozen schema.")
```

**Security hardening:**
- **Bool exclusion**: `isinstance(True, int)` is `True` in Python. Booleans are explicitly excluded from integer/number type checks.
- **NaN/Infinity guards**: `float('nan') > max_val` is always `False` in Python, silently bypassing max constraints. Explicit `math.isnan()` and `math.isinf()` checks reject non-finite values.
- **Null-before-type**: `None` is checked before type validation to prevent `isinstance(None, str)` false negatives.

### Layer B: Deception Detection (Deterministic)

Scans tool output for known prompt injection patterns, social engineering phrases, code execution attempts, and data exfiltration indicators.

```python
from sovereign_mcp import DeceptionDetector

# 40+ pre-compiled regex patterns across 4 categories
DeceptionDetector.scan("IGNORE ALL PREVIOUS INSTRUCTIONS")
# → (False, [{"category": "injection", "match": "IGNORE ALL PREVIOUS INSTRUCTIONS", ...}])

DeceptionDetector.scan("The weather is sunny.")
# → (True, [])  ← Clean

# Recursive scanning of nested dicts
DeceptionDetector.scan_dict({
    "data": {"nested": {"deep": "eval(malicious_code)"}}
})
# → (False, [{"category": "code_execution", "match": "eval(", ...}])
```

**Four detection categories:**

| Category | Examples |
| -------- | -------- |
| **Injection** | `IGNORE PREVIOUS`, `DISREGARD`, `NEW INSTRUCTIONS`, `[SYSTEM]`, `JAILBREAK`, `DAN MODE` |
| **Social Engineering** | `I AM THE ADMIN`, `EMERGENCY OVERRIDE`, `SAFETY DISABLED`, `BYPASS ALL SECURITY` |
| **Code Execution** | `<script>`, `eval(`, `exec(`, `__import__(`, `os.system(`, `subprocess.run(` |
| **Exfiltration** | `send data to`, `curl -d`, `wget`, `base64 encode` |

All patterns are pre-compiled at module load. Both dict keys and values are scanned. Max recursion depth of 10 prevents infinite loops.

### Layer C: Structured JSON Consensus (Deterministic)

Two independent models process tool output and produce structured JSON. The **decision** is a deterministic SHA-256 hash comparison.

```python
from sovereign_mcp import ConsensusVerifier, OutputGate

# Two DIFFERENT models (same model = tautology, blocked by design)
verifier = ConsensusVerifier(
    model_a=gemini_provider,   # Cloud model
    model_b=ollama_provider,   # Local model (different weights)
)
# Both must use temperature=0 (frozen, cannot be raised at runtime)

gate = OutputGate(frozen_registry, consensus_verifier=verifier)
result = gate.verify("get_customer", tool_output)
```

**Canonical JSON Normalization** (critical for practical reliability):

Before hashing, both outputs undergo canonical normalization:

1. Sort all keys alphabetically
2. Strip all whitespace from string values
3. Lowercase all string values
4. Consistent number formatting (no trailing zeros, no leading zeros, `-0.0` → `0`)
5. Consistent separators (no spaces after colons or commas)
6. Remove any optional/null fields
7. NaN → `"__NaN__"`, Infinity → `"__+Infinity__"` / `"__-Infinity__"` (unique sentinels — prevents false consensus when one model returns NaN and another returns 0)

```python
from sovereign_mcp import canonical_hash, hashes_match

# Minor formatting differences are eliminated before hashing
data_a = {"Customer_Name": "  John  ", "Age": 34, "City": "BRUSSELS"}
data_b = {"age": 34, "city": "Brussels", "customer_name": "John"}

match, hash_a, hash_b = hashes_match(data_a, data_b)
# match = True — semantically identical after normalization
```

**Why this is deterministic:**
- The comparison is a SHA-256 hash match, not a model judgment
- Canonical normalization eliminates formatting variance
- The models are probabilistic, but the **DECISION MECHANISM** is deterministic
- An attacker must fool **BOTH** models in **exactly the same way** to produce matching hashes

**Consensus Integrity Requirements:**

| Requirement | Why | Enforcement |
| ----------- | --- | ----------- |
| **Model Diversity** | Same model for both = tautology (comparing X to X) | Different `model_id` required, frozen at init |
| **Deterministic Inference** | Temperature > 0 = random output = false rejections | `temperature=0` required, frozen at init |
| **Schema Tightness** | Loose schema = large attack surface | Field-level constraints (alpha_only, min/max, enum) |

### Layer D: FrozenNamespace Behavioral Floor (Deterministic)

Even if an injection somehow passes Layers A, B, and C, the FrozenNamespace constraints prevent the agent from following injected instructions outside the frozen capability set:

- "IGNORE PREVIOUS INSTRUCTIONS" cannot work because the instructions are frozen and cannot be overridden
- The agent physically cannot execute actions outside the frozen constraint set
- The constraint is enforced by the Python runtime, not by policy

---

## Closing the Semantic Gap

The semantic gap is the hardest problem in AI security: an attacker crafts content that passes structural validation but carries malicious semantic payload.

**For an attacker to succeed, ALL FOUR conditions must be met simultaneously:**

1. Craft content that passes schema validation (Layer 1)
2. Use no known injection patterns (Layer 2)
3. Make two independent models produce identical compromised output (Layer 3)
4. Inject an instruction that falls within the agent's frozen permissions (Layer 4)

The probability of all four is astronomically small. And condition 4 means that even in the worst case, the attacker can only make the agent do something it was already allowed to do — just with bad data.

---

## Data Poisoning Countermeasures

The remaining theoretical gap after the four verification layers is **data poisoning**: a compromised tool returns structurally valid but incorrect data. Both models read the same poisoned source, extract the same wrong values, and the consensus hashes match.

Three countermeasures address this:

### Countermeasure 1: Frozen Value Constraints

Hard numeric limits per action parameter, frozen in FrozenNamespace at startup.

```python
registry.register_tool(
    name="send_money",
    # ...
    value_constraints={
        "amount": {"max": 100, "min": 0},  # Hard ceiling: $100
    },
)

# Tool call: send_money(amount=1000000)
# Check:    1000000 > frozen max (100)
# Result:   DECLINED
```

Deterministic number comparison. No model judgment. No AI. The agent **cannot raise its own limit at runtime**. Even if both models agree the amount is correct, the hard ceiling blocks it.

**Security hardening:**
- NaN bypass blocked: `math.isnan()` check before all comparisons
- Infinity bypass blocked: `math.isinf()` check before all comparisons
- Bool bypass blocked: `isinstance(True, int)` excluded explicitly

### Countermeasure 2: Independent Source Verification

Instead of both models reading from the same tool output, Model B queries a **different data source** to cross-reference the data.

```
Standard consensus (vulnerable to poisoned well):
  Tool output → Model A reads → hash
  Tool output → Model B reads → hash
  Same source → same data → hashes match → poisoned data passes

Independent source verification (solves the poisoned well):
  Tool output   → Model A reads → hash
  SECOND SOURCE → Model B reads → hash
  Different sources → if data disagrees → hashes mismatch → DECLINED
```

```python
registry.register_tool(
    name="get_stock_price",
    # ...
    verification_source="https://api.alternative-exchange.com/v1/price",
    # Model B will query this independent source instead of the tool output
)
```

The verification source is frozen per tool at registration and **cannot be changed at runtime**.

### Countermeasure 3: Human-in-the-Loop Threshold

Above a frozen value threshold, require human approval before execution. Below the threshold, automatic execution with all verification layers.

```python
registry.register_tool(
    name="send_money",
    # ...
    approval_thresholds={
        "amount": {
            "auto_approve_max": 10,   # Up to $10: fully automatic
            "timeout_seconds": 300,    # 5 minutes to respond
            "timeout_default": "DECLINE",  # Fail-safe: decline on timeout
        },
    },
)

# $5 → auto-approved (all 4 layers still run)
# $50 → PAUSED → notification → operator approves/denies
# No response in 5 minutes → auto-DECLINED (fail-safe)
```

The threshold is frozen in FrozenNamespace. The agent **cannot raise its own approval limit**. The timeout defaults to **DECLINE**, not APPROVE. If the operator is unavailable, nothing happens. **Fail-safe.**

**Security hardening:**
- Pending IDs use `uuid.uuid4()` instead of `time.time()` to prevent collisions
- Thread-safe via `threading.Lock()`
- NaN/Infinity rejected before threshold comparison

---

## Hash-Chained Audit Log

Every verification decision, every incident, and every tool call is logged with a hash chain for tamper detection. Each entry includes the SHA-256 hash of the previous entry. Tampering with any entry breaks the chain.

```python
from sovereign_mcp import AuditLog

log = AuditLog(log_file="audit.jsonl")

# Automatic logging via OutputGate
gate = OutputGate(frozen, audit_log=log)

# Verify log integrity at any time
is_valid, broken_at = log.verify_chain()
assert is_valid  # Chain intact

# Query incidents
critical = log.get_incidents(severity="CRITICAL", limit=10)
```

**Incident Classification:**

| Severity | Triggered By | Response |
| -------- | ------------ | -------- |
| **CRITICAL** | Layer D (behavioral floor) — attacker bypassed 3 layers | Immediate escalation |
| **HIGH** | Layer C (consensus) failed — potential data poisoning | Tool quarantine + investigation |
| **MEDIUM** | Layer B (deception) — known injection pattern blocked | Pattern logged for analysis |
| **LOW** | Layer A (schema) — structural violation | Logged only |

**Security hardening:**
- All hash comparisons use `hmac.compare_digest()` for constant-time comparison (prevents timing attacks)
- `entry_hash` is computed BEFORE file write, then re-serialized WITH hash for independent verifiability

---

## Permission Checker

Validates tool actions against frozen capability grants and allowed targets.

```python
from sovereign_mcp import PermissionChecker

# Check: can this tool do this action on this target?
allowed, reason = PermissionChecker.check(
    tool_name="file_reader",
    action="read_file",
    target="/data/users.json",
    frozen_registry=frozen,
)
```

**Security hardening:**
- **Path traversal prevention**: All targets normalized via `posixpath.normpath()` before wildcard matching. `/data/../etc/passwd` normalizes to `/etc/passwd` which does NOT match `/data/*`.
- **Empty capabilities = no actions allowed**: An empty `CAPABILITIES` tuple means the tool can do nothing (not "everything").
- **Empty targets = no targets allowed**: Same principle.

---

## Hardware Memory Protection

Optional C extension that allocates dedicated memory pages and marks them **read-only at the OS level**. Any write attempt — from Python, ctypes, C extensions, or assembly — triggers a hardware fault (SIGSEGV/ACCESS_VIOLATION).

```python
from sovereign_mcp.hardware_protection import freeze, verify, is_protected, destroy
import hashlib

# Freeze data into OS-protected memory
data = b'{"tool": "get_weather", "hash": "a1b2c3..."}'
buf = freeze(data)

# OS-level read-only — hardware enforced
assert is_protected(buf)

# Verify integrity
assert verify(buf, hashlib.sha256(data).digest())

# Secure destruction: re-enable write → zero all bytes → free page
destroy(buf)
```

**Two implementations:**

| Backend | How | When |
| ------- | --- | ---- |
| **C Extension** (`frozen_memory.c`) | Direct OS syscalls (`mmap`/`mprotect` on Unix, `VirtualAlloc`/`VirtualProtect` on Windows) | When compiled via `python setup.py build_ext --inplace` |
| **ctypes Fallback** (`frozen_memory_fallback.py`) | Same OS syscalls via Python ctypes | Automatic when C extension unavailable |

Both provide identical API. The system auto-detects which is available:
```
C extension available? → Use it (fastest, most secure)
  └─ No → ctypes available? → Use fallback (same OS protection)
       └─ No → Python-level protection only (FrozenNamespace metaclass)
```

---

## How This Solves Each Vulnerability

| # | Vulnerability | Solution |
| - | ------------- | -------- |
| 1 | No authentication | Tool identity check against FrozenNamespace. Unknown tools declined. |
| 2 | Description poisoning | Descriptions frozen at startup. Hash check catches post-init changes. |
| 3 | Prompt injection via responses | Four-layer output verification before context admission. |
| 4 | Cross-tool context leakage | Each tool verified against its own frozen schema. Cross-tool data mismatches caught. |
| 5 | No input validation | All inputs validated against frozen input schema. Type + constraint enforcement. |
| 6 | Excessive permissions | Capabilities and targets frozen. Out-of-scope access declined. |
| 7 | No audit trail | Hash-chained tamper-evident logging of every decision. |
| 8 | Supply chain risk | Third-party definitions captured and frozen. Post-init modifications detected by hash. |
| 9 | Token/metadata bloat | Schema defines expected size/format. Excess declined. |
| 10 | No transport encryption | mTLS with frozen CA certificate via `transport_security.py`. |

---

## Why This Is Fully Deterministic

Every component in the decision path:

| Component | Mechanism | Deterministic? |
| --------- | --------- | -------------- |
| FrozenNamespace immutability | Python metaclass + OS memory protection | ✓ |
| SHA-256 hash verification | Mathematical proof | ✓ |
| Schema validation | Structural check: same data + same schema = same result | ✓ |
| Permission checks | Binary lookup: has permission or doesn't | ✓ |
| Deception detection | Pre-compiled regex pattern matching | ✓ |
| Structured JSON Consensus | Hash comparison: same hashes = accept, different = decline | ✓ |
| Behavioral floor | Frozen constraints prevent unauthorized execution | ✓ |

**The key insight:** determinism was moved from the MODEL to the COMPARISON. Each model is probabilistic individually. But the accept/reject decision is based on exact hash match, which is deterministic. The probabilistic components produce outputs, but the system **never asks a model to make the security decision**.

---

## Modules Reference

| Module | Purpose | Lines |
| ------ | ------- | ----- |
| `frozen_namespace.py` | Immutable metaclass — root of trust. Deep-copy on access with caching. | ~200 |
| `tool_registry.py` | Register → freeze → verify lifecycle. Aggregate hash. | ~290 |
| `schema_validator.py` | Layer A — type checking, constraints, field whitelisting. Immutable class. | ~240 |
| `deception_detector.py` | Layer B — 40+ regex patterns, 4 categories, recursive scan. Zero-width strip. | ~205 |
| `pii_detector.py` | PII/sensitive data detection — 17 pattern types, factory-compiled tuple. | ~195 |
| `content_safety.py` | Content safety — 16 harmful content patterns, factory-compiled tuple. | ~165 |
| `canonical_json.py` | Canonical normalization + SHA-256 hashing for consensus. NaN/Inf sentinels. | ~180 |
| `consensus.py` | Layer C — dual-model structured JSON consensus. Full immutability. | ~260 |
| `consensus_cache.py` | Cached consensus results — TTL, sweep, thread-safe. Full immutability. | ~250 |
| `output_gate.py` | Orchestrates all layers + checks. Recursive hallucination detection. | ~485 |
| `audit_log.py` | Hash-chained tamper-evident logging. File locking + rollback. | ~220 |
| `value_constraints.py` | Countermeasure 1 — frozen numeric limits. Type-validated constraints. | ~106 |
| `human_approval.py` | Countermeasure 3 — human-in-the-loop with fail-safe timeout + sweep. | ~185 |
| `permission_checker.py` | Capability + target validation with path traversal prevention. | ~95 |
| `identity_checker.py` | Caller identity verification — token hashing, MappingProxyType freeze. | ~122 |
| `input_sanitizer.py` | Active input sanitization — SQL, XSS, shell, path traversal, double-encoding. | ~213 |
| `domain_checker.py` | Restricted domain access — whitelist/blacklist with wildcard matching. | ~180 |
| `rate_limiter.py` | Per-tool rate limiting — sliding window, thread-safe. | ~119 |
| `incident_response.py` | 5-stage incident pipeline — quarantine, escalation, forensics. | ~337 |
| `sandbox_registry.py` | Dynamic tool staging — discover, validate, approve, export. | ~348 |
| `tool_updater.py` | Blue-green freeze rotation — diff analysis, rollback snapshots. | ~481 |
| `transport_security.py` | Mandatory mTLS — frozen CA, revocation, channel binding. | ~479 |
| `hardware_protection.py` | Auto-loading wrapper for C extension / ctypes fallback. | ~77 |
| `frozen_memory.c` | C extension — OS-level read-only memory pages. | ~418 |
| `frozen_memory_fallback.py` | ctypes fallback — same OS protection without compilation. | ~327 |
| `integrity_lock.py` | Supply-chain defense. SHA-256 lockfile for .py/.c/.pyd/.so files. | ~308 |
| `input_filter.py` | 9-layer multi-decode anti-bypass input sanitization. Persona hijack, multilingual keywords (15 languages), co-occurrence detection. | ~530 |
| `adaptive_shield.py` | Self-learning security filter. Attack reporting, rule generation, sandbox testing, auto-deploy. | ~640 |
| `truth_guard.py` | Hallucination detection. Tracks verification tool usage, blocks unverified factual claims. SQLite cache. | ~470 |
| `conscience.py` | Ethical evaluation engine. Multi-factor harm assessment with configurable thresholds. | ~240 |
| `siem_logger.py` | Structured security event logging. CEF/JSON output for Splunk, Elastic, QRadar. 17 event types. | ~235 |

---

## Installation

```bash
pip install sovereign-mcp
```

**Optional: Build the C extension for hardware memory protection:**

```bash
cd sovereign-mcp
python setup.py build_ext --inplace
```

---

## Security Audit Results

The codebase has undergone **9 full audit passes** across 27 source files. **111 bugs found and fixed** (CRITICAL through sweep-level), including 7 new issues found in the final fresh sweep.

**Bug categories fixed:**
- **Timing attacks** — All hash comparisons use `hmac.compare_digest()` (constant-time)
- **NaN/Infinity bypass** — Explicit `math.isnan()`/`math.isinf()` guards on all numeric comparisons
- **Bool subclass bypass** — `isinstance(value, bool)` exclusion before `isinstance(value, int)`
- **Immutability gaps** — `__delattr__` added to all frozen result classes (`GateResult`, `ConsensusResult`, `ConsensusCacheEntry`, `SchemaValidator`)
- **Mutable windows** — Factory-compiled tuples for `_PII_PATTERNS` and `_SAFETY_PATTERNS` (eliminated mutable list during module load)
- **Per-call recompilation** — Zero-width regex moved to module-level precompiled constant
- **Return type inconsistency** — `transport_security.is_local_connection()` fixed to always return `bool`
- **Internal state leaks** — `sandbox_registry.list_tools()` always returns a copy
- **File locking** — Multi-process audit log safety (Windows `msvcrt`, Unix `fcntl`)
- **In-memory rollback** — Audit log rolls back on file write failure
- **Supply-chain defense** — Integrity lock now scans `.pyd`/`.so` compiled binaries
- **ASLR protection** — Raw memory addresses redacted from logs
- **Deep-copy caching** — FrozenNamespace caches immutable container copies for performance
- **Thread-safe escalation** — Incident count + escalation inside lock (TOCTOU prevention)
- **Expired request sweep** — Human approval proactively cleans up timed-out requests
- **Runtime certificate revocation** — `transport_security.revoke_certificate()` for post-freeze CRL updates

**Known limitations:**
- C extension `memcmp` is not constant-time (Python fallback uses `hmac.compare_digest`)

---

## Performance

| Layer | Latency | Notes |
| ----- | ------- | ----- |
| Layer A (Schema) | ~0.01 ms | JSON parse + type check |
| Layer B (Deception) | ~0.1 ms | Regex matching |
| Layer C (Consensus) | ~200-500 ms | 2 model calls + normalization |
| Layer D (Behavioral) | ~0.01 ms | FrozenNamespace lookup |

**Risk-based optimization:**
- **LOW risk tools**: Layers A, B, D only (~0.12 ms total). Layer C skipped.
- **MEDIUM risk tools**: Full verification, consensus cached for repeated calls.
- **HIGH risk tools**: Full verification on every call, no caching.

Risk classification is frozen per tool at registration and cannot be changed at runtime.

---

## Standards Alignment

| Standard | How Sovereign MCP Aligns |
| -------- | ------------------------ |
| **OWASP Agentic AI Top 10** | Excessive Agency (frozen capabilities), Prompt Injection (4-layer detection), Insecure Tool Use (schema validation), Supply Chain (hash-sealed definitions) |
| **NIST AI RMF** | GOVERN (architectural enforcement), MAP (frozen capability mapping), MEASURE (auditable verification), MANAGE (default-deny) |
| **EU AI Act** | Frozen definitions as immutable documentation, deterministic verification is auditable and explainable, human oversight via startup configuration |

---

## License

Business Source License 1.1 (BSL 1.1). See [LICENSE](LICENSE) for details.

---

## Summary

MCP has 10 major security vulnerabilities. Current approaches try to patch them individually with different tools and protocols. This architecture solves all of them with one mechanism: **FrozenNamespace as root of trust**.

Freeze the tool definitions. Freeze the schemas. Freeze the permissions. Freeze the expected output formats. Force structured JSON output. Verify everything against frozen references using hash consensus between two independent models. **Match = accept. Mismatch = decline. No exceptions. No overrides. No probability anywhere in the decision path.**

The semantic gap — the hardest problem in AI security — is closed through four deterministic layers: schema validation, deception detection, structured JSON consensus, and the FrozenNamespace behavioral floor. Even the model-assisted verification step uses deterministic hash comparison for its accept/reject decision.

**One primitive. Ten vulnerabilities. Four defense layers. Three data poisoning countermeasures. Fully deterministic. Patent pending.**

*Sovereign Shield — Deterministic AI Security*
*Mattijs Moens, 2026*
