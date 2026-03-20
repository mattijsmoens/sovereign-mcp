# Sovereign MCP — Complete Code Documentation

> **Sovereign MCP** is a deterministic security verification layer for the Model Context Protocol (MCP). It sits between AI models and their tools, ensuring every tool output passes through a four-layer verification chain before reaching the LLM context. Nothing is probabilistic in the decision path. Every accept/reject is a deterministic comparison — hashes match or they don't, schemas validate or they don't, patterns are found or they aren't.

This document describes **every module, every class, every function, and every design decision** in the codebase. It is written as narrative prose so that someone reading the code for the first time understands not just *what* each piece does, but *why* it exists and *how* it connects to the rest of the system.

---

## Table of Contents

1. [Package Entry Point (`__init__.py`)](#1-package-entry-point)
2. [Frozen Namespace (`frozen_namespace.py`)](#2-frozen-namespace)
3. [Tool Registry (`tool_registry.py`)](#3-tool-registry)
4. [Integrity Lock (`integrity_lock.py`)](#4-integrity-lock)
5. [Schema Validator — Layer A (`schema_validator.py`)](#5-schema-validator--layer-a)
6. [Deception Detector — Layer B (`deception_detector.py`)](#6-deception-detector--layer-b)
7. [PII Detector (`pii_detector.py`)](#7-pii-detector)
8. [Content Safety (`content_safety.py`)](#8-content-safety)
9. [Canonical JSON (`canonical_json.py`)](#9-canonical-json)
10. [Consensus Verifier — Layer C (`consensus.py`)](#10-consensus-verifier--layer-c)
11. [Consensus Cache (`consensus_cache.py`)](#11-consensus-cache)
12. [Output Gate (`output_gate.py`)](#12-output-gate)
13. [Identity Checker (`identity_checker.py`)](#13-identity-checker)
14. [Input Sanitizer (`input_sanitizer.py`)](#14-input-sanitizer)
15. [Domain Checker (`domain_checker.py`)](#15-domain-checker)
16. [Rate Limiter (`rate_limiter.py`)](#16-rate-limiter)
17. [Value Constraints (`value_constraints.py`)](#17-value-constraints)
18. [Human Approval (`human_approval.py`)](#18-human-approval)
19. [Permission Checker (`permission_checker.py`)](#19-permission-checker)
20. [Audit Log (`audit_log.py`)](#20-audit-log)
21. [Incident Response (`incident_response.py`)](#21-incident-response)
22. [Sandbox Registry (`sandbox_registry.py`)](#22-sandbox-registry)
23. [Tool Updater (`tool_updater.py`)](#23-tool-updater)
24. [Transport Security (`transport_security.py`)](#24-transport-security)
25. [Frozen Memory — C Extension (`frozen_memory.c`)](#25-frozen-memory--c-extension)
26. [Frozen Memory — Python Fallback (`frozen_memory_fallback.py`)](#26-frozen-memory--python-fallback)
27. [Hardware Protection Wrapper (`hardware_protection.py`)](#27-hardware-protection-wrapper)

---

## 1. Package Entry Point

**File:** `sovereign_mcp/__init__.py` (99 lines)

This file is the front door of the entire package. When anyone writes `import sovereign_mcp`, this is the first code that executes — and the very first thing it does is run a security check.

Before importing a single class or function from any other module, line 15 imports `verify_integrity` from `integrity_lock.py` and calls it immediately. This is a deliberate design choice: if someone has tampered with any source file in the package (modified a `.py` or `.c` file), the integrity check fails with an `IntegrityViolation` exception and the entire import aborts. No code from the potentially compromised package ever runs. This is the supply-chain defense — it happens before anything else.

The environment variable `SOVEREIGN_MCP_SKIP_INTEGRITY` can bypass this check (used during development and testing), but in production, the check is always active.

After the integrity gate passes, `__init__.py` imports and re-exports every public class and function from every module in the package. This means users can write `from sovereign_mcp import OutputGate` directly. The `__all__` list at the top explicitly declares every public name — there are no implicit exports.

The file also defines `__version__` (currently `"0.1.0"`) and `__author__` (`"Mattijs Moens"`).

---

## 2. Frozen Namespace

**File:** `sovereign_mcp/frozen_namespace.py` (184 lines)

This is the foundational building block of the entire security architecture. The `FrozenNamespace` metaclass makes class attributes **completely immutable after creation**. Not "convention immutable" (like Python's `@property`) — actually immutable in a way that resists deliberate attack.

### The `FrozenNamespace` Metaclass

When you create a class using `FrozenNamespace` as its metaclass, three things happen:

1. **`__setattr__` is blocked.** Any attempt to modify an attribute after the class is created raises `AttributeError` with the message `"FROZEN: Cannot modify..."`. This isn't just `__setattr__` on instances — it's on the **class itself**. You cannot do `MyTool.DESCRIPTION = "hacked"`.

2. **`__delattr__` is blocked.** You cannot delete attributes from a frozen class. This prevents an attacker from removing security-critical fields like `OUTPUT_SCHEMA` or `CAPABILITIES`.

3. **`__call__` is blocked.** You cannot instantiate a frozen class. These classes exist purely as namespaces — containers for read-only attributes. There's no reason to create instances, and allowing instantiation would open an attack surface (instance attributes can shadow class attributes).

4. **Mutable containers are deep-copied on access, with caching.** This is subtle but critical. If a frozen class has a `dict` or `list` attribute, Python returns a reference to the actual object. An attacker could do `MyTool.OUTPUT_SCHEMA["injected_field"] = {...}` and mutate the original dict even though `__setattr__` is blocked. To prevent this, `__getattribute__` is overridden: when you access an attribute that is a `dict`, `list`, or `set`, you get a `copy.deepcopy()` of it, never the original. Deep copies are cached by `id()` and content hash — since the namespace is immutable, the cache is always valid, avoiding repeated O(n) copies.

### The `freeze_tool_definition()` Function

This function takes a plain dictionary (a tool definition with keys like `name`, `description`, `input_schema`, `output_schema`, `capabilities`, etc.) and dynamically creates a new class using `FrozenNamespace` as its metaclass. Each dictionary key becomes an uppercase class attribute: `name` → `NAME`, `description` → `DESCRIPTION`, `input_schema` → `INPUT_SCHEMA`, and so on.

Before freezing, it also computes a SHA-256 hash of the entire definition (serialized as canonical JSON with sorted keys). This hash is stored as `DEFINITION_HASH` on the frozen class. This hash is the integrity seal — it's used later by `FrozenRegistry.verify_tool_integrity()` to detect if anyone has somehow managed to alter the frozen data.

If a field is missing from the definition (e.g., no `output_schema` provided), it defaults to an empty tuple `()` or empty dict `{}` depending on the field. This ensures every frozen tool has every expected attribute, even if the original definition was incomplete.

---

## 3. Tool Registry

**File:** `sovereign_mcp/tool_registry.py` (287 lines)

This file manages the lifecycle of tool definitions from registration through freezing. It contains two classes: `ToolRegistry` (mutable staging area) and `FrozenRegistry` (immutable production registry).

### `ToolRegistry` — The Mutable Staging Area

`ToolRegistry` is where tool definitions live before they're frozen. You call `register()` to add a tool, providing its name, description, schemas, capabilities, allowed targets, risk level, and other metadata.

**`register(name, description, input_schema, output_schema, capabilities, allowed_targets, risk_level, verification_source, value_constraints, approval_thresholds, rate_limits, allowed_domains)`** — This method accepts all the fields that define a tool's identity and security profile. It validates that `name` is a non-empty string, that `capabilities` is a list, and that `risk_level` is one of `"LOW"`, `"MEDIUM"`, or `"HIGH"` (defaulting to `"HIGH"` — fail-safe). The definition is stored as a plain dict in `self._tools[name]`.

**`freeze()`** — This is the point of no return. It iterates over every registered tool definition, calls `freeze_tool_definition()` from `frozen_namespace.py` to convert each one into an immutable `FrozenNamespace` class, and collects them all into a `FrozenRegistry`. It also computes an **aggregate hash** — a SHA-256 hash of all individual tool definition hashes concatenated together (in sorted order by tool name). This aggregate hash is the fingerprint of the entire registry. If any single tool definition changes, the aggregate hash changes.

After `freeze()` is called, the `ToolRegistry` marks itself as frozen and refuses any further registrations.

### `FrozenRegistry` — The Immutable Production Registry

`FrozenRegistry` is what the rest of the system uses at runtime. It provides read-only access to frozen tool definitions.

**`get_tool(name)`** — Returns the frozen class for a tool. Since the class uses `FrozenNamespace`, all attributes are read-only and mutable containers are deep-copied on access.

**`is_registered(name)`** — Boolean check for tool existence.

**`tool_names`** — Property returning a tuple of all registered tool names.

**`verify_tool_integrity(name)`** — Recomputes the SHA-256 hash of a tool's attributes and compares it to the stored `DEFINITION_HASH` using `hmac.compare_digest()` (constant-time comparison to prevent timing attacks). If the hashes don't match, something has been tampered with.

**`verify_all_integrity()`** — Runs `verify_tool_integrity()` on every tool and recomputes the aggregate hash. Returns `(is_valid, failures)` where `failures` is a list of tool names that failed integrity verification.

---

## 4. Integrity Lock

**File:** `sovereign_mcp/integrity_lock.py` (306 lines)

This module implements **supply-chain attack defense**. It protects against an attacker who modifies the source code files of the package on disk (e.g., through a compromised dependency, a malicious PyPI package, or direct file modification).

### How It Works

On **first run** (when no lockfile exists), `verify_integrity()` scans every `.py`, `.c`, `.pyd`, and `.so` file in the `sovereign_mcp/` directory, computes a SHA-256 hash of each file's contents, and writes them all to `.integrity_lock.json` in the package directory. This lockfile becomes the "known good" state. The inclusion of compiled binaries (`.pyd`/`.so`) prevents a supply-chain attacker from replacing a compiled extension without detection.

On **subsequent runs**, it re-scans all files, recomputes their hashes, and compares them to the lockfile. Three types of violations are detected:

1. **Modified files** — A file exists in both the lockfile and on disk, but its hash has changed. Someone edited the source code.
2. **New files** — A file exists on disk but not in the lockfile. Someone added a new file (possibly a malicious module that gets imported).
3. **Deleted files** — A file exists in the lockfile but not on disk. Someone removed a file (possibly to disable a security check).

Any of these violations raises `IntegrityViolation`, a custom exception that inherits from both `RuntimeError` and `SecurityError`. The exception message includes the specific files that were modified, added, or deleted.

### Key Functions

**`_compute_file_hash(filepath)`** — Reads a file in 8KB chunks and feeds them to a SHA-256 hasher. Returns the hex digest. Uses chunked reading to handle large files without loading them entirely into memory.

**`_scan_source_files(package_dir)`** — Uses `os.walk()` to find all `.py`, `.c`, `.pyd`, and `.so` files in the package directory. Returns a dict of `{relative_path: sha256_hash}`. Paths are normalized to forward slashes for cross-platform consistency.

**`_load_lockfile(lockfile_path)`** — Reads and parses the JSON lockfile. Returns `None` if the file doesn't exist (first run).

**`_save_lockfile(lockfile_path, file_hashes)`** — Writes the lockfile as formatted JSON with a `"generated_at"` timestamp and a `"files"` dict mapping paths to hashes.

**`verify_integrity()`** — The main entry point, called from `__init__.py`. Determines the package directory, checks for `SOVEREIGN_MCP_SKIP_INTEGRITY` env var, scans files, loads/creates the lockfile, and performs the comparison. Uses `hmac.compare_digest()` for constant-time hash comparison (prevents timing side-channels that could reveal which bytes of the hash differ).

---

## 5. Schema Validator — Layer A

**File:** `sovereign_mcp/schema_validator.py` (222 lines)

Layer A of the verification chain. This is the first check that tool output passes through. It validates that the output (and optionally the input) conforms to the frozen schema — correct types, required fields present, constraints satisfied.

### `SchemaValidator` Class

**`validate_output(output_data, frozen_schema)`** — Takes the raw tool output (a dict) and the frozen output schema (from the `FrozenNamespace`), and validates every field. Returns `(is_valid, errors)`. The schema is a dict where each key maps to a field definition with `type`, `required`, and optional constraints.

**`validate_input(input_data, frozen_schema)`** — Same logic, applied to input parameters before tool execution.

**`_validate_field(field_name, value, field_schema)`** — The core validation engine. Handles:
- **Type checking:** Maps schema types (`"string"`, `"integer"`, `"number"`, `"boolean"`, `"array"`, `"object"`) to Python types.
- **Numeric constraints:** `min`, `max` for numbers. Explicitly rejects `NaN` and `Infinity` — this is a security fix (Bug M-06) because `NaN` comparisons in Python always return `False`, meaning `NaN > max` would silently pass, allowing unlimited values.
- **String constraints:** `min_length`, `max_length`, `pattern` (regex matching with ReDoS protection — patterns are tested against a timeout), `enum` (value must be one of a fixed set), `alpha_only` (letters only, no injection characters).
- **Array validation:** Checks `min_items`, `max_items`, and optionally validates each item against an `items` sub-schema.
- **Nested objects:** Recursively validates nested dicts against sub-schemas.

---

## 6. Deception Detector — Layer B

**File:** `sovereign_mcp/deception_detector.py` (~205 lines)

Layer B scans tool output for **prompt injection patterns** — attempts by a malicious tool to hijack the LLM's behavior by embedding instructions in its output.

### Pattern Categories

All patterns are pre-compiled at module load (not at call time) and stored as a frozen tuple — they cannot be modified, cleared, or extended at runtime. A module-level `_ZERO_WIDTH_CHARS` regex is also pre-compiled for stripping zero-width Unicode characters from content before scanning (prevents attackers from breaking up patterns with invisible characters). There are four categories:

1. **Injection phrases** (25 patterns) — Classic prompt injection: `"IGNORE ALL PREVIOUS INSTRUCTIONS"`, `"YOU ARE NOW"`, `"ACT AS IF"`, `"DEVELOPER MODE"`, `"JAILBREAK"`, `"SUDO"`, etc. Includes obfuscated variants like `"1GN0R3 PR3V10US"` and spaced-out versions like `"IGN O R E  PR E V"`.

2. **Social engineering** (10 patterns) — Authority claims: `"I AM THE ADMIN"`, `"EMERGENCY OVERRIDE"`, `"SAFETY DISABLED"`, `"BYPASS ALL SECURITY"`, `"UNRESTRICTED MODE"`.

3. **Code execution** (9 patterns) — Attempts to run code through tool output: `<script>`, `javascript:`, `eval()`, `exec()`, `__import__()`, `os.system()`, `subprocess.run()`.

4. **Exfiltration indicators** (4 patterns) — Commands that would send data somewhere: `"send data to"`, `curl -d`, `wget`, `base64 encode`.

### `DeceptionDetector` Class

**`scan(content)`** — Takes a string, first strips all zero-width Unicode characters using the pre-compiled `_ZERO_WIDTH_CHARS` module-level regex, then runs every compiled pattern against it. Returns `(is_clean, detections)` where `detections` is a list of dicts with `category`, `pattern`, `match` (the matched text), and `position` (character offset). All patterns use `re.IGNORECASE`.

**`scan_dict(data, depth, max_depth)`** — Recursively scans all string values within a nested data structure (dict, list, or string). Scans both keys and values in dicts. Has a depth limit (default 10) — if exceeded, returns `False` with a `"depth_exceeded"` detection. This prevents infinite recursion from circular data structures and also catches attackers who deeply nest injection payloads hoping to evade shallow scanning.

---

## 7. PII Detector

**File:** `sovereign_mcp/pii_detector.py` (~195 lines)

Part of the 13 Audit Checks (Check 4). Scans tool output for personally identifiable information and sensitive data before it enters the LLM context. This prevents scenarios where a database tool returns raw customer data including SSNs, credit cards, or API keys.

### Pattern Categories

17 patterns in total, all compiled via a factory function `_compile_pii_patterns()` that returns an immutable tuple directly — eliminating the mutable list window during module load. The factory function is deleted from the module namespace after use to prevent re-invocation:

- **SSN** — Both `123-45-6789` format and contextual `ssn: 123456789` format
- **Credit cards** — Visa (starts with 4), Mastercard (starts with 51-55), Amex (starts with 34/37), with optional dashes/spaces
- **Email addresses** — Standard email regex
- **Phone numbers** — US format with optional +1 and international `+CC-NNNN` format
- **IPv4 addresses** — Dotted quad with valid octet ranges (0-255)
- **API keys/tokens** — Generic `api_key=`, `access_token=`, `Bearer` tokens
- **AWS access keys** — AKIA/ABIA/ACCA/ASIA followed by 16 uppercase chars
- **Passwords** — Key-value pairs like `password=`, `passwd:`, `pwd=`
- **Private keys** — PEM markers (`-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN EC PRIVATE KEY-----`)
- **Database connection strings** — `mongodb://`, `postgres://`, `mysql://`, `redis://`
- **JWT tokens** — Base64url-encoded three-part tokens starting with `eyJ`

### Sensitivity Levels

The `HIGH_SENSITIVITY` set marks patterns that should always be flagged: SSNs, credit cards, private keys, AWS keys, passwords, and DB connection strings. Others (like email, phone, IP) are marked `MEDIUM`.

### `PIIDetector` Class

**`scan(content)`** — Uses `finditer()` (not just `search()`) to find **all** matches, not just the first. Each detection includes a **redacted** version of the match for logging — showing only the first 4 and last 2 characters (`"4532***89"`). This way the log captures what was detected without exposing the actual sensitive data.

**`scan_dict(data, depth, max_depth)`** — Recursive scanning identical in structure to `DeceptionDetector.scan_dict()`. Scans both keys and values.

---

## 8. Content Safety

**File:** `sovereign_mcp/content_safety.py` (160 lines)

Part of the 13 Audit Checks (Check 10). Separate from deception detection (which targets prompt injection) and PII detection (which targets data leaks). Content Safety targets **harmful, violent, illegal, or otherwise unsafe content** in tool output.

### Pattern Categories

16 patterns covering:

- **Violence/threats** — `"kill everyone"`, `"how to make a bomb"`, `"let's attack"`
- **Illegal activity** — Drug synthesis instructions, hacking instructions, fraud instructions
- **Self-harm** — Instructions or encouragement for self-harm
- **CSAM indicators** — Child exploitation content markers
- **Hate speech** — White supremacy, ethnic cleansing, genocide references
- **Malware/ransomware** — Ransomware instructions, malware distribution commands
- **Doxxing/harassment** — Revealing personal information, stalking, threatening

### `ContentSafety` Class

Same API pattern as `DeceptionDetector` and `PIIDetector`: `scan(content)` for strings, `scan_dict(data)` for nested structures. Redacts matches in logs (first 6 + last 4 characters). Uses `finditer()` to catch all occurrences.

---

## 9. Canonical JSON

**File:** `sovereign_mcp/canonical_json.py` (176 lines)

This is the critical component that makes the structured JSON consensus **deterministic**. The problem: two different LLMs processing the same data will produce semantically identical JSON but with different formatting — different key order, different whitespace, different number representations. If you hash these raw outputs, you get different hashes even though the data is the same. Canonical JSON solves this.

### Normalization Rules

**`normalize(data, remove_nulls)`** — Recursively normalizes any JSON-compatible Python object:

1. **Booleans** — Left unchanged (must be checked before int because `bool` is a subclass of `int` in Python — `isinstance(True, int)` returns `True`).
2. **Integers** — Left unchanged.
3. **Floats** — Passed through `_normalize_number()`: removes `-0.0` (becomes `0`), converts integer-valued floats to int (e.g., `5.0` → `5`), converts `NaN` to the string `"__NaN__"` and `Infinity` to `"__+Infinity__"` / `"__-Infinity__"`. These are unique sentinel strings — this is critical because if NaN was converted to `0`, then Model A returning `NaN` and Model B returning `0` would produce the same hash, creating a **false consensus**.
4. **Strings** — Stripped of whitespace and lowercased via `_normalize_string()`.
5. **Dicts** — Keys sorted alphabetically, converted to lowercase strings, values recursively normalized. Null values are **removed** (optional fields don't affect the hash). Key collision warning if two keys normalize to the same string.
6. **Arrays** — Each element normalized. Nulls are **NOT** removed from arrays (unlike dicts) because array position is semantically meaningful — `[1, null, 3]` must not collapse to `[1, 3]`.

**`canonical_dumps(data)`** — Normalizes, then serializes with `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)`. The compact separators ensure no spaces after colons or commas. `ensure_ascii=True` prevents Unicode variation.

**`canonical_hash(data)`** — SHA-256 of `canonical_dumps()`. This is the core comparison mechanism.

**`hashes_match(data_a, data_b)`** — Computes canonical hashes of both inputs and compares them using `hmac.compare_digest()` (constant-time). Returns `(match, hash_a, hash_b)`.

---

## 10. Consensus Verifier — Layer C

**File:** `sovereign_mcp/consensus.py` (254 lines)

Layer C is the dual-model structured JSON consensus. Two independent LLMs process the same tool output and produce structured data. Their outputs are canonically normalized and hashed. **Hash match = accept. Hash mismatch = decline.** The models are probabilistic; the decision is deterministic.

### `ModelProvider` — Abstract Base

The abstract base class for LLM backends. Subclass this for OpenAI, Gemini, Ollama, etc.

**`__init__(model_id, temperature)`** — Stores the model ID and temperature. **Enforces `temperature=0`** — if you pass any other value, it raises `ValueError`. Temperature > 0 introduces randomness, which would cause Model A to produce different output each time, leading to false rejections. The model ID and temperature are stored as name-mangled private attributes (`self.__model_id`, `self.__temperature`) with read-only properties, preventing modification after construction.

**`extract_structured(content, schema)`** — Abstract method. Subclasses implement this to call their LLM with the tool output and frozen schema, returning structured JSON.

### `MockModelProvider`

A testing implementation that returns a fixed response. Has `set_response()` to change what it returns.

### `ConsensusVerifier`

**`__init__(model_a, model_b)`** — Takes two `ModelProvider` instances. **Enforces model diversity** — if both use the same `model_id`, it raises `ValueError` with the message `"Same model = same output = tautology (comparing X to X)"`. Also re-verifies both temperatures are 0.

**`verify(tool_output, frozen_schema, verification_source)`** — The main verification method:

1. Model A processes `tool_output` with the frozen schema → `output_a`
2. Model B processes either `tool_output` or an independent `verification_source` (Countermeasure 2) → `output_b`
3. Both outputs are canonically hashed via `hashes_match()`
4. Match → accepted. Mismatch → declined.

If either model throws an exception, the result is an automatic mismatch (fail-safe). The `verification_source` parameter enables independent source verification — Model B can verify the tool's output against a different data source entirely.

### `ConsensusResult`

An immutable result object using `__slots__` and `object.__setattr__()` for construction. After `_initialized` is set to `True`, any further `__setattr__` calls raise `AttributeError`. A `__delattr__` override also prevents attribute deletion. Contains: `match`, `hash_a`, `hash_b`, `output_a`, `output_b`, `reason`, `latency_ms`, `used_independent_source`.

---

## 11. Consensus Cache

**File:** `sovereign_mcp/consensus_cache.py` (242 lines)

Performance optimization (Phase 9, Strategy A). Running dual-model consensus on every call is expensive. The cache stores results for identical inputs to avoid redundant LLM calls.

### `ConsensusCacheEntry`

Immutable (same `__slots__` + `object.__setattr__` pattern, with `__delattr__` override). Stores: `match`, `hash_a`, `hash_b`, `reason`, `created_at`, `ttl`, `tool_name`. Has an `is_expired` property that checks `(now - created_at) > ttl`.

### `ConsensusCache`

**`__init__(default_ttl, max_entries)`** — Default TTL is 300 seconds (5 minutes). Max entries is 10,000. Thread-safe via `threading.Lock()`.

**`_make_key(tool_name, input_params)`** — Generates a cache key by recursively sorting the input params dict (via `_sort_recursive()`), serializing to canonical JSON, and SHA-256 hashing. Uses `default=str` to handle non-serializable params without crashing (Bug M-21).

**`get(tool_name, input_params)`** — Thread-safe lookup. Returns `None` on miss or expiry (expired entries are deleted on access). Tracks `_hits` and `_misses` for statistics.

**`put(tool_name, input_params, consensus_result, ttl)`** — Thread-safe insert. Every 10th `put` call triggers `_sweep_expired()` to clean up expired entries (Bug M-26). If at capacity, `_evict_oldest()` removes the oldest 10% of entries.

**`invalidate(tool_name)`** — Clears cache entries. If `tool_name` is provided, only entries for that tool are cleared. If `None`, the entire cache is cleared. Called when a tool is updated or a security incident occurs.

**`stats`** — Property returning `{entries, hits, misses, hit_rate_pct, max_entries, default_ttl}`.

---

## 12. Output Gate

**File:** `sovereign_mcp/output_gate.py` (447 lines)

The Output Gate is the **central orchestrator** of the entire verification chain. Every tool output passes through this single class, which executes all checks in a fixed order and produces an immutable `GateResult`. This is the "one gate" through which everything flows.

### `OutputGate` Class

**`__init__(frozen_registry, consensus_verifier, audit_log, incident_responder, rate_limiter, identity_checker, consensus_cache)`** — Takes references to every subsystem. All are optional except `frozen_registry` — this allows flexible deployment (e.g., skip consensus in development).

**`verify(tool_name, tool_output, input_params, caller_identity, caller_token)`** — The main entry point. Executes the following checks **in order**, stopping at the first failure:

1. **Registration check** — Is the tool registered in the frozen registry? If not, immediate decline.
2. **Quarantine check** — Has the tool been quarantined by the incident responder (due to a previous security incident)? If so, immediate decline.
3. **Rate limiting** — If the tool's frozen definition includes `RATE_LIMITS` (with `max_per_minute` and/or `max_per_hour`), check with the `RateLimiter`. Over the limit → decline.
4. **Integrity verification** — Recompute the tool's definition hash and compare to the stored hash. Tampered → decline.
5. **Value constraints** — Check input parameters against frozen numeric limits (e.g., `amount` ≤ 10000). Exceeded → decline.
6. **Layer A: Schema Validation** — Validate tool output against the frozen output schema. Invalid → decline.
7. **Layer B: Deception Detection** — Scan tool output for prompt injection patterns. Detected → decline.
8. **PII Detection** — Scan for SSNs, credit cards, API keys, etc. Detected → decline.
9. **Content Safety** — Scan for violent, harmful, or illegal content. Detected → decline.
10. **Domain Check** — If the tool has `ALLOWED_DOMAINS`, scan output for URLs and verify all domains are allowed. Prohibited domain → decline.
11. **Layer C: Consensus Verification** — Run dual-model consensus (or check cache). Mismatch → decline.
12. **Layer D: Behavioral Floor / Hallucination Detection** — (Extensibility point for future checks.)

Each failure triggers `_log_incident()`, which writes to both the `AuditLog` (hash-chained) and the `IncidentResponder` (which may quarantine the tool or send alerts).

### `GateResult`

An immutable result object (same `__slots__` + `object.__setattr__` pattern, with `__delattr__` override). Contains: `accepted` (bool), `tool_name`, `layer` (which layer made the final decision), `reason`, `latency_ms`, `consensus_match` (bool or None), `detections` (list of any findings from scanners).

---

## 13. Identity Checker

**File:** `sovereign_mcp/identity_checker.py` (122 lines)

Part of the 13 Audit Checks (Check 9). Verifies that the **caller** (agent, user, or service) is authorized to invoke a specific tool. Operates on a register-then-freeze lifecycle.

### `IdentityChecker` Class

**`__init__()`** — Creates a mutable identity store (`self._identities = {}`) and a name-mangled frozen flag (`self.__frozen = False`). Name mangling prevents external code from doing `checker._frozen = False` to unfreeze it.

**`register_identity(identity_id, token, allowed_tools)`** — Registers an authorized identity. The raw token is **never stored** — only its SHA-256 hash. The `allowed_tools` list (optional) restricts which tools this identity can invoke. If `None`, the identity can invoke any tool.

**`freeze()`** — Converts `self._identities` from a regular dict to `types.MappingProxyType` — Python's built-in read-only dict wrapper. After this, no new identities can be injected.

**`verify(identity_id, token, tool_name)`** — Three-step verification:
1. Does the identity exist? (Unknown → decline)
2. Does the token hash match? Uses `hmac.compare_digest()` for constant-time comparison — prevents timing attacks that could brute-force tokens by measuring response time.
3. Is this identity authorized for this specific tool? (If `allowed_tools` is set and the tool isn't in the list → decline)

---

## 14. Input Sanitizer

**File:** `sovereign_mcp/input_sanitizer.py` (206 lines)

Part of the 13 Audit Checks (Check 12). Unlike the Schema Validator (which **rejects** bad inputs), the Input Sanitizer **actively cleans** inputs by stripping dangerous characters. This provides defense-in-depth: validation catches known bad patterns, sanitization cleans edge cases that might slip through.

### Pre-compiled Patterns

7 categories of dangerous patterns, all compiled at module load:

- **`_SQL_KEYWORDS`** — `UNION SELECT`, `DROP TABLE`, `DELETE FROM`, `INSERT INTO`, `xp_cmdshell`, etc.
- **`_SQL_COMMENTS`** — `--`, `/*`, `*/`, `;`
- **`_HTML_TAGS`** — Any `<...>` tag
- **`_SCRIPT_TAGS`** — `<script>...</script>` blocks (including multiline via `re.DOTALL`)
- **`_EVENT_HANDLERS`** — HTML event attributes: `onclick=`, `onload=`, `onerror=`, etc.
- **`_SHELL_META`** — Shell metacharacters: `;`, `&`, `|`, `` ` ``, `$`, `(`, `)`, `{`, `}`, `!`, `>`, `<`
- **`_NULL_BYTES`** — Null byte injection (`\x00`)
- **`_ZERO_WIDTH`** — Zero-width Unicode characters (used to hide content from visual inspection): U+200B through U+FEFF
- **`_PATH_TRAVERSAL`** — `../`, `..\`, URL-encoded variants (`%2e%2e%2f`)
- **`_DOUBLE_ENCODED`** — Double URL-encoding attacks (Bug M-09): `%252e` (which decodes to `%2e`, which decodes to `.`)

### `InputSanitizer` Class

**`sanitize_string(value, mode)`** — Three modes:
- `"minimal"` — Only removes null bytes and zero-width chars
- `"standard"` (default) — Also removes SQL injection, HTML/script tags, event handlers, path traversal, double encoding
- `"strict"` — Everything in standard + shell metacharacters

Returns `(sanitized_value, changes)` where `changes` is a list of what was removed (e.g., `["sql_keywords_removed", "path_traversal_removed"]`).

**`sanitize_params(params, mode)`** — Recursively sanitizes all string values in a dict. Handles nested dicts, lists, and lists of dicts. Returns `(sanitized_params, all_changes)` where `all_changes` maps parameter names to their removal lists.

---

## 15. Domain Checker

**File:** `sovereign_mcp/domain_checker.py` (176 lines)

Part of the 13 Audit Checks (Check 5). Validates URLs and domains found in tool output against frozen whitelist/blacklist rules.

### `DomainChecker` Class

**`__init__(whitelist, blacklist)`** — Lists are stored as tuples (immutable). Whitelist takes precedence: if a whitelist is defined, ONLY whitelisted domains are allowed (blacklist is ignored).

**`check_domain(domain)`** — Lowercased comparison with wildcard support via `fnmatch.fnmatch()`. The pattern `*.example.com` matches `api.example.com` but not `example.com` itself.

**`check_url(url)`** — Extracts the hostname using `urllib.parse.urlparse()`, then calls `check_domain()`. If the URL can't be parsed or has no hostname, it's blocked (fail-safe).

**`check_content(content)`** — Scans a string for all URLs using a pre-compiled regex, checks every domain found. Returns `(all_allowed, violations)`.

**`check_dict(data, depth, max_depth)`** — Recursive scanning of nested structures, same pattern as the detectors.

---

## 16. Rate Limiter

**File:** `sovereign_mcp/rate_limiter.py` (119 lines)

Part of the 13 Audit Checks (Check 8). Enforces per-tool rate limits using a sliding window. Even if all verification layers pass, a tool that's been called too many times gets blocked.

### `RateLimiter` Class

**`__init__()`** — Creates `self._calls = {}` (tool_name → deque of timestamps) and a `threading.Lock()` for thread safety.

**`check(tool_name, max_per_minute, max_per_hour)`** — Records the current timestamp and checks:
1. Count calls in the last 60 seconds vs `max_per_minute`
2. Count calls in the last 3600 seconds vs `max_per_hour`
3. If either limit is exceeded → decline

Timestamps are stored in a `collections.deque()`. Old entries (>1 hour) are pruned only when the deque exceeds 1000 entries, to avoid pruning overhead on every call (performance heuristic).

**`get_usage(tool_name)`** — Returns `{calls_last_minute, calls_last_hour}`.

**`reset(tool_name)`** — Clears rate limit counters for a tool (or all tools if `None`).

---

## 17. Value Constraints

**File:** `sovereign_mcp/value_constraints.py` (92 lines)

Countermeasure 1 from the architecture doc. Hard numeric limits per action parameter, frozen in FrozenNamespace. Pure deterministic number comparison — no model judgment, no AI.

### `ValueConstraintChecker` Class

**`check(params, constraints)`** — For each constrained parameter:
1. Skip if the parameter isn't in the input (missing params aren't violations)
2. Skip non-numeric values and booleans (booleans are technically `int` subclasses in Python)
3. **Reject `NaN` and `Infinity`** — `NaN > max` is always `False` in Python, meaning NaN would silently bypass all max checks. This is Bug M-06.
4. Check `max`: `value > max_val` → decline
5. Check `min`: `value < min_val` → decline

The constraints come from the frozen tool definition, so even if both consensus models say "this amount is correct," a $50,000 transfer still gets blocked by a $10,000 hard ceiling.

---

## 18. Human Approval

**File:** `sovereign_mcp/human_approval.py` (165 lines)

Countermeasure 3. Above a frozen value threshold, require human approval before execution. Below the threshold, automatic execution with all four verification layers. The timeout defaults to DECLINE (fail-safe).

### `HumanApprovalChecker` Class

**`check(params, approval_thresholds)`** — For each parameter with an approval threshold:
1. **Reject NaN/Infinity** — NaN > auto_max is always False, meaning NaN would silently auto-approve any amount.
2. If `value > auto_approve_max` → generate a unique `pending_id`, store a `PendingApproval` record, return `(False, reason, pending_id)`.
3. If no thresholds defined or all values within limits → `(True, reason, None)`.

**`approve(pending_id)`** — Called when a human approves. Checks timeout first — if too much time has passed, returns decline even if the human says "yes" (prevents stale approvals).

**`deny(pending_id)`** — Explicit denial by human.

**`check_timeout(pending_id)`** — Checks if a pending request has expired. Expired requests are auto-DECLINED (fail-safe: if the operator is unavailable, nothing happens).

### `PendingApproval`

Simple data class tracking: `param_name`, `value`, `threshold`, `timeout_seconds`, `created_at`.

---

## 19. Permission Checker

**File:** `sovereign_mcp/permission_checker.py` (95 lines)

Step 3 of the runtime verification flow. Deterministic capability and target validation — binary lookup against the frozen registry.

### `PermissionChecker` Class

**`check(tool_name, action, target, frozen_registry)`** — Four-step check:

1. **Is the tool registered?** — `frozen_registry.is_registered()`. Unknown tools → decline.
2. **Is the tool's integrity valid?** — `frozen_registry.verify_tool_integrity()`. Tampered → decline.
3. **Does the tool have this capability?** — `action in tool.CAPABILITIES`. The capability list is frozen in the FrozenNamespace. If the list is empty, NO actions are allowed.
4. **Is the target allowed?** — The target path/URL is **normalized** via `posixpath.normpath()` to prevent traversal attacks (e.g., `/data/../etc/passwd` normalizes to `/etc/passwd`, which no longer matches the `/data/*` wildcard). Supports both exact matches and prefix wildcards (`/data/*` matches `/data/users.json`).

---

## 20. Audit Log

**File:** `sovereign_mcp/audit_log.py` (204 lines)

Part of Phase 7: Incident Response Pipeline. Every verification decision and every incident is logged with a **hash chain** for tamper detection. Each entry includes the SHA-256 hash of the previous entry. If an attacker deletes or modifies any log entry, the chain breaks and the tampering is detectable.

### `AuditLog` Class

**`__init__(log_file)`** — Creates an empty entry list with a genesis hash (`"0" * 64`). If `log_file` is provided, entries are also appended to a file on disk (one JSON line per entry) for persistent storage.

**`log_incident(tool_name, layer, severity, reason, tool_output, input_params)`** — Logs a security incident. Generates a unique `incident_id` (UUID), captures timestamp (both epoch and ISO-8601), and records what happened. Tool output is truncated to 10,000 characters and input params to 5,000 characters to prevent log flooding from massive payloads. Truncation is done **before** JSON serialization break points to avoid invalid JSON fragments. Returns the incident ID.

**`log_verification(tool_name, accepted, layer, latency_ms, reason)`** — Logs every verification result, both accepts and declines. This creates a complete audit trail of all tool interactions.

**`_append(entry)`** — The hash-chaining core. Thread-safe (via `threading.Lock()`):
1. Sets `entry["previous_hash"]` to `self._last_hash` (chain link)
2. Serializes the entry to canonical JSON (sorted keys, compact separators)
3. Computes SHA-256 of the serialized entry → `entry["entry_hash"]`
4. Appends to `self._entries` and updates `self._last_hash`
5. If a log file is configured, **re-serializes** the entry with the `entry_hash` included and appends to the file. The re-serialization is important — the file must contain self-verifiable entries.

**`verify_chain()`** — Walks the entire entry list, verifying two things for each entry:
1. The `previous_hash` matches the `entry_hash` of the previous entry (chain continuity)
2. The `entry_hash` matches a recomputed hash of the entry's content (entry integrity)

Both comparisons use `hmac.compare_digest()` (constant-time). Returns `(is_valid, broken_at)` where `broken_at` is the index of the first broken entry, or `None` if the chain is intact.

**`get_incidents(severity, tool_name, limit)`** — Query interface with optional filters. Returns most recent first. Returns **copies** of entries (not references) to protect the hash chain from external mutation.

---

## 21. Incident Response

**File:** `sovereign_mcp/incident_response.py` (337 lines)

Implements the five-stage incident response pipeline from the architecture doc.

### `Incident` Class

Uses `__slots__` for memory efficiency. Stores: `incident_id` (UUID), `severity`, `tool_name`, `layer`, `reason`, `timestamp`, `forensic_data` (dict), `response_actions` (list of what was done), `resolved` (bool), `resolved_at`.

### `IncidentResponder` Class

**Classification Map (`SEVERITY_MAP`)** — Maps verification layer names to severity levels:
- `layer_d_behavioral` → CRITICAL
- `layer_c_consensus`, `pii_detection`, `content_safety`, `identity_check`, `hallucination` → HIGH
- `layer_b_deception`, `rate_limit`, `domain_check` → MEDIUM
- `layer_a_schema`, `pre_check` → LOW

Unknown layers default to HIGH (fail-safe).

**`__init__(alert_callback, escalation_threshold, auto_quarantine_on_critical)`** — `alert_callback` is a callable that receives an incident dict (for PagerDuty, Slack, email, etc.). `escalation_threshold` (default 5) is how many MEDIUM incidents before auto-escalation to HIGH. `auto_quarantine_on_critical` (default True) auto-quarantines tools on CRITICAL incidents.

**`report(tool_name, layer, reason, forensic_data)`** — Stages 1+2+3 combined:
1. **Detection** — Incident has been caught (by OutputGate)
2. **Classification** — Look up severity from `SEVERITY_MAP`. If the tool has accumulated ≥ `escalation_threshold` MEDIUM incidents, escalate to HIGH. The count check and increment are inside the lock to prevent TOCTOU race conditions (Bug M-13).
3. **Forensic Capture** — Store all context in an `Incident` object.

Then calls `_respond()` for Stage 4.

**`_respond(incident)`** — Stage 4: Automated response based on severity:
- **CRITICAL** — Quarantine tool + send alert + recommend process quarantine
- **HIGH** — Quarantine tool + send alert + flag for investigation
- **MEDIUM** — Log pattern (escalation already handled)
- **LOW** — Log only

**`quarantine_tool(tool_name)` / `release_tool(tool_name)`** — Add/remove tools from the quarantine set. While quarantined, the OutputGate blocks all calls to that tool.

**`resolve(incident_id, resolution_notes)`** — Stage 5: Mark an incident as resolved with notes on what was done.

**`get_incidents(severity, tool_name, resolved, limit)`** — Query with filters. Returns most recent first.

**`stats`** — Property: `{total_incidents, by_severity, quarantined_tools, unresolved}`.

---

## 22. Sandbox Registry

**File:** `sovereign_mcp/sandbox_registry.py` (347 lines)

Handles **dynamically discovered tools** at runtime. When a new tool appears (e.g., a new MCP server exposes a tool that wasn't known at freeze time), it goes into the sandbox. Sandbox tools have **NO execution privileges** — they cannot be used in production until they pass validation, approval, and a new freeze cycle.

### `SandboxTool` Class

Uses `__slots__`. Tracks: `name`, `definition`, `status` (lifecycle state), `discovered_at`, `validated_at`, `approved_at`, `approved_by`, `validation_results`, `incident_count`, `emergency_mode`, `sandbox_id` (UUID).

Status progression: `DISCOVERED` → `VALIDATED` → `APPROVED` → `EXPORTED` (or `VALIDATION_FAILED` / `EMERGENCY`).

### `SandboxRegistry` Class

**`__init__(validation_policies)`** — Accepts a policy dict: `max_capabilities`, `blocked_capabilities`, `require_output_schema`, `require_input_schema`, `max_description_length`.

**`discover(tool_name, tool_definition)`** — Stage 1. Places a new tool in the sandbox. Returns a sandbox ID for tracking.

**`validate(tool_name)`** — Stage 2. Runs 6 validation checks:
1. Capabilities count ≤ `max_capabilities` (default 20)
2. No blocked capabilities (e.g., `admin`, `sudo`, `root`)
3. Input schema present (if required by policy)
4. Output schema present (if required by policy)
5. Description length ≤ `max_description_length` (default 1000)
6. Description doesn't contain suspicious patterns (prompt injection in the tool description itself — `"ignore previous"`, `"<script>"`, `"eval("`)

Returns `(passed, results)` where `results` has `checks_passed`, `checks_failed`, and `warnings`.

**`approve(tool_name, approved_by)`** — Stage 3. Only works on `VALIDATED` tools. Records who approved.

**`export_approved()`** — Stage 4. Returns all `APPROVED` tools as `(name, definition)` tuples for the next freeze cycle.

**`enable_emergency(tool_name)`** — Stage 5. Emergency mode allows restricted execution with heightened scrutiny — all inputs/outputs logged, rate limited, full 4-layer verification, flagged for priority freeze. But NEVER gets full frozen-registry privileges.

**`history`** — Full audit trail of all sandbox actions (DISCOVER, VALIDATE, APPROVE, EXPORT, EMERGENCY, REMOVE).

---

## 23. Tool Updater

**File:** `sovereign_mcp/tool_updater.py` (481 lines)

Handles legitimate tool updates (new version, updated capabilities) without compromising frozen reference integrity. Uses a **blue-green deployment** pattern: the current frozen registry (v1) is NEVER modified in place. Updates create a NEW frozen registry (v2) in a NEW process.

### `ToolUpdateAnalysis` Class

Result of comparing v1 and v2 tool definitions. Tracks: `changes` (list of descriptions), `capabilities_added`, `capabilities_removed`, `schema_changed`, `schema_fields_added`, `schema_fields_removed`, `schema_types_changed`, `requires_manual_approval`, `auto_approve_reason`, `risk_level_changed`, `v1_hash`, `v2_hash`.

**`is_safe_update`** — Property: `not self.requires_manual_approval`.

### `ToolUpdater` Class

**`analyze_update(v1_definition, v2_definition)`** — Comprehensive diff analysis:
- **Capabilities added** → requires manual approval (capability expansion = new attack surface)
- **Capabilities removed** → safe, can auto-approve
- **Output schema fields added/removed** → requires manual approval
- **Output field types changed** → requires manual approval
- **Input schema modified** → requires manual approval (new attack surface)
- **Risk level changed** → requires manual approval
- **Allowed targets expanded** → requires manual approval
- **Allowed targets reduced** → safe
- **Description updated** → noted but doesn't require approval

If only safe changes (removals, description updates): auto-approve. Any expansion or structural change: manual review required.

**`approve_update(analysis, approver)`** — Approves a pending update. If `requires_manual_approval` is true and `approver` is `"auto"`, rejects the approval — humans must explicitly approve dangerous updates.

**`prepare_freeze_cycle(current_definitions, approved_updates)`** — Merges current frozen definitions with approved updates via deep copy. Returns a new definition dict ready for `ToolRegistry.register()` → `freeze()`.

**`create_rollback_snapshot(frozen_registry)`** — Extracts all tool definitions from the current frozen registry and stores them in a snapshot dict. Returns a `snapshot_id` for later rollback.

**`rollback(snapshot_id)`** — Returns a deep copy of the snapshot's definitions, ready to re-freeze. If the snapshot doesn't exist, raises `KeyError`.

**`get_update_history(tool_name, limit)`** — Query update analysis history.

---

## 24. Transport Security

**File:** `sovereign_mcp/transport_security.py` (451 lines)

Enforces **mutual TLS (mTLS)** for all network MCP connections. The CA certificate is frozen at startup and cannot be modified at runtime, extending the root of trust to the transport layer. An attacker cannot substitute a fake CA.

### `TransportSecurity` Class

**`__init__(ca_cert_path, client_cert_path, client_key_path, revocation_list, max_cert_age_hours)`** — Accepts paths to certificates and a list of revoked certificate serial numbers. `max_cert_age_hours` (default 24) enforces short-lived certificates.

**`freeze()`** — Reads the CA certificate from disk, computes its SHA-256 hash, and stores both the raw bytes and the hash. Optionally hashes the client certificate. After this, the certificates cannot be changed. Attempting to freeze twice raises `RuntimeError` — certificate rotation requires blue-green deployment (new process with new certs).

**`verify_ca_integrity()`** — Re-reads the CA cert file from disk and compares its hash to the frozen hash using `hmac.compare_digest()`. Detects post-freeze tampering.

**`create_client_context()`** — Creates an `ssl.SSLContext` for outgoing connections:
- TLS 1.2 minimum
- Server certificate validated against frozen CA
- Client certificate presented for mutual authentication
- `CERT_REQUIRED` + `check_hostname = True`
- No fallback to unencrypted

**`create_server_context(server_cert_path, server_key_path)`** — Creates an `ssl.SSLContext` for incoming connections:
- TLS 1.2 minimum
- Client certificate validated against frozen CA (mutual TLS)
- `CERT_REQUIRED` (not optional — no fallback)

**`validate_connection(ssl_socket)`** — Validates an established SSL connection:
1. Peer certificate must be present (mutual TLS)
2. Certificate serial number not in revocation list
3. TLS version is ≥ 1.2
4. Certificate age within `max_cert_age_hours` (parses `notBefore` from the cert, computes age in hours). This is Bug H-18 — enforcing short-lived certificates to limit the window of a compromised cert.

**`generate_channel_binding_token(ssl_socket)`** — Generates a token from the TLS `tls-unique` channel binding data. This value is unique to the specific TLS session — an attacker who terminates and re-establishes the connection gets a different value. SHA-256 hashed. If `tls-unique` is unavailable, returns `None` (no unsafe fallback — Bug H-19 fixed by removing a cert DER hash fallback that wasn't session-unique).

**`verify_channel_binding(ssl_socket, expected_token)`** — Verifies a channel binding token using `hmac.compare_digest()`. Mismatch = possible MITM attack.

**`is_local_connection(connection_type)`** — Returns `True` for `"stdio"`, `"pipe"`, `"local"` — these don't need encryption. Non-string inputs return `False` (fail-safe — non-string connection types are never treated as local).

**`revoke_certificate(serial_number)`** — Allows post-freeze certificate revocation without a process restart. The revocation list is append-only by design — revocations can be added but never removed. Returns `(success, reason)`.

**`enforce_policy(connection_type, ssl_socket)`** — The enforcement entry point:
- Local → allowed without encryption
- Network without frozen transport → CONNECTION REFUSED
- Network without SSL socket → CONNECTION REFUSED (no fallback to plain TCP)
- Network with SSL socket → validate the connection

---

## 25. Frozen Memory — C Extension

**File:** `sovereign_mcp/frozen_memory.c` (418 lines)

The hardware memory protection layer. This C extension allocates **dedicated memory pages** and marks them **read-only at the OS level** using `mprotect()` (Unix) or `VirtualProtect()` (Windows). Any write attempt — from Python, ctypes, C extensions, or even raw assembly — triggers a hardware fault (`SIGSEGV` on Unix, `ACCESS_VIOLATION` on Windows). This is protection that Python-level immutability cannot provide.

### Low-Level Functions

**`constant_time_compare(a, b, len)`** — Compares two byte arrays in constant time by ORing all XOR differences together. Unlike `memcmp()`, this always compares ALL bytes regardless of where the first mismatch is. Prevents timing side-channel attacks.

**`secure_wipe(ptr, size)`** — Zeros memory using a `volatile` pointer, which forces the compiler to execute the writes. Without `volatile`, the compiler may optimize away the zeroing because it sees the memory is about to be freed and considers the writes "unnecessary." This ensures sensitive data is actually erased.

**`get_page_size()`** — Returns the OS memory page size (typically 4096 bytes) via `GetSystemInfo()` (Windows) or `sysconf(_SC_PAGESIZE)` (Unix).

**`alloc_page(size)`** — Allocates page-aligned memory via `VirtualAlloc(MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)` (Windows) or `mmap(PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS)` (Unix).

**`protect_page(ptr, size)`** — Marks memory as read-only: `VirtualProtect(PAGE_READONLY)` (Windows) or `mprotect(PROT_READ)` (Unix). **This is the critical step.**

**`unprotect_page(ptr, size)` / `free_page(ptr, size)` / `check_protection(ptr, size)`** — Reverse protection, free memory, and query protection status (Windows only via `VirtualQuery()`).

### `FrozenBuffer` Python Type

A custom Python type (not instantiable from Python — `tp_new = NULL`). Only `freeze()` can create instances.

Properties:
- **`data`** — Returns a copy of the frozen bytes (via `PyBytes_FromStringAndSize()`). This is a copy, not a reference — the original memory stays behind the read-only protection.
- **`size`** — Data size in bytes.
- **`protected`** — Whether the memory page is currently read-only.

Deallocation (`FrozenBuffer_dealloc()`): unprotects the page, secure-wipes it, then frees it. This ensures sensitive data doesn't linger in memory after the buffer is garbage collected.

### Module Functions

**`freeze(data: bytes) -> FrozenBuffer`** — The main entry point:
1. Calculate page-aligned allocation size (round up to next page boundary)
2. Allocate the page(s)
3. Copy data into the page
4. Zero any remaining space in the page
5. Mark read-only via `protect_page()` — **the critical step**
6. Create and return a `FrozenBuffer` object

**`verify(buffer, expected_hash: bytes) -> bool`** — Computes SHA-256 of the buffer's data (using Python's `hashlib` for auditability) and compares to the expected hash using `constant_time_compare()`.

**`is_protected(buffer) -> bool`** — On Windows, queries the OS via `VirtualQuery()` to check the actual page protection flags. On Unix, falls back to the internal `is_protected` flag (querying `/proc/self/maps` is Linux-specific and fragile).

**`destroy(buffer)`** — Explicit destruction: unprotect → secure wipe → free. Sets all pointers to NULL.

**`page_size() -> int`** — Returns the OS page size.

---

## 26. Frozen Memory — Python Fallback

**File:** `sovereign_mcp/frozen_memory_fallback.py` (304 lines)

Pure-Python ctypes implementation providing the **same API** as the C extension. Used when the C extension cannot be compiled (e.g., no C compiler on the deployment machine, or running in a restricted environment).

### Platform Setup

On Windows, loads `kernel32.dll` and sets up ctypes wrappers for `VirtualAlloc`, `VirtualProtect`, `VirtualFree`, `VirtualQuery`, and `GetSystemInfo` with correct `restype` and `argtypes` declarations. Defines `SYSTEM_INFO` and `MEMORY_BASIC_INFORMATION` as `ctypes.Structure` subclasses with all required fields.

On Unix (Linux/macOS), loads libc via `ctypes.util.find_library("c")` and wraps `mmap`, `mprotect`, and `munmap`. Handles the macOS vs Linux difference for `MAP_ANONYMOUS` (0x20 on Linux, 0x1000 on macOS).

### `FrozenBuffer` Class

Uses `__slots__` for efficiency. Has `data`, `size`, and `protected` properties matching the C extension's API exactly. The `__del__` method guards against interpreter shutdown (ctypes may be unavailable during garbage collection at exit).

### Public Functions

**`freeze(data)`**, **`verify(buffer, expected_hash)`**, **`is_protected(buffer)`**, **`destroy(buffer)`**, **`page_size()`** — All mirror the C extension API exactly. The `verify()` function uses `hmac.compare_digest()` for constant-time comparison. The `destroy()` function follows the same secure pattern: unprotect → zero via `ctypes.memset()` → free.

The key security difference from the C extension: ctypes must remain available in the Python process. An attacker who can import ctypes can potentially unprotect the memory. The C extension is more secure because the protection is enforced at the compiled level.

---

## 27. Hardware Protection Wrapper

**File:** `sovereign_mcp/hardware_protection.py` (77 lines)

Auto-loading wrapper that provides a unified API regardless of which backend is available. This is what the rest of the codebase imports.

### Loading Logic

Three-tier fallback:
1. Try to import the C extension (`frozen_memory`) → `BACKEND = "c_extension"` (most secure)
2. If that fails, try the ctypes fallback (`frozen_memory_fallback`) → `BACKEND = "ctypes_fallback"` (still OS-level protection)
3. If both fail → `BACKEND = "none"` + warning (Python-level `FrozenNamespace` protection only)

### Public Functions

**`is_available()`** — Returns `True` if either backend loaded.

**`freeze(data)`**, **`verify(buffer, expected_hash)`**, **`is_protected(buffer)`**, **`destroy(buffer)`**, **`page_size()`** — All delegate to the loaded backend. If no backend is available, all raise `RuntimeError`. `page_size()` returns 4096 as a default fallback if no backend.

---

## Architecture Summary

The entire codebase follows a consistent set of design principles:

1. **Fail-safe defaults** — Unknown input → decline. Missing config → most restrictive. Timeout → deny. NaN/Infinity → reject.

2. **Immutability** — Tool definitions are frozen via `FrozenNamespace` metaclass. Mutable containers are deep-copied on access (with caching for performance). Results are immutable via `__slots__` + `object.__setattr__()` + `__delattr__()`. The identity registry uses `MappingProxyType`. Patterns are pre-compiled into frozen tuples via factory functions.

3. **Constant-time comparisons** — Every hash comparison uses `hmac.compare_digest()` to prevent timing attacks. The C extension has its own `constant_time_compare()`.

4. **Deterministic decisions** — Every accept/reject is a deterministic comparison: hashes match or don't, schemas validate or don't, patterns are found or aren't. The LLMs in consensus are probabilistic, but the DECISION (hash comparison) is deterministic.

5. **Defense in depth** — Multiple independent checks, any of which can reject. Schema validation + deception detection + PII scanning + content safety + consensus verification. Input sanitization + input validation. Integrity lockfile + runtime hash verification.

6. **Thread safety** — All shared state is protected by `threading.Lock()`. Critical sections are as small as possible. TOCTOU prevention in incident escalation.

7. **Audit trail** — Hash-chained log for tamper detection. Every verification decision logged. Every incident captured with forensic data.

---

*Total codebase: 27 modules, ~5,500 lines of Python + 418 lines of C. Zero external dependencies (stdlib only).*
