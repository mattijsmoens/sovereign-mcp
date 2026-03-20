# Changelog

All notable changes to sovereign-mcp are documented here.

## [1.0.0] — 2026-03-20

### First PyPI Release

Initial public release on PyPI. 27 modules, 4 defense layers, 3 data poisoning countermeasures.

- All v0.1.x pre-release changes (below) included
- Added Patent Pending badge to README
- Added 5 missing modules to README Module Reference table (input_filter, adaptive_shield, truth_guard, conscience, siem_logger)
- Created MANIFEST.in for clean PyPI packaging
- Regenerated integrity lockfile (32 files sealed)
- `pyproject.toml` updated with email, package-data, Beta classifier

## [0.1.2] — 2026-03-19

### InputFilter Detection Improvements — Adversarial Benchmark Hardening

Benchmark-driven improvements targeting three weak detection categories. Overall local test detection jumped from 75% to 83.3% with zero false positives.

#### New Detection Layers

- **Layer 5.5: Persona Hijack / Jailbreak Detection** — New regex-based layer catches DAN, "Do Anything Now", evil AI persona, developer mode, and content filter bypass patterns. Single-match is sufficient (no 2-hit threshold). Detection: 25% → **100%**.
- **Layer 6a: High-Confidence Single-Match Keywords** — `IGNORE PREVIOUS`, `IGNORE ALL INSTRUCTIONS`, `DISREGARD ALL INSTRUCTIONS`, `OVERRIDE SYSTEM PROMPT`, `NEW SYSTEM PROMPT` now trigger on a single hit (previously required 2+). These patterns are virtually never benign.

#### Enhanced Unicode Attack Resistance

- **Combining diacritics stripping** — Unicode category `Mn` (non-spacing marks) stripped in Layer 0, defeating accent obfuscation attacks (e.g., `ì̀g̀ǹo̥ṙe̥` → `ignore`). Detection: 25% → **100%**.
- **Null byte → space replacement** — Control characters (`Cc`) now replaced with spaces instead of stripped, preserving word boundaries so `ignore\x00previous` becomes `ignore previous` and matches keywords.

#### Multilingual Co-occurrence Expansion

- **Multilingual action verbs added** — `IGNORIERE`, `IGNOREZ`, `IGNORA`, `IGNORAR`, `DESACTIVAR`, `SUPPRIMER`, `DEAKTIVIEREN`, `ACTIVA`, `STARTE`, `PASSEZ` added to `_DANGER_ACTIONS` set.
- **Multilingual target nouns added** — `ANWEISUNGEN`, `INSTRUCCIONES`, `ENTWICKLERMODUS`, `DESARROLLADOR`, `DEVELOPPEUR`, `SICHERHEIT`, `SEGURIDAD`, `EINSCHRÄNKUNGEN`, `RESTRICCIONES` added to `_DANGER_TARGETS` set.
- Co-occurrence detection now catches German/French/Spanish injection phrases. Detection: 33% → **100%**.

#### Changes Applied To

- `sovereign_mcp/input_filter.py` (sovereign-mcp package)
- `sovereign_shield/input_filter.py` (SovereignShield package)

## [0.1.1] — 2026-03-19

### Security Fixes — Full Codebase Audit (111 bugs fixed across 9 audit passes)

#### Critical

- **Integrity lock expanded** — `.pyd` and `.so` compiled binaries now included in supply-chain integrity checks (`integrity_lock.py`)

#### Immutability Hardening

- **`__delattr__` overrides added** — `ConsensusResult`, `ConsensusCacheEntry`, `GateResult`, and `SchemaValidator` now block attribute deletion, closing an immutability bypass gap
- **Factory-compiled tuples** — `_PII_PATTERNS` in `pii_detector.py` and `_SAFETY_PATTERNS` in `content_safety.py` now compile directly into immutable tuples via factory functions, eliminating a mutable list window during module load
- **Zero-width regex precompiled** — `deception_detector.py` now uses a module-level `_ZERO_WIDTH_CHARS` constant instead of recompiling on every `scan()` call

#### Security Bypass Prevention

- **NaN/Infinity guards** — All numeric comparisons (`value_constraints.py`, `human_approval.py`, `schema_validator.py`, `canonical_json.py`) now explicitly reject `NaN` and `Infinity` to prevent bypass via IEEE 754 comparison semantics
- **Bool subclass exclusion** — `isinstance(value, bool)` checked before `isinstance(value, int)` across all type validators
- **ReDoS thread leak** — Schema validator regex timeout thread made daemon to prevent process hangs

#### Bug Fixes

- **`transport_security.is_local_connection()`** — Fixed inconsistent return type (returned `(bool, str)` tuple on error vs `bool` on success); now consistently returns `bool`
- **`sandbox_registry.list_tools()`** — Always returns a copy of internal state
- **`audit_log.py`** — Added file-level locking (Windows `msvcrt`, Unix `fcntl`) for multi-process safety; in-memory rollback on write failure
- **`frozen_memory_fallback.py`** — Raw memory addresses redacted from logs (ASLR protection); `is_protected()` now queries OS page status on Linux
- **`frozen_namespace.py`** — Deep-copy caching for mutable containers (performance optimization)
- **`human_approval.py`** — Proactive sweep of expired pending requests; passive timeout check
- **`incident_response.py`** — Escalation count + check moved inside lock (TOCTOU prevention)
- **`deception_detector.py`** — `import os` false-positive tightened; exfiltration patterns tightened

#### New Features

- **`transport_security.revoke_certificate()`** — Runtime certificate revocation without process restart
- **`canonical_json.normalize(preserve_case=True)`** — Optional case preservation for non-consensus use cases
- **Recursive hallucination detection** — `output_gate.py` now recursively scans nested dicts for action hallucination claims

### Documentation

- `README.md` — Updated module reference (all 27 modules), security audit results, NaN sentinel docs
- `API_REFERENCE.md` — Updated 12 module sections to reflect code changes
- `CHANGELOG.md` — Created (this file)
- `SECURITY.md` — Created with security properties and responsible disclosure

## [0.1.0] — 2026-03-01

### Initial Release

- FrozenNamespace metaclass as root of trust
- Four-layer verification chain (Schema, Deception, Consensus, Behavioral)
- 13 audit checks across 27 modules
- Hardware memory protection (C extension + ctypes fallback)
- Hash-chained audit logging
- Blue-green tool update lifecycle
- Mutual TLS transport security
