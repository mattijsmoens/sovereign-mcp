# Security Policy — Sovereign MCP

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Active  |

## Security Properties

Sovereign MCP enforces the following security properties by architecture:

### Immutability Guarantees

- **FrozenNamespace metaclass** — `__setattr__`, `__delattr__`, and `__call__` all blocked on frozen classes
- **Deep-copy on access** — Mutable containers (dict, list, set) are deep-copied on read, with caching for performance
- **Result immutability** — All result classes (`GateResult`, `ConsensusResult`, `ConsensusCacheEntry`, `SchemaValidator`) enforce both `__setattr__` and `__delattr__`
- **Pattern immutability** — All detection patterns compiled into frozen tuples via factory functions at module load

### Timing Attack Prevention

- **All hash comparisons** use `hmac.compare_digest()` (constant-time)
- **C extension** uses custom `constant_time_compare()` with XOR accumulation

### Numeric Bypass Prevention

- **NaN/Infinity** explicitly rejected before all numeric comparisons (`math.isnan()`, `math.isinf()`)
- **Bool subclass** excluded before `isinstance(int)` checks (`isinstance(value, bool)`)
- **NaN sentinel strings** in canonical JSON normalization prevent false consensus

### Supply-Chain Defense

- **Integrity lockfile** hashes all `.py`, `.c`, `.pyd`, and `.so` files
- **Import-time verification** runs before any module code executes
- **HMAC comparison** of file hashes prevents timing side-channels

### Transport Security

- **Mandatory mTLS** for all network connections (no fallback to unencrypted)
- **Frozen CA certificate** — trust anchor cannot be modified at runtime
- **Runtime certificate revocation** via append-only CRL
- **Channel binding tokens** prevent MITM re-establishment attacks

### Thread Safety

- All shared state protected by `threading.Lock()`
- TOCTOU prevention in incident escalation (check + increment inside lock)
- Expired request sweep in human approval prevents memory leaks

## Audit History

| Pass    | Date           | Bugs Found | Bugs Fixed |
|---------|----------------|------------|------------|
| 1-7     | Mar 2026       | 104        | 104        |
| 8 (fresh sweep) | Mar 19, 2026 | 7    | 7          |
| **Total** |              | **111**    | **111**    |

All 27 source files have been read line-by-line across multiple independent audit passes. Zero known open bugs.

## Reporting Vulnerabilities

If you discover a security vulnerability in Sovereign MCP:

1. **Do NOT open a public GitHub issue**
2. Email: mattijsmoens@gmail.com
3. Include: affected module, reproduction steps, potential impact
4. Expected response time: 48 hours

## Known Limitations

### 1. C extension `memcmp()` is not constant-time

When comparing two hashes to verify a frozen buffer's integrity, the C extension (`frozen_memory.c`) uses C's built-in `memcmp()`. This function stops comparing **as soon as it finds a difference** — if byte 1 differs it returns immediately, but if byte 99 differs it takes longer. An attacker measuring response times (microsecond-level) could theoretically determine how many bytes of the hash they got right, narrowing their brute-force search.

The Python fallback (`frozen_memory_fallback.py`) uses `hmac.compare_digest()` instead, which **always compares every byte** regardless of where the mismatch is — same time for "first byte wrong" and "last byte wrong."

**Real-world risk: Very low.** This attack requires extremely precise timing measurements and only applies to the C extension's `verify()` function. The rest of the codebase already uses `hmac.compare_digest()` for all hash comparisons.

### 2. ctypes memory protection can be bypassed by code that can import ctypes

The ctypes fallback (`frozen_memory_fallback.py`) uses OS syscalls (`VirtualProtect` on Windows, `mprotect` on Linux) to mark memory pages as read-only. This is real OS-level protection — a normal Python write will crash with a segfault/access violation.

However, any Python code that can `import ctypes` can call those same syscalls to **un-protect** the memory before writing to it. The C extension is more secure because the protection is managed inside compiled C code — an attacker would need to load their own C extension or use ctypes to bypass it.

**Real-world risk: Low.** If an attacker has enough control to import ctypes and call OS memory APIs, they likely have enough control to do much worse things. This is a defense-in-depth layer, not the primary security boundary.

### 3. Hardware memory protection requires OS-level page allocation support

The `freeze()` function allocates **entire memory pages** from the OS (typically 4096 bytes each) and marks them read-only. Some environments don't support this:

- **Sandboxed/containerized environments** may block `mmap()`/`VirtualAlloc()` syscalls
- **Embedded Python runtimes** may not have ctypes available
- **WebAssembly/Pyodide runtimes** don't support OS memory management

If neither the C extension nor ctypes works, the system falls back to **Python-level protection only** (`FrozenNamespace` metaclass) — which is still strong but doesn't have the hardware-fault guarantee.

**Real-world risk: None in standard deployments.** The primary security comes from `FrozenNamespace` (Python-level immutability) + `hmac.compare_digest()` (constant-time hashes). Hardware memory protection is an extra hardening layer on top.
