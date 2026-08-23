#!/bin/bash
# Audit one MCP server inside the container.
#
#   audit_one.sh <npm|pypi> <identifier> [extra args for the server...]
#
# The auditor lives in /opt/auditor, owned by root and not writable here. The
# target gets its own environment under /work. That separation matters: `pip
# install` and `npm install` execute arbitrary code from the package, and a
# hostile setup.py should not be able to reach into the tool that is inspecting
# it.
#
# Writes /out/<slug>.json and /out/<slug>.txt. A finding is not a container
# failure: the batch runner has to tell "found something" apart from "the
# container broke", so exit 0 covers both clean and findings.
set -uo pipefail

KIND="${1:-}"; IDENT="${2:-}"; shift 2 || true
if [[ -z "$KIND" || -z "$IDENT" ]]; then
  echo "usage: audit_one.sh <npm|pypi> <identifier> [server args...]" >&2
  exit 64
fi

SLUG="$(echo "$IDENT" | tr '/@' '__' | tr -cd '[:alnum:]_.-')"
LOG="/out/${SLUG}.txt"
JSON="/out/${SLUG}.json"

{
  echo "=== target: $KIND $IDENT"
  echo "=== date:   $(date -u +%FT%TZ)"

  if [[ "$KIND" == "npm" ]]; then
    echo "--- npm install"
    if ! timeout 300 npm install --no-audit --no-fund --prefix /work "$IDENT" >/dev/null 2>&1; then
      echo "INSTALL FAILED"; exit 70
    fi
    BIN="$(ls /work/node_modules/.bin 2>/dev/null | head -1 || true)"
    if [[ -z "$BIN" ]]; then echo "NO EXECUTABLE IN PACKAGE"; exit 71; fi
    CMD=(/work/node_modules/.bin/"$BIN")
  else
    echo "--- pip install into a target-owned venv"
    if ! python3 -m venv /work/target >/dev/null 2>&1; then
      echo "VENV FAILED"; exit 70
    fi
    if ! timeout 300 /work/target/bin/pip install --no-cache-dir -q "$IDENT" >/dev/null 2>&1; then
      echo "INSTALL FAILED"; exit 70
    fi
    # Prefer a console script; fall back to `-m module`.
    GUESS="$(echo "$IDENT" | tr '_' '-')"
    if [[ -x "/work/target/bin/$GUESS" ]]; then
      CMD=("/work/target/bin/$GUESS")
    else
      SCRIPT="$(ls /work/target/bin | grep -iv -E '^(pip|python|activate|wheel|easy_install)' | head -1 || true)"
      if [[ -n "$SCRIPT" && -x "/work/target/bin/$SCRIPT" ]]; then
        CMD=("/work/target/bin/$SCRIPT")
      else
        CMD=(/work/target/bin/python3 -m "$(echo "$IDENT" | tr '-' '_')")
      fi
    fi
  fi

  echo "--- launching: ${CMD[*]} $*"
  # A hard timeout on the audit. A server that hangs the handshake looks
  # identical to one that is merely slow, and neither should stall the batch.
  timeout 420 /opt/auditor/bin/sovereign-mcp-audit \
      --quiet --timeout 20 --json "$JSON" -- "${CMD[@]}" "$@"
  RC=$?
  echo "--- auditor exit: $RC"
  # 0 = clean, 1 = findings. But Python exits 1 on an unhandled exception
  # too, so the exit code alone cannot tell a finding from a crash. The
  # report is the evidence: no report means no audit happened, whatever
  # the code said.
  if [[ ! -s "$JSON" ]]; then
    echo "NO REPORT WRITTEN - the audit did not run"
    exit 72
  fi
  if [[ $RC -gt 1 ]]; then exit 72; fi
  exit 0
} 2>&1 | tee "$LOG"
