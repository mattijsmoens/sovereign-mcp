# -*- coding: utf-8 -*-
"""Audit a worklist of MCP servers, each in a throwaway container.

Stage two of the funnel. `npm_sweep.py` produces the worklist; this runs it.

Every target is installed and probed inside a fresh container with no mount
except a write-only output directory. `npm install` and `pip install` execute
arbitrary code from the package, so auditing a few hundred unvetted packages
means running a few hundred unknown codebases. Doing that on a machine holding
PyPI tokens and signing material is not a trade worth making for a shortlist.

Resumable: a target with a report already on disk is skipped, so an interrupted
run continues rather than starting over.

    python batch_audit.py --worklist worklist.json --out reports --workers 3
"""
import argparse
import json
import os
import queue
import subprocess
import sys
import threading
import time

IMAGE = "sovereign-audit:2"


def docker_path(path):
    """Docker on Windows needs a drive-letter path, not an MSYS one.

    Passing /c/Users/... silently creates an anonymous volume: the container
    writes happily and nothing ever appears on the host. The whole batch would
    run and collect nothing.
    """
    return os.path.abspath(path).replace("\\", "/")


def slug_for(identifier):
    out = identifier.replace("/", "__").replace("@", "__")
    return "".join(c for c in out if c.isalnum() or c in "_.-")


def audit_one(row, out_dir, timeout, log):
    ident = row["identifier"]
    kind = "npm" if row.get("registry", "npm") == "npm" else "pypi"
    slug = slug_for(ident)
    report = os.path.join(out_dir, "%s.json" % slug)
    marker = os.path.join(out_dir, "%s.attempted" % slug)

    if os.path.exists(report) or os.path.exists(marker):
        return ident, "skipped", None

    cmd = [
        "docker", "run", "--rm",
        "--network", "bridge",
        "--memory", "2g", "--cpus", "2", "--pids-limit", "512",
        "--security-opt", "no-new-privileges",
        "-v", "%s:/out" % docker_path(out_dir),
        IMAGE, kind, ident,
    ]
    started = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
        rc, tail = proc.returncode, (proc.stdout or "")[-400:]
    except subprocess.TimeoutExpired:
        rc, tail = 124, "timed out after %ds" % timeout
    except Exception as exc:                                # noqa: BLE001
        rc, tail = 125, str(exc)[:200]

    # Record the attempt either way, so a failing target is not retried forever
    # on every resume.
    if not os.path.exists(report):
        with open(marker, "w", encoding="utf-8") as fh:
            fh.write("rc=%s\n%s\n" % (rc, tail))

    status = {0: "ok", 70: "install failed", 71: "no executable",
              72: "audit failed", 124: "timeout"}.get(rc, "rc=%s" % rc)
    log("  %-46s %-16s %4.0fs" % (ident[:46], status, time.time() - started))
    return ident, status, report if os.path.exists(report) else None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--worklist", default="worklist.json")
    ap.add_argument("--out", default="reports")
    ap.add_argument("--workers", type=int, default=3,
                    help="containers at once; each does a full npm install")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--limit", type=int, default=0, help="first N targets only")
    args = ap.parse_args(argv)

    with open(args.worklist, encoding="utf-8") as fh:
        work = json.load(fh)
    if args.limit:
        work = work[:args.limit]
    os.makedirs(args.out, exist_ok=True)

    lock = threading.Lock()

    def log(msg):
        with lock:
            print(msg, flush=True)

    log("auditing %d targets, %d at a time, into %s/\n"
        % (len(work), args.workers, args.out))

    q = queue.Queue()
    for row in work:
        q.put(row)
    results = []

    def worker():
        while True:
            try:
                row = q.get_nowait()
            except queue.Empty:
                return
            try:
                results.append(audit_one(row, args.out, args.timeout, log))
            except Exception as exc:                        # noqa: BLE001
                log("  %-46s worker error: %s" % (row["identifier"][:46], exc))
            finally:
                q.task_done()

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(max(1, args.workers))]
    t0 = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    done = sum(1 for _i, s, _r in results if s == "ok")
    log("\n%d audited, %d could not be, %d skipped, %.0f minutes"
        % (done,
           sum(1 for _i, s, _r in results if s not in ("ok", "skipped")),
           sum(1 for _i, s, _r in results if s == "skipped"),
           (time.time() - t0) / 60))
    log("\nnow: python triage.py --reports %s --worklist %s"
        % (args.out, args.worklist))
    return 0


if __name__ == "__main__":
    sys.exit(main())
