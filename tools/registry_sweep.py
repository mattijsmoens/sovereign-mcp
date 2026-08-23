# -*- coding: utf-8 -*-
"""Enumerate the MCP registry and rank servers worth auditing.

Stage one of the funnel. Produces a work list; audits nothing itself.

Ranking is by weekly download count, because severity is not intrinsic. The same
missing input check is worth reporting in a package with 800,000 weekly
installs and worth nobody's afternoon in one with twelve.

Servers requiring credentials are excluded. Without a key they refuse every
call, and a clean result would mean nothing.

    python registry_sweep.py --out worklist.json --limit 400
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
UA = {"User-Agent": "sovereign-mcp-audit/registry-sweep"}


def _get(url, timeout=40):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def enumerate_servers(page_limit=100, max_pages=60, verbose=True):
    """Walk the registry, newest entries first, following its cursor."""
    seen, cursor, pages = [], None, 0
    while pages < max_pages:
        url = "%s?limit=%d" % (REGISTRY, page_limit)
        if cursor:
            url += "&cursor=" + urllib.parse.quote(cursor)
        try:
            data = _get(url)
        except Exception as exc:                            # noqa: BLE001
            print("  registry page %d failed: %s" % (pages, exc), file=sys.stderr)
            break
        batch = data.get("servers") or []
        if not batch:
            break
        seen.extend(batch)
        pages += 1
        if verbose:
            print("  page %-3d %5d servers so far" % (pages, len(seen)), file=sys.stderr)
        cursor = (data.get("metadata") or {}).get("nextCursor")
        if not cursor:
            break
    return seen


def npm_downloads(name, cache):
    if name in cache:
        return cache[name]
    try:
        url = ("https://api.npmjs.org/downloads/point/last-week/"
               + urllib.parse.quote(name, safe="@/"))
        cache[name] = _get(url, timeout=20).get("downloads", 0)
    except Exception:                                       # noqa: BLE001
        cache[name] = 0
    return cache[name]


def pypi_exists(name, cache):
    """PyPI publishes no download counts, so presence is all we can check."""
    if name in cache:
        return cache[name]
    try:
        _get("https://pypi.org/pypi/%s/json" % urllib.parse.quote(name), timeout=20)
        cache[name] = True
    except Exception:                                       # noqa: BLE001
        cache[name] = False
    return cache[name]


def build_worklist(servers, min_downloads=0, verbose=True):
    out, npm_cache, pypi_cache, skipped = [], {}, {}, {"creds": 0, "no_pkg": 0, "dupe": 0}
    seen_ids = set()
    for row in servers:
        s = row.get("server") or row
        meta = (row.get("_meta") or {}).get(
            "io.modelcontextprotocol.registry/official", {}) or {}
        if not meta.get("isLatest", True):
            continue
        for pkg in (s.get("packages") or []):
            rt = pkg.get("registryType")
            ident = pkg.get("identifier")
            if rt not in ("npm", "pypi") or not ident:
                skipped["no_pkg"] += 1
                continue
            # A server needing a secret refuses everything without one, so a
            # clean audit of it would be meaningless rather than reassuring.
            if pkg.get("environmentVariables"):
                skipped["creds"] += 1
                continue
            key = "%s:%s" % (rt, ident)
            if key in seen_ids:
                skipped["dupe"] += 1
                continue
            seen_ids.add(key)

            downloads = npm_downloads(ident, npm_cache) if rt == "npm" else 0
            if rt == "pypi" and not pypi_exists(ident, pypi_cache):
                continue
            if downloads < min_downloads:
                continue

            args = [a.get("value") or a.get("name") for a in
                    (pkg.get("packageArguments") or []) if isinstance(a, dict)]
            out.append({
                "name": s.get("name"),
                "registry": rt,
                "identifier": ident,
                "version": pkg.get("version"),
                "downloads_weekly": downloads,
                "declared_args": [a for a in args if a],
                "needs_args": bool(args),
                "transport": (pkg.get("transport") or {}).get("type"),
                "repository": (s.get("repository") or {}).get("url"),
            })
            if verbose and len(out) % 25 == 0:
                print("  %d candidates" % len(out), file=sys.stderr)
    out.sort(key=lambda r: -r["downloads_weekly"])
    return out, skipped


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="worklist.json")
    ap.add_argument("--min-downloads", type=int, default=0,
                    help="drop npm packages below this weekly count")
    ap.add_argument("--max-pages", type=int, default=60)
    args = ap.parse_args(argv)

    t0 = time.time()
    print("Enumerating the registry...", file=sys.stderr)
    servers = enumerate_servers(max_pages=args.max_pages)
    print("  %d entries\n" % len(servers), file=sys.stderr)

    print("Resolving packages and download counts...", file=sys.stderr)
    work, skipped = build_worklist(servers, args.min_downloads)

    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(work, fh, indent=2)

    print("\n  wrote %s" % args.out, file=sys.stderr)
    print("  %d auditable candidates" % len(work), file=sys.stderr)
    print("  skipped: %d needing credentials, %d without an npm/pypi package, "
          "%d duplicates" % (skipped["creds"], skipped["no_pkg"], skipped["dupe"]),
          file=sys.stderr)
    print("  %.0fs\n" % (time.time() - t0), file=sys.stderr)

    print("  %-46s %10s  %s" % ("package", "weekly", "needs args"))
    for row in work[:30]:
        print("  %-46s %10s  %s" % (
            row["identifier"][:46],
            "{:,}".format(row["downloads_weekly"]) if row["downloads_weekly"] else "-",
            "yes" if row["needs_args"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
