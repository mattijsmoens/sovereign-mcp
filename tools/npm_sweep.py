# -*- coding: utf-8 -*-
"""Find the MCP servers people actually run, ranked by weekly downloads.

The official MCP registry is the wrong source for this. Sweeping 1,200 registry
entries produced 32 auditable candidates whose most-installed package had 1,992
weekly downloads, while `@playwright/mcp` alone has 5.6 million and is not
listed there. The registry is a discovery index, not a popularity ranking.

npm's own search is the better source: it indexes what is published and
published packages are what get installed.

Severity is not intrinsic. The same missing input check is worth reporting in a
package with a million weekly installs and worth nobody's afternoon in one with
twelve, so downloads decide the order of work.

    python npm_sweep.py --out worklist.json --min-downloads 1000
"""
import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request

UA = {"User-Agent": "sovereign-mcp-audit/npm-sweep"}

#: Search terms. npm search is fuzzy, so several narrow queries beat one broad
#: one, and the union is deduplicated afterwards.
QUERIES = [
    "mcp-server", "mcp server", "modelcontextprotocol",
    "model context protocol", "mcp", "@modelcontextprotocol",
]

#: Packages that are clients, SDKs or frameworks rather than servers. Auditing
#: them makes no sense: there is nothing to connect to.
NOT_A_SERVER = re.compile(
    r"(^|[-/@])(sdk|client|cli|inspector|proxy|bridge|template|boilerplate|"
    r"starter|example|docs?|types?|schema|eslint|test)([-/]|$)", re.I)


def get(url, timeout=30):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA),
                                timeout=timeout) as r:
        return json.load(r)


def search(query, size=250):
    url = ("https://registry.npmjs.org/-/v1/search?text=%s&size=%d"
           % (urllib.parse.quote(query), size))
    try:
        return get(url).get("objects") or []
    except Exception as exc:                                # noqa: BLE001
        print("  search %r failed: %s" % (query, exc), file=sys.stderr)
        return []


def downloads(name, cache):
    if name in cache:
        return cache[name]
    try:
        url = ("https://api.npmjs.org/downloads/point/last-week/"
               + urllib.parse.quote(name, safe="@/"))
        cache[name] = get(url, timeout=20).get("downloads", 0)
    except Exception:                                       # noqa: BLE001
        cache[name] = 0
    return cache[name]


def looks_like_server(name, description):
    if NOT_A_SERVER.search(name):
        return False
    blob = "%s %s" % (name, description or "")
    return "mcp" in blob.lower() or "context protocol" in blob.lower()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="worklist.json")
    ap.add_argument("--min-downloads", type=int, default=500)
    ap.add_argument("--top", type=int, default=60, help="how many to report")
    args = ap.parse_args(argv)

    t0 = time.time()
    found = {}
    for q in QUERIES:
        hits = search(q)
        print("  %-28s %4d hits" % (q, len(hits)), file=sys.stderr)
        for obj in hits:
            pkg = obj.get("package") or {}
            name = pkg.get("name")
            if not name or name in found:
                continue
            found[name] = {
                "identifier": name,
                "version": pkg.get("version"),
                "description": (pkg.get("description") or "")[:160],
                "links": (pkg.get("links") or {}).get("repository"),
            }
    print("\n  %d distinct packages\n" % len(found), file=sys.stderr)

    cache, work = {}, []
    for i, (name, row) in enumerate(found.items(), 1):
        if not looks_like_server(name, row["description"]):
            continue
        n = downloads(name, cache)
        if n < args.min_downloads:
            continue
        row["downloads_weekly"] = n
        work.append(row)
        if i % 50 == 0:
            print("  checked %d/%d" % (i, len(found)), file=sys.stderr)

    work.sort(key=lambda r: -r["downloads_weekly"])
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(work, fh, indent=2)

    print("\n  wrote %s: %d candidates above %d weekly downloads (%.0fs)\n"
          % (args.out, len(work), args.min_downloads, time.time() - t0),
          file=sys.stderr)
    print("  %-46s %12s" % ("package", "weekly"))
    for row in work[:args.top]:
        print("  %-46s %12s" % (row["identifier"][:46],
                                "{:,}".format(row["downloads_weekly"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
