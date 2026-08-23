# -*- coding: utf-8 -*-
"""Rank audit reports into a shortlist worth reading source for.

Stage three. The scanner produces findings; this decides which are worth an
afternoon.

Two judgements are baked in, both learned by getting them wrong:

Severity is not intrinsic. The same missing input check is worth reporting in a
package with 800,000 weekly installs and worth nobody's time in one with twelve,
so the score is severity weighted by reach.

And a finding is a lead, not a report. Every response is printed alongside its
finding, because the whole exercise today was discovering that counts lie and
the response is the only thing that settles it. Nothing here should be submitted
anywhere without reading the text underneath it.

    python triage.py --reports reports --worklist worklist.json
"""
import argparse
import json
import os
import sys

WEIGHT = {"HIGH": 10, "MEDIUM": 3, "LOW": 1}

#: Classes where a hit is unambiguous and maps onto a CWE a bounty programme
#: recognises. Everything else is a prompt to go and read the source.
STRONG = {
    "cloud_metadata": "CWE-918 SSRF",
    "localhost_service": "CWE-918 SSRF",
    "private_range": "CWE-918 SSRF",
    "file_scheme": "CWE-918 SSRF",
    "handle_sequential_low": "CWE-639 authorisation bypass via user-controlled key",
    "handle_sequential_next": "CWE-639 authorisation bypass via user-controlled key",
    "handle_zero_uuid": "CWE-639 authorisation bypass via user-controlled key",
    "handle_guessed_name": "CWE-639 authorisation bypass via user-controlled key",
    "sql_metacharacters": "CWE-89 SQL injection (needs confirmation in source)",
    "path_traversal": "CWE-22 path traversal (needs confirmation in source)",
    "shell_metacharacters": "CWE-78 command injection (needs confirmation in source)",
}


def load(reports_dir, worklist):
    reach = {}
    if worklist and os.path.exists(worklist):
        with open(worklist, encoding="utf-8") as fh:
            for row in json.load(fh):
                reach[row["identifier"]] = row.get("downloads_weekly", 0)

    out = []
    for name in sorted(os.listdir(reports_dir)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(reports_dir, name)
        try:
            with open(path, encoding="utf-8") as fh:
                report = json.load(fh)
        except Exception:                                   # noqa: BLE001
            continue
        target = report.get("target") or name[:-5]
        ident = next((k for k in reach if k.replace("/", "__").replace("@", "__")
                      in name), None)
        out.append({
            "file": name,
            "target": target,
            "identifier": ident or name[:-5],
            "downloads": reach.get(ident, 0),
            "findings": report.get("findings", []),
            "discounted": len(report.get("accepted_without_effect", [])),
            "probes": report.get("probes_sent", 0),
        })
    return out


def score(entry):
    """Severity weighted by reach. A quiet package cannot outrank a loud one."""
    raw = sum(WEIGHT.get(f.get("severity"), 0) for f in entry["findings"])
    strong = sum(4 for f in entry["findings"] if f.get("probe") in STRONG)
    import math
    reach = math.log10(max(entry["downloads"], 1) + 1)
    return (raw + strong) * (1 + reach)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--worklist", default="worklist.json")
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--json", help="write the shortlist here as JSON")
    args = ap.parse_args(argv)

    if not os.path.isdir(args.reports):
        sys.stderr.write("no such directory: %s\n" % args.reports)
        return 2

    entries = load(args.reports, args.worklist)
    audited = len(entries)
    withf = [e for e in entries if e["findings"]]
    withf.sort(key=score, reverse=True)

    print("=" * 78)
    print("TRIAGE")
    print("=" * 78)
    print("  %d servers audited, %d with findings, %d clean"
          % (audited, len(withf), audited - len(withf)))
    print()

    if not withf:
        print("  Nothing to look at. That is a real result, not a failed run:")
        print("  a scanner that reports clean honestly is worth more than one")
        print("  that always finds something.")
        return 0

    print("  %-40s %10s %6s %s" % ("package", "weekly", "score", "findings"))
    print("  " + "-" * 74)
    for e in withf[:args.top]:
        sev = {}
        for f in e["findings"]:
            sev[f["severity"]] = sev.get(f["severity"], 0) + 1
        print("  %-40s %10s %6.0f  %s"
              % (e["identifier"][:40],
                 "{:,}".format(e["downloads"]) if e["downloads"] else "-",
                 score(e),
                 " ".join("%s:%d" % (k, v) for k, v in sorted(sev.items()))))

    print()
    print("=" * 78)
    print("WORTH READING SOURCE FOR")
    print("=" * 78)
    print("  These map onto a CWE a bounty programme recognises. Read the")
    print("  response under each one before believing it.")
    print()
    shortlist = []
    for e in withf[:args.top]:
        strong = [f for f in e["findings"] if f.get("probe") in STRONG]
        if not strong:
            continue
        print("  %s  (%s weekly)"
              % (e["identifier"],
                 "{:,}".format(e["downloads"]) if e["downloads"] else "unknown"))
        for f in strong[:4]:
            print("    %s.%s  <-  %s" % (f["tool"], f["field"], f["probe"]))
            print("       %s" % STRONG[f["probe"]])
            excerpt = " ".join((f.get("response_excerpt") or "").split())[:150]
            print("       response: %s" % (excerpt or "(empty)"))
        print()
        shortlist.append({
            "identifier": e["identifier"],
            "downloads_weekly": e["downloads"],
            "score": round(score(e), 1),
            "strong_findings": [
                {"tool": f["tool"], "field": f["field"], "probe": f["probe"],
                 "cwe": STRONG[f["probe"]],
                 "response_excerpt": f.get("response_excerpt", "")[:400]}
                for f in strong],
        })

    if not shortlist:
        print("  None. Everything found is an input-validation observation")
        print("  rather than something with a CWE behind it.")

    if args.json:
        with open(args.json, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(shortlist, fh, indent=2)
        print("  wrote %s" % args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
