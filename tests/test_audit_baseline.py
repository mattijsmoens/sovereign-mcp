"""A probe is only a finding if it had an observable effect.

The scanner used to treat any non-error response as a finding, without ever
looking at what came back. Against the published `server-memory` that produced
five HIGH findings on `search_nodes.query`, a free-text search field, where
every single response was:

    { "entities": [], "relations": [] }

The server searched for the hostile string, found nothing, and said so. That is
correct behaviour, and calling it HIGH is what gets a security tool uninstalled:
the first person to check the response sees an empty result set and stops
trusting the output.

"Accepted" is not "vulnerable". A field that legitimately takes free text
accepting free text is its contract. So each probe is now compared against a
benign baseline, and only a difference, or the payload appearing in the
response, counts.

Two baseline calls are taken rather than one. A tool returning a timestamp or a
fresh id differs from itself, which would make every probe look significant; if
the two disagree the tool is marked non-deterministic and only reflected
payloads are reported for it.

These tests drive `_probe_tool` with a fake session, because the behaviour that
matters is the decision, not the transport.
"""

import unittest

import anyio

from sovereign_mcp.audit import AuditReport, ToolProfile, _probe_tool


class FakeContent:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class FakeResult:
    def __init__(self, text, is_error=False):
        self.content = [FakeContent(text)]
        self.isError = is_error


class FakeSession:
    """Answers according to a rule, and records every call."""

    def __init__(self, responder):
        self.responder = responder
        self.calls = []

    async def call_tool(self, name, args):
        self.calls.append((name, dict(args)))
        return self.responder(name, dict(args), len(self.calls))


SCHEMA = {"type": "object",
          "properties": {"query": {"type": "string"}},
          "required": ["query"]}


def run_probe(responder, name="search_nodes", schema=None):
    tool = ToolProfile(name, "Search for nodes.", schema or SCHEMA)
    report = AuditReport("fake")
    report.tools = [tool]
    session = FakeSession(responder)
    anyio.run(lambda: _probe_tool(session, tool, report, 5))
    return report, session


class BaselineTests(unittest.TestCase):

    def test_constant_response_produces_no_findings(self):
        """The server-memory case: every answer identical, nothing reached."""
        report, _ = run_probe(
            lambda n, a, i: FakeResult('{"entities": [], "relations": []}'))
        self.assertEqual(report.findings, [],
                         "a constant response means the payload changed nothing")
        self.assertTrue(report.no_effect,
                        "the discounted probes should still be counted, not hidden")

    def test_reflected_payload_is_still_a_finding(self):
        """If the input comes back out, it reached something."""
        def echo(name, args, i):
            return FakeResult("you searched for: %s" % args.get("query", ""))
        report, _ = run_probe(echo)
        self.assertTrue(report.findings,
                        "a reflected payload must survive baseline comparison")

    def test_differing_response_is_a_finding(self):
        """The sqlite case: a hostile value produces a different answer."""
        def differ(name, args, i):
            q = str(args.get("query", ""))
            if q == "sovereign-audit-probe":
                return FakeResult("ok")
            return FakeResult("sqlite error near %r" % q[:5])
        report, _ = run_probe(differ)
        self.assertTrue(report.findings)

    def test_errors_are_never_findings(self):
        report, _ = run_probe(lambda n, a, i: FakeResult("refused", is_error=True))
        self.assertEqual(report.findings, [])

    def test_two_baseline_calls_are_taken(self):
        report, session = run_probe(lambda n, a, i: FakeResult("same"))
        benign = [a for _, a in session.calls
                  if a.get("query") == "sovereign-audit-probe"]
        self.assertGreaterEqual(
            len(benign), 2,
            "one baseline cannot tell a stable tool from a noisy one")

    def test_nondeterministic_tool_reports_only_reflections(self):
        """A tool returning a fresh value each call must not flag everything."""
        def noisy(name, args, i):
            return FakeResult("request id %d" % i)
        report, _ = run_probe(noisy)
        self.assertEqual(report.findings, [],
                         "a changing response is not evidence the payload mattered")
        self.assertTrue(report.notes, "the reader should be told comparison was unreliable")

    def test_refused_baseline_falls_back_to_reporting(self):
        """If benign arguments are rejected there is nothing to compare against.

        Reporting accepted probes is then the safer default: without a baseline
        the scanner cannot prove a payload was inert, and silently reporting
        nothing would be the false negative this tool exists to avoid.
        """
        def picky(name, args, i):
            if args.get("query") == "sovereign-audit-probe":
                return FakeResult("benign rejected", is_error=True)
            return FakeResult("accepted")
        report, _ = run_probe(picky)
        self.assertTrue(report.findings)


if __name__ == "__main__":
    unittest.main()
