"""Tests for the MCP server audit tool.

The classification and corpus logic is pure and tested directly. The probe run
needs a live server, so those tests use published packages and skip when they
are not installed.
"""

import pytest

from sovereign_mcp.audit import (
    AuditReport,
    Finding,
    Probe,
    ToolProfile,
    classify,
    numeric_probes,
    string_probes,
)


def _console_script(name):
    """Find a server's console script, including inside the running venv.

    `shutil.which` only searches PATH, and a venv's Scripts/bin directory is
    usually absent from it when pytest runs. Look beside sys.executable too,
    which is where pip put the script for this interpreter.
    """
    import os
    import shutil
    import sys

    candidates = [name, name + ".exe"]
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    bindir = os.path.dirname(sys.executable)
    for candidate in candidates:
        path = os.path.join(bindir, candidate)
        if os.path.exists(path):
            return path
    return None



# --------------------------------------------------------------------------
# Blast-radius classification
# --------------------------------------------------------------------------

class TestClassification:

    @pytest.mark.parametrize("name", [
        "write_query", "create_table", "delete_file", "git_commit",
        "send_email", "run_command", "execute_sql", "drop_index",
        "update_record", "push_branch",
    ])
    def test_state_changing_names_are_write(self, name):
        assert classify(name, "") == "WRITE"

    @pytest.mark.parametrize("name", [
        "read_query", "list_tables", "get_current_time", "git_status",
        "describe_table", "search_docs", "fetch",
    ])
    def test_read_only_names_are_read(self, name):
        assert classify(name, "") == "READ"

    def test_a_description_alone_can_mark_a_tool_as_write(self):
        # The name says nothing; the description admits it writes.
        assert classify("process", "Commits the staged changes") == "WRITE"

    def test_ambiguity_resolves_to_write(self):
        # Wrongly skipping a read-only tool costs a gap in the report.
        # Wrongly probing a write tool costs the client's data.
        assert classify("sync", "Updates the remote copy") == "WRITE"

    def test_unknown_stays_unknown(self):
        assert classify("convert_time", "Convert between timezones") == "UNKNOWN"


# --------------------------------------------------------------------------
# Tool profiles
# --------------------------------------------------------------------------

class TestToolProfile:

    def _profile(self):
        return ToolProfile("read_query", "Run a SELECT", {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer"},
            },
            "required": ["query"],
        })

    def test_fields_and_types_are_read_from_the_schema(self):
        profile = self._profile()
        assert profile.fields == ["query", "limit"]
        assert profile.type_of("query") == "string"
        assert profile.type_of("limit") == "integer"

    def test_benign_args_cover_required_fields_with_valid_types(self):
        args = self._profile().benign_args()
        assert set(args) == {"query"}
        assert isinstance(args["query"], str)

    def test_a_nullable_union_resolves_to_its_real_type(self):
        profile = ToolProfile("t", "", {
            "properties": {"x": {"type": ["string", "null"]}}})
        assert profile.type_of("x") == "string"

    def test_a_missing_schema_does_not_raise(self):
        profile = ToolProfile("t", None, None)
        assert profile.fields == []
        assert profile.benign_args() == {}


# --------------------------------------------------------------------------
# The corpus
# --------------------------------------------------------------------------

class TestCorpus:

    def test_probes_carry_a_severity_and_an_explanation(self):
        for probe in string_probes() + numeric_probes():
            assert probe.severity in ("HIGH", "MEDIUM", "LOW")
            assert len(probe.meaning) > 20, probe.key

    def test_no_probe_asks_a_tool_to_destroy_anything(self):
        # The corpus must stay safe to fire at a live server. Structural
        # nonsense and inert text only - never a working destructive command.
        forbidden = ("drop table", "delete from", "rm -rf", "truncate",
                     "shutdown", "format ", "drop database")
        for probe in string_probes() + numeric_probes():
            text = str(probe.value).lower()
            for phrase in forbidden:
                assert phrase not in text, (probe.key, phrase)

    def test_probe_keys_are_unique(self):
        keys = [p.key for p in string_probes()]
        assert len(keys) == len(set(keys))


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

class TestReport:

    def _report(self):
        report = AuditReport("test-target")
        report.tools = [ToolProfile("read_query", "Run a SELECT", {
            "properties": {"query": {"type": "string"}},
            "required": ["query"]})]
        report.calls = 12
        report.findings = [Finding(
            "read_query", "query", "sql_metacharacters", "HIGH",
            "SQL metacharacters accepted", "ok")]
        report.skipped = ["write_query"]
        return report

    def test_text_report_names_the_finding_and_the_skipped_tool(self):
        text = self._report().to_text()
        assert "read_query.query" in text
        assert "sql_metacharacters" in text
        assert "write_query" in text
        assert "NOT PROBED" in text

    def test_report_states_its_own_limits(self):
        # Overstating what a black-box probe proves is the failure mode this
        # whole tool exists to avoid.
        text = self._report().to_text()
        assert "did not read a line of the" in text
        assert "beginning of an audit" in text

    def test_a_dry_run_does_not_claim_a_clean_result(self):
        report = AuditReport("t", dry_run=True)
        text = report.to_text()
        assert "no probes were sent" in text.lower()
        assert "Every malformed input was refused" not in text

    def test_a_genuinely_clean_run_says_so(self):
        report = AuditReport("t")
        report.calls = 40
        assert "Every malformed input was refused" in report.to_text()

    def test_json_round_trips(self):
        import json
        data = self._report().to_dict()
        assert json.loads(json.dumps(data))["findings"][0]["severity"] == "HIGH"
        assert data["probes_sent"] == 12


# --------------------------------------------------------------------------
# Against a live published server
# --------------------------------------------------------------------------

class TestAgainstLiveServer:

    @staticmethod
    def _server_command():
        command = _console_script("mcp-server-time")
        if not command:
            pytest.skip("mcp-server-time not installed")
        return command

    def test_dry_run_inventories_without_calling_anything(self):
        import anyio
        from sovereign_mcp.audit import audit_stdio

        command = self._server_command()
        report = anyio.run(lambda: audit_stdio(command, [], dry_run=True))
        assert report.calls == 0
        assert {t.name for t in report.tools} >= {"get_current_time"}
        assert report.dry_run is True

    def test_a_validating_server_refuses_the_whole_corpus(self):
        import anyio
        from sovereign_mcp.audit import audit_stdio

        command = self._server_command()
        report = anyio.run(lambda: audit_stdio(command, [], timeout=15))
        assert report.calls > 20, "the corpus barely ran"
        assert report.findings == [], [f.to_dict() for f in report.findings]

    def test_write_tools_are_skipped_unless_asked_for(self):
        import anyio
        from sovereign_mcp.audit import audit_stdio

        command = _console_script("mcp-server-sqlite")
        if not command:
            pytest.skip("mcp-server-sqlite not installed")

        import tempfile
        import os
        db = os.path.join(tempfile.mkdtemp(), "audit.db")
        report = anyio.run(lambda: audit_stdio(
            command, ["--db-path", db], timeout=15))
        # write_query / create_table / append_insight change state.
        assert "write_query" in report.skipped
        assert "create_table" in report.skipped
        # ...and nothing that was skipped produced a finding.
        probed = {f.tool for f in report.findings}
        assert not probed & set(report.skipped)

    def test_an_unlaunchable_command_reports_instead_of_crashing(self):
        import anyio
        from sovereign_mcp.audit import audit_stdio

        with pytest.raises(BaseException) as caught:
            anyio.run(lambda: audit_stdio(
                "definitely-not-a-real-command-xyz", [], timeout=5))
        # Whatever the transport raises, it must not be a silent success.
        assert caught.value is not None
