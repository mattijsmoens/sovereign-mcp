"""
AntiPatternDetector targeting tests.

The anti-pattern rules describe what an agent is about to *do*: `git add .`,
a bare `cd`, `npm install` without `-y`, a 500-character blob written to a
file. OutputGate applied them to what a tool *returned*, which is a category
error and produced false declines on ordinary data:

  * an image tool's base64 thumbnail  -> "binary hallucination"
  * documentation explaining `git add .` -> "greedy_git"
  * any prose containing "cd "        -> "cd_trap"
  * any long opaque token (JWT, hash) -> "binary hallucination"

They are now scanned against the tool call. `scan_output_for_anti_patterns=True`
restores the previous behaviour.
"""

import base64

import pytest

from sovereign_mcp import ToolRegistry, OutputGate


@pytest.fixture
def frozen():
    registry = ToolRegistry()
    registry.register_tool(
        name="get_image",
        description="Return an image thumbnail",
        input_schema={"query": {"type": "string", "required": True}},
        output_schema={"thumbnail": {"type": "string"}},
        capabilities=["read_api"],
        risk_level="LOW",
    )
    registry.register_tool(
        name="run_cmd",
        description="Run a command",
        input_schema={"command": {"type": "string", "required": True},
                      "action": {"type": "string"}},
        output_schema={"stdout": {"type": "string"}},
        capabilities=["read_api"],
        risk_level="LOW",
    )
    registry.register_tool(
        name="read_docs",
        description="Return documentation",
        input_schema={"topic": {"type": "string", "required": True}},
        output_schema={"content": {"type": "string"}},
        capabilities=["read_api"],
        risk_level="LOW",
    )
    return registry.freeze()


BIG_BLOB = base64.b64encode(b"x" * 600).decode()


class TestLegitimateOutputAccepted:

    def test_base64_image_output(self, frozen):
        gate = OutputGate(frozen)
        result = gate.verify("get_image", {"thumbnail": BIG_BLOB},
                             input_params={"query": "cat"})
        assert result.accepted, result.reason

    def test_docs_mentioning_shell_commands(self, frozen):
        gate = OutputGate(frozen)
        result = gate.verify(
            "read_docs",
            {"content": "To stage everything at once run git add . in the repo"},
            input_params={"topic": "git"},
        )
        assert result.accepted, result.reason

    def test_prose_containing_cd(self, frozen):
        gate = OutputGate(frozen)
        result = gate.verify("read_docs",
                             {"content": "First cd into the directory, then run make"},
                             input_params={"topic": "build"})
        assert result.accepted, result.reason


class TestAntiPatternsStillCaughtOnTheCall:

    def test_greedy_git_in_call(self, frozen):
        gate = OutputGate(frozen)
        result = gate.verify("run_cmd", {"stdout": "ok"},
                             input_params={"action": "run_command",
                                           "command": "git add ."})
        assert result.accepted is False
        assert result.layer == "anti_patterns"
        assert "greedy_git" in result.reason

    def test_cd_trap_in_call(self, frozen):
        gate = OutputGate(frozen)
        result = gate.verify("run_cmd", {"stdout": "ok"},
                             input_params={"action": "run_command",
                                           "command": "cd /tmp && make"})
        assert result.accepted is False
        assert "cd_trap" in result.reason

    def test_interactive_trap_in_call(self, frozen):
        gate = OutputGate(frozen)
        result = gate.verify("run_cmd", {"stdout": "ok"},
                             input_params={"action": "run_command",
                                           "command": "npm install express"})
        assert result.accepted is False
        assert "interactive_trap" in result.reason


class TestBackwardCompatibility:

    def test_opt_in_restores_output_scanning(self, frozen):
        gate = OutputGate(frozen, scan_output_for_anti_patterns=True)
        result = gate.verify("get_image", {"thumbnail": BIG_BLOB},
                             input_params={"query": "cat"})
        assert result.accepted is False
        assert "binary_hallucination" in result.reason
