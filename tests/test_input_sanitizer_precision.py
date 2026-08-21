"""
InputSanitizer precision tests.

`_HTML_TAGS` was r"<[^>]*>", which treats any "<...>" span as a tag. In
standard mode that silently deleted the middle of ordinary text:

    "5 < 10 and 10 > 5"  ->  "5  5"

Comparisons, inequalities and ranges are common in tool parameters, and
corrupting them is worse than the markup the pattern was trying to remove.
The pattern now requires a tag-like name after "<".
"""

import pytest

from sovereign_mcp import InputSanitizer


def _clean(text, mode="standard"):
    return InputSanitizer.sanitize_string(text, mode=mode)[0]


class TestMarkupStillStripped:

    @pytest.mark.parametrize("text", [
        "<script>alert(1)</script>",
        "<div onclick='x'>hi</div>",
        "<img src=x onerror=y>",
        "</p>",
        "<iframe src='evil'></iframe>",
    ])
    def test_markup_removed(self, text):
        assert "<" not in _clean(text)


class TestOrdinaryTextSurvives:
    """These were being corrupted."""

    @pytest.mark.parametrize("text", [
        "5 < 10 and 10 > 5",
        "price < 100 > 50",
        "temp range: 20 < t < 30",
        "if x < y then y > x",
        "It's a sunny day",
        "quarterly_report_2026.pdf",
        "What is the weather in Brussels?",
    ])
    def test_unchanged(self, text):
        assert _clean(text) == text


class TestKnownAmbiguity:

    def test_letter_immediately_after_angle_bracket_is_treated_as_markup(self):
        """`a<b and b>c` is indistinguishable from an HTML <b> tag.

        Documented rather than fixed: for a sanitizer, erring toward removing
        markup is the correct trade-off when the input is genuinely ambiguous.
        """
        assert _clean("a<b and b>c") == "ac"


class TestOtherSanitizersUnaffected:

    def test_null_bytes(self):
        assert "\x00" not in _clean("file.txt\x00.exe")

    def test_path_traversal(self):
        assert ".." not in _clean("../../../etc/passwd")

    def test_double_encoding(self):
        assert "%25" not in _clean("..%252f..%252fetc%252fpasswd")

    def test_sql_keywords(self):
        assert "UNION SELECT" not in _clean("x UNION SELECT password FROM users")

    def test_shell_metacharacters_are_strict_mode_only(self):
        """By design: ';' and '&' are common in ordinary prose."""
        text = "file.txt; rm -rf /"
        assert _clean(text, mode="standard") == text
        assert ";" not in _clean(text, mode="strict")
