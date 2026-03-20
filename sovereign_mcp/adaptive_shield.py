"""
AdaptiveShield — Self-Improving Security Filter.
=================================================
All-in-one class that wraps the InputFilter with:
  - Local SQLite storage for scan history
  - Report endpoint for missed attacks
  - Category-based keyword extraction and classification
  - Sandbox replay to validate candidate rules
  - Auto-deployment of validated rules at runtime
  - Self-expanding minefield: one report blocks an entire attack class
  - Self-pruning: false positives auto-remove learned keywords

Zero cloud dependencies. Works entirely offline.

Patent: Sovereign Shield Patent 20 (MCP Security Architecture)
"""

import os
import time
import uuid
import sqlite3
import threading
import logging
from typing import Optional, List, Set, Dict

from sovereign_mcp.input_filter import InputFilter, DEFAULT_BAD_SIGNALS

logger = logging.getLogger(__name__)

# Predefined attack category keyword clusters
ATTACK_CATEGORIES: Dict[str, List[str]] = {
    "exfiltration": [
        "extract", "dump", "reveal", "show", "leak", "expose", "export",
        "steal", "exfiltrate", "copy", "send", "transmit", "email",
    ],
    "injection": [
        "execute", "run", "eval", "system", "shell", "cmd", "exec",
        "subprocess", "popen", "os.system", "bash", "powershell",
    ],
    "impersonation": [
        "i am the admin", "override", "bypass", "emergency", "disable",
        "i am authorized", "maintenance mode", "superuser",
    ],
    "encoding_bypass": [
        "base64", "hex", "unicode", "encode", "decode", "rot13",
        "binary", "obfuscate", "encrypt",
    ],
    "data_access": [
        "password", "credential", "secret", "api key", "token",
        "config", "connection string", "private key", "certificate",
    ],
    "persistence": [
        "scheduled", "cron", "recurring", "backdoor", "persist",
        "reverse shell", "callback", "webhook",
    ],
    "destruction": [
        "delete", "drop", "truncate", "destroy", "wipe", "erase",
        "format", "rm -rf", "purge", "remove all",
    ],
}

# Common stopwords to filter out during keyword extraction
_STOPWORDS = {
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "can", "shall", "to", "of", "in", "for",
    "on", "with", "at", "by", "from", "as", "into", "through", "about",
    "and", "but", "or", "nor", "not", "so", "yet", "both", "either",
    "neither", "this", "that", "these", "those", "it", "its", "my",
    "your", "his", "her", "our", "their", "me", "him", "us", "them",
    "i", "you", "he", "she", "we", "they", "what", "which", "who",
    "how", "when", "where", "why", "all", "each", "every", "some",
    "any", "no", "just", "also", "very", "too", "please", "then",
    "now", "here", "there", "up", "out", "if", "than", "after",
    "before", "above", "below", "between", "under", "over",
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_log (
    scan_id TEXT PRIMARY KEY,
    input_text TEXT NOT NULL,
    allowed INTEGER NOT NULL,
    stage TEXT NOT NULL,
    reason TEXT NOT NULL,
    timestamp REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    report_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    reported_input TEXT NOT NULL,
    reason TEXT NOT NULL,
    timestamp REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS rules (
    rule_id TEXT PRIMARY KEY,
    pattern TEXT NOT NULL,
    source_report_id TEXT NOT NULL,
    false_positive_rate REAL NOT NULL DEFAULT 0,
    tested_against INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS attack_categories (
    category TEXT NOT NULL,
    keyword TEXT NOT NULL,
    source_report_id TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (category, keyword)
);

CREATE INDEX IF NOT EXISTS idx_scan_allowed ON scan_log(allowed);
"""


class AdaptiveShield:
    """
    Self-improving input security filter.

    Args:
        db_path: Path to SQLite database file (default: ./data/adaptive.db)
        extra_keywords: Additional keywords to block on top of defaults
        fp_threshold: Max false positive rate for auto-approving rules (default: 1%)
        retention_days: How long to keep scan history (default: 30)
        auto_deploy: If True, validated rules deploy automatically.
                     If False, all rules go to 'pending' for manual review.
    """

    def __init__(
        self,
        db_path: str = os.path.join("data", "adaptive.db"),
        extra_keywords: Optional[List[str]] = None,
        fp_threshold: float = 0.01,
        retention_days: int = 30,
        auto_deploy: bool = True,
        allow_pruning: bool = True,
    ):
        self._db_path = db_path
        self._fp_threshold = fp_threshold
        self._retention_days = retention_days
        self._auto_deploy = auto_deploy
        self._allow_pruning = allow_pruning
        self._lock = threading.Lock()

        # Built-in filter
        signals = list(DEFAULT_BAD_SIGNALS)
        if extra_keywords:
            signals.extend(extra_keywords)
        self._filter = InputFilter(bad_signals=signals)

        # Custom rules loaded from DB (legacy exact-match patterns)
        self._custom_rules: Set[str] = set()

        # Category keywords loaded from DB (v2 self-expanding minefield)
        self._category_keywords: Dict[str, Set[str]] = {}

        # Init database
        self._init_db()

        # Load any previously approved rules
        self._load_approved_rules()

        # Load learned category keywords
        self._load_category_keywords()

        # Cleanup old entries
        self._cleanup(self._retention_days)

    # ------------------------------------------------------------------
    # DATABASE
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        os.makedirs(os.path.dirname(self._db_path) or ".", exist_ok=True)
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript(_SCHEMA)
        conn.commit()
        conn.close()

    def _load_approved_rules(self):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT pattern FROM rules WHERE status = 'approved'")
        for row in cur.fetchall():
            self._custom_rules.add(row["pattern"].lower())
        conn.close()
        if self._custom_rules:
            logger.info(f"Loaded {len(self._custom_rules)} custom rules from database.")

    def _load_category_keywords(self):
        """Load learned category keywords from the database."""
        conn = self._get_conn()
        cur = conn.cursor()
        try:
            cur.execute("SELECT category, keyword FROM attack_categories")
            for row in cur.fetchall():
                cat = row["category"]
                kw = row["keyword"].lower()
                if cat not in self._category_keywords:
                    self._category_keywords[cat] = set()
                self._category_keywords[cat].add(kw)
        except sqlite3.OperationalError:
            pass  # Table may not exist yet on first run
        conn.close()
        total = sum(len(v) for v in self._category_keywords.values())
        if total:
            logger.info(f"Loaded {total} category keywords across {len(self._category_keywords)} categories.")

    def _cleanup(self, days: int):
        cutoff = time.time() - (days * 86400)
        conn = self._get_conn()
        conn.execute("DELETE FROM scan_log WHERE timestamp < ?", (cutoff,))
        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # SCAN
    # ------------------------------------------------------------------

    def scan(self, text: str) -> dict:
        """
        Scan input text through all security layers.

        Returns:
            dict with keys: scan_id, allowed, stage, reason, clean_input
        """
        scan_id = uuid.uuid4().hex[:12]
        start = time.perf_counter()

        # Layer 1: Built-in filter (includes multi-decode + multilingual)
        is_safe, result = self._filter.process(text)

        # Layer 2a: Custom adaptive rules (require 2+ matches to reduce FP)
        if is_safe and self._custom_rules:
            text_lower = text.lower()
            matched_rules = [rule for rule in self._custom_rules if rule in text_lower]
            if len(matched_rules) >= 2:
                is_safe = False
                result = f"Blocked by adaptive rules: matched {matched_rules[:3]}"

        # Layer 2b: Category keyword matching (v2 self-expanding minefield)
        if is_safe and self._category_keywords:
            text_lower = text.lower()
            for category, learned_kws in self._category_keywords.items():
                all_kws = learned_kws | set(ATTACK_CATEGORIES.get(category, []))
                matched = [kw for kw in all_kws if kw in text_lower]
                if len(matched) >= 2:
                    is_safe = False
                    result = (f"Blocked by category '{category}': "
                              f"matched {matched[:3]}")
                    break

        stage = "Approved" if is_safe else "InputFilter"
        reason = "Input is clean." if is_safe else result
        latency = (time.perf_counter() - start) * 1000

        # Record scan
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                "INSERT INTO scan_log (scan_id, input_text, allowed, stage, reason, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (scan_id, text, int(is_safe), stage, reason, time.time()),
            )
            conn.commit()
            conn.close()

        return {
            "scan_id": scan_id,
            "allowed": is_safe,
            "stage": stage,
            "reason": reason,
            "clean_input": result if is_safe else None,
            "latency_ms": round(latency, 2),
        }

    # ------------------------------------------------------------------
    # REPORT
    # ------------------------------------------------------------------

    def report(self, scan_id: str, reason: str) -> dict:
        """
        Report a missed attack (false negative).

        The system will:
        1. Look up the original input
        2. Sandbox-test the pattern against historical allowed scans
        3. Auto-deploy the rule if false positive rate is below threshold

        Returns:
            dict with: report_id, status, rule_created, sandbox_result, message
        """
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT input_text, allowed FROM scan_log WHERE scan_id = ?",
            (scan_id,),
        )
        row = cur.fetchone()
        conn.close()

        if not row:
            return {"report_id": None, "status": "error", "rule_created": False,
                    "message": "Scan ID not found. It may have expired."}

        if not row["allowed"]:
            return {"report_id": None, "status": "error", "rule_created": False,
                    "message": "This scan was already blocked."}

        input_text = row["input_text"]
        if not input_text or len(input_text.strip()) < 5:
            return {"report_id": None, "status": "stored", "rule_created": False,
                    "message": "Input too short for automatic rule creation."}

        # Save report
        report_id = uuid.uuid4().hex[:12]
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                "INSERT INTO reports (report_id, scan_id, reported_input, reason, timestamp, status) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (report_id, scan_id, input_text, reason, time.time(), "pending"),
            )
            conn.commit()
            conn.close()

        # Keyword extraction + category classification
        keywords = self._extract_keywords(input_text)
        category, matched_cat_keywords = self._classify_attack(keywords)

        # Save keywords to category with FP validation
        new_keywords = []
        rejected_keywords = []
        if category:
            validated = []
            for kw in keywords:
                kw_lower = kw.lower()
                if kw_lower in self._category_keywords.get(category, set()):
                    continue
                fp_result = self._validate_keyword(kw_lower, exclude_scan_id=scan_id)
                if fp_result["safe"]:
                    validated.append(kw_lower)
                else:
                    rejected_keywords.append(kw_lower)

            if validated:
                with self._lock:
                    conn = self._get_conn()
                    for kw_lower in validated:
                        try:
                            conn.execute(
                                "INSERT OR IGNORE INTO attack_categories "
                                "(category, keyword, source_report_id, created_at) "
                                "VALUES (?, ?, ?, ?)",
                                (category, kw_lower, report_id, time.time()),
                            )
                            new_keywords.append(kw_lower)
                        except sqlite3.IntegrityError:
                            pass
                    conn.commit()
                    conn.close()

                if category not in self._category_keywords:
                    self._category_keywords[category] = set()
                for kw_lower in validated:
                    self._category_keywords[category].add(kw_lower)

        # Legacy: also store as exact-match rule
        pattern = input_text.strip().lower()
        sandbox = self._replay(pattern, exclude_scan_id=scan_id)

        rule_id = uuid.uuid4().hex[:12]
        passes_threshold = sandbox["false_positive_rate"] <= self._fp_threshold

        cat_info = (f" Category: '{category}', "
                    f"{len(new_keywords)} new keywords added.") if category else ""

        if passes_threshold and self._auto_deploy:
            self._save_rule(rule_id, pattern, report_id, sandbox, "approved")
            self._custom_rules.add(pattern)
            return {
                "report_id": report_id,
                "status": "auto_approved",
                "rule_created": True,
                "category": category,
                "new_keywords": new_keywords,
                "sandbox_result": sandbox,
                "message": f"Rule deployed.{cat_info}",
            }
        else:
            status = "ready_for_approval" if passes_threshold else "pending_review"
            self._save_rule(rule_id, pattern, report_id, sandbox, "pending")
            return {
                "report_id": report_id,
                "status": status,
                "rule_created": False,
                "category": category,
                "new_keywords": new_keywords,
                "sandbox_result": sandbox,
                "message": f"Rule needs review.{cat_info} "
                           f"FP rate: {sandbox['false_positive_rate']*100:.1f}%.",
            }

    # ------------------------------------------------------------------
    # FALSE POSITIVE REPORTING (self-pruning)
    # ------------------------------------------------------------------

    def report_false_positive(self, scan_id: str, reason: str = "") -> dict:
        """
        Report a false positive (a clean input that was wrongly blocked).
        The system will identify and remove the learned keywords that caused it.
        Predefined ATTACK_CATEGORIES keywords are NEVER removed.
        """
        if not self._allow_pruning or not self._auto_deploy:
            return {
                "status": "pending_review",
                "pruned_keywords": [],
                "category": None,
                "message": "Manual mode active. Logged for admin review.",
            }

        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT input_text, allowed, reason FROM scan_log WHERE scan_id = ?",
            (scan_id,),
        )
        row = cur.fetchone()
        conn.close()

        if not row:
            return {"status": "error", "pruned_keywords": [],
                    "message": "Scan ID not found."}

        if row["allowed"]:
            return {"status": "error", "pruned_keywords": [],
                    "message": "This scan was allowed. Only blocked scans can be reported."}

        input_text = row["input_text"]
        text_lower = input_text.lower()
        pruned = []
        pruned_category = None

        for category, learned_kws in list(self._category_keywords.items()):
            predefined = set(ATTACK_CATEGORIES.get(category, []))
            all_kws = learned_kws | predefined
            matched = [kw for kw in all_kws if kw in text_lower]

            if len(matched) >= 2:
                pruned_category = category
                to_prune = [kw for kw in matched if kw in learned_kws and kw not in predefined]

                if to_prune:
                    with self._lock:
                        conn = self._get_conn()
                        for kw in to_prune:
                            conn.execute(
                                "DELETE FROM attack_categories WHERE category = ? AND keyword = ?",
                                (category, kw),
                            )
                            learned_kws.discard(kw)
                            pruned.append(kw)
                        conn.commit()
                        conn.close()

                    if not learned_kws:
                        del self._category_keywords[category]
                break

        if pruned:
            return {
                "status": "pruned",
                "pruned_keywords": pruned,
                "category": pruned_category,
                "message": f"Removed {len(pruned)} learned keywords from '{pruned_category}'.",
            }
        return {
            "status": "no_action",
            "pruned_keywords": [],
            "category": pruned_category,
            "message": "Block caused by predefined keywords (immutable).",
        }

    # ------------------------------------------------------------------
    # SANDBOX REPLAY
    # ------------------------------------------------------------------

    def _replay(self, pattern: str, exclude_scan_id: str = "") -> dict:
        """Test a pattern against all historical allowed scans."""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT input_text FROM scan_log WHERE allowed = 1 AND input_text != '' AND scan_id != ?",
            (exclude_scan_id,)
        )
        rows = cur.fetchall()
        conn.close()

        total = len(rows)
        if total == 0:
            return {"total_tested": 0, "would_block": 0, "false_positive_rate": 0.0}

        pattern_lower = pattern.lower()
        would_block = sum(1 for r in rows if pattern_lower in r["input_text"].lower())
        fp_rate = would_block / total

        return {
            "total_tested": total,
            "would_block": would_block,
            "false_positive_rate": round(fp_rate, 4),
        }

    def _validate_keyword(self, keyword: str, exclude_scan_id: str = "") -> dict:
        """Validate a keyword against historical benign traffic."""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT input_text FROM scan_log WHERE allowed = 1 "
            "AND input_text != '' AND scan_id != ?",
            (exclude_scan_id,),
        )
        rows = cur.fetchall()
        conn.close()

        total = len(rows)
        if total == 0:
            return {"safe": True, "total_tested": 0, "would_block": 0, "fp_rate": 0.0}

        kw_lower = keyword.lower()
        would_block = sum(1 for r in rows if kw_lower in r["input_text"].lower())
        fp_rate = would_block / total

        return {
            "safe": fp_rate <= self._fp_threshold,
            "total_tested": total,
            "would_block": would_block,
            "fp_rate": round(fp_rate, 4),
        }

    def _save_rule(self, rule_id, pattern, report_id, sandbox, status):
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                "INSERT INTO rules (rule_id, pattern, source_report_id, "
                "false_positive_rate, tested_against, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (rule_id, pattern, report_id, sandbox["false_positive_rate"],
                 sandbox["total_tested"], status, time.time()),
            )
            conn.commit()
            conn.close()

    # ------------------------------------------------------------------
    # KEYWORD EXTRACTION + CLASSIFICATION
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_keywords(text: str) -> List[str]:
        """Extract meaningful keywords from attack text."""
        words = text.lower().split()
        keywords = []
        seen = set()
        for word in words:
            clean = word.strip('.,!?;:\'"()[]{}/')
            if (len(clean) >= 3
                    and clean not in _STOPWORDS
                    and clean not in seen):
                keywords.append(clean)
                seen.add(clean)
        return keywords

    @staticmethod
    def _classify_attack(keywords: List[str]) -> tuple:
        """Classify extracted keywords into an attack category."""
        best_cat = None
        best_matches: List[str] = []
        best_score = 0

        for cat, cat_keywords in ATTACK_CATEGORIES.items():
            matches = [kw for kw in keywords if kw in cat_keywords]
            if len(matches) > best_score:
                best_score = len(matches)
                best_cat = cat
                best_matches = matches

        if best_score >= 1:
            return best_cat, best_matches

        if len(keywords) >= 2:
            return f"learned_{keywords[0]}_{keywords[1]}", []
        elif keywords:
            return f"learned_{keywords[0]}", []

        return None, []

    # ------------------------------------------------------------------
    # ADMIN HELPERS
    # ------------------------------------------------------------------

    def get_rules(self, status: Optional[str] = None) -> List[dict]:
        """Get all rules, optionally filtered by status."""
        conn = self._get_conn()
        cur = conn.cursor()
        if status:
            cur.execute("SELECT * FROM rules WHERE status = ?", (status,))
        else:
            cur.execute("SELECT * FROM rules")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    @property
    def stats(self) -> dict:
        """Quick stats about the adaptive shield."""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as c FROM scan_log")
        total_scans = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM scan_log WHERE allowed = 0")
        blocked = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM rules WHERE status = 'approved'")
        approved = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM rules WHERE status = 'pending'")
        pending = cur.fetchone()["c"]
        conn.close()
        total_kws = sum(len(v) for v in self._category_keywords.values())
        return {
            "total_scans": total_scans,
            "blocked": blocked,
            "approved_rules": approved,
            "pending_rules": pending,
            "custom_rules_loaded": len(self._custom_rules),
            "category_keywords": total_kws,
        }
