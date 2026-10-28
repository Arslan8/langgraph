"""Repeatable stdlib tests for the proof-evidence driver's refusal conditions."""

from __future__ import annotations

import argparse
import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import check


def valid_axioms() -> str:
    return "\n".join(
        f"'{name}' depends on axioms: [propext]" for name in check.REQUIRED_THEOREMS
    )


class AxiomAuditTests(unittest.TestCase):
    def test_fixed_nonempty_required_obligations(self):
        self.assertEqual(len(check.WORKER_THEOREMS), 17)
        self.assertGreater(len(check.RECEIPT_THEOREMS), 0)
        self.assertIn("WorkerRoute.useful_route_succeeds", check.REQUIRED_THEOREMS)
        self.assertIn(
            "WorkerRoute.go_requires_matching_authorized_activation",
            check.REQUIRED_THEOREMS,
        )
        self.assertIn(
            "WorkerRoute.unknown_cleanup_anywhere_refuses", check.REQUIRED_THEOREMS
        )
        self.assertIn("ReceiptCoverage.coverageAccept_iff", check.REQUIRED_THEOREMS)
        self.assertIn("ReceiptCoverage.certificateValid_iff", check.REQUIRED_THEOREMS)
        self.assertEqual(
            len(check.parse_axioms(valid_axioms())), len(check.REQUIRED_THEOREMS)
        )

    def test_accepts_standard_axioms_and_no_axioms(self):
        source = valid_axioms().replace(
            "[propext]", "[propext, Classical.choice, Quot.sound]", 1
        )
        first = check.REQUIRED_THEOREMS[1]
        source = source.replace(
            f"'{first}' depends on axioms: [propext]",
            f"'{first}' does not depend on any axioms",
        )
        self.assertEqual(check.parse_axioms(source)[first], [])

    def test_missing_or_empty_audit_refuses(self):
        for source in ("", "\n".join(valid_axioms().splitlines()[1:])):
            with self.subTest(source=source), self.assertRaises(check.AuditFailure):
                check.parse_axioms(source)

    def test_duplicate_or_unexpected_results_refuse(self):
        for suffix in (
            valid_axioms().splitlines()[0],
            "'WorkerRoute.unreviewed' depends on axioms: [propext]",
        ):
            with self.subTest(suffix=suffix), self.assertRaises(check.AuditFailure):
                check.parse_axioms(valid_axioms() + "\n" + suffix)

    def test_custom_and_native_reduction_axioms_refuse(self):
        for axiom in ("sorryAx", "Custom.security", "Lean.ofReduceBool", "trustMe"):
            with self.subTest(axiom=axiom), self.assertRaises(check.AuditFailure):
                check.parse_axioms(valid_axioms().replace("[propext]", f"[{axiom}]", 1))

    def test_malformed_axiom_lists_do_not_count(self):
        for replacement in (
            "[propext",
            "[propext] extra",
            "unknown format",
            "[propext,]",
            "[,propext]",
            "[propext,,Quot.sound]",
            "[propext,propext]",
        ):
            with (
                self.subTest(replacement=replacement),
                self.assertRaises(check.AuditFailure),
            ):
                check.parse_axioms(valid_axioms().replace("[propext]", replacement, 1))

    def test_extra_malformed_and_foreign_namespace_queries_refuse(self):
        for suffix in (
            "'ReceiptCoverage.coverageAccept_iff' depends on axioms: [sorryAx",
            "'ReceiptCoverage.coverageAccept_iff' depends on axioms: [propext] extra",
            "'Unreviewed.valid' depends on axioms: [propext]",
        ):
            with self.subTest(suffix=suffix), self.assertRaises(check.AuditFailure):
                check.parse_axioms(valid_axioms() + "\n" + suffix)


class SourceAndEvidenceTests(unittest.TestCase):
    def test_proof_bypass_source_refuses(self):
        for source in (
            "axiom insecure : False",
            "theorem x : True := by sorry",
            "theorem x : True := by admit",
            "example : True := by native_decide",
            "#eval 1",
            "unsafe def x := 1",
            "set_option debug.skipKernelTC true",
            "initialize effect : IO Unit := pure ()",
            "@[implemented_by replacement] def original := 1",
        ):
            with self.subTest(source=source), self.assertRaises(check.AuditFailure):
                check.source_hygiene(source, "candidate")

    def test_nested_comments_and_literal_strings_are_not_code(self):
        check.source_hygiene(
            '/- outer /- sorry -/ axiom -/\n-- native_decide\ndef x := "sorry"',
            "candidate",
        )

    def test_character_literals_and_identifier_apostrophes_preserve_scanning(self):
        check.source_hygiene(
            "def quote := '\"'\ndef f (h' : Nat) := h'\ndef slash := '/'\n"
            + r"def newline := '\n'"
            + "\n"
            + r"def backslash := '\\'",
            "candidate",
        )

    def test_character_literals_do_not_hide_following_proof_bypass(self):
        for prefix in (
            "def quote := '\"'",
            r"def newline := '\n'",
            "def f (h' : Nat) := h'",
        ):
            with self.subTest(prefix=prefix), self.assertRaises(check.AuditFailure):
                check.source_hygiene(
                    prefix + "\ntheorem bad : False := by sorry", "candidate"
                )

    def test_unterminated_comment_or_string_refuses(self):
        for source in ("/- unclosed", 'def x := "unclosed'):
            with self.subTest(source=source), self.assertRaises(check.AuditFailure):
                check.source_hygiene(source, "candidate")

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            sentinel = output / "report.json"
            sentinel.write_bytes(b"previous observation\n")
            args = argparse.Namespace(output=str(output), lake="missing", timeout=10)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(check.audit(args), 2)
            self.assertEqual(sentinel.read_bytes(), b"previous observation\n")
            self.assertEqual(list(output.iterdir()), [sentinel])

    def test_capture_preserves_before_and_changed_after_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project, before, after = (
                root / name for name in ("project", "before", "after")
            )
            for folder in (project, before, after):
                folder.mkdir()
            for name in check.SOURCE_FILES:
                (project / name).write_bytes(name.encode())
            first = check.capture_before(project, before)
            (project / "Main.lean").write_bytes(b"changed")
            last = check.capture_after(project, after)
            self.assertNotEqual(first, last)
            self.assertEqual((before / "Main.lean").read_bytes(), b"Main.lean")
            self.assertEqual((after / "Main.lean").read_bytes(), b"changed")

    def test_missing_receipt_module_prevents_complete_capture(self):
        self.assertIn("ReceiptCoverage.lean", check.SOURCE_FILES)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project, snapshot = root / "project", root / "snapshot"
            project.mkdir()
            snapshot.mkdir()
            for name in check.SOURCE_FILES:
                if name != "ReceiptCoverage.lean":
                    (project / name).write_text(name)
            with self.assertRaises(FileNotFoundError):
                check.capture_before(project, snapshot)

    def test_missing_grant_module_prevents_complete_capture(self):
        self.assertIn("GrantCoverage.lean", check.SOURCE_FILES)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project, snapshot = root / "project", root / "snapshot"
            project.mkdir()
            snapshot.mkdir()
            for name in check.SOURCE_FILES:
                if name != "GrantCoverage.lean":
                    (project / name).write_text(name)
            with self.assertRaises(FileNotFoundError):
                check.capture_before(project, snapshot)

    def test_grant_negative_controls_distinguish_fields_and_typed_values(self):
        self.assertIn(
            "(deriveRule rule).selector = rule.operation",
            check.NEGATIVE_AUDITS["WrongGeneratedSelector"],
        )
        self.assertIn(
            "Value.bool true = Value.int 1",
            check.NEGATIVE_AUDITS["WrongTypedCondition"],
        )
        self.assertNotIn("digest :=", check.NEGATIVE_AUDITS["MissingGrantDigest"])

    def test_failed_command_retains_output_and_exit_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = {"commands": []}
            log = root / "failure.log"
            with self.assertRaises(check.AuditFailure):
                check.run_command(
                    [
                        sys.executable,
                        "-c",
                        "print('kept observation'); raise SystemExit(3)",
                    ],
                    root,
                    log,
                    report,
                    10,
                )
            self.assertEqual(report["commands"][0]["exit_code"], 3)
            self.assertIn("kept observation", log.read_text())

    def test_missing_kernel_replay_binary_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = {"commands": [], "kernel_replay_checked": False}
            with self.assertRaises(check.AuditFailure):
                check.require_kernel_replay(
                    "lake", root, root, root / "replay.log", report, 10
                )
            self.assertFalse(report["kernel_replay_checked"])
            self.assertFalse(report["kernel_replay"]["available"])
            self.assertFalse(report["kernel_replay"]["is_independent_implementation"])

    def test_wrong_field_controls_must_reach_type_errors(self):
        self.assertIn(
            ".binding.runtime = b.deployment",
            check.NEGATIVE_AUDITS["WrongBindingField"],
        )
        self.assertNotIn("runtime :=", check.NEGATIVE_AUDITS["MissingReceiptField"])
        for exit_code, message, accepted in (
            (1, "error: Type mismatch", True),
            (1, "error: Fields missing: runtime", True),
            (1, "error: unknown module", False),
            (2, "error: Type mismatch", False),
            (None, "timeout", False),
            (0, "", False),
        ):
            with (
                self.subTest(exit_code=exit_code, message=message),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                report = {"commands": []}

                def command(
                    argv, cwd, log, report, timeout, code=exit_code, message=message
                ):
                    report["commands"].append({"exit_code": code})
                    log.write_text(message)
                    if code != 0:
                        raise check.AuditFailure("controlled command refusal")

                with patch.object(check, "run_command", command):
                    if accepted:
                        check.check_negative_audits("lake", root, root, report, 10)
                        self.assertEqual(
                            len(report["negative_audit_controls"]),
                            len(check.NEGATIVE_AUDITS),
                        )
                        self.assertTrue(
                            all(
                                row["rejected"]
                                for row in report["negative_audit_controls"]
                            )
                        )
                    else:
                        with self.assertRaises(check.AuditFailure):
                            check.check_negative_audits("lake", root, root, report, 10)


if __name__ == "__main__":
    unittest.main()
