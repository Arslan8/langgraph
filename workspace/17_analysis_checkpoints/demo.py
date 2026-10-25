"""Demo 17: analysis checkpoints."""

from pathlib import Path
from secrets import token_bytes
from tempfile import TemporaryDirectory

from langgraph.prebuilt.analysis import AnalysisConfig
from langgraph.prebuilt.analysis.errors import AnalysisUnavailable
from langgraph.prebuilt.analysis.provenance.checkpoint import CheckpointBinding
from langgraph.prebuilt.analysis.provenance.records import ValueRecord
from langgraph.prebuilt.analysis.provenance.sqlite import SqliteProvenanceStore
from langgraph.prebuilt.security import Principal
from langgraph.prebuilt.security.objects import SecurityLabels


def main():
    key = token_bytes(32)  # Keep signing keys outside graph state.
    principal = Principal("owner", frozenset(), frozenset(), "session")
    version = AnalysisConfig('{"policy": "internal"}', ()).policy_version
    with TemporaryDirectory() as directory:
        original = SqliteProvenanceStore(str(Path(directory) / "original.db"))
        try:
            source = original.register(
                ValueRecord(
                    "demo",
                    "session",
                    "lesson",
                    b'"Private report"',
                    labels=SecurityLabels(frozenset({"secret"}), "low"),
                )
            )
            summary = original.derive(
                (source,),
                ValueRecord(
                    "demo",
                    "session",
                    "lesson",
                    b'"Summary"',
                ),
                "summarize",
            )
            envelope = CheckpointBinding(original, key, version).save(
                principal,
                (summary,),
                checkpoint_id="lesson-checkpoint",
            )
        finally:
            original.close()
        # Restore into a fresh database after closing the original store.
        restored = SqliteProvenanceStore(str(Path(directory) / "restored.db"))
        try:
            roots = CheckpointBinding(restored, key, version).restore(
                principal, envelope
            )
            assert roots == (summary,)
            assert source in restored.ancestors(summary)
            assert restored.get(summary).labels.confidentiality == frozenset({"secret"})
            print(
                "Fresh database: summary identity, ancestry and secret label restored"
            )
            changed = AnalysisConfig('{"policy": "public"}', ()).policy_version
            try:
                CheckpointBinding(restored, key, changed).restore(principal, envelope)
            except AnalysisUnavailable as error:
                assert "checkpoint_configuration_mismatch" in str(error)
                print("Restore with changed policy: denied")
            else:
                raise AssertionError("Changed policy must be rejected")
        finally:
            restored.close()


if __name__ == "__main__":
    main()
