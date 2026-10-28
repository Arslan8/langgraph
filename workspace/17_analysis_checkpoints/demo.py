"""Demo 17: restore analysis metadata after closing its original store."""

from langgraph.prebuilt.analysis import StructuredAnalysis
from langgraph.prebuilt.analysis.errors import AnalysisUnavailable


def main():
    with StructuredAnalysis(configuration={"format": "v1"}) as analysis:
        source = analysis.value("Private report", confidentiality={"secret"})
        summary = analysis.value("Summary", parents=(source,))
        checkpoint = analysis.checkpoint(summary)

    # The original session is closed. Restore into a new, independently owned store.
    with checkpoint.restore() as restored:
        labels = restored.client.get_labels(summary)
        provenance = restored.client.get_provenance(summary)
        assert labels.record.confidentiality == frozenset({"secret"})
        assert {source, summary}.issubset({item.ref for item in provenance.records})
        print("Fresh store: summary identity, ancestry and secret label restored")

    try:
        with checkpoint.restore(configuration={"format": "v2"}):
            raise AssertionError("Incompatible configuration must not restore")
    except AnalysisUnavailable as error:
        assert "checkpoint_configuration_mismatch" in str(error)
        print("Restore with incompatible configuration: rejected")


if __name__ == "__main__":
    main()
