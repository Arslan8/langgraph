"""Demo 13: provenance."""

from langgraph.prebuilt.analysis.provenance.records import ValueRecord
from langgraph.prebuilt.analysis.provenance.store import MemoryProvenanceStore


def main():
    store = MemoryProvenanceStore()
    try:

        def value(text):
            return ValueRecord(
                "demo", "session", "lesson", text.encode(), media_type="text/plain"
            )

        source = store.register(value("Revenue increased by ten percent."))
        summary = store.derive((source,), value("Revenue grew."), "summarize")
        answer = store.derive((summary,), value("Growth was positive."), "format")
        unrelated = store.register(value("Revenue increased by ten percent."))
        ancestors = store.ancestors(answer)
        assert source in ancestors and summary in ancestors
        assert unrelated not in ancestors and unrelated != source
        print("source -> summarize -> format")
        print("Answer retains source and summary ancestry: yes")
        print("Identical text admitted separately is an ancestor: no")
    finally:
        store.close()


if __name__ == "__main__":
    main()
