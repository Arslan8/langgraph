"""Demo 18: evaluate an analyzer offline, independently of the runtime."""

from time import perf_counter


def analyze(text):
    """Deliberately crude test classifier; its result format is our own choice."""
    return "secret" in text.lower()


def main():
    cases = (
        ("The secret password is swordfish", True),
        ("Lunch is at noon", False),
        ("The novel is called Secret Garden", False),
        ("The password is swordfish", True),
    )
    counts = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    elapsed = []
    for text, sensitive in cases:
        start = perf_counter()
        flagged = analyze(text)
        elapsed.append(perf_counter() - start)
        bucket = (
            ("TP" if sensitive else "FP") if flagged else ("FN" if sensitive else "TN")
        )
        counts[bucket] += 1
        print(f"{bucket}: {text}")

    assert counts == {"TP": 1, "TN": 1, "FP": 1, "FN": 1}
    precision = counts["TP"] / (counts["TP"] + counts["FP"])
    recall = counts["TP"] / (counts["TP"] + counts["FN"])
    print(f"Precision: {precision:.0%}; recall: {recall:.0%}")
    print(f"Mean analyzer time: {1000 * sum(elapsed) / len(elapsed):.3f} ms")


if __name__ == "__main__":
    main()
