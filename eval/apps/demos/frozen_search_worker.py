"""Frozen query-dependent search backend for the upstream add-tools demo."""

DOCUMENTS = (
    {
        "url": "https://www.olympics.com/en/olympic-games/atlanta-1996",
        "content": (
            "The 1996 Summer Olympics were held in Atlanta, United States. "
            "The United States used the US dollar (USD)."
        ),
    },
    {
        "url": "https://www.olympics.com/en/olympic-games/sydney-2000",
        "content": (
            "The 2000 Summer Olympics were held in Sydney, Australia. "
            "Australia used the Australian dollar (AUD)."
        ),
    },
    {
        "url": "https://www.olympics.com/en/olympic-games/athens-2004",
        "content": (
            "The 2004 Summer Olympics were held in Athens, Greece. Greece used the euro (EUR)."
        ),
    },
    {
        "url": "https://www.olympics.com/en/olympic-games/london-2012",
        "content": (
            "The 2012 Summer Olympics were held in London, United Kingdom. "
            "The United Kingdom used pound sterling (GBP)."
        ),
    },
    {
        "url": "https://www.olympics.com/en/olympic-games/rio-2016",
        "content": (
            "The 2016 Summer Olympics were held in Rio de Janeiro, Brazil. "
            "Brazil used the Brazilian real (BRL)."
        ),
    },
)


def search(query: str) -> list[dict[str, str]]:
    """Return the two frozen documents with the greatest token overlap."""
    query_tokens = set(query.lower().replace("?", "").split())

    def score(document: dict[str, str]) -> tuple[int, str]:
        content_tokens = set(document["content"].lower().replace(".", "").split())
        return len(query_tokens & content_tokens), document["url"]

    return [dict(item) for item in sorted(DOCUMENTS, key=score, reverse=True)[:2]]
