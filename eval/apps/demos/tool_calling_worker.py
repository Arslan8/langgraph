"""Stateless tool implementations adapted from frozen LangGraph documentation."""


def multiply(a: int, b: int) -> int:
    """Multiply two numbers."""
    return a * b


def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


def get_weather(location: str) -> str:
    """Return the tutorial's deterministic weather response."""
    if location.lower() in {"sf", "san francisco"}:
        return "It's 60 degrees and foggy."
    return "It's 90 degrees and sunny."


def get_coolest_cities() -> str:
    """Return the tutorial's deterministic list of coolest cities."""
    return "nyc, sf"


def greet(user_name: str) -> str:
    """Greet a user."""
    return f"Hello {user_name}!"
