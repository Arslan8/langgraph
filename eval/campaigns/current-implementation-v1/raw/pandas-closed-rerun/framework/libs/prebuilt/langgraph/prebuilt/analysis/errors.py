"""Stable, content-free failures at analysis trust boundaries."""


class AnalysisError(Exception):
    """Base analysis failure; never interpret as a clean result."""


class ConfigurationError(AnalysisError, ValueError):
    """Invalid fixed configuration or incomplete instrumentation."""


class AnalysisUnavailable(AnalysisError):
    """Required analysis could not complete."""


class MissingValue(AnalysisUnavailable):
    """Unknown, inaccessible or mismatched value reference."""


class StorageExhausted(AnalysisUnavailable):
    """Protected metadata capacity exhausted."""


class AccessDenied(AnalysisError, PermissionError):
    """The authenticated caller lacks access."""


class CursorExpired(AnalysisError):
    """Requested revision is no longer retained."""


class SubscriptionOverflow(AnalysisError):
    """Consumer exceeded its bounded notification queue."""

    def __init__(self, last_delivered_cursor: str | None) -> None:
        super().__init__("analysis:subscription_overflow")
        self.last_delivered_cursor = last_delivered_cursor
