"""Security enforcement errors with explicit execution-state semantics."""


class SecurityAuditError(RuntimeError):
    """Raised when a required security audit record cannot be persisted."""


class SecurityIndeterminateError(RuntimeError):
    """Raised when an operation may have executed but its outcome is not durable."""


class SecurityConfigurationError(RuntimeError):
    """Raised when secured execution would lose its inherited configuration."""
