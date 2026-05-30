"""Sift-mcp exceptions."""


class SiftError(Exception):
    """Base exception for sift-mcp."""


class ToolNotFoundError(SiftError):
    """Tool binary not found on system."""


class DeniedBinaryError(SiftError):
    """Raised when a binary is on the hard denylist."""


class ExecutionError(SiftError):
    """Tool execution failed."""


class ExecutionTimeoutError(SiftError):
    """Tool execution timed out."""


class PolicyDenialError(SiftError):
    """Raised when the OPA policy engine denies a command.

    Carries the full structured decision (allowed, reasons, policies_evaluated)
    so the MCP layer can return ALL violation reasons, not just the first.
    """

    def __init__(self, message: str, decision: dict):
        super().__init__(message)
        self.decision = decision


class PolicyEngineError(SiftError):
    """Raised when OPA evaluation cannot be performed (binary missing, compile
    failure, eval error). Distinct from PolicyDenialError: this means the engine
    failed, not that a command was denied."""


class SandboxError(SiftError):
    """Raised when the bubblewrap sandbox cannot be set up (bwrap missing,
    profile load failure)."""


# Backward compatibility alias
TimeoutError = ExecutionTimeoutError
