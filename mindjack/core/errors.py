"""Custom exceptions for MindJack v2."""

from __future__ import annotations


class MindJackError(Exception):
    """Base exception for all MindJack errors."""


class ScopeError(MindJackError):
    """Raised when a scope constraint is violated."""


class RegistryError(MindJackError):
    """Raised when a plugin cannot be registered or found."""


class ParserError(MindJackError):
    """Raised when an artifact cannot be parsed."""


class EvidenceError(MindJackError):
    """Raised when evidence logging fails."""


class ModeError(MindJackError):
    """Raised when an operation is not allowed in the current mode."""
