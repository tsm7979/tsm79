"""
TSM Layer - Custom Error Types
================================

Custom exceptions for TSM operations.
"""


class LLMError(Exception):
    """Base exception for LLM-related errors."""
    pass


class ProviderError(LLMError):
    """Provider-specific errors."""
    pass


class RateLimitError(LLMError):
    """Rate limit exceeded."""
    pass


class AuthenticationError(LLMError):
    """Authentication failed."""
    pass


class InvalidModelError(LLMError):
    """Invalid model specified."""
    pass


class ContextLengthError(LLMError):
    """Context length exceeded."""
    pass
