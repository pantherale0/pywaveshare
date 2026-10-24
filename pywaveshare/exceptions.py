"""Exceptions raised by pywaveshare."""

from __future__ import annotations


class WaveshareError(Exception):
    """Base exception for all pywaveshare errors."""


class WaveshareConnectionError(WaveshareError):
    """Raised when connecting to or communicating with a Waveshare device fails."""


class WaveshareTimeoutError(WaveshareConnectionError, TimeoutError):
    """Raised when a device operation or connection attempt times out."""


class WaveshareAuthenticationError(WaveshareError):
    """Raised when device password/key authentication fails."""


class WaveshareConfigurationError(WaveshareError):
    """Raised when invalid or unsupported configuration parameters are provided."""


class WaveshareProtocolError(WaveshareError):
    """Raised when a malformed or unexpected protocol frame is received."""
