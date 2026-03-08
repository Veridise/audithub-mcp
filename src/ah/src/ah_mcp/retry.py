"""Exponential backoff with full jitter for transient HTTP errors.

The ``audithub_client`` library handles 401 retries internally (re-fetching OIDC tokens).
This module handles 429 and 5xx responses, which the library does not retry.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable

import httpx

_RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429, 500, 502, 503, 504})
_MAX_RETRIES: int = 3
_BASE_DELAY: float = 1.0
_MAX_DELAY: float = 30.0


def get_with_retry(request_fn: Callable[[], httpx.Response]) -> httpx.Response:
    """Execute *request_fn* with exponential backoff and full jitter on transient errors.

    Retries on status codes: 429, 500, 502, 503, 504.  Respects ``Retry-After``
    header (integer seconds) when present.  On non-retryable responses or after
    exhausting retries, returns or raises as-is so callers can apply their own
    error handling.

    Args:
        request_fn: Zero-argument callable returning an ``httpx.Response``.

    Returns:
        The response once a non-retryable status code is received.

    Raises:
        httpx.HTTPStatusError: After exhausting retries on a persistently failing
            status code.
    """
    last_response: httpx.Response | None = None
    for attempt in range(_MAX_RETRIES + 1):
        response = request_fn()
        if response.status_code not in _RETRYABLE_STATUS_CODES:
            return response
        last_response = response
        if attempt == _MAX_RETRIES:
            break
        time.sleep(_retry_delay(response, attempt))
    assert last_response is not None  # loop always executes at least once
    last_response.raise_for_status()
    return last_response  # unreachable; satisfies type checker


def _retry_delay(response: httpx.Response, attempt: int) -> float:
    """Compute sleep duration in seconds before the next retry.

    Uses ``Retry-After`` header value (as integer seconds) when present; falls
    back to full-jitter exponential backoff: ``uniform(0, min(30, 1.0 * 2^attempt))``.
    """
    retry_after = response.headers.get("Retry-After")
    if retry_after is not None:
        try:
            return float(int(retry_after))
        except ValueError:
            pass
    cap = min(_MAX_DELAY, _BASE_DELAY * (2**attempt))
    return random.uniform(0, cap)
