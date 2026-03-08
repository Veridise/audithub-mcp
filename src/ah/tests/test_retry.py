"""Tests for ah_mcp.retry — exponential backoff with full jitter."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

import httpx

from ah_mcp.retry import _MAX_DELAY, _MAX_RETRIES, get_with_retry


def _mock_response(status_code: int, headers: dict[str, str] | None = None) -> MagicMock:
    """Build an httpx.Response-like mock with the given status code and headers."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.headers = httpx.Headers(headers or {})
    return resp


class TestGetWithRetryNonRetryable(unittest.TestCase):
    """Non-retryable status codes return immediately without sleeping."""

    def _assert_no_sleep(self, status_code: int) -> None:
        resp = _mock_response(status_code)
        request_fn = MagicMock(return_value=resp)
        with patch("ah_mcp.retry.time.sleep") as mock_sleep:
            result = get_with_retry(request_fn)
        self.assertIs(result, resp)
        mock_sleep.assert_not_called()
        request_fn.assert_called_once()

    def test_200_returns_immediately(self) -> None:
        self._assert_no_sleep(200)

    def test_201_returns_immediately(self) -> None:
        self._assert_no_sleep(201)

    def test_400_returns_immediately(self) -> None:
        self._assert_no_sleep(400)

    def test_401_returns_immediately(self) -> None:
        self._assert_no_sleep(401)

    def test_403_returns_immediately(self) -> None:
        self._assert_no_sleep(403)

    def test_404_returns_immediately(self) -> None:
        self._assert_no_sleep(404)


class TestGetWithRetryRetryable(unittest.TestCase):
    """Retryable status codes (429, 5xx) trigger sleep and retry."""

    def _run_with_mocked_sleep(
        self, responses: list[MagicMock]
    ) -> tuple[MagicMock, list[float]]:
        """Run get_with_retry with a sequence of responses; return (last_result, sleep_calls)."""
        it = iter(responses)
        request_fn = MagicMock(side_effect=lambda: next(it))
        sleep_calls: list[float] = []
        with patch("ah_mcp.retry.time.sleep", side_effect=lambda s: sleep_calls.append(s)), \
                patch("ah_mcp.retry.random.uniform", return_value=1.0):
            try:
                get_with_retry(request_fn)
            except httpx.HTTPStatusError:
                return request_fn, sleep_calls
        return request_fn, sleep_calls

    def test_429_triggers_retry(self) -> None:
        responses = [_mock_response(429), _mock_response(200)]
        request_fn, sleep_calls = self._run_with_mocked_sleep(responses)
        self.assertEqual(request_fn.call_count, 2)
        self.assertEqual(len(sleep_calls), 1)

    def test_500_triggers_retry(self) -> None:
        responses = [_mock_response(500), _mock_response(200)]
        request_fn, sleep_calls = self._run_with_mocked_sleep(responses)
        self.assertEqual(request_fn.call_count, 2)
        self.assertEqual(len(sleep_calls), 1)

    def test_502_503_504_trigger_retry(self) -> None:
        for code in (502, 503, 504):
            with self.subTest(code=code):
                responses = [_mock_response(code), _mock_response(200)]
                fn, sleeps = self._run_with_mocked_sleep(responses)
                self.assertEqual(fn.call_count, 2)
                self.assertEqual(len(sleeps), 1)

    def test_max_retries_exhausted_raises(self) -> None:
        """After _MAX_RETRIES retries, the last response's raise_for_status() is called."""
        bad = _mock_response(503)
        bad.raise_for_status.side_effect = httpx.HTTPStatusError(
            "503", request=MagicMock(), response=bad
        )
        responses = [bad] * (_MAX_RETRIES + 1)
        it = iter(responses)
        request_fn = MagicMock(side_effect=lambda: next(it))
        sleep_calls: list[float] = []
        with patch("ah_mcp.retry.time.sleep", side_effect=lambda s: sleep_calls.append(s)), \
                patch("ah_mcp.retry.random.uniform", return_value=1.0), \
                self.assertRaises(httpx.HTTPStatusError):
            get_with_retry(request_fn)
        # Called once per attempt (initial + _MAX_RETRIES retries)
        self.assertEqual(request_fn.call_count, _MAX_RETRIES + 1)
        # Slept exactly _MAX_RETRIES times (no sleep after the final attempt)
        self.assertEqual(len(sleep_calls), _MAX_RETRIES)

    def test_eventual_success_after_retry(self) -> None:
        """A success response after some retries is returned, not raised."""
        responses = [_mock_response(503), _mock_response(503), _mock_response(200)]
        fn, sleeps = self._run_with_mocked_sleep(responses)
        self.assertEqual(fn.call_count, 3)
        self.assertEqual(len(sleeps), 2)


class TestRetryAfterHeader(unittest.TestCase):
    """Retry-After header controls sleep duration, capped at _MAX_DELAY."""

    def _run_one_retry(
        self, headers: dict[str, str]
    ) -> float:
        """Return the sleep duration used after a single 429 response."""
        resp = _mock_response(429, headers=headers)
        ok = _mock_response(200)
        it = iter([resp, ok])
        request_fn = MagicMock(side_effect=lambda: next(it))
        sleep_calls: list[float] = []
        with patch("ah_mcp.retry.time.sleep", side_effect=lambda s: sleep_calls.append(s)):
            get_with_retry(request_fn)
        self.assertEqual(len(sleep_calls), 1)
        return sleep_calls[0]

    def test_retry_after_integer_used_as_delay(self) -> None:
        delay = self._run_one_retry({"Retry-After": "5"})
        self.assertEqual(delay, 5.0)

    def test_retry_after_zero_used_as_delay(self) -> None:
        delay = self._run_one_retry({"Retry-After": "0"})
        self.assertEqual(delay, 0.0)

    def test_retry_after_capped_at_max_delay(self) -> None:
        """A Retry-After value larger than _MAX_DELAY must be capped."""
        delay = self._run_one_retry({"Retry-After": "99999"})
        self.assertEqual(delay, _MAX_DELAY)

    def test_retry_after_exactly_max_delay_not_capped(self) -> None:
        delay = self._run_one_retry({"Retry-After": str(int(_MAX_DELAY))})
        self.assertEqual(delay, _MAX_DELAY)

    def test_retry_after_invalid_falls_back_to_jitter(self) -> None:
        """Non-integer Retry-After triggers jitter fallback (not a hard error)."""
        resp = _mock_response(429, headers={"Retry-After": "Wed, 21 Oct 2025 07:28:00 GMT"})
        ok = _mock_response(200)
        it = iter([resp, ok])
        request_fn = MagicMock(side_effect=lambda: next(it))
        sleep_calls: list[float] = []
        with patch("ah_mcp.retry.time.sleep", side_effect=lambda s: sleep_calls.append(s)), \
                patch("ah_mcp.retry.random.uniform", return_value=2.5):
            get_with_retry(request_fn)
        self.assertEqual(len(sleep_calls), 1)
        self.assertEqual(sleep_calls[0], 2.5)  # jitter fallback value

    def test_retry_after_negative_clamped_to_zero(self) -> None:
        """Negative Retry-After must be clamped to 0, not passed as a negative sleep."""
        delay = self._run_one_retry({"Retry-After": "-5"})
        self.assertEqual(delay, 0.0)

    def test_retry_after_capped_emits_debug_log(self) -> None:
        """When Retry-After exceeds _MAX_DELAY, a debug log must be emitted."""
        from ah_mcp.retry import _retry_delay

        resp = _mock_response(429, headers={"Retry-After": "9999"})
        with patch("ah_mcp.retry.logger") as mock_logger:
            _retry_delay(resp, 0)
        mock_logger.debug.assert_called_once()
        call_str = str(mock_logger.debug.call_args)
        self.assertIn("9999", call_str)


class TestJitterBounds(unittest.TestCase):
    """Jitter cap is always <= _MAX_DELAY regardless of attempt number."""

    def test_jitter_cap_does_not_exceed_max_delay(self) -> None:
        from ah_mcp.retry import _retry_delay

        for attempt in range(10):
            resp = _mock_response(503)
            with patch("ah_mcp.retry.random.uniform") as mock_uniform:
                mock_uniform.return_value = 0.0
                _retry_delay(resp, attempt)
                _, cap = mock_uniform.call_args.args
                msg = f"cap exceeded _MAX_DELAY at attempt {attempt}"
                self.assertLessEqual(cap, _MAX_DELAY, msg)

    def test_jitter_lower_bound_is_zero(self) -> None:
        from ah_mcp.retry import _retry_delay

        resp = _mock_response(503)
        with patch("ah_mcp.retry.random.uniform") as mock_uniform:
            mock_uniform.return_value = 0.0
            _retry_delay(resp, 0)
            lower, _ = mock_uniform.call_args.args
            self.assertEqual(lower, 0.0)
