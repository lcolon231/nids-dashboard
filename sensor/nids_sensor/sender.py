"""Batch and POST feature records to the backend's /score/live endpoint.

Reuses one httpx.Client for the whole session. On network failure the batch
is kept (capped) and retried on the next flush.
"""
from __future__ import annotations

import httpx

MAX_BUFFER = 500


class LiveScoreSender:
    def __init__(
        self,
        base_url: str,
        batch_size: int = 10,
        client: httpx.Client | None = None,
        dataset: str = "nsl",  # which backend model family scores the batch
        api_key: str | None = None,  # sent as X-API-Key if the backend requires it
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.batch_size = batch_size
        self.dataset = dataset
        self._headers = {"X-API-Key": api_key} if api_key else {}
        self._client = client or httpx.Client(timeout=10.0)
        self._buffer: list[dict] = []

    @property
    def pending(self) -> int:
        return len(self._buffer)

    def add(self, record: dict) -> dict | None:
        """Buffer a record; flush automatically when the batch is full."""
        self._buffer.append(record)
        if len(self._buffer) >= self.batch_size:
            return self.flush()
        return None

    def flush(self) -> dict | None:
        """POST the buffer. Returns the API response body, or None if empty
        or the request failed (records are kept for the next flush)."""
        if not self._buffer:
            return None
        try:
            r = self._client.post(
                f"{self.base_url}/score/live",
                params={"dataset": self.dataset},
                json={"records": self._buffer},
                headers=self._headers,
            )
            r.raise_for_status()
        except httpx.HTTPError as e:
            print(f"[warn] POST /score/live failed ({e}) — keeping {len(self._buffer)} records")
            del self._buffer[:-MAX_BUFFER]
            return None
        self._buffer = []
        return r.json()

    def close(self) -> None:
        self._client.close()
