"""Opt-in webhook notifications.

Posts a short JSON summary (Slack-compatible: includes a `text` field) to
a webhook URL after a run finishes. Only ever sent when the caller
explicitly supplies a URL (`--notify-webhook`) — nothing here fires
without that.

Uses `urllib` from the standard library rather than adding a dependency
like `requests`, since this is a single best-effort POST.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional


@dataclass
class NotifyResult:
    """Outcome of a webhook notification attempt."""

    sent: bool
    status_code: int = 0
    error: str = ""


def notify_webhook(
    url: str, text: str, *, extra: Optional[dict] = None, timeout: int = 10
) -> NotifyResult:
    """POST a JSON payload with a `text` field (Slack-compatible) to `url`."""
    payload = {"text": text, **(extra or {})}
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - explicit user-supplied URL
            return NotifyResult(sent=True, status_code=response.status)
    except urllib.error.HTTPError as exc:
        return NotifyResult(sent=False, status_code=exc.code, error=str(exc))
    except urllib.error.URLError as exc:
        return NotifyResult(sent=False, error=str(exc.reason))
    except OSError as exc:  # pragma: no cover - defensive
        return NotifyResult(sent=False, error=str(exc))
