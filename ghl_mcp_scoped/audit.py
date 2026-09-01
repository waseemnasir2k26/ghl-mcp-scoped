"""Append-only JSONL audit log with key-based redaction."""

from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .policy import AuditConfig

TRUNCATED_SUFFIX = "...[truncated]"


def redact(value: Any, pattern: re.Pattern[str], placeholder: str, max_len: int) -> Any:
    """Recursively redact by KEY name, then clamp long strings.

    Redaction is structural: any mapping key whose name matches ``pattern``
    (case-insensitive ``re.search``) has its whole value replaced, however deep
    it sits and whatever type it is. Values are never inspected for secrets;
    that would be guesswork.
    """
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and pattern.search(key):
                out[key] = placeholder
            else:
                out[key] = redact(item, pattern, placeholder, max_len)
        return out
    if isinstance(value, list):
        return [redact(item, pattern, placeholder, max_len) for item in value]
    if isinstance(value, str) and len(value) > max_len:
        return value[:max_len] + TRUNCATED_SUFFIX
    return value


class AuditLog:
    """One JSONL line per decision. Opened lazily, flushed on every write."""

    def __init__(self, config: AuditConfig, base_dir: Path | None = None) -> None:
        self.config = config
        self._pattern = re.compile(config.redact_keys, re.IGNORECASE)
        self._lock = threading.Lock()
        self._handle = None
        path = Path(config.path)
        if base_dir is not None and not path.is_absolute():
            path = Path(base_dir) / path
        self.path = path

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    def _ensure_open(self):
        if self._handle is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._handle = open(self.path, "a", encoding="utf-8")
        return self._handle

    def redact_arguments(self, arguments: Any) -> Any:
        return redact(
            arguments,
            self._pattern,
            self.config.redact_placeholder,
            self.config.max_string_length,
        )

    def record(
        self,
        *,
        event: str,
        tool: str | None = None,
        decision: str | None = None,
        rule: str | None = None,
        reason: str | None = None,
        arguments: Any = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
                "+00:00", "Z"
            ),
            "event": event,
            "pid": os.getpid(),
        }
        if tool is not None:
            entry["tool"] = tool
        if decision is not None:
            entry["decision"] = decision
        if rule is not None:
            entry["rule"] = rule
        if reason is not None:
            entry["reason"] = reason
        if arguments is not None:
            if self.config.log_arguments:
                entry["arguments"] = self.redact_arguments(arguments)
            else:
                entry["arguments"] = self.config.redact_placeholder
        if extra:
            entry.update(extra)

        if self.enabled:
            line = json.dumps(entry, ensure_ascii=False, default=str)
            with self._lock:
                handle = self._ensure_open()
                handle.write(line + "\n")
                handle.flush()
        return entry

    def close(self) -> None:
        with self._lock:
            if self._handle is not None:
                self._handle.close()
                self._handle = None
