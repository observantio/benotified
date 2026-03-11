"""Helpers for identifying suppressed Alertmanager alerts."""

from __future__ import annotations


def is_suppressed_status(raw_status: object) -> bool:
    if isinstance(raw_status, dict):
        state_text = str(raw_status.get("state") or "").strip().lower()
        if state_text == "suppressed":
            return True
        if raw_status.get("silencedBy"):
            return True
        if raw_status.get("inhibitedBy"):
            return True
        return False
    return str(raw_status or "").strip().lower() == "suppressed"